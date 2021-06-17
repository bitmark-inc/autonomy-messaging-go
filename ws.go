package messaging

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/signal-golang/textsecure/axolotl"
	log "github.com/sirupsen/logrus"

	"github.com/bitmark-inc/autonomy-wallet-server/schema"
)

type WSMessagingClient struct {
	sync.Mutex
	wg              sync.WaitGroup
	messagingClient *Client
	wsConnection    *websocket.Conn

	wsMessageChan        chan json.RawMessage
	decryptedMessageChan chan *Message

	commandLock      sync.RWMutex
	commandResponses map[string]chan MessagingCommandResponse
}

// WSMessagePayload is the websocket wrapped message for signal message and command response
type WSMessagePayload struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type MessagingCommand struct {
	ID      string      `json:"id"`
	Command string      `json:"command"`
	Args    interface{} `json:"args"`
}

type MessagingCommandResponse struct {
	ID    string `json:"id"`
	OK    int    `json:"ok"`
	Error string `json:"errors"`
}

// NewWSClient creates a websocket client based on the configuration from the HTTP client
func (c *Client) NewWSClient() (*WSMessagingClient, error) {
	u, err := url.Parse(c.endpoint)
	if err != nil {
		return nil, err
	}

	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path = "/api/messaging/ws"

	wsConnection, _, err := websocket.DefaultDialer.Dial(u.String(), http.Header{"Authorization": []string{fmt.Sprintf("Bearer %s", c.authToken)}})
	if err != nil {
		return nil, err
	}

	return &WSMessagingClient{
		messagingClient:  c,
		wsConnection:     wsConnection,
		commandResponses: make(map[string]chan MessagingCommandResponse),
	}, nil
}

// readWSMessages will create a routine to read messages from the websocket connection
func (c *WSMessagingClient) readWSMessages() {
	c.Lock()
	defer c.Unlock()

	// make sure there is only one routing processing websocket messages
	if c.wsMessageChan != nil {
		return
	}
	c.wsMessageChan = make(chan json.RawMessage)

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		log.Info("start listening websocket messages...")
		for {
			_, b, err := c.wsConnection.ReadMessage()
			if err != nil {
				log.WithError(err).Error("unable to read message")
				c.closeChannels()
				break
			}
			log.WithField("message", string(b)).Debug("new websocket messages")

			var payload WSMessagePayload
			if err := json.Unmarshal(b, &payload); err != nil {
				log.WithError(err).Error("can not decode websocket message")
				continue
			}

			switch payload.Type {
			case "response":
				log.WithField("response", string(b)).Debug("receive response")

				var resp MessagingCommandResponse
				if err := json.Unmarshal(payload.Data, &resp); err != nil {
					log.WithError(err).Error("can not decode response message")
				}

				if resp.ID == "" {
					log.Error("empty id in command response")
					continue
				}

				c.commandLock.RLock()
				respChan, ok := c.commandResponses[resp.ID]
				c.commandLock.RUnlock()
				if !ok {
					log.WithField("id", resp.ID).Error("command id not found")
					continue
				}

				respChan <- resp
			case "message":
				log.WithField("message", string(b)).Info("receive messages")
				c.wsMessageChan <- payload.Data
			}
		}
		log.Debug("websocket channel closed")
	}()
}

// Close will close the websocket connection which leads the cleaning process being triggered
func (c *WSMessagingClient) Close() {
	log.Info("close websocket client")
	c.wsConnection.Close()
	c.wg.Wait()
}

// closeChannels is to help cleaning up all the existing channels
func (c *WSMessagingClient) closeChannels() {
	log.Debug("close all unfulfilled command channels")
	for _, ch := range c.commandResponses {
		ch <- MessagingCommandResponse{Error: "websocket connection closed"}
	}

	log.Debug("close websocket message channels")
	if c.wsMessageChan != nil {
		close(c.wsMessageChan)
	}
	log.Debug("close decrypted message channel")
	if c.decryptedMessageChan != nil {
		close(c.decryptedMessageChan)
	}
}

// SendWhisperMessages is a shortcuts for send messages via websocket connection
func (c *WSMessagingClient) SendWhisperMessages(to string, deviceID uint32, messages [][]byte) MessagingCommandResponse {
	if deviceID == 0 {
		deviceID = schema.MasterDeviceId
	}

	cipherMessages, err := c.messagingClient.PrepareEncryptedMessages(to, deviceID, messages)
	if err != nil {
		log.Panic(err)
	}

	return c.Command(MessagingCommand{
		ID:      time.Now().String(),
		Command: "send_messages",
		Args: map[string]interface{}{
			"destination": to,
			"messages":    cipherMessages,
			"timestamp":   time.Now().Unix(),
		},
	})
}

// Command sends messaging command through messaging websocket client
func (c *WSMessagingClient) Command(cmd MessagingCommand) MessagingCommandResponse {
	log.WithField("id", cmd).WithField("command", cmd.Command).Info("send command")
	defer log.WithField("id", cmd.ID).Debug("finish command")
	cmd.ID = uuid.New().String()
	c.wsConnection.WriteJSON(cmd)

	respChan := make(chan MessagingCommandResponse)
	defer close(respChan)

	c.commandLock.Lock()
	c.commandResponses[cmd.ID] = respChan
	c.commandLock.Unlock()

	defer func() {
		c.commandLock.Lock()
		delete(c.commandResponses, cmd.ID)
		c.commandLock.Unlock()
	}()

	select {
	case resp := <-respChan:
		return resp
	case <-time.After(30 * time.Second):
		return MessagingCommandResponse{Error: "timeout command response"}
	}
}

// WhisperMessages starts a process to process incoming messages and returns a read channel of decrypted signal messages
func (c *WSMessagingClient) WhisperMessages() <-chan *Message {
	c.readWSMessages()

	c.Lock()
	defer c.Unlock()
	// make sure there is only one routing processing cipher messages
	if c.decryptedMessageChan != nil {
		return c.decryptedMessageChan
	}
	c.decryptedMessageChan = make(chan *Message, 1000)

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for message := range c.wsMessageChan {
			var batchMessage struct {
				BatchID  string     `json:"batch_id"`
				Messages []*Message `json:"messages"`
			}
			if err := json.Unmarshal(message, &batchMessage); err != nil {
				log.WithError(err).Error("can not decode batch message")
				continue
			}

			for _, m := range batchMessage.Messages {
				sc := c.messagingClient.SessionCipher(m.Source, uint32(m.SourceDevice))

			sw_type:
				switch m.Type {
				case MessageTypeCiphertext:
					wm, err := axolotl.LoadWhisperMessage(m.Content)
					if err != nil {
						log.WithError(err).Error("LoadWhisperMessage")
						break sw_type
					}

					plaintext, err := sc.SessionDecryptWhisperMessage(wm)
					if err != nil {
						log.WithError(err).Error("SessionDecryptWhisperMessage")
						break sw_type
					}

					m.Content = plaintext
					c.decryptedMessageChan <- m

				case MessageTypePrekeyBundle:
					pkwm, err := axolotl.LoadPreKeyWhisperMessage(m.Content)
					if err != nil {
						log.WithError(err).Debug("LoadPreKeyWhisperMessage")
						break sw_type
					}

					plaintext, err := sc.SessionDecryptPreKeyWhisperMessage(pkwm)
					if err != nil {
						log.WithError(err).Debug("SessionDecryptPreKeyWhisperMessage")
						break sw_type
					}

					m.Content = plaintext
					c.decryptedMessageChan <- m

				default:
					err := errors.New("unsupported message type")
					log.WithError(err).Debug("message type decode")
				}
			}

			// cleanup processed messages
			log.WithField("batch_id", batchMessage.BatchID).Debug("remove processed messages")
			commandRequest := MessagingCommand{
				ID:      time.Now().String(),
				Command: "delete_messages",
				Args:    []interface{}{batchMessage.BatchID},
			}
			resp := c.Command(commandRequest)

			log.WithField("response", resp).WithField("batch_id", batchMessage.BatchID).Debug("delete batch messages")
		}
		log.Debug("message channel closed")
	}()

	return c.decryptedMessageChan
}
