package messaging

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/signal-golang/textsecure/axolotl"
	protobuf "github.com/signal-golang/textsecure/axolotl/protobuf"
	"github.com/signal-golang/textsecure/curve25519sign"
	"github.com/sirupsen/logrus"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	preKeyMinimumInventoryCount = 35
	preKeyGenerationCount       = 100
)

type PrivateKeyStore interface {
	StoreIdentityKeyPair(*axolotl.IdentityKeyPair) error
	StoreRegistrationID(uint32) error
}

type Client struct {
	apiClient         *apiClient
	privateKeyStore   PrivateKeyStore
	identityStore     axolotl.IdentityStore
	preKeyStore       axolotl.PreKeyStore
	signedPreKeyStore axolotl.SignedPreKeyStore
	sessionStore      axolotl.SessionStore
	log               *logrus.Entry
}

func New(httpClient *http.Client, endpoint, jwt, storePath string) *Client {
	apiClient := newAPIClient(httpClient, endpoint, jwt)
	store := newLevelDBAxolotlStore(storePath)
	return &Client{
		apiClient:         apiClient,
		privateKeyStore:   store,
		identityStore:     store,
		preKeyStore:       store,
		signedPreKeyStore: store,
		sessionStore:      store,
		log:               logrus.WithField("prefix", "messaging_client"),
	}
}

func (c *Client) RegisterAccount() error {
	registrationID, err := c.identityStore.GetLocalRegistrationID()
	if err != nil {
		switch err {
		case leveldb.ErrNotFound:
			registrationID = generateRegistrationID()
			if err := c.privateKeyStore.StoreRegistrationID(registrationID); err != nil {
				return err
			}
		default:
			return err
		}
	}

	return c.apiClient.registerAccount(context.Background(), registrationID)
}

func (c *Client) RegisterTemporaryAccount() error {
	registrationID, err := c.identityStore.GetLocalRegistrationID()
	if err != nil {
		switch err {
		case leveldb.ErrNotFound:
			registrationID = generateRegistrationID()
			if err := c.privateKeyStore.StoreRegistrationID(registrationID); err != nil {
				return err
			}
		default:
			return err
		}
	}

	return c.apiClient.registerTemporaryAccount(context.Background(), registrationID)
}

func (c *Client) RegisterKeys() error {
	identityKey, err := c.identityStore.GetIdentityKeyPair()
	if err != nil {
		switch err {
		case leveldb.ErrNotFound:
			identityKey = axolotl.GenerateIdentityKeyPair()
			if err := c.privateKeyStore.StoreIdentityKeyPair(identityKey); err != nil {
				return err
			}
		default:
			return err
		}
	}

	inventoryCount, err := c.apiClient.getAvailablePreKeyCount(context.Background())
	if err != nil {
		return err
	}
	if inventoryCount >= preKeyMinimumInventoryCount {
		return nil
	}

	// generate pre keys
	nextPreKeyID := randID()

	preKeys := make([]*PreKey, 0)
	for i := 0; i < preKeyGenerationCount; i++ {
		id := nextPreKeyID
		preKey := axolotl.NewECKeyPair()
		preKeyRecord := &axolotl.PreKeyRecord{
			Pkrs: &protobuf.PreKeyRecordStructure{
				Id:         &id,
				PublicKey:  preKey.PublicKey.Key()[:],
				PrivateKey: preKey.PrivateKey.Key()[:],
			},
		}
		if err := c.preKeyStore.StorePreKey(id, preKeyRecord); err != nil {
			return err
		}

		nextPreKeyID += 1
		preKeys = append(preKeys, &PreKey{ID: id, PublicKey: preKey.PublicKey.Key()[:]})
	}

	// generate signed pre key
	ts := uint64(time.Now().UTC().Second())
	key := axolotl.NewECKeyPair()
	var random [64]byte
	io.ReadFull(rand.Reader, random[:])
	signature := curve25519sign.Sign(identityKey.PrivateKey.Key(), key.PublicKey.Serialize(), random)
	signedPreKeyID := randID()
	signedPreKey := SignedPreKey{signedPreKeyID, key.PublicKey.Key()[:], signature[:]}
	signedPreKeyRecord := &axolotl.SignedPreKeyRecord{
		Spkrs: &protobuf.SignedPreKeyRecordStructure{
			Id:         &signedPreKeyID,
			PublicKey:  key.PublicKey.Key()[:],
			PrivateKey: key.PrivateKey.Key()[:],
			Signature:  signature[:],
			Timestamp:  &ts,
		},
	}
	if err := c.signedPreKeyStore.StoreSignedPreKey(signedPreKeyID, signedPreKeyRecord); err != nil {
		return err
	}

	// send keys
	if err := c.apiClient.addKeys(context.Background(), identityKey.PublicKey.Key()[:], preKeys, &signedPreKey); err != nil {
		return err
	}

	return nil
}

// SessionCipher returns a session cipher with a specific recipient id and device id
func (c *Client) SessionCipher(recipientID string, deviceID uint32) *axolotl.SessionCipher {
	return axolotl.NewSessionCipher(c.identityStore, c.preKeyStore, c.signedPreKeyStore, c.sessionStore, recipientID, deviceID)
}

// PrepareEncryptedMessages generates encrypted messages by local session and remote recipient key
func (c *Client) PrepareEncryptedMessages(recipientID string, deviceID uint32, messages [][]byte) ([]Message, error) {
	if !c.sessionStore.ContainsSession(recipientID, deviceID) {
		preKeyState, err := c.apiClient.getRecipientKey(context.Background(), recipientID, deviceID)
		if err != nil {
			return nil, err
		}

		if len(preKeyState.Devices) < 1 {
			return nil, errors.New("registration of recipient not completed")
		}

		device := new(Device)
		for _, d := range preKeyState.Devices {
			if d.ID == deviceID {
				device = &d
			}
		}
		if device == nil {
			return nil, fmt.Errorf("recipient device %d not exists", deviceID)
		}

		pkb, err := axolotl.NewPreKeyBundle(
			device.RegistrationID, device.ID,
			device.PreKey.ID, axolotl.NewECPublicKey(device.PreKey.PublicKey[1:]),
			int32(device.SignedPreKey.ID), axolotl.NewECPublicKey(device.SignedPreKey.PublicKey[1:]), device.SignedPreKey.Signature,
			axolotl.NewIdentityKey(preKeyState.IdentityKey[1:]),
		)
		if err != nil {
			return nil, err
		}

		sb := axolotl.NewSessionBuilder(c.identityStore, c.preKeyStore, c.signedPreKeyStore, c.sessionStore, recipientID, deviceID)
		if err = sb.BuildSenderSession(pkb); err != nil {
			return nil, err
		}
	}

	sc := axolotl.NewSessionCipher(c.identityStore, c.preKeyStore, c.signedPreKeyStore, c.sessionStore, recipientID, deviceID)
	registrationID, err := sc.GetRemoteRegistrationID()
	if err != nil {
		return nil, err
	}

	encryptedMessages := make([]Message, 0)
	for _, m := range messages {
		ciphertext, msgType, err := sc.SessionEncryptMessage(m)
		if err != nil {
			return nil, err
		}

		encryptedMessages = append(encryptedMessages, Message{
			Type:               msgType,
			DestDeviceID:       deviceID,
			DestRegistrationID: registrationID,
			Content:            ciphertext,
		})
	}

	return encryptedMessages, nil
}

func (c *Client) SendMessages(recipientID string, deviceID uint32, messages [][]byte) error {
	encryptedMessages, err := c.PrepareEncryptedMessages(recipientID, deviceID, messages)
	if err != nil {
		return err
	}

	if err := c.apiClient.sendMessages(context.Background(), recipientID, encryptedMessages, time.Now().Unix()); err != nil {
		return err
	}

	return nil
}

func (c *Client) ReceiveMessages() ([]*Message, bool, error) {
	messages, more, err := c.apiClient.getMessages(context.Background())
	if err != nil {
		return nil, false, err
	}

	decryptedMessages := make([]*Message, 0)
	for _, m := range messages {
		sc := axolotl.NewSessionCipher(c.identityStore, c.preKeyStore, c.signedPreKeyStore, c.sessionStore, m.Source, uint32(m.SourceDevice))

	sw_type:
		switch m.Type {
		case MessageTypeCiphertext:
			wm, err := axolotl.LoadWhisperMessage(m.Content)
			if err != nil {
				c.log.WithError(err).Debug("LoadWhisperMessage")
				break sw_type
			}

			plaintext, err := sc.SessionDecryptWhisperMessage(wm)
			if err != nil {
				c.log.WithError(err).Debug("SessionDecryptWhisperMessage")
				break sw_type
			}

			m.Content = plaintext
			decryptedMessages = append(decryptedMessages, m)

		case MessageTypePrekeyBundle:
			pkwm, err := axolotl.LoadPreKeyWhisperMessage(m.Content)
			if err != nil {
				c.log.WithError(err).Debug("LoadPreKeyWhisperMessage")
				break sw_type
			}

			plaintext, err := sc.SessionDecryptPreKeyWhisperMessage(pkwm)
			if err != nil {
				c.log.WithError(err).Debug("SessionDecryptPreKeyWhisperMessage")
				break sw_type
			}

			m.Content = plaintext
			decryptedMessages = append(decryptedMessages, m)
		default:
			err = errors.New("unsupported message type")
			c.log.WithError(err).Debug("message type decode")
		}
		err = c.apiClient.deleteMessage(context.Background(), m.Guid)
		c.log.WithError(err).Debug("delete message")
	}

	return decryptedMessages, more, nil
}

func generateRegistrationID() uint32 {
	return randUint32() & 0x3fff
}

func randID() uint32 {
	return randUint32() & 0xffffff
}

func randUint32() uint32 {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint32(b)
}
