package messaging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/bitmark-inc/autonomy-wallet-server/store"
)

const (
	MessageTypeUnknown = iota
	MessageTypeCiphertext
	MessageTypeKeyExchange
	MessageTypePrekeyBundle
	MessageTypeReceipt
	MessageTypeUnidentifiedSender
)

const (
	publicKeyVersion = byte(5)
)

type apiClient struct {
	httpClient *http.Client
	endpoint   string
	jwt        string
	log        *logrus.Entry
}

type AccountAttributes struct {
	RegistrationID uint32 `json:"registrationId"`
}

type PrekeyState struct {
	IdentityKey []byte   `json:"identityKey"`
	Devices     []Device `json:"devices"`
}

type Device struct {
	ID             uint32       `json:"deviceId"`
	RegistrationID uint32       `json:"registrationId"`
	SignedPreKey   SignedPreKey `json:"signedPreKey"`
	PreKey         PreKey       `json:"preKey"`
}

type SignedPreKey struct {
	ID        uint32 `json:"keyId"`
	PublicKey []byte `json:"publicKey"`
	Signature []byte `json:"signature"`
}

type PreKey struct {
	ID        uint32 `json:"keyId"`
	PublicKey []byte `json:"publicKey"`
}

type Messages struct {
	Destination string    `json:"destination"`
	Messages    []Message `json:"messages"`
	Timestamp   int64     `json:"timestamp"`
}

type Message struct {
	Guid               uuid.UUID `json:"guid"`
	Type               int32     `json:"type"`
	Source             string    `json:"source"`
	SourceDevice       uint32    `json:"sourceDevice"`
	DestDeviceID       uint32    `json:"destinationDeviceId"`
	DestRegistrationID uint32    `json:"destinationRegistrationId"`
	Content            []byte    `json:"content"`
	ServerTimestamp    int64     `json:"serverTimestamp"`
}

func newAPIClient(httpClient *http.Client, endpoint, jwt string) *apiClient {
	return &apiClient{
		httpClient: httpClient,
		endpoint:   endpoint,
		jwt:        jwt,
		log:        logrus.WithField("prefix", "messaging_api"),
	}
}

func (c *apiClient) createRequest(ctx context.Context, method, path string, body interface{}) (*http.Request, error) {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(body); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, buf)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.jwt)
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

func (c *apiClient) registerAccount(ctx context.Context, registrationID uint32) error {
	body := struct {
		SignalAccountAttributes AccountAttributes `json:"signal_account_attributes"`
		DisableWallet           bool
		Invitation              string
	}{
		SignalAccountAttributes: AccountAttributes{RegistrationID: registrationID},
		DisableWallet:           true,
		Invitation:              store.MagicInvitationCode,
	}

	req, err := c.createRequest(ctx, "POST", "/api/accounts", body)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dumpedRequest, err := httputil.DumpRequest(req, true)
		if err != nil {
			c.log.Error("unable to dump the request")
		}
		c.log.WithField("req", string(dumpedRequest)).Debug("unable to create the messaging account")

		dumpedResponse, err := httputil.DumpResponse(resp, true)
		if err != nil {
			c.log.Error("unable to dump the response")
		}
		c.log.WithContext(ctx).WithField("resp", string(dumpedResponse)).Debug("unable to create the messaging account")

		return errors.New("unable to create the messaging account")
	}

	return nil
}

func (c *apiClient) registerTemporaryAccount(ctx context.Context, registrationID uint32) error {
	body := struct {
		SignalAccountAttributes AccountAttributes `json:"signal_account_attributes"`
	}{
		AccountAttributes{RegistrationID: registrationID},
	}

	req, err := c.createRequest(ctx, "POST", "/api/recover", body)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dumpedRequest, err := httputil.DumpRequest(req, true)
		if err != nil {
			c.log.Error("unable to dump the request")
		}
		c.log.WithField("req", string(dumpedRequest)).Debug("unable to acquire a temporary messaging account")

		dumpedResponse, err := httputil.DumpResponse(resp, true)
		if err != nil {
			c.log.Error("unable to dump the response")
		}
		c.log.WithContext(ctx).WithField("resp", string(dumpedResponse)).Debug("unable to acquire a temporary messaging account")

		return errors.New("unable to acquire a temporary messaging account")
	}

	return nil
}

func (c *apiClient) addKeys(ctx context.Context, identityKey []byte, preKeys []*PreKey, signedPreKey *SignedPreKey) error {
	identityKey = append([]byte{publicKeyVersion}, identityKey...)
	for _, pk := range preKeys {
		pk.PublicKey = append([]byte{publicKeyVersion}, pk.PublicKey...)
	}
	signedPreKey.PublicKey = append([]byte{publicKeyVersion}, signedPreKey.PublicKey...)

	body := struct {
		IdentityKey  []byte        `json:"identityKey"`
		PreKeys      []*PreKey     `json:"preKeys"`
		SignedPreKey *SignedPreKey `json:"signedPreKey"`
	}{
		identityKey, preKeys, signedPreKey,
	}

	req, err := c.createRequest(ctx, "PUT", "/api/messaging/keys", body)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dumpedRequest, err := httputil.DumpRequest(req, true)
		if err != nil {
			c.log.Error("unable to dump the request")
		}
		c.log.WithField("req", string(dumpedRequest)).Debug("unable to add keys")

		dumpedResponse, err := httputil.DumpResponse(resp, true)
		if err != nil {
			c.log.Error("unable to dump the response")
		}
		c.log.WithContext(ctx).WithField("resp", string(dumpedResponse)).Debug("unable to add keys")

		return errors.New("unable to add keys")
	}

	return nil
}

func (c *apiClient) getRecipientKey(ctx context.Context, recipientID string, deviceID uint32) (*PrekeyState, error) {
	req, err := c.createRequest(ctx, "GET", fmt.Sprintf("/api/messaging/keys/%s/%d", recipientID, deviceID), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dumpedRequest, err := httputil.DumpRequest(req, true)
		if err != nil {
			c.log.Error("unable to dump the request")
		}
		c.log.WithField("req", string(dumpedRequest)).Debug("get recipient keys")

		dumpedResponse, err := httputil.DumpResponse(resp, true)
		if err != nil {
			c.log.Error("unable to dump the response")
		}
		c.log.WithContext(ctx).WithField("resp", string(dumpedResponse)).Debug("get recipient keys")

		return nil, errors.New("unable to get keys")
	}

	var prekeyState PrekeyState
	if err := json.NewDecoder(resp.Body).Decode(&prekeyState); err != nil {
		return nil, errors.New("unable to read prekey state")
	}

	return &prekeyState, nil
}

func (c *apiClient) getAvailablePreKeyCount(ctx context.Context) (int, error) {
	req, err := c.createRequest(ctx, "GET", "/api/messaging/keys", nil)
	if err != nil {
		return 0, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, errors.New("unable to get keys")
	}

	var result struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, errors.New("unable to read prekey state")
	}

	return result.Count, nil
}

func (c *apiClient) sendMessages(ctx context.Context, recipientID string, msgs []Message, ts int64) error {
	messages := Messages{
		Destination: recipientID,
		Messages:    msgs,
		Timestamp:   ts,
	}
	req, err := c.createRequest(ctx, "PUT", fmt.Sprintf("/api/messaging/messages/%s", recipientID), messages)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dumpedRequest, err := httputil.DumpRequest(req, true)
		if err != nil {
			c.log.Error("unable to dump the request")
		}
		c.log.WithField("req", string(dumpedRequest)).Debug("unable to send messages")

		dumpedResponse, err := httputil.DumpResponse(resp, true)
		if err != nil {
			c.log.Error("unable to dump the response")
		}
		c.log.WithContext(ctx).WithField("resp", string(dumpedResponse)).Debug("unable to send messages")

		return errors.New("unable to send messages")
	}

	return nil
}

func (c *apiClient) getMessages(ctx context.Context) ([]*Message, bool, error) {
	req, err := c.createRequest(ctx, "GET", fmt.Sprintf("/api/messaging/messages"), nil)
	if err != nil {
		return nil, false, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dumpedRequest, err := httputil.DumpRequest(req, true)
		if err != nil {
			c.log.Error("unable to dump the request")
		}
		c.log.WithField("req", string(dumpedRequest)).Debug("unable to retrieve messages")

		dumpedResponse, err := httputil.DumpResponse(resp, true)
		if err != nil {
			c.log.Error("unable to dump the response")
		}
		c.log.WithContext(ctx).WithField("resp", string(dumpedResponse)).Debug("unable to retrieve messages")

		return nil, false, errors.New("unable to retrieve messages")
	}

	var response struct {
		Messages []*Message `json:"messages"`
		More     bool       `json:"more"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, false, err
	}

	return response.Messages, response.More, nil
}

func (c *apiClient) deleteMessage(ctx context.Context, guid uuid.UUID) error {
	req, err := c.createRequest(ctx, "DELETE", fmt.Sprintf("/api/messaging/messages/uuid/%s", guid.String()), nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dumpedResponse, err := httputil.DumpResponse(resp, true)
		if err != nil {
			c.log.Error("unable to dump the response")
		}
		c.log.WithContext(ctx).WithField("resp", string(dumpedResponse)).Debug("unable to delete the message")

		return errors.New("unable to delete the message")
	}

	return nil
}
