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

	uuid "github.com/jackc/pgtype/ext/gofrs-uuid"
	"github.com/signal-golang/textsecure/axolotl"
	protobuf "github.com/signal-golang/textsecure/axolotl/protobuf"
	"github.com/signal-golang/textsecure/curve25519sign"
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
	username          string
	apiClient         *apiClient
	privateKeyStore   PrivateKeyStore
	identityStore     axolotl.IdentityStore
	preKeyStore       axolotl.PreKeyStore
	signedPreKeyStore axolotl.SignedPreKeyStore
	sessionStore      axolotl.SessionStore
}

func New(httpClient *http.Client, endpoint, username, password, storePath string) *Client {
	apiClient := newAPIClient(httpClient, endpoint, username, password)
	store := newLevelDBAxolotlStore(storePath)
	return &Client{username, apiClient, store, store, store, store, store}
}

func (c *Client) Init() {

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

	_, err = c.identityStore.GetLocalRegistrationID()
	if err != nil {
		switch err {
		case leveldb.ErrNotFound:
			// TODO: MAKE 1
			if err := c.privateKeyStore.StoreRegistrationID(1); err != nil {
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

	preKeys := make([]PreKey, 0)
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
		preKeys = append(preKeys, PreKey{ID: id, PublicKey: preKey.PublicKey.Key()[:]})
	}
	fmt.Println(preKeys)

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
	if err := c.apiClient.addKeys(context.Background(), identityKey.PublicKey.Key()[:], preKeys, signedPreKey); err != nil {
		return err
	}

	fmt.Println(identityKey, preKeys, signedPreKey, err)

	return nil
}

func (c *Client) SendMessages(recipientID string, deviceID uint32, messages [][]byte) error {
	if !c.sessionStore.ContainsSession(recipientID, deviceID) {
		preKeyState, err := c.apiClient.getRecipientKey(context.Background(), recipientID, deviceID)
		if err != nil {
			return err
		}

		if len(preKeyState.Devices) < 1 {
			return errors.New("registration of recipient not completed")
		}

		device := new(Device)
		for _, d := range preKeyState.Devices {
			if d.ID == deviceID {
				device = &d
			}
		}
		if device == nil {
			return fmt.Errorf("recipient device %d not exists", deviceID)
		}

		// TODO: determine key serialization format
		pkb, err := axolotl.NewPreKeyBundle(
			device.RegistrationID, device.ID,
			device.PreKey.ID, axolotl.NewECPublicKey(device.PreKey.PublicKey),
			int32(device.SignedPreKey.ID), axolotl.NewECPublicKey(device.SignedPreKey.PublicKey), device.SignedPreKey.Signature,
			axolotl.NewIdentityKey(preKeyState.IdentityKey),
		)
		if err != nil {
			return err
		}

		sb := axolotl.NewSessionBuilder(c.identityStore, c.preKeyStore, c.signedPreKeyStore, c.sessionStore, recipientID, deviceID)
		if err = sb.BuildSenderSession(pkb); err != nil {
			return err
		}
	}

	sc := axolotl.NewSessionCipher(c.identityStore, c.preKeyStore, c.signedPreKeyStore, c.sessionStore, recipientID, deviceID)
	registrationID, err := sc.GetRemoteRegistrationID()
	if err != nil {
		return err
	}

	encryptedMessages := make([]Message, 0)
	for _, m := range messages {
		ciphertext, msgType, err := sc.SessionEncryptMessage(m)
		if err != nil {
			return err
		}

		encryptedMessages = append(encryptedMessages, Message{
			Type:               msgType,
			DestDeviceID:       deviceID,
			DestRegistrationID: registrationID,
			Content:            ciphertext,
		})
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
		pkwm, err := axolotl.LoadPreKeyWhisperMessage(m.Content)
		if err != nil {
			return nil, false, err
		}

		if m.Type != messageTypePrekeyBundle {
			return nil, false, err
		}

		plaintext, err := sc.SessionDecryptPreKeyWhisperMessage(pkwm)
		if err != nil {
			return nil, false, err
		}

		m.Content = plaintext
		decryptedMessages = append(decryptedMessages, m)
	}

	return decryptedMessages, more, nil
}

func (c *Client) DeleteMessage(guid uuid.UUID) error {
	// c.apiClient.

	return nil
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
