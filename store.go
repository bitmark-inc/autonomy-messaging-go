// SPDX-License-Identifier: ISC
// Copyright (c) 2019-2021 Bitmark Inc.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package messaging

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/signal-golang/textsecure/axolotl"
	"github.com/syndtr/goleveldb/leveldb"
)

type LevelDBAxolotlStore struct {
	sync.Mutex
	db *leveldb.DB
}

func newLevelDBAxolotlStore(path string) *LevelDBAxolotlStore {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		panic(err)
	}
	s := &LevelDBAxolotlStore{db: db}
	return s
}

//
func (l *LevelDBAxolotlStore) StoreIdentityKeyPair(kp *axolotl.IdentityKeyPair) error {
	data := make([]byte, 64)
	copy(data, kp.PublicKey.Key()[:])
	copy(data[32:], kp.PrivateKey.Key()[:])
	return l.db.Put([]byte("identity"), data, nil)
}

func (l *LevelDBAxolotlStore) StoreRegistrationID(id uint32) error {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, id)
	return l.db.Put([]byte("regid"), data, nil)
}

// IdentityStore
func (l *LevelDBAxolotlStore) GetIdentityKeyPair() (*axolotl.IdentityKeyPair, error) {
	data, err := l.db.Get([]byte("identity"), nil)
	if err != nil {
		return nil, err
	}

	if len(data) != 64 {
		return nil, fmt.Errorf("invalid identity key length: %d", len(data))
	}
	return axolotl.NewIdentityKeyPairFromKeys(data[32:], data[:32]), nil
}

func (l *LevelDBAxolotlStore) GetLocalRegistrationID() (uint32, error) {
	data, err := l.db.Get([]byte("regid"), nil)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(data), nil
}

func (l *LevelDBAxolotlStore) SaveIdentity(id string, key *axolotl.IdentityKey) error {
	// TODO: add the implementation when used
	return nil
}

func (l *LevelDBAxolotlStore) IsTrustedIdentity(string, *axolotl.IdentityKey) bool {
	return true
}

// PreKeyStore
func (l *LevelDBAxolotlStore) LoadPreKey(id uint32) (*axolotl.PreKeyRecord, error) {
	if !l.ContainsPreKey(id) {
		return nil, fmt.Errorf("key %d not found", id)
	}

	data, err := l.db.Get(l.preKeyID(id), nil)
	if err != nil {
		return nil, err
	}

	pkr, err := axolotl.LoadPreKeyRecord(data)
	if err != nil {
		return nil, err
	}
	return pkr, nil
}

func (l *LevelDBAxolotlStore) StorePreKey(id uint32, r *axolotl.PreKeyRecord) error {
	data, err := r.Serialize()
	if err != nil {
		return err
	}
	return l.db.Put(l.preKeyID(id), data, nil)
}

func (l *LevelDBAxolotlStore) ContainsPreKey(id uint32) bool {
	ok, _ := l.db.Has(l.preKeyID(id), nil)
	return ok
}

func (l *LevelDBAxolotlStore) RemovePreKey(id uint32) {
	l.db.Delete(l.preKeyID(id), nil)
}

// SignedPreKeyStore
func (l *LevelDBAxolotlStore) LoadSignedPreKey(id uint32) (*axolotl.SignedPreKeyRecord, error) {
	if !l.ContainsSignedPreKey(id) {
		return nil, fmt.Errorf("key %d not found", id)
	}

	data, err := l.db.Get(l.signedPreKeyID(id), nil)
	if err != nil {
		return nil, err
	}

	pkr, err := axolotl.LoadSignedPreKeyRecord(data)
	if err != nil {
		return nil, err
	}
	return pkr, nil
}

func (l *LevelDBAxolotlStore) LoadSignedPreKeys() []axolotl.SignedPreKeyRecord {
	return []axolotl.SignedPreKeyRecord{} // not used
}

func (l *LevelDBAxolotlStore) StoreSignedPreKey(id uint32, r *axolotl.SignedPreKeyRecord) error {
	data, err := r.Serialize()
	if err != nil {
		return err
	}
	return l.db.Put(l.signedPreKeyID(id), data, nil)
}

func (l *LevelDBAxolotlStore) ContainsSignedPreKey(id uint32) bool {
	ok, _ := l.db.Has(l.signedPreKeyID(id), nil)
	return ok
}

func (l *LevelDBAxolotlStore) RemoveSignedPreKey(id uint32) {
	l.db.Delete(l.signedPreKeyID(id), nil)
}

// SessionStore
func (l *LevelDBAxolotlStore) LoadSession(recipientID string, deviceID uint32) (*axolotl.SessionRecord, error) {
	sessionID := l.sessionID(recipientID, deviceID)

	if !l.ContainsSession(recipientID, deviceID) {
		return axolotl.NewSessionRecord(), nil
	}

	data, err := l.db.Get(sessionID, nil)
	if err != nil {
		return nil, err
	}

	pkr, err := axolotl.LoadSessionRecord(data)
	if err != nil {
		return nil, err
	}
	return pkr, nil
}

func (l *LevelDBAxolotlStore) GetSubDeviceSessions(string) []uint32 {
	// TODO: add the implementation when used
	return nil
}

func (l *LevelDBAxolotlStore) StoreSession(recipientID string, deviceID uint32, r *axolotl.SessionRecord) error {
	data, err := r.Serialize()
	if err != nil {
		return err
	}
	return l.db.Put(l.sessionID(recipientID, deviceID), data, nil)
}

func (l *LevelDBAxolotlStore) ContainsSession(recipientID string, deviceID uint32) bool {
	ok, _ := l.db.Has(l.sessionID(recipientID, deviceID), nil)
	return ok
}

func (l *LevelDBAxolotlStore) DeleteSession(recipientID string, deviceID uint32) {
	l.db.Delete(l.sessionID(recipientID, deviceID), nil)
}

func (l *LevelDBAxolotlStore) DeleteAllSessions(string) {
	// TODO: add the implementation when used
}

func (l *LevelDBAxolotlStore) preKeyID(id uint32) []byte {
	return []byte(fmt.Sprintf("prekey_%d", id))
}

func (l *LevelDBAxolotlStore) signedPreKeyID(id uint32) []byte {
	return []byte(fmt.Sprintf("signedprekey_%d", id))
}

func (l *LevelDBAxolotlStore) sessionID(recipientID string, deviceID uint32) []byte {
	return []byte(fmt.Sprintf("session_%s_%d", recipientID, deviceID))
}
