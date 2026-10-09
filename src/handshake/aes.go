// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/handshake/aes.go
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
)

// MaxSecureMessageSize bounds a single plaintext message (anti memory-DoS).
const MaxSecureMessageSize = 16 << 20 // 16 MiB

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// NewEncryptionKey creates a single-key AES-256-GCM session from a shared secret.
//
// Deprecated: legacy mode (one key for both directions, random nonces, no
// replay protection). Sessions from PerformKEM do not use this.
func NewEncryptionKey(sharedSecret []byte) (*EncryptionKey, error) {
	if len(sharedSecret) < 32 {
		return nil, errors.New("shared secret too short for AES-256")
	}
	aead, err := newGCM(sharedSecret[:32])
	if err != nil {
		return nil, err
	}
	return &EncryptionKey{SharedSecret: sharedSecret, AESGCM: aead}, nil
}

// newDirectionalKey builds a session with separate send and receive keys.
func newDirectionalKey(sendKey, recvKey []byte) (*EncryptionKey, error) {
	if len(sendKey) != 32 || len(recvKey) != 32 {
		return nil, errors.New("session keys must be 32 bytes")
	}
	s, err := newGCM(sendKey)
	if err != nil {
		return nil, err
	}
	r, err := newGCM(recvKey)
	if err != nil {
		return nil, err
	}
	return &EncryptionKey{AESGCM: s, sendAEAD: s, recvAEAD: r}, nil
}

// Close drops the session's key references and wipes any stored secret.
func (enc *EncryptionKey) Close() {
	if enc == nil {
		return
	}
	for i := range enc.SharedSecret {
		enc.SharedSecret[i] = 0
	}
	enc.SharedSecret = nil
	enc.AESGCM, enc.sendAEAD, enc.recvAEAD = nil, nil, nil
}

func seqNonce(seq uint64) []byte {
	n := make([]byte, 12) // 4 zero bytes || 8-byte big-endian counter
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

// Encrypt encrypts plaintext.
//
// Handshake sessions: output = seq(8) || AES-GCM(plaintext), nonce derived from
// seq, seq bound as AAD, never reused (per-direction key + counter).
// Legacy keys: output = nonce(12) || AES-GCM(plaintext).
func (enc *EncryptionKey) Encrypt(plaintext []byte) ([]byte, error) {
	if enc == nil || enc.AESGCM == nil {
		return nil, errors.New("encryption key is nil")
	}
	if len(plaintext) > MaxSecureMessageSize {
		return nil, errors.New("plaintext too large")
	}

	if enc.sendAEAD == nil { // legacy path
		nonce := make([]byte, enc.AESGCM.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		return enc.AESGCM.Seal(nonce, nonce, plaintext, nil), nil
	}

	enc.sendMu.Lock()
	if enc.sendSeq == math.MaxUint64 {
		enc.sendMu.Unlock()
		return nil, errors.New("session send counter exhausted; re-handshake")
	}
	seq := enc.sendSeq
	enc.sendSeq++
	enc.sendMu.Unlock()

	out := make([]byte, 8, 8+len(plaintext)+enc.sendAEAD.Overhead())
	binary.BigEndian.PutUint64(out, seq)
	return enc.sendAEAD.Seal(out, seqNonce(seq), plaintext, out[:8]), nil
}

// acceptSeq records seq in a 64-wide sliding window; false = replay or too old.
func (enc *EncryptionKey) acceptSeq(seq uint64) bool {
	enc.recvMu.Lock()
	defer enc.recvMu.Unlock()
	if !enc.recvAny {
		enc.recvAny, enc.recvMax, enc.recvBitmap = true, seq, 1
		return true
	}
	if seq > enc.recvMax {
		shift := seq - enc.recvMax
		if shift >= 64 {
			enc.recvBitmap = 1
		} else {
			enc.recvBitmap = (enc.recvBitmap << shift) | 1
		}
		enc.recvMax = seq
		return true
	}
	diff := enc.recvMax - seq
	if diff >= 64 {
		return false
	}
	bit := uint64(1) << diff
	if enc.recvBitmap&bit != 0 {
		return false
	}
	enc.recvBitmap |= bit
	return true
}

// Decrypt authenticates and decrypts a message from Encrypt. Replays and
// messages older than the 64-message window are rejected.
func (enc *EncryptionKey) Decrypt(ciphertext []byte) ([]byte, error) {
	if enc == nil || enc.AESGCM == nil {
		return nil, errors.New("encryption key is nil")
	}
	if len(ciphertext) > MaxSecureMessageSize+64 {
		return nil, errors.New("ciphertext too large")
	}

	if enc.recvAEAD == nil { // legacy path
		ns := enc.AESGCM.NonceSize()
		if len(ciphertext) < ns {
			return nil, errors.New("ciphertext too short")
		}
		return enc.AESGCM.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
	}

	if len(ciphertext) < 8+enc.recvAEAD.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	seq := binary.BigEndian.Uint64(ciphertext[:8])
	plaintext, err := enc.recvAEAD.Open(nil, seqNonce(seq), ciphertext[8:], ciphertext[:8])
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	// Check for replay only AFTER authentication, so forged packets cannot
	// poison the window.
	if !enc.acceptSeq(seq) {
		return nil, errors.New("replayed or stale message")
	}
	return plaintext, nil
}

// SecureMessage serializes and encrypts the message.
func SecureMessage(msg *Message, enc *EncryptionKey) ([]byte, error) {
	if msg == nil {
		return nil, errors.New("message is nil")
	}
	if enc == nil {
		return nil, errors.New("encryption key is nil")
	}
	data, err := msg.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode message: %w", err)
	}
	ciphertext, err := enc.Encrypt(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message: %w", err)
	}
	return ciphertext, nil
}

// DecodeSecureMessage decrypts, deserializes and validates an encrypted message.
func DecodeSecureMessage(data []byte, enc *EncryptionKey) (*Message, error) {
	if enc == nil {
		return nil, errors.New("encryption key is nil")
	}
	plaintext, err := enc.Decrypt(data)
	if err != nil {
		return nil, err
	}
	var msg Message
	if err := json.Unmarshal(plaintext, &msg); err != nil {
		return nil, err
	}
	if err := msg.ValidateMessage(); err != nil {
		return nil, err
	}
	return &msg, nil
}
