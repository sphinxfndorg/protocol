// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/sphincs/sign/backend/utils.go
package sign

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"
)

// SIPS-0011 https://github.com/sphinxorg/SIPS/wiki/sips0011

// generateNonce creates a cryptographically secure 16-byte random nonce.
func generateNonce() ([]byte, error) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}

// generateTimestamp creates an 8-byte big-endian Unix timestamp (seconds since epoch).
func generateTimestamp() []byte {
	timestamp := time.Now().Unix()
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp))
	return timestampBytes
}

// PublicKeyRegistry maps a node identity string to its canonical public key bytes.
// Charlie trusts this registry and rejects any transaction whose PK does not match.
type PublicKeyRegistry struct {
	mu      sync.RWMutex
	entries map[string][]byte // nodeID → pkBytes
}

// NewPublicKeyRegistry creates an empty registry.
func NewPublicKeyRegistry() *PublicKeyRegistry {
	return &PublicKeyRegistry{entries: make(map[string][]byte)}
}

// Register stores a trusted public key for a node identity.
// This must be called through a trusted channel (setup, bootstrap, on-chain),
// never from the contents of an unverified incoming message.
func (r *PublicKeyRegistry) Register(nodeID string, pkBytes []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// TOFU: reject attempts to overwrite an already-registered key.
	// An attacker who learns Alice's node ID cannot replace her key by
	// sending a message — the first registration wins.
	if _, exists := r.entries[nodeID]; exists {
		log.Printf("PublicKeyRegistry: rejected attempt to overwrite key for %s", nodeID)
		return
	}
	r.entries[nodeID] = pkBytes
	fmt.Printf("PublicKeyRegistry: registered key for node %q\n", nodeID)
}

// Lookup returns the trusted public key for a node, and false if unknown.
func (r *PublicKeyRegistry) Lookup(nodeID string) ([]byte, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pk, ok := r.entries[nodeID]
	return pk, ok
}

// VerifyIdentity checks that receivedPK matches the registry entry for nodeID.
// This is the identity layer on top of the cryptographic layer.
// Cryptographic checks (proof, commitment, Spx_verify) prove the message was
// signed by whoever owns receivedPK. This check proves receivedPK IS Alice.
func (r *PublicKeyRegistry) VerifyIdentity(nodeID string, receivedPK []byte) bool {
	trustedPK, ok := r.Lookup(nodeID)
	if !ok {
		log.Printf("PublicKeyRegistry: unknown node %q — transaction rejected", nodeID)
		return false
	}
	if !bytes.Equal(trustedPK, receivedPK) {
		log.Printf("PublicKeyRegistry: PK mismatch for %q — possible identity spoofing", nodeID)
		return false
	}
	return true
}
