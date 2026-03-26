// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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

// SIPS-0002 https://github.com/sphinx-core/sips/wiki/SIPS-0002

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
