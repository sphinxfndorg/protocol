// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/handshake/types.go

package security

import (
	"crypto/cipher"
	"encoding/json"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Message represents a secure P2P or RPC message.
type Message struct {
	Type string `json:"type"`
	// Data is kept as json.RawMessage so callers can decode it into the exact
	// concrete type they expect. It must remain RawMessage end-to-end.
	Data json.RawMessage `json:"data"`
	// Metadata carries optional in-process context (e.g. request_id). It is
	// not marshaled into the transport payload.
	Metadata map[string]interface{} `json:"-"`
}

// Authenticator authenticates the peer during the handshake. Without one the
// key exchange is unauthenticated and can be intercepted by a man in the
// middle, even though it is post-quantum.
//
// Prove returns this node's proof over digest (e.g. a SPHINCS+ signature plus
// public key). Verify checks the peer's proof over the digest and MUST also
// check that the peer's public key is one you trust (registry / allow-list),
// otherwise anyone can authenticate as themselves.
type Authenticator interface {
	Prove(digest []byte) ([]byte, error)
	Verify(digest, proof []byte) error
}

// Handshake manages secure channel handshakes.
type Handshake struct {
	Metrics *HandshakeMetrics
	// Timeout bounds the whole handshake (default DefaultHandshakeTimeout).
	Timeout time.Duration
	// Auth, if non-nil, authenticates the peer. nil = unauthenticated.
	Auth Authenticator
}

// HandshakeMetrics encapsulates Prometheus metrics.
type HandshakeMetrics struct {
	Latency *prometheus.HistogramVec
	Errors  *prometheus.CounterVec
}

// EncryptionKey holds the cryptographic state of a secure session.
//
// Sessions made by the handshake use two independent keys (one per direction),
// counter nonces and a replay window. Keys made by the legacy NewEncryptionKey
// use one key with random nonces and no replay protection.
type EncryptionKey struct {
	SharedSecret []byte
	AESGCM       cipher.AEAD // send-direction AEAD (kept for compatibility)

	// PeerAuthenticated is true only if an Authenticator verified the peer.
	PeerAuthenticated bool

	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD

	sendMu  sync.Mutex
	sendSeq uint64

	recvMu     sync.Mutex
	recvAny    bool
	recvMax    uint64
	recvBitmap uint64 // bit i set => (recvMax - i) already accepted
}
