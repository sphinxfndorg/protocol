// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/handshake/types.go

package security

import (
	"crypto/cipher"
	"encoding/json"

	"github.com/prometheus/client_golang/prometheus"
)

// Message represents a secure P2P or RPC message.
type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"` // This is correct - stays as json.RawMessage
}

// Handshake manages TLS or secure channel handshakes.
type Handshake struct {
	Metrics *HandshakeMetrics
}

// HandshakeMetrics encapsulates Prometheus metrics.
type HandshakeMetrics struct {
	Latency *prometheus.HistogramVec
	Errors  *prometheus.CounterVec
}

// EncryptionKey holds the shared cryptographic material for secure communication.
type EncryptionKey struct {
	SharedSecret []byte
	AESGCM       cipher.AEAD
}
