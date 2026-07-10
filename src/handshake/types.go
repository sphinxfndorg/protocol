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
	Type string `json:"type"`
	// Data is kept as json.RawMessage so callers can decode it into the exact
	// concrete type they expect (e.g. GetBlocksResponse, transactions, blocks).
	// It must remain RawMessage end-to-end; the transport layer will
	// json.Marshal/json.Unmarshal this field.
	Data json.RawMessage `json:"data"`
	// Metadata carries optional key-value context such as request_id for
	// correlating requests with responses. It is not marshaled into the
	// transport payload; instead callers set it before handing the message
	// to in-process handlers.
	Metadata map[string]interface{} `json:"-"`
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
