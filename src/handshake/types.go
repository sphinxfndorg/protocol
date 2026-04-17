// MIT License
//
// # Copyright (c) 2024 sphinx-core
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

// go/src/handshake/types.go
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
