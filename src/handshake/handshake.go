// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/handshake/handshake.go
package security

import (
	"errors"
	"log"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// handshakeLatency tracks the latency of handshakes.
	handshakeLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "kyber_handshake_latency_seconds",
			Help:    "Latency of Kyber768 handshakes",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"protocol"},
	)

	// handshakeErrors counts handshake failures.
	handshakeErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kyber_handshake_errors_total",
			Help: "Total number of Kyber768 handshake errors",
		},
		[]string{"protocol"},
	)
)

// register tolerates duplicate registration instead of panicking at import time.
func register(c prometheus.Collector) {
	if err := prometheus.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if !errors.As(err, &already) {
			log.Printf("handshake: failed to register metric: %v", err)
		}
	}
}

func init() {
	register(handshakeLatency)
	register(handshakeErrors)
}

// NewHandshake initializes a Handshake with metrics and the default timeout.
// Set Auth on the result to authenticate peers.
func NewHandshake() *Handshake {
	return &Handshake{
		Metrics: &HandshakeMetrics{Latency: handshakeLatency, Errors: handshakeErrors},
		Timeout: DefaultHandshakeTimeout,
	}
}

// PerformHandshake runs the hybrid key exchange on conn.
func (h *Handshake) PerformHandshake(conn net.Conn, protocol string, isInitiator bool) (*EncryptionKey, error) {
	if h == nil {
		h = NewHandshake()
	}
	start := time.Now()

	enc, err := PerformKEMWithAuth(conn, isInitiator, h.Auth, h.Timeout)
	if err != nil {
		if h.Metrics != nil && h.Metrics.Errors != nil {
			h.Metrics.Errors.WithLabelValues(protocol).Inc()
		}
		log.Printf("handshake error for %s: %v", protocol, err)
		return nil, err
	}

	if h.Metrics != nil && h.Metrics.Latency != nil {
		h.Metrics.Latency.WithLabelValues(protocol).Observe(time.Since(start).Seconds())
	}
	log.Printf("handshake successful for %s (peer authenticated: %t)", protocol, enc.PeerAuthenticated)
	return enc, nil
}
