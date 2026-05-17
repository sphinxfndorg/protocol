// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/rpc/metrics.go
package rpc

import (
	"github.com/prometheus/client_golang/prometheus"
)

// NewMetrics initializes Prometheus metrics for the RPC server.
func NewMetrics() *Metrics {
	return &Metrics{
		RequestCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rpc_request_count",
				Help: "Number of RPC requests received",
			},
			[]string{"method"},
		),
		RequestLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rpc_request_latency_seconds",
				Help:    "Latency of RPC requests",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method"},
		),
		ErrorCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rpc_error_count",
				Help: "Number of RPC errors",
			},
			[]string{"method"},
		),
	}
}
