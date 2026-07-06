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

		// Ops/RPC hardening: additional Prometheus metrics
		SyncProgress: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "rpc_sync_progress_percent",
				Help: "Sync progress percentage (0-100)",
			},
			[]string{"node_id"},
		),
		ConsensusLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rpc_consensus_latency_seconds",
				Help:    "Consensus round latency in seconds",
				Buckets: []float64{0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0},
			},
			[]string{"node_id", "phase"},
		),
		MempoolEvictions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rpc_mempool_evictions_total",
				Help: "Total number of mempool evictions",
			},
			[]string{"reason"},
		),
	}
}
