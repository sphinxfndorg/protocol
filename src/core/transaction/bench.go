// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/transaction/bench.go
package types

import (
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	logger "github.com/sphinxfndorg/protocol/src/log"
)

// NewTPSMonitor creates a new TPS monitor
func NewTPSMonitor(windowDuration time.Duration) *TPSMonitor {
	tm := &TPSMonitor{
		windowStartTime: time.Now(),
		windowDuration:  windowDuration,
		tpsHistory:      make([]float64, 0),
		maxHistorySize:  1000,
		txsPerBlock:     make([]uint64, 0),
	}
	// Background ticker for TPS updates AND window finalization
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		for range ticker.C {
			tm.updateTPS()              // Update current TPS for display
			tm.finalizeWindowIfNeeded() // Finalize window and update peak if needed
		}
	}()
	return tm
}

// RecordTransaction records a new transaction for TPS calculation
func (tm *TPSMonitor) RecordTransaction() {
	// Reset window on first transaction if no transactions yet
	if atomic.LoadUint64(&tm.totalTransactions) == 0 {
		tm.mu.Lock()
		tm.windowStartTime = time.Now()
		atomic.StoreUint64(&tm.currentWindowCount, 0)
		tm.mu.Unlock()
		logger.Info("TPS: Reset window start time on first transaction")
	}

	count := atomic.AddUint64(&tm.totalTransactions, 1)
	windowCount := atomic.AddUint64(&tm.currentWindowCount, 1)
	logger.Info("TPS: Recorded transaction #%d (window: %d)", count, windowCount)
	tm.updateTPS()
}

// RecordBlock records block information for block-based TPS calculation
func (tm *TPSMonitor) RecordBlock(txCount uint64, blockTime time.Duration) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Reset window on first block to align timing
	if !tm.firstBlockRecorded.Load() {
		tm.windowStartTime = time.Now()
		atomic.StoreUint64(&tm.currentWindowCount, 0)
		tm.firstBlockRecorded.Store(true)
		logger.Info("TPS: Reset window start time on first block")
	}

	atomic.AddUint64(&tm.blocksProcessed, 1)
	tm.txsPerBlock = append(tm.txsPerBlock, txCount)

	if blockTime > 0 {
		blockTPS := float64(txCount) / blockTime.Seconds()

		// Cap block TPS at realistic maximum
		const maxReasonableTPS = 10000.0
		cappedBlockTPS := blockTPS
		if blockTPS > maxReasonableTPS {
			logger.Warn("⚠️ Capping unrealistic block TPS: %.2f -> %.2f", blockTPS, maxReasonableTPS)
			cappedBlockTPS = maxReasonableTPS
		}

		logger.Info("📊 Block TPS: %d txs in %v = %.2f TPS", txCount, blockTime, cappedBlockTPS)

		// Add block transactions to current window
		atomic.AddUint64(&tm.currentWindowCount, txCount)
		tm.updateHistory(cappedBlockTPS)

		// Only update peak if this is a COMPLETED WINDOW
		// Check if window has completed
		windowElapsed := time.Since(tm.windowStartTime)
		if windowElapsed >= tm.windowDuration {
			// This is a completed window, safe to update peak
			if cappedBlockTPS > tm.peakTPS && cappedBlockTPS < maxReasonableTPS {
				tm.peakTPS = cappedBlockTPS
				logger.Info("📊 Peak TPS updated from completed window: %.2f", tm.peakTPS)
			}
			// Reset window
			tm.windowStartTime = time.Now()
			atomic.StoreUint64(&tm.currentWindowCount, 0)
		}
	}

	// Keep only recent history
	if len(tm.txsPerBlock) > tm.maxHistorySize {
		tm.txsPerBlock = tm.txsPerBlock[1:]
	}
}

// updateTPS calculates current TPS (for display only, does NOT update peak)
func (tm *TPSMonitor) updateTPS() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	now := time.Now()
	windowElapsed := now.Sub(tm.windowStartTime)
	windowCount := atomic.LoadUint64(&tm.currentWindowCount)

	// Only calculate current TPS for display - NEVER update peak here
	const minElapsed = 100 * time.Millisecond

	if windowElapsed > minElapsed && windowCount > 0 {
		tm.currentTPS = float64(windowCount) / windowElapsed.Seconds()

		// Cap at realistic maximum
		const maxReasonableTPS = 10000.0
		if tm.currentTPS > maxReasonableTPS {
			tm.currentTPS = maxReasonableTPS
		}
	}
	// REMOVED: peak TPS update from here
	// Peak should only come from completed windows in RecordBlock
}

// Add a method to finalize window periodically
func (tm *TPSMonitor) finalizeWindowIfNeeded() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	windowElapsed := time.Since(tm.windowStartTime)
	windowCount := atomic.LoadUint64(&tm.currentWindowCount)

	if windowElapsed >= tm.windowDuration && windowCount > 0 {
		finalTPS := float64(windowCount) / tm.windowDuration.Seconds()

		const maxReasonableTPS = 10000.0
		if finalTPS > tm.peakTPS && finalTPS < maxReasonableTPS {
			tm.peakTPS = finalTPS
			logger.Info("📊 Peak TPS updated from auto-finalized window: %.2f (txs=%d)",
				finalTPS, windowCount)
		}

		// Reset window
		atomic.StoreUint64(&tm.currentWindowCount, 0)
		tm.windowStartTime = time.Now()
	}
}

// updateHistory updates TPS history
func (tm *TPSMonitor) updateHistory(tps float64) {
	tm.tpsHistory = append(tm.tpsHistory, tps)

	// Calculate rolling average
	var sum float64
	for _, val := range tm.tpsHistory {
		sum += val
	}
	tm.averageTPS = sum / float64(len(tm.tpsHistory))

	// Maintain history size
	if len(tm.tpsHistory) > tm.maxHistorySize {
		tm.tpsHistory = tm.tpsHistory[1:]
	}
}

// GetStats returns current TPS statistics
func (tm *TPSMonitor) GetStats() map[string]interface{} {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	// Force read of atomic values
	blocksProc := atomic.LoadUint64(&tm.blocksProcessed)
	totalTx := atomic.LoadUint64(&tm.totalTransactions)
	windowCount := atomic.LoadUint64(&tm.currentWindowCount)

	elapsed := time.Since(tm.windowStartTime)

	// Calculate current TPS
	var currentTPS float64
	if elapsed > 100*time.Millisecond && windowCount > 0 {
		currentTPS = float64(windowCount) / elapsed.Seconds()
	} else {
		currentTPS = tm.currentTPS
	}

	// Cap current TPS for display
	const maxReasonableTPS = 10000.0
	if currentTPS > maxReasonableTPS {
		currentTPS = maxReasonableTPS
	}

	// Calculate average TPS
	var avgTPS float64
	if blocksProc > 0 {
		// Average TPS = total transactions / total time (estimate using block count)
		avgTPS = float64(totalTx) / float64(blocksProc*5) // 5 seconds per block
	}

	// Calculate average transactions per block - USE THE METHOD HERE
	avgTxsPerBlock := tm.calculateAverageTxsPerBlock()

	logger.Info("TPS Debug: blocks_processed=%d, total_txs=%d, avg_txs_per_block=%.2f",
		blocksProc, totalTx, avgTxsPerBlock)

	// Ensure peak TPS is also capped
	peakTPS := tm.peakTPS
	if peakTPS > maxReasonableTPS {
		peakTPS = maxReasonableTPS
	}

	return map[string]interface{}{
		"current_tps":                currentTPS,
		"average_tps":                avgTPS,
		"peak_tps":                   peakTPS,
		"total_transactions":         totalTx,
		"blocks_processed":           blocksProc,
		"current_window_count":       windowCount,
		"window_duration_sec":        tm.windowDuration.Seconds(),
		"window_elapsed_sec":         elapsed.Seconds(),
		"window_start_time":          tm.windowStartTime.Format(time.RFC3339),
		"history_size":               len(tm.tpsHistory),
		"avg_transactions_per_block": avgTxsPerBlock,
		"txs_per_block_count":        len(tm.txsPerBlock),
	}
}

// GetDetailedStats returns comprehensive TPS statistics
func (tm *TPSMonitor) GetDetailedStats() map[string]interface{} {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	stats := tm.GetStats()

	// Add percentile data
	stats["txs_per_block_stats"] = tm.calculateTxsPerBlockStats()
	stats["tps_history_recent"] = tm.getRecentTPSHistory(10) // Last 10 measurements
	stats["current_window_start"] = tm.windowStartTime.Format(time.RFC3339)

	return stats
}

// calculateAverageTxsPerBlock calculates average transactions per block
func (tm *TPSMonitor) calculateAverageTxsPerBlock() float64 {
	if len(tm.txsPerBlock) == 0 {
		return 0
	}

	var sum uint64
	for _, count := range tm.txsPerBlock {
		sum += count
	}
	return float64(sum) / float64(len(tm.txsPerBlock))
}

// calculateTxsPerBlockStats calculates statistics for transactions per block
func (tm *TPSMonitor) calculateTxsPerBlockStats() map[string]interface{} {
	if len(tm.txsPerBlock) == 0 {
		return map[string]interface{}{
			"min":   0,
			"max":   0,
			"mean":  0,
			"count": 0,
		}
	}

	var min, max, sum uint64
	min = ^uint64(0) // Max uint64

	for _, count := range tm.txsPerBlock {
		if count < min {
			min = count
		}
		if count > max {
			max = count
		}
		sum += count
	}

	return map[string]interface{}{
		"min":   min,
		"max":   max,
		"mean":  float64(sum) / float64(len(tm.txsPerBlock)),
		"count": len(tm.txsPerBlock),
	}
}

// getRecentTPSHistory returns recent TPS history
func (tm *TPSMonitor) getRecentTPSHistory(count int) []float64 {
	if len(tm.tpsHistory) == 0 {
		return []float64{}
	}

	start := len(tm.tpsHistory) - count
	if start < 0 {
		start = 0
	}

	return tm.tpsHistory[start:]
}

// Reset resets the TPS monitor (useful for tests)
func (tm *TPSMonitor) Reset() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	atomic.StoreUint64(&tm.totalTransactions, 0)
	atomic.StoreUint64(&tm.currentWindowCount, 0)
	atomic.StoreUint64(&tm.blocksProcessed, 0)

	tm.currentTPS = 0
	tm.averageTPS = 0
	tm.peakTPS = 0
	tm.windowStartTime = time.Now()
	tm.tpsHistory = make([]float64, 0)
	tm.txsPerBlock = make([]uint64, 0)
}

// Benchmarking to ensure the Merkle tree implementation is efficient
func BenchmarkMerkleTree(b *testing.B) {
	// Create many transactions for benchmarking
	var txs []*Transaction
	for i := 0; i < 1000; i++ {
		txs = append(txs, &Transaction{
			ID:       fmt.Sprintf("tx%d", i),
			Sender:   "alice",
			Receiver: "bob",
			Amount:   big.NewInt(int64(i)),
			GasLimit: big.NewInt(21000),
			GasPrice: big.NewInt(10),
			Nonce:    uint64(i),
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewMerkleTree(txs)
	}
}

// BenchmarkTransactionProcessing benchmarks transaction processing
func BenchmarkTransactionProcessing(b *testing.B) {
	monitor := NewTPSMonitor(time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tx := &Transaction{
			ID:       fmt.Sprintf("benchmark-tx-%d", i),
			Sender:   "benchmark-sender",
			Receiver: "benchmark-receiver",
			Amount:   big.NewInt(int64(i % 1000)),
			GasLimit: big.NewInt(21000),
			GasPrice: big.NewInt(10),
			Nonce:    uint64(i),
		}

		// Simulate transaction processing
		monitor.RecordTransaction()

		// Validate transaction (simulated)
		_ = tx.SanityCheck()
	}
}

// BenchmarkTPSMonitoring benchmarks TPS monitoring itself
func BenchmarkTPSMonitoring(b *testing.B) {
	monitor := NewTPSMonitor(time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		monitor.RecordTransaction()
		if i%1000 == 0 {
			_ = monitor.GetStats()
		}
	}
}

// BenchmarkRealWorldTPS simulates real-world TPS patterns
func BenchmarkRealWorldTPS(b *testing.B) {
	monitor := NewTPSMonitor(time.Second)

	// Simulate bursty traffic pattern
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate transaction bursts
		if i%100 == 0 {
			// Burst of 10 transactions
			for j := 0; j < 10; j++ {
				monitor.RecordTransaction()
			}
		} else {
			monitor.RecordTransaction()
		}

		// Simulate block creation every 1000 transactions
		if i%1000 == 0 && i > 0 {
			monitor.RecordBlock(50, 5*time.Second) // 50 txs in 5 seconds
		}
	}

	stats := monitor.GetStats()
	b.ReportMetric(stats["average_tps"].(float64), "avg_tps")
	b.ReportMetric(stats["peak_tps"].(float64), "peak_tps")
}
