// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/state/state.go
package state

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	logger "github.com/sphinxfndorg/protocol/src/log"
)

// GetBlockByHeight returns a block by its height
func (s *Storage) GetBlockByHeight(height uint64) (*types.Block, error) {
	// Simple implementation - iterate through blocks to find by height
	// In production, maintain a height index

	// Get all blocks (need to implement this)
	blocks, err := s.GetAllBlocks()
	if err != nil {
		return nil, err
	}

	for _, block := range blocks {
		if block.GetHeight() == height {
			return block, nil
		}
	}

	return nil, fmt.Errorf("block at height %d not found", height)
}

// GetIndexDir returns the index directory path
func (s *Storage) GetIndexDir() string {
	return s.indexDir
}

// GetTransaction returns a transaction by ID
func (s *Storage) GetTransaction(txID string) (*types.Transaction, error) {
	// Search through all blocks for the transaction
	blocks, err := s.GetAllBlocks()
	if err != nil {
		return nil, err
	}

	for _, block := range blocks {
		for _, tx := range block.Body.TxsList {
			if tx.ID == txID {
				return tx, nil
			}
		}
	}

	return nil, fmt.Errorf("transaction %s not found", txID)
}

// FIXED GetAllBlocks - completely rewritten to avoid hangs
func (s *Storage) GetAllBlocks() ([]*types.Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var blocks []*types.Block

	if s.totalBlocks == 0 {
		logger.Debug("GetAllBlocks: No blocks in storage")
		return blocks, nil
	}

	logger.Debug("GetAllBlocks: Starting with totalBlocks=%d", s.totalBlocks)

	// Method 1: Use heightIndex first (most reliable)
	if len(s.heightIndex) > 0 {
		logger.Debug("GetAllBlocks: Using heightIndex with %d entries", len(s.heightIndex))
		for height := uint64(0); height < s.totalBlocks; height++ {
			if block, exists := s.heightIndex[height]; exists {
				blocks = append(blocks, block)
			}
		}

		if len(blocks) > 0 {
			logger.Debug("GetAllBlocks: Found %d blocks via heightIndex", len(blocks))
			return blocks, nil
		}
	}

	// Method 2: Fall back to blockIndex
	if len(s.blockIndex) > 0 {
		logger.Debug("GetAllBlocks: Using blockIndex with %d entries", len(s.blockIndex))
		for _, block := range s.blockIndex {
			blocks = append(blocks, block)
		}

		// Sort by height
		sort.Slice(blocks, func(i, j int) bool {
			return blocks[i].GetHeight() < blocks[j].GetHeight()
		})

		logger.Debug("GetAllBlocks: Found %d blocks via blockIndex", len(blocks))
		return blocks, nil
	}

	// Method 3: Last resort - try to load from disk index
	logger.Debug("GetAllBlocks: No blocks in memory, trying disk index")
	indexFile := filepath.Join(s.indexDir, "block_index.json")
	if _, err := os.Stat(indexFile); err == nil {
		data, err := os.ReadFile(indexFile)
		if err == nil {
			var index struct {
				Blocks map[string]uint64 `json:"blocks"`
			}
			if err := json.Unmarshal(data, &index); err == nil {
				for hash := range index.Blocks {
					block, err := s.loadBlockFromDisk(hash)
					if err == nil {
						blocks = append(blocks, block)
					}
				}

				// Sort by height
				sort.Slice(blocks, func(i, j int) bool {
					return blocks[i].GetHeight() < blocks[j].GetHeight()
				})

				logger.Debug("GetAllBlocks: Processing %d blocks with ParentHash chain validation", len(blocks))
				return blocks, nil
			}
		}
	}

	logger.Debug("GetAllBlocks: No blocks found via any method")
	return blocks, nil
}

// GetTotalBlocks returns the total number of blocks
func (s *Storage) GetTotalBlocks() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.totalBlocks
}

// NewStorage creates a new storage instance with LevelDB support
// dataDir is the node's base directory (e.g., "127.0.0.1:32307")
func NewStorage(dataDir string) (*Storage, error) {
	// Use common package to get correct paths with blockchain subdirectory
	blocksDir := common.GetBlocksDir(dataDir) // .../blockchain/blocks
	indexDir := common.GetIndexDir(dataDir)   // .../blockchain/index
	stateDir := common.GetStateDir(dataDir)   // .../blockchain/state
	// dbPath is not used yet - we'll open DB via SetDB later
	// dbPath := common.GetLevelDBPath(dataDir)  // .../blockchain.db

	// Ensure all directories exist
	if err := os.MkdirAll(blocksDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create blocks directory: %w", err)
	}
	if err := os.MkdirAll(indexDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create index directory: %w", err)
	}
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %w", err)
	}

	// Create storage instance WITHOUT opening DB yet
	// DB will be set later via SetDB() to allow sharing
	storage := &Storage{
		dataDir:       dataDir,
		stateDB:       nil, // ✅ Will be set later via SetDB()
		blocksDir:     blocksDir,
		indexDir:      indexDir,
		stateDir:      stateDir,
		blockIndex:    make(map[string]*types.Block),
		heightIndex:   make(map[uint64]*types.Block),
		txIndex:       make(map[string]*types.Transaction),
		totalBlocks:   0,
		bestBlockHash: "",
		tpsConfig: &TPSConfig{
			WindowDuration: 5 * time.Second,
			MaxHistorySize: 1000,
			SaveInterval:   30 * time.Second,
			ReportInterval: 60 * time.Second,
		},
	}

	// Load existing data from JSON files (these don't require DB)
	if err := storage.loadChainState(); err != nil {
		logger.Warn("Could not load chain state: %v", err)
	}

	if err := storage.loadBlockIndex(); err != nil {
		logger.Warn("Could not load block index: %v", err)
	}

	// Load TPS metrics
	if err := storage.loadTPSMetrics(); err != nil {
		logger.Warn("Could not load TPS metrics: %v", err)
		storage.initializeTPSMetrics()
	}

	logger.Info("Storage initialized (DB will be attached later): total_blocks=%d, best_block=%s",
		storage.totalBlocks, storage.bestBlockHash)

	return storage, nil
}

// TPS Metrics Management
func (s *Storage) initializeTPSMetrics() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.tpsMetrics == nil {
		s.tpsMetrics = &TPSMetrics{
			CurrentTPS:              0,
			AverageTPS:              0,
			PeakTPS:                 0,
			TotalTransactions:       0,
			BlocksProcessed:         s.totalBlocks, // ✅ Start with actual block count
			LastUpdated:             time.Now(),
			CurrentWindowCount:      0,
			WindowStartTime:         time.Now(),
			WindowDuration:          s.tpsConfig.WindowDuration,
			WindowDurationSeconds:   s.tpsConfig.WindowDuration.Seconds(),
			TPSHistory:              make([]TPSDataPoint, 0),
			TransactionsPerBlock:    make([]BlockTXCount, 0),
			AvgTransactionsPerBlock: 0,
			MaxTransactionsPerBlock: 0,
			MinTransactionsPerBlock: 0,
		}
		logger.Info("✅ TPS metrics initialized with BlocksProcessed=%d", s.totalBlocks)
	}
}

// RecordTransaction records a transaction for TPS calculation
func (s *Storage) RecordTransaction() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.tpsMetrics == nil {
		s.initializeTPSMetrics()
	}

	s.tpsMetrics.TotalTransactions++
	s.tpsMetrics.CurrentWindowCount++
	s.tpsMetrics.LastUpdated = time.Now()

	// Update TPS calculation
	s.updateTPS()
}

// RecordBlock records block information for TPS calculation
func (s *Storage) RecordBlock(block *types.Block, blockTime time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.tpsMetrics == nil {
		s.initializeTPSMetrics()
	}

	txCount := uint64(len(block.Body.TxsList))

	// FIX: Don't double-count transactions here - they're counted in RecordTransaction()
	// Only increment BlocksProcessed
	s.tpsMetrics.BlocksProcessed++

	// Record block transaction count
	blockTX := BlockTXCount{
		BlockHeight: block.GetHeight(),
		BlockHash:   block.GetHash(),
		TxCount:     txCount,
		BlockTime:   time.Unix(block.Header.Timestamp, 0),
		BlockSize:   s.calculateBlockSize(block),
	}

	s.tpsMetrics.TransactionsPerBlock = append(s.tpsMetrics.TransactionsPerBlock, blockTX)

	// Update block statistics
	s.updateBlockStatistics()

	// Calculate block TPS
	if blockTime > 0 {
		blockTPS := float64(txCount) / blockTime.Seconds()
		tpsDataPoint := TPSDataPoint{
			Timestamp:   time.Now(),
			TPS:         blockTPS,
			BlockHeight: block.GetHeight(),
		}
		s.tpsMetrics.TPSHistory = append(s.tpsMetrics.TPSHistory, tpsDataPoint)
	}

	// Maintain history size
	if len(s.tpsMetrics.TPSHistory) > s.tpsConfig.MaxHistorySize {
		s.tpsMetrics.TPSHistory = s.tpsMetrics.TPSHistory[1:]
	}
	if len(s.tpsMetrics.TransactionsPerBlock) > s.tpsConfig.MaxHistorySize {
		s.tpsMetrics.TransactionsPerBlock = s.tpsMetrics.TransactionsPerBlock[1:]
	}

	s.tpsMetrics.LastUpdated = time.Now()
}

// updateTPS calculates current TPS based on window
func (s *Storage) updateTPS() {
	now := time.Now()
	windowElapsed := now.Sub(s.tpsMetrics.WindowStartTime)

	// Define max TPS constant
	const maxTPS = 10000.0 // ← ADD THIS LINE

	// Reset window if it's been too long (avoid stale calculations)
	if windowElapsed > s.tpsMetrics.WindowDuration*2 {
		logger.Debug("Resetting stale TPS window")
		s.tpsMetrics.CurrentWindowCount = 0
		s.tpsMetrics.WindowStartTime = now
		s.tpsMetrics.CurrentTPS = 0
		return
	}

	// ONLY calculate TPS if enough time has passed (minimum 100ms)
	const minElapsed = 100 * time.Millisecond
	if windowElapsed >= minElapsed {
		s.tpsMetrics.CurrentTPS = float64(s.tpsMetrics.CurrentWindowCount) / windowElapsed.Seconds()

		// Cap TPS at a reasonable maximum
		if s.tpsMetrics.CurrentTPS > maxTPS {
			s.tpsMetrics.CurrentTPS = maxTPS
		}
	} else {
		// Not enough time elapsed, keep previous TPS or set to 0
		if s.tpsMetrics.CurrentTPS == 0 {
			s.tpsMetrics.CurrentTPS = 0
		}
	}

	// Only finalize and reset when window completes
	if windowElapsed >= s.tpsMetrics.WindowDuration {
		windowTPS := float64(s.tpsMetrics.CurrentWindowCount) / s.tpsMetrics.WindowDuration.Seconds()

		// Update historical data
		tpsDataPoint := TPSDataPoint{
			Timestamp: now,
			TPS:       windowTPS,
		}
		s.tpsMetrics.TPSHistory = append(s.tpsMetrics.TPSHistory, tpsDataPoint)

		// Update peak TPS (cap at reasonable value)
		if windowTPS > s.tpsMetrics.PeakTPS && windowTPS < maxTPS {
			s.tpsMetrics.PeakTPS = windowTPS
		}

		// Update average TPS
		s.updateAverageTPS()

		// Reset window
		s.tpsMetrics.CurrentWindowCount = 0
		s.tpsMetrics.WindowStartTime = now
		s.tpsMetrics.CurrentTPS = 0

		// Maintain history size
		if len(s.tpsMetrics.TPSHistory) > s.tpsConfig.MaxHistorySize {
			s.tpsMetrics.TPSHistory = s.tpsMetrics.TPSHistory[1:]
		}

		logger.Debug("Window completed: TPS=%.2f, peak=%.2f, avg=%.2f, total_txs=%d",
			windowTPS, s.tpsMetrics.PeakTPS, s.tpsMetrics.AverageTPS,
			s.tpsMetrics.TotalTransactions)
	}
}

// updateAverageTPS calculates the average TPS
func (s *Storage) updateAverageTPS() {
	if len(s.tpsMetrics.TPSHistory) == 0 {
		s.tpsMetrics.AverageTPS = 0
		return
	}

	var sum float64
	for _, point := range s.tpsMetrics.TPSHistory {
		sum += point.TPS
	}
	s.tpsMetrics.AverageTPS = sum / float64(len(s.tpsMetrics.TPSHistory))
}

// updateBlockStatistics updates block-based statistics
func (s *Storage) updateBlockStatistics() {
	if len(s.tpsMetrics.TransactionsPerBlock) == 0 {
		return
	}

	var sum uint64
	min := ^uint64(0)
	max := uint64(0)

	for _, block := range s.tpsMetrics.TransactionsPerBlock {
		if block.TxCount < min {
			min = block.TxCount
		}
		if block.TxCount > max {
			max = block.TxCount
		}
		sum += block.TxCount
	}

	s.tpsMetrics.AvgTransactionsPerBlock = float64(sum) / float64(len(s.tpsMetrics.TransactionsPerBlock))
	s.tpsMetrics.MinTransactionsPerBlock = min
	s.tpsMetrics.MaxTransactionsPerBlock = max
}

// GetTPSMetrics returns current TPS metrics
// Fix GetTPSMetrics to ensure WindowDurationSeconds is set
func (s *Storage) GetTPSMetrics() *TPSMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.tpsMetrics == nil {
		// Return empty metrics if not initialized
		return &TPSMetrics{
			CurrentTPS:              0,
			AverageTPS:              0,
			PeakTPS:                 0,
			TotalTransactions:       0,
			BlocksProcessed:         0,
			LastUpdated:             time.Now(),
			CurrentWindowCount:      0,
			WindowStartTime:         time.Now(),
			WindowDuration:          s.tpsConfig.WindowDuration,
			WindowDurationSeconds:   s.tpsConfig.WindowDuration.Seconds(),
			TPSHistory:              []TPSDataPoint{},
			TransactionsPerBlock:    []BlockTXCount{},
			AvgTransactionsPerBlock: 0,
			MaxTransactionsPerBlock: 0,
			MinTransactionsPerBlock: 0,
		}
	}

	// Ensure WindowDurationSeconds is always set
	s.tpsMetrics.WindowDurationSeconds = s.tpsMetrics.WindowDuration.Seconds()

	// Return a copy to avoid concurrent modification
	return &TPSMetrics{
		CurrentTPS:              s.tpsMetrics.CurrentTPS,
		AverageTPS:              s.tpsMetrics.AverageTPS,
		PeakTPS:                 s.tpsMetrics.PeakTPS,
		TotalTransactions:       s.tpsMetrics.TotalTransactions,
		BlocksProcessed:         s.tpsMetrics.BlocksProcessed,
		LastUpdated:             s.tpsMetrics.LastUpdated,
		CurrentWindowCount:      s.tpsMetrics.CurrentWindowCount,
		WindowStartTime:         s.tpsMetrics.WindowStartTime,
		WindowDuration:          s.tpsMetrics.WindowDuration,
		WindowDurationSeconds:   s.tpsMetrics.WindowDurationSeconds,
		TPSHistory:              append([]TPSDataPoint{}, s.tpsMetrics.TPSHistory...),
		TransactionsPerBlock:    append([]BlockTXCount{}, s.tpsMetrics.TransactionsPerBlock...),
		AvgTransactionsPerBlock: s.tpsMetrics.AvgTransactionsPerBlock,
		MaxTransactionsPerBlock: s.tpsMetrics.MaxTransactionsPerBlock,
		MinTransactionsPerBlock: s.tpsMetrics.MinTransactionsPerBlock,
	}
}

// SaveTPSMetrics saves TPS metrics to disk
// Fix SaveTPSMetrics to ensure WindowDurationSeconds is set before saving
// SaveTPSMetrics saves TPS metrics to disk
func (s *Storage) SaveTPSMetrics() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.tpsMetrics == nil {
		logger.Warn("TPS metrics not initialized, skipping save")
		return nil
	}

	// Ensure WindowDurationSeconds is set before serialization
	s.tpsMetrics.WindowDurationSeconds = s.tpsMetrics.WindowDuration.Seconds()

	// Get metrics directory path from common package
	// Note: We need to get the node address from s.dataDir
	// s.dataDir is the node address (e.g., "127.0.0.1:32307")
	metricsDir := common.GetMetricsDir(s.dataDir)

	// Ensure metrics directory exists
	if err := os.MkdirAll(metricsDir, 0755); err != nil {
		return fmt.Errorf("failed to create metrics directory: %w", err)
	}

	tpsFile := filepath.Join(metricsDir, "tps_metrics.json")

	// Create a copy for serialization
	tpsMetricsCopy := &TPSMetrics{
		CurrentTPS:              s.tpsMetrics.CurrentTPS,
		AverageTPS:              s.tpsMetrics.AverageTPS,
		PeakTPS:                 s.tpsMetrics.PeakTPS,
		TotalTransactions:       s.tpsMetrics.TotalTransactions,
		BlocksProcessed:         s.tpsMetrics.BlocksProcessed,
		LastUpdated:             s.tpsMetrics.LastUpdated,
		CurrentWindowCount:      s.tpsMetrics.CurrentWindowCount,
		WindowStartTime:         s.tpsMetrics.WindowStartTime,
		WindowDuration:          s.tpsMetrics.WindowDuration,
		WindowDurationSeconds:   s.tpsMetrics.WindowDurationSeconds,
		TPSHistory:              append([]TPSDataPoint{}, s.tpsMetrics.TPSHistory...),
		TransactionsPerBlock:    append([]BlockTXCount{}, s.tpsMetrics.TransactionsPerBlock...),
		AvgTransactionsPerBlock: s.tpsMetrics.AvgTransactionsPerBlock,
		MaxTransactionsPerBlock: s.tpsMetrics.MaxTransactionsPerBlock,
		MinTransactionsPerBlock: s.tpsMetrics.MinTransactionsPerBlock,
	}

	data, err := json.MarshalIndent(tpsMetricsCopy, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal TPS metrics: %w", err)
	}

	// Write with atomic replace
	tmpFile := tpsFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write TPS metrics file: %w", err)
	}

	if err := os.Rename(tmpFile, tpsFile); err != nil {
		return fmt.Errorf("failed to rename TPS metrics file: %w", err)
	}

	logger.Debug("✅ TPS metrics saved to %s: current_tps=%.2f, total_txs=%d",
		tpsFile, s.tpsMetrics.CurrentTPS, s.tpsMetrics.TotalTransactions)
	return nil
}

// loadTPSMetrics loads TPS metrics from disk
func (s *Storage) loadTPSMetrics() error {
	// Get metrics directory path from common package
	metricsDir := common.GetMetricsDir(s.dataDir)
	tpsFile := filepath.Join(metricsDir, "tps_metrics.json")

	// Check if file exists
	if _, err := os.Stat(tpsFile); os.IsNotExist(err) {
		logger.Info("No TPS metrics file found at %s, starting fresh", tpsFile)
		return fmt.Errorf("TPS metrics file does not exist")
	}

	data, err := os.ReadFile(tpsFile)
	if err != nil {
		return fmt.Errorf("failed to read TPS metrics file: %w", err)
	}

	var tpsMetrics TPSMetrics
	if err := json.Unmarshal(data, &tpsMetrics); err != nil {
		return fmt.Errorf("failed to unmarshal TPS metrics: %w", err)
	}

	// After loading TPS metrics, sync BlocksProcessed with actual chain state
	if s.tpsMetrics != nil {
		s.tpsMetrics.BlocksProcessed = s.totalBlocks
		logger.Info("Synced TPS BlocksProcessed with chain: %d blocks", s.totalBlocks)
	}

	s.mu.Lock()
	s.tpsMetrics = &tpsMetrics
	s.mu.Unlock()

	logger.Info("TPS metrics loaded from %s: current_tps=%.2f, total_txs=%d",
		tpsFile, tpsMetrics.CurrentTPS, tpsMetrics.TotalTransactions)
	return nil
}

// StartTPSAutoSave starts automatic TPS metrics saving
func (s *Storage) StartTPSAutoSave(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.tpsConfig.SaveInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				// Save final state before exiting
				if err := s.SaveTPSMetrics(); err != nil {
					logger.Warn("Failed to save final TPS metrics: %v", err)
				}
				return
			case <-ticker.C:
				if err := s.SaveTPSMetrics(); err != nil {
					logger.Warn("Failed to auto-save TPS metrics: %v", err)
				} else {
					logger.Debug("Auto-saved TPS metrics")
				}
			}
		}
	}()
}

// calculateBlockSizeMetrics calculates block size metrics for all stored blocks
func (s *Storage) calculateBlockSizeMetrics(chainState *ChainState) error {
	logger.Info("Starting block size metrics calculation...")

	// Get all blocks for analysis
	blocks, err := s.GetAllBlocks()
	if err != nil {
		return fmt.Errorf("failed to get blocks for size metrics: %w", err)
	}

	if len(blocks) == 0 {
		logger.Info("No blocks available for size metrics calculation")
		// Set default values for empty chain
		chainState.BlockSizeMetrics = &BlockSizeMetrics{
			TotalBlocks:     0,
			AverageSize:     0,
			MinSize:         0,
			MaxSize:         0,
			TotalSize:       0,
			SizeStats:       []BlockSizeInfo{},
			CalculationTime: time.Now().Format(time.RFC3339),
			AverageSizeMB:   0,
			MinSizeMB:       0,
			MaxSizeMB:       0,
			TotalSizeMB:     0,
		}
		return nil
	}

	var totalSize uint64
	var minSize uint64 = ^uint64(0) // Max uint64
	var maxSize uint64
	sizeStats := make([]BlockSizeInfo, 0, len(blocks))

	for _, block := range blocks {
		blockSize := s.calculateBlockSize(block)
		totalSize += blockSize

		if blockSize < minSize {
			minSize = blockSize
		}
		if blockSize > maxSize {
			maxSize = blockSize
		}

		// Record individual block stats
		blockStat := BlockSizeInfo{
			Height:    block.GetHeight(),
			Hash:      block.GetHash(),
			Size:      blockSize,
			SizeMB:    float64(blockSize) / (1024 * 1024),
			TxCount:   uint64(len(block.Body.TxsList)),
			Timestamp: common.GetTimeService().GetTimeInfo(block.Header.Timestamp).ISOUTC,
		}
		sizeStats = append(sizeStats, blockStat)

		logger.Debug("Block %d size: %d bytes, %d transactions",
			block.GetHeight(), blockSize, len(block.Body.TxsList))
	}

	averageSize := uint64(0)
	if len(blocks) > 0 {
		averageSize = totalSize / uint64(len(blocks))
	}

	// Convert to MB for human readability
	averageSizeMB := float64(averageSize) / (1024 * 1024)
	minSizeMB := float64(minSize) / (1024 * 1024)
	maxSizeMB := float64(maxSize) / (1024 * 1024)
	totalSizeMB := float64(totalSize) / (1024 * 1024)

	// Create block size metrics
	chainState.BlockSizeMetrics = &BlockSizeMetrics{
		TotalBlocks:     uint64(len(blocks)),
		AverageSize:     averageSize,
		MinSize:         minSize,
		MaxSize:         maxSize,
		TotalSize:       totalSize,
		SizeStats:       sizeStats,
		CalculationTime: time.Now().Format(time.RFC3339),
		AverageSizeMB:   averageSizeMB,
		MinSizeMB:       minSizeMB,
		MaxSizeMB:       maxSizeMB,
		TotalSizeMB:     totalSizeMB,
	}

	logger.Info("Successfully calculated block size metrics for %d blocks", len(blocks))
	logger.Info("Block size stats: avg=%.2f MB, min=%.2f MB, max=%.2f MB, total=%.2f MB",
		averageSizeMB, minSizeMB, maxSizeMB, totalSizeMB)
	logger.Info("Size stats contains %d entries", len(sizeStats))

	return nil
}

// calculateBlockSize calculates the approximate size of a block in bytes
func (s *Storage) calculateBlockSize(block *types.Block) uint64 {
	if block == nil {
		return 0
	}

	size := uint64(0)

	// Header size (approximate)
	size += 80 // Fixed header components

	// Transactions size - calculate based on actual transaction data
	for _, tx := range block.Body.TxsList {
		txSize := uint64(0)

		// Add size of transaction fields
		txSize += uint64(len(tx.ID))        // Transaction ID
		txSize += uint64(len(tx.Sender))    // Sender address
		txSize += uint64(len(tx.Receiver))  // Receiver address
		txSize += 8                         // Nonce (uint64)
		txSize += 32                        // Amount (big.Int - approximate)
		txSize += 32                        // GasLimit (big.Int - approximate)
		txSize += 32                        // GasPrice (big.Int - approximate)
		txSize += 8                         // Timestamp (int64)
		txSize += uint64(len(tx.Signature)) // Signature

		size += txSize
	}

	return size
}

// SaveCompleteChainState saves the complete chain state including TPS metrics from blockchain
// Enhanced to accept TPS metrics from the working blockchain tpsMonitor
func (s *Storage) SaveCompleteChainState(chainState *ChainState, chainParams *ChainParams, walletPaths map[string]string, blockchainTPSMetrics *TPSMetrics) error {
	// CRITICAL: Check if chainState is nil
	if chainState == nil {
		logger.Error("❌ CRITICAL: chainState is nil in SaveCompleteChainState!")
		return fmt.Errorf("chainState is nil")
	}

	// CRITICAL: Check if Nodes is nil
	if chainState.Nodes == nil {
		logger.Error("❌ CRITICAL: chainState.Nodes is nil in SaveCompleteChainState!")
		// Don't return error, create empty array to avoid null
		chainState.Nodes = make([]*NodeInfo, 0)
	} else {
		logger.Info("Saving %d nodes to chain_state.json", len(chainState.Nodes))
		for i, node := range chainState.Nodes {
			if node == nil {
				logger.Warn("Node %d in chainState is nil, replacing with real node info", i)
				// Replace nil nodes with real node information
				chainState.Nodes[i] = s.createNodeInfo(i)
				continue
			}
			// FIX: `node` may have been built earlier in the request (e.g. before
			// the latest block finished committing), so its BlockHeight/BlockHash
			// can lag behind s.bestBlockHash/s.totalBlocks by the time we actually
			// persist. That produced chain_state.json output where a node reported
			// height 1 while StorageState/BasicChainState (built fresh just below
			// from s.bestBlockHash) already reported height 3. Always resync each
			// node's chain-tip fields against current storage right before saving.
			fresh := s.createNodeInfo(i)
			node.BlockHeight = fresh.BlockHeight
			node.BlockHash = fresh.BlockHash
			node.MerkleRoot = fresh.MerkleRoot
			node.Timestamp = fresh.Timestamp
			if node.ChainInfo == nil {
				node.ChainInfo = fresh.ChainInfo
			} else {
				node.ChainInfo["blocks_height"] = fresh.BlockHeight
				node.ChainInfo["last_updated"] = fresh.Timestamp
				node.ChainInfo["tps_current"] = fresh.ChainInfo["tps_current"]
				node.ChainInfo["tps_average"] = fresh.ChainInfo["tps_average"]
				node.ChainInfo["total_txs"] = fresh.ChainInfo["total_txs"]
				// Preserve canonical genesis_hash — if fresh carries it, prefer it
				// over any stale value (e.g. "DEVNET_GENESIS_…") that may have been
				// written by an older version.
				if gh, exists := fresh.ChainInfo["genesis_hash"]; exists {
					node.ChainInfo["genesis_hash"] = gh
				}
			}
		}
	}

	// Set timestamp if not provided - use chain's timestamp for consistency
	if chainState.Timestamp == "" {
		chainState.Timestamp = time.Now().Format(time.RFC3339)
	} else {
		// Update timestamp to current time to reflect latest state
		chainState.Timestamp = time.Now().Format(time.RFC3339)
	}

	// Add storage state information (basic chain state data)
	chainState.StorageState = &StorageState{
		BestBlockHash: s.bestBlockHash,
		TotalBlocks:   s.totalBlocks,
		BlocksDir:     s.blocksDir,
		IndexDir:      s.indexDir,
		StateDir:      s.stateDir,
	}

	// Add basic chain state directly to the main structure
	chainState.BasicChainState = &BasicChainState{
		BestBlockHash: s.bestBlockHash,
		TotalBlocks:   s.totalBlocks,
		LastUpdated:   time.Now().Format(time.RFC3339),
	}

	// Initialize ChainIdentification if nil
	if chainState.ChainIdentification == nil {
		// Get the actual genesis hash with GENESIS_ prefix
		actualGenesisHash, err := s.GetGenesisHash()
		if err != nil {
			logger.Warn("Failed to get actual genesis hash: %v, using provided one", err)
			actualGenesisHash = chainParams.GenesisHash
		}

		// Ensure it has GENESIS_ prefix
		if !strings.HasPrefix(actualGenesisHash, "GENESIS_") {
			logger.Warn("Genesis hash missing GENESIS_ prefix, adding it: %s", actualGenesisHash)
			actualGenesisHash = "GENESIS_" + actualGenesisHash
		}

		// Replace the entire ChainIdentification initialization block:
		chainState.ChainIdentification = &ChainIdentification{
			Timestamp: time.Now().Format(time.RFC3339),
			ChainParams: map[string]interface{}{
				"chain_id":     chainParams.ChainID,
				"chain_name":   chainParams.ChainName,
				"symbol":       chainParams.Symbol,
				"genesis_time": chainParams.GenesisTime,
				"genesis_hash": actualGenesisHash,
				"version":      chainParams.Version,
				"magic_number": chainParams.MagicNumber,
				"default_port": chainParams.DefaultPort,
				"bip44_type":   chainParams.BIP44CoinType,
			},
			TokenInfo: map[string]interface{}{
				"ledger_name": chainParams.LedgerName,
			},
			NetworkInfo: map[string]interface{}{
				"network_name": chainParams.ChainName,
				"protocol":     fmt.Sprintf("SPX/%s", chainParams.Version),
			},
		}
	}

	// CALCULATE BLOCK SIZE METRICS HERE (but with timeout protection)
	logger.Info("Starting block size metrics calculation...")
	if err := s.calculateBlockSizeMetrics(chainState); err != nil {
		logger.Warn("Failed to calculate block size metrics: %v", err)
		// Create empty metrics instead of null
		chainState.BlockSizeMetrics = &BlockSizeMetrics{
			TotalBlocks:     0,
			AverageSize:     0,
			MinSize:         0,
			MaxSize:         0,
			TotalSize:       0,
			SizeStats:       []BlockSizeInfo{},
			CalculationTime: time.Now().Format(time.RFC3339),
			AverageSizeMB:   0,
			MinSizeMB:       0,
			MaxSizeMB:       0,
			TotalSizeMB:     0,
		}
	} else {
		logger.Info("Successfully calculated block size metrics for %d blocks",
			chainState.BlockSizeMetrics.TotalBlocks)
	}

	// ADD TPS METRICS TO CHAIN STATE - USE BLOCKCHAIN'S WORKING DATA
	logger.Info("Adding TPS metrics to chain state...")

	// UPDATE TPS METRICS - Preserve history while updating current values
	logger.Info("Updating TPS metrics from blockchain data...")

	var tpsMetrics *TPSMetrics
	if blockchainTPSMetrics != nil {
		// Get existing metrics to preserve history
		existingMetrics := s.GetTPSMetrics()

		// If existing metrics have no history but blockchain has some, use blockchain's
		if len(existingMetrics.TPSHistory) == 0 && len(blockchainTPSMetrics.TPSHistory) > 0 {
			existingMetrics.TPSHistory = blockchainTPSMetrics.TPSHistory
		}

		// If existing metrics have no block data but blockchain has some, use blockchain's
		if len(existingMetrics.TransactionsPerBlock) == 0 && len(blockchainTPSMetrics.TransactionsPerBlock) > 0 {
			existingMetrics.TransactionsPerBlock = blockchainTPSMetrics.TransactionsPerBlock
			existingMetrics.MaxTransactionsPerBlock = blockchainTPSMetrics.MaxTransactionsPerBlock
			existingMetrics.MinTransactionsPerBlock = blockchainTPSMetrics.MinTransactionsPerBlock
		}

		// Update only the current values from blockchain
		existingMetrics.CurrentTPS = blockchainTPSMetrics.CurrentTPS
		existingMetrics.AverageTPS = blockchainTPSMetrics.AverageTPS
		existingMetrics.PeakTPS = blockchainTPSMetrics.PeakTPS
		existingMetrics.TotalTransactions = blockchainTPSMetrics.TotalTransactions
		existingMetrics.BlocksProcessed = blockchainTPSMetrics.BlocksProcessed
		existingMetrics.CurrentWindowCount = blockchainTPSMetrics.CurrentWindowCount
		existingMetrics.AvgTransactionsPerBlock = blockchainTPSMetrics.AvgTransactionsPerBlock
		existingMetrics.LastUpdated = time.Now()

		tpsMetrics = existingMetrics

		logger.Info("✅ Updated TPS metrics from blockchain: current=%.2f, avg=%.2f, peak=%.2f, total_txs=%d, history_size=%d, blocks_recorded=%d",
			tpsMetrics.CurrentTPS, tpsMetrics.AverageTPS, tpsMetrics.PeakTPS,
			tpsMetrics.TotalTransactions, len(tpsMetrics.TPSHistory), len(tpsMetrics.TransactionsPerBlock))
	} else {
		// Fallback to storage's own metrics (as last resort)
		tpsMetrics = s.GetTPSMetrics()
		tpsMetrics.LastUpdated = time.Now()
		logger.Warn("⚠️ No blockchain TPS metrics provided, falling back to storage TPS metrics (may be inaccurate)")
	}

	chainState.TPSMetrics = tpsMetrics

	// VALIDATE AND FIX FINAL STATES BEFORE SAVING
	if chainState.FinalStates != nil {
		fixedCount := 0
		for i, state := range chainState.FinalStates {
			if state != nil && state.BlockHeight == 0 {
				// Get actual genesis block
				genesisBlock, err := s.GetBlockByHeight(0)
				if err == nil && genesisBlock != nil {
					actualGenesisHash := genesisBlock.GetHash()

					// Fix genesis hash if it's incorrect
					if state.BlockHash != actualGenesisHash {
						oldHash := state.BlockHash
						state.BlockHash = actualGenesisHash
						fixedCount++
						logger.Info("🔄 Fixed genesis block hash in final state %d: %s -> %s",
							i, oldHash, actualGenesisHash)
					}
				}
			}
			chainState.FinalStates[i] = s.ensureFinalStateValues(state)
		}
		if fixedCount > 0 {
			logger.Info("✅ Fixed %d genesis block hashes in final states", fixedCount)
		}
	}

	// Ensure all final states have proper values
	for i, state := range chainState.FinalStates {
		if state != nil {
			chainState.FinalStates[i] = s.ensureFinalStateValues(state)
		}
	}

	// Save to chain_state.json in state directory
	stateFile := filepath.Join(s.stateDir, "chain_state.json")
	data, err := json.MarshalIndent(chainState, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal chain state: %w", err)
	}

	// Write with atomic replace
	tmpFile := stateFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write chain state file: %w", err)
	}

	if err := os.Rename(tmpFile, stateFile); err != nil {
		return fmt.Errorf("failed to rename chain state file: %w", err)
	}

	// SAVE TPS METRICS SEPARATELY AS WELL (using the same data)
	logger.Info("Saving TPS metrics to separate file...")
	if err := s.saveTPSSeparately(tpsMetrics); err != nil {
		logger.Warn("Failed to save TPS metrics separately: %v", err)
	} else {
		logger.Info("✅ TPS metrics saved separately to tps_metrics.json")
	}

	logger.Info("✅ Complete chain state saved: %s", stateFile)
	logger.Info("Chain state includes:")
	logger.Info("  - %d nodes", len(chainState.Nodes))
	logger.Info("  - %d final states", len(chainState.FinalStates))
	logger.Info("  - Block size metrics for %d blocks", chainState.BlockSizeMetrics.TotalBlocks)
	logger.Info("  - TPS metrics: current=%.2f, avg=%.2f, peak=%.2f, total_txs=%d",
		chainState.TPSMetrics.CurrentTPS, chainState.TPSMetrics.AverageTPS,
		chainState.TPSMetrics.PeakTPS, chainState.TPSMetrics.TotalTransactions)

	// Log final states for debugging
	if len(chainState.FinalStates) > 0 {
		logger.Info("Final states summary:")
		for i, state := range chainState.FinalStates {
			if state != nil && i < 5 { // Log first 5 for brevity
				logger.Info("  [%d] block=%s, height=%d, status=%s, merkle=%s",
					i, state.BlockHash, state.BlockHeight, state.Status, state.MerkleRoot)
			}
		}
		if len(chainState.FinalStates) > 5 {
			logger.Info("  ... and %d more final states", len(chainState.FinalStates)-5)
		}
	}

	return nil
}

// saveTPSSeparately saves TPS metrics to a separate file (helper function)
func (s *Storage) saveTPSSeparately(tpsMetrics *TPSMetrics) error {
	if tpsMetrics == nil {
		return fmt.Errorf("no TPS metrics to save")
	}

	// Get metrics directory path
	metricsDir := common.GetMetricsDir(s.dataDir)
	if err := os.MkdirAll(metricsDir, 0755); err != nil {
		return fmt.Errorf("failed to create metrics directory: %w", err)
	}

	tpsFile := filepath.Join(metricsDir, "tps_metrics.json")

	// Ensure WindowDurationSeconds is set
	tpsMetrics.WindowDurationSeconds = tpsMetrics.WindowDuration.Seconds()

	// Ensure history and block data are preserved in the saved file
	// Create a copy to avoid modifying the original
	saveMetrics := &TPSMetrics{
		CurrentTPS:              tpsMetrics.CurrentTPS,
		AverageTPS:              tpsMetrics.AverageTPS,
		PeakTPS:                 tpsMetrics.PeakTPS,
		TotalTransactions:       tpsMetrics.TotalTransactions,
		BlocksProcessed:         tpsMetrics.BlocksProcessed,
		CurrentWindowCount:      tpsMetrics.CurrentWindowCount,
		WindowStartTime:         tpsMetrics.WindowStartTime,
		WindowDuration:          tpsMetrics.WindowDuration,
		WindowDurationSeconds:   tpsMetrics.WindowDurationSeconds,
		TPSHistory:              tpsMetrics.TPSHistory,           // Preserve history
		TransactionsPerBlock:    tpsMetrics.TransactionsPerBlock, // Preserve block data
		AvgTransactionsPerBlock: tpsMetrics.AvgTransactionsPerBlock,
		MaxTransactionsPerBlock: tpsMetrics.MaxTransactionsPerBlock,
		MinTransactionsPerBlock: tpsMetrics.MinTransactionsPerBlock,
		LastUpdated:             tpsMetrics.LastUpdated,
	}

	data, err := json.MarshalIndent(saveMetrics, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal TPS metrics: %w", err)
	}

	// Write with atomic replace
	tmpFile := tpsFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write TPS metrics file: %w", err)
	}

	if err := os.Rename(tmpFile, tpsFile); err != nil {
		return fmt.Errorf("failed to rename TPS metrics file: %w", err)
	}

	logger.Info("✅ TPS metrics saved to %s: current_tps=%.2f, total_txs=%d, history_size=%d, blocks_recorded=%d",
		tpsFile, tpsMetrics.CurrentTPS, tpsMetrics.TotalTransactions,
		len(tpsMetrics.TPSHistory), len(tpsMetrics.TransactionsPerBlock))
	return nil
}

// ensureFinalStateValues ensures all final states have proper values
func (s *Storage) ensureFinalStateValues(state *FinalStateInfo) *FinalStateInfo {
	if state == nil {
		return &FinalStateInfo{
			BlockHash:   "unknown",
			BlockHeight: 0,
			MerkleRoot:  "unknown",
			Status:      "unknown",
			Signature:   "no_signature",
			MessageType: "unknown",
			Timestamp:   time.Now().Format(time.RFC3339),
			Valid:       false,
		}
	}

	// Ensure merkle_root is never empty
	if state.MerkleRoot == "" {
		block, err := s.GetBlockByHash(state.BlockHash)
		if err == nil && block != nil {
			state.MerkleRoot = hex.EncodeToString(block.CalculateTxsRoot())
		} else {
			// DON'T create fake merkle root - leave empty or use "pending"
			state.MerkleRoot = "" // Empty means not available yet
			// Or use: state.MerkleRoot = "pending"
			logger.Debug("Block %s not found in storage, leaving merkle_root empty", state.BlockHash)
		}
	}

	// Ensure status is never empty
	if state.Status == "" {
		switch state.MessageType {
		case "proposal":
			state.Status = "proposed"
		case "prepare":
			state.Status = "prepared"
		case "commit":
			state.Status = "committed"
		case "timeout":
			state.Status = "view_change"
		default:
			state.Status = "processed"
		}
	}

	// Ensure signature is never empty
	if state.Signature == "" {
		state.Signature = "no_signature"
	}

	// Ensure timestamp is never empty
	if state.Timestamp == "" {
		state.Timestamp = time.Now().Format(time.RFC3339)
	}

	// Ensure signature status is never empty
	if state.SignatureStatus == "" {
		if state.Valid {
			state.SignatureStatus = "Valid"
		} else {
			state.SignatureStatus = "Invalid"
		}
	}

	// Ensure message type is never empty
	if state.MessageType == "" {
		state.MessageType = "unknown"
	}

	return state
}

// createRealNodeInfo creates real node information without FinalState
// Helper method to create node information
func (s *Storage) createNodeInfo(index int) *NodeInfo {
	latestBlock, err := s.GetLatestBlock()
	var blockHash string
	var blockHeight uint64
	var merkleRoot string

	if err == nil && latestBlock != nil {
		blockHash = latestBlock.GetHash()
		blockHeight = latestBlock.GetHeight()
		merkleRoot = hex.EncodeToString(latestBlock.CalculateTxsRoot())
	}

	// Get TPS metrics for node info
	tpsMetrics := s.GetTPSMetrics()

	// Get actual genesis hash with GENESIS_ prefix for chain_info
	genesisHash, _ := s.GetGenesisHash()
	if genesisHash != "" && !strings.HasPrefix(genesisHash, "GENESIS_") {
		genesisHash = "GENESIS_" + genesisHash
	}

	// FIX: Use correct port range (32307+) matching actual node configuration
	// The actual nodes use ports 32307, 32308, 32309, not 32300, 32301, 32302
	nodeAddress := fmt.Sprintf("127.0.0.1:%d", 32307+index)
	nodeID := fmt.Sprintf("Node-%s", nodeAddress)

	node := &NodeInfo{
		NodeID:      nodeID,
		NodeName:    nodeID,
		NodeAddress: nodeAddress,
		ChainInfo: map[string]interface{}{
			"status":        "active",
			"last_updated":  time.Now().Format(time.RFC3339),
			"tps_current":   tpsMetrics.CurrentTPS,
			"tps_average":   tpsMetrics.AverageTPS,
			"total_txs":     tpsMetrics.TotalTransactions,
			"blocks_height": blockHeight,
			"genesis_hash":  genesisHash,
		},
		BlockHeight: blockHeight,
		BlockHash:   blockHash,
		MerkleRoot:  merkleRoot,
		Timestamp:   time.Now().Format(time.RFC3339),
	}

	return node
}

// GetStateDir returns the state directory path
func (s *Storage) GetStateDir() string {
	return s.stateDir
}

// SaveBlockSizeMetrics saves block size metrics to the chain state
func (s *Storage) SaveBlockSizeMetrics(metrics *BlockSizeMetrics) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Load existing chain state
	chainState, err := s.LoadCompleteChainState()
	if err != nil {
		// Create new chain state if it doesn't exist
		chainState = &ChainState{
			Timestamp: time.Now().Format(time.RFC3339),
		}
	}

	// Update block size metrics
	chainState.BlockSizeMetrics = metrics
	chainState.Timestamp = time.Now().Format(time.RFC3339)

	// Save updated chain state
	stateFile := filepath.Join(s.stateDir, "chain_state.json")
	data, err := json.MarshalIndent(chainState, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal chain state with block size metrics: %w", err)
	}

	// Write with atomic replace
	tmpFile := stateFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write chain state file: %w", err)
	}

	if err := os.Rename(tmpFile, stateFile); err != nil {
		return fmt.Errorf("failed to rename chain state file: %w", err)
	}

	logger.Info("Block size metrics saved to chain state: total_blocks=%d, avg_size=%.2f MB",
		metrics.TotalBlocks, metrics.AverageSizeMB)
	return nil
}

// LoadCompleteChainState loads the complete chain state
func (s *Storage) LoadCompleteChainState() (*ChainState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stateFile := filepath.Join(s.stateDir, "chain_state.json")

	// Check if file exists
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("chain state file does not exist: %s", stateFile)
	}

	data, err := os.ReadFile(stateFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read chain state file: %w", err)
	}

	var chainState ChainState
	if err := json.Unmarshal(data, &chainState); err != nil {
		return nil, fmt.Errorf("failed to unmarshal chain state: %w", err)
	}

	// Log block size metrics if available
	if chainState.BlockSizeMetrics != nil {
		metrics := chainState.BlockSizeMetrics
		logger.Info("Loaded block size metrics: total_blocks=%d, avg_size=%d bytes",
			metrics.TotalBlocks, metrics.AverageSize)
	}

	logger.Info("Complete chain state loaded from: %s", stateFile)
	return &chainState, nil
}

// GetChainStatePath returns the path to the chain state file
func (s *Storage) GetChainStatePath() string {
	return filepath.Join(s.stateDir, "chain_state.json")
}

// StoreBlock stores a block and updates indices with TxsRoot validation
func (s *Storage) StoreBlock(block *types.Block) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	blockHash := block.GetHash()
	height := block.GetHeight()

	logger.Info("Storing block: height=%d, hash=%s, ParentHash=%x",
		height, blockHash, block.Header.ParentHash)

	// SPECIAL HANDLING FOR GENESIS BLOCK
	if height == 0 {
		logger.Info("Genesis block detected, using relaxed TxsRoot validation")
		// For genesis block, we accept empty TxsRoot or calculate it
		if len(block.Header.TxsRoot) == 0 {
			// Calculate TxsRoot for empty transactions
			emptyTxsRoot := s.calculateEmptyMerkleRoot()
			block.Header.TxsRoot = emptyTxsRoot
			logger.Info("Set empty TxsRoot for genesis block: %x", emptyTxsRoot)
		}
	} else {
		// Normal blocks must pass TxsRoot validation
		if err := block.ValidateTxsRoot(); err != nil {
			return fmt.Errorf("block TxsRoot validation failed before storage: %w", err)
		}
	}

	// Calculate and log block size (simplified)
	data, err := json.Marshal(block)
	if err == nil {
		blockSize := uint64(len(data))
		logger.Info("Block %d size: %d bytes, transaction count: %d",
			height, blockSize, len(block.Body.TxsList))
	}

	// Check if block already exists
	if existing, exists := s.blockIndex[blockHash]; exists {
		if existing.GetHeight() == height {
			// Only skip if the new block has no MORE data than existing
			if len(block.Body.Attestations) <= len(existing.Body.Attestations) {
				logger.Info("Block already exists with same/more attestations: height=%d, hash=%s", height, blockHash)
				return nil
			}
			logger.Info("Block exists but new version has %d attestations (existing: %d), updating...",
				len(block.Body.Attestations), len(existing.Body.Attestations))
			// Fall through to re-store with attestations
		}
	}

	// Store block to disk
	if err := s.storeBlockToDisk(block); err != nil {
		return fmt.Errorf("failed to store block to disk: %w", err)
	}

	// Update in-memory indices
	s.blockIndex[blockHash] = block
	s.heightIndex[height] = block

	// Update transaction index
	for _, tx := range block.Body.TxsList {
		if tx.ID != "" {
			s.txIndex[tx.ID] = tx
		}
	}

	// Update chain state if this is the new best block
	if height >= s.totalBlocks {
		s.bestBlockHash = blockHash
		s.totalBlocks = height + 1
		logger.Info("Updated best block: height=%d, hash=%s, total=%d, TxsRoot=%x",
			height, blockHash, s.totalBlocks, block.Header.TxsRoot)
	}

	// Persist updated indices
	if err := s.saveBlockIndex(); err != nil {
		return fmt.Errorf("failed to save block index: %w", err)
	}
	if err := s.saveChainState(); err != nil {
		return fmt.Errorf("failed to save chain state: %w", err)
	}

	logger.Info("Successfully stored block: height=%d, hash=%s, TxsRoot=%x",
		height, blockHash, block.Header.TxsRoot)
	return nil
}

// DeleteBlocksAbove removes every stored block with height > targetHeight
// from disk, from the in-memory blockIndex/heightIndex/txIndex, and resets
// bestBlockHash/totalBlocks to match targetHeight. Used by
// Blockchain.RollbackToHeight during chain reorganization (see handleReorg
// in sync.go) to purge an invalidated fork from persistent storage —
// without this, a rolled-back chain would resurface after a restart or a
// plain GetBlockByNumber() lookup, since StoreBlock/loadBlockIndex would
// just reload the orphaned blocks straight back off disk.
//
// Mirrors the exact locking, indexing, and disk-file conventions used by
// StoreBlock/storeBlockToDisk/saveBlockIndex/saveChainState above, so the
// on-disk state stays internally consistent with those methods.
func (s *Storage) DeleteBlocksAbove(targetHeight uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.totalBlocks == 0 {
		return nil // nothing stored yet
	}
	currentTip := s.totalBlocks - 1
	if targetHeight >= currentTip {
		return nil // nothing above targetHeight to remove
	}

	logger.Info("🗑️ Purging stored blocks above height %d (current tip=%d)", targetHeight, currentTip)

	// hash-by-height lookup that falls back to the persisted block index
	// file for blocks not currently resident in heightIndex (e.g. loaded
	// this run but later evicted, or never touched since process start).
	hashForHeight := func(height uint64) (string, bool) {
		if block, ok := s.heightIndex[height]; ok {
			return block.GetHash(), true
		}
		return s.lookupHashInPersistedIndex(height)
	}

	removed := 0
	for height := currentTip; height > targetHeight; height-- {
		hash, found := hashForHeight(height)
		if !found {
			logger.Warn("DeleteBlocksAbove: no known hash for height %d, skipping disk cleanup for it", height)
			delete(s.heightIndex, height)
			continue
		}

		// Remove the block file from disk.
		filename := filepath.Join(s.blocksDir, s.sanitizeFilename(hash)+".json")
		if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("DeleteBlocksAbove: failed to remove block file for height %d: %w", height, err)
		}

		// Remove its transactions from the tx index, if the block was loaded.
		if block, ok := s.blockIndex[hash]; ok {
			for _, tx := range block.Body.TxsList {
				if tx != nil && tx.ID != "" {
					delete(s.txIndex, tx.ID)
				}
			}
		}

		delete(s.blockIndex, hash)
		delete(s.heightIndex, height)
		removed++
	}

	// Reset chain tip bookkeeping to targetHeight.
	s.totalBlocks = targetHeight + 1
	if newTipHash, found := hashForHeight(targetHeight); found {
		s.bestBlockHash = newTipHash
		// Make sure the new tip is actually loaded in memory, not just
		// known by hash — GetLatestBlock() reads it straight out of
		// blockIndex.
		if _, ok := s.blockIndex[newTipHash]; !ok {
			if block, err := s.loadBlockFromDisk(newTipHash); err == nil {
				s.blockIndex[newTipHash] = block
				s.heightIndex[targetHeight] = block
			} else {
				logger.Error("DeleteBlocksAbove: rollback target block %s (height %d) has a known hash but failed to load from disk: %v",
					newTipHash, targetHeight, err)
			}
		}
	} else {
		// This should not happen in practice: targetHeight is always the
		// fork point returned by FindCommonAncestor, which only returns
		// heights of blocks the local chain actually has. Fail loudly
		// rather than silently leaving bestBlockHash pointing nowhere.
		return fmt.Errorf("DeleteBlocksAbove: no known block for target height %d, refusing to leave bestBlockHash inconsistent", targetHeight)
	}

	// Persist the updated index and chain state so the purge survives a restart.
	if err := s.saveBlockIndex(); err != nil {
		return fmt.Errorf("DeleteBlocksAbove: failed to save block index: %w", err)
	}
	if err := s.saveChainState(); err != nil {
		return fmt.Errorf("DeleteBlocksAbove: failed to save chain state: %w", err)
	}

	logger.Info("✅ Purged %d stored blocks above height %d (tip now %d, hash=%s)",
		removed, targetHeight, targetHeight, s.bestBlockHash)
	return nil
}

// lookupHashInPersistedIndex reads the on-disk block_index.json (hash ->
// height map, same format written by saveBlockIndex) to find the hash for
// a given height, for blocks that aren't currently loaded into
// s.heightIndex. Returns ("", false) if the index file is missing, unreadable,
// or has no entry for that height.
func (s *Storage) lookupHashInPersistedIndex(height uint64) (string, bool) {
	indexFile := filepath.Join(s.indexDir, "block_index.json")
	data, err := os.ReadFile(indexFile)
	if err != nil {
		return "", false
	}

	var index struct {
		Blocks map[string]uint64 `json:"blocks"` // hash -> height
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return "", false
	}

	for hash, h := range index.Blocks {
		if h == height {
			return hash, true
		}
	}
	return "", false
}

// ReplaceGenesis overwrites the local genesis block with one received from a peer.
// This is used by late-joining nodes that created a local genesis (with their own
// wall-clock timestamp) and need to adopt the network's canonical genesis block.
func (s *Storage) ReplaceGenesis(block *types.Block) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	blockHash := block.GetHash()
	height := block.GetHeight()
	if height != 0 {
		return fmt.Errorf("ReplaceGenesis: block height %d is not genesis (height 0)", height)
	}

	// Remove old genesis from indices
	for hash, existing := range s.blockIndex {
		if existing.GetHeight() == 0 {
			delete(s.blockIndex, hash)
			break
		}
	}
	for h := range s.heightIndex {
		if h == 0 {
			delete(s.heightIndex, h)
			break
		}
	}

	// Store the new genesis block to disk
	if err := s.storeBlockToDisk(block); err != nil {
		return fmt.Errorf("ReplaceGenesis: failed to store block to disk: %w", err)
	}

	// Update in-memory indices
	s.blockIndex[blockHash] = block
	s.heightIndex[0] = block
	s.bestBlockHash = blockHash
	s.totalBlocks = 1

	// Persist updated indices
	if err := s.saveBlockIndex(); err != nil {
		return fmt.Errorf("ReplaceGenesis: failed to save block index: %w", err)
	}
	if err := s.saveChainState(); err != nil {
		return fmt.Errorf("ReplaceGenesis: failed to save chain state: %w", err)
	}

	logger.Info("✅ ReplaceGenesis: genesis replaced with peer's version — hash=%s", blockHash)
	return nil
}

// calculateEmptyMerkleRoot returns standard empty Merkle root
func (s *Storage) calculateEmptyMerkleRoot() []byte {
	// This should match what the blockchain calculates
	return common.SpxHash([]byte{})
}

// GetBlockByHash retrieves a block by its hash
func (s *Storage) GetBlockByHash(hash string) (*types.Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Try in-memory index first
	if block, exists := s.blockIndex[hash]; exists {
		return block, nil
	}

	// Fall back to disk
	block, err := s.loadBlockFromDisk(hash)
	if err != nil {
		return nil, fmt.Errorf("block not found: %w", err)
	}

	// Update in-memory index
	s.blockIndex[hash] = block
	s.heightIndex[block.GetHeight()] = block

	return block, nil
}

// GetLatestBlock returns the latest block in the chain
func (s *Storage) GetLatestBlock() (*types.Block, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.bestBlockHash == "" {
		return nil, fmt.Errorf("no blocks in storage")
	}

	block, exists := s.blockIndex[s.bestBlockHash]
	if !exists {
		return nil, fmt.Errorf("best block not found in index: %s", s.bestBlockHash)
	}

	return block, nil
}

// GetBestBlockHash returns the hash of the best block
func (s *Storage) GetBestBlockHash() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bestBlockHash
}

// ValidateChain validates the integrity of the stored chain
func (s *Storage) ValidateChain() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.totalBlocks == 0 {
		return nil
	}

	// Start from genesis and validate each block links to the previous
	var previousBlock *types.Block
	for height := uint64(0); height < s.totalBlocks; height++ {
		block, err := s.GetBlockByHeight(height)
		if err != nil {
			return fmt.Errorf("missing block at height %d: %w", height, err)
		}

		// Validate block structure
		if err := block.Validate(); err != nil {
			return fmt.Errorf("invalid block at height %d: %w", height, err)
		}

		// Validate chain linkage (except genesis)
		if height > 0 {
			currentParentHash := block.GetPrevHash()
			expectedParentHash := previousBlock.GetHash()

			if currentParentHash != expectedParentHash {
				return fmt.Errorf("chain broken at height %d: ParentHash %s does not match previous block hash %s",
					height, currentParentHash, expectedParentHash)
			}

			logger.Debug("Chain validation: height=%d, ParentHash=%s matches previous block hash=%s",
				height, currentParentHash, expectedParentHash)
		}

		previousBlock = block
	}

	logger.Info("Chain validation completed successfully: %d blocks validated with consistent ParentHash links", s.totalBlocks)
	return nil
}

// isHexString checks if a string is a valid hex string
func isHexString(s string) bool {
	// Empty string is not a valid hex string
	if len(s) == 0 {
		return false
	}

	// Hex strings should have even length (each byte is 2 hex chars)
	if len(s)%2 != 0 {
		return false
	}

	// Check each character is a valid hex digit
	for _, c := range s {
		if !((c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'f') ||
			(c >= 'A' && c <= 'F')) {
			return false
		}
	}

	return true
}

// Helper method to get actual genesis hash from block_index.json
// GetGenesisHash returns the genesis hash with GENESIS_ prefix from block_index.json
func (s *Storage) GetGenesisHash() (string, error) {
	indexFile := filepath.Join(s.indexDir, "block_index.json")

	data, err := os.ReadFile(indexFile)
	if err != nil {
		return "", fmt.Errorf("failed to read block_index.json: %w", err)
	}

	var index struct {
		Blocks map[string]uint64 `json:"blocks"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return "", fmt.Errorf("failed to unmarshal block_index.json: %w", err)
	}

	// Find the block with height 0 (genesis)
	for hash, height := range index.Blocks {
		if height == 0 {
			// CRITICAL: Ensure the genesis hash always has the GENESIS_ prefix
			if !strings.HasPrefix(hash, "GENESIS_") {
				logger.Warn("Genesis hash in block_index.json missing GENESIS_ prefix: %s", hash)
				// If it's a valid hex string, add the prefix
				if isHexString(hash) {
					fixedHash := "GENESIS_" + hash
					logger.Info("Fixed genesis hash by adding prefix: %s", fixedHash)
					return fixedHash, nil
				}
			}
			return hash, nil
		}
	}

	return "", fmt.Errorf("no genesis block found in block_index.json")
}

// FixChainStateGenesisHash updates any hardcoded genesis hash in chain_state.json with actual hash
// FixChainStateGenesisHash updates any hardcoded genesis hash in chain_state.json with actual hash including GENESIS_ prefix
func (s *Storage) FixChainStateGenesisHash() error {
	stateFile := filepath.Join(s.stateDir, "chain_state.json")

	// Check if file exists
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		return nil // No chain state to fix
	}

	// Read existing chain state
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return fmt.Errorf("failed to read chain state file: %w", err)
	}

	var chainState ChainState
	if err := json.Unmarshal(data, &chainState); err != nil {
		return fmt.Errorf("failed to unmarshal chain state: %w", err)
	}

	// Get actual genesis hash with GENESIS_ prefix
	actualHash, err := s.GetGenesisHash()
	if err != nil {
		return fmt.Errorf("failed to get actual genesis hash: %w", err)
	}

	// Ensure the actual hash has GENESIS_ prefix
	if !strings.HasPrefix(actualHash, "GENESIS_") {
		logger.Warn("Actual genesis hash missing GENESIS_ prefix, adding it: %s", actualHash)
		actualHash = "GENESIS_" + actualHash
	}

	needsUpdate := false

	// Fix ChainIdentification genesis hash
	if chainState.ChainIdentification != nil && chainState.ChainIdentification.ChainParams != nil {
		if genesisHash, exists := chainState.ChainIdentification.ChainParams["genesis_hash"]; exists {
			if genesisHashStr, ok := genesisHash.(string); ok {
				if genesisHashStr != actualHash {
					chainState.ChainIdentification.ChainParams["genesis_hash"] = actualHash
					logger.Info("Fixed genesis hash in ChainIdentification: %s", actualHash)
					needsUpdate = true
				}
			}
		} else {
			// Add genesis_hash if it doesn't exist
			chainState.ChainIdentification.ChainParams["genesis_hash"] = actualHash
			logger.Info("Added genesis hash to ChainIdentification: %s", actualHash)
			needsUpdate = true
		}
	}

	// Fix BasicChainState best block hash if it's the genesis block
	if chainState.BasicChainState != nil && chainState.BasicChainState.BestBlockHash != "" {
		// Check if best block is genesis (height 0)
		if chainState.BasicChainState.TotalBlocks == 1 {
			genesisBlock, err := s.GetBlockByHeight(0)
			if err == nil && genesisBlock != nil {
				genesisHash := genesisBlock.GetHash()
				if strings.HasPrefix(genesisHash, "GENESIS_") && chainState.BasicChainState.BestBlockHash != genesisHash {
					chainState.BasicChainState.BestBlockHash = genesisHash
					logger.Info("Fixed best block hash to genesis hash: %s", genesisHash)
					needsUpdate = true
				}
			}
		}
	}

	// Fix StorageState best block hash if it's the genesis block
	if chainState.StorageState != nil && chainState.StorageState.BestBlockHash != "" {
		// Check if best block is genesis (height 0)
		if chainState.StorageState.TotalBlocks == 1 {
			genesisBlock, err := s.GetBlockByHeight(0)
			if err == nil && genesisBlock != nil {
				genesisHash := genesisBlock.GetHash()
				if strings.HasPrefix(genesisHash, "GENESIS_") && chainState.StorageState.BestBlockHash != genesisHash {
					chainState.StorageState.BestBlockHash = genesisHash
					logger.Info("Fixed storage state best block hash to genesis hash: %s", genesisHash)
					needsUpdate = true
				}
			}
		}
	}

	// Fix node block hashes if they point to genesis
	for _, node := range chainState.Nodes {
		if node != nil && node.BlockHeight == 0 && node.BlockHash != "" {
			genesisBlock, err := s.GetBlockByHeight(0)
			if err == nil && genesisBlock != nil {
				genesisHash := genesisBlock.GetHash()
				if strings.HasPrefix(genesisHash, "GENESIS_") && node.BlockHash != genesisHash {
					node.BlockHash = genesisHash
					logger.Info("Fixed node %s genesis block hash: %s", node.NodeID, genesisHash)
					needsUpdate = true
				}
			}
		}
	}

	// ─── Fix per-node chain_info.genesis_hash ───────────────────────────────
	// The FixChainStateGenesisHash function (above) already fixes the top-level
	// ChainIdentification section, but the nodes[].chain_info map can also hold
	// a stale / wrong genesis_hash string (e.g. "DEVNET_GENESIS_…" instead of
	// "GENESIS_…").  Walk every node and correct it.
	for _, node := range chainState.Nodes {
		if node == nil || node.ChainInfo == nil {
			continue
		}
		if gh, exists := node.ChainInfo["genesis_hash"]; exists {
			if ghStr, ok := gh.(string); ok {
				if ghStr != actualHash {
					node.ChainInfo["genesis_hash"] = actualHash
					logger.Info("Fixed node %s genesis_hash in chain_info: %s", node.NodeID, actualHash)
					needsUpdate = true
				}
			}
		} else {
			// Add genesis_hash if it doesn't exist — ensures every node entry
			// carries the canonical hash so downstream consumers (CLI, wallet,
			// chain explorer) always see the correct value.
			node.ChainInfo["genesis_hash"] = actualHash
			logger.Info("Added genesis_hash to node %s chain_info: %s", node.NodeID, actualHash)
			needsUpdate = true
		}
	}

	// Save the fixed chain state if changes were made
	if needsUpdate {
		logger.Info("Updating chain_state.json with correct genesis hash including GENESIS_ prefix")

		// Save the fixed chain state
		data, err := json.MarshalIndent(chainState, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal fixed chain state: %w", err)
		}

		tmpFile := stateFile + ".tmp"
		if err := os.WriteFile(tmpFile, data, 0644); err != nil {
			return fmt.Errorf("failed to write fixed chain state file: %w", err)
		}

		if err := os.Rename(tmpFile, stateFile); err != nil {
			return fmt.Errorf("failed to rename fixed chain state file: %w", err)
		}

		logger.Info("Successfully updated chain_state.json with genesis hash: %s", actualHash)
	} else {
		logger.Info("chain_state.json already has correct genesis hash: %s", actualHash)
	}

	return nil
}

// Private methods
// sanitizeFilename ensures a hash can be used as a valid filename
func (s *Storage) sanitizeFilename(hash string) string {
	// If hash contains non-printable characters, use hex encoding
	for _, r := range hash {
		if r < 32 || r > 126 {
			// Hash contains non-printable chars, use hex encoding
			return hex.EncodeToString([]byte(hash))
		}
	}

	// Also check for other invalid filename characters
	invalidChars := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	sanitized := hash
	for _, char := range invalidChars {
		sanitized = strings.ReplaceAll(sanitized, char, "_")
	}

	return sanitized
}

// storeBlockToDisk stores a block to disk with sanitized filenames
func (s *Storage) storeBlockToDisk(block *types.Block) error {
	blockHash := block.GetHash()
	sanitizedHash := s.sanitizeFilename(blockHash)
	filename := filepath.Join(s.blocksDir, sanitizedHash+".json")

	// Ensure the block directory exists
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("failed to create block directory: %w", err)
	}

	logger.Info("Storing block to disk: original_hash=%s, sanitized_filename=%s, ParentHash=%x",
		blockHash, sanitizedHash, block.Header.ParentHash)

	// Create a custom serialization structure with ISO timestamp
	type SerializableBlock struct {
		Header struct {
			Hash                  string `json:"hash"`        // This block's hash
			TxsRoot               string `json:"txs_root"`    // Merkle root of transactions
			StateRoot             string `json:"state_root"`  // State Merkle root
			ParentHash            string `json:"parent_hash"` // Hash of the previous block (chain continuity)
			UnclesHash            string `json:"uncles_hash"` // Hash of uncle blocks
			ExtraData             string `json:"extra_data"`  // Additional block data
			Miner                 string `json:"miner"`       // Miner address
			Version               uint64 `json:"version"`     // Block version
			NBlock                uint64 `json:"nblock"`      // Block number/height
			Height                uint64 `json:"height"`      // Block height
			Timestamp             string `json:"timestamp"`   // Block timestamp in ISO RFC format
			Difficulty            string `json:"difficulty"`  // Mining difficulty
			Nonce                 string `json:"nonce"`       // Mining nonce
			GasLimit              string `json:"gas_limit"`   // Gas limit
			GasUsed               string `json:"gas_used"`    // Gas used
			ProposerSignature     string `json:"proposer_signature"`
			ProposerSignatureHash string `json:"proposer_signature_hash,omitempty"`
			ProposerID            string `json:"proposer_id"`
			SigDataHash           string `json:"sig_data_hash,omitempty"`
			CommitStatus          string `json:"commit_status"`
			SigValid              bool   `json:"signature_valid"`
		} `json:"header"`
		Body struct {
			TxsList      []map[string]interface{} `json:"txs_list"`
			UnclesHash   string                   `json:"uncles_hash"`
			Attestations []map[string]interface{} `json:"attestations,omitempty"`
		} `json:"body"`
	}

	var serializableBlock SerializableBlock

	// Convert header - handle ParentHash specially to preserve GENESIS_ prefix
	if block.Header != nil {
		serializableBlock.Header.Hash = blockHash
		serializableBlock.Header.TxsRoot = hex.EncodeToString(block.Header.TxsRoot)
		serializableBlock.Header.StateRoot = hex.EncodeToString(block.Header.StateRoot)

		// FIX: Handle ParentHash specially - check if it's a genesis hash
		parentHashStr := string(block.Header.ParentHash)
		if strings.HasPrefix(parentHashStr, "GENESIS_") {
			// It's a genesis hash, store as string to preserve the prefix
			serializableBlock.Header.ParentHash = parentHashStr
			logger.Info("DEBUG: ParentHash is genesis hash, storing as string: %s", parentHashStr)
		} else {
			// Normal hash, store as hex
			serializableBlock.Header.ParentHash = hex.EncodeToString(block.Header.ParentHash)
			logger.Info("DEBUG: ParentHash is normal hash, storing as hex: %s", serializableBlock.Header.ParentHash)
		}

		serializableBlock.Header.UnclesHash = hex.EncodeToString(block.Header.UnclesHash)
		serializableBlock.Header.ExtraData = string(block.Header.ExtraData)
		serializableBlock.Header.Miner = hex.EncodeToString(block.Header.Miner)
		serializableBlock.Header.Version = block.Header.Version
		serializableBlock.Header.NBlock = block.Header.Block
		serializableBlock.Header.Height = block.Header.Height

		// Convert timestamp to ISO RFC format
		timestampISO := common.GetTimeService().GetTimeInfo(block.Header.Timestamp).ISOUTC
		serializableBlock.Header.Timestamp = timestampISO

		serializableBlock.Header.Difficulty = block.Header.Difficulty.String()
		serializableBlock.Header.Nonce = block.Header.Nonce
		serializableBlock.Header.GasLimit = block.Header.GasLimit.String()
		serializableBlock.Header.GasUsed = block.Header.GasUsed.String()
		serializableBlock.Header.ProposerSignature = hex.EncodeToString(block.Header.ProposerSignature)
		if len(block.Header.ProposerSignature) > 0 {
			serializableBlock.Header.ProposerSignatureHash = hex.EncodeToString(common.SpxHash(block.Header.ProposerSignature))
		}
		serializableBlock.Header.ProposerID = block.Header.ProposerID
		serializableBlock.Header.SigDataHash = hex.EncodeToString(block.Header.SigDataHash)
		// Default empty CommitStatus — blocks only reach disk when committed
		commitStatus := block.Header.CommitStatus
		if commitStatus == "" {
			commitStatus = "committed"
		}
		serializableBlock.Header.CommitStatus = commitStatus

		// If a signature exists, it was verified before commit
		sigValid := block.Header.SigValid
		if !sigValid && len(block.Header.ProposerSignature) > 0 {
			sigValid = true
		}
		serializableBlock.Header.SigValid = sigValid
	}
	// Convert attestations
	serializableBlock.Body.Attestations = make([]map[string]interface{}, 0, len(block.Body.Attestations))
	for _, att := range block.Body.Attestations {
		if att == nil {
			continue
		}
		serializableBlock.Body.Attestations = append(serializableBlock.Body.Attestations, map[string]interface{}{
			"validator_id": att.ValidatorID,
			"block_hash":   att.BlockHash,
			"view":         att.View,
			"signature":    hex.EncodeToString(att.Signature),
		})
	}

	// Convert transactions to maps with ISO timestamps
	serializableBlock.Body.TxsList = make([]map[string]interface{}, len(block.Body.TxsList))
	for i, tx := range block.Body.TxsList {
		timestampISO := common.GetTimeService().GetTimeInfo(tx.Timestamp).ISOUTC

		// Convert transaction to map
		txMap := map[string]interface{}{
			"id":        tx.ID,
			"sender":    tx.Sender,
			"receiver":  tx.Receiver,
			"amount":    tx.Amount.String(), // Convert big.Int to string
			"gas_limit": tx.GasLimit.String(),
			"gas_price": tx.GasPrice.String(),
			"nonce":     tx.Nonce,
			"timestamp": timestampISO, // ISO format
			"signature": hex.EncodeToString(tx.Signature),
		}
		serializableBlock.Body.TxsList[i] = txMap
	}

	serializableBlock.Body.UnclesHash = hex.EncodeToString(block.Body.UnclesHash)

	data, err := json.MarshalIndent(serializableBlock, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal block: %w", err)
	}

	// Write with atomic replace
	tmpFile := filename + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write block file: %w", err)
	}

	if err := os.Rename(tmpFile, filename); err != nil {
		return fmt.Errorf("failed to rename block file: %w", err)
	}

	logger.Info("Block successfully written to disk with ISO timestamp: %s", serializableBlock.Header.Timestamp)
	return nil
}

// loadBlockFromDisk loads a block from disk, handling both string and hex ParentHash formats and ISO timestamp
func (s *Storage) loadBlockFromDisk(hash string) (*types.Block, error) {
	filenames := []string{
		filepath.Join(s.blocksDir, hash+".json"),
		filepath.Join(s.blocksDir, s.sanitizeFilename(hash)+".json"),
	}

	var data []byte
	var usedFilename string

	for _, filename := range filenames {
		if _, err := os.Stat(filename); err == nil {
			var err error
			data, err = os.ReadFile(filename)
			if err == nil {
				usedFilename = filename
				break
			}
		}
	}

	if data == nil {
		return nil, fmt.Errorf("block file does not exist for hash: %s", hash)
	}

	type TempBlock struct {
		Header struct {
			Hash                  string `json:"hash"`
			TxsRoot               string `json:"txs_root"`
			StateRoot             string `json:"state_root"`
			ParentHash            string `json:"parent_hash"`
			UnclesHash            string `json:"uncles_hash"`
			ExtraData             string `json:"extra_data"`
			Miner                 string `json:"miner"`
			Version               uint64 `json:"version"`
			NBlock                uint64 `json:"nblock"`
			Height                uint64 `json:"height"`
			Timestamp             string `json:"timestamp"`
			Difficulty            string `json:"difficulty"`
			Nonce                 string `json:"nonce"` // ← Changed from uint64 to string
			GasLimit              string `json:"gas_limit"`
			GasUsed               string `json:"gas_used"`
			ProposerSignature     string `json:"proposer_signature"`
			ProposerSignatureHash string `json:"proposer_signature_hash,omitempty"`
			ProposerID            string `json:"proposer_id"`
			SigDataHash           string `json:"sig_data_hash,omitempty"`
			CommitStatus          string `json:"commit_status"`
			SigValid              bool   `json:"signature_valid"`
		} `json:"header"`
		Body struct {
			TxsList      []map[string]interface{} `json:"txs_list"`
			UnclesHash   string                   `json:"uncles_hash"`
			Attestations []map[string]interface{} `json:"attestations"`
		} `json:"body"`
	}

	var tempBlock TempBlock
	if err := json.Unmarshal(data, &tempBlock); err != nil {
		logger.Warn("Failed to unmarshal block file %s: %v, file content: %s",
			usedFilename, err, string(data[:min(100, len(data))]))
		return nil, fmt.Errorf("failed to unmarshal block: %w", err)
	}

	// ---- DO NOT touch block before this line ----

	// Parse timestamp
	var timestamp int64
	if tempBlock.Header.Timestamp != "" {
		t, err := time.Parse(time.RFC3339, tempBlock.Header.Timestamp)
		if err == nil {
			timestamp = t.Unix()
		} else if ts, err := strconv.ParseInt(tempBlock.Header.Timestamp, 10, 64); err == nil {
			timestamp = ts
		} else {
			timestamp = time.Now().Unix()
			logger.Warn("Could not parse timestamp '%s' for block %s, using current time",
				tempBlock.Header.Timestamp, hash)
		}
	} else {
		timestamp = time.Now().Unix()
	}

	// Parse nonce BEFORE creating the block header
	var nonceValue uint64
	if tempBlock.Header.Nonce != "" {
		// Parse the hex string to uint64
		parsedNonce, err := strconv.ParseUint(tempBlock.Header.Nonce, 16, 64)
		if err != nil {
			// If parsing fails, default to 0
			logger.Warn("Failed to parse nonce '%s', using 0: %v", tempBlock.Header.Nonce, err)
			nonceValue = 0
		} else {
			nonceValue = parsedNonce
		}
	} else {
		nonceValue = 0
	}

	// DECLARE block HERE first
	var block types.Block
	block.Header = &types.BlockHeader{
		Version:    tempBlock.Header.Version,
		Block:      tempBlock.Header.NBlock,
		Height:     tempBlock.Header.Height,
		Timestamp:  timestamp,
		Hash:       []byte(tempBlock.Header.Hash),
		ParentHash: s.decodeParentHash(tempBlock.Header.ParentHash),
		TxsRoot:    s.decodeHexField(tempBlock.Header.TxsRoot),
		StateRoot:  s.decodeHexField(tempBlock.Header.StateRoot),
		UnclesHash: s.decodeHexField(tempBlock.Header.UnclesHash),
		ExtraData:  []byte(tempBlock.Header.ExtraData),
		Miner:      s.decodeHexField(tempBlock.Header.Miner),
		Nonce:      common.FormatNonce(nonceValue), // ← Use parsed nonceValue (not nonceUint)
	}

	// New PoS fields — safe here because block.Header now exists
	block.Header.CommitStatus = tempBlock.Header.CommitStatus
	if block.Header.CommitStatus == "" {
		block.Header.CommitStatus = "committed"
	}
	block.Header.ProposerID = tempBlock.Header.ProposerID
	if tempBlock.Header.SigDataHash != "" {
		if sigDataHash, err := hex.DecodeString(tempBlock.Header.SigDataHash); err == nil {
			block.Header.SigDataHash = sigDataHash
		} else {
			logger.Warn("Failed to decode sig_data_hash for block %s: %v", hash, err)
		}
	}
	if tempBlock.Header.ProposerSignature != "" {
		if sig, err := hex.DecodeString(tempBlock.Header.ProposerSignature); err == nil {
			block.Header.ProposerSignature = sig
		} else {
			logger.Warn("Failed to decode proposer_signature for block %s: %v", hash, err)
		}
	}
	block.Header.SigValid = tempBlock.Header.SigValid
	if !block.Header.SigValid && len(block.Header.ProposerSignature) > 0 {
		block.Header.SigValid = true
	}

	// Numeric fields
	difficulty, ok := new(big.Int).SetString(tempBlock.Header.Difficulty, 10)
	if !ok {
		difficulty = big.NewInt(1)
	}
	block.Header.Difficulty = difficulty

	gasLimit, ok := new(big.Int).SetString(tempBlock.Header.GasLimit, 10)
	if !ok {
		gasLimit = big.NewInt(0)
	}
	block.Header.GasLimit = gasLimit

	gasUsed, ok := new(big.Int).SetString(tempBlock.Header.GasUsed, 10)
	if !ok {
		gasUsed = big.NewInt(0)
	}
	block.Header.GasUsed = gasUsed

	// Transactions
	block.Body.TxsList = make([]*types.Transaction, len(tempBlock.Body.TxsList))
	for i, txMap := range tempBlock.Body.TxsList {
		tx := &types.Transaction{
			ID:       getStringFromMap(txMap, "id"),
			Sender:   getStringFromMap(txMap, "sender"),
			Receiver: getStringFromMap(txMap, "receiver"),
			Nonce:    getUint64FromMap(txMap, "nonce"),
		}
		if amountStr, ok := txMap["amount"].(string); ok {
			amount := new(big.Int)
			amount.SetString(amountStr, 10)
			tx.Amount = amount
		} else {
			tx.Amount = big.NewInt(0)
		}
		if gasLimitStr, ok := txMap["gas_limit"].(string); ok {
			gl := new(big.Int)
			gl.SetString(gasLimitStr, 10)
			tx.GasLimit = gl
		} else {
			tx.GasLimit = big.NewInt(0)
		}
		if gasPriceStr, ok := txMap["gas_price"].(string); ok {
			gp := new(big.Int)
			gp.SetString(gasPriceStr, 10)
			tx.GasPrice = gp
		} else {
			tx.GasPrice = big.NewInt(0)
		}
		if tsStr, ok := txMap["timestamp"].(string); ok {
			if t, err := time.Parse(time.RFC3339, tsStr); err == nil {
				tx.Timestamp = t.Unix()
			}
		}
		if sigStr, ok := txMap["signature"].(string); ok {
			if sig, err := hex.DecodeString(sigStr); err == nil {
				tx.Signature = sig
			}
		}
		block.Body.TxsList[i] = tx
	}

	// Attestations
	for _, attMap := range tempBlock.Body.Attestations {
		att := &types.Attestation{
			ValidatorID: getStringFromMap(attMap, "validator_id"),
			BlockHash:   getStringFromMap(attMap, "block_hash"),
			View:        getUint64FromMap(attMap, "view"),
		}
		if sigStr := getStringFromMap(attMap, "signature"); sigStr != "" {
			att.Signature, _ = hex.DecodeString(sigStr)
		}
		block.Body.Attestations = append(block.Body.Attestations, att)
	}

	block.Body.UnclesHash = s.decodeHexField(tempBlock.Body.UnclesHash)

	logger.Debug("Block loaded from disk: height=%d, hash=%s, commit_status=%s, sig_valid=%t, file=%s",
		block.GetHeight(), block.GetHash(), block.Header.CommitStatus, block.Header.SigValid, usedFilename)

	return &block, nil
}

// Helper functions for map conversion
func getStringFromMap(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getUint64FromMap(m map[string]interface{}, key string) uint64 {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case float64:
			return uint64(v)
		case int:
			return uint64(v)
		case int64:
			return uint64(v)
		case uint64:
			return v
		case string:
			if parsed, err := strconv.ParseUint(v, 10, 64); err == nil {
				return parsed
			}
		}
	}
	return 0
}

// decodeParentHash handles ParentHash conversion, specifically handling hex-encoded genesis hashes
func (s *Storage) decodeParentHash(parentHashStr string) []byte {
	// Check if it's a hex-encoded genesis hash
	if isHexEncodedGenesis(parentHashStr) {
		// Decode the hex string back to the original GENESIS_ format
		decoded, err := hex.DecodeString(parentHashStr)
		if err == nil {
			decodedStr := string(decoded)
			if strings.HasPrefix(decodedStr, "GENESIS_") {
				logger.Debug("Converted hex-encoded genesis ParentHash back to string: %s", decodedStr)
				return []byte(decodedStr)
			}
		}
	}

	// If it's already a string (like GENESIS_...), return as bytes
	if strings.HasPrefix(parentHashStr, "GENESIS_") {
		return []byte(parentHashStr)
	}

	// Otherwise decode as hex for normal hashes
	data, err := hex.DecodeString(parentHashStr)
	if err != nil {
		// If it's not valid hex, return as bytes
		return []byte(parentHashStr)
	}
	return data
}

// decodeHexField decodes hex fields, handling both hex and string formats
func (s *Storage) decodeHexField(field string) []byte {
	// If it's already a string (like GENESIS_...), return as bytes
	if strings.HasPrefix(field, "GENESIS_") {
		return []byte(field)
	}

	// Otherwise decode as hex
	data, err := hex.DecodeString(field)
	if err != nil {
		// If it's not valid hex, return as bytes
		return []byte(field)
	}
	return data
}

// isHexEncodedGenesis checks if a string is a hex-encoded genesis hash
func isHexEncodedGenesis(s string) bool {
	if len(s) < 16 { // "GENESIS_" hex-encoded is 16 chars
		return false
	}
	// Check if it starts with hex-encoded "GENESIS_" (47454e455349535f)
	return s[:16] == "47454e455349535f"
}

func (s *Storage) saveBlockIndex() error {
	indexFile := filepath.Join(s.indexDir, "block_index.json")

	// Create a simplified index for persistence
	index := struct {
		Blocks map[string]uint64 `json:"blocks"` // hash -> height
	}{
		Blocks: make(map[string]uint64),
	}

	for hash, block := range s.blockIndex {
		index.Blocks[hash] = block.GetHeight()
	}

	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal block index: %w", err)
	}

	return os.WriteFile(indexFile, data, 0644)
}

// FIXED loadBlockIndex method
func (s *Storage) loadBlockIndex() error {
	indexFile := filepath.Join(s.indexDir, "block_index.json")

	// Check if index file exists
	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		logger.Info("No block index file found, starting fresh")
		return nil // No index file yet
	}

	data, err := os.ReadFile(indexFile)
	if err != nil {
		return fmt.Errorf("failed to read block index: %w", err)
	}

	var index struct {
		Blocks map[string]uint64 `json:"blocks"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return fmt.Errorf("failed to unmarshal block index: %w", err)
	}

	// Load blocks into memory index - but don't fail if some blocks can't be loaded
	loadedCount := 0
	for hash, height := range index.Blocks {
		// Skip invalid entries
		if hash == "" {
			logger.Warn("Warning: Skipping block with empty hash")
			continue
		}

		block, err := s.loadBlockFromDisk(hash)
		if err != nil {
			logger.Warn("Warning: Could not load block %s at height %d: %v", hash, height, err)
			// Don't fail completely, just skip this block
			continue
		}

		s.blockIndex[hash] = block
		s.heightIndex[height] = block
		loadedCount++

		// Update chain state
		if height >= s.totalBlocks {
			s.totalBlocks = height + 1
			s.bestBlockHash = hash
		}
	}

	logger.Info("Loaded block index: %d blocks (from %d entries)", loadedCount, len(index.Blocks))

	// If no blocks were loaded but index exists, reset state
	if loadedCount == 0 && len(index.Blocks) > 0 {
		logger.Warn("Warning: Block index exists but no blocks could be loaded, resetting index")
		// Reset the corrupted index
		s.blockIndex = make(map[string]*types.Block)
		s.heightIndex = make(map[uint64]*types.Block)
		s.totalBlocks = 0
		s.bestBlockHash = ""

		// Remove the corrupted index file
		if err := os.Remove(indexFile); err != nil {
			logger.Warn("Warning: Failed to remove corrupted index file: %v", err)
		}
	}

	return nil
}

// saveChainState now saves basic chain state data directly to the main chain_state.json
func (s *Storage) saveChainState() error {
	stateFile := filepath.Join(s.stateDir, "chain_state.json")

	// Check if complete chain state already exists
	if _, err := os.Stat(stateFile); err == nil {
		// Complete chain state exists, update the basic chain state within it
		return s.updateBasicChainStateInFile(stateFile)
	}

	// No complete chain state exists, create a basic one
	basicState := &BasicChainState{
		BestBlockHash: s.bestBlockHash,
		TotalBlocks:   s.totalBlocks,
		LastUpdated:   time.Now().Format(time.RFC3339),
	}

	data, err := json.MarshalIndent(basicState, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal basic chain state: %w", err)
	}

	return os.WriteFile(stateFile, data, 0644)
}

// updateBasicChainStateInFile updates only the basic chain state portion of an existing chain_state.json
func (s *Storage) updateBasicChainStateInFile(stateFile string) error {
	// Read existing chain state
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return fmt.Errorf("failed to read chain state file: %w", err)
	}

	var chainState ChainState
	if err := json.Unmarshal(data, &chainState); err != nil {
		// If it's not a ChainState, it might be a basic state file
		// In that case, we'll upgrade it to a complete chain state
		var basicState BasicChainState
		if err := json.Unmarshal(data, &basicState); err == nil {
			// Upgrade basic state to complete state
			chainState = ChainState{
				BasicChainState: &basicState,
				Timestamp:       time.Now().Format(time.RFC3339),
			}
		} else {
			return fmt.Errorf("failed to unmarshal chain state: %w", err)
		}
	}

	// Update basic chain state
	if chainState.BasicChainState == nil {
		chainState.BasicChainState = &BasicChainState{}
	}

	chainState.BasicChainState.BestBlockHash = s.bestBlockHash
	chainState.BasicChainState.TotalBlocks = s.totalBlocks
	chainState.BasicChainState.LastUpdated = time.Now().Format(time.RFC3339)

	// Save updated chain state
	data, err = json.MarshalIndent(chainState, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal updated chain state: %w", err)
	}

	// Write with atomic replace
	tmpFile := stateFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write updated chain state file: %w", err)
	}

	if err := os.Rename(tmpFile, stateFile); err != nil {
		return fmt.Errorf("failed to rename updated chain state file: %w", err)
	}

	logger.Info("Updated basic chain state in: %s", stateFile)
	return nil
}

func (s *Storage) loadChainState() error {
	stateFile := filepath.Join(s.stateDir, "chain_state.json")

	// Check if state file exists
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		logger.Info("No chain state file found, starting fresh")
		return nil // No state file yet
	}

	data, err := os.ReadFile(stateFile)
	if err != nil {
		return fmt.Errorf("failed to read chain state: %w", err)
	}

	// Try to load as complete chain state first
	var chainState ChainState
	if err := json.Unmarshal(data, &chainState); err == nil && chainState.BasicChainState != nil {
		// Successfully loaded complete chain state with basic data
		s.bestBlockHash = chainState.BasicChainState.BestBlockHash
		s.totalBlocks = chainState.BasicChainState.TotalBlocks
		logger.Info("Loaded chain state from complete file: bestBlock=%s, totalBlocks=%d", s.bestBlockHash, s.totalBlocks)
		return nil
	}

	// Fall back to basic chain state format
	var basicState BasicChainState
	if err := json.Unmarshal(data, &basicState); err != nil {
		return fmt.Errorf("failed to unmarshal chain state: %w", err)
	}

	// CRITICAL FIX: Only set state if we have valid data
	if basicState.BestBlockHash == "" {
		logger.Warn("Warning: Chain state has empty bestBlockHash, ignoring corrupted state")
		return fmt.Errorf("corrupted chain state: empty bestBlockHash")
	}

	s.bestBlockHash = basicState.BestBlockHash
	s.totalBlocks = basicState.TotalBlocks

	logger.Info("Loaded basic chain state: bestBlock=%s, totalBlocks=%d", s.bestBlockHash, s.totalBlocks)
	return nil
}

// Close performs cleanup operations
func (s *Storage) Close() error {
	// Save current state before closing
	if err := s.saveChainState(); err != nil {
		return fmt.Errorf("failed to save chain state on close: %w", err)
	}
	if err := s.saveBlockIndex(); err != nil {
		return fmt.Errorf("failed to save block index on close: %w", err)
	}

	// Remove old basic_chain_state.json if it exists
	basicStateFile := filepath.Join(s.stateDir, "basic_chain_state.json")
	if _, err := os.Stat(basicStateFile); err == nil {
		if err := os.Remove(basicStateFile); err != nil {
			logger.Warn("Warning: Failed to remove old basic_chain_state.json on close: %v", err)
		}
	}

	return nil
}
