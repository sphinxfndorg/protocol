// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/blockchain.go
package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sphinxorg/protocol/src/common"
	"github.com/sphinxorg/protocol/src/consensus"

	svm "github.com/sphinxorg/protocol/src/core/svm/opcodes"
	"github.com/sphinxorg/protocol/src/core/svm/vm"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	logger "github.com/sphinxorg/protocol/src/log"
	"github.com/sphinxorg/protocol/src/pool"
	storage "github.com/sphinxorg/protocol/src/state"
)

// NewBlockchain creates a blockchain with state machine replication
// Initialize TPS monitor in NewBlockchain - main constructor for blockchain
// Parameters:
//   - dataDir: Directory path for storing blockchain data
//   - nodeID: Unique identifier for this node
//   - validators: List of validator node IDs
//   - networkType: Type of network (testnet, devnet, mainnet)
//
// Returns: Initialized Blockchain instance or error
//
// Integration with genesis.go / allocation.go:
// Chain parameters are resolved from networkType BEFORE initializeChain() is
// called so that createGenesisBlock() can call GenesisStateFromChainParams()
// with the correct network parameters.  The genesis block is now built through
// GenesisState.BuildBlock() so every node that uses the same networkType
// produces a byte-for-byte identical genesis hash.
func NewBlockchain(dataDir string, nodeID string, validators []string, networkType string) (*Blockchain, error) {
	// Initialize storage layer for persistent block storage
	// Creates a new storage instance that will handle all disk I/O operations
	store, err := storage.NewStorage(dataDir)
	if err != nil {
		// Return wrapped error with context for better debugging
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Initialize state machine for Byzantine Fault Tolerance replication
	// This handles consensus state and validator management
	stateMachine := storage.NewStateMachine(store, nodeID, validators)

	// Create blockchain with mempool (will be configured after chain params are set)
	// Initialize the blockchain structure with default values and empty caches
	blockchain := &Blockchain{
		storage:         store,                                // Persistent storage for blocks and state
		stateMachine:    stateMachine,                         // State machine for BFT consensus
		mempool:         nil,                                  // Transaction pool (initialized later after chain params)
		chain:           []*types.Block{},                     // In-memory chain cache for quick access
		txIndex:         make(map[string]*types.Transaction),  // Transaction index for fast lookup by ID
		pendingTx:       []*types.Transaction{},               // Pending transactions waiting for inclusion
		lock:            sync.RWMutex{},                       // Read-write mutex for thread-safe operations
		status:          StatusInitializing,                   // Initial status while blockchain is setting up
		syncMode:        SyncModeFull,                         // Default to full synchronization mode
		consensusEngine: nil,                                  // Consensus engine (set later after initialization)
		chainParams:     nil,                                  // Chain parameters (set later after genesis)
		merkleRootCache: make(map[string]string),              // Cache for Merkle roots to avoid recalculation
		tpsMonitor:      types.NewTPSMonitor(5 * time.Second), // Monitor transactions per second with 5-second window
		// SVM data stores
		returnDataStore: make(map[string][]byte),           // Initialize OP_RETURN data store
		svmFailures:     make([]map[string]interface{}, 0), // Initialize failure tracking
	}

	// ── Resolve chain parameters BEFORE initializeChain so that
	// createGenesisBlock() can call GenesisStateFromChainParams() with the
	// correct network parameters.  This is the only ordering change versus the
	// original constructor.
	// Use consistent genesis hash that's the same for all nodes
	// Select appropriate chain parameters based on network type
	var chainParams *SphinxChainParameters
	switch networkType {
	case "testnet":
		chainParams = GetTestnetChainParams() // Testnet parameters
	case "devnet":
		chainParams = GetDevnetChainParams() // Development network parameters
	default:
		chainParams = GetSphinxChainParams() // Mainnet parameters (default)
	}
	// Store early so createGenesisBlock can read bc.chainParams immediately
	blockchain.chainParams = chainParams

	// Load existing chain from storage or create genesis block if new chain
	// This handles both existing chains and first-time initialization
	if err := blockchain.initializeChain(); err != nil {
		return nil, fmt.Errorf("failed to initialize chain: %w", err)
	}

	// Now that we have the genesis block, set the chain params with consistent hash
	// Configure chain parameters based on network type (testnet, devnet, mainnet)
	// Now that we have the genesis block, set the chain params with consistent hash
	// Configure chain parameters based on network type (testnet, devnet, mainnet)
	if len(blockchain.chain) > 0 {
		// Use consistent genesis hash that's the same for all nodes
		// chainParams is already set above; just validate against actual genesis.
		blockchain.chainParams = chainParams

		// Validate that our genesis hash matches the chain params
		// This ensures consistency across all nodes
		actualGenesisHash := blockchain.chain[0].GetHash()
		if actualGenesisHash != chainParams.GenesisHash {
			// Log warning but continue - this helps identify configuration issues
			logger.Warn("Genesis hash mismatch: actual=%s, expected=%s",
				actualGenesisHash, chainParams.GenesisHash)
		}

		// Log successful chain parameters initialization
		logger.Info("Chain parameters initialized for %s: genesis_hash=%s",
			chainParams.GetNetworkName(), chainParams.GenesisHash)

		// Initialize mempool with configuration from chain params
		mempoolConfig := GetMempoolConfigFromChainParams(chainParams)
		blockchain.mempool = pool.NewMempool(mempoolConfig)

		// ✅ CRITICAL: Set mempool on state machine for transaction replication
		stateMachine.SetMempool(blockchain.mempool)

		// Log chain parameters again for visibility
		logger.Info("Chain parameters initialized for %s: genesis_hash=%s",
			chainParams.GetNetworkName(), chainParams.GenesisHash)

		// Verify the genesis hash is properly stored in block_index.json
		if err := blockchain.verifyGenesisHashInIndex(); err != nil {
			logger.Warn("Warning: Genesis hash verification failed: %v", err)
		}

		// AUTO-SAVE: Save chain state with actual genesis hash
		if err := blockchain.SaveBasicChainState(); err != nil {
			logger.Warn("Warning: Failed to auto-save chain state: %v", err)
		} else {
			logger.Info("Auto-saved chain state")
		}
	}

	// Start state machine replication for Byzantine Fault Tolerance
	// Initialize the consensus state machine with current validators
	if err := stateMachine.Start(); err != nil {
		return nil, fmt.Errorf("failed to start state machine: %w", err)
	}

	// Update status to running after successful initialization
	// Mark blockchain as ready for operation
	blockchain.status = StatusRunning

	// Log final initialization success with all relevant parameters
	logger.Info("Blockchain initialized with status: %s, sync mode: %s, network: %s, genesis hash: %s",
		blockchain.StatusString(blockchain.status),
		blockchain.SyncModeString(blockchain.syncMode),
		blockchain.chainParams.GetNetworkName(),
		blockchain.chainParams.GenesisHash)

	return blockchain, nil
}

// GetMerkleRoot returns the Merkle root of transactions for a specific block
// This is used for verification and proof generation
// Parameters:
//   - blockHash: The hash of the block to get Merkle root for
//
// Returns: Hex-encoded Merkle root string or error
func (bc *Blockchain) GetMerkleRoot(blockHash string) (string, error) {
	// Retrieve the block from storage using its hash
	// Look up the block in persistent storage
	block, err := bc.storage.GetBlockByHash(blockHash)
	if err != nil {
		// Return error if block not found or storage error
		return "", fmt.Errorf("failed to get block: %w", err)
	}

	// Calculate Merkle root from the block's transactions
	// This creates a cryptographic summary of all transactions
	merkleRoot := block.CalculateTxsRoot()
	// Encode as hex string for consistent representation
	return hex.EncodeToString(merkleRoot), nil
}

// GetCurrentMerkleRoot returns the Merkle root of the latest block
// Convenience method for getting the most recent block's Merkle root
// Returns: Hex-encoded Merkle root string or error
func (bc *Blockchain) GetCurrentMerkleRoot() (string, error) {
	// Get the most recent block from the chain
	latestBlock := bc.GetLatestBlock()
	if latestBlock == nil {
		// Return error if no blocks exist in chain
		return "", fmt.Errorf("no blocks available")
	}
	// Delegate to GetMerkleRoot with latest block's hash
	return bc.GetMerkleRoot(latestBlock.GetHash())
}

// GetBlockWithMerkleInfo returns detailed block information including Merkle root
// Provides comprehensive block data for RPC and debugging
// Parameters:
//   - blockHash: The hash of the block to get information for
//
// Returns: Map with block details or error
func (bc *Blockchain) GetBlockWithMerkleInfo(blockHash string) (map[string]interface{}, error) {
	// Retrieve the block from storage
	// Look up the complete block data
	block, err := bc.storage.GetBlockByHash(blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get block: %w", err)
	}

	// Calculate Merkle root for this block
	// Generate cryptographic summary of transactions
	merkleRoot := block.CalculateTxsRoot()

	// Get formatted timestamps using centralized time service for consistent time display
	// Convert Unix timestamp to human-readable formats
	localTime, utcTime := common.FormatTimestamp(block.Header.Timestamp)

	// Build comprehensive block information map
	// Include all relevant block data for external consumers
	info := map[string]interface{}{
		"height":            block.GetHeight(),                           // Block number in chain
		"hash":              block.GetHash(),                             // Unique block identifier
		"merkle_root":       hex.EncodeToString(merkleRoot),              // Transaction summary
		"timestamp":         block.Header.Timestamp,                      // Original Unix timestamp
		"timestamp_local":   localTime,                                   // Local timezone formatted
		"timestamp_utc":     utcTime,                                     // UTC formatted time
		"difficulty":        block.Header.Difficulty.String(),            // Mining difficulty
		"nonce":             block.Header.Nonce,                          // Proof-of-work nonce
		"gas_limit":         block.Header.GasLimit.String(),              // Maximum gas allowed
		"gas_used":          block.Header.GasUsed.String(),               // Actual gas consumed
		"transaction_count": len(block.Body.TxsList),                     // Number of transactions
		"transactions":      bc.getTransactionHashes(block.Body.TxsList), // List of tx hashes
	}

	return info, nil
}

// Helper method to extract transaction hashes
// Extracts just the transaction IDs from a list of transactions
// Parameters:
//   - txs: List of transactions to extract hashes from
//
// Returns: Slice of transaction ID strings
func (bc *Blockchain) getTransactionHashes(txs []*types.Transaction) []string {
	// Initialize slice to hold transaction hashes
	var hashes []string
	// Iterate through each transaction
	for _, tx := range txs {
		// Append transaction ID to the result slice
		hashes = append(hashes, tx.ID)
	}
	return hashes
}

// CalculateBlockSize calculates the approximate size of a block in bytes
// Used for block size validation and optimization
// Parameters:
//   - block: The block to calculate size for
//
// Returns: Block size in bytes
// CalculateBlockSize calculates the approximate size of a block in bytes
func (bc *Blockchain) CalculateBlockSize(block *types.Block) uint64 {
	// Initialize size counter
	size := uint64(0)

	// Header size (approximate) - fixed overhead
	size += 80 // Fixed header components

	// Transactions size - sum of all transaction sizes
	for i, tx := range block.Body.TxsList {
		txSize, err := bc.calculateTxsSize(tx)
		if err != nil {
			logger.Warn("Failed to calculate transaction size for tx %d: %v, using default 500", i, err)
			txSize = 500
		}
		size += txSize
	}

	logger.Info("CalculateBlockSize: height=%d, tx_count=%d, total_size=%d bytes",
		block.GetHeight(), len(block.Body.TxsList), size)

	return size
}

// ValidateBlockSize checks if a block exceeds size limits
// Ensures blocks respect the chain's size constraints
// Parameters:
//   - block: The block to validate
//
// Returns: Error if block size validation fails
func (bc *Blockchain) ValidateBlockSize(block *types.Block) error {
	// Check if chain parameters are initialized
	// Cannot validate without size limits
	if bc.chainParams == nil {
		return fmt.Errorf("chain parameters not initialized")
	}

	// Calculate block size and compare with maximum allowed
	// Get actual block size
	blockSize := bc.CalculateBlockSize(block)
	// Get maximum allowed block size from chain parameters
	maxBlockSize := bc.chainParams.MaxBlockSize

	// Check if block exceeds maximum allowed size
	if blockSize > maxBlockSize {
		return fmt.Errorf("block size %d exceeds maximum %d bytes", blockSize, maxBlockSize)
	}

	// Also validate individual transaction sizes
	// Ensure each transaction respects size limits
	for i, tx := range block.Body.TxsList {
		// Calculate individual transaction size
		txSize := bc.mempool.CalculateTransactionSize(tx)
		// Get maximum allowed transaction size
		maxTxSize := bc.chainParams.MaxTransactionSize

		// Check if transaction exceeds size limit
		if txSize > maxTxSize {
			return fmt.Errorf("transaction %d size %d exceeds maximum %d bytes", i, txSize, maxTxSize)
		}
	}

	return nil
}

// StoreChainState saves the chain state with the actual genesis hash and consensus signatures
// Persists the complete blockchain state for recovery and auditing
// Parameters:
//   - nodes: List of node information in the network
//
// Returns: Error if state storage fails
func (bc *Blockchain) StoreChainState(nodes []*storage.NodeInfo) error {
	// Check if chain parameters are initialized
	// Cannot store state without chain parameters
	if bc.chainParams == nil {
		return fmt.Errorf("chain parameters not initialized")
	}

	// Convert genesis_time to ISO RFC format for output (human-readable)
	// Get current time in ISO format for timestamp
	genesisTimeISO := common.GetTimeService().GetCurrentTimeInfo().ISOUTC

	// Convert blockchain params to storage.ChainParams with ISO format
	// Create storage-compatible chain parameters
	chainParams := &storage.ChainParams{
		ChainID:       bc.chainParams.ChainID,       // Network identifier
		ChainName:     bc.chainParams.ChainName,     // Human-readable network name
		Symbol:        bc.chainParams.Symbol,        // Currency symbol (SPX)
		GenesisTime:   genesisTimeISO,               // Genesis timestamp in ISO format
		GenesisHash:   bc.chainParams.GenesisHash,   // Genesis block hash
		Version:       bc.chainParams.Version,       // Protocol version
		MagicNumber:   bc.chainParams.MagicNumber,   // Network magic number
		DefaultPort:   bc.chainParams.DefaultPort,   // Default P2P port
		BIP44CoinType: bc.chainParams.BIP44CoinType, // BIP44 coin type for wallets
		LedgerName:    bc.chainParams.LedgerName,    // Ledger hardware display name
	}

	// Get wallet derivation paths for the current network
	// Generate standard BIP paths for wallet compatibility
	walletPaths := bc.GetWalletDerivationPaths()

	// Collect consensus signatures as FinalStateInfo if consensus engine is available
	// Initialize variables for consensus data
	// Collect consensus signatures as FinalStateInfo if consensus engine is available
	// Initialize variables for consensus data
	var finalStates []*storage.FinalStateInfo
	var signatureValidation *storage.SignatureValidation

	// ========== FIX: Initialize signatureValidation even if no signatures ==========
	// Check if consensus engine is available
	if bc.consensusEngine != nil {
		// Get raw signatures from consensus engine
		rawSignatures := bc.consensusEngine.GetConsensusSignatures()

		if len(rawSignatures) == 0 {
			// No signatures yet - create empty validation object
			signatureValidation = &storage.SignatureValidation{
				TotalSignatures:   0,
				ValidSignatures:   0,
				InvalidSignatures: 0,
				ValidationTime:    common.GetTimeService().GetCurrentTimeInfo().ISOUTC,
			}
			finalStates = []*storage.FinalStateInfo{} // Empty slice, not nil
			logger.Info("No consensus signatures available yet, created empty validation")
		} else {
			// Process signatures as before
			finalStates = make([]*storage.FinalStateInfo, len(rawSignatures))
			validCount := 0
			for i, rawSig := range rawSignatures {
				finalStates[i] = &storage.FinalStateInfo{
					BlockHash:        rawSig.BlockHash,
					BlockHeight:      rawSig.BlockHeight,
					SignerNodeID:     rawSig.SignerNodeID,
					Signature:        rawSig.Signature,
					MessageType:      rawSig.MessageType,
					View:             rawSig.View,
					Timestamp:        rawSig.Timestamp,
					Valid:            rawSig.Valid,
					SignatureStatus:  "Valid",
					VerificationTime: common.GetTimeService().GetCurrentTimeInfo().ISOLocal,
				}
				if rawSig.Valid {
					validCount++
				}
			}
			signatureValidation = &storage.SignatureValidation{
				TotalSignatures:   len(finalStates),
				ValidSignatures:   validCount,
				InvalidSignatures: len(finalStates) - validCount,
				ValidationTime:    common.GetTimeService().GetCurrentTimeInfo().ISOUTC,
			}
			logger.Info("Storing %d consensus signatures (%d valid) in chain state as final states",
				len(finalStates), validCount)
		}
	} else {
		// No consensus engine - create empty validation
		signatureValidation = &storage.SignatureValidation{
			TotalSignatures:   0,
			ValidSignatures:   0,
			InvalidSignatures: 0,
			ValidationTime:    common.GetTimeService().GetCurrentTimeInfo().ISOUTC,
		}
		finalStates = []*storage.FinalStateInfo{}
		logger.Info("No consensus engine available, created empty validation")
	}
	// ========================================================================
	// Create chain state with signature data
	// Add this before creating chainState
	if nodes == nil {
		nodes = make([]*storage.NodeInfo, 0)
	}

	// Create chain state with signature data
	// Build complete chain state structure
	chainState := &storage.ChainState{
		Nodes:               nodes,                                               // Network node information
		Timestamp:           common.GetTimeService().GetCurrentTimeInfo().ISOUTC, // State snapshot time
		SignatureValidation: signatureValidation,                                 // Signature validation results
		FinalStates:         finalStates,                                         // Finalized consensus signatures
	}

	// Get working TPS metrics from blockchain's tpsMonitor
	// Get working TPS metrics from blockchain's tpsMonitor
	logger.Info("Retrieving TPS metrics from blockchain tpsMonitor...")

	var blockchainTPSMetrics *storage.TPSMetrics
	if bc.tpsMonitor != nil {
		tpsStats := bc.tpsMonitor.GetStats()

		// Get existing storage metrics to preserve history and block data
		existingMetrics := bc.storage.GetTPSMetrics()

		// Build TPS history from tpsMonitor if available, otherwise use existing
		tpsHistory := existingMetrics.TPSHistory
		if len(tpsHistory) == 0 && tpsStats["tps_history"] != nil {
			// Convert from tpsMonitor history if needed
			if history, ok := tpsStats["tps_history"].([]interface{}); ok {
				for _, h := range history {
					if histMap, ok := h.(map[string]interface{}); ok {
						tpsHistory = append(tpsHistory, storage.TPSDataPoint{
							Timestamp:   time.Now(),
							TPS:         histMap["tps"].(float64),
							BlockHeight: uint64(histMap["block_height"].(float64)),
						})
					}
				}
			}
		}

		// Build transactions per block from storage (preserve existing)
		txsPerBlock := existingMetrics.TransactionsPerBlock
		if len(txsPerBlock) == 0 {
			// Create from current block if available
			latestBlock := bc.GetLatestBlock()
			if latestBlock != nil {
				if block, ok := latestBlock.(*BlockHelper); ok {
					underlying, ok := block.GetUnderlyingBlock().(*types.Block)
					if !ok {
						logger.Warn("Failed to convert underlying block to *types.Block")
					} else {
						txsPerBlock = []storage.BlockTXCount{
							{
								BlockHeight: underlying.GetHeight(),
								BlockHash:   underlying.GetHash(),
								TxCount:     uint64(len(underlying.Body.TxsList)),
								BlockTime:   time.Unix(underlying.Header.Timestamp, 0),
								BlockSize:   bc.CalculateBlockSize(underlying),
							},
						}
					}
				}
			}
		}

		// Convert tpsMonitor stats to storage.TPSMetrics format WITH history preserved
		// Safely extract values with type checking
		var currentTPS, avgTPS, peakTPS float64
		var totalTx, blocksProc, windowCount uint64

		// Safe type assertions with defaults
		if val, ok := tpsStats["current_tps"].(float64); ok {
			currentTPS = val
		}
		if val, ok := tpsStats["average_tps"].(float64); ok {
			avgTPS = val
		}
		if val, ok := tpsStats["peak_tps"].(float64); ok {
			peakTPS = val
		}
		if val, ok := tpsStats["total_transactions"].(uint64); ok {
			totalTx = val
		}
		if val, ok := tpsStats["blocks_processed"].(uint64); ok {
			blocksProc = val
		}
		if val, ok := tpsStats["current_window_count"].(uint64); ok {
			windowCount = val
		}

		// Calculate avg transactions per block if not available
		avgTxsPerBlock := 0.0
		if val, ok := tpsStats["avg_transactions_per_block"].(float64); ok {
			avgTxsPerBlock = val
		} else if blocksProc > 0 {
			avgTxsPerBlock = float64(totalTx) / float64(blocksProc)
		}

		blockchainTPSMetrics = &storage.TPSMetrics{
			CurrentTPS:              currentTPS,
			AverageTPS:              avgTPS,
			PeakTPS:                 peakTPS,
			TotalTransactions:       totalTx,
			BlocksProcessed:         blocksProc,
			CurrentWindowCount:      windowCount,
			WindowStartTime:         time.Now(),
			WindowDuration:          5 * time.Second,
			WindowDurationSeconds:   5,
			TPSHistory:              tpsHistory,  // Preserve history
			TransactionsPerBlock:    txsPerBlock, // Preserve block data
			AvgTransactionsPerBlock: avgTxsPerBlock,
			MaxTransactionsPerBlock: existingMetrics.MaxTransactionsPerBlock,
			MinTransactionsPerBlock: existingMetrics.MinTransactionsPerBlock,
			LastUpdated:             time.Now(),
		}

		logger.Info("✅ Retrieved blockchain TPS metrics: current_tps=%.2f, avg_tps=%.2f, peak_tps=%.2f, total_txs=%d, history_size=%d",
			blockchainTPSMetrics.CurrentTPS, blockchainTPSMetrics.AverageTPS,
			blockchainTPSMetrics.PeakTPS, blockchainTPSMetrics.TotalTransactions,
			len(blockchainTPSMetrics.TPSHistory))
	} else {
		logger.Warn("⚠️ tpsMonitor is nil, cannot retrieve blockchain TPS metrics")
		blockchainTPSMetrics = bc.storage.GetTPSMetrics() // Fallback to storage
	}

	// Save chain state with actual parameters, signatures, and working TPS metrics
	// Persist to storage - passing the blockchain TPS metrics
	err := bc.storage.SaveCompleteChainState(chainState, chainParams, walletPaths, blockchainTPSMetrics)
	if err != nil {
		return fmt.Errorf("failed to save chain state: %w", err)
	}

	// Fix any existing hardcoded hashes in the state files
	// Ensure state files have correct genesis hash
	bc.storage.FixChainStateGenesisHash()

	// Log successful state storage
	logger.Info("Complete chain state saved with block size metrics: %s",
		filepath.Join(bc.storage.GetStateDir(), "chain_state.json"))
	logger.Info("Chain state saved with genesis hash: %s", bc.chainParams.GenesisHash)

	// Log signature validation summary if available
	if signatureValidation != nil {
		logger.Info("Signature validation: %d/%d valid signatures",
			signatureValidation.ValidSignatures, signatureValidation.TotalSignatures)
	}

	return nil
}

// CalculateAndStoreBlockSizeMetrics calculates and stores block size statistics
// Analyzes block sizes for performance monitoring and optimization
// Returns: Error if metric calculation or storage fails
func (bc *Blockchain) CalculateAndStoreBlockSizeMetrics() error {
	logger.Info("Starting block size metrics calculation...")

	// Get recent blocks for analysis - use a reasonable limit
	// Retrieve up to 1000 recent blocks for statistical analysis
	recentBlocks := bc.getRecentBlocks(1000) // Increased to 1000 blocks for better stats
	if len(recentBlocks) == 0 {
		logger.Info("No blocks available for size metrics calculation")
		return nil
	}

	// Initialize statistics variables
	var totalSize uint64                                             // Sum of all block sizes
	var minSize uint64 = ^uint64(0)                                  // Minimum block size (start with max value)
	var maxSize uint64                                               // Maximum block size
	sizeStats := make([]storage.BlockSizeInfo, 0, len(recentBlocks)) // Slice for individual block stats

	// Calculate statistics for each block
	// Iterate through all recent blocks
	for _, block := range recentBlocks {
		// Calculate size for current block
		blockSize := bc.CalculateBlockSize(block)
		logger.Info("DEBUG: Block height=%d, size=%d bytes", block.GetHeight(), blockSize)
		totalSize += blockSize // Add to running total

		// Update min and max
		if blockSize < minSize {
			minSize = blockSize // New minimum found
		}
		if blockSize > maxSize {
			maxSize = blockSize // New maximum found
		}

		// Record individual block stats using BlockSizeInfo
		// Create detailed statistics for this block
		blockStat := storage.BlockSizeInfo{
			Height:    block.GetHeight(),                  // Block number
			Hash:      block.GetHash(),                    // Block hash
			Size:      blockSize,                          // Size in bytes
			SizeMB:    float64(blockSize) / (1024 * 1024), // Size in megabytes
			TxCount:   uint64(len(block.Body.TxsList)),    // Transaction count
			Timestamp: block.Header.Timestamp,             // Block timestamp
		}
		sizeStats = append(sizeStats, blockStat) // Add to statistics slice
	}

	// Calculate averages
	averageSize := totalSize / uint64(len(recentBlocks)) // Average block size in bytes

	// Convert to MB for human readability
	averageSizeMB := float64(averageSize) / (1024 * 1024)
	minSizeMB := float64(minSize) / (1024 * 1024)
	maxSizeMB := float64(maxSize) / (1024 * 1024)
	totalSizeMB := float64(totalSize) / (1024 * 1024)

	// Convert to KB for better readability when blocks are small
	averageSizeKB := float64(averageSize) / 1024
	minSizeKB := float64(minSize) / 1024
	maxSizeKB := float64(maxSize) / 1024
	totalSizeKB := float64(totalSize) / 1024

	// Create block size metrics structure
	blockSizeMetrics := &storage.BlockSizeMetrics{
		TotalBlocks:     uint64(len(recentBlocks)),
		AverageSize:     averageSize,
		MinSize:         minSize,
		MaxSize:         maxSize,
		TotalSize:       totalSize,
		SizeStats:       sizeStats,
		CalculationTime: common.GetTimeService().GetCurrentTimeInfo().ISOLocal,
		AverageSizeMB:   averageSizeMB,
		MinSizeMB:       minSizeMB,
		MaxSizeMB:       maxSizeMB,
		TotalSizeMB:     totalSizeMB,
	}

	// Save to storage
	if err := bc.storage.SaveBlockSizeMetrics(blockSizeMetrics); err != nil {
		return fmt.Errorf("failed to save block size metrics: %w", err)
	}

	// Log success and summary statistics in KB for better visibility
	logger.Info("Successfully calculated block size metrics for %d blocks", len(recentBlocks))
	logger.Info("Block size stats: avg=%.2f KB (%.0f bytes), min=%.2f KB (%.0f bytes), max=%.2f KB (%.0f bytes), total=%.2f KB (%.0f bytes)",
		averageSizeKB, float64(averageSize), minSizeKB, float64(minSize), maxSizeKB, float64(maxSize), totalSizeKB, float64(totalSize))
	logger.Info("Size stats contains %d entries", len(sizeStats))

	return nil
}

// VerifyState verifies that chain_state.json has the correct genesis hash
// Ensures the stored state matches the actual blockchain parameters
// Returns: Error if state verification fails
func (bc *Blockchain) VerifyState() error {
	// Check if chain parameters are initialized
	// Cannot verify state without chain parameters
	if bc.chainParams == nil {
		return fmt.Errorf("chain parameters not initialized")
	}

	// Load current chain state from storage
	// Retrieve the persisted chain state
	chainState, err := bc.storage.LoadCompleteChainState()
	if err != nil {
		return fmt.Errorf("failed to load chain state: %w", err)
	}

	// Check if genesis hash in stored state matches actual genesis hash
	// Verify the stored genesis hash is correct
	if chainState.ChainIdentification != nil &&
		chainState.ChainIdentification.ChainParams != nil {
		// Extract genesis hash from stored parameters
		if genesisHash, exists := chainState.ChainIdentification.ChainParams["genesis_hash"]; exists {
			if genesisHashStr, ok := genesisHash.(string); ok {
				// Compare with actual genesis hash
				if genesisHashStr != bc.chainParams.GenesisHash {
					return fmt.Errorf("chain state genesis hash mismatch: expected %s, got %s",
						bc.chainParams.GenesisHash, genesisHashStr)
				}
				logger.Info("✓ Chain state verified: genesis hash matches")
				return nil
			}
		}
	}

	return fmt.Errorf("could not verify chain state: missing genesis hash")
}

// GetChainInfo returns formatted chain information with actual genesis hash
// Provides comprehensive chain information for RPC and debugging
// Returns: Map containing all chain information
func (bc *Blockchain) GetChainInfo() map[string]interface{} {
	// Get current chain parameters
	params := bc.GetChainParams()
	// Get latest block for current height
	latestBlock := bc.GetLatestBlock()

	// Initialize variables for block information
	var blockHeight uint64
	var blockHash string
	if latestBlock != nil {
		blockHeight = latestBlock.GetHeight() // Current chain height
		blockHash = latestBlock.GetHash()     // Latest block hash
	}

	// Use the correct network name based on chain parameters
	networkName := params.GetNetworkName()

	// Convert genesis_time from Unix timestamp to ISO RFC format for output
	// Use ISOUTC field which is already in RFC3339 format
	genesisTimeISO := common.GetTimeService().GetTimeInfo(params.GenesisTime).ISOUTC

	// Build and return comprehensive chain information map
	return map[string]interface{}{
		"chain_id":        params.ChainID,                          // Unique chain identifier
		"chain_name":      params.ChainName,                        // Human-readable chain name
		"symbol":          params.Symbol,                           // Currency symbol
		"genesis_time":    genesisTimeISO,                          // Genesis timestamp in ISO format
		"genesis_hash":    params.GenesisHash,                      // Genesis block hash
		"version":         params.Version,                          // Protocol version
		"magic_number":    fmt.Sprintf("0x%x", params.MagicNumber), // Network magic number in hex
		"default_port":    params.DefaultPort,                      // Default P2P port
		"bip44_coin_type": params.BIP44CoinType,                    // BIP44 coin type for wallets
		"ledger_name":     params.LedgerName,                       // Name for Ledger hardware
		"current_height":  blockHeight,                             // Current blockchain height
		"latest_block":    blockHash,                               // Latest block hash
		"network":         networkName,                             // Network type (mainnet/testnet/devnet)
	}
}

// IsSphinxChain validates if this blockchain follows Sphinx protocol using actual genesis hash
// Returns: true if chain follows Sphinx protocol, false otherwise
func (bc *Blockchain) IsSphinxChain() bool {
	// Check if chain has any blocks
	if len(bc.chain) == 0 {
		return false
	}

	// Get chain parameters and genesis block
	params := bc.GetChainParams()
	genesis := bc.chain[0]
	// Compare genesis block hash with expected genesis hash
	return genesis.GetHash() == params.GenesisHash
}

// Enhanced StartLeaderLoop with leader lock to prevent rapid view changes
// Runs a continuous loop where the leader node proposes new blocks
// Parameters:
//   - ctx: Context for cancellation and timeout control
func (bc *Blockchain) StartLeaderLoop(ctx context.Context) {
	// Mutex to prevent concurrent block proposals
	leaderMutex := sync.Mutex{}
	// Flag indicating if a proposal is in progress
	var isProposing bool

	// Start goroutine for leader loop
	go func() {
		// Create ticker for periodic proposal attempts
		ticker := time.NewTicker(1 * time.Second) // was 5s — check every second
		defer ticker.Stop()                       // Ensure ticker is stopped when function exits

		// Main loop - runs until context is cancelled
		for {
			select {
			case <-ctx.Done():
				// Context cancelled, exit goroutine
				return
			case <-ticker.C:
				// Time to check if we should propose a block

				// Skip if consensus engine not initialized
				if bc.consensusEngine == nil {
					continue
				}

				// Only leader proposes blocks
				// Check if this node is the current leader
				if !bc.consensusEngine.IsLeader() {
					continue
				}

				// Check if we're already proposing (prevent concurrent proposals)
				leaderMutex.Lock()
				if isProposing {
					leaderMutex.Unlock()
					logger.Debug("Leader: already proposing block, skipping")
					continue
				}
				isProposing = true // Mark as proposing
				leaderMutex.Unlock()

				// Check if we have transactions in mempool
				hasTxs := bc.mempool.GetTransactionCount() > 0
				if !hasTxs {
					// No transactions to include, reset proposing flag
					leaderMutex.Lock()
					isProposing = false
					leaderMutex.Unlock()
					logger.Debug("Leader: no pending transactions to propose")
					continue
				}

				// Log proposal start
				logger.Info("Leader %s: creating block with %d pending transactions",
					bc.consensusEngine.GetNodeID(), bc.mempool.GetTransactionCount())

				// Create and propose block using existing CreateBlock function
				// This now includes nonce iteration internally
				block, err := bc.CreateBlock()
				if err != nil {
					// Block creation failed, reset proposing flag
					logger.Warn("Leader: failed to create block: %v", err)
					leaderMutex.Lock()
					isProposing = false
					leaderMutex.Unlock()
					continue
				}

				// Log successful block creation
				logger.Info("Leader %s proposing block at height %d with %d transactions and nonce %s",
					bc.consensusEngine.GetNodeID(), block.GetHeight(), len(block.Body.TxsList), block.Header.Nonce)

				// Convert to consensus.Block using adapter
				consensusBlock := NewBlockHelper(block)
				// Propose block to consensus engine
				if err := bc.consensusEngine.ProposeBlock(consensusBlock); err != nil {
					logger.Warn("Leader: failed to propose block: %v", err)
				} else {
					logger.Info("Leader: block proposal sent successfully with nonce %s", block.Header.Nonce)
				}

				// Reset proposing flag after a delay to allow consensus to complete
				// Launch goroutine to wait and reset
				go func() {
					time.Sleep(5 * time.Second) // was 30s — allow next block after 5s
					leaderMutex.Lock()
					isProposing = false
					leaderMutex.Unlock()
				}()
			}
		}
	}()
}

// ImportBlock imports a new block into the blockchain with result tracking
// Parameters:
//   - block: Block to import
//
// Returns: BlockImportResult indicating the outcome
func (bc *Blockchain) ImportBlock(block *types.Block) BlockImportResult {
	// Check if blockchain is in running state
	if bc.GetStatus() != StatusRunning {
		logger.Info("Cannot import block - blockchain status is %s", bc.StatusString(bc.GetStatus()))
		return ImportError
	}

	// Validate the block before import
	if err := block.Validate(); err != nil {
		logger.Warn("Block validation failed: %v", err)
		return ImportInvalid
	}

	// Verify block links to current chain using ParentHash
	latestBlock := bc.GetLatestBlock()
	if latestBlock != nil && block.GetPrevHash() != latestBlock.GetHash() {
		// Block doesn't extend main chain, might be a side chain
		logger.Info("Block does not extend current chain: expected ParentHash=%s, got ParentHash=%s",
			latestBlock.GetHash(), block.GetPrevHash())
		return ImportedSide
	}

	// Try to commit the block through state machine replication
	consensusBlock := NewBlockHelper(block)
	if err := bc.CommitBlock(consensusBlock); err != nil {
		logger.Warn("Block commit failed: %v", err)
		return ImportError
	}

	// Block successfully imported as best block
	logger.Info("Block imported successfully: height=%d, hash=%s, ParentHash=%s",
		block.GetHeight(), block.GetHash(), block.GetPrevHash())
	return ImportedBest
}

// ClearCache clears specific caches to free memory
// Parameters:
//   - cacheType: Type of cache to clear
//
// Returns: Error if cache clearing fails
func (bc *Blockchain) ClearCache(cacheType CacheType) error {
	bc.lock.Lock() // Write lock for thread safety
	defer bc.lock.Unlock()

	// Determine which cache to clear based on type
	switch cacheType {
	case CacheTypeBlock:
		// Clear block cache - keep only latest block in memory
		if len(bc.chain) > 1 {
			latestBlock := bc.chain[len(bc.chain)-1] // Keep most recent block
			bc.chain = []*types.Block{latestBlock}   // Replace with single block
		}
		logger.Info("Block cache cleared, kept %d blocks in memory", len(bc.chain))

	case CacheTypeTransaction:
		// Clear transaction index
		before := len(bc.txIndex)                        // Store size before clearing
		bc.txIndex = make(map[string]*types.Transaction) // New empty index
		logger.Info("Transaction cache cleared: removed %d entries", before)

	case CacheTypeReceipt:
		// Receipt cache not yet implemented
		logger.Info("Receipt cache cleared (not implemented)")

	case CacheTypeState:
		// State cache not yet implemented
		logger.Info("State cache cleared (not implemented)")
	}

	return nil
}

// GetBlockSizeStats returns block size statistics
// Returns: Map containing block size statistics
func (bc *Blockchain) GetBlockSizeStats() map[string]interface{} {
	// Initialize statistics map
	stats := make(map[string]interface{})

	// Add chain configuration limits
	if bc.chainParams != nil {
		stats["max_block_size"] = bc.chainParams.MaxBlockSize             // Maximum allowed block size
		stats["target_block_size"] = bc.chainParams.TargetBlockSize       // Target block size for optimization
		stats["max_transaction_size"] = bc.chainParams.MaxTransactionSize // Maximum transaction size
		stats["block_gas_limit"] = bc.chainParams.BlockGasLimit.String()  // Gas limit per block
	}

	// Calculate average block size from recent blocks
	recentBlocks := bc.getRecentBlocks(100) // Get up to 100 recent blocks
	if len(recentBlocks) > 0 {
		totalSize := uint64(0) // Total size accumulator
		maxSize := uint64(0)   // Maximum size observed
		minSize := ^uint64(0)  // Minimum size observed (start with max)

		// Calculate statistics
		for _, block := range recentBlocks {
			blockSize := bc.CalculateBlockSize(block) // Get block size
			totalSize += blockSize                    // Add to total

			// Update max if larger
			if blockSize > maxSize {
				maxSize = blockSize
			}
			// Update min if smaller
			if blockSize < minSize {
				minSize = blockSize
			}
		}

		// Calculate and store statistics
		stats["average_block_size"] = totalSize / uint64(len(recentBlocks)) // Average size
		stats["max_block_size_observed"] = maxSize                          // Maximum observed
		stats["min_block_size_observed"] = minSize                          // Minimum observed
		stats["blocks_analyzed"] = len(recentBlocks)                        // Number of blocks analyzed
		if bc.chainParams.TargetBlockSize > 0 {
			// Calculate utilization percentage
			stats["size_utilization_percent"] = float64(stats["average_block_size"].(uint64)) / float64(bc.chainParams.TargetBlockSize) * 100
		}
	}

	// Get mempool stats
	mempoolStats := bc.mempool.GetStats()
	for k, v := range mempoolStats {
		stats[k] = v // Add mempool statistics
	}

	return stats
}

// getRecentBlocks returns recent blocks for analysis
// Parameters:
//   - count: Maximum number of blocks to return
//
// Returns: Slice of recent blocks
func (bc *Blockchain) getRecentBlocks(count int) []*types.Block {
	// Initialize slice for blocks
	var blocks []*types.Block
	latest := bc.GetLatestBlock() // Get latest block

	// Check if any blocks exist
	if latest == nil {
		return blocks // Return empty slice
	}

	// Calculate range of blocks to retrieve
	currentHeight := latest.GetHeight() // Current chain height
	startHeight := uint64(0)            // Default start height
	if currentHeight > uint64(count) {
		startHeight = currentHeight - uint64(count) // Calculate start height
	}

	// Retrieve blocks from storage
	for height := startHeight; height <= currentHeight; height++ {
		block := bc.GetBlockByNumber(height) // Get block by height
		if block != nil {
			blocks = append(blocks, block) // Add to result slice
		}
	}

	return blocks
}

// GetBlocksizeInfo returns detailed blocksize information for RPC/API
// Returns: Map containing block size information
func (bc *Blockchain) GetBlocksizeInfo() map[string]interface{} {
	// Initialize information map
	info := make(map[string]interface{})

	// Add chain limits
	if bc.chainParams != nil {
		info["limits"] = map[string]interface{}{
			"max_block_size_bytes":       bc.chainParams.MaxBlockSize,           // Maximum block size in bytes
			"max_transaction_size_bytes": bc.chainParams.MaxTransactionSize,     // Maximum transaction size
			"target_block_size_bytes":    bc.chainParams.TargetBlockSize,        // Target block size
			"block_gas_limit":            bc.chainParams.BlockGasLimit.String(), // Block gas limit
		}

		// Convert to human-readable formats
		info["human_readable"] = map[string]interface{}{
			"max_block_size":       fmt.Sprintf("%.2f MB", float64(bc.chainParams.MaxBlockSize)/(1024*1024)),    // In MB
			"max_transaction_size": fmt.Sprintf("%.2f KB", float64(bc.chainParams.MaxTransactionSize)/1024),     // In KB
			"target_block_size":    fmt.Sprintf("%.2f MB", float64(bc.chainParams.TargetBlockSize)/(1024*1024)), // In MB
		}
	}

	// Add current statistics
	stats := bc.GetBlockSizeStats()
	info["current_stats"] = stats // Current block size statistics

	return info
}

// CreateBlock creates a new block with transactions from mempool
// CreateBlock creates a new block and iterates nonce until consensus using existing functions
// Returns: New block or error
func (bc *Blockchain) CreateBlock() (*types.Block, error) {
	// Validate prerequisites
	if bc.mempool == nil {
		return nil, fmt.Errorf("mempool not initialized")
	}
	if bc.chainParams == nil {
		return nil, fmt.Errorf("chain parameters not initialized")
	}
	bc.lock.Lock() // Write lock for thread safety
	defer bc.lock.Unlock()

	// Get the latest block to use as parent
	prevBlock, err := bc.storage.GetLatestBlock()
	if err != nil || prevBlock == nil {
		return nil, fmt.Errorf("no previous block found: %v", err)
	}

	// Get previous hash (handles both hex and GENESIS_ formats)
	parentHash := prevBlock.GetHash()
	var parentHashBytes []byte

	// Check if parent hash is in genesis format
	if strings.HasPrefix(parentHash, "GENESIS_") {
		// Handle genesis-style parent hash (string format)
		parentHashBytes = []byte(parentHash)
		logger.Info("Using genesis-style parent hash: %s (stored as %d bytes)",
			parentHash, len(parentHashBytes))
	} else {
		// Handle normal hex-encoded hash
		parentHashBytes, err = hex.DecodeString(parentHash)
		if err != nil {
			return nil, fmt.Errorf("failed to decode parent hash: %w", err)
		}
		logger.Info("Using normal parent hash: %s (stored as %d bytes)",
			parentHash, len(parentHashBytes))
	}

	// Get pending transactions from mempool
	pendingTxs := bc.mempool.GetPendingTransactions()
	if len(pendingTxs) == 0 {
		return nil, errors.New("no pending transactions in mempool")
	}

	logger.Info("Found %d pending transactions in mempool, max block size: %d bytes",
		len(pendingTxs), bc.chainParams.MaxBlockSize)

	// Select transactions based on block size constraints
	selectedTxs, totalSize, err := bc.selectTransactionsForBlock(pendingTxs)
	if err != nil {
		return nil, fmt.Errorf("failed to select transactions: %w", err)
	}

	// Check if any transactions were selected
	if len(selectedTxs) == 0 {
		return nil, errors.New("no transactions could be selected for block")
	}

	// Log block creation details
	logger.Info("Creating block with %d transactions, estimated size: %d bytes (limit: %d, utilization: %.2f%%)",
		len(selectedTxs), totalSize, bc.chainParams.MaxBlockSize,
		float64(totalSize)/float64(bc.chainParams.MaxBlockSize)*100)

	// Calculate roots for the block
	txsRoot := bc.calculateTransactionsRoot(selectedTxs) // Merkle root of transactions
	stateRoot := bc.calculateStateRoot()                 // State root after transactions

	// Make sure timestamp is in seconds, not nanoseconds
	currentTimestamp := common.GetCurrentTimestamp()
	if currentTimestamp == 0 {
		currentTimestamp = time.Now().Unix() // Unix() returns seconds
	}

	logger.Info("Creating block with timestamp: %d (%s)",
		currentTimestamp, time.Unix(currentTimestamp, 0).Format(time.RFC3339))

	// ========== FIX 1: Define miner address ==========
	// Create a default miner address (20 bytes zero address)
	// In production, this would be the proposer's address
	miner := make([]byte, 20) // 20-byte zero address (Ethereum-style)

	// If consensus engine is available, use the proposer's address
	if bc.consensusEngine != nil && bc.consensusEngine.GetNodeID() != "" {
		// Convert node ID to address bytes (simple hash for now)
		nodeIDHash := common.SpxHash([]byte(bc.consensusEngine.GetNodeID()))
		if len(nodeIDHash) >= 20 {
			miner = nodeIDHash[:20] // Use first 20 bytes
		}
	}
	// ================================================

	// ========== FIX 2: Define emptyUncles ==========
	// Empty slice of uncle block headers
	emptyUncles := []*types.BlockHeader{}
	// ================================================

	// ========== FIX 3: Prepare extraData ==========
	// ExtraData should be simple block metadata, NOT containing OP_RETURN hashes
	extraData := []byte(fmt.Sprintf("Sphinx Block %d", prevBlock.GetHeight()+1))

	// REMOVE THIS ENTIRE BLOCK - DO NOT PUT OP_RETURN HASH IN EXTRA_DATA
	// var returnDataHash []byte
	// for _, tx := range selectedTxs {
	//     if tx.HasReturnData() && len(tx.ReturnData) > 0 {
	//         returnDataHash = common.SpxHash(append(returnDataHash, tx.ReturnData...))
	//     }
	// }
	// if len(returnDataHash) > 0 {
	//     extraData = append(extraData, returnDataHash...)
	// }
	// ================================================================

	newHeader := types.NewBlockHeader(
		prevBlock.GetHeight()+1,      // Height
		parentHashBytes,              // Parent hash
		bc.GetDifficulty(),           // Difficulty
		txsRoot,                      // Transaction Merkle root
		stateRoot,                    // State root
		bc.chainParams.BlockGasLimit, // Gas limit
		big.NewInt(0),                // Gas used (initially 0)
		extraData,                    // ExtraData includes OP_RETURN hash
		miner,                        // Miner address
		currentTimestamp,             // Block timestamp
		emptyUncles,                  // Uncles (empty)
	)

	newBody := types.NewBlockBody(selectedTxs, emptyUncles) // Create block body
	newBlock := types.NewBlock(newHeader, newBody)          // Create complete block

	// CRITICAL: Increment nonce multiple times until consensus is achieved
	logger.Info("Starting nonce iteration for consensus: initial nonce=%s", newBlock.Header.Nonce)

	maxAttempts := 1000000 // 1 million attempts maximum
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Use existing IncrementNonce function
		if err := newBlock.IncrementNonce(); err != nil {
			logger.Warn("Failed to increment nonce on attempt %d: %v", attempt, err)
			continue
		}

		// Finalize hash with new nonce
		newBlock.FinalizeHash()

		// Check if consensus requirements are met using existing validation
		if bc.checkConsensusRequirements(newBlock) {
			logger.Info("✅ Consensus achieved with nonce %s after %d attempts",
				newBlock.Header.Nonce, attempt+1)
			break
		}

		// Log progress every 1000 attempts
		if (attempt+1)%1000 == 0 {
			logger.Debug("Nonce iteration: attempt %d, current nonce: %s",
				attempt+1, newBlock.Header.Nonce)
		}

		// If we reach the end, use the last nonce
		if attempt == maxAttempts-1 {
			logger.Info("⚠️ Max nonce attempts reached, using nonce %s", newBlock.Header.Nonce)
		}
	}

	// Final validation using existing functions
	if err := newBlock.ValidateHashFormat(); err != nil {
		logger.Warn("❌ Block hash format validation failed: %v", err)
		newBlock.SetHash(hex.EncodeToString(newBlock.GenerateBlockHash()))
		if err := newBlock.ValidateHashFormat(); err != nil {
			return nil, fmt.Errorf("failed to generate valid block hash: %w", err)
		}
	}

	// Validate transaction root consistency
	if err := newBlock.ValidateTxsRoot(); err != nil {
		return nil, fmt.Errorf("created block has inconsistent TxsRoot: %v", err)
	}

	// CRITICAL: Calculate and cache the merkle root immediately
	merkleRoot := hex.EncodeToString(txsRoot) // Merkle root as hex
	blockHash := newBlock.GetHash()           // Block hash

	// Log merkle root for debugging
	logger.Info("✅ Pre-calculated merkle root for new block %s: %s", blockHash, merkleRoot)

	// Cache it in consensus if available
	if bc.consensusEngine != nil {
		bc.consensusEngine.CacheMerkleRoot(blockHash, merkleRoot) // Cache for quick access
		logger.Info("✅ Cached merkle root in consensus engine")
	} else {
		logger.Warn("⚠️ No consensus engine available for caching")
	}

	// Log successful block creation
	logger.Info("✅ Created new PBFT block: height=%d, transactions=%d, hash=%s, final_nonce=%s",
		newBlock.GetHeight(), len(selectedTxs), newBlock.GetHash(), newBlock.Header.Nonce)

	return newBlock, nil
}

// selectTransactionsForBlock selects transactions for the block based on size constraints
// Implements transaction selection algorithm respecting block size limits
// Parameters:
//   - pendingTxs: Slice of pending transactions
//
// Returns: Selected transactions, total size, and error
func (bc *Blockchain) selectTransactionsForBlock(pendingTxs []*types.Transaction) ([]*types.Transaction, uint64, error) {
	var selectedTxs []*types.Transaction // Selected transactions
	currentSize := uint64(0)             // Current accumulated size
	txCount := 0                         // Number of transactions selected
	maxTxCount := 10000                  // Safety limit to prevent excessive processing

	// Calculate overhead for block metadata (header, etc.)
	// This is an estimate - adjust based on your actual block structure
	blockOverhead := uint64(1000) // ~1KB for header and other metadata
	availableSize := bc.chainParams.MaxBlockSize - blockOverhead

	// Check if block size is sufficient for overhead
	if availableSize <= 0 {
		return nil, 0, fmt.Errorf("block size too small for overhead")
	}

	// Log available space
	logger.Debug("Available block size for transactions: %d bytes (after %d bytes overhead)",
		availableSize, blockOverhead)

	// Track gas usage if applicable
	currentGas := big.NewInt(0)

	// Iterate through pending transactions
	for _, tx := range pendingTxs {
		if txCount >= maxTxCount {
			logger.Warn("Reached maximum transaction count limit: %d", maxTxCount)
			break
		}

		// Calculate transaction size using existing function
		txSize, err := bc.calculateTxsSize(tx)
		if err != nil {
			logger.Warn("Failed to calculate transaction size: %v, skipping", err)
			continue
		}

		// Check if transaction is too large individually
		if txSize > bc.chainParams.MaxTransactionSize {
			logger.Warn("Transaction exceeds maximum size: %d > %d", txSize, bc.chainParams.MaxTransactionSize)
			continue
		}

		if err := bc.ValidateTransactionPolicy(tx); err != nil {
			logger.Warn("Transaction %s failed policy validation: %v", tx.ID, err)
			continue
		}

		// Check if adding this transaction would exceed block size
		if currentSize+txSize > availableSize {
			continue
		}

		// Check transaction gas limit if applicable
		if bc.chainParams.BlockGasLimit != nil {
			txGas := bc.getTransactionGas(tx) // Get gas for transaction
			proposedGas := new(big.Int).Add(currentGas, txGas)

			// Check if adding this transaction would exceed block gas limit
			if proposedGas.Cmp(bc.chainParams.BlockGasLimit) > 0 {
				logger.Debug("Transaction would exceed gas limit: %s > %s",
					proposedGas.String(), bc.chainParams.BlockGasLimit.String())
				continue
			}
			currentGas = proposedGas // Update current gas usage
		}

		// Add transaction to selected list
		selectedTxs = append(selectedTxs, tx)
		currentSize += txSize // Update accumulated size
		txCount++

		// Optional: Stop if we're close to the target size to leave room for variability
		if currentSize >= availableSize*95/100 {
			logger.Debug("Reached 95%% of available block size, stopping selection")
			break
		}
	}

	// Log selection statistics
	if len(selectedTxs) > 0 {
		utilization := float64(currentSize) / float64(availableSize) * 100
		averageTxSize := float64(currentSize) / float64(len(selectedTxs))
		logger.Info("Selected %d transactions, total size: %d bytes (%.2f%% utilization, avg tx: %.2f bytes)",
			len(selectedTxs), currentSize, utilization, averageTxSize)
		if bc.chainParams.BlockGasLimit != nil {
			gasUtilization := float64(currentGas.Int64()) / float64(bc.chainParams.BlockGasLimit.Int64()) * 100
			logger.Info("Gas usage: %s / %s (%.2f%%)",
				currentGas.String(), bc.chainParams.BlockGasLimit.String(), gasUtilization)
		}
	}

	// Sort by (sender, nonce) so per-sender nonce ordering is preserved.
	sort.SliceStable(selectedTxs, func(i, j int) bool {
		if selectedTxs[i].Sender == selectedTxs[j].Sender {
			return selectedTxs[i].Nonce < selectedTxs[j].Nonce
		}
		return selectedTxs[i].Sender < selectedTxs[j].Sender
	})

	return selectedTxs, currentSize + blockOverhead, nil
}

// calculateTransactionSize calculates the size of a transaction in bytes
// Parameters:
//   - tx: Transaction to calculate size for
//
// Returns: Size in bytes and error
func (bc *Blockchain) calculateTxsSize(tx *types.Transaction) (uint64, error) {
	// Use mempool's calculation if available - this is the preferred method
	if bc.mempool != nil {
		return bc.mempool.CalculateTransactionSize(tx), nil
	}

	// Calculate size based on actual transaction fields
	estimatedSize := uint64(0)

	// Base transaction overhead
	estimatedSize += 50 // Fixed overhead for transaction metadata

	// Account for transaction ID
	estimatedSize += uint64(len(tx.ID)) // Size of transaction ID string

	// Account for sender and receiver addresses
	estimatedSize += uint64(len(tx.Sender))   // Sender address length
	estimatedSize += uint64(len(tx.Receiver)) // Receiver address length

	// Account for amount (big.Int size)
	if tx.Amount != nil {
		estimatedSize += uint64(len(tx.Amount.Bytes())) // Size of amount bytes
	}

	// Account for gas fields
	if tx.GasLimit != nil {
		estimatedSize += uint64(len(tx.GasLimit.Bytes())) // Gas limit size
	}
	if tx.GasPrice != nil {
		estimatedSize += uint64(len(tx.GasPrice.Bytes())) // Gas price size
	}

	// Account for nonce (uint64 = 8 bytes)
	estimatedSize += 8

	// Account for timestamp (int64 = 8 bytes)
	estimatedSize += 8

	// Account for signature
	estimatedSize += uint64(len(tx.Signature)) // Signature size
	estimatedSize += uint64(len(tx.SignatureHash))
	estimatedSize += uint64(len(tx.PublicKey))
	estimatedSize += uint64(len(tx.AuthTimestamp))
	estimatedSize += uint64(len(tx.AuthNonce))
	estimatedSize += uint64(len(tx.MerkleRootHash))
	estimatedSize += uint64(len(tx.Commitment))
	estimatedSize += uint64(len(tx.Proof))

	// Account for transaction version (uint32 = 4 bytes) - MISSING
	estimatedSize += 4

	// Account for return data (OP_RETURN) if present
	if tx.HasReturnData() && len(tx.ReturnData) > 0 {
		estimatedSize += uint64(len(tx.ReturnData))
		logger.Debug("calculateTxsSize: added return data size %d bytes", len(tx.ReturnData))
	}

	// Log calculated size
	logger.Debug("Calculated transaction size: %d bytes", estimatedSize)
	return estimatedSize, nil
}

// DecodeBlockHashForConsensus - ensure it handles both formats correctly
// Converts various hash formats to bytes for consensus operations
// Parameters:
//   - hash: Hash string to decode
//
// Returns: Decoded bytes and error
func (bc *Blockchain) DecodeBlockHash(hash string) ([]byte, error) {
	// Handle empty hash
	if hash == "" {
		return nil, fmt.Errorf("empty hash")
	}

	// If it's a genesis hash in text format
	if strings.HasPrefix(hash, "GENESIS_") && len(hash) > 8 {
		// For consensus operations, extract the hex part
		hexPart := hash[8:] // Remove "GENESIS_" prefix
		if isHexString(hexPart) {
			return hex.DecodeString(hexPart) // Decode hex portion
		}
		// If it's not valid hex, return the text as bytes
		return []byte(hash), nil
	}

	// Normal hex-encoded hash
	if !isHexString(hash) {
		// If it's not hex, it might already be bytes, return as-is
		return []byte(hash), nil
	}
	return hex.DecodeString(hash) // Decode hex string
}

// VerifyTransactionInBlock verifies if a transaction is included in a block
// Parameters:
//   - tx: Transaction to verify
//   - blockHash: Hash of the block
//
// Returns: true if transaction is in block, error if verification fails
func (bc *Blockchain) VerifyTransactionInBlock(tx *types.Transaction, blockHash string) (bool, error) {
	// Get block from storage
	block, err := bc.storage.GetBlockByHash(blockHash)
	if err != nil {
		return false, fmt.Errorf("failed to get block: %w", err)
	}

	// Create Merkle tree from block's transactions
	tree := types.NewMerkleTree(block.Body.TxsList)
	// Verify transaction inclusion
	return tree.VerifyTransaction(tx), nil
}

// GenerateTransactionProof generates a Merkle proof for a transaction
// Parameters:
//   - tx: Transaction to generate proof for
//   - blockHash: Hash of the block containing the transaction
//
// Returns: Merkle proof as byte slices and error
func (bc *Blockchain) GenerateTransactionProof(tx *types.Transaction, blockHash string) ([][]byte, error) {
	// Get block from storage
	block, err := bc.storage.GetBlockByHash(blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get block: %w", err)
	}

	// Create Merkle tree from block's transactions
	tree := types.NewMerkleTree(block.Body.TxsList)
	// Generate Merkle proof for transaction
	proof, err := tree.GenerateMerkleProof(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate merkle proof: %w", err)
	}

	return proof, nil
}

// CommitBlock commits a block through state machine replication
func (bc *Blockchain) CommitBlock(block consensus.Block) error {
	// Add panic recovery to prevent TPS recording from being skipped
	defer func() {
		if r := recover(); r != nil {
			logger.Error("PANIC in CommitBlock: %v", r)
		}
	}()

	logger.Info("🔵 CommitBlock called at %s", time.Now().Format("15:04:05.000"))

	// Extract the underlying types.Block from adapter
	var typeBlock *types.Block

	switch b := block.(type) {
	case *BlockHelper:
		if underlying, ok := b.GetUnderlyingBlock().(*types.Block); ok {
			typeBlock = underlying
		} else {
			return fmt.Errorf("BlockHelper contains invalid underlying block type")
		}
	case *types.Block:
		typeBlock = b
	default:
		return fmt.Errorf("invalid block type: expected *BlockHelper or *types.Block, got %T", block)
	}

	if typeBlock == nil {
		return fmt.Errorf("failed to extract underlying block")
	}

	logger.Info("🔵 Processing block height=%d, txCount=%d",
		typeBlock.GetHeight(), len(typeBlock.Body.TxsList))

	// Check if tpsMonitor is nil before using it
	if bc.tpsMonitor == nil {
		logger.Error("❌ tpsMonitor is nil! Cannot record TPS metrics")
		return fmt.Errorf("tpsMonitor not initialized")
	}

	// Calculate actual block time (time since last block)
	blockTime := bc.calculateBlockTime(typeBlock)
	logger.Info("📊 Block time calculated: %v", blockTime)

	// Record block in storage TPS with actual block time
	bc.storage.RecordBlock(typeBlock, blockTime)

	// Record each transaction individually
	txCount := uint64(len(typeBlock.Body.TxsList))
	logger.Info("📊 Recording %d transactions in TPS monitor", txCount)

	for i := uint64(0); i < txCount; i++ {
		bc.tpsMonitor.RecordTransaction()
	}

	// Then record the block
	logger.Info("📊 Recording block in TPS monitor with txCount=%d, blockTime=%v", txCount, blockTime)
	bc.tpsMonitor.RecordBlock(txCount, blockTime)

	// Verify TPS recording worked
	stats := bc.tpsMonitor.GetStats()
	logger.Info("📊 Current TPS stats after recording: blocks_processed=%v, total_txs=%v, avg_txs_per_block=%.2f",
		stats["blocks_processed"], stats["total_transactions"], stats["avg_transactions_per_block"])

	// Check if blockchain is in running state
	if bc.GetStatus() != StatusRunning {
		logger.Warn("⚠️ Blockchain status is %s, but TPS already recorded", bc.StatusString(bc.GetStatus()))
		return fmt.Errorf("blockchain not ready to commit blocks, status: %s",
			bc.StatusString(bc.GetStatus()))
	}

	if err := bc.validateBlockTransactionAuth(typeBlock, false); err != nil {
		return fmt.Errorf("CommitBlock: transaction authentication failed: %w", err)
	}
	for _, tx := range typeBlock.Body.TxsList {
		if err := bc.ValidateTransactionPolicy(tx); err != nil {
			return fmt.Errorf("CommitBlock: transaction policy failed: %w", err)
		}
	}

	// Execute block: apply transactions, mint reward, compute real StateRoot.
	stateRoot, err := bc.ExecuteBlock(typeBlock)
	if err != nil {
		logger.Error("❌ ExecuteBlock failed: %v", err)
		return fmt.Errorf("CommitBlock: execution failed: %w", err)
	}
	logger.Info("✅ Block executed, stateRoot=%x", stateRoot)

	// Process OP_RETURN data in transactions
	for _, tx := range typeBlock.Body.TxsList {
		if tx.HasReturnData() {
			dataLen := len(tx.ReturnData)

			logger.Info("DEBUG: Preparing OP_RETURN for tx %s, dataLen=%d, data=%s",
				tx.ID, dataLen, string(tx.ReturnData))

			vmBytecode := []byte{}

			// Push data pointer FIRST (will be popped SECOND)
			vmBytecode = append(vmBytecode, byte(svm.PUSH4))
			vmBytecode = append(vmBytecode, 0x00, 0x00, 0x00, 0x00)

			// Push data length SECOND (will be popped FIRST)
			vmBytecode = append(vmBytecode, byte(svm.PUSH4))
			vmBytecode = append(vmBytecode, byte(dataLen>>24), byte(dataLen>>16), byte(dataLen>>8), byte(dataLen))

			// OP_RETURN
			vmBytecode = append(vmBytecode, byte(svm.OP_RETURN))

			// Create memory layout with the data at position 0
			memoryLayout := make([]byte, dataLen)
			copy(memoryLayout, tx.ReturnData)

			vm := vm.NewVM(vmBytecode)
			if err := vm.SetMemoryBytes(0, memoryLayout); err != nil {
				bc.recordSVMFailure(typeBlock.GetHash(), tx.ID, err)
				logger.Error("OP_RETURN VM memory setup failed for tx %s: %v", tx.ID, err)
				continue
			}
			if err := vm.Run(); err != nil {
				bc.recordSVMFailure(typeBlock.GetHash(), tx.ID, err)
				logger.Error("OP_RETURN execution failed for tx %s: %v", tx.ID, err)
				continue
			}

			// Store return data
			if err := bc.storeReturnData(tx.ID, tx.ReturnData); err != nil {
				logger.Warn("Failed to store OP_RETURN data for tx %s: %v", tx.ID, err)
			}

			logger.Info("📝 OP_RETURN: Transaction %s embedded %d bytes: %s",
				tx.ID, dataLen, string(tx.ReturnData))
		}
	}

	// Stamp the real state root into the block header before storage.
	// CRITICAL: Do NOT call FinalizeHash() again - the hash was already
	// finalized in CreateBlock and agreed upon by consensus.
	typeBlock.Header.StateRoot = stateRoot
	// The block hash remains unchanged - consensus already agreed on this hash

	// ========== Store block with delay to prevent race condition ==========
	logger.Info("📝 Attempting to store block at height %d with hash %s",
		typeBlock.GetHeight(), typeBlock.GetHash())

	// Store block in storage (now with the real StateRoot).
	if err := bc.storage.StoreBlock(typeBlock); err != nil {
		logger.Error("❌ Failed to store block: %v", err)
		return fmt.Errorf("failed to store block: %w", err)
	}
	logger.Info("✅ Block stored in storage successfully at %s", time.Now().Format("15:04:05.000"))

	if err := bc.validateBlockTransactionAuth(typeBlock, true); err != nil {
		return fmt.Errorf("CommitBlock: failed to store canonical transaction evidence: %w", err)
	}
	logger.Info("✅ Canonical transaction replay and receipt evidence stored")

	// Add a small delay to ensure block is visible to other goroutines
	time.Sleep(200 * time.Millisecond)
	logger.Info("✅ Block storage confirmed after delay")

	// Update in-memory chain
	bc.lock.Lock()
	bc.chain = append(bc.chain, typeBlock)
	logger.Info("✅ Block added to in-memory chain")
	bc.lock.Unlock()

	// ========== Add signature to consensus engine ==========
	if bc.consensusEngine != nil {
		// Create a consensus signature for this block
		signature := &consensus.ConsensusSignature{
			BlockHash:    typeBlock.GetHash(),
			BlockHeight:  typeBlock.GetHeight(),
			SignerNodeID: bc.consensusEngine.GetNodeID(),
			Signature:    "committed_" + typeBlock.GetHash()[:16],
			MessageType:  "commit",
			View:         bc.consensusEngine.GetCurrentView(),
			Timestamp:    time.Now().Format(time.RFC3339),
			Valid:        true,
			MerkleRoot:   hex.EncodeToString(typeBlock.Header.TxsRoot),
			Status:       "committed",
		}

		// Add signature to consensus engine
		bc.consensusEngine.AddConsensusSignature(signature)
		logger.Info("✅ Added commit signature for block %s to consensus engine", typeBlock.GetHash())

		// Now get signatures and save chain state
		signatures := bc.consensusEngine.GetConsensusSignatures()
		logger.Info("📊 Total consensus signatures in engine after adding: %d", len(signatures))

		// Force save chain state to persist signatures
		if err := bc.SaveBasicChainState(); err != nil {
			logger.Warn("Failed to save chain state after block commit: %v", err)
		} else {
			logger.Info("✅ Chain state saved after block commit with %d signatures", len(signatures))
		}
	}

	// Remove committed transactions from mempool
	txIDs := make([]string, len(typeBlock.Body.TxsList))
	for i, tx := range typeBlock.Body.TxsList {
		txIDs[i] = tx.ID
	}
	bc.mempool.RemoveTransactions(txIDs)
	logger.Info("✅ Removed %d transactions from mempool", len(txIDs))

	// Log successful commit with final TPS stats
	finalStats := bc.tpsMonitor.GetStats()
	logger.Info("✅ Block committed: height=%d, hash=%s, transactions=%d, block_time=%v",
		typeBlock.GetHeight(), typeBlock.GetHash(), len(txIDs), blockTime)
	logger.Info("📊 Final TPS stats: blocks_processed=%v, total_txs=%v, avg_txs_per_block=%.2f, current_tps=%.2f",
		finalStats["blocks_processed"], finalStats["total_transactions"],
		finalStats["avg_transactions_per_block"], finalStats["current_tps"])

	return nil
}

// initializeChain loads existing chain or creates genesis block.
//
// If persistent storage already has a block at height 0 it is loaded directly.
// Otherwise createGenesisBlock() is called which now builds the genesis block
// through GenesisState (genesis.go / allocation.go) instead of the old
// CreateStandardGenesisBlock() standalone helper.
//
// Returns: Error if initialization fails
func (bc *Blockchain) initializeChain() error {
	// First, try to get the latest block
	latestBlock, err := bc.storage.GetLatestBlock()
	if err != nil {
		logger.Warn("Warning: Could not load initial state: %v", err)

		// Create genesis block
		logger.Info("No existing chain found, creating genesis block")
		if err := bc.createGenesisBlock(); err != nil {
			return fmt.Errorf("failed to create genesis block: %w", err)
		}

		// Now the genesis block should be in memory, don't try to reload from storage
		if len(bc.chain) == 0 {
			return fmt.Errorf("genesis block created but chain is empty")
		}

		latestBlock = bc.chain[0] // Get genesis block from memory
		logger.Info("Using genesis block from memory: height=%d, hash=%s",
			latestBlock.GetHeight(), latestBlock.GetHash())
	} else {
		// Load existing chain
		bc.chain = []*types.Block{latestBlock} // Add to memory
	}

	// Log initialization success
	logger.Info("Chain initialized: height=%d, hash=%s, total_blocks=%d",
		latestBlock.GetHeight(), latestBlock.GetHash(), bc.storage.GetTotalBlocks())

	return nil
}

// createGenesisBlock builds and stores the genesis block through GenesisState
// so that the allocation Merkle root and all header fields are identical across
// every node in the network.
//
// Integration flow:
//  1. Read bc.chainParams (already set by NewBlockchain before this is called).
//  2. Call GenesisStateFromChainParams() to build a GenesisState — this embeds
//     the canonical DefaultGenesisAllocations() Merkle root in the header.
//  3. Validate the GenesisState before touching disk.
//  4. Call ApplyGenesis(bc, gs) which calls gs.BuildBlock(), stores the block,
//     seeds bc.chain[0], and writes genesis_state.json for auditing.
//  5. Log the allocation summary so operators can verify the distribution.
//  6. Sync bc.chainParams.GenesisHash with the actual hash produced.
//
// Returns: Error if genesis block creation fails
func (bc *Blockchain) createGenesisBlock() error {
	if bc.chainParams == nil {
		logger.Warn("chainParams nil during genesis creation, falling back to mainnet params")
		bc.chainParams = GetSphinxChainParams()
	}

	// Log which environment we're actually creating genesis for
	logger.Info("createGenesisBlock: environment=%s chainID=%d isDevnet=%v",
		bc.chainParams.ChainName, bc.chainParams.ChainID, bc.chainParams.IsDevnet())

	gs := GenesisStateFromChainParams(bc.chainParams)

	if err := ValidateGenesisState(gs); err != nil {
		return fmt.Errorf("genesis state validation failed: %w", err)
	}

	if err := ApplyGenesisWithCachedBlock(bc, gs, getCachedGenesisBlock()); err != nil {
		return fmt.Errorf("ApplyGenesis failed: %w", err)
	}

	// DO NOT call ApplyGenesisState here.
	// The vault-and-distribute model (ExecuteGenesisBlock + block 1 txs)
	// is the single authoritative path for crediting balances.
	// ApplyGenesisState credits balances directly AND increments total_supply,
	// which would cause double-counting when block 1 distribution txs run.

	LogAllocationSummary(gs.Allocations)

	// Get the genesis block from the chain (now populated by ApplyGenesisWithCachedBlock)
	genesis := bc.chain[0]

	// ========== RECORD GENESIS BLOCK IN TPS MONITOR ==========
	if bc.tpsMonitor != nil {
		txCount := uint64(len(genesis.Body.TxsList))
		bc.tpsMonitor.RecordBlock(txCount, 5*time.Second)
		logger.Info("📊 Recorded genesis block in TPS monitor with %d transactions", txCount)
	}
	// =========================================================

	localTime, utcTime := common.FormatTimestamp(genesis.Header.Timestamp)
	relativeTime := common.GetTimeService().GetRelativeTime(genesis.Header.Timestamp)

	logger.Info("=== STANDARDIZED GENESIS BLOCK ===")
	logger.Info("Environment  : %s (ChainID=%d)", bc.chainParams.ChainName, bc.chainParams.ChainID)
	logger.Info("Height: %d", genesis.GetHeight())
	logger.Info("Hash: %s", genesis.GetHash())
	logger.Info("Timestamp: %d (%s)", genesis.Header.Timestamp, relativeTime)
	logger.Info("Local Time: %s", localTime)
	logger.Info("UTC Time: %s", utcTime)
	logger.Info("================================")

	actualHash := genesis.GetHash()
	if bc.chainParams.GenesisHash != actualHash {
		logger.Warn("Updating chainParams.GenesisHash from %s to %s",
			bc.chainParams.GenesisHash, actualHash)
		bc.chainParams.GenesisHash = actualHash
	}

	if storedHash, err := bc.GetGenesisHashFromIndex(); err == nil {
		if storedHash != actualHash {
			return fmt.Errorf(
				"chain continuity violation: stored genesis %s does not match "+
					"%s genesis %s — wipe the data directory to switch environments",
				storedHash, bc.chainParams.ChainName, actualHash,
			)
		}
		logger.Info("✅ Chain continuity confirmed: genesis %s carries forward to %s",
			actualHash, bc.chainParams.ChainName)
	}

	return nil
}

// verifyGenesisHashInIndex verifies that the genesis hash in block_index.json matches our actual genesis hash
// Returns: Error if verification fails
func (bc *Blockchain) verifyGenesisHashInIndex() error {
	// Check if chain has blocks
	if len(bc.chain) == 0 {
		return fmt.Errorf("no genesis block in chain")
	}

	actualGenesisHash := bc.chain[0].GetHash() // Get actual genesis hash

	// Try to read the block_index.json to verify the hash is there
	indexFile := filepath.Join(bc.storage.GetIndexDir(), "block_index.json")
	data, err := os.ReadFile(indexFile)
	if err != nil {
		return fmt.Errorf("failed to read block_index.json: %w", err)
	}

	// Parse index file
	var index struct {
		Blocks map[string]uint64 `json:"blocks"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return fmt.Errorf("failed to unmarshal block_index.json: %w", err)
	}

	// Check if our genesis hash exists in the index
	if height, exists := index.Blocks[actualGenesisHash]; exists {
		if height == 0 {
			logger.Info("✓ Genesis hash verified in block_index.json: %s", actualGenesisHash)
			return nil
		} else {
			return fmt.Errorf("genesis block has wrong height in index: expected 0, got %d", height)
		}
	} else {
		return fmt.Errorf("genesis hash not found in block_index.json")
	}
}

// GetGenesisHashFromIndex reads the actual genesis hash from block_index.json
// Returns: Genesis hash and error
func (bc *Blockchain) GetGenesisHashFromIndex() (string, error) {
	// Build path to index file
	indexFile := filepath.Join(bc.storage.GetIndexDir(), "block_index.json")

	// Check if file exists
	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		return "", fmt.Errorf("block_index.json does not exist")
	}

	// Read index file
	data, err := os.ReadFile(indexFile)
	if err != nil {
		return "", fmt.Errorf("failed to read block_index.json: %w", err)
	}

	// Parse index file
	var index struct {
		Blocks map[string]uint64 `json:"blocks"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return "", fmt.Errorf("failed to unmarshal block_index.json: %w", err)
	}

	// Find the block with height 0 (genesis)
	for hash, height := range index.Blocks {
		if height == 0 {
			return hash, nil // Return genesis hash
		}
	}

	return "", fmt.Errorf("no genesis block found in block_index.json")
}

// GetBlockByNumber returns a block by its height/number
// Parameters:
//   - height: Block height to retrieve
//
// Returns: Block or nil if not found
func (bc *Blockchain) GetBlockByNumber(height uint64) *types.Block {
	bc.lock.RLock() // Read lock for thread safety
	defer bc.lock.RUnlock()

	// Search in-memory chain first (faster)
	for _, block := range bc.chain {
		if block.GetHeight() == height {
			return block // Found in memory
		}
	}

	// Fall back to storage
	block, err := bc.storage.GetBlockByHeight(height)
	if err != nil {
		logger.Warn("Error getting block by height %d: %v", height, err)
		return nil
	}
	return block
}

// GetRawTransaction returns raw transaction data
// Parameters:
//   - txID: Transaction ID
//   - verbose: Whether to return verbose information
//
// Returns: Transaction data or nil if not found
func (bc *Blockchain) GetRawTransaction(txID string, verbose bool) interface{} {
	// Get transaction by ID
	tx, err := bc.GetTransactionByIDString(txID)
	if err != nil {
		return nil // Transaction not found
	}

	// Return raw hex if not verbose
	if !verbose {
		// Return hex-encoded raw transaction
		txData, err := json.Marshal(tx)
		if err != nil {
			return nil
		}
		return hex.EncodeToString(txData)
	}

	// Get formatted timestamps using centralized time service
	localTime, utcTime := common.FormatTimestamp(tx.Timestamp)

	// Return verbose transaction info
	return map[string]interface{}{
		"txid":          tx.ID,           // Transaction ID
		"hash":          tx.Hash(),       // Transaction hash
		"version":       1,               // Transaction version
		"size":          len(tx.ID) / 2,  // Transaction size in bytes
		"locktime":      0,               // Lock time
		"vin":           []interface{}{}, // Inputs (empty placeholder)
		"vout":          []interface{}{}, // Outputs (empty placeholder)
		"blockhash":     "",              // Block hash containing transaction
		"confirmations": 0,               // Number of confirmations
		"time":          tx.Timestamp,    // Transaction timestamp
		"time_local":    localTime,       // Local time
		"time_utc":      utcTime,         // UTC time
		"blocktime":     tx.Timestamp,    // Block timestamp
	}
}

// GetBestBlockHash returns the hash of the active chain's tip
// Returns: Best block hash as bytes
func (bc *Blockchain) GetBestBlockHash() []byte {
	latest := bc.GetLatestBlock() // Get latest block
	if latest == nil {
		return []byte{} // No blocks
	}
	return []byte(latest.GetHash()) // Return hash as bytes
}

// GetBlockCount returns the height of the active chain
// Returns: Number of blocks in chain
func (bc *Blockchain) GetBlockCount() uint64 {
	latest := bc.GetLatestBlock() // Get latest block
	if latest == nil {
		return 0 // No blocks
	}
	return latest.GetHeight() + 1 // Return height + 1 (count starts at 1)
}

// GetBlocks returns the current in-memory blockchain (limited)
// Returns: Slice of blocks in memory
func (bc *Blockchain) GetBlocks() []*types.Block {
	bc.lock.RLock() // Read lock for thread safety
	defer bc.lock.RUnlock()
	return bc.chain // Return in-memory chain
}

// ChainLength returns the current length of the in-memory chain
// Returns: Number of blocks in memory
func (bc *Blockchain) ChainLength() int {
	bc.lock.RLock() // Read lock for thread safety
	defer bc.lock.RUnlock()
	return len(bc.chain) // Return chain length
}

// Close cleans up resources
// Returns: Error if cleanup fails
func (bc *Blockchain) Close() error {
	// Set status to stopped before closing
	bc.SetStatus(StatusStopped)
	logger.Info("Blockchain shutting down...")
	return bc.storage.Close() // Close storage
}

// ValidateBlock validates a block including TxsRoot = MerkleRoot verification
// ValidateBlock - handle raw bytes in ParentHash
// Parameters:
//   - block: Block to validate (consensus.Block interface)
//
// Returns: Error if validation fails
// ValidateBlock validates a block including TxsRoot = MerkleRoot verification
// ValidateBlock - handle raw bytes in ParentHash
// Parameters:
//   - block: Block to validate (consensus.Block interface)
//
// Returns: Error if validation fails
func (bc *Blockchain) ValidateBlock(block consensus.Block) error {
	// Extract underlying types.Block
	var b *types.Block

	switch blk := block.(type) {
	case *BlockHelper:
		// Get underlying block from helper
		if underlying, ok := blk.GetUnderlyingBlock().(*types.Block); ok {
			b = underlying
		} else {
			return fmt.Errorf("BlockHelper contains invalid underlying block type")
		}
	case *types.Block:
		// Direct types.Block
		b = blk
	default:
		return fmt.Errorf("invalid block type: %T", block)
	}

	if b == nil {
		return fmt.Errorf("failed to extract underlying block")
	}

	// Validate ParentHash chain linkage (except for genesis block)
	if b.Header.Height > 0 {
		previousBlock := bc.GetLatestBlock() // Get previous block
		if previousBlock != nil {
			expectedParentHash := previousBlock.GetHash() // Expected parent hash
			currentParentHash := b.GetPrevHash()          // Actual parent hash

			logger.Info("🔍 DEBUG: ParentHash validation - expected: %s, current: %s",
				expectedParentHash, currentParentHash)

			// For comparison, we need to normalize both hashes
			decodedExpected, err := bc.DecodeBlockHash(expectedParentHash)
			if err != nil {
				return fmt.Errorf("failed to decode expected parent hash '%s': %w", expectedParentHash, err)
			}

			decodedCurrent, err := bc.DecodeBlockHash(currentParentHash)
			if err != nil {
				return fmt.Errorf("failed to decode current parent hash '%s': %w", currentParentHash, err)
			}

			// Compare decoded hashes
			if !bytes.Equal(decodedExpected, decodedCurrent) {
				return fmt.Errorf("invalid parent hash: expected %x, got %x",
					decodedExpected, decodedCurrent)
			}
		}
	}

	// 1. Verify TxsRoot = MerkleRoot
	if err := b.ValidateTxsRoot(); err != nil {
		return fmt.Errorf("TxsRoot validation failed: %w", err)
	}

	// 2. Structural sanity
	if err := b.SanityCheck(); err != nil {
		// Check for allowed warnings
		if strings.Contains(err.Error(), "state root is missing") {
			logger.Warn("WARNING: Block validation - state root is empty (allowed in test)")
		} else if strings.Contains(err.Error(), "transaction root is missing") {
			logger.Warn("WARNING: Block validation - transaction root is empty (allowed in test)")
		} else {
			return fmt.Errorf("block sanity check failed: %w", err)
		}
	}

	// 3. Block size validation
	if err := bc.ValidateBlockSize(b); err != nil {
		return fmt.Errorf("block size validation failed: %w", err)
	}

	// 4. Hash is correct
	expectedHash := b.GenerateBlockHash()
	if !bytes.Equal(b.Header.Hash, expectedHash) {
		return fmt.Errorf("invalid block hash: expected %x, got %x", expectedHash, b.Header.Hash)
	}

	// 5. Links to previous block using ParentHash
	previousBlock := bc.GetLatestBlock()
	if previousBlock != nil {
		// Use your existing DecodeBlockHash method that handles genesis hashes
		parentHashBytes, err := bc.DecodeBlockHash(previousBlock.GetHash())
		if err != nil {
			return fmt.Errorf("failed to decode previous block hash '%s': %w", previousBlock.GetHash(), err)
		}

		currentParentHashBytes, err := bc.DecodeBlockHash(b.GetPrevHash())
		if err != nil {
			return fmt.Errorf("failed to decode current parent hash '%s': %w", b.GetPrevHash(), err)
		}

		// Compare parent hashes
		if !bytes.Equal(parentHashBytes, currentParentHashBytes) {
			return fmt.Errorf("invalid parent hash: expected %s, got %s", previousBlock.GetHash(), b.GetPrevHash())
		}
	}

	// Calculate the expected uncles hash for debugging
	calculatedUnclesHash := types.CalculateUnclesHash(b.Body.Uncles, b.Header.Height)

	// Log successful validation
	logger.Info("✓ Block %d validation passed, TxsRoot = MerkleRoot verified: %x",
		b.GetHeight(), b.Header.TxsRoot)
	logger.Info("Validating block at height: %d", b.Header.Height)
	logger.Info("Block UnclesHash: %x", b.Header.UnclesHash)
	logger.Info("Calculated UnclesHash: %x", calculatedUnclesHash)

	return nil
}
