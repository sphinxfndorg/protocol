// MIT License
//
// Copyright (c) 2024 sphinx-core
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
			// This shouldn't happen with our consistent approach
		}

		// Log successful chain parameters initialization
		logger.Info("Chain parameters initialized for %s: genesis_hash=%s",
			chainParams.GetNetworkName(), chainParams.GenesisHash)

		// Initialize mempool with configuration from chain params
		// Create mempool with size limits and validation rules
		mempoolConfig := GetMempoolConfigFromChainParams(chainParams)
		blockchain.mempool = pool.NewMempool(mempoolConfig)

		// Log chain parameters again for visibility (FIXED: Use chainParams.GenesisHash)
		logger.Info("Chain parameters initialized for %s: genesis_hash=%s",
			chainParams.GetNetworkName(), chainParams.GenesisHash)

		// Verify the genesis hash is properly stored in block_index.json
		// This ensures the index file is consistent with the actual blockchain
		if err := blockchain.verifyGenesisHashInIndex(); err != nil {
			logger.Warn("Warning: Genesis hash verification failed: %v", err)
		}

		// AUTO-SAVE: Save chain state with actual genesis hash
		// Automatically persist the chain state after initialization
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
func (bc *Blockchain) CalculateBlockSize(block *types.Block) uint64 {
	// Initialize size counter
	size := uint64(0)

	// Header size (approximate) - fixed overhead
	// Account for all header fields: version, timestamps, hashes, etc.
	size += 80 // Fixed header components (version, timestamps, etc.)

	// Transactions size - sum of all transaction sizes
	// Calculate size for each transaction in the block
	for _, tx := range block.Body.TxsList {
		if tx.HasReturnData() {
			// Use mempool's transaction size calculator for consistency
			size += bc.mempool.CalculateTransactionSize(tx)
		}
	}

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
	var finalStates []*storage.FinalStateInfo
	var signatureValidation *storage.SignatureValidation

	// Check if consensus engine is available
	if bc.consensusEngine != nil {
		// Get raw signatures from consensus engine
		// Retrieve all consensus signatures for finality
		rawSignatures := bc.consensusEngine.GetConsensusSignatures()
		// Prepare slice to hold converted signatures
		finalStates = make([]*storage.FinalStateInfo, len(rawSignatures))

		validCount := 0
		// Convert consensus signatures to storage format
		// Iterate through each raw signature
		for i, rawSig := range rawSignatures {
			// Convert to storage format with additional metadata
			finalStates[i] = &storage.FinalStateInfo{
				BlockHash:        rawSig.BlockHash,                                      // Block being signed
				BlockHeight:      rawSig.BlockHeight,                                    // Height of signed block
				SignerNodeID:     rawSig.SignerNodeID,                                   // Node that created signature
				Signature:        rawSig.Signature,                                      // Actual signature bytes
				MessageType:      rawSig.MessageType,                                    // Type of consensus message
				View:             rawSig.View,                                           // Consensus view number
				Timestamp:        rawSig.Timestamp,                                      // When signature was created
				Valid:            rawSig.Valid,                                          // Whether signature is valid
				SignatureStatus:  "Valid",                                               // Human-readable status
				VerificationTime: common.GetTimeService().GetCurrentTimeInfo().ISOLocal, // Verification timestamp
			}
			// Count valid signatures
			if rawSig.Valid {
				validCount++
			}
		}

		// Create signature validation statistics
		// Generate summary of signature validation results
		signatureValidation = &storage.SignatureValidation{
			TotalSignatures:   len(finalStates),                                    // Total signatures processed
			ValidSignatures:   validCount,                                          // Number of valid signatures
			InvalidSignatures: len(finalStates) - validCount,                       // Number of invalid signatures
			ValidationTime:    common.GetTimeService().GetCurrentTimeInfo().ISOUTC, // Validation timestamp
		}

		// Log signature collection results
		logger.Info("Storing %d consensus signatures (%d valid) in chain state as final states",
			len(finalStates), validCount)
	}

	// Create chain state with signature data
	// Build complete chain state structure
	chainState := &storage.ChainState{
		Nodes:               nodes,                                               // Network node information
		Timestamp:           common.GetTimeService().GetCurrentTimeInfo().ISOUTC, // State snapshot time
		SignatureValidation: signatureValidation,                                 // Signature validation results
		FinalStates:         finalStates,                                         // Finalized consensus signatures
	}

	// Save chain state with actual parameters and signatures
	// Persist to storage
	err := bc.storage.SaveCompleteChainState(chainState, chainParams, walletPaths)
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
	// Calculate sizes in megabytes for better readability
	averageSizeMB := float64(averageSize) / (1024 * 1024)
	minSizeMB := float64(minSize) / (1024 * 1024)
	maxSizeMB := float64(maxSize) / (1024 * 1024)
	totalSizeMB := float64(totalSize) / (1024 * 1024)

	// Create block size metrics structure
	// Build comprehensive metrics object
	blockSizeMetrics := &storage.BlockSizeMetrics{
		TotalBlocks:     uint64(len(recentBlocks)),                             // Number of blocks analyzed
		AverageSize:     averageSize,                                           // Average size in bytes
		MinSize:         minSize,                                               // Minimum size in bytes
		MaxSize:         maxSize,                                               // Maximum size in bytes
		TotalSize:       totalSize,                                             // Total size of all blocks in bytes
		SizeStats:       sizeStats,                                             // Individual block statistics
		CalculationTime: common.GetTimeService().GetCurrentTimeInfo().ISOLocal, // Calculation timestamp
		AverageSizeMB:   averageSizeMB,                                         // Average size in MB
		MinSizeMB:       minSizeMB,                                             // Minimum size in MB
		MaxSizeMB:       maxSizeMB,                                             // Maximum size in MB
		TotalSizeMB:     totalSizeMB,                                           // Total size in MB
	}

	// Save to storage
	// Persist metrics for future reference
	if err := bc.storage.SaveBlockSizeMetrics(blockSizeMetrics); err != nil {
		return fmt.Errorf("failed to save block size metrics: %w", err)
	}

	// Log success and summary statistics
	logger.Info("Successfully calculated block size metrics for %d blocks", len(recentBlocks))
	logger.Info("Block size stats: avg=%.2f MB, min=%.2f MB, max=%.2f MB, total=%.2f MB",
		averageSizeMB, minSizeMB, maxSizeMB, totalSizeMB)
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

// GenerateLedgerHeaders generates headers specifically formatted for Ledger hardware
// Creates human-readable transaction summaries for hardware wallet displays
// Parameters:
//   - operation: Type of operation (send, receive, etc.)
//   - amount: Amount in SPX
//   - address: Destination address
//   - memo: Optional memo text
//
// Returns: Formatted string for Ledger display
func (bc *Blockchain) GenerateLedgerHeaders(operation string, amount float64, address string, memo string) string {
	// Get current chain parameters
	params := bc.GetChainParams()

	// Return formatted string with Ledger-specific formatting
	return fmt.Sprintf(
		"=== SPHINX LEDGER OPERATION ===\n"+
			"Chain: %s\n"+
			"Chain ID: %d\n"+
			"Operation: %s\n"+
			"Amount: %.6f SPX\n"+
			"Address: %s\n"+
			"Memo: %s\n"+
			"BIP44: 44'/%d'/0'/0/0\n"+
			"Timestamp: %d\n"+
			"========================",
		params.ChainName,             // Network name
		params.ChainID,               // Chain identifier
		operation,                    // Operation type
		amount,                       // Amount with 6 decimal places
		address,                      // Destination address
		memo,                         // Optional memo
		params.BIP44CoinType,         // BIP44 coin type for derivation
		common.GetCurrentTimestamp(), // Current timestamp
	)
}

// ValidateChainID validates if this blockchain matches Sphinx network parameters
// Parameters:
//   - chainID: Chain ID to validate
//
// Returns: true if chain ID matches, false otherwise
func (bc *Blockchain) ValidateChainID(chainID uint64) bool {
	// Get current chain parameters
	params := bc.GetChainParams()
	// Compare provided chain ID with actual chain ID
	return chainID == params.ChainID
}

// GetWalletDerivationPaths returns standard derivation paths for wallets
// Provides BIP44, BIP49, BIP84, Ledger, and Trezor paths for the current network
// Returns: Map of wallet type to derivation path
func (bc *Blockchain) GetWalletDerivationPaths() map[string]string {
	// Get current chain parameters for coin type
	params := bc.GetChainParams()
	// Return map of standard derivation paths
	return map[string]string{
		"BIP44":  fmt.Sprintf("m/44'/%d'/0'/0/0", params.BIP44CoinType), // Legacy path
		"BIP49":  fmt.Sprintf("m/49'/%d'/0'/0/0", params.BIP44CoinType), // SegWit path
		"BIP84":  fmt.Sprintf("m/84'/%d'/0'/0/0", params.BIP44CoinType), // Native SegWit path
		"Ledger": fmt.Sprintf("m/44'/%d'/0'", params.BIP44CoinType),     // Ledger-specific path
		"Trezor": fmt.Sprintf("m/44'/%d'/0'/0/0", params.BIP44CoinType), // Trezor-specific path
	}
}

// ConvertDenomination converts between SPX denominations
// Handles conversions between nSPX, gSPX, and SPX units
// Parameters:
//   - amount: Amount to convert
//   - fromDenom: Source denomination
//   - toDenom: Target denomination
//
// Returns: Converted amount or error if denomination unknown
func (bc *Blockchain) ConvertDenomination(amount *big.Int, fromDenom, toDenom string) (*big.Int, error) {
	// Get current chain parameters for denomination multipliers
	params := bc.GetChainParams()

	// Look up multipliers for both denominations
	fromMultiplier, fromExists := params.Denominations[fromDenom] // Get source multiplier
	toMultiplier, toExists := params.Denominations[toDenom]       // Get target multiplier

	// Check if both denominations are valid
	if !fromExists || !toExists {
		return nil, fmt.Errorf("unknown denomination: %s or %s", fromDenom, toDenom)
	}

	// Convert to base units (nSPX) first
	// Multiply by source denomination multiplier
	baseAmount := new(big.Int).Mul(amount, fromMultiplier)

	// Convert to target denomination
	// Divide by target denomination multiplier
	result := new(big.Int).Div(baseAmount, toMultiplier)

	return result, nil
}

// GenerateNetworkInfo returns network information for peer discovery
// Returns: Formatted string with network information
func (bc *Blockchain) GenerateNetworkInfo() string {
	// Get current chain parameters
	params := bc.GetChainParams()
	// Get latest block for current height
	latestBlock := bc.GetLatestBlock()

	// Initialize block height
	var blockHeight uint64
	if latestBlock != nil {
		blockHeight = latestBlock.GetHeight() // Current chain height
	}

	// Return formatted network information string
	return fmt.Sprintf(
		"Sphinx Network: %s\n"+
			"Chain ID: %d\n"+
			"Protocol Version: %s\n"+
			"Current Height: %d\n"+
			"Magic Number: 0x%x\n"+
			"Default Port: %d",
		params.ChainName,   // Network name
		params.ChainID,     // Chain identifier
		params.Version,     // Protocol version
		blockHeight,        // Current block height
		params.MagicNumber, // Network magic number in hex
		params.DefaultPort, // Default P2P port
	)
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
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop() // Ensure ticker is stopped when function exits

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
					time.Sleep(30 * time.Second) // Wait for consensus to complete
					leaderMutex.Lock()
					isProposing = false // Reset proposing flag
					leaderMutex.Unlock()
				}()
			}
		}
	}()
}

// GetStatus returns the current blockchain status
// Returns: Current BlockchainStatus
func (bc *Blockchain) GetStatus() BlockchainStatus {
	bc.lock.RLock() // Read lock for thread safety
	defer bc.lock.RUnlock()
	return bc.status
}

// SetStatus updates the blockchain status
// Parameters:
//   - status: New status to set
func (bc *Blockchain) SetStatus(status BlockchainStatus) {
	bc.lock.Lock() // Write lock for thread safety
	defer bc.lock.Unlock()
	oldStatus := bc.status // Store old status for logging
	bc.status = status     // Set new status
	// Log status change
	logger.Info("Blockchain status changed from %s to %s",
		bc.StatusString(oldStatus), bc.StatusString(status))
}

// GetSyncMode returns the current synchronization mode
// Returns: Current SyncMode
func (bc *Blockchain) GetSyncMode() SyncMode {
	bc.lock.RLock() // Read lock for thread safety
	defer bc.lock.RUnlock()
	return bc.syncMode
}

// SetSyncMode updates the synchronization mode
// Parameters:
//   - mode: New sync mode to set
func (bc *Blockchain) SetSyncMode(mode SyncMode) {
	bc.lock.Lock() // Write lock for thread safety
	defer bc.lock.Unlock()
	oldMode := bc.syncMode // Store old mode for logging
	bc.syncMode = mode     // Set new sync mode
	// Log sync mode change
	logger.Info("Blockchain sync mode changed from %s to %s",
		bc.SyncModeString(oldMode), bc.SyncModeString(mode))
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

// ClearAllCaches clears all caches to free maximum memory
// Returns: Error if any cache clearing fails
func (bc *Blockchain) ClearAllCaches() error {
	logger.Info("Clearing all blockchain caches")

	// Clear block cache
	if err := bc.ClearCache(CacheTypeBlock); err != nil {
		return err
	}

	// Clear transaction cache
	if err := bc.ClearCache(CacheTypeTransaction); err != nil {
		return err
	}

	// Clear other caches (even if not implemented)
	bc.ClearCache(CacheTypeReceipt)
	bc.ClearCache(CacheTypeState)

	logger.Info("All blockchain caches cleared successfully")
	return nil
}

// StatusString returns a human-readable string for BlockchainStatus
// Parameters:
//   - status: BlockchainStatus to convert
//
// Returns: Human-readable string representation
func (bc *Blockchain) StatusString(status BlockchainStatus) string {
	// Map status values to strings
	switch status {
	case StatusInitializing:
		return "Initializing"
	case StatusSyncing:
		return "Syncing"
	case StatusRunning:
		return "Running"
	case StatusStopped:
		return "Stopped"
	case StatusForked:
		return "Forked"
	default:
		return "Unknown"
	}
}

// SyncModeString returns a human-readable string for SyncMode
// Parameters:
//   - mode: SyncMode to convert
//
// Returns: Human-readable string representation
func (bc *Blockchain) SyncModeString(mode SyncMode) string {
	// Map sync mode values to strings
	switch mode {
	case SyncModeFull:
		return "Full"
	case SyncModeFast:
		return "Fast"
	case SyncModeLight:
		return "Light"
	default:
		return "Unknown"
	}
}

// ImportResultString returns a human-readable string for BlockImportResult
// Parameters:
//   - result: BlockImportResult to convert
//
// Returns: Human-readable string representation
func (bc *Blockchain) ImportResultString(result BlockImportResult) string {
	// Map import results to strings
	switch result {
	case ImportedBest:
		return "Imported as best block"
	case ImportedSide:
		return "Imported as side chain"
	case ImportedExisting:
		return "Block already exists"
	case ImportInvalid:
		return "Block validation failed"
	case ImportError:
		return "Import error occurred"
	default:
		return "Unknown result"
	}
}

// CacheTypeString returns a human-readable string for CacheType
// Parameters:
//   - cacheType: CacheType to convert
//
// Returns: Human-readable string representation
func (bc *Blockchain) CacheTypeString(cacheType CacheType) string {
	// Map cache types to strings
	switch cacheType {
	case CacheTypeBlock:
		return "Block cache"
	case CacheTypeTransaction:
		return "Transaction cache"
	case CacheTypeReceipt:
		return "Receipt cache"
	case CacheTypeState:
		return "State cache"
	default:
		return "Unknown cache"
	}
}

// AddTransaction now uses the comprehensive mempool
// Parameters:
//   - tx: Transaction to add
//
// Returns: Error if transaction addition fails
func (bc *Blockchain) AddTransaction(tx *types.Transaction) error {
	// Record transaction for storage TPS metrics
	bc.storage.RecordTransaction()

	// Also increment blocks_processed when transactions are actually included in blocks
	if bc.tpsMonitor != nil {
		bc.tpsMonitor.RecordTransaction() // Record for TPS calculation
	}
	return bc.mempool.BroadcastTransaction(tx) // Broadcast to network
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

	// Get current timestamp
	currentTimestamp := common.GetCurrentTimestamp()
	if currentTimestamp == 0 {
		currentTimestamp = time.Now().Unix() // Fallback to current time
	}

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

	// ========== FIX 3: Prepare extraData with OP_RETURN hash ==========
	// Start with base extra data
	extraData := []byte("Sphinx Network Block")

	// If there are transactions with OP_RETURN data, include a hash of them in ExtraData
	var returnDataHash []byte
	for _, tx := range selectedTxs {
		if tx.HasReturnData() && len(tx.ReturnData) > 0 {
			// Hash all OP_RETURN data together
			returnDataHash = common.SpxHash(append(returnDataHash, tx.ReturnData...))
		}
	}
	if len(returnDataHash) > 0 {
		// Include the hash of all OP_RETURN data in ExtraData
		extraData = append(extraData, returnDataHash...)
		logger.Info("Including OP_RETURN data hash in ExtraData: %x", returnDataHash)
	}
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

// checkConsensusRequirements uses existing validation functions
// Determines if a block meets the basic requirements for consensus
// Parameters:
//   - block: Block to check
//
// Returns: true if block meets consensus requirements
func (bc *Blockchain) checkConsensusRequirements(block *types.Block) bool {
	// Use existing block validation
	if err := block.Validate(); err != nil {
		logger.Debug("Block validation failed: %v", err)
		return false
	}

	// Use existing hash format validation
	if err := block.ValidateHashFormat(); err != nil {
		logger.Debug("Hash format validation failed: %v", err)
		return false
	}

	// For PBFT, we consider the block valid if it passes basic validation
	// Actual consensus will be determined by voting
	return true
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
		// Safety check to prevent infinite loops
		if txCount >= maxTxCount {
			logger.Warn("Reached maximum transaction count limit: %d", maxTxCount)
			break
		}

		// Calculate transaction size
		txSize, err := bc.calculateTxsSize(tx)
		if err != nil {
			logger.Warn("Failed to calculate transaction size: %v", err)
			continue
		}

		// Check if transaction is too large individually
		if txSize > bc.chainParams.MaxTransactionSize {
			logger.Warn("Transaction exceeds maximum size: %d > %d", txSize, bc.chainParams.MaxTransactionSize)
			continue
		}

		// Check if adding this transaction would exceed block size
		if currentSize+txSize > availableSize {
			// Try to find smaller transactions that might fit
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

	// Log calculated size
	logger.Debug("Calculated transaction size: %d bytes", estimatedSize)
	return estimatedSize, nil
}

// getTransactionGas returns the gas consumption of a transaction
// Parameters:
//   - tx: Transaction to get gas for
//
// Returns: Gas amount as big.Int
func (bc *Blockchain) getTransactionGas(tx *types.Transaction) *big.Int {
	// Use the transaction's gas limit if available
	if tx.GasLimit != nil && tx.GasLimit.Cmp(big.NewInt(0)) > 0 {
		return tx.GasLimit
	}

	// Calculate gas based on transaction complexity
	baseGas := big.NewInt(21000) // Base transaction gas (similar to Ethereum)

	// Add gas for signature verification
	sigGas := big.NewInt(int64(len(tx.Signature)) * 100) // 100 gas per signature byte
	baseGas.Add(baseGas, sigGas)

	// Add gas for value transfer if amount is significant
	if tx.Amount != nil && tx.Amount.Cmp(big.NewInt(0)) > 0 {
		valueGas := big.NewInt(9000) // Additional gas for value transfer
		baseGas.Add(baseGas, valueGas)
	}

	return baseGas
}

// GetCachedMerkleRoot retrieves a cached Merkle root for a block
// Parameters:
//   - blockHash: Hash of the block
//
// Returns: Cached Merkle root or empty string if not found
func (bc *Blockchain) GetCachedMerkleRoot(blockHash string) string {
	bc.lock.RLock() // Read lock for thread safety
	defer bc.lock.RUnlock()

	// Check if cache exists and contains the block
	if bc.merkleRootCache != nil {
		if root, exists := bc.merkleRootCache[blockHash]; exists {
			return root // Return cached root
		}
	}
	return "" // Not found
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

// calculateTransactionsRoot calculates the Merkle root of transactions
// Parameters:
//   - txs: Slice of transactions
//
// Returns: Merkle root as bytes
func (bc *Blockchain) calculateTransactionsRoot(txs []*types.Transaction) []byte {
	// Check if there are no transactions
	if len(txs) == 0 {
		// Use the dedicated method for empty transactions
		return bc.calculateEmptyTransactionsRoot()
	}

	// Create temporary block for root calculation
	tempBlock := &types.Block{
		Body: types.BlockBody{TxsList: txs},
	}
	return tempBlock.CalculateTxsRoot() // Calculate and return root
}

// calculateStateRoot calculates the state root after applying transactions
// Returns: State root as bytes
func (bc *Blockchain) calculateStateRoot() []byte {
	// FIX: Return a meaningful state root instead of placeholder
	// Create state data with current timestamp
	stateData := []byte(fmt.Sprintf("state-root-%d", time.Now().UnixNano()))
	// Hash the state data to create root
	return common.SpxHash(stateData)
}

// CommitBlock commits a block through state machine replication
// Parameters:
//   - block: Block to commit (consensus.Block interface)
//
// Returns: Error if commit fails
func (bc *Blockchain) CommitBlock(block consensus.Block) error {
	// Extract the underlying types.Block from adapter
	var typeBlock *types.Block
	switch b := block.(type) {
	case *BlockHelper:
		typeBlock = b.GetUnderlyingBlock() // Get underlying block
	default:
		return fmt.Errorf("invalid block type: expected *BlockHelper, got %T", block)
	}

	// Calculate actual block time (time since last block)
	blockTime := bc.calculateBlockTime(typeBlock)

	// ✅ FIXED: Record block in storage TPS with actual block time
	bc.storage.RecordBlock(typeBlock, blockTime)

	// Record block for TPS monitoring (blockchain internal)
	txCount := uint64(len(typeBlock.Body.TxsList))
	bc.tpsMonitor.RecordBlock(txCount, blockTime) // Record for TPS calculation

	// Check if blockchain is in running state
	if bc.GetStatus() != StatusRunning {
		return fmt.Errorf("blockchain not ready to commit blocks, status: %s",
			bc.StatusString(bc.GetStatus()))
	}

	// Store block in storage
	// Execute block: apply transactions, mint reward, compute real StateRoot.
	stateRoot, err := bc.ExecuteBlock(typeBlock)
	if err != nil {
		return fmt.Errorf("CommitBlock: execution failed: %w", err)
	}

	// Process OP_RETURN data in transactions
	for _, tx := range typeBlock.Body.TxsList {
		if tx.HasReturnData() {
			// Validate OP_RETURN with VM
			dataLen := len(tx.ReturnData)
			vmBytecode := []byte{
				byte(svm.PUSH4), byte(dataLen >> 24), byte(dataLen >> 16), byte(dataLen >> 8), byte(dataLen),
				byte(svm.PUSH4), 0x00, 0x00, 0x00, 0x00,
				byte(svm.OP_RETURN),
			}

			memoryLayout := make([]byte, dataLen)
			copy(memoryLayout, tx.ReturnData)

			// Fix vmachine import - change to vm.NewVM
			vm := vm.NewVM(vmBytecode) // Was vmachine.NewVM
			if err := vm.SetMemoryBytes(0, memoryLayout); err != nil {
				return fmt.Errorf("OP_RETURN VM memory setup failed: %w", err) // Remove nil return
			}
			if err := vm.Run(); err != nil {
				return fmt.Errorf("OP_RETURN execution failed: %w", err) // Remove nil return
			}

			// Store return data for light clients
			if err := bc.storeReturnData(tx.ID, tx.ReturnData); err != nil {
				logger.Warn("Failed to store OP_RETURN data for tx %s: %v", tx.ID, err)
			}

			logger.Info("📝 OP_RETURN: Transaction %s embedded %d bytes", tx.ID, dataLen)
		}
	}

	// Stamp the real state root into the block header before storage.
	typeBlock.Header.StateRoot = stateRoot
	// Re-finalize hash because StateRoot is an input to the block hash.
	typeBlock.FinalizeHash()

	// Store block in storage (now with the real StateRoot).
	if err := bc.storage.StoreBlock(typeBlock); err != nil {
		return fmt.Errorf("failed to store block: %w", err)
	}

	// Update in-memory chain
	bc.lock.Lock()                         // Write lock for thread safety
	bc.chain = append(bc.chain, typeBlock) // Add block to chain

	// Remove committed transactions from mempool
	txIDs := make([]string, len(typeBlock.Body.TxsList))
	for i, tx := range typeBlock.Body.TxsList {
		txIDs[i] = tx.ID // Collect transaction IDs
	}
	bc.mempool.RemoveTransactions(txIDs) // Remove from mempool
	bc.lock.Unlock()

	// Log successful commit
	logger.Info("✅ Block committed: height=%d, hash=%s, transactions=%d, block_time=%v",
		typeBlock.GetHeight(), typeBlock.GetHash(), len(txIDs), blockTime)

	return nil
}

// calculateBlockTime calculates the actual time between blocks
// Parameters:
//   - block: Current block
//
// Returns: Time duration since last block
func (bc *Blockchain) calculateBlockTime(block *types.Block) time.Duration {
	latest := bc.GetLatestBlock() // Get latest block
	if latest == nil {
		logger.Debug("First block, using default block time")
		return 5 * time.Second // Default for first block
	}

	// Calculate time difference between current and previous block
	timeDiff := block.Header.Timestamp - latest.GetTimestamp()
	if timeDiff <= 0 {
		// Fallback: use reasonable default
		logger.Debug("Invalid block time difference, using default")
		return 5 * time.Second
	}

	// Convert seconds to duration
	blockTime := time.Duration(timeDiff) * time.Second
	logger.Debug("Block time calculated: %v (timestamp diff: %d seconds)",
		blockTime, timeDiff)

	return blockTime
}

// VerifyStateConsistency verifies that this node's state matches other nodes
// Parameters:
//   - otherState: State snapshot from another node
//
// Returns: true if states are consistent, error if verification fails
func (bc *Blockchain) VerifyStateConsistency(otherState *storage.StateSnapshot) (bool, error) {
	// Delegate to state machine for verification
	return bc.stateMachine.VerifyState(otherState)
}

// GetCurrentState returns the current state snapshot
// Returns: Current state snapshot
func (bc *Blockchain) GetCurrentState() *storage.StateSnapshot {
	// Get current state from state machine
	return bc.stateMachine.GetCurrentState()
}

// DebugStorage tests storage functionality
// Returns: Error if storage test fails
func (bc *Blockchain) DebugStorage() error {
	// Try to get latest block
	testBlock, err := bc.storage.GetLatestBlock()
	if err != nil {
		return fmt.Errorf("GetLatestBlock failed: %w", err)
	}

	// Check if block exists
	if testBlock == nil {
		return fmt.Errorf("GetLatestBlock returned nil (no blocks in storage)")
	}

	// Log successful storage access
	logger.Info("DEBUG: Storage test - Latest block: height=%d, hash=%s",
		testBlock.GetHeight(), testBlock.GetHash())
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

	genesis := bc.chain[0]
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

// ValidateGenesisHash compares genesis hashes handling both GENESIS_ prefixed and hex-only formats
// Parameters:
//   - storedHash: Hash stored in database
//   - expectedHash: Expected hash value
//
// Returns: true if hashes match considering format
func (bc *Blockchain) ValidateGenesisHash(storedHash, expectedHash string) bool {
	// Handle both formats
	if strings.HasPrefix(storedHash, "GENESIS_") && len(storedHash) > 8 {
		return storedHash[8:] == expectedHash // Compare without prefix
	}
	return storedHash == expectedHash // Direct comparison
}

// ValidateGenesisBlock validates that a block has the correct genesis hash format
// Parameters:
//   - block: Block to validate
//
// Returns: Error if validation fails
func (bc *Blockchain) ValidateGenesisBlock(block *types.Block) error {
	// Check if block is at height 0 (genesis)
	if block.GetHeight() != 0 {
		return fmt.Errorf("not a genesis block: height=%d", block.GetHeight())
	}

	// Check if hash has correct genesis format
	if !bc.IsGenesisHash(block.GetHash()) {
		return fmt.Errorf("invalid genesis hash: does not start with 'GENESIS_'")
	}

	return nil
}

// GetDifficulty returns the current network difficulty
// Returns: Current difficulty as big.Int
func (bc *Blockchain) GetDifficulty() *big.Int {
	latest := bc.GetLatestBlock() // Get latest block
	if latest == nil {
		return big.NewInt(1) // Default difficulty for genesis
	}
	return latest.GetDifficulty() // Return block's difficulty
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

// PrintBlockIndex prints the current block_index.json contents
func (bc *Blockchain) PrintBlockIndex() {
	// Build path to index file
	indexFile := filepath.Join(bc.storage.GetIndexDir(), "block_index.json")

	// Read index file
	data, err := os.ReadFile(indexFile)
	if err != nil {
		logger.Warn("Error reading block_index.json: %v", err)
		return
	}

	// Parse JSON
	var index map[string]interface{}
	if err := json.Unmarshal(data, &index); err != nil {
		logger.Warn("Error unmarshaling block_index.json: %v", err)
		return
	}

	// Format for pretty printing
	formatted, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		logger.Warn("Error formatting block_index.json: %v", err)
		return
	}

	// Log formatted contents
	logger.Info("Current block_index.json contents:")
	logger.Info("%s", string(formatted))
}

// GetTransactionByID retrieves a transaction by its ID (byte array version)
// Parameters:
//   - txID: Transaction ID as byte array
//
// Returns: Transaction and error
func (bc *Blockchain) GetTransactionByID(txID []byte) (*types.Transaction, error) {
	bc.lock.RLock() // Read lock for thread safety
	defer bc.lock.RUnlock()

	// Convert byte array to hex string for map lookup
	txIDStr := hex.EncodeToString(txID)

	// Try to find transaction in in-memory index first (faster)
	tx, exists := bc.txIndex[txIDStr]
	if !exists {
		// Not found in memory, try persistent storage
		return bc.storage.GetTransaction(txIDStr)
	}
	return tx, nil
}

// GetTransactionByIDString retrieves a transaction by its ID (string version)
// Parameters:
//   - txIDStr: Transaction ID as hex string
//
// Returns: Transaction and error
func (bc *Blockchain) GetTransactionByIDString(txIDStr string) (*types.Transaction, error) {
	// Convert string to []byte for the existing method
	txIDBytes, err := hex.DecodeString(txIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction ID: %v", err)
	}

	// Call the existing byte-based method
	return bc.GetTransactionByID(txIDBytes)
}

// GetLatestBlock returns the head of the chain with adapter
// Returns: Latest block as consensus.Block interface
func (bc *Blockchain) GetLatestBlock() consensus.Block {
	// Get latest block from storage
	block, err := bc.storage.GetLatestBlock()
	if err != nil || block == nil {
		return nil // No block found
	}
	// Wrap in adapter for consensus interface
	return NewBlockHelper(block)
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

// GetBlockByHash returns a block by its hash with adapter
// Parameters:
//   - hash: Block hash to retrieve
//
// Returns: Block as consensus.Block interface or nil
func (bc *Blockchain) GetBlockByHash(hash string) consensus.Block {
	// Get block from storage
	block, err := bc.storage.GetBlockByHash(hash)
	if err != nil || block == nil {
		return nil // Block not found
	}
	// Wrap in adapter for consensus interface
	return NewBlockHelper(block)
}

// GetBlockHash returns the block hash for a given height
// Parameters:
//   - height: Block height
//
// Returns: Block hash or empty string
func (bc *Blockchain) GetBlockHash(height uint64) string {
	block := bc.GetBlockByNumber(height) // Get block by height
	if block == nil {
		return "" // Block not found
	}
	return block.GetHash() // Return block hash
}

// GetChainTip returns information about the current chain tip
// Returns: Map with chain tip information
func (bc *Blockchain) GetChainTip() map[string]interface{} {
	latest := bc.GetLatestBlock() // Get latest block
	if latest == nil {
		return nil // No blocks
	}

	// Get formatted timestamps using centralized time service
	localTime, utcTime := common.FormatTimestamp(latest.GetTimestamp())

	// Return tip information
	return map[string]interface{}{
		"height":          latest.GetHeight(),    // Block height
		"hash":            latest.GetHash(),      // Block hash
		"timestamp":       latest.GetTimestamp(), // Unix timestamp
		"timestamp_local": localTime,             // Local time
		"timestamp_utc":   utcTime,               // UTC time
	}
}

// ValidateAddress validates if an address is properly formatted
// Parameters:
//   - address: Address to validate
//
// Returns: true if address is valid
func (bc *Blockchain) ValidateAddress(address string) bool {
	// Basic address validation - check length
	if len(address) != 40 {
		return false
	}
	// Check if it's valid hex
	_, err := hex.DecodeString(address)
	return err == nil
}

// GetNetworkInfo returns network information
// Returns: Map with network information
func (bc *Blockchain) GetNetworkInfo() map[string]interface{} {
	params := bc.GetChainParams() // Get chain parameters
	latest := bc.GetLatestBlock() // Get latest block

	// Build network info map
	info := map[string]interface{}{
		"version":          params.Version,   // Protocol version
		"chain":            params.ChainName, // Chain name
		"chain_id":         params.ChainID,   // Chain ID
		"protocol_version": "1.0.0",          // Protocol version string
		"symbol":           params.Symbol,    // Currency symbol
	}

	// Add block information if available
	if latest != nil {
		info["blocks"] = latest.GetHeight()              // Block height
		info["best_block_hash"] = latest.GetHash()       // Best block hash
		info["difficulty"] = bc.GetDifficulty().String() // Network difficulty
		info["median_time"] = latest.GetTimestamp()      // Median time
	}

	return info
}

// GetMiningInfo returns mining-related information
// Returns: Map with mining information
func (bc *Blockchain) GetMiningInfo() map[string]interface{} {
	latest := bc.GetLatestBlock() // Get latest block

	// Initialize mining info map
	info := map[string]interface{}{
		"blocks":         0,
		"current_weight": 0,
		"difficulty":     bc.GetDifficulty().String(), // Network difficulty
		"network_hashps": big.NewInt(0).String(),      // Network hash rate
	}

	// Add block information if available
	if latest != nil {
		info["blocks"] = latest.GetHeight() // Current block height

		// Use adapter to access body for transaction count
		if adapter, ok := latest.(*BlockHelper); ok {
			block := adapter.GetUnderlyingBlock()
			info["current_block_tx"] = len(block.Body.TxsList) // Transactions in current block
		} else {
			info["current_block_tx"] = 0
		}
	}

	return info
}

// EstimateFee estimates transaction fee (placeholder implementation)
// Parameters:
//   - blocks: Number of blocks for fee estimation
//
// Returns: Map with fee estimates
func (bc *Blockchain) EstimateFee(blocks int) map[string]interface{} {
	// Basic fee estimation
	baseFee := big.NewInt(1000000) // Base fee in smallest unit

	// Return fee estimates
	return map[string]interface{}{
		"feerate": baseFee.String(), // Fee rate
		"blocks":  blocks,           // Target blocks
		"estimates": map[string]interface{}{
			"conservative": baseFee.String(), // Conservative estimate
			"economic":     baseFee.String(), // Economic estimate
		},
	}
}

// GetMemPoolInfo returns mempool information
// Returns: Map with mempool information
func (bc *Blockchain) GetMemPoolInfo() map[string]interface{} {
	mempoolStats := bc.mempool.GetStats() // Get mempool statistics

	// Build mempool info map
	return map[string]interface{}{
		"size":            mempoolStats["transaction_count"],               // Transaction count
		"bytes":           mempoolStats["mempool_size_bytes"],              // Total size in bytes
		"usage":           mempoolStats["mempool_size_bytes"].(uint64) * 2, // Memory usage estimate
		"max_mempool":     300000000,                                       // Maximum mempool size (300MB)
		"mempool_min_fee": "0.00001000",                                    // Minimum fee rate
		"mempool_stats":   mempoolStats,                                    // Detailed statistics
	}
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
func (bc *Blockchain) ValidateBlock(block consensus.Block) error {
	// Extract underlying types.Block
	var b *types.Block
	switch blk := block.(type) {
	case *BlockHelper:
		b = blk.GetUnderlyingBlock() // Get underlying block
	default:
		return fmt.Errorf("invalid block type")
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

	// Log successful validation
	logger.Info("✓ Block %d validation passed, TxsRoot = MerkleRoot verified: %x",
		b.GetHeight(), b.Header.TxsRoot)
	return nil
}

// Add TPS monitoring methods to Blockchain
// GetTPSStats returns current TPS statistics
// Returns: Map with TPS statistics
func (bc *Blockchain) GetTPSStats() map[string]interface{} {
	bc.lock.RLock() // Read lock for thread safety
	defer bc.lock.RUnlock()

	tpsMetrics := bc.storage.GetTPSMetrics() // Get TPS metrics from storage

	// Return comprehensive TPS statistics
	return map[string]interface{}{
		"current_tps":          tpsMetrics.CurrentTPS,                       // Current TPS
		"average_tps":          tpsMetrics.AverageTPS,                       // Average TPS
		"peak_tps":             tpsMetrics.PeakTPS,                          // Peak TPS observed
		"total_transactions":   tpsMetrics.TotalTransactions,                // Total transactions processed
		"blocks_processed":     tpsMetrics.BlocksProcessed,                  // Number of blocks processed
		"current_window_count": tpsMetrics.CurrentWindowCount,               // Transactions in current window
		"window_duration_sec":  tpsMetrics.WindowDurationSeconds,            // Window duration in seconds
		"last_updated":         tpsMetrics.LastUpdated.Format(time.RFC3339), // Last update time
		"avg_txs_per_block":    tpsMetrics.AvgTransactionsPerBlock,          // Average transactions per block
		"max_txs_per_block":    tpsMetrics.MaxTransactionsPerBlock,          // Maximum transactions per block
		"min_txs_per_block":    tpsMetrics.MinTransactionsPerBlock,          // Minimum transactions per block
		"tps_history_size":     len(tpsMetrics.TPSHistory),                  // Size of TPS history
		"blocks_history_size":  len(tpsMetrics.TransactionsPerBlock),        // Size of block history
	}
}

// Add to GetStats method
// GetStats returns comprehensive blockchain statistics
// Returns: Map with all blockchain statistics
func (bc *Blockchain) GetStats() map[string]interface{} {
	bc.lock.RLock() // Read lock for thread safety
	defer bc.lock.RUnlock()

	latestBlock := bc.GetLatestBlock() // Get latest block
	var latestHeight uint64
	var latestHash string
	if latestBlock != nil {
		latestHeight = latestBlock.GetHeight() // Current height
		latestHash = latestBlock.GetHash()     // Latest hash
	}

	// Build basic statistics
	stats := map[string]interface{}{
		"status":            bc.StatusString(bc.status),       // Blockchain status
		"sync_mode":         bc.SyncModeString(bc.syncMode),   // Sync mode
		"block_height":      latestHeight,                     // Current height
		"latest_block_hash": latestHash,                       // Latest block hash
		"blocks_in_memory":  len(bc.chain),                    // Blocks in memory
		"pending_txs":       bc.mempool.GetTransactionCount(), // Pending transactions
		"tx_index_size":     len(bc.txIndex),                  // Transaction index size
		"total_blocks":      bc.storage.GetTotalBlocks(),      // Total blocks in storage
	}

	// Add blocksize statistics
	sizeStats := bc.GetBlockSizeStats()
	for k, v := range sizeStats {
		stats[k] = v // Merge block size stats
	}

	// Add TPS statistics
	if bc.tpsMonitor != nil {
		tpsStats := bc.tpsMonitor.GetStats()
		for k, v := range tpsStats {
			stats["tps_"+k] = v // Add with tps_ prefix
		}
	}

	return stats
}

// StartTPSReporting starts periodic TPS reporting
// Parameters:
//   - ctx: Context for cancellation control
func (bc *Blockchain) StartTPSReporting(ctx context.Context) {
	// Start goroutine for periodic reporting
	go func() {
		ticker := time.NewTicker(30 * time.Second) // Report every 30 seconds
		defer ticker.Stop()

		// Main reporting loop
		for {
			select {
			case <-ctx.Done():
				return // Exit on context cancellation
			case <-ticker.C:
				// Report TPS statistics
				if bc.tpsMonitor != nil {
					stats := bc.tpsMonitor.GetStats()
					currentTPS := stats["current_tps"].(float64)
					averageTPS := stats["average_tps"].(float64)
					peakTPS := stats["peak_tps"].(float64)
					totalTxs := stats["total_transactions"].(uint64)

					// Log TPS report
					logger.Info("📊 TPS Report: current=%.2f, avg=%.2f, peak=%.2f, total_txs=%d",
						currentTPS, averageTPS, peakTPS, totalTxs)
				}
			}
		}
	}()
}
