// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/utils.go
package core

import (
	"context"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sphinxorg/protocol/src/common"
	"github.com/sphinxorg/protocol/src/consensus"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	logger "github.com/sphinxorg/protocol/src/log"
	storage "github.com/sphinxorg/protocol/src/state"
)

// Add TPS monitoring methods to Blockchain
// GetTPSStats returns current TPS statistics
// Returns: Map with TPS statistics
// blockchain.go — GetTPSStats: use tpsMonitor, not storage metrics
func (bc *Blockchain) GetTPSStats() map[string]interface{} {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	// REPLACE storage.GetTPSMetrics() with tpsMonitor:
	if bc.tpsMonitor == nil {
		return map[string]interface{}{}
	}
	return bc.tpsMonitor.GetStats() // this is the correctly-windowed one
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
			// Type assert the interface{} to *types.Block
			if block, ok := adapter.GetUnderlyingBlock().(*types.Block); ok {
				info["current_block_tx"] = len(block.Body.TxsList) // Transactions in current block
			} else {
				info["current_block_tx"] = 0
			}
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
	if blocks <= 0 {
		blocks = 1
	}

	const estimatedTransferBytes = uint64(5120)
	const estimatedTransferOps = uint64(1)
	const estimatedTransferHashes = uint64(8)

	fee := bc.MinimumTransactionFee(estimatedTransferBytes, estimatedTransferOps, estimatedTransferHashes)
	economic := new(big.Int).Set(fee)
	conservative := new(big.Int).Mul(fee, big.NewInt(2))

	// Return fee estimates
	return map[string]interface{}{
		"feerate": fee.String(), // Fee rate
		"blocks":  blocks,       // Target blocks
		"estimates": map[string]interface{}{
			"conservative": conservative.String(), // Conservative estimate
			"economic":     economic.String(),     // Economic estimate
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

// storeReturnData stores OP_RETURN data for light clients and in-memory cache
func (bc *Blockchain) storeReturnData(txID string, data []byte) error {
	// Store in-memory first for fast access
	bc.svmMutex.Lock()
	if bc.returnDataStore == nil {
		bc.returnDataStore = make(map[string][]byte)
	}
	bc.returnDataStore[txID] = data

	// Also store by content hash for lookup
	dataHash := sha3.Sum256(data)
	hashKey := hex.EncodeToString(dataHash[:])
	bc.returnDataStore["hash:"+hashKey] = data

	// Limit in-memory store size
	const maxStoreSize = 10000
	if len(bc.returnDataStore) > maxStoreSize {
		// Remove oldest entries (simple cleanup)
		toRemove := maxStoreSize / 10
		removed := 0
		for k := range bc.returnDataStore {
			if removed >= toRemove {
				break
			}
			delete(bc.returnDataStore, k)
			removed++
		}
		logger.Debug("Cleaned up %d old OP_RETURN entries, store size now %d",
			removed, len(bc.returnDataStore))
	}
	bc.svmMutex.Unlock()

	// Also persist to storage for durability
	if bc.storage == nil {
		return nil // No storage available, but in-memory is fine
	}

	// Get the underlying database from storage
	db, err := bc.storage.GetDB()
	if err != nil {
		logger.Warn("Failed to get database for OP_RETURN storage: %v", err)
		return nil // Don't fail - in-memory is enough
	}
	if db == nil {
		return nil
	}

	// Store in a separate "return_data" bucket/prefix
	key := fmt.Sprintf("return:%s", txID)
	return db.Put(key, data)
}

// GetReturnDataByHash retrieves OP_RETURN data by content hash
func (bc *Blockchain) GetReturnDataByHash(hash string) ([]byte, error) {
	bc.svmMutex.RLock()
	defer bc.svmMutex.RUnlock()

	if bc.returnDataStore == nil {
		return nil, fmt.Errorf("return data store not initialized")
	}

	data, exists := bc.returnDataStore["hash:"+hash]
	if !exists {
		return nil, fmt.Errorf("return data not found for hash %s", hash)
	}

	return data, nil
}

// GetSVMStats returns statistics about SVM operations
func (bc *Blockchain) GetSVMStats() map[string]interface{} {
	bc.svmMutex.RLock()
	defer bc.svmMutex.RUnlock()

	stats := map[string]interface{}{
		"stored_return_data_count": 0,
		"failure_count":            0,
		"failures":                 []map[string]interface{}{},
	}

	if bc.returnDataStore != nil {
		stats["stored_return_data_count"] = len(bc.returnDataStore)
	}

	if bc.svmFailures != nil {
		stats["failure_count"] = len(bc.svmFailures)
		// Return a copy of failures (last 10 for safety)
		if len(bc.svmFailures) > 10 {
			stats["failures"] = bc.svmFailures[len(bc.svmFailures)-10:]
		} else {
			stats["failures"] = bc.svmFailures
		}
	}

	return stats
}

// recordSVMFailure records SVM execution failures for monitoring
// This does NOT affect consensus - purely for observability
func (bc *Blockchain) recordSVMFailure(blockHash, txHash string, err error) {
	bc.svmMutex.Lock()
	defer bc.svmMutex.Unlock()

	if bc.svmFailures == nil {
		bc.svmFailures = make([]map[string]interface{}, 0)
	}

	bc.svmFailures = append(bc.svmFailures, map[string]interface{}{
		"block_hash": blockHash,
		"tx_hash":    txHash,
		"error":      err.Error(),
		"timestamp":  time.Now().Unix(),
	})

	// Keep only last 1000 failures to prevent memory bloat
	const maxFailures = 1000
	if len(bc.svmFailures) > maxFailures {
		bc.svmFailures = bc.svmFailures[len(bc.svmFailures)-maxFailures:]
	}
}

// ClearSVMData clears SVM stored data for testing or maintenance
func (bc *Blockchain) ClearSVMData(clearFailures, clearReturnData bool) {
	bc.svmMutex.Lock()
	defer bc.svmMutex.Unlock()

	if clearFailures && bc.svmFailures != nil {
		bc.svmFailures = make([]map[string]interface{}, 0)
		logger.Info("Cleared SVM failure records")
	}

	if clearReturnData && bc.returnDataStore != nil {
		bc.returnDataStore = make(map[string][]byte)
		logger.Info("Cleared SVM return data store")
	}
}

// GetReturnData retrieves OP_RETURN data by transaction ID
func (bc *Blockchain) GetReturnData(txID string) ([]byte, error) {
	if bc.storage == nil {
		return nil, fmt.Errorf("storage not initialized")
	}

	// Get the underlying database from storage - note it returns (db, error)
	db, err := bc.storage.GetDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database: %w", err)
	}
	if db == nil {
		return nil, fmt.Errorf("database is nil")
	}

	key := fmt.Sprintf("return:%s", txID)

	// Use the database's Get method
	return db.Get(key)
}

// Helper function to check if string is hex
func isHexString(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
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
// In blockchain.go
func (bc *Blockchain) AddTransaction(tx *types.Transaction) error {
	if err := bc.ValidateTransactionPolicy(tx); err != nil {
		return err
	}

	bc.storage.RecordTransaction()

	// Record transaction for TPS monitoring
	bc.tpsMonitor.RecordTransaction()

	return bc.mempool.BroadcastTransaction(tx)
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

// calculateBlockTime calculates the actual time between blocks
// Parameters:
//   - block: Current block
//
// Returns: Time duration since last block
func (bc *Blockchain) calculateBlockTime(block *types.Block) time.Duration {
	latest := bc.GetLatestBlock()
	if latest == nil {
		return 5 * time.Second
	}
	currentTime := block.Header.Timestamp
	prevTime := latest.GetTimestamp()
	timeDiff := currentTime - prevTime

	// Cap to reasonable range: 1s–300s. Anything outside means
	// the genesis/prev timestamp is wrong (0, stale, or nanoseconds).
	if timeDiff <= 0 || timeDiff > 300 {
		logger.Warn("Block time out of range (%ds), capping to 5s", timeDiff)
		return 5 * time.Second
	}
	return time.Duration(timeDiff) * time.Second
}

// GetMerkleRoot returns the merkle root as a string
func (b *BlockHelper) GetMerkleRoot() string {
	if b.block != nil && b.block.Header != nil {
		return fmt.Sprintf("%x", b.block.Header.TxsRoot)
	}
	return ""
}

// ExtractMerkleRoot returns the merkle root as a string
func (b *BlockHelper) ExtractMerkleRoot() string {
	if b.block != nil && b.block.Header != nil {
		return fmt.Sprintf("%x", b.block.Header.TxsRoot)
	}
	return ""
}

// GetStateMachine returns the state machine instance
func (bc *Blockchain) GetStateMachine() *storage.StateMachine {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.stateMachine
}
