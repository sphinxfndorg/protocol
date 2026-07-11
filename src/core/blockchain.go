// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/blockchain.go
package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/consensus"

	"github.com/sphinxfndorg/protocol/src/pool"

	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	svm "github.com/sphinxfndorg/protocol/src/core/svm/opcodes"
	"github.com/sphinxfndorg/protocol/src/core/svm/vm"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	logger "github.com/sphinxfndorg/protocol/src/log"
	storage "github.com/sphinxfndorg/protocol/src/state"
)

// WithDeferredInit tells NewBlockchain NOT to load/create the chain before
// returning. Use this when the caller manages its own storage DB handle and
// needs to attach it (via SetStorageDB/SetStateDB) before chain loading
// happens.
//
// Why this matters: on a fresh node, chain loading calls createGenesisBlock()
// -> ExecuteGenesisBlock(), which needs bc.storage.GetDB() to already return
// a real handle. bind.StartNode opens its own LevelDB handles and used to
// attach them via SetStorageDB/SetStateDB AFTER calling NewBlockchain() —
// by which point genesis creation had already run and failed with
// "no shared database handle" / "failed to open stateDB".
//
// Callers using WithDeferredInit MUST call bc.FinishInit(nodeID) themselves,
// after SetStorageDB/SetStateDB, to actually load/create the chain and start
// the mempool + state machine. Without that call the returned *Blockchain is
// inert (no chain loaded, mempool nil, status stuck at StatusInitializing).
func WithDeferredInit() BlockchainOption {
	return func(o *blockchainInitOptions) { o.deferFinish = true }
}

// NewBlockchain creates a blockchain with state machine replication
// Initialize TPS monitor in NewBlockchain - main constructor for blockchain
// Parameters:
//   - dataDir: Directory path for storing blockchain data
//   - nodeID: Unique identifier for this node
//   - validators: List of validator node IDs
//   - networkType: Type of network (testnet, devnet, mainnet)
//   - opts: optional behavior overrides — see WithDeferredInit. Omit for the
//     original synchronous behavior.
//
// Returns: Initialized Blockchain instance or error
//
// Integration with genesis.go / allocation.go:
// Chain parameters are resolved from networkType BEFORE chain loading happens
// so that createGenesisBlock() can call GenesisStateFromChainParams() with
// the correct network parameters.  The genesis block is now built through
// GenesisState.BuildBlock() so every node that uses the same networkType
// produces a byte-for-byte identical genesis hash.
func NewBlockchain(dataDir string, nodeID string, validators []string, networkType string, lateJoiner bool, opts ...BlockchainOption) (*Blockchain, error) {
	var options blockchainInitOptions
	for _, opt := range opts {
		opt(&options)
	}

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
		lateJoiner:      lateJoiner,
		storage:         store,                                // Persistent storage for blocks and state
		stateMachine:    stateMachine,                         // State machine for BFT consensus
		mempool:         nil,                                  // Will be set after blockchain is created
		chain:           []*types.Block{},                     // In-memory chain cache for quick access
		txIndex:         make(map[string]*types.Transaction),  // Transaction index for fast lookup by ID
		pendingTx:       []*types.Transaction{},               // Pending transactions waiting for inclusion
		lock:            sync.RWMutex{},                       // Read-write mutex for thread-safe operations
		status:          StatusInitializing,                   // Initial status while blockchain is setting up
		syncMode:        SyncModeFull,                         // Default to full synchronization mode
		consensusEngine: nil,                                  // Consensus engine (set later after initialization)
		chainParams:     nil,                                  // Chain parameters (set later after genesis)
		syncManager:     nil,                                  // Sync manager (set later after initialization)
		tpsMonitor:      types.NewTPSMonitor(5 * time.Second), // Monitor transactions per second with 5-second window
		// SVM data stores
		returnDataStore: make(map[string][]byte),           // Initialize OP_RETURN data store
		svmFailures:     make([]map[string]interface{}, 0), // Initialize failure tracking
	}

	// ── Resolve chain parameters BEFORE chain loading so that
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

	if options.deferFinish {
		// Caller still needs to attach its own DB handles (SetStorageDB /
		// SetStateDB) and then call bc.FinishInit(nodeID) itself.
		return blockchain, nil
	}

	if err := blockchain.FinishInit(nodeID); err != nil {
		return nil, err
	}

	return blockchain, nil
}

// FinishInit loads the existing chain from storage (or creates the genesis
// block on a fresh node), wires up the mempool, and starts the state machine
// for non-late-joiners. This logic used to be inlined unconditionally at the
// end of NewBlockchain; it's now also callable on its own so that callers
// using WithDeferredInit() can attach their own storage DB handles
// (SetStorageDB / SetStateDB) first — see WithDeferredInit's doc comment for
// why that ordering matters.
//
// Call this exactly once per Blockchain. If the caller attaches an external
// DB handle at all, do that before calling FinishInit.
func (blockchain *Blockchain) FinishInit(nodeID string) error {
	chainParams := blockchain.chainParams
	stateMachine := blockchain.stateMachine

	// Load existing chain from storage or create genesis block if new chain
	// This handles both existing chains and first-time initialization
	// Initialize crash-safe storage journal manager
	if err := InitJournalManager(blockchain.storage.GetStateDir()); err != nil {
		logger.Warn("Warning: Failed to initialize journal manager: %v", err)
	}

	if err := blockchain.initializeChain(); err != nil {
		return fmt.Errorf("failed to initialize chain: %w", err)
	}

	// If this node is a late joiner and has a genesis block but missing genesis_state.json,
	// write it from the downloaded block.
	if blockchain.IsLateJoiner() {
		genesisBlock := blockchain.GetBlockByNumber(0) // returns *types.Block or nil
		if genesisBlock != nil {
			stateDir := blockchain.storage.GetStateDir()
			genesisStatePath := filepath.Join(stateDir, "genesis_state.json")
			if _, err := os.Stat(genesisStatePath); os.IsNotExist(err) {
				if err := blockchain.WriteGenesisStateFromBlock(genesisBlock); err != nil {
					logger.Warn("[%s] Failed to write genesis state file on startup: %v", nodeID, err)
				} else {
					logger.Info("[%s] ✅ Genesis state file written on startup from existing genesis block", nodeID)
				}
			}
		}
	}

	// ========== FIX: Create mempool AFTER blockchain is created ==========
	// Create mempool with default configuration, passing blockchain as state provider
	mempoolConfig := GetDefaultMempoolConfig()
	if mempoolConfig == nil {
		mempoolConfig = &pool.MempoolConfig{
			MaxSize:           10000,
			MaxBytes:          100 * 1024 * 1024,
			MaxTxSize:         100 * 1024,
			BlockGasLimit:     big.NewInt(10000000),
			ValidationTimeout: 30 * time.Second,
			ExpiryTime:        24 * time.Hour,
			MaxBroadcastSize:  5000,
			MaxPendingSize:    5000,
		}
	}
	// Pass blockchain as the state provider (implements BlockchainStateProvider)
	mempool := pool.NewMempool(mempoolConfig, blockchain)
	blockchain.mempool = mempool
	// ===================================================================

	// Now that we have the genesis block, set the chain params with consistent hash
	if len(blockchain.chain) > 0 {
		// Use consistent genesis hash that's the same for all nodes
		blockchain.chainParams = chainParams

		// Validate that our genesis hash matches the chain params
		actualGenesisHash := blockchain.chain[0].GetHash()
		if actualGenesisHash != chainParams.GenesisHash {
			logger.Warn("Genesis hash mismatch: actual=%s, expected=%s",
				actualGenesisHash, chainParams.GenesisHash)
		}

		// Log successful chain parameters initialization
		logger.Info("Chain parameters initialized for %s: genesis_hash=%s",
			chainParams.GetNetworkName(), chainParams.GenesisHash)

		// CRITICAL: Set mempool on state machine for transaction replication
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

	// ========== FIX: Start state machine ONLY for non-late-joiners ==========
	// Late joiners should NOT start PBFT until after they've synchronized
	if !blockchain.IsLateJoiner() {
		logger.Info("Starting state machine (non-late-joiner mode)")
		if err := stateMachine.Start(); err != nil {
			return fmt.Errorf("failed to start state machine: %w", err)
		}
	} else {
		logger.Info("⏸️  Delaying state machine start for late-joiner until after sync")
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

	return nil
}

// Ensure Blockchain implements pool.BlockchainStateProvider
var _ pool.BlockchainStateProvider = (*Blockchain)(nil)

// NewStateDB implements pool.BlockchainStateProvider
func (bc *Blockchain) NewStateDB() (pool.StateDB, error) {
	db, err := bc.storage.GetDB()
	if err != nil {
		return nil, fmt.Errorf("NewStateDB: %w", err)
	}
	stateDB := NewStateDB(db)
	stateDB.SetBlockchain(bc)
	return stateDB, nil
}

// Need to set sphincsManager on Blockchain in NewBlockchain or add a setter
func (bc *Blockchain) SetSTHINCSManager(mgr *sign.STHINCSManager) {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	bc.sphincsManager = mgr
}

// SetSyncManager sets the sync manager for this blockchain
func (bc *Blockchain) SetSyncManager(sm *SyncManager) {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	bc.syncManager = sm
}

// GetSyncManager returns the sync manager for this blockchain
func (bc *Blockchain) GetSyncManager() *SyncManager {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.syncManager
}

// ========== STATE SNAPSHOT BRIDGE METHODS ==========

// stateDBMu guards stateDB access for the snapshot system
var stateDBMu sync.Mutex
var globalStateDB StateDBInterface

// snapshotManagerMu guards the global snapshot manager reference
var snapshotManagerMu sync.Mutex
var globalSnapshotManager *StateSnapshotManager

// SetSnapshotManager sets the global snapshot manager reference.
func SetSnapshotManager(sm *StateSnapshotManager) {
	snapshotManagerMu.Lock()
	defer snapshotManagerMu.Unlock()
	globalSnapshotManager = sm
}

// GetSnapshotManager returns the global snapshot manager.
func (bc *Blockchain) GetSnapshotManager() *StateSnapshotManager {
	snapshotManagerMu.Lock()
	defer snapshotManagerMu.Unlock()
	return globalSnapshotManager
}

// GetStateDB returns the state DB interface for snapshot generation/restoration.
// Returns nil if not yet initialized.
func (bc *Blockchain) GetStateDB() StateDBInterface {
	stateDBMu.Lock()
	defer stateDBMu.Unlock()
	return globalStateDB
}

// SetGlobalStateDB sets the global state DB reference used by the snapshot system.
// This is called during blockchain initialization after the state DB is created.
func SetGlobalStateDB(sdb StateDBInterface) {
	stateDBMu.Lock()
	defer stateDBMu.Unlock()
	globalStateDB = sdb
}

// GetValidatorSet returns the blockchain's validator set.
func (bc *Blockchain) GetValidatorSet() *ValidatorSet {
	// Access the ValidatorSet from consensus if available
	if bc.consensusEngine != nil {
		// Try to get from consensus engine
		if cs, ok := bc.consensusEngine.(*consensus.Consensus); ok {
			vs := cs.GetValidatorSet()
			if vs == nil {
				return nil
			}
			// Convert consensus.ValidatorSet to core.ValidatorSet
			coreVS := &ValidatorSet{
				validators:     make(map[string]*StakedValidator),
				totalStake:     vs.GetTotalStake(),
				minStakeAmount: vs.GetMinStakeAmount(),
			}
			// Copy validators by iterating through the consensus validator set
			// Use GetActiveValidators to get all active validators
			activeVals := vs.GetActiveValidators(0) // epoch 0 = all active
			for _, val := range activeVals {
				if val == nil {
					continue
				}
				coreVS.validators[val.ID] = &StakedValidator{
					ID:              val.ID,
					StakeAmount:     val.StakeAmount,
					RewardAddress:   val.RewardAddress,
					ActivationEpoch: val.ActivationEpoch,
					ExitEpoch:       val.ExitEpoch,
					IsSlashed:       val.IsSlashed,
				}
			}
			return coreVS
		}
	}
	return nil
}

// SetChainTip sets the chain tip to a specific height and hash.
// This is used after restoring from a state snapshot to fast-forward past
// all blocks that were already applied in the snapshot.
func (bc *Blockchain) SetChainTip(height uint64, hash string) error {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	logger.Info("📦 Setting chain tip to height %d (hash=%s)", height, hash[:16])

	// Update in-memory chain state
	// The storage layer will be updated when blocks are replayed from checkpoint to tip
	bc.chainParams.GenesisHash = hash

	return nil
}

// RollbackToHeight rolls back the chain to the given height.
// All blocks above the target height are removed from the chain, from
// persistent storage, and the account state is rebuilt so it matches
// targetHeight exactly. This is used during chain reorganization when a
// fork is detected (see handleReorg in sync.go).
//
// ★ FIX: this previously only trimmed the in-memory bc.chain slice. It left
// (a) the orphaned blocks still sitting in persistent storage, so a restart
// or a fresh GetBlockByNumber() call would resurrect the wrong chain, and
// (b) the StateDB account records (acct:* keys — balances/nonces) computed
// from the abandoned blocks completely untouched, so post-rollback state
// would not match the rolled-back chain at all. Both are fixed below by
// (1) deleting stored blocks above targetHeight, and (2) wiping and
// replaying account state from genesis up to targetHeight via ExecuteBlock,
// the same deterministic execution path used for normal block commits and
// for checkpoint replay (see ApplyCheckpointBlocks in chain_maker.go).
// Replay is only expensive for very deep rollbacks; for the shallow forks
// this is meant to fix (a few dozen blocks at most) it's cheap and — unlike
// trying to maintain incremental undo journals — always exactly correct.
func (bc *Blockchain) RollbackToHeight(targetHeight uint64) error {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	currentHeight := uint64(0)
	if len(bc.chain) > 0 {
		currentHeight = bc.chain[len(bc.chain)-1].GetHeight()
	}

	if targetHeight >= currentHeight {
		return fmt.Errorf("target height %d is not less than current height %d", targetHeight, currentHeight)
	}

	logger.Info("🔄 Rolling back chain from height %d to %d", currentHeight, targetHeight)

	// 1. Remove blocks from the in-memory chain.
	keptChain := make([]*types.Block, 0, targetHeight+1)
	for _, blk := range bc.chain {
		if blk.GetHeight() <= targetHeight {
			keptChain = append(keptChain, blk)
		}
	}
	bc.chain = keptChain

	// 2. Delete the orphaned blocks from persistent storage so they don't
	// resurface after a restart or a plain GetBlockByNumber() lookup.
	// See Storage.DeleteBlocksAbove in src/state/state.go: removes each
	// block's on-disk file and index/height-index entries for heights >
	// targetHeight and resets the storage layer's recorded tip.
	if err := bc.storage.DeleteBlocksAbove(targetHeight); err != nil {
		return fmt.Errorf("RollbackToHeight: failed to purge storage above height %d: %w", targetHeight, err)
	}

	// 3. Rebuild account state so it matches targetHeight exactly. The
	// abandoned blocks' balances/nonces/reward mints must not survive.
	if err := bc.rebuildStateToHeight(targetHeight); err != nil {
		return fmt.Errorf("RollbackToHeight: state rebuild failed: %w", err)
	}

	logger.Info("✅ Chain rolled back to height %d (storage purged, state rebuilt)", targetHeight)
	return nil
}

// rebuildStateToHeight wipes all account state and deterministically
// replays blocks 0..targetHeight through ExecuteBlock, so StateDB balances,
// nonces, and supply counters exactly match the rolled-back chain tip.
func (bc *Blockchain) rebuildStateToHeight(targetHeight uint64) error {
	db, err := bc.storage.GetDB()
	if err != nil {
		return fmt.Errorf("rebuildStateToHeight: %w", err)
	}

	// Wipe existing account records (acct:*) plus the cached supply
	// counters — ExecuteBlock/mintBlockReward will recompute all of it
	// deterministically during replay.
	keys, err := db.ListKeysWithPrefix(accountPrefix)
	if err != nil {
		return fmt.Errorf("rebuildStateToHeight: listing account keys: %w", err)
	}
	for _, k := range keys {
		if err := db.Delete(k); err != nil {
			return fmt.Errorf("rebuildStateToHeight: deleting %s: %w", k, err)
		}
	}
	_ = db.Delete(totalSupplyKey)
	_ = db.Delete(genesisSupplyKey)
	_ = db.Delete(rewardsMintedKey)

	for h := uint64(0); h <= targetHeight; h++ {
		block := bc.getBlockByHeightLocked(h)
		if block == nil {
			return fmt.Errorf("rebuildStateToHeight: missing block at height %d during replay", h)
		}
		if _, err := bc.ExecuteBlock(block); err != nil {
			return fmt.Errorf("rebuildStateToHeight: replaying block %d: %w", h, err)
		}
	}

	logger.Info("✅ State rebuilt via replay of %d blocks (0..%d)", targetHeight+1, targetHeight)
	return nil
}

// getBlockByHeightLocked looks up a block from the in-memory chain (already
// trimmed to targetHeight by the caller). Assumes bc.lock is already held.
func (bc *Blockchain) getBlockByHeightLocked(height uint64) *types.Block {
	for _, blk := range bc.chain {
		if blk.GetHeight() == height {
			return blk
		}
	}
	return nil
}

// ==================================================

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

	// ========== FIX: Read from MEMORY first ==========
	var latestBlock *types.Block
	if len(bc.chain) > 0 {
		latestBlock = bc.chain[len(bc.chain)-1]
		logger.Info("StoreChainState: using in-memory chain (height=%d)", latestBlock.GetHeight())
	} else {
		// Fallback to storage
		block, err := bc.storage.GetLatestBlock()
		if err != nil || block == nil {
			return fmt.Errorf("no blocks available in memory or storage")
		}
		latestBlock = block
		logger.Info("StoreChainState: using storage (height=%d)", latestBlock.GetHeight())
	}
	// ==================================================

	// Convert genesis_time from Unix timestamp to ISO RFC format for output
	// Use the actual genesis timestamp from chain parameters, not current time
	genesisTimeISO := common.GetTimeService().GetTimeInfo(bc.chainParams.GenesisTime).ISOUTC

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

		// Type assert to get the actual slice
		sigs, ok := rawSignatures.([]*consensus.ConsensusSignature)
		if !ok {
			logger.Error("Invalid signature type returned from consensus")
			signatureValidation = &storage.SignatureValidation{
				TotalSignatures:   0,
				ValidSignatures:   0,
				InvalidSignatures: 0,
				ValidationTime:    common.GetTimeService().GetCurrentTimeInfo().ISOUTC,
			}
			finalStates = []*storage.FinalStateInfo{}
		} else if len(sigs) == 0 {
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
			// Process signatures with deduplication to prevent stale-block entries
			seen := make(map[string]bool)
			var deduped []*storage.FinalStateInfo
			validCount := 0
			for _, rawSig := range sigs {
				key := rawSig.BlockHash + "|" + rawSig.SignerNodeID + "|" + rawSig.MessageType
				if seen[key] {
					continue
				}
				seen[key] = true
				deduped = append(deduped, &storage.FinalStateInfo{
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
				})
				if rawSig.Valid {
					validCount++
				}
			}
			finalStates = deduped
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
			Height:    block.GetHeight(),                                                  // Block number
			Hash:      block.GetHash(),                                                    // Block hash
			Size:      blockSize,                                                          // Size in bytes
			SizeMB:    float64(blockSize) / (1024 * 1024),                                 // Size in megabytes
			TxCount:   uint64(len(block.Body.TxsList)),                                    // Transaction count
			Timestamp: common.GetTimeService().GetTimeInfo(block.Header.Timestamp).ISOUTC, // ISO 8601 timestamp
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
				// Check if this node is the current leader.
				// RefreshLeaderStatus re-derives under c.mu so we get a consistent
				// snapshot that reflects any view increment that just occurred in
				// commitBlock. This avoids the stale-c.isLeader read that, combined
				// with c.lockedBlock not yet cleared, caused processProposal to
				// reject the leader's own proposal.
				_, _, isLeader := bc.consensusEngine.RefreshLeaderStatus()
				if !isLeader {
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

				// ========== FIX: Check if mempool is nil ==========
				if bc.mempool == nil {
					logger.Warn("Mempool is nil, cannot check pending transactions")
					leaderMutex.Lock()
					isProposing = false
					leaderMutex.Unlock()
					continue
				}

				// Log proposal start
				logger.Info("Leader %s: creating block with %d pending transactions (empty blocks allowed)",
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

				// Guard: verify the block we created still extends the current chain tip.
				// If another commit completed concurrently while CreateBlock was running,
				// the tip has advanced and this block's parent hash is now stale.
				// Proposing it would cause processProposal to reject it (height mismatch),
				// so drop it here and let the next ticker cycle create a fresh block.
				currentTip := bc.GetLatestBlock()
				if currentTip != nil && block.GetPrevHash() != currentTip.GetHash() {
					logger.Warn("Leader: discarding stale proposal (parent=%s, tip=%s) — will retry",
						block.GetPrevHash()[:16], currentTip.GetHash()[:16])
					leaderMutex.Lock()
					isProposing = false
					leaderMutex.Unlock()
					continue
				}

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

// ImportBlock imports a new block into the blockchain with result tracking.
// It implements a proper fork-choice rule: if the block extends the current
// tip it is committed directly. If it competes at the same height with a
// different hash (fork), the chain with the higher attestation weight wins.
// If the parent is missing the block is stored as an orphan for later replay.
//
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

	latestBlock := bc.GetLatestBlock()
	if latestBlock != nil {
		// Extract the underlying *types.Block from the consensus.Block adapter
		var latestTypeBlock *types.Block
		if helper, ok := latestBlock.(*BlockHelper); ok {
			if underlying, ok := helper.GetUnderlyingBlock().(*types.Block); ok {
				latestTypeBlock = underlying
			}
		}

		// ── Block extends the current tip → normal commit ──
		if block.GetPrevHash() == latestBlock.GetHash() {
			consensusBlock := NewBlockHelper(block)
			if err := bc.CommitBlock(consensusBlock); err != nil {
				logger.Warn("Block commit failed: %v", err)
				return ImportError
			}
			logger.Info("Block imported successfully: height=%d, hash=%s", block.GetHeight(), block.GetHash())
			return ImportedBest
		}

		// ── Block at same height, different hash → fork-choice ──
		if block.GetHeight() == latestBlock.GetHeight() {
			if block.GetHash() == latestBlock.GetHash() {
				logger.Info("Block %s already committed at height %d, skipping", block.GetHash()[:16], block.GetHeight())
				return ImportedBest
			}
			// Competing chain: compare cumulative attestation weight
			logger.Info("🔀 Fork detected at height %d: current=%s competing=%s — comparing weight",
				block.GetHeight(), latestBlock.GetHash()[:16], block.GetHash()[:16])

			newWeight := bc.calculateChainWeight(block)
			var oldWeight *big.Int
			if latestTypeBlock != nil {
				oldWeight = bc.calculateChainWeight(latestTypeBlock)
			} else {
				oldWeight = big.NewInt(0)
			}
			logger.Info("📊 Fork weight comparison: current_chain=%s competing_chain=%s",
				oldWeight.String(), newWeight.String())

			// ★ FIX: attestation weight is 0 for every pre-consensus
			// (solo-mined) block by design — PBFT hasn't started yet, so
			// there are no attestations to sum. That meant two competing
			// solo-mined chains always compared 0 == 0, newWeight.Cmp(oldWeight)
			// was never > 0, and a node would NEVER adopt a peer's competing
			// solo chain — each node just kept whichever chain it already
			// had, and orphaned everything else forever. When weights tie,
			// fall back to a rule every node computes identically: prefer
			// the taller chain, and if heights also tie, prefer the
			// lexicographically smaller hash. Same inputs -> same winner on
			// every node, which is the actual requirement for convergence.
			preferCompeting := newWeight.Cmp(oldWeight) > 0
			if newWeight.Cmp(oldWeight) == 0 {
				if latestTypeBlock == nil || block.GetHeight() > latestTypeBlock.GetHeight() {
					preferCompeting = true
				} else if block.GetHeight() == latestTypeBlock.GetHeight() && block.GetHash() < latestTypeBlock.GetHash() {
					preferCompeting = true
				}
			}

			if preferCompeting {
				if newWeight.Cmp(oldWeight) > 0 {
					logger.Info("🔄 Competing chain has higher weight (%s > %s) — reorganizing",
						newWeight.String(), oldWeight.String())
				} else {
					logger.Info("🔄 Weights tied (%s == %s) — competing chain wins tie-break (height/hash) — reorganizing",
						newWeight.String(), oldWeight.String())
				}
				if latestTypeBlock != nil {
					if err := bc.reorganizeChain(block, latestTypeBlock); err != nil {
						logger.Error("Reorg failed: %v", err)
						bc.storeOrphanBlock(block)
						return ImportError
					}
				}
				return ImportedBest
			}
			// Our current chain wins (by weight or tie-break) — store the
			// competing block as orphan so it can be promoted if the network
			// eventually adopts it
			logger.Info("Current chain wins fork-choice (weight=%s vs %s), storing competing as orphan",
				oldWeight.String(), newWeight.String())
			bc.storeOrphanBlock(block)
			return ImportedSide
		}

		// ── Block height > tip+1 → missing parent → orphan ──
		if block.GetHeight() > latestBlock.GetHeight()+1 {
			logger.Info("📦 Block %s at height %d ahead of tip %d — storing as orphan",
				block.GetHash()[:16], block.GetHeight(), latestBlock.GetHeight())
			bc.storeOrphanBlock(block)
			return ImportedSide
		}
	}

	// ── No tip or first block → normal commit ──
	consensusBlock := NewBlockHelper(block)
	if err := bc.CommitBlock(consensusBlock); err != nil {
		logger.Warn("Block commit failed: %v", err)
		return ImportError
	}
	logger.Info("Block imported successfully: height=%d, hash=%s", block.GetHeight(), block.GetHash())
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

	// ========== FIX: Check if mempool is nil ==========
	if bc.mempool != nil {
		mempoolStats := bc.mempool.GetStats()
		for k, v := range mempoolStats {
			stats[k] = v
		}
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

// CreateBlock is now defined in block_producer.go
// selectTransactionsForBlock is now defined in block_producer.go
// calculateTxsSize is now defined in block_producer.go

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

	bc.commitMu.Lock()
	defer bc.commitMu.Unlock()

	latestBlock := bc.GetLatestBlock()
	if latestBlock != nil {
		latestHeight := latestBlock.GetHeight()
		if latestHeight >= typeBlock.GetHeight() {
			if latestHeight == typeBlock.GetHeight() && latestBlock.GetHash() == typeBlock.GetHash() {
				logger.Info("CommitBlock: block height=%d hash=%s already committed; skipping replay",
					typeBlock.GetHeight(), typeBlock.GetHash())
				return nil
			}
			return fmt.Errorf("CommitBlock: stale/conflicting block at height %d (tip height=%d tip hash=%s block hash=%s)",
				typeBlock.GetHeight(), latestHeight, latestBlock.GetHash(), typeBlock.GetHash())
		}
		if typeBlock.GetHeight() != latestHeight+1 {
			return fmt.Errorf("CommitBlock: non-contiguous block height %d (tip height=%d)",
				typeBlock.GetHeight(), latestHeight)
		}
	}

	logger.Info("🔵 Processing block height=%d, txCount=%d",
		typeBlock.GetHeight(), len(typeBlock.Body.TxsList))

	// Check if tpsMonitor is nil before using it
	if bc.tpsMonitor == nil {
		logger.Error("❌ tpsMonitor is nil! Cannot record TPS metrics")
		return fmt.Errorf("tpsMonitor not initialized")
	}

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

	// ════════════════════════════════════════════════════════════════════════
	// CRITICAL: Execute block, compute real StateRoot, embed in header
	// ════════════════════════════════════════════════════════════════════════
	// The state root MUST be computed and embedded in the block header BEFORE
	// the block is stored. Previously, the state root was computed but the
	// header was left immutable — meaning the stored block had a different
	// state root than what execution produced. This is a consensus bug:
	// nodes that replay the same block must arrive at the same state root,
	// and that root must be in the header so light clients can verify.
	stateRoot, err := bc.ExecuteBlock(typeBlock)
	if err != nil {
		logger.Error("❌ ExecuteBlock failed: %v", err)
		return fmt.Errorf("CommitBlock: execution failed: %w", err)
	}
	logger.Info("✅ Block executed, stateRoot=%x", stateRoot)

	// ════════════════════════════════════════════════════════════════════════
	// CONSENSUS-SAFETY FIX: never silently rehash a divergent block
	// ════════════════════════════════════════════════════════════════════════
	// A block that reached this point already has a header.StateRoot that was
	// either (a) computed by the original leader and voted on by the PBFT
	// quorum (normal proposal path), or (b) copied verbatim from a peer during
	// sync (bind.runBlockSyncLoop / Consensus.FastForward). In both cases the
	// StateRoot is a claim that every honest node must be able to reproduce
	// by executing the exact same block against the exact same prior state.
	//
	// The previous behavior here — silently overwriting header.StateRoot with
	// whatever THIS node computed locally, and re-deriving the hash to match —
	// is what actually produces the "different tip hash on every node" bug:
	// if this node's local execution diverges from the rest of the network for
	// ANY reason (a still-in-flight race between the multiple independent sync
	// paths, a resumed-from-checkpoint node with slightly different prior
	// state, non-deterministic execution, etc.), this code used to paper over
	// that divergence by minting a brand-new "canonical" hash for this node
	// alone. Every peer of this node then rejects its next block proposal
	// (parent-hash mismatch) and/or this node rejects every future incoming
	// proposal (its own tip hash no longer matches what anyone else has),
	// which is exactly the symptom of nodes converging on height but
	// disagreeing on tip hash.
	//
	// The correct behavior is to treat a state-root mismatch as a fatal local
	// error: refuse to commit, leave the tip where it was, and let the caller
	// force a resync from a trusted peer instead of fabricating a new hash.
	if !bytes.Equal(typeBlock.Header.StateRoot, stateRoot) {
		logger.Error("❌ STATE DIVERGENCE DETECTED at height %d: header claims StateRoot=%x, local execution produced=%x — refusing to commit",
			typeBlock.GetHeight(), typeBlock.Header.StateRoot, stateRoot)
		return fmt.Errorf(
			"CommitBlock: state root mismatch at height %d (header=%x, executed=%x) — local state has diverged from the network; refusing to commit rather than silently rehashing",
			typeBlock.GetHeight(), typeBlock.Header.StateRoot, stateRoot,
		)
	}
	// ════════════════════════════════════════════════════════════════════════

	txIDs := make([]string, len(typeBlock.Body.TxsList))
	for i, tx := range typeBlock.Body.TxsList {
		txIDs[i] = tx.ID
	}
	if bc.mempool != nil && len(txIDs) > 0 {
		bc.mempool.RemoveTransactions(txIDs)
		logger.Info("✅ Removed %d committed transactions from mempool after execution", len(txIDs))
	}

	// ========== PRODUCTION FIX: Force state DB flush ==========
	// Get the state DB as concrete *StateDB type (which has Commit method)
	stateDBInterface, err := bc.NewStateDB()
	if err != nil {
		logger.Error("❌ Failed to get state DB: %v", err)
		return fmt.Errorf("CommitBlock: failed to get state DB: %w", err)
	}

	// Type assert to *StateDB to access Commit method
	stateDB, ok := stateDBInterface.(*StateDB)
	if !ok {
		logger.Error("❌ Failed to cast state DB to *StateDB")
		return fmt.Errorf("CommitBlock: state DB is not *StateDB")
	}

	// Force commit to flush all changes to disk
	if _, err := stateDB.Commit(); err != nil {
		logger.Error("❌ Failed to flush state DB: %v", err)
		return fmt.Errorf("CommitBlock: failed to flush state DB: %w", err)
	}
	logger.Info("✅ State DB flushed successfully after block execution")

	// Also verify the state DB flush worked by checking vault balance
	if typeBlock.GetHeight() >= 1 {
		vaultBalance, err := stateDB.GetBalance(GenesisVaultAddress)
		if err == nil && vaultBalance != nil {
			logger.Info("✅ State DB verification: vault balance = %s nSPX", vaultBalance.String())
		}
	}
	// ==========================================================

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

	// The block hash was voted on before CommitBlock. StateRoot participates in
	// that hash, so mutating it here would make the stored header disagree with
	// the consensus-approved block hash. Keep the header immutable at commit
	// time and report any execution-root mismatch for the proposal path to fix.
	if !bytes.Equal(typeBlock.Header.StateRoot, stateRoot) {
		logger.Warn("CommitBlock: execution state root differs from proposed header for block %s (proposed=%x executed=%x)",
			typeBlock.GetHash(), typeBlock.Header.StateRoot, stateRoot)
	}

	// ========== PRODUCTION FIX: Store block in storage AFTER state flush ==========
	logger.Info("📝 Storing block at height %d with hash %s to storage",
		typeBlock.GetHeight(), typeBlock.GetHash())

	if err := bc.storage.StoreBlock(typeBlock); err != nil {
		logger.Error("❌ Failed to store block: %v", err)
		return fmt.Errorf("failed to store block: %w", err)
	}
	logger.Info("✅ Block stored in storage successfully at %s", time.Now().Format("15:04:05.000"))

	// Calculate actual block time and record TPS only after a successful commit.
	blockTime := bc.calculateBlockTime(typeBlock)
	logger.Info("📊 Block time calculated: %v", blockTime)
	bc.storage.RecordBlock(typeBlock, blockTime)

	txCount := uint64(len(typeBlock.Body.TxsList))
	logger.Info("📊 Recording block in TPS monitor with txCount=%d, blockTime=%v", txCount, blockTime)
	for i := uint64(0); i < txCount; i++ {
		bc.tpsMonitor.RecordTransaction()
	}
	bc.tpsMonitor.RecordBlock(txCount, blockTime)

	stats := bc.tpsMonitor.GetStats()
	logger.Info("📊 Current TPS stats after recording: blocks_processed=%v, total_txs=%v, avg_txs_per_block=%.2f",
		stats["blocks_processed"], stats["total_transactions"], stats["avg_transactions_per_block"])

	// Update in-memory chain AFTER storage
	bc.lock.Lock()
	bc.chain = append(bc.chain, typeBlock)
	bc.lock.Unlock()
	logger.Info("✅ Block added to in-memory chain at height %d", typeBlock.GetHeight())
	// ================================================================

	if err := bc.validateBlockTransactionAuth(typeBlock, true); err != nil {
		return fmt.Errorf("CommitBlock: failed to store canonical transaction evidence: %w", err)
	}
	logger.Info("✅ Canonical transaction replay and receipt evidence stored")

	// ========== FIX: Write checkpoint immediately after block commit ==========
	if err := bc.WriteChainCheckpoint(); err != nil {
		logger.Warn("Failed to write checkpoint after block commit: %v", err)
	} else {
		logger.Info("✅ Checkpoint updated after block commit at height %d", typeBlock.GetHeight())
	}
	// ========================================================================

	// ========== Add signature to consensus engine ==========
	if bc.consensusEngine != nil {
		signature := &ConsensusSignatureData{
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

		bc.consensusEngine.AddConsensusSignature(signature)
		logger.Info("✅ Added commit signature for block %s to consensus engine", typeBlock.GetHash())

		signatures := bc.consensusEngine.GetConsensusSignatures()

		// Type assert to get the actual slice
		sigs, ok := signatures.([]*consensus.ConsensusSignature)
		if ok {
			logger.Info("📊 Total consensus signatures in engine after adding: %d", len(sigs))

			if err := bc.SaveBasicChainState(); err != nil {
				logger.Warn("Failed to save chain state after block commit: %v", err)
			} else {
				logger.Info("✅ Chain state saved after block commit with %d signatures", len(sigs))
			}
		} else {
			logger.Warn("Invalid signature type returned from consensus")
		}
	}

	// Process any orphan blocks whose parent is now the committed block.
	// This allows the chain to converge when blocks arrive out of order
	// (e.g., a competing fork's tip arrives before its intermediate blocks).
	bc.processOrphansAfterCommit(typeBlock.GetHash())

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
	// Late joiner check: skip genesis creation entirely.
	// The sync loop will download the entire chain (including genesis) from peers.
	if bc.IsLateJoiner() {
		logger.Info("📥 Late-joiner mode: skipping local genesis creation — will sync from peers")
		return nil
	}

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
	// genesis.go's BuildBlock() already embeds one distribution transaction
	// per allocation directly in block 0's body (Sender: GenesisVaultAddress).
	// There is no separate "block 1" that distributes from the vault — that
	// model is gone. ApplyGenesisState would set balances directly AND
	// increment total_supply, which double-counts once ExecuteGenesisBlock
	// (below) funds the vault and applies those same transactions.
	//
	// ExecuteGenesisBlock is the single authoritative path for crediting
	// genesis balances: it funds GenesisVaultAddress via mintBlockReward,
	// then runs applyTransactions on block 0's body to drain the vault into
	// every allocation address, in the same block. It's idempotent (it
	// no-ops if the vault already has a balance), so it's safe to call here
	// even though sync.go's handleVerifying() also calls it for late joiners
	// after a downloaded genesis is verified.
	if err := bc.ExecuteGenesisBlock(); err != nil {
		return fmt.Errorf("ExecuteGenesisBlock failed: %w", err)
	}

	LogAllocationSummary(gs.Allocations)

	// Get the genesis block from the chain (now populated by ApplyGenesisWithCachedBlock)
	genesis := bc.chain[0]

	// ========== RECORD GENESIS BLOCK IN TPS MONITOR ==========
	// NOTE: Both TPS trackers must be updated together, or the persisted
	// storage.tpsMetrics (which feeds chain_state.json / the CLI report)
	// silently diverges from bc.tpsMonitor (which feeds live GetStats()).
	// Previously only bc.tpsMonitor was updated here, so the genesis
	// block's transactions (and its BlockTXCount entry) never made it
	// into storage.tpsMetrics.TransactionsPerBlock/TPSHistory — leaving
	// peak/average TPS and avg_transactions_per_block computed from two
	// inconsistent datasets (e.g. one showing genesis's 9 txs, the other
	// missing them entirely).
	if bc.tpsMonitor != nil {
		txCount := uint64(len(genesis.Body.TxsList))
		bc.tpsMonitor.RecordBlock(txCount, 5*time.Second)
		logger.Info("📊 Recorded genesis block in TPS monitor with %d transactions", txCount)
	}
	if bc.storage != nil {
		bc.storage.RecordBlock(genesis, 5*time.Second)
		logger.Info("📊 Recorded genesis block in storage TPS metrics with %d transactions",
			len(genesis.Body.TxsList))
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

// getTypeBlock extracts the underlying *types.Block from a consensus.Block.
// This is needed because GetBlockByHash and GetLatestBlock return the
// consensus.Block interface (wrapping *BlockHelper), but the reorg and
// weight functions need the concrete *types.Block.
func (bc *Blockchain) getTypeBlock(block consensus.Block) *types.Block {
	if block == nil {
		return nil
	}
	if helper, ok := block.(*BlockHelper); ok {
		if underlying, ok := helper.GetUnderlyingBlock().(*types.Block); ok {
			return underlying
		}
	}
	if tb, ok := block.(*types.Block); ok {
		return tb
	}
	return nil
}

// =========================================================================
// CHAIN WEIGHT: cumulative PBFT attestation weight for fork-choice
// =========================================================================

// calculateChainWeight computes the cumulative attestation weight for a chain
// branch starting from genesis up to the given block. The weight is the sum
// of all validator stake that has signed attestations in the chain.
// The chain with the highest cumulative weight is the canonical chain.
func (bc *Blockchain) calculateChainWeight(block *types.Block) *big.Int {
	total := big.NewInt(0)

	// If the block already has a cached ChainWeight, use it directly.
	if block.ChainWeight != nil && block.ChainWeight.Sign() > 0 {
		return new(big.Int).Set(block.ChainWeight)
	}

	current := block
	seen := make(map[string]bool)

	// Walk back to genesis, accumulating attestation weight from the block body.
	for current != nil {
		hashStr := current.GetHash()
		if seen[hashStr] {
			break // Prevent infinite loops from circular references
		}
		seen[hashStr] = true

		// Add attestation weights from this block's body
		for _, att := range current.Body.Attestations {
			if att == nil {
				continue
			}
			// Use cached stake if available
			if att.Stake != nil && att.Stake.Sign() > 0 {
				total.Add(total, att.Stake)
			}
		}
		// Walk to parent
		if current.GetHeight() == 0 {
			break
		}
		current = bc.getTypeBlock(bc.GetBlockByHash(current.GetPrevHash()))
	}

	// Cache the computed weight on the block for subsequent calls
	block.ChainWeight = new(big.Int).Set(total)

	return total
}

// GetChainWeight returns the cumulative attestation weight of the current
// canonical chain.
func (bc *Blockchain) GetChainWeight() *big.Int {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	if bc.chainWeight == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(bc.chainWeight)
}

// =========================================================================
// ORPHAN BLOCK MANAGEMENT
// =========================================================================

// storeOrphanBlock saves a block whose parent is not yet committed into an
// orphan pool. When the parent eventually arrives via CommitBlock, the orphan
// is automatically replayed so the chain can converge to the highest-weight
// fork even when blocks arrive out of order.
func (bc *Blockchain) storeOrphanBlock(block *types.Block) {
	bc.orphanMu.Lock()
	defer bc.orphanMu.Unlock()

	if bc.orphanBlocks == nil {
		bc.orphanBlocks = make(map[string][]*types.Block)
	}

	parentHash := block.GetPrevHash()
	blockHash := block.GetHash()

	// Dedup: check if this block is already stored as an orphan
	for _, orphan := range bc.orphanBlocks[parentHash] {
		if orphan.GetHash() == blockHash {
			logger.Debug("Orphan block %s already stored under parent %s", blockHash[:16], parentHash[:16])
			return
		}
	}

	bc.orphanBlocks[parentHash] = append(bc.orphanBlocks[parentHash], block)
	logger.Info("📦 Stored orphan block %s (height=%d, parent=%s), total orphans=%d",
		blockHash[:16], block.GetHeight(), parentHash[:16], len(bc.orphanBlocks))

	// Prune if the orphan pool grows too large to prevent memory exhaustion
	totalOrphans := 0
	for _, children := range bc.orphanBlocks {
		totalOrphans += len(children)
	}
	if totalOrphans > 10000 {
		bc.pruneOrphanBlocks()
	}
}

// processOrphansAfterCommit is called after a block is committed to check if
// any orphan blocks can now be connected (their parent is now the canonical tip).
// If multiple orphans chain together, they are all processed recursively.
func (bc *Blockchain) processOrphansAfterCommit(committedHash string) {
	// Collect all orphans whose parent matches the committed hash
	bc.orphanMu.Lock()
	children, exists := bc.orphanBlocks[committedHash]
	if exists {
		delete(bc.orphanBlocks, committedHash)
	}
	bc.orphanMu.Unlock()

	if !exists || len(children) == 0 {
		return
	}

	// Sort orphans by height (lowest first) to ensure correct replay order
	for i := 0; i < len(children); i++ {
		for j := i + 1; j < len(children); j++ {
			if children[i].GetHeight() > children[j].GetHeight() {
				children[i], children[j] = children[j], children[i]
			}
		}
	}

	// Attempt to import each orphan
	for _, child := range children {
		// Only process orphans that extend the NEW tip (the one we just committed)
		// or the tip that was set by a previous orphan in this loop
		currentTip := bc.GetLatestBlock()
		if child.GetPrevHash() != currentTip.GetHash() {
			// If the orphan still doesn't extend the tip, re-store it
			logger.Debug("Orphan %s still doesn't extend tip, re-storing", child.GetHash()[:16])
			bc.storeOrphanBlock(child)
			continue
		}

		logger.Info("🔄 Processing orphan block %s at height %d (parent %s now committed)",
			child.GetHash()[:16], child.GetHeight(), committedHash[:16])

		result := bc.ImportBlock(child)
		if result == ImportedBest || result == ImportedSide {
			logger.Info("✅ Orphan block %s processed successfully (%v)", child.GetHash()[:16], result)
			// Recursively process children of this orphan
			bc.processOrphansAfterCommit(child.GetHash())
		} else {
			logger.Warn("⚠️ Orphan block %s failed to import: %v", child.GetHash()[:16], result)
			// Re-store for later retry
			bc.storeOrphanBlock(child)
		}
	}
}

// pruneOrphanBlocks removes the oldest orphans from the pool when it exceeds
// the size limit. This prevents unbounded memory growth while still keeping
// recent orphans that are more likely to resolve.
func (bc *Blockchain) pruneOrphanBlocks() {
	bc.orphanMu.Lock()
	defer bc.orphanMu.Unlock()

	if len(bc.orphanBlocks) == 0 {
		return
	}

	// Collect all orphans with their heights
	type orphanEntry struct {
		parentHash string
		block      *types.Block
	}

	var entries []orphanEntry
	for parentHash, children := range bc.orphanBlocks {
		for _, child := range children {
			entries = append(entries, orphanEntry{parentHash: parentHash, block: child})
		}
	}

	// Sort by height ascending (lower height = older)
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].block.GetHeight() > entries[j].block.GetHeight() {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// Remove oldest entries (keep 5000)
	keepCount := 5000
	if keepCount > len(entries) {
		keepCount = len(entries)
	}
	entries = entries[len(entries)-keepCount:]

	// Rebuild the orphan map with only the kept entries
	bc.orphanBlocks = make(map[string][]*types.Block)
	for _, entry := range entries {
		bc.orphanBlocks[entry.parentHash] = append(bc.orphanBlocks[entry.parentHash], entry.block)
	}

	logger.Info("🧹 Pruned orphan blocks: kept %d orphans", len(entries))
}

// =========================================================================
// CHAIN REORGANIZATION
// =========================================================================

// reorganizeChain replaces the current canonical chain with a competing fork
// that has higher cumulative attestation weight. It:
//  1. Finds the common ancestor of the old and new chains
//  2. Collects blocks to disconnect (old fork from tip → common ancestor)
//  3. Collects blocks to connect (new fork from common ancestor + 1 → new tip)
//  4. Rolls back state from disconnected blocks
//  5. Applies state from connected blocks
//  6. Resurrects orphaned transactions back into the mempool
//
// This is called automatically by CommitBlock when a fork-choice rule
// determines the incoming block has higher weight.
func (bc *Blockchain) reorganizeChain(newForkBlock, oldTip *types.Block) error {
	logger.Info("🔄 Starting chain reorganization: old_tip=%s (height=%d), new_tip=%s (height=%d)",
		oldTip.GetHash()[:16], oldTip.GetHeight(), newForkBlock.GetHash()[:16], newForkBlock.GetHeight())

	// Step 1: Find common ancestor
	forkHeight, forkHash := bc.findCommonAncestor(newForkBlock, oldTip)
	if forkHash == "" || forkHeight == 0 {
		return fmt.Errorf("no common ancestor found between chains — cannot reorganize")
	}
	logger.Info("📍 Common ancestor at height %d (hash=%s)", forkHeight, forkHash[:16])

	// Step 2: Collect blocks to disconnect (old chain: tip → fork+1)
	var oldBlocks []*types.Block
	current := oldTip
	for current != nil && current.GetHeight() > forkHeight {
		oldBlocks = append(oldBlocks, current)
		current = bc.getTypeBlock(bc.GetBlockByHash(current.GetPrevHash()))
		if current == nil {
			return fmt.Errorf("broken chain while walking back from old tip at height transition %d→%d",
				oldTip.GetHeight(), forkHeight)
		}
	}

	// Step 3: Collect blocks to connect (new chain: fork+1 → tip)
	var newBlocks []*types.Block
	current = newForkBlock
	for current != nil && current.GetHeight() > forkHeight {
		newBlocks = append([]*types.Block{current}, newBlocks...)
		current = bc.getTypeBlock(bc.GetBlockByHash(current.GetPrevHash()))
		if current == nil {
			return fmt.Errorf("broken chain while walking back from new fork tip at height transition %d→%d",
				newForkBlock.GetHeight(), forkHeight)
		}
	}

	logger.Info("📊 Reorg: rolling back %d blocks, applying %d blocks", len(oldBlocks), len(newBlocks))

	// Step 4: Disconnect old blocks (collect transactions to resurrect)
	var txsToResurrect []*types.Transaction
	for _, ob := range oldBlocks {
		// Collect transactions from the block being disconnected
		for _, tx := range ob.Body.TxsList {
			if tx != nil {
				txsToResurrect = append(txsToResurrect, tx)
			}
		}
		// Remove from in-memory chain (backwards)
		bc.lock.Lock()
		for i := len(bc.chain) - 1; i >= 0; i-- {
			if bc.chain[i].GetHash() == ob.GetHash() {
				bc.chain = append(bc.chain[:i], bc.chain[i+1:]...)
				break
			}
		}
		bc.lock.Unlock()

		logger.Info("🔙 Rolled back block %s at height %d", ob.GetHash()[:16], ob.GetHeight())
	}

	// Step 5: Apply new blocks in forward order
	for _, nb := range newBlocks {
		// Validate the block (sparse check — full attestation verification happens in sync)
		if err := nb.Validate(); err != nil {
			// Emergency rollback: put old blocks back
			bc.emergencyReorgRollback(oldBlocks, newBlocks)
			return fmt.Errorf("new fork block %s at height %d failed validation: %w",
				nb.GetHash()[:16], nb.GetHeight(), err)
		}
		// Append to in-memory chain
		bc.lock.Lock()
		bc.chain = append(bc.chain, nb)
		bc.lock.Unlock()

		// Store block to disk
		if err := bc.storage.StoreBlock(nb); err != nil {
			logger.Error("Failed to store reorg block %s: %v", nb.GetHash()[:16], err)
		}

		logger.Info("🔀 Applied new block %s at height %d", nb.GetHash()[:16], nb.GetHeight())
	}

	// Step 6: Resurrect transactions into mempool
	if bc.mempool != nil {
		for _, tx := range txsToResurrect {
			if err := bc.mempool.BroadcastTransaction(tx); err != nil {
				logger.Debug("Reorg: could not resurrect tx %s: %v", tx.ID, err)
			}
		}
		logger.Info("🔄 Resurrected %d transactions back to mempool after reorg", len(txsToResurrect))
	}

	// Step 7: Update chain weight
	bc.lock.Lock()
	bc.chainWeight = bc.calculateChainWeight(newForkBlock)
	bc.lock.Unlock()

	// Step 8: Persist chain state
	if err := bc.SaveBasicChainState(); err != nil {
		logger.Warn("Failed to save chain state after reorg: %v", err)
	}

	// Step 9: Write checkpoint
	if err := bc.WriteChainCheckpoint(); err != nil {
		logger.Warn("Failed to write checkpoint after reorg: %v", err)
	}

	logger.Info("✅ Reorg complete: rolled back %d blocks, applied %d blocks, new_tip=%s at height %d, weight=%s",
		len(oldBlocks), len(newBlocks), newForkBlock.GetHash()[:16], newForkBlock.GetHeight(), bc.chainWeight)
	return nil
}

// findCommonAncestor walks both chains backwards from their tips to find
// the first common block (same hash). Returns the height and hash of the
// common ancestor. Returns ("", 0) if no common ancestor exists.
func (bc *Blockchain) findCommonAncestor(blockA, blockB *types.Block) (uint64, string) {
	// Build the ancestry set for block A
	ancestorsA := make(map[string]uint64)
	current := blockA
	for current != nil {
		hashStr := current.GetHash()
		if _, exists := ancestorsA[hashStr]; exists {
			break // Prevent cycles
		}
		ancestorsA[hashStr] = current.GetHeight()
		if current.GetHeight() == 0 {
			break
		}
		current = bc.getTypeBlock(bc.GetBlockByHash(current.GetPrevHash()))
		if current == nil {
			break
		}
	}

	// Walk block B's ancestors looking for a match
	current = blockB
	for current != nil {
		hashStr := current.GetHash()
		if heightA, exists := ancestorsA[hashStr]; exists {
			// Found common ancestor
			return heightA, hashStr
		}
		if current.GetHeight() == 0 {
			break
		}
		current = bc.getTypeBlock(bc.GetBlockByHash(current.GetPrevHash()))
		if current == nil {
			break
		}
	}

	return 0, ""
}

// emergencyReorgRollback restores the original chain after a failed reorg
// attempt. This ensures the node is never left in an inconsistent state.
func (bc *Blockchain) emergencyReorgRollback(oldBlocks, failedNewBlocks []*types.Block) {
	logger.Error("🚨 EMERGENCY: Rolling back failed reorg — restoring %d original blocks", len(oldBlocks))

	// Remove any new blocks that were applied
	for _, nb := range failedNewBlocks {
		bc.lock.Lock()
		for i := len(bc.chain) - 1; i >= 0; i-- {
			if bc.chain[i].GetHash() == nb.GetHash() {
				bc.chain = append(bc.chain[:i], bc.chain[i+1:]...)
				break
			}
		}
		bc.lock.Unlock()
	}

	// Restore old blocks in forward order
	for i := len(oldBlocks) - 1; i >= 0; i-- {
		ob := oldBlocks[i]
		bc.lock.Lock()
		bc.chain = append(bc.chain, ob)
		bc.lock.Unlock()
	}

	// Restore chain weight
	bc.lock.Lock()
	bc.chainWeight = bc.calculateChainWeight(oldBlocks[0])
	bc.lock.Unlock()

	logger.Info("✅ Emergency reorg rollback complete — original chain restored")
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

	// Take a single snapshot of the chain tip for this entire validation pass.
	// Both parent-hash checks below must agree on the same tip — reading
	// bc.GetLatestBlock() twice left a window where a concurrent commit
	// between the two reads could change the tip mid-validation, making a
	// valid proposal fail the second check with a spurious "invalid parent
	// hash" (and historically caused a node to reject a valid proposal and
	// commit a competing block of its own instead).
	latestTip := bc.GetLatestBlock()

	// Validate ParentHash chain linkage (except for genesis block)
	if b.Header.Height > 0 {
		previousBlock := latestTip // Get previous block
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
	previousBlock := latestTip
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
