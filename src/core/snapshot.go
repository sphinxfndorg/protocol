// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/snapshot.go
//
// ========== STATE SNAPSHOT SYNC (Phase B+C) ==========
// Checkpoint-based state sync for late joiners.
//
// Instead of replaying every block from genesis, a late joiner can:
//  1. Download the latest validator-signed checkpoint
//  2. Download the full state snapshot at that checkpoint
//  3. Restore accounts and validator set from the snapshot
//  4. Only replay blocks from the checkpoint to the tip
//
// Checkpoints are generated every CHECKPOINT_INTERVAL blocks (10,000).
// State snapshots are stored as compressed JSON files in the state directory.
// ======================================================

package core

import (
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"time"

	logger "github.com/sphinxfndorg/protocol/src/console"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
)

// ========== CONSTANTS ==========

// CheckpointInterval is the number of blocks between checkpoints.
// Every CHECKPOINT_INTERVAL blocks, a state snapshot is generated.
const CheckpointInterval uint64 = 10000

// StateSnapshotVersion is the version of the snapshot format.
const StateSnapshotVersion = 1

// NewStateSnapshotManager creates a new state snapshot manager.
func NewStateSnapshotManager(bc *Blockchain, dataDir string) *StateSnapshotManager {
	snapshotsDir := filepath.Join(dataDir, "snapshots")
	if err := os.MkdirAll(snapshotsDir, 0755); err != nil {
		logger.Warn("Failed to create snapshots directory: %v", err)
	}

	sm := &StateSnapshotManager{
		bc:            bc,
		snapshotsDir:  snapshotsDir,
		snapshotIndex: make(map[uint64]*StateSnapshotHeader),
		checkpoints:   make(map[uint64]*CheckpointMessage),
	}

	sm.loadSnapshotIndex()
	return sm
}

// GetSnapshotsDir returns the snapshots directory path.
func (sm *StateSnapshotManager) GetSnapshotsDir() string {
	return sm.snapshotsDir
}

// GetLatestCheckpoint returns the latest checkpoint, or nil.
func (sm *StateSnapshotManager) GetLatestCheckpoint() *CheckpointMessage {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var latestHeight uint64
	var latest *CheckpointMessage
	for height, cp := range sm.checkpoints {
		if height > latestHeight {
			latestHeight = height
			latest = cp
		}
	}
	return latest
}

// GetCheckpointAtHeight returns the checkpoint at the given height, or nil.
func (sm *StateSnapshotManager) GetCheckpointAtHeight(height uint64) *CheckpointMessage {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.checkpoints[height]
}

// GetAllCheckpoints returns all known checkpoints sorted by height.
func (sm *StateSnapshotManager) GetAllCheckpoints() []*CheckpointMessage {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var heights []uint64
	for h := range sm.checkpoints {
		heights = append(heights, h)
	}
	sort.Slice(heights, func(i, j int) bool { return heights[i] < heights[j] })

	result := make([]*CheckpointMessage, len(heights))
	for i, h := range heights {
		result[i] = sm.checkpoints[h]
	}
	return result
}

// AddCheckpointFromPeer stores a checkpoint received from a peer.
func (sm *StateSnapshotManager) AddCheckpointFromPeer(cp *CheckpointMessage) bool {
	if cp == nil {
		return false
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	existing, exists := sm.checkpoints[cp.BlockHeight]
	if !exists || existing.Timestamp < cp.Timestamp {
		sm.checkpoints[cp.BlockHeight] = cp
		logger.Info("📥 Stored checkpoint from peer at height %d (hash=%s)",
			cp.BlockHeight, cp.BlockHash[:16])
		return true
	}
	return false
}

// ========== SNAPSHOT GENERATION ==========

// ShouldGenerateSnapshot checks if a snapshot should be generated at the given height.
func ShouldGenerateSnapshot(height uint64) bool {
	if height == 0 {
		return false
	}
	return height%CheckpointInterval == 0
}

// GenerateSnapshot creates a state snapshot at the current chain tip.
func (sm *StateSnapshotManager) GenerateSnapshot(height uint64) (*StateSnapshotHeader, error) {
	logger.Info("📸 Generating state snapshot at height %d...", height)

	block := sm.bc.GetBlockByNumber(height)
	if block == nil {
		return nil, fmt.Errorf("block at height %d not found", height)
	}

	stateRoot := hex.EncodeToString(block.Header.StateRoot)
	blockHash := block.GetHash()

	// Collect accounts from the state DB
	accounts := make(map[string]*SnapshotAccount)
	if err := sm.collectAccounts(accounts); err != nil {
		return nil, fmt.Errorf("failed to collect accounts: %w", err)
	}

	// Collect validators
	validators := make(map[string]*SnapshotValidator)
	if err := sm.collectValidators(validators); err != nil {
		return nil, fmt.Errorf("failed to collect validators: %w", err)
	}

	totalSupply := sm.calculateTotalSupply(accounts)
	now := time.Now().UTC().Format(time.RFC3339)

	snapshotData := &StateSnapshotData{
		Version:     StateSnapshotVersion,
		BlockHeight: height,
		BlockHash:   blockHash,
		StateRoot:   stateRoot,
		Accounts:    accounts,
		Validators:  validators,
		TotalSupply: totalSupply,
		Timestamp:   now,
	}

	snapshotFile, fileSize, err := sm.writeSnapshot(snapshotData)
	if err != nil {
		return nil, fmt.Errorf("failed to write snapshot: %w", err)
	}

	header := &StateSnapshotHeader{
		Version:         StateSnapshotVersion,
		BlockHeight:     height,
		BlockHash:       blockHash,
		StateRoot:       stateRoot,
		Epoch:           height / 100,
		TotalAccounts:   len(accounts),
		TotalValidators: len(validators),
		TotalSupply:     totalSupply,
		Timestamp:       now,
		FileSize:        fileSize,
		SnapshotFile:    snapshotFile,
	}

	sm.mu.Lock()
	sm.snapshotIndex[height] = header
	sm.latestSnapshot = header
	sm.mu.Unlock()

	if err := sm.saveSnapshotIndex(); err != nil {
		logger.Warn("Failed to save snapshot index: %v", err)
	}

	cp := &CheckpointMessage{
		BlockHeight: height,
		BlockHash:   blockHash,
		StateRoot:   stateRoot,
		Epoch:       height / 100,
		Signatures:  make(map[string]string),
		Timestamp:   time.Now().Unix(),
	}

	sm.mu.Lock()
	sm.checkpoints[height] = cp
	sm.mu.Unlock()

	logger.Info("SUCCESS State snapshot generated at height %d: %d accounts, %d validators, %s SPX total, %s (%d MB)",
		height, len(accounts), len(validators),
		formatSPX(totalSupply), snapshotFile, fileSize/(1024*1024))

	return header, nil
}

// collectAccounts reads all accounts from the state DB into the snapshot.
func (sm *StateSnapshotManager) collectAccounts(accounts map[string]*SnapshotAccount) error {
	// Access the state DB through the blockchain's storage layer
	// Use the state DB helper from the core package
	stateDB := sm.bc.GetStateDB()
	if stateDB != nil {
		// Read pending accounts from the state DB's in-memory cache
		stateDB.IterateAccounts(func(addr string, balance *big.Int, nonce uint64) {
			accounts[addr] = &SnapshotAccount{
				BalanceNSPX: balance.String(),
				Nonce:       nonce,
			}
		})
	}

	if len(accounts) == 0 {
		logger.Warn("No accounts found in state DB for snapshot — chain may be empty")
	}

	return nil
}

// collectValidators reads the current validator set into the snapshot.
func (sm *StateSnapshotManager) collectValidators(validators map[string]*SnapshotValidator) error {
	vs := sm.bc.GetValidatorSet()
	if vs == nil {
		logger.Warn("No validator set available for snapshot")
		return nil
	}

	vs.mu.RLock()
	defer vs.mu.RUnlock()

	for id, v := range vs.validators {
		validators[id] = &SnapshotValidator{
			StakeNSPX:       v.StakeAmount.String(),
			RewardAddress:   v.RewardAddress,
			ActivationEpoch: v.ActivationEpoch,
			ExitEpoch:       v.ExitEpoch,
			IsSlashed:       v.IsSlashed,
		}
	}

	return nil
}

// calculateTotalSupply sums all account balances.
func (sm *StateSnapshotManager) calculateTotalSupply(accounts map[string]*SnapshotAccount) string {
	total := big.NewInt(0)
	for _, acct := range accounts {
		bal, ok := new(big.Int).SetString(acct.BalanceNSPX, 10)
		if ok {
			total.Add(total, bal)
		}
	}
	return total.String()
}

// writeSnapshot serializes and compresses the snapshot data to disk.
func (sm *StateSnapshotManager) writeSnapshot(data *StateSnapshotData) (string, int64, error) {
	filename := fmt.Sprintf("snapshot_%d.json.gz", data.BlockHeight)
	path := filepath.Join(sm.snapshotsDir, filename)

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", 0, fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return "", 0, fmt.Errorf("failed to create snapshot file: %w", err)
	}
	defer f.Close()

	gzWriter, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return "", 0, fmt.Errorf("failed to create gzip writer: %w", err)
	}
	defer gzWriter.Close()

	if _, err := gzWriter.Write(jsonData); err != nil {
		return "", 0, fmt.Errorf("failed to write compressed snapshot: %w", err)
	}

	if err := gzWriter.Close(); err != nil {
		return "", 0, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", 0, fmt.Errorf("failed to stat snapshot file: %w", err)
	}

	return filename, info.Size(), nil
}

// ========== SNAPSHOT RESTORATION ==========

// RestoreFromSnapshot restores the blockchain state from a snapshot at the given height.
func (sm *StateSnapshotManager) RestoreFromSnapshot(height uint64) error {
	logger.Info("INFO Restoring from state snapshot at height %d...", height)

	snapshot, err := sm.LoadSnapshot(height)
	if err != nil {
		return fmt.Errorf("failed to load snapshot at height %d: %w", height, err)
	}

	logger.Info("INFO Snapshot state root: %s", snapshot.StateRoot[:16])

	if err := sm.restoreAccounts(snapshot); err != nil {
		return fmt.Errorf("failed to restore accounts: %w", err)
	}

	if err := sm.restoreValidators(snapshot); err != nil {
		return fmt.Errorf("failed to restore validators: %w", err)
	}

	if err := sm.bc.SetChainTip(snapshot.BlockHeight, snapshot.BlockHash); err != nil {
		return fmt.Errorf("failed to set chain tip: %w", err)
	}

	logger.Info("SUCCESS State restored from snapshot at height %d: %d accounts, %d validators, %s SPX total",
		height, len(snapshot.Accounts), len(snapshot.Validators),
		formatSPX(snapshot.TotalSupply))

	return nil
}

// LoadSnapshot loads and decompresses a snapshot from disk.
func (sm *StateSnapshotManager) LoadSnapshot(height uint64) (*StateSnapshotData, error) {
	filename := fmt.Sprintf("snapshot_%d.json.gz", height)
	path := filepath.Join(sm.snapshotsDir, filename)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("snapshot file not found: %s", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open snapshot file: %w", err)
	}
	defer f.Close()

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	var data StateSnapshotData
	decoder := json.NewDecoder(gzReader)
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode snapshot: %w", err)
	}

	return &data, nil
}

// restoreAccounts writes all accounts from the snapshot into the state DB.
func (sm *StateSnapshotManager) restoreAccounts(snapshot *StateSnapshotData) error {
	stateDB := sm.bc.GetStateDB()
	if stateDB == nil {
		return fmt.Errorf("state DB not available")
	}

	for addr, acct := range snapshot.Accounts {
		balance, ok := new(big.Int).SetString(acct.BalanceNSPX, 10)
		if !ok {
			logger.Warn("Failed to parse balance for account %s: %s", addr, acct.BalanceNSPX)
			continue
		}
		stateDB.SetBalance(addr, balance)
		stateDB.SetNonce(addr, acct.Nonce)
	}

	logger.Info("INFO Restored %d accounts to state DB", len(snapshot.Accounts))
	return nil
}

// restoreValidators writes all validators from the snapshot into the validator set.
func (sm *StateSnapshotManager) restoreValidators(snapshot *StateSnapshotData) error {
	vs := sm.bc.GetValidatorSet()
	if vs == nil {
		logger.Warn("No validator set available — cannot restore validators")
		return nil
	}

	vs.mu.Lock()
	defer vs.mu.Unlock()

	vs.validators = make(map[string]*StakedValidator)
	vs.totalStake = big.NewInt(0)

	for id, val := range snapshot.Validators {
		stake, ok := new(big.Int).SetString(val.StakeNSPX, 10)
		if !ok {
			logger.Warn("Failed to parse stake for validator %s: %s", id, val.StakeNSPX)
			continue
		}

		vs.validators[id] = &StakedValidator{
			ID:              id,
			StakeAmount:     stake,
			RewardAddress:   val.RewardAddress,
			ActivationEpoch: val.ActivationEpoch,
			ExitEpoch:       val.ExitEpoch,
			IsSlashed:       val.IsSlashed,
		}
		vs.totalStake.Add(vs.totalStake, stake)
	}

	logger.Info("INFO Restored %d validators to validator set", len(snapshot.Validators))
	return nil
}

// ========== SNAPSHOT INDEX MANAGEMENT ==========

func (sm *StateSnapshotManager) loadSnapshotIndex() {
	indexFile := filepath.Join(sm.snapshotsDir, "snapshot_index.json")
	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		return
	}

	data, err := os.ReadFile(indexFile)
	if err != nil {
		logger.Warn("Failed to read snapshot index: %v", err)
		return
	}

	var headers []*StateSnapshotHeader
	if err := json.Unmarshal(data, &headers); err != nil {
		logger.Warn("Failed to unmarshal snapshot index: %v", err)
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, h := range headers {
		sm.snapshotIndex[h.BlockHeight] = h
		if sm.latestSnapshot == nil || h.BlockHeight > sm.latestSnapshot.BlockHeight {
			sm.latestSnapshot = h
		}
	}

	logger.Info("📸 Loaded %d snapshot headers from index (latest: height %d)",
		len(headers), sm.latestSnapshot.BlockHeight)
}

func (sm *StateSnapshotManager) saveSnapshotIndex() error {
	sm.mu.RLock()
	headers := make([]*StateSnapshotHeader, 0, len(sm.snapshotIndex))
	for _, h := range sm.snapshotIndex {
		headers = append(headers, h)
	}
	sm.mu.RUnlock()

	sort.Slice(headers, func(i, j int) bool {
		return headers[i].BlockHeight < headers[j].BlockHeight
	})

	indexFile := filepath.Join(sm.snapshotsDir, "snapshot_index.json")
	data, err := json.MarshalIndent(headers, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot index: %w", err)
	}

	tmpFile := indexFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write snapshot index: %w", err)
	}

	return os.Rename(tmpFile, indexFile)
}

// GetLatestSnapshotHeader returns the header of the most recent snapshot.
func (sm *StateSnapshotManager) GetLatestSnapshotHeader() *StateSnapshotHeader {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.latestSnapshot
}

// GetSnapshotHeaderAtHeight returns the snapshot header at the given height.
func (sm *StateSnapshotManager) GetSnapshotHeaderAtHeight(height uint64) *StateSnapshotHeader {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.snapshotIndex[height]
}

// StoreReceivedSnapshot stores a snapshot received from a peer to disk.
// This is used by the P2P message handler when a "snapshot" message arrives.
func (sm *StateSnapshotManager) StoreReceivedSnapshot(data *StateSnapshotData) error {
	if data == nil {
		return fmt.Errorf("snapshot data is nil")
	}

	logger.Info("📥 Storing received snapshot at height %d (%d accounts, %d validators)",
		data.BlockHeight, len(data.Accounts), len(data.Validators))

	// Write snapshot to disk
	snapshotFile, fileSize, err := sm.writeSnapshot(data)
	if err != nil {
		return fmt.Errorf("failed to write received snapshot: %w", err)
	}

	// Build header
	header := &StateSnapshotHeader{
		Version:         StateSnapshotVersion,
		BlockHeight:     data.BlockHeight,
		BlockHash:       data.BlockHash,
		StateRoot:       data.StateRoot,
		Epoch:           data.BlockHeight / 100,
		TotalAccounts:   len(data.Accounts),
		TotalValidators: len(data.Validators),
		TotalSupply:     data.TotalSupply,
		Timestamp:       data.Timestamp,
		FileSize:        fileSize,
		SnapshotFile:    snapshotFile,
	}

	// Add to index
	sm.mu.Lock()
	sm.snapshotIndex[data.BlockHeight] = header
	if sm.latestSnapshot == nil || data.BlockHeight > sm.latestSnapshot.BlockHeight {
		sm.latestSnapshot = header
	}
	sm.mu.Unlock()

	// Save index
	if err := sm.saveSnapshotIndex(); err != nil {
		logger.Warn("Failed to save snapshot index: %v", err)
	}

	logger.Info("SUCCESS Received snapshot stored at height %d: %s (%d MB)",
		data.BlockHeight, snapshotFile, fileSize/(1024*1024))

	return nil
}

// ========== STATE SYNC ORCHESTRATION ==========

// PerformStateSync performs a full state sync from peers.
func (sm *StateSnapshotManager) PerformStateSync() error {
	logger.Info("INFO Starting state sync...")

	cp := sm.GetLatestCheckpoint()
	if cp == nil {
		return fmt.Errorf("no checkpoints available from peers")
	}

	logger.Info("INFO Best checkpoint: height=%d, hash=%s, state_root=%s",
		cp.BlockHeight, cp.BlockHash[:16], cp.StateRoot[:16])

	existing := sm.GetSnapshotHeaderAtHeight(cp.BlockHeight)
	if existing != nil {
		logger.Info("INFO Snapshot already exists at height %d, restoring...", cp.BlockHeight)
		return sm.RestoreFromSnapshot(cp.BlockHeight)
	}

	return fmt.Errorf("snapshot at height %d needs to be downloaded from peers", cp.BlockHeight)
}

// ========== HELPERS ==========

// formatSPX converts an nSPX balance string to a human-readable SPX string.
func formatSPX(nspxStr string) string {
	nspx, ok := new(big.Int).SetString(nspxStr, 10)
	if !ok {
		return nspxStr
	}
	spx := new(big.Float).Quo(
		new(big.Float).SetInt(nspx),
		new(big.Float).SetFloat64(denom.SPX),
	)
	// Use Text('f', 2) for 2 decimal places (FloatString is not available in all Go versions)
	result := spx.Text('f', 2)
	return result + " SPX"
}
