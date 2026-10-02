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

	"github.com/sphinxfndorg/protocol/src/consensus"

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
	vs := sm.bc.liveValidatorSet()
	if vs == nil {
		logger.Warn("No validator set available for snapshot")
		return nil
	}

	for _, v := range vs.GetValidators() {
		if v == nil {
			continue
		}
		id := v.ID
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
	vs := sm.bc.liveValidatorSet()
	if vs == nil {
		logger.Warn("No validator set available — cannot restore validators")
		return nil
	}

	// Build the replacement set fully, THEN swap it in atomically via ReplaceAll.
	// The old code cleared the live set and re-added members one at a time under
	// a lock it held only on the shadow copy — a reader on the live set could
	// observe an empty or half-restored set. ReplaceAll takes the live set's
	// lock once, so the swap is all-or-nothing.
	rows := make(map[string]*consensus.StakedValidator, len(snapshot.Validators))

	for id, val := range snapshot.Validators {
		stake, ok := new(big.Int).SetString(val.StakeNSPX, 10)
		if !ok {
			logger.Warn("Failed to parse stake for validator %s: %s", id, val.StakeNSPX)
			continue
		}

		rows[id] = &consensus.StakedValidator{
			ID:              id,
			StakeAmount:     stake,
			RewardAddress:   val.RewardAddress,
			ActivationEpoch: val.ActivationEpoch,
			ExitEpoch:       val.ExitEpoch,
			IsSlashed:       val.IsSlashed,
		}
	}

	vs.ReplaceAll(rows)

	logger.Info("INFO Restored %d validators to validator set", len(rows))
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

// ============================================================================
// EPOCH-0 SNAPSHOT LIFECYCLE — SINGLE OWNER
//
// A node cannot produce block 1 without the snapshot that governs epoch 0:
// CreateBlock fails closed when the snapshot for the proposed height is
// missing, and heights 1..EpochBlocks-1 all live in epoch 0.
//
// The snapshot used to be taken in two unrelated places, guarded differently:
//
//   - ExecuteGenesisBlock, but only when the live set happened to be attached,
//     and NOT AT ALL on the "already executed, skipping" branch that a restart
//     takes;
//   - CommitBlock's epoch-boundary helper, which a solo bootstrap never reaches
//     because genesis runs through ExecuteGenesisBlock instead.
//
// A fresh devnet node seeded its validator set AFTER ExecuteGenesisBlock ran, so
// the guard saw no set, skipped the snapshot, never retried — and then logged
// "validator snapshot for height 1 is unavailable" every ten seconds forever.
// One owner, called from every path that can reach height 1, removes the
// ordering dependency entirely.
// ============================================================================

// ensureEpoch0Snapshot guarantees the snapshot governing epoch 0 exists and is
// the one the genesis block committed to.
//
// ★ NEVER OVERWRITES A PERSISTED SNAPSHOT. The store is the record of what this
// node already agreed to; a recovered row wins, and disagreement is an error
// rather than a silent overwrite. Overwriting would let a re-commit redefine
// the very set an earlier block was verified against.
func (bc *Blockchain) ensureEpoch0Snapshot() error {
	// 1. If a snapshot already exists in memory, honour it — but verify it is
	//    the one genesis committed to, so a corrupted store cannot propagate.
	existing := consensus.SnapshotAtEpoch(0)
	if existing != nil {
		return bc.verifyEpoch0AgainstGenesis(existing, "recovered")
	}

	// 2. Nothing in memory. Decide whether rebuilding is even valid: the genesis
	//    document only describes epoch 0. If the chain is already past it,
	//    guessing is worse than refusing.
	tipHeight := uint64(0)
	if bc.storage != nil {
		if tip, err := bc.storage.GetLatestBlock(); err == nil && tip != nil {
			tipHeight = tip.GetHeight()
		}
	}
	if consensus.EpochForHeight(tipHeight) != 0 {
		return fmt.Errorf("cannot rebuild the epoch-0 validator snapshot: local chain is at height %d (epoch %d) and "+
			"genesis alone cannot describe the current epoch's membership; a full resync from peers is required",
			tipHeight, consensus.EpochForHeight(tipHeight))
	}

	// 3. Build from the DOCUMENT (single shared builder), not the live set.
	gf := bc.GenesisDocument()
	if gf == nil {
		return fmt.Errorf("cannot build the epoch-0 validator snapshot: no genesis document is loaded on this node")
	}
	snap, err := epoch0SnapshotFromGenesis(gf)
	if err != nil {
		return fmt.Errorf("build epoch-0 snapshot from genesis: %w", err)
	}
	if err := bc.verifyEpoch0AgainstGenesis(snap, "rebuilt"); err != nil {
		return err
	}

	// 4. Cross-check the live set IF it is already attached.
	//
	// This is deliberately not fatal here. ensureEpoch0Snapshot is called from
	// ExecuteGenesisBlock, which runs from FinishInit — BEFORE the consensus
	// engine exists and therefore before genesis validators can have been
	// seeded. At that point an unattached set is the normal, correct state, and
	// treating it as an error would make startup impossible.
	//
	// The authoritative cross-check is assertLiveSetMatchesEpoch0, which runs
	// from BootstrapGenesisValidatorSet immediately AFTER seeding and is fatal
	// there. See that function for what it catches.
	if vs := bc.liveValidatorSet(); vs != nil {
		if err := bc.assertLiveSetMatchesEpoch0(snap); err != nil {
			return err
		}
	} else {
		logger.Debug("Epoch-0 snapshot built from genesis; live set not attached yet — " +
			"the membership cross-check will run after seeding completes")
	}

	// 5. Install and persist.
	consensus.StoreSnapshot(*snap)
	logger.Info("Epoch-0 validator snapshot ensured: %d validator(s), total %s nSPX, hash %s",
		len(snap.Validators), snap.TotalStake.String(), snap.Hash()[:16])
	return nil
}

// verifyEpoch0AgainstGenesis checks a candidate epoch-0 snapshot against the
// commitment the genesis block header carries. A mismatch is a startup error:
// neither side is taken as authoritative, because "which one is right" is
// exactly the question that cannot be answered locally.
func (bc *Blockchain) verifyEpoch0AgainstGenesis(snap *consensus.ValidatorSnapshot, origin string) error {
	if snap == nil {
		return fmt.Errorf("epoch-0 snapshot (%s) is nil", origin)
	}
	committed, err := bc.GenesisSnapshotCommitment()
	if err != nil {
		// No commitment available (e.g. no genesis document attached yet). The
		// snapshot hash is still deterministic, so record it and let a later
		// comparison catch a divergence.
		logger.Debug("Epoch-0 snapshot (%s): no genesis commitment available to compare against (%v)", origin, err)
		return nil
	}
	if committed == "" {
		return nil
	}
	if got := snap.Hash(); got != committed {
		return fmt.Errorf("epoch-0 validator snapshot (%s) hash %s does not match the genesis commitment %s; "+
			"this node's genesis data disagrees with what the block-0 header committed to, and neither can be "+
			"trusted — refusing to start rather than picking one", origin, got[:16], committed[:16])
	}
	logger.Debug("Epoch-0 snapshot (%s) matches genesis commitment %s", origin, committed[:16])
	return nil
}

// assertLiveSetMatchesEpoch0 confirms the live ValidatorSet agrees with the
// epoch-0 snapshot on membership and stakes.
//
// The snapshot is built from the genesis DOCUMENT precisely so it does not
// depend on seeding order. That makes the live set redundant for construction
// but valuable as an independent check: if seeding produced a different set
// (wrong stake, missing or extra validator), the node would compute quorum
// denominators from the live set while verifying blocks against the snapshot,
// and the two would disagree on every round.
func (bc *Blockchain) assertLiveSetMatchesEpoch0(snap *consensus.ValidatorSnapshot) error {
	vs := bc.liveValidatorSet()
	if vs == nil {
		return fmt.Errorf("no validator set attached; genesis validators were not seeded, so the epoch-0 " +
			"snapshot cannot be cross-checked — refusing to continue")
	}
	for id, row := range snap.Validators {
		live, ok := vs.GetValidator(id).(*consensus.StakedValidator)
		if !ok || live == nil {
			return fmt.Errorf("genesis validator %s is in the epoch-0 snapshot but not in the seeded validator set", id)
		}
		if live.StakeAmount == nil || row.StakeAmount == nil || live.StakeAmount.Cmp(row.StakeAmount) != 0 {
			return fmt.Errorf("genesis validator %s stake disagrees: snapshot %s, seeded set %s",
				id, row.StakeAmount, live.StakeAmount)
		}
	}
	if seeded := vs.GetActiveValidators(0); len(seeded) != len(snap.Validators) {
		return fmt.Errorf("seeded validator set has %d active member(s) but the epoch-0 snapshot has %d; "+
			"membership disagrees with genesis", len(seeded), len(snap.Validators))
	}
	return nil
}

// SetGenesisDocument records the parsed, validated genesis document on the
// blockchain so later phases read it from memory instead of re-parsing the file.
//
// The document is validated (including the owner-address normalization and the
// pinned/committed digest check) by the loader before it is set here, so
// anything reachable through GenesisDocument has already passed those gates.
// Keeping it on the node is what lets the epoch-0 snapshot builder be
// order-independent: it no longer has to be handed a document by whichever
// startup phase happened to run first.
func (bc *Blockchain) SetGenesisDocument(gf *GenesisStateFile) {
	bc.genesisDocMu.Lock()
	bc.genesisDoc = gf
	bc.genesisDocMu.Unlock()
}

// GenesisDocument returns the loaded genesis document, or nil if none is set.
func (bc *Blockchain) GenesisDocument() *GenesisStateFile {
	bc.genesisDocMu.RLock()
	defer bc.genesisDocMu.RUnlock()
	return bc.genesisDoc
}

// GenesisSnapshotCommitment returns the epoch-0 snapshot hash that the genesis
// block header commits to, derived from the loaded genesis document using the
// SAME builder that creates the snapshot. It is an error when no document is
// available, because there is then nothing to compare against.
func (bc *Blockchain) GenesisSnapshotCommitment() (string, error) {
	gf := bc.GenesisDocument()
	if gf == nil {
		return "", fmt.Errorf("no genesis document loaded")
	}
	return gf.validatorSnapshotHash()
}

// BootstrapGenesisValidatorSet performs the membership bootstrap in ONE place:
// it attaches the genesis document, seeds the consensus validator set from it,
// and ensures the epoch-0 snapshot exists.
//
// ★ WHY THIS IS A SINGLE FUNCTION. Seeding and snapshot creation used to live in
// different startup phases, hundreds of lines apart: seeding ran where the
// consensus engine is constructed, while the epoch-0 snapshot was taken from
// inside ExecuteGenesisBlock, which runs EARLIER. On a fresh devnet the
// validator set was therefore attached after the snapshot code had already
// looked for it, found none, skipped, and never retried — leaving the node
// unable to produce block 1 and logging the same fatal error every ten seconds
// forever.
//
// Doing both here makes the order correct by construction rather than by
// luck: the document is attached, the set is seeded, and only then is the
// snapshot built and cross-checked against the live set.
//
// Any error is returned so the caller fails node construction. Nothing here
// logs-and-continues: a node that cannot build the snapshot governing height 1
// must not start.
//
// lateJoiner is passed through so a late joiner (which must NOT seed from its
// own local document, because that document may be absent) is skipped here and
// instead takes the snapshot from the chain it syncs.
func (bc *Blockchain) BootstrapGenesisValidatorSet(
	genesisFile *GenesisStateFile,
	seed func(*GenesisStateFile) error,
) error {
	// The document is retained on the node so the snapshot builder is
	// order-independent: it reads the same validated bytes the loader checked.
	bc.SetGenesisDocument(genesisFile)

	if seed != nil {
		if err := seed(genesisFile); err != nil {
			return fmt.Errorf("seed genesis validators: %w", err)
		}
	}

	if err := bc.ensureEpoch0Snapshot(); err != nil {
		return fmt.Errorf("ensure epoch-0 validator snapshot: %w", err)
	}

	// ★ THE AUTHORITATIVE MEMBERSHIP CROSS-CHECK, and it is fatal.
	//
	// Seeding has just run, so the live set MUST now exist and MUST agree with
	// the epoch-0 snapshot the chain committed to. ensureEpoch0Snapshot tolerates
	// an unattached set because it is also called from ExecuteGenesisBlock, which
	// runs before any seeding exists. Here the set is REQUIRED.
	//
	// Why it matters: the node measures quorum against the snapshot, so if
	// seeding produced a different membership or a different stake than the
	// document, the node would verify blocks against one set and weight itself
	// by another. That is a divergence, not a cosmetic mismatch, so it is a
	// startup error rather than a warning.
	snap := consensus.SnapshotAtEpoch(0)
	if snap == nil {
		return fmt.Errorf("epoch-0 validator snapshot is absent immediately after bootstrap")
	}
	if err := bc.assertLiveSetMatchesEpoch0(snap); err != nil {
		return fmt.Errorf("genesis seeding does not match the genesis document: %w", err)
	}
	logger.Info("Genesis validator set verified against the epoch-0 snapshot (%d member(s), %s nSPX)",
		len(snap.Validators), snap.TotalStake.String())
	return nil
}
