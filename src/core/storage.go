// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/storage.go
package core

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	logger "github.com/sphinxfndorg/protocol/src/console"
)

// ============================================================================
// ROLLBACK JOURNAL - Records state changes for crash-safe rollback
// ============================================================================

// StateChangeJournal records a single account state change for potential rollback
type StateChangeJournal struct {
	Address         string `json:"address"`
	PreviousBalance string `json:"previous_balance"`
	PreviousNonce   uint64 `json:"previous_nonce"`
}

// AtomicCommitJournal records all state changes for a single block commit
// This enables exact rollback if the commit is interrupted
type AtomicCommitJournal struct {
	BlockHash         string               `json:"block_hash"`
	BlockHeight       uint64               `json:"block_height"`
	Phase             string               `json:"phase"` // "started", "state_applied", "block_stored", "committed"
	StateChanged      []StateChangeJournal `json:"state_changes"`
	Committed         bool                 `json:"committed"`
	PreviousTipHash   string               `json:"previous_tip_hash,omitempty"`
	PreviousTipHeight uint64               `json:"previous_tip_height,omitempty"`
	PreviousWeight    *big.Int             `json:"previous_weight,omitempty"`
	StartedAt         time.Time            `json:"started_at"`
	CommittedAt       time.Time            `json:"committed_at,omitempty"`
	StateRootBefore   string               `json:"state_root_before,omitempty"`
	BlockFileWritten  bool                 `json:"block_file_written,omitempty"`
	IndexUpdated      bool                 `json:"index_updated,omitempty"`
}

// ReorgJournal records chain reorganization state for crash recovery
type ReorgJournal struct {
	OldTipHash         string    `json:"old_tip_hash"`
	OldTipHeight       uint64    `json:"old_tip_height"`
	OldTipStateRoot    string    `json:"old_tip_state_root,omitempty"`
	ForkHash           string    `json:"fork_hash"`
	ForkHeight         uint64    `json:"fork_height"`
	BlocksToDisconnect []string  `json:"blocks_to_disconnect"`
	BlocksToConnect    []string  `json:"blocks_to_connect"`
	Phase              string    `json:"phase"` // "started", "disconnecting", "connecting", "complete"
	StartedAt          time.Time `json:"started_at"`
	// For proper rollback, store the pre-reorg state
	DisconnectedBlocks []string `json:"disconnected_blocks,omitempty"`
}

// ============================================================================
// JOURNAL MANAGER - Manages crash-safe journals
// ============================================================================

// JournalManager manages rollback journals for atomic commits and reorganizations
type JournalManager struct {
	mu sync.Mutex

	dataDir    string
	journalDir string

	activeTx   *AtomicCommitJournal
	inProgress bool

	// For reorg crash recovery
	reorgTx         *ReorgJournal
	reorgInProgress bool
}

// Global journal manager
var globalJournalManager *JournalManager

// InitJournalManager initializes the journal manager with crash recovery
func InitJournalManager(dataDir string) error {
	journalDir := filepath.Join(dataDir, "journals")
	if err := os.MkdirAll(journalDir, 0755); err != nil {
		return fmt.Errorf("failed to create journal directory: %w", err)
	}

	globalJournalManager = &JournalManager{
		dataDir:    dataDir,
		journalDir: journalDir,
	}

	// Recover from incomplete operations on startup
	if err := globalJournalManager.recoverIncompleteOperations(); err != nil {
		logger.Warn("Journal recovery warning: %v", err)
	}

	logger.Info("SUCCESS Journal manager initialized at %s", journalDir)
	return nil
}

// GetJournalManager returns the global journal manager
func GetJournalManager() *JournalManager {
	return globalJournalManager
}

// StartAtomicCommit begins recording a block commit with rollback capability
// This MUST be called before any state modifications or disk writes
func (jm *JournalManager) StartAtomicCommit(blockHash string, blockHeight uint64, previousTipHash string, previousTipHeight uint64) {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if jm.inProgress {
		logger.Warn("Atomic commit already in progress, skipping")
		return
	}

	jm.activeTx = &AtomicCommitJournal{
		BlockHash:         blockHash,
		BlockHeight:       blockHeight,
		Phase:             "started",
		Committed:         false,
		StateChanged:      make([]StateChangeJournal, 0),
		PreviousTipHash:   previousTipHash,
		PreviousTipHeight: previousTipHeight,
		StartedAt:         time.Now(),
	}

	jm.inProgress = true
	jm.persistTx()
	logger.Info(" Started atomic commit journal for block %s at height %d", blockHash[:16], blockHeight)
}

// RecordStateChange records an account state change for potential rollback
// Must be called BEFORE modifying the state DB
func (jm *JournalManager) RecordStateChange(address string, prevBalance *big.Int, prevNonce uint64) {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if jm.activeTx == nil {
		return
	}

	jm.activeTx.StateChanged = append(jm.activeTx.StateChanged, StateChangeJournal{
		Address:         address,
		PreviousBalance: prevBalance.String(),
		PreviousNonce:   prevNonce,
	})
}

// UpdatePhase updates and persists the transaction phase
// Call this after each major step to enable recovery
func (jm *JournalManager) UpdatePhase(phase string) {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if jm.activeTx == nil {
		return
	}

	jm.activeTx.Phase = phase
	jm.persistTx()
}

// MarkBlockWritten marks that the block file has been written to disk
func (jm *JournalManager) MarkBlockWritten() {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if jm.activeTx == nil {
		return
	}

	jm.activeTx.BlockFileWritten = true
}

// MarkIndexUpdated marks that the index has been updated
func (jm *JournalManager) MarkIndexUpdated() {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if jm.activeTx == nil {
		return
	}

	jm.activeTx.IndexUpdated = true
}

// Commit completes the atomic transaction
// This is the final step - call only after all writes succeed
func (jm *JournalManager) Commit(previousWeight *big.Int) error {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if jm.activeTx == nil {
		return fmt.Errorf("no active transaction")
	}

	jm.activeTx.Phase = "committed"
	jm.activeTx.Committed = true
	jm.activeTx.CommittedAt = time.Now()
	jm.activeTx.PreviousWeight = previousWeight

	// Mark as committed (but keep journal for diagnostics)
	jm.persistTx()

	// Remove the active transaction
	jm.inProgress = false
	jm.activeTx = nil

	logger.Info("SUCCESS Committed atomic transaction")
	return nil
}

// Rollback reverts all changes made in the current transaction
// This is called when a commit fails - actual state restoration happens in blockchain
func (jm *JournalManager) Rollback() error {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if jm.activeTx == nil {
		return fmt.Errorf("no active transaction")
	}

	logger.Info("🔄 Rolling back atomic commit for block %s", jm.activeTx.BlockHash[:16])

	jm.inProgress = false
	jm.activeTx = nil

	logger.Info("SUCCESS Completed rollback of atomic transaction")
	return nil
}

// persistTx saves the transaction to disk atomically
func (jm *JournalManager) persistTx() error {
	if jm.activeTx == nil {
		return nil
	}

	txPath := filepath.Join(jm.journalDir, fmt.Sprintf("tx_%s.json", jm.activeTx.BlockHash[:16]))

	data, err := json.MarshalIndent(jm.activeTx, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %w", err)
	}

	// Write atomically using tmp + rename pattern
	tmpPath := txPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write transaction file: %w", err)
	}

	return os.Rename(tmpPath, txPath)
}

// recoverIncompleteOperations recovers from incomplete commits on startup
// This is called during InitJournalManager
func (jm *JournalManager) recoverIncompleteOperations() error {
	// Find all transaction files
	txPathPattern := filepath.Join(jm.journalDir, "tx_*.json")
	files, err := filepath.Glob(txPathPattern)
	if err != nil {
		return fmt.Errorf("failed to scan transaction files: %w", err)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var tx AtomicCommitJournal
		if err := json.Unmarshal(data, &tx); err != nil {
			continue
		}

		if !tx.Committed {
			logger.Warn("Detected incomplete commit for block %s in phase %s - state may need recovery",
				tx.BlockHash[:16], tx.Phase)
			// The block may have been written but state changes not applied
			// Recovery strategy: if block file exists but state not consistent, rollback
		}
	}

	// Check for incomplete reorg
	return jm.RecoverIncompleteReorg()
}

// IsInProgress returns true if a commit is currently in progress
func (jm *JournalManager) IsInProgress() bool {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	return jm.inProgress
}

// GetStateChanges returns the state changes recorded so far
func (jm *JournalManager) GetStateChanges() []StateChangeJournal {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	if jm.activeTx == nil {
		return nil
	}
	return jm.activeTx.StateChanged
}

// GetPreviousState returns the previous tip hash and height for recovery
func (jm *JournalManager) GetPreviousState() (string, uint64) {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	if jm.activeTx == nil {
		return "", 0
	}
	return jm.activeTx.PreviousTipHash, jm.activeTx.PreviousTipHeight
}

// StartReorg begins recording a chain reorganization for crash recovery
func (jm *JournalManager) StartReorg(oldTipHash string, oldTipHeight uint64) error {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if jm.inProgress {
		return fmt.Errorf("reorg already in progress - atomic commit in flight")
	}

	reorgPath := filepath.Join(jm.journalDir, "reorg_journal.json")

	journal := &ReorgJournal{
		OldTipHash:   oldTipHash,
		OldTipHeight: oldTipHeight,
		Phase:        "started",
		StartedAt:    time.Now(),
	}

	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal reorg journal: %w", err)
	}

	tmpPath := reorgPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write reorg journal: %w", err)
	}

	if err := os.Rename(tmpPath, reorgPath); err != nil {
		return fmt.Errorf("failed to rename reorg journal: %w", err)
	}

	jm.reorgTx = journal
	jm.reorgInProgress = true
	return nil
}

// UpdateReorgProgress updates the reorg journal phase
func (jm *JournalManager) UpdateReorgProgress(phase string, forkHash string, forkHeight uint64,
	blocksToDisconnect, blocksToConnect []string, disconnectedBlocks []string) error {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if jm.reorgTx == nil {
		return fmt.Errorf("no active reorg transaction")
	}

	reorgPath := filepath.Join(jm.journalDir, "reorg_journal.json")

	jm.reorgTx.Phase = phase
	jm.reorgTx.ForkHash = forkHash
	jm.reorgTx.ForkHeight = forkHeight
	jm.reorgTx.BlocksToDisconnect = blocksToDisconnect
	jm.reorgTx.BlocksToConnect = blocksToConnect
	jm.reorgTx.DisconnectedBlocks = disconnectedBlocks

	data, err := json.MarshalIndent(jm.reorgTx, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal reorg journal: %w", err)
	}

	tmpPath := reorgPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write reorg journal: %w", err)
	}

	return os.Rename(tmpPath, reorgPath)
}

// CompleteReorg removes the reorg journal (reorg complete)
func (jm *JournalManager) CompleteReorg() error {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	reorgPath := filepath.Join(jm.journalDir, "reorg_journal.json")
	jm.reorgInProgress = false
	jm.reorgTx = nil
	return os.Remove(reorgPath)
}

// RecoverIncompleteReorg checks for and recovers from incomplete reorganizations
func (jm *JournalManager) RecoverIncompleteReorg() error {
	reorgPath := filepath.Join(jm.journalDir, "reorg_journal.json")

	if _, err := os.Stat(reorgPath); os.IsNotExist(err) {
		return nil // No reorg in progress
	}

	data, err := os.ReadFile(reorgPath)
	if err != nil {
		return fmt.Errorf("failed to read reorg journal: %w", err)
	}

	var journal ReorgJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		return fmt.Errorf("failed to parse reorg journal: %w", err)
	}

	logger.Warn("🔄 Recovering from incomplete reorg in phase: %s", journal.Phase)

	// Recovery strategy based on phase:
	// - "started": No changes made, safe to just remove journal
	// - "disconnecting": Blocks were removed from in-memory chain but not re-added to DB
	// - "connecting": Partial blocks may have been written
	// We need the blockchain to handle actual state restoration
	jm.reorgInProgress = true
	jm.reorgTx = &journal

	return nil
}

// GetReorgJournal returns the current reorg journal for recovery
func (jm *JournalManager) GetReorgJournal() *ReorgJournal {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	return jm.reorgTx
}

// ClearReorgJournal clears the reorg journal after recovery
func (jm *JournalManager) ClearReorgJournal() {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	jm.reorgTx = nil
	jm.reorgInProgress = false
}

// ============================================================================
// CRASH RECOVERY - Global recovery coordinator
// ============================================================================

// PerformCrashRecovery is called on node startup to recover from crashes
// Returns true if recovery was performed, false if clean state
func (jm *JournalManager) PerformCrashRecovery() bool {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	recoveryPerformed := false

	// Check for incomplete block commit
	txPathPattern := filepath.Join(jm.journalDir, "tx_*.json")
	files, err := filepath.Glob(txPathPattern)
	if err == nil && len(files) > 0 {
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				continue
			}

			var tx AtomicCommitJournal
			if err := json.Unmarshal(data, &tx); err != nil {
				continue
			}

			if !tx.Committed {
				logger.Warn("Crash recovery: found incomplete block commit for height %d", tx.BlockHeight)
				recoveryPerformed = true
				// Remove the incomplete journal
				os.Remove(file)
			}
		}
	}

	// Check for incomplete reorg - store for blockchain to process
	reorgPath := filepath.Join(jm.journalDir, "reorg_journal.json")
	if _, err := os.Stat(reorgPath); err == nil {
		data, err := os.ReadFile(reorgPath)
		if err == nil {
			var journal ReorgJournal
			if err := json.Unmarshal(data, &journal); err == nil {
				logger.Warn("Crash recovery: found incomplete reorg in phase %s", journal.Phase)
				recoveryPerformed = true
				// Store the journal for blockchain to process via GetReorgJournal
				jm.reorgTx = &journal
			}
		}
	}

	return recoveryPerformed
}
