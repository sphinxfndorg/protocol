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
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	logger "github.com/sphinxfndorg/protocol/src/console"
)

// AttachBlockchain wires the blockchain instance into the journal manager so
// recovery can actually replay state, instead of only detecting and logging
// an incomplete commit. Call this once, after NewBlockchain/FinishInit has
// loaded bc.chain from storage, and before the node starts accepting new
// commits.
func (jm *JournalManager) AttachBlockchain(bc *Blockchain) {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	jm.bc = bc
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

// ████████ JOURNAL MONITORING HOOK - Every state change call logs ████████
// RecordStateChange records an account state change for potential rollback.
// Must be called BEFORE modifying the state DB. If the journal manager is
// nil (e.g. during early init or when journaling is disabled), this is a
// no-op.
func RecordStateChange(address string, prevBalance *big.Int, prevNonce uint64) {
	jm := GetJournalManager()
	if jm != nil {
		jm.RecordStateChange(address, prevBalance, prevNonce)
	}
}

// RecordBurn records a protocol burn credited to the DEAD address for the
// currently-active commit journal. Must be called BEFORE the corresponding
// AddBalance(DEAD) so the recorded "before" total is the pre-burn value that
// rollback would restore. No-op when no journal is active.
func RecordBurn(amount *big.Int) {
	jm := GetJournalManager()
	if jm != nil {
		jm.RecordBurn(amount)
	}
}

// RecordBurn accumulates amount into the active journal's burn accounting.
//
// The DEAD address's own balance change is already captured as an ordinary
// StateChangeJournal entry (AddBalance records it), so rollback correctness
// does not depend on this. What this adds is an explicit, human-auditable
// "burned in this block / burned before this block" record so an operator
// reading a journal (or a crash-recovery dump) can see protocol burn activity
// without having to identify the DEAD address and sum its deltas by hand.
func (jm *JournalManager) RecordBurn(amount *big.Int) {
	if amount == nil || amount.Sign() <= 0 {
		return
	}
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if jm.activeTx == nil {
		return
	}

	blockTotal := big.NewInt(0)
	if jm.activeTx.BurnedThisBlockNSPX != "" {
		if parsed, ok := new(big.Int).SetString(jm.activeTx.BurnedThisBlockNSPX, 10); ok {
			blockTotal = parsed
		}
	}
	if jm.activeTx.BurnedBeforeNSPX == "" && jm.bc != nil {
		// First burn recorded in this block: snapshot the DEAD balance as it
		// stands right now, i.e. before this burn (and before any earlier burn
		// in this same block, since this branch runs only on the first call).
		if bal, err := jm.bcBurnedBalance(); err == nil && bal != nil {
			jm.activeTx.BurnedBeforeNSPX = bal.String()
		}
	}

	jm.activeTx.BurnedThisBlockNSPX = new(big.Int).Add(blockTotal, amount).String()
	jm.persistTx()
}

// bcBurnedBalance reads the current DEAD-address balance from state, or an
// error when no blockchain/state handle is attached.
func (jm *JournalManager) bcBurnedBalance() (*big.Int, error) {
	if jm.bc == nil {
		return nil, fmt.Errorf("no blockchain attached")
	}
	stateDB, err := jm.bc.newStateDB()
	if err != nil {
		return nil, err
	}
	return stateDB.GetBalance(common.CanonicalAddress(common.DefaultBurnAddress))
}

// RecordStateChange (alias) is the method form; delegates to the same hook.
// Kept for backward compatibility with any direct jm.RecordStateChange calls
// found in the codebase.
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

// rollbackUsingRecordedState restores account state using the recorded state
// changes from the journal. This is much faster than rebuildStateToHeight()
// which replays all blocks from genesis. Returns an error if the recorded state
// is incomplete or corrupted, in which case the caller should fall back to
// rebuildStateToHeight().
func (jm *JournalManager) rollbackUsingRecordedState() error {
	if jm.bc == nil {
		return fmt.Errorf("no blockchain attached")
	}

	db, err := jm.bc.storage.GetDB()
	if err != nil {
		return fmt.Errorf("failed to get DB: %w", err)
	}

	// Track which addresses we've already restored to avoid overwriting
	// earlier (more original) state with later state from the same block.
	// The journal records state changes in order, so the FIRST record for
	// each address contains the original state before any modifications.
	restored := make(map[string]bool)

	for _, change := range jm.activeTx.StateChanged {
		if restored[change.Address] {
			continue
		}
		restored[change.Address] = true

		key := accountPrefix + change.Address
		prevBalance, ok := new(big.Int).SetString(change.PreviousBalance, 10)
		if !ok {
			return fmt.Errorf("failed to parse previous balance for %s: %s",
				change.Address, change.PreviousBalance)
		}

		existingData, err := db.Get(key)
		accountExisted := err == nil && len(existingData) > 0

		if !accountExisted && prevBalance.Sign() == 0 && change.PreviousNonce == 0 {
			if err := db.Delete(key); err != nil {
				return fmt.Errorf("failed to delete account %s: %w", change.Address, err)
			}
			logger.Info("rollbackUsingRecordedState: deleted account %s", change.Address)
		} else {
			rec := accountRecord{
				Balance: change.PreviousBalance,
				Nonce:   change.PreviousNonce,
			}
			data, err := json.Marshal(rec)
			if err != nil {
				return fmt.Errorf("failed to marshal account record for %s: %w", change.Address, err)
			}
			if err := db.Put(key, data); err != nil {
				return fmt.Errorf("failed to write account record for %s: %w", change.Address, err)
			}
			logger.Info("rollbackUsingRecordedState: restored %s to balance=%s nonce=%d",
				change.Address, change.PreviousBalance, change.PreviousNonce)
		}
	}

	return jm.restoreSupplyCounters()
}

// restoreSupplyCounters recomputes the total supply from current account state
func (jm *JournalManager) restoreSupplyCounters() error {
	db, err := jm.bc.storage.GetDB()
	if err != nil {
		return fmt.Errorf("failed to get DB: %w", err)
	}

	totalSupply := new(big.Int)
	keys, err := db.ListKeysWithPrefix(accountPrefix)
	if err != nil {
		return fmt.Errorf("failed to list account keys: %w", err)
	}

	for _, key := range keys {
		data, err := db.Get(key)
		if err != nil || len(data) == 0 {
			continue
		}
		var rec accountRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			continue
		}
		bal, ok := new(big.Int).SetString(rec.Balance, 10)
		if !ok {
			continue
		}
		totalSupply.Add(totalSupply, bal)
	}

	if err := db.Put(totalSupplyKey, []byte(totalSupply.String())); err != nil {
		return fmt.Errorf("failed to write total supply: %w", err)
	}

	logger.Info("restoreSupplyCounters: recomputed total supply = %s", totalSupply.String())
	return nil
}

// Rollback reverts all changes made in the current transaction.
// Uses fast recorded-state rollback first, falls back to rebuildStateToHeight
// if the recorded state is incomplete or corrupted.
func (jm *JournalManager) Rollback() error {
	jm.mu.Lock()
	tx := jm.activeTx
	bc := jm.bc
	jm.mu.Unlock()

	if tx == nil {
		return fmt.Errorf("no active transaction")
	}

	logger.Info("🔄 Rolling back atomic commit for block %s (restoring state to height %d)",
		tx.BlockHash[:16], tx.PreviousTipHeight)

	if bc == nil {
		logger.Warn("JournalManager.Rollback: no blockchain attached — clearing journal pointer only")
	} else {
		// Try fast rollback using recorded state first
		if err := jm.rollbackUsingRecordedState(); err != nil {
			logger.Warn("JournalManager.Rollback: fast rollback failed, falling back to rebuildStateToHeight: %v", err)
			if err := bc.rebuildStateToHeight(tx.PreviousTipHeight); err != nil {
				return fmt.Errorf("JournalManager.Rollback: failed to restore state to height %d: %w",
					tx.PreviousTipHeight, err)
			}
		} else {
			logger.Info("SUCCESS State restored using recorded state changes")
		}
	}

	jm.mu.Lock()
	jm.inProgress = false
	jm.activeTx = nil
	jm.mu.Unlock()

	if tx.BlockHash != "" {
		txPath := filepath.Join(jm.journalDir, fmt.Sprintf("tx_%s.json", tx.BlockHash[:16]))
		if err := os.Remove(txPath); err != nil && !os.IsNotExist(err) {
			logger.Warn("JournalManager.Rollback: failed to remove journal file: %v", err)
		}
	}

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

// recoverIncompleteOperations scans for incomplete commit journals on
// startup. It can only detect and queue them here — bc.chain hasn't been
// loaded from storage yet at InitJournalManager time, so there's nothing to
// replay state against. RepairIncompleteCommits() does the actual repair
// once AttachBlockchain has run; FinishInit calls it in that order.
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
			logger.Warn("Detected incomplete commit for block %s in phase %s (height %d) — queued for repair once chain is loaded",
				tx.BlockHash[:16], tx.Phase, tx.BlockHeight)
			txCopy := tx
			jm.pendingRepair = append(jm.pendingRepair, &txCopy)
		}
	}

	// Check for incomplete reorg
	return jm.RecoverIncompleteReorg()
}

// RepairIncompleteCommits processes every journal queued by
// recoverIncompleteOperations, restoring state to each journal's
// PreviousTipHeight via bc.rebuildStateToHeight and then removing the
// journal file. Must be called after AttachBlockchain and after the chain
// has been loaded from storage (i.e. after initializeChain in FinishInit).
//
// This replaces the old behavior, where an incomplete commit was either
// only logged (recoverIncompleteOperations) or detected-and-discarded
// (the old PerformCrashRecovery, which deleted the journal file without
// touching state at all) — in both cases the node would boot with account
// state silently ahead of what storage actually persisted.
func (jm *JournalManager) RepairIncompleteCommits() error {
	jm.mu.Lock()
	bc := jm.bc
	pending := jm.pendingRepair
	jm.pendingRepair = nil
	jm.mu.Unlock()

	if bc == nil {
		if len(pending) > 0 {
			logger.Warn("RepairIncompleteCommits: %d incomplete commit journal(s) found but no blockchain attached — not repaired", len(pending))
		}
		return nil
	}

	for _, tx := range pending {
		logger.Warn("Repairing incomplete commit for block %s: restoring state to height %d",
			tx.BlockHash[:16], tx.PreviousTipHeight)

		// Try fast rollback using recorded state first
		jm.activeTx = tx
		if err := jm.rollbackUsingRecordedState(); err != nil {
			logger.Warn("RepairIncompleteCommits: fast rollback failed for block %s, falling back to rebuildStateToHeight: %v",
				tx.BlockHash[:16], err)
			jm.activeTx = nil
			if err := bc.rebuildStateToHeight(tx.PreviousTipHeight); err != nil {
				return fmt.Errorf("RepairIncompleteCommits: failed to restore state to height %d for block %s: %w",
					tx.PreviousTipHeight, tx.BlockHash[:16], err)
			}
		} else {
			logger.Info("SUCCESS Repaired incomplete commit for block %s using recorded state changes",
				tx.BlockHash[:16])
			jm.activeTx = nil
		}

		txPath := filepath.Join(jm.journalDir, fmt.Sprintf("tx_%s.json", tx.BlockHash[:16]))
		if err := os.Remove(txPath); err != nil && !os.IsNotExist(err) {
			logger.Warn("RepairIncompleteCommits: failed to remove repaired journal file: %v", err)
		}
	}

	return nil
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

// PerformCrashRecovery is called on node startup to recover from crashes.
// Requires AttachBlockchain to have been called first (and the chain to
// already be loaded) — otherwise it can detect incomplete commits but can't
// actually repair state, same limitation as RepairIncompleteCommits.
// Returns true if recovery was performed, false if clean state.
func (jm *JournalManager) PerformCrashRecovery() bool {
	jm.mu.Lock()
	bc := jm.bc
	jm.mu.Unlock()

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
				logger.Warn("Crash recovery: found incomplete block commit for height %d (block %s)",
					tx.BlockHeight, tx.BlockHash)
				recoveryPerformed = true

				if bc == nil {
					// Nothing attached yet — leave the journal file in place
					// so a later, properly-sequenced call (via
					// RepairIncompleteCommits after AttachBlockchain) can
					// still repair it. Previously this branch deleted the
					// journal unconditionally, which discarded the only
					// record that state needed rolling back.
					logger.Warn("Crash recovery: no blockchain attached yet — leaving journal in place for later repair")
					continue
				}

				if err := bc.rebuildStateToHeight(tx.PreviousTipHeight); err != nil {
					logger.Error("Crash recovery: failed to restore state to height %d for block %s: %v",
						tx.PreviousTipHeight, tx.BlockHash[:16], err)
					continue
				}
				logger.Info("SUCCESS Crash recovery: state restored to height %d", tx.PreviousTipHeight)
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
				jm.mu.Lock()
				jm.reorgTx = &journal
				jm.mu.Unlock()
			}
		}
	}

	return recoveryPerformed
}
