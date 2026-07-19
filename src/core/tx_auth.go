// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/tx_auth.go
package core

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	logger "github.com/sphinxfndorg/protocol/src/console"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

func transactionAuthTimestamp(tx *types.Transaction) []byte {
	if len(tx.AuthTimestamp) == 8 {
		out := make([]byte, 8)
		copy(out, tx.AuthTimestamp)
		return out
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, uint64(tx.Timestamp))
	return out
}

func transactionAuthNonce(tx *types.Transaction) []byte {
	if len(tx.AuthNonce) == 16 {
		out := make([]byte, 16)
		copy(out, tx.AuthNonce)
		return out
	}
	out := make([]byte, 16)
	binary.BigEndian.PutUint64(out[:8], tx.Nonce)
	return out
}

func (bc *Blockchain) validateTransactionAuth(tx *types.Transaction, storeEvidence bool) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	if tx.IsSystemTransaction() {
		return nil
	}
	if !tx.HasFullAuthBundle() {
		return fmt.Errorf("transaction %s missing full SPHINCS auth bundle", tx.ID)
	}
	if bc.sphincsManager == nil {
		return fmt.Errorf("transaction %s cannot be verified: STHINCS manager is not configured", tx.ID)
	}

	if err := bc.sphincsManager.VerifyTransactionAuth(
		[]byte(tx.ID),
		transactionAuthTimestamp(tx),
		transactionAuthNonce(tx),
		tx.Signature,
		tx.PublicKey,
		tx.SignatureHash,
		tx.MerkleRootHash,
		tx.Commitment,
		tx.Proof,
		storeEvidence,
	); err != nil {
		return fmt.Errorf("transaction %s SPHINCS auth failed: %w", tx.ID, err)
	}

	if storeEvidence {
		if err := bc.sphincsManager.StoreTransactionReceipt(tx.Commitment, tx.MerkleRootHash, tx.Proof); err != nil {
			return fmt.Errorf("transaction %s receipt storage failed: %w", tx.ID, err)
		}
	}

	return nil
}

// validateBlockTransactionAuth enforces per-block uniqueness of every
// transaction's identity before running the SPHINCS auth check on each one.
//
// Identity is anchored the same way Ethereum anchors it: (Sender, Nonce).
// That pair is what the state machine actually uses to order and admit a
// transaction (see StateDB/ExecuteBlock's expected-nonce check) — it is the
// account's ground truth, and it is checked here FIRST so a duplicate is
// rejected as exactly that ("this account replayed a nonce") rather than
// surfacing later, incidentally, as a generic nonce-mismatch error out of
// ExecuteBlock once execution order happens to expose it.
//
// The remaining checks (signature hash, auth timestamp/nonce session,
// commitment) are SPHINCS-specific replay guards, not identity: AuthNonce is
// a random one-time-signature nonce unrelated to the account's nonce, so it
// can't stand in for account+nonce uniqueness on its own. They stay in place
// to catch signature-level replay (e.g. the same auth bundle resubmitted
// under a different account/nonce pairing) independent of the account check.
func (bc *Blockchain) validateBlockTransactionAuth(block *types.Block, storeEvidence bool) error {
	if block == nil {
		return fmt.Errorf("nil block")
	}

	// Pre-sized to the block's tx count — avoids incremental map growth/
	// rehashing on blocks with more than a handful of transactions.
	n := len(block.Body.TxsList)
	seenAccountNonces := make(map[string]struct{}, n)
	seenSigHashes := make(map[string]struct{}, n)
	seenSessions := make(map[string]struct{}, n)
	seenCommitments := make(map[string]struct{}, n)

	for i, tx := range block.Body.TxsList {
		if tx == nil {
			return fmt.Errorf("transaction %d is nil", i)
		}
		if tx.IsSystemTransaction() {
			continue
		}

		// Primary identity check: (Sender, Nonce), Ethereum-style.
		// strconv+concat instead of fmt.Sprintf: this runs once per tx per
		// block and Sprintf's reflection-based formatting is measurably
		// slower on the hot path for large blocks.
		accountNonceKey := tx.Sender + ":" + strconv.FormatUint(tx.Nonce, 10)
		if _, exists := seenAccountNonces[accountNonceKey]; exists {
			return fmt.Errorf("duplicate account nonce in block: sender=%s nonce=%d transaction=%s",
				tx.Sender, tx.Nonce, tx.ID)
		}
		seenAccountNonces[accountNonceKey] = struct{}{}

		sigHashKey := string(tx.SignatureHash)
		if _, exists := seenSigHashes[sigHashKey]; exists {
			return fmt.Errorf("duplicate signature hash in block for transaction %s", tx.ID)
		}
		seenSigHashes[sigHashKey] = struct{}{}

		sessionKey := string(transactionAuthTimestamp(tx)) + string(transactionAuthNonce(tx))
		if _, exists := seenSessions[sessionKey]; exists {
			return fmt.Errorf("duplicate timestamp/nonce in block for transaction %s", tx.ID)
		}
		seenSessions[sessionKey] = struct{}{}

		commitmentKey := string(tx.Commitment)
		if _, exists := seenCommitments[commitmentKey]; exists {
			return fmt.Errorf("duplicate commitment in block for transaction %s", tx.ID)
		}
		seenCommitments[commitmentKey] = struct{}{}

		if err := bc.validateTransactionAuth(tx, storeEvidence); err != nil {
			return err
		}
	}

	return nil
}

// SignTransaction fills a transaction with the full SPHINCS auth bundle required
// for mempool admission, P2P gossip, and block validation.
func (bc *Blockchain) SignTransaction(tx *types.Transaction, skBytes, pkBytes []byte) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	if tx.IsSystemTransaction() {
		return nil
	}
	if bc.sphincsManager == nil {
		return fmt.Errorf("STHINCS manager is not configured")
	}
	if tx.ID == "" {
		tx.ID = tx.Hash()
	}

	km, err := key.NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to initialize key manager: %w", err)
	}
	privateKey, publicKey, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		return fmt.Errorf("failed to deserialize transaction signing key pair: %w", err)
	}

	bundle, err := bc.sphincsManager.SignTransactionAuth([]byte(tx.ID), privateKey, publicKey)
	if err != nil {
		return fmt.Errorf("failed to sign transaction auth bundle: %w", err)
	}

	tx.Signature = bundle.Signature
	tx.SignatureHash = bundle.SignatureHash
	tx.PublicKey = bundle.PublicKey
	tx.AuthTimestamp = bundle.Timestamp
	tx.AuthNonce = bundle.Nonce
	tx.MerkleRootHash = bundle.MerkleRootHash
	tx.Commitment = bundle.Commitment
	tx.Proof = bundle.Proof

	return nil
}

// replayEvidenceMu serializes RebuildCanonicalReplayEvidence end-to-end
// (read checkpoint -> rebuild -> write checkpoint) so two overlapping calls
// (e.g. two fork-choice updates firing close together) can't interleave
// their checkpoint reads/writes and clobber each other's progress.
//
// Package-level rather than a bc field for the same reason as rewardMapMu /
// uiProgress in executor.go: it avoids editing wherever `type Blockchain
// struct` is declared. One process runs one Blockchain instance, so this is
// equivalent to a per-instance lock in practice.
var replayEvidenceMu sync.Mutex

// replayEvidenceCheckpoint records how far RebuildCanonicalReplayEvidence has
// gotten, so a later call can resume instead of re-verifying and re-storing
// evidence for every transaction back to genesis every single time.
type replayEvidenceCheckpoint struct {
	// GenesisHash pins the checkpoint to a specific chain. If the running
	// node's genesis hash doesn't match this, the checkpoint belongs to a
	// different chain entirely (e.g. devnet data dir reused for testnet) and
	// must not be trusted.
	GenesisHash string `json:"genesis_hash"`
	// LastHeight is the height of the last block whose transactions were
	// fully written to the evidence store.
	LastHeight uint64 `json:"last_height"`
	// LastBlockHash is the hash of the block at LastHeight. On resume this is
	// compared against whatever block currently sits at LastHeight in the
	// canonical chain: if it differs, a reorg reshuffled blocks at or below
	// the checkpoint since it was written, the recorded evidence for that
	// range can no longer be trusted, and the checkpoint is discarded in
	// favor of a full rebuild from genesis.
	LastBlockHash string `json:"last_block_hash"`
}

// replayEvidenceCheckpointPath returns the on-disk path for the checkpoint
// file, using the same data directory the journal manager was initialized
// with. Returns ok=false if no journal manager has been initialized yet
// (e.g. tests, or tooling that calls this before InitJournalManager) — in
// that case the rebuild still runs correctly, it just can't persist or load
// a checkpoint across process restarts and always does a full walk.
func replayEvidenceCheckpointPath() (path string, ok bool) {
	jm := GetJournalManager()
	if jm == nil || jm.dataDir == "" {
		return "", false
	}
	return filepath.Join(jm.dataDir, "replay_evidence_checkpoint.json"), true
}

// loadReplayEvidenceCheckpoint reads the checkpoint file if present and
// valid. Any failure to load (missing file, corrupt JSON, wrong genesis) is
// treated as "no usable checkpoint" rather than a hard error — the caller
// falls back to a full rebuild, which is always correct, just slower.
func loadReplayEvidenceCheckpoint() *replayEvidenceCheckpoint {
	path, ok := replayEvidenceCheckpointPath()
	if !ok {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil // no checkpoint yet, or unreadable — full rebuild
	}

	var cp replayEvidenceCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		logger.Warn("loadReplayEvidenceCheckpoint: corrupt checkpoint file, ignoring: %v", err)
		return nil
	}

	if cp.GenesisHash != GetGenesisHash() {
		logger.Warn("loadReplayEvidenceCheckpoint: checkpoint genesis=%s does not match current genesis=%s, ignoring",
			cp.GenesisHash, GetGenesisHash())
		return nil
	}

	return &cp
}

// saveReplayEvidenceCheckpoint atomically persists progress after a block's
// evidence has been fully written. Written with the same tmp+rename pattern
// used elsewhere in this package (see persistTx in storage.go) so a crash
// mid-write can never leave a half-written, unparseable checkpoint behind.
func saveReplayEvidenceCheckpoint(cp *replayEvidenceCheckpoint) error {
	path, ok := replayEvidenceCheckpointPath()
	if !ok {
		// No journal manager / data dir known — nothing to persist to.
		// Not an error: the rebuild itself already succeeded for this block.
		return nil
	}

	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal replay evidence checkpoint: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write replay evidence checkpoint: %w", err)
	}
	return os.Rename(tmpPath, path)
}

// RebuildCanonicalReplayEvidence replays compact authentication evidence from
// the current canonical chain into the configured SPHINCS evidence database.
// Call this after chain sync or fork choice selects a new canonical head.
//
// Resumes from the last checkpointed height instead of always walking from
// genesis: on a long-running chain, re-verifying and re-storing evidence for
// every transaction back to block 0 on every call is a real and growing
// startup/recovery-time cost. Only the range of blocks after the checkpoint
// is processed; the checkpoint then advances one block at a time so a crash
// or error partway through loses at most the in-progress block's work, not
// the whole rebuild.
//
// If the block recorded at the checkpoint height no longer matches what's
// currently in the canonical chain at that height (i.e. a reorg touched
// blocks at or below the checkpoint since it was last written), the
// checkpoint is discarded and this falls back to a full rebuild from
// genesis — resumption is only ever a performance optimization, never a
// correctness shortcut.
func (bc *Blockchain) RebuildCanonicalReplayEvidence() error {
	if bc.sphincsManager == nil {
		return fmt.Errorf("STHINCS manager is not configured")
	}

	replayEvidenceMu.Lock()
	defer replayEvidenceMu.Unlock()

	bc.lock.RLock()
	chain := append([]*types.Block(nil), bc.chain...)
	bc.lock.RUnlock()

	blockByHeight := make(map[uint64]*types.Block, len(chain))
	for _, block := range chain {
		if block != nil {
			blockByHeight[block.GetHeight()] = block
		}
	}

	startHeight := uint64(0)
	if cp := loadReplayEvidenceCheckpoint(); cp != nil {
		if current, exists := blockByHeight[cp.LastHeight]; exists && current.GetHash() == cp.LastBlockHash {
			startHeight = cp.LastHeight + 1
			logger.Info("RebuildCanonicalReplayEvidence: resuming from checkpoint at height %d", cp.LastHeight)
		} else {
			logger.Warn("RebuildCanonicalReplayEvidence: checkpoint at height %d no longer matches canonical chain (reorg?), doing full rebuild", cp.LastHeight)
		}
	}

	genesisHash := GetGenesisHash()

	for _, block := range chain {
		if block == nil || block.GetHeight() < startHeight {
			continue
		}
		for _, tx := range block.Body.TxsList {
			if tx == nil || tx.IsSystemTransaction() {
				continue
			}
			if err := bc.sphincsManager.VerifyTransactionAuthStateless(
				[]byte(tx.ID),
				transactionAuthTimestamp(tx),
				transactionAuthNonce(tx),
				tx.Signature,
				tx.PublicKey,
				tx.SignatureHash,
				tx.MerkleRootHash,
				tx.Commitment,
				tx.Proof,
			); err != nil {
				return fmt.Errorf("transaction %s stateless auth failed during replay-index rebuild: %w", tx.ID, err)
			}
			if err := bc.sphincsManager.StoreSignatureHash(tx.Signature); err != nil {
				return fmt.Errorf("failed to rebuild signature hash evidence for tx %s: %w", tx.ID, err)
			}
			if err := bc.sphincsManager.StoreTimestampNonce(transactionAuthTimestamp(tx), transactionAuthNonce(tx)); err != nil {
				return fmt.Errorf("failed to rebuild timestamp/nonce evidence for tx %s: %w", tx.ID, err)
			}
			if err := bc.sphincsManager.StoreTransactionReceipt(tx.Commitment, tx.MerkleRootHash, tx.Proof); err != nil {
				return fmt.Errorf("failed to rebuild receipt evidence for tx %s: %w", tx.ID, err)
			}
		}

		// This block's evidence is now fully and durably written — advance
		// the checkpoint before moving to the next block. A failure to save
		// the checkpoint is logged, not fatal: the rebuild's correctness
		// doesn't depend on it, only future calls' ability to skip this
		// block will be affected.
		cp := &replayEvidenceCheckpoint{
			GenesisHash:   genesisHash,
			LastHeight:    block.GetHeight(),
			LastBlockHash: block.GetHash(),
		}
		if err := saveReplayEvidenceCheckpoint(cp); err != nil {
			logger.Warn("RebuildCanonicalReplayEvidence: failed to persist checkpoint at height %d: %v", block.GetHeight(), err)
		}
	}

	return nil
}
