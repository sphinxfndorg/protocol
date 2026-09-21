// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/block.go
package rawdb

import (
	"encoding/json"
	"fmt"

	"github.com/sphinxfndorg/protocol/src/policy"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// writeBlockBatch populates batch with all entries for block (header, body,
// height lookup, tx lookups, per-transaction payloads, address→tx index,
// per-transaction receipts). Shared by WriteBlock and any caller that holds
// its own batch (e.g. StoreBlock integrating receipts).
//
// The canonical height→hash pointer is deliberately NOT written here. Every
// block store funnels through writeBlockBatch — including losing forks during
// a reorg window, emergency rollbacks that re-persist old blocks, and genesis
// replacement — and an unconditional Put here would let whichever block was
// written last silently claim the height, with no record of the overwrite.
// Canonical ownership is decided by the caller (WriteBlock), which checks the
// existing pointer before staging the batch; see WriteBlock's comment.
//
// Receipts are quoted with the default policy schedule — the same
// deterministic inputs the executor uses (QuoteTransactionGas over the
// ReturnData footprint) — rather than a caller-supplied policy object. This
// keeps rawdb free of a policy dependency on its write path: the only
// production callers are WriteBlock (tests, backfills, genesis, storage
// mirror) and the receipts must agree with consensus regardless of which one
// invoked the write. WriteReceipts' policyParams argument stays explicit so
// the quoting inputs remain visible at the receipt layer itself.
func writeBlockBatch(batch *database.WriteBatch, block *types.Block) error {
	if block == nil || block.Header == nil {
		return fmt.Errorf("rawdb: nil block or header")
	}
	hash := block.GetHash()
	if hash == "" {
		return fmt.Errorf("rawdb: block has empty hash")
	}
	height := block.GetHeight()

	headerJSON, err := json.Marshal(storedHeaderCopy(block.Header))
	if err != nil {
		return fmt.Errorf("rawdb: marshal header %s: %w", hash, err)
	}
	batch.Put(headerKey(hash), headerJSON)

	// The 256-byte filter goes under its own key in raw wire format rather
	// than base64-encoded inside the header JSON.
	if len(block.Header.LogsBloom) > 0 {
		batch.Put(bloomKey(hash), block.Header.LogsBloom)
	}

	bodyJSON, err := json.Marshal(&block.Body)
	if err != nil {
		return fmt.Errorf("rawdb: marshal body %s: %w", hash, err)
	}
	batch.Put(bodyKey(hash), bodyJSON)

	// Canonical pointer is staged by the caller (WriteBlock), not here — see
	// the package comment on writeBlockBatch.
	batch.Put(heightLookupKey(hash), []byte(encodeHeight(height)))

	for i, tx := range block.Body.TxsList {
		if tx == nil {
			continue
		}
		entry := TxLookupEntry{BlockHash: hash, BlockHeight: height, Index: i}
		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("rawdb: marshal tx lookup %s: %w", tx.ID, err)
		}
		batch.Put(txLookupKey(tx.ID), data)
	}

	// Address→tx index: O(1) history lookup per address.
	if err := WriteAddressTxIndex(batch, block); err != nil {
		return fmt.Errorf("rawdb: address index for block %s: %w", hash, err)
	}

	// Per-transaction payloads: O(1) by-ID lookup that does not read the body.
	if err := WriteTxPayloads(batch, block); err != nil {
		return fmt.Errorf("rawdb: tx payloads for block %s: %w", hash, err)
	}

	// Per-transaction receipts: gas-used-per-tx persisted alongside the
	// block so explorers, fee calibration, and disputes have an on-disk
	// record. Same atomic batch as everything above — a crash can never
	// leave a block whose txs have no receipts, or receipts for a block
	// that was never persisted. DeleteBlock mirrors this with
	// DeleteReceipts so reorgs never leak rcpt: keys.
	txIfaces := make([]interface{}, 0, len(block.Body.TxsList))
	for _, tx := range block.Body.TxsList {
		txIfaces = append(txIfaces, tx)
	}
	if err := WriteReceipts(batch, hash, height, txIfaces, policy.GetDefaultPolicyParams()); err != nil {
		return fmt.Errorf("rawdb: receipts for block %s: %w", hash, err)
	}

	return nil
}

// WriteBlock stores header, body, canonical height→hash, reverse
// hash→height lookup, tx lookup entries, per-transaction payloads,
// per-transaction receipts, and address→tx index entries in a single atomic
// LevelDB batch. A crash mid-write can never leave a header with no matching
// body, or a canonical pointer to a block that was never persisted.
//
// Canonical guard: the height→hash pointer is only staged when the height is
// unclaimed or already points at this block's hash. A different hash already
// claiming the height means a fork wrote here first — silently overwriting it
// would make ReadCanonicalHash (and everything built on it: range scans,
// prune walks, sync responses) resolve to whichever fork stored last instead
// of whichever fork won. Re-storing the same block (backfills, genesis
// replacement after DeleteBlock, attestation merges) is idempotent and always
// allowed; Only a *different* hash is refused, with an error naming both
// sides so the caller can decide whether this is a fork to resolve or a bug.
// Height 0 is exempt: ReplaceGenesis deletes the old genesis first, so the
// pointer is unclaimed by the time the new genesis stages its batch.
func WriteBlock(db *database.DB, block *types.Block) error {
	if block == nil || block.Header == nil {
		return fmt.Errorf("rawdb: nil block or header")
	}
	hash := block.GetHash()
	if hash == "" {
		return fmt.Errorf("rawdb: block has empty hash")
	}
	height := block.GetHeight()
	if height != 0 {
		if existing, err := ReadCanonicalHash(db, height); err == nil && existing != "" && existing != hash {
			return fmt.Errorf("rawdb: refusing to overwrite canonical pointer at height %d: claimed by %s, store attempted %s (resolve the fork before writing — see reorganizeChain/RollbackToHeight)",
				height, existing, hash)
		}
	}

	batch := db.NewWriteBatch()
	if err := writeBlockBatch(batch, block); err != nil {
		return err
	}
	// Canonical pointer stages here, after the guard above and inside the
	// same atomic batch as everything else — a crash can never leave a
	// pointer to a block whose body was never persisted.
	batch.Put(canonicalKey(height), []byte(hash))
	if err := batch.Commit(); err != nil {
		return fmt.Errorf("rawdb: commit block %s: %w", hash, err)
	}
	return nil
}

// ReadBlock reconstructs a full block from its header and body. A missing
// body for an existing header — which WriteBlock's atomicity should make
// impossible — is reported as corruption, not a plain not-found.
func ReadBlock(db *database.DB, hash string) (*types.Block, error) {
	header, err := ReadHeader(db, hash)
	if err != nil {
		return nil, err
	}
	body, err := ReadBody(db, hash)
	if err != nil {
		return nil, fmt.Errorf("rawdb: header %s exists but body missing: %w", hash, err)
	}
	return &types.Block{Header: header, Body: *body}, nil
}

// DeleteBlock removes header, body, height lookup, tx lookups,
// per-transaction payloads, receipts, and address→tx entries for the block
// at hash, atomically. Every namespace writeBlockBatch creates is mirrored
// here — including receipts, so a reorg or DeleteBlocksAbove purge can never
// leak rcpt: keys for blocks the index no longer knows about.
//
// The canonical height→hash pointer is deleted only when it still points at
// this block. After a fork resolves, the pointer already belongs to the
// winner; blindly deleting it here would orphan the winning fork's canonical
// entry and leave ReadCanonicalHash resolving to nothing. Height 0 is
// exempt from this check the same way WriteBlock is: ReplaceGenesis deletes
// the old genesis explicitly before writing the new one, and the pointer
// must follow the block being deleted unconditionally in that path.
func DeleteBlock(db *database.DB, hash string) error {
	block, err := ReadBlock(db, hash)
	if err != nil {
		return err
	}
	height := block.GetHeight()

	batch := db.NewWriteBatch()
	batch.Delete(headerKey(hash))
	batch.Delete(bloomKey(hash))
	batch.Delete(bodyKey(hash))
	if height == 0 {
		batch.Delete(canonicalKey(height))
	} else if existing, rerr := ReadCanonicalHash(db, height); rerr != nil || existing == hash {
		// Unclaimed (already purged / never written) or still ours: safe to
		// clear. A different hash means the height has since been reclaimed
		// by the winning fork — leave its pointer alone.
		batch.Delete(canonicalKey(height))
	}
	batch.Delete(heightLookupKey(hash))
	for _, tx := range block.Body.TxsList {
		if tx == nil {
			continue
		}
		batch.Delete(txLookupKey(tx.ID))
	}
	txIfaces := make([]interface{}, 0, len(block.Body.TxsList))
	for _, tx := range block.Body.TxsList {
		txIfaces = append(txIfaces, tx)
	}
	DeleteReceipts(batch, txIfaces)
	DeleteTxPayloads(batch, block)
	DeleteAddressTxIndex(batch, block)

	if err := batch.Commit(); err != nil {
		return fmt.Errorf("rawdb: delete block %s: %w", hash, err)
	}
	return nil
}
