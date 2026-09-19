// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/txlookup.go
package rawdb

import (
	"encoding/json"
	"errors"
	"fmt"

	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// TxLookupEntry records where a transaction lives so a caller can go
// straight from a tx ID to its containing block in O(1), instead of
// GetTransactionHistory's current up-to-1000-block backward scan.
type TxLookupEntry struct {
	BlockHash   string `json:"block_hash"`
	BlockHeight uint64 `json:"block_height"`
	Index       int    `json:"index"` // position within BlockBody.TxsList
}

// WriteTxPayloads stores each transaction's own JSON under "txb:<txID>".
//
// The lookup entry alone can only point at a block, so serving one
// transaction from it means unmarshalling the block's entire body (tens of
// KB for a full block). A transaction's own record is a couple of hundred
// bytes, so this makes a by-ID read one small Get instead of a whole-block
// read. Called from WriteBlock, in the same atomic batch as the body.
func WriteTxPayloads(batch *database.WriteBatch, block *types.Block) error {
	for _, tx := range block.Body.TxsList {
		if tx == nil || tx.ID == "" {
			continue
		}
		data, err := json.Marshal(tx)
		if err != nil {
			return fmt.Errorf("rawdb: marshal tx payload %s: %w", tx.ID, err)
		}
		batch.Put(txBodyKey(tx.ID), data)
	}
	return nil
}

// DeleteTxPayloads removes the payload written for every transaction in
// block. Mirrors WriteTxPayloads so a delete can never leave a payload
// behind for a transaction the block index no longer knows about.
func DeleteTxPayloads(batch *database.WriteBatch, block *types.Block) {
	for _, tx := range block.Body.TxsList {
		if tx == nil || tx.ID == "" {
			continue
		}
		batch.Delete(txBodyKey(tx.ID))
	}
}

// ReadTxPayload returns the transaction stored under its own key. A miss
// means this node has no payload for that ID: a chain written before
// payloads existed, or one whose body has since been pruned. Callers fall
// back to the block-based lookup in that case.
func ReadTxPayload(db *database.DB, txID string) (*types.Transaction, error) {
	if txID == "" {
		return nil, fmt.Errorf("rawdb: empty transaction ID")
	}

	data, err := db.GetQuiet(txBodyKey(txID))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, fmt.Errorf("%w: tx payload %s", ErrNotFound, txID)
		}
		return nil, fmt.Errorf("rawdb: read tx payload %s: %w", txID, err)
	}

	var tx types.Transaction
	if err := json.Unmarshal(data, &tx); err != nil {
		return nil, fmt.Errorf("rawdb: corrupt tx payload %s: %w", txID, err)
	}
	return &tx, nil
}

// WriteTxLookupEntries writes one entry per non-nil transaction in block,
// atomically. Called internally by WriteBlock; also exposed standalone for
// backfilling or reindexing a chain that predates this package.
func WriteTxLookupEntries(db *database.DB, block *types.Block) error {
	if block == nil {
		return fmt.Errorf("rawdb: nil block")
	}
	hash := block.GetHash()
	height := block.GetHeight()

	batch := db.NewWriteBatch()
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
	if err := batch.Commit(); err != nil {
		return fmt.Errorf("rawdb: write tx lookup entries for block %s: %w", hash, err)
	}
	return nil
}

func ReadTxLookupEntry(db *database.DB, txID string) (*TxLookupEntry, error) {
	// Quietly: this is the first thing every transaction lookup tries, and
	// an uncommitted or unknown tx is a miss, not a problem to report.
	data, err := db.GetQuiet(txLookupKey(txID))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, fmt.Errorf("%w: tx %s", ErrNotFound, txID)
		}
		return nil, fmt.Errorf("rawdb: read tx lookup entry %s: %w", txID, err)
	}
	var entry TxLookupEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("rawdb: corrupt tx lookup entry %s: %w", txID, err)
	}
	return &entry, nil
}

func DeleteTxLookupEntries(db *database.DB, block *types.Block) error {
	if block == nil {
		return fmt.Errorf("rawdb: nil block")
	}
	batch := db.NewWriteBatch()
	for _, tx := range block.Body.TxsList {
		if tx == nil {
			continue
		}
		batch.Delete(txLookupKey(tx.ID))
	}
	if err := batch.Commit(); err != nil {
		return fmt.Errorf("rawdb: delete tx lookup entries: %w", err)
	}
	return nil
}
