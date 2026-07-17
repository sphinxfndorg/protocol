// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/txlookup.go
package rawdb

import (
	"encoding/json"
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
	data, err := db.Get(txLookupKey(txID))
	if err != nil {
		return nil, fmt.Errorf("%w: tx %s", ErrNotFound, txID)
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
