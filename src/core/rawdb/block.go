// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/block.go
package rawdb

import (
	"encoding/json"
	"fmt"

	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// writeBlockBatch populates batch with all entries for block (header, body,
// canonical pointer, height lookup, tx lookups, address→tx index). Shared
// by WriteBlock and any caller that holds its own batch (e.g. StoreBlock
// integrating receipts).
func writeBlockBatch(batch *database.WriteBatch, block *types.Block) error {
	if block == nil || block.Header == nil {
		return fmt.Errorf("rawdb: nil block or header")
	}
	hash := block.GetHash()
	if hash == "" {
		return fmt.Errorf("rawdb: block has empty hash")
	}
	height := block.GetHeight()

	headerJSON, err := json.Marshal(block.Header)
	if err != nil {
		return fmt.Errorf("rawdb: marshal header %s: %w", hash, err)
	}
	batch.Put(headerKey(hash), headerJSON)

	bodyJSON, err := json.Marshal(&block.Body)
	if err != nil {
		return fmt.Errorf("rawdb: marshal body %s: %w", hash, err)
	}
	batch.Put(bodyKey(hash), bodyJSON)

	batch.Put(canonicalKey(height), []byte(hash))
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

	return nil
}

// WriteBlock stores header, body, canonical height→hash, reverse
// hash→height lookup, tx lookup entries, and address→tx index entries
// in a single atomic LevelDB batch. A crash mid-write can never leave
// a header with no matching body, or a canonical pointer to a block
// that was never persisted.
func WriteBlock(db *database.DB, block *types.Block) error {
	if block == nil || block.Header == nil {
		return fmt.Errorf("rawdb: nil block or header")
	}
	hash := block.GetHash()
	if hash == "" {
		return fmt.Errorf("rawdb: block has empty hash")
	}

	batch := db.NewWriteBatch()
	if err := writeBlockBatch(batch, block); err != nil {
		return err
	}
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

// DeleteBlock removes header, body, canonical pointer, height lookup, tx
// lookups, and address→tx entries for the block at hash, atomically.
func DeleteBlock(db *database.DB, hash string) error {
	block, err := ReadBlock(db, hash)
	if err != nil {
		return err
	}
	height := block.GetHeight()

	batch := db.NewWriteBatch()
	batch.Delete(headerKey(hash))
	batch.Delete(bodyKey(hash))
	batch.Delete(canonicalKey(height))
	batch.Delete(heightLookupKey(hash))
	for _, tx := range block.Body.TxsList {
		if tx == nil {
			continue
		}
		batch.Delete(txLookupKey(tx.ID))
	}
	DeleteAddressTxIndex(batch, block)

	if err := batch.Commit(); err != nil {
		return fmt.Errorf("rawdb: delete block %s: %w", hash, err)
	}
	return nil
}
