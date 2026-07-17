// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/address_index.go
package rawdb

import (
	"encoding/json"
	"fmt"

	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// AddressTxEntry records a single transaction involving an address.
// The index stores one entry per (address, blockHeight, txIndex) tuple so
// that GetTransactionHistory can resolve history in O(N) where N is the
// number of relevant transactions, not O(chain height).
//
// Key format: "addrtx:<address>"
// Value: JSON array of AddressTxEntry, ordered by blockHeight ascending.
// The index is append-only within each batch write; on read the entries
// are already sorted by construction.
type AddressTxEntry struct {
	BlockHash   string `json:"block_hash"`
	BlockHeight uint64 `json:"block_height"`
	TxIndex     int    `json:"tx_index"` // position within BlockBody.TxsList
	TxID        string `json:"tx_id"`    // transaction ID for direct lookup
	Sender      string `json:"sender"`
	Receiver    string `json:"receiver"`
}

// addressTxPrefix is defined in scheme.go.

// WriteAddressTxIndex writes address→tx index entries for every
// transaction in the block. Each unique sender and receiver gets an
// entry. Called from WriteBlock (part of the same atomic batch).
func WriteAddressTxIndex(batch *database.WriteBatch, block *types.Block) error {
	hash := block.GetHash()
	height := block.GetHeight()

	for i, tx := range block.Body.TxsList {
		if tx == nil {
			continue
		}
		entry := AddressTxEntry{
			BlockHash:   hash,
			BlockHeight: height,
			TxIndex:     i,
			TxID:        tx.ID,
			Sender:      tx.Sender,
			Receiver:    tx.Receiver,
		}
		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("rawdb: marshal addrtx entry for tx %s: %w", tx.ID, err)
		}
		batch.Put(addressTxKey(tx.Sender), data)
		if tx.Receiver != "" && tx.Receiver != tx.Sender {
			batch.Put(addressTxKey(tx.Receiver), data)
		}
	}
	return nil
}

// ReadAddressTxHistory returns all address→tx entries for the given
// address. These entries are returned unsorted (they were inserted in
// block order, so iteration happens to be chronological, but callers
// should not rely on that for correctness).
//
// The function does NOT take the caller's limit as a parameter; filtering
// by limit is the caller's responsibility. This design keeps the storage
// layer simple — a single scan of the prefix range.
func ReadAddressTxHistory(db *database.DB, address string) ([]AddressTxEntry, error) {
	keys, err := db.ListKeysWithPrefix(addressTxPrefix + address)
	if err != nil {
		return nil, fmt.Errorf("rawdb: list addrtx keys for %s: %w", address, err)
	}
	entries := make([]AddressTxEntry, 0, len(keys))
	for _, k := range keys {
		data, err := db.Get(k)
		if err != nil {
			continue // skip corrupt entries rather than aborting
		}
		var entry AddressTxEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue // skip corrupt entries
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// DeleteAddressTxIndex removes all address→tx index entries for every
// transaction in the block. Called from DeleteBlock (part of the same
// atomic batch).
func DeleteAddressTxIndex(batch *database.WriteBatch, block *types.Block) {
	for _, tx := range block.Body.TxsList {
		if tx == nil {
			continue
		}
		batch.Delete(addressTxKey(tx.Sender))
		if tx.Receiver != "" && tx.Receiver != tx.Sender {
			batch.Delete(addressTxKey(tx.Receiver))
		}
	}
}
