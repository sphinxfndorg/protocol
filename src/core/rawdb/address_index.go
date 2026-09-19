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
//
// One entry is stored per (address, blockHeight, txIndex), under a key that
// carries all three; the value repeats only what the key does not:
//
//	Key:   "addrtx:<address>:<8-byte hex height>:<4-byte hex txIndex>"
//	Value: {"tx_id":...,"sender":...,"receiver":...}
//
// The trailing ':' after the address terminates it, and the fixed-width
// big-endian components make lexicographic key order match height/index
// order — so a reverse, limited scan returns an address's most recent
// activity without reading whole blocks or sorting anything.
type AddressTxEntry struct {
	TxID     string `json:"tx_id"`
	Sender   string `json:"sender"`
	Receiver string `json:"receiver"`
}

// addressTxPrefix and the key builders are defined in scheme.go.

// addressable reports whether addr is worth indexing. An empty address
// would otherwise create a single "addrtx::" key shared by every such
// transaction in the chain.
func addressable(addr string) bool { return addr != "" }

// WriteAddressTxIndex writes address→tx index entries for every
// transaction in the block, for both its sender and its receiver. Called
// from WriteBlock, so the entries land in the same atomic batch as the
// header and body.
func WriteAddressTxIndex(batch *database.WriteBatch, block *types.Block) error {
	height := block.GetHeight()

	for i, tx := range block.Body.TxsList {
		if tx == nil {
			continue
		}
		entry := AddressTxEntry{
			TxID:     tx.ID,
			Sender:   tx.Sender,
			Receiver: tx.Receiver,
		}
		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("rawdb: marshal addrtx entry for tx %s: %w", tx.ID, err)
		}
		if addressable(tx.Sender) {
			batch.Put(addressTxKey(tx.Sender, height, i), data)
		}
		if addressable(tx.Receiver) && tx.Receiver != tx.Sender {
			batch.Put(addressTxKey(tx.Receiver, height, i), data)
		}
	}
	return nil
}

// ReadAddressTxHistory returns up to limit of address's indexed
// transactions, newest first. limit <= 0 returns every entry.
//
// The scan is a single bounded reverse iteration over the address's key
// prefix, so it costs the number of entries actually returned rather than
// the length of the chain. Corrupt entries are skipped rather than aborting
// the whole read; a failure of the underlying scan is returned.
func ReadAddressTxHistory(db *database.DB, address string, limit int) ([]AddressTxEntry, error) {
	if !addressable(address) {
		return nil, fmt.Errorf("rawdb: empty address")
	}

	prefix := addressTxScanPrefix(address)
	entries := make([]AddressTxEntry, 0, 16)
	err := db.IterateEntriesWithPrefixReverse(prefix, func(key string, value []byte) bool {
		// Trust only keys of the exact shape this writer produces. A key
		// left by an older, address-only layout can fall inside this range
		// (e.g. "addrtx:xAlice:something" for an address containing ':'),
		// and its value must not be served as history.
		if len(key) != len(prefix)+addressTxKeySuffixLen {
			return true
		}
		var entry AddressTxEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			return true // skip corrupt entries, keep scanning
		}
		entries = append(entries, entry)
		return limit <= 0 || len(entries) < limit
	})
	if err != nil {
		return nil, fmt.Errorf("rawdb: read addrtx history for %s: %w", address, err)
	}
	return entries, nil
}

// DeleteAddressTxIndex removes every address→tx index entry written for
// block's transactions. It must reconstruct the identical keys
// WriteAddressTxIndex wrote — including the block height and each
// transaction's position — or it would leave orphans behind.
func DeleteAddressTxIndex(batch *database.WriteBatch, block *types.Block) {
	height := block.GetHeight()

	for i, tx := range block.Body.TxsList {
		if tx == nil {
			continue
		}
		if addressable(tx.Sender) {
			batch.Delete(addressTxKey(tx.Sender, height, i))
		}
		if addressable(tx.Receiver) && tx.Receiver != tx.Sender {
			batch.Delete(addressTxKey(tx.Receiver, height, i))
		}
	}
}
