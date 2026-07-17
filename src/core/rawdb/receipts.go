// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/receipts.go
package rawdb

import (
	"encoding/json"
	"fmt"

	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// TxReceipt records the outcome of executing a single transaction.
// This is a minimal structure — fields will be extended when the
// execution loop actually tracks per-tx gas/status. For now the
// storage layer exists so the keyspace is reserved and the write
// path can be wired into StoreBlock without blocking on the
// executor changes described in §7 of the spec.
type TxReceipt struct {
	TxID            string `json:"tx_id"`
	BlockHash       string `json:"block_hash"`
	BlockHeight     uint64 `json:"block_height"`
	Index           int    `json:"index"`
	GasUsed         uint64 `json:"gas_used"`
	CumulativeGas   uint64 `json:"cumulative_gas"`
	Status          uint64 `json:"status"` // 1 = success, 0 = failure
	ContractAddress string `json:"contract_address,omitempty"`
}

// WriteReceipts stores one receipt per transaction in the block, keyed by
// "rcpt:<txID>". This happens inside the same atomic batch as the header,
// body, and index entries so a crash never creates an orphaned receipt.
func WriteReceipts(batch *database.WriteBatch, hash string, height uint64, txs []interface{}) error {
	// txs is []interface{} to avoid a circular import with the
	// transaction package. In practice the caller passes []*types.Transaction
	// (or an empty slice when wiring receipts into StoreBlock before the
	// executor tracks per-tx results).
	_ = hash
	_ = height

	// Currently a no-op for per-tx receipts because the execution loop
	// does not yet produce per-tx gas/status. When it does, this function
	// will write one entry per tx.
	//
	// For now, expand this when executor.go starts tracking receipt data:
	//
	//   for i, txIface := range txs {
	//       tx, ok := txIface.(*types.Transaction)
	//       if !ok || tx == nil || tx.ID == "" {
	//           continue
	//       }
	//       // GasUsed, Status etc. come from the executor, not from the tx.
	//       // Those values are passed in separately — this is just a placeholder.
	//       r := TxReceipt{
	//           TxID:        tx.ID,
	//           BlockHash:   hash,
	//           BlockHeight: height,
	//           Index:       i,
	//           GasUsed:     0,      // placeholder
	//           CumulativeGas: 0,    // placeholder
	//           Status:      1,      // placeholder (assume success)
	//       }
	//       data, _ := json.Marshal(r)
	//       batch.Put(receiptKey(tx.ID), data)
	//   }
	return nil
}

// ReadReceipt looks up a single receipt by tx ID.
func ReadReceipt(db *database.DB, txID string) (*TxReceipt, error) {
	data, err := db.Get(receiptKey(txID))
	if err != nil {
		return nil, fmt.Errorf("%w: receipt for tx %s", ErrNotFound, txID)
	}
	var r TxReceipt
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("rawdb: corrupt receipt for tx %s: %w", txID, err)
	}
	return &r, nil
}

// DeleteReceipts removes one receipt entry per transaction in the block.
func DeleteReceipts(batch *database.WriteBatch, txs []interface{}) {
	for _, txIface := range txs {
		tx, ok := txIface.(*types.Transaction)
		if !ok || tx == nil || tx.ID == "" {
			continue
		}
		batch.Delete(receiptKey(tx.ID))
	}
}
