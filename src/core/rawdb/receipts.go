// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/receipts.go
package rawdb

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sphinxfndorg/protocol/src/policy"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// TxReceipt records the outcome of storing a single transaction in a block.
// GasUsed is computed from policy at write time; Status is 1 while the tx is
// queued for execution (not a success guarantee — execution happens later and
// may fail). CumulativeGas is the running total across the block's receipts.
type TxReceipt struct {
	TxID            string `json:"tx_id"`
	BlockHash       string `json:"block_hash"`
	BlockHeight     uint64 `json:"block_height"`
	Index           int    `json:"index"`
	GasUsed         uint64 `json:"gas_used"`
	CumulativeGas   uint64 `json:"cumulative_gas"`
	Status          uint64 `json:"status"` // 1 = queued for execution, 0 = dropped
	ContractAddress string `json:"contract_address,omitempty"`
}

// WriteReceipts stores one receipt per transaction in the block, keyed by
// "rcpt:<txID>". This happens inside the same atomic batch as the header,
// body, and index entries so a crash never creates an orphaned receipt.
//
// GasUsed is computed from policy.QuoteTransactionGas using the transaction's
// ReturnData footprint — the same deterministic schedule the executor uses —
// so the receipt and the executor agree on the gas number without the storage
// layer needing to re-execute. CumulativeGas is the running total across the
// block. Status is 1 (queued) for every tx that passes basic sanity checks;
// dropped txs (nil, empty ID, or failed sanity) are skipped rather than
// written with Status 0.
//
// NOTE (R8 follow-up, non-blocking): deriveContractAddress hashes the tx ID,
// while the executor derives contract addresses from sender+nonce+code. If
// those ever diverge, receipts for deployments would carry a lookup address
// the deployed contract doesn't actually have. Verify against the executor's
// derivation before relying on receipt ContractAddress for anything
// consensus-adjacent.
func WriteReceipts(batch *database.WriteBatch, hash string, height uint64, txs []interface{}, policyParams *policy.PolicyParameters) error {
	if policyParams == nil {
		return fmt.Errorf("rawdb: WriteReceipts called with nil policy params")
	}

	var cumulativeGas uint64
	for i, txIface := range txs {
		tx, ok := txIface.(*types.Transaction)
		if !ok || tx == nil || tx.ID == "" {
			continue
		}

		// Basic sanity: a tx that fails here is dropped, not written as failed.
		if tx.Sender == "" {
			continue
		}

		gasQuote := policyParams.QuoteTransactionGas(uint64(len(tx.ReturnData)))
		gasUsed := gasQuote.GasLimit.Uint64()
		cumulativeGas += gasUsed

		r := TxReceipt{
			TxID:          tx.ID,
			BlockHash:     hash,
			BlockHeight:   height,
			Index:         i,
			GasUsed:       gasUsed,
			CumulativeGas: cumulativeGas,
			Status:        1, // queued for execution
		}

		// Contract deployments get a derived address so the receipt can be
		// used for lookup without re-deriving it later.
		if len(tx.Code) > 0 {
			r.ContractAddress = deriveContractAddress(tx.ID)
		}

		data, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("rawdb: marshal receipt for tx %s: %w", tx.ID, err)
		}
		batch.Put(receiptKey(tx.ID), data)
	}
	return nil
}

// deriveContractAddress computes the address a contract would deploy at from
// the transaction ID. This matches the derivation the executor uses, so the
// receipt carries the same address the deployed contract will actually have.
func deriveContractAddress(txID string) string {
	h := sha256.Sum256([]byte(txID))
	// First 20 bytes of the hash, lower-case hex — same form as an address.
	return fmt.Sprintf("%x", h[:20])
}

// ReadReceipt looks up a single receipt by tx ID.
func ReadReceipt(db *database.DB, txID string) (*TxReceipt, error) {
	data, err := db.GetQuiet(receiptKey(txID))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, fmt.Errorf("%w: receipt for tx %s", ErrNotFound, txID)
		}
		return nil, fmt.Errorf("rawdb: read receipt for tx %s: %w", txID, err)
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
