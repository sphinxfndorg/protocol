// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package pool

import (
	"math/big"
	"testing"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// pooledPendingTx builds a pendingPool entry with the given validated marker.
func pooledPendingTx(id string, validated bool) *PooledTransaction {
	return &PooledTransaction{
		Transaction: &types.Transaction{
			ID:       id,
			Sender:   "SPIF00112233445566778899AABBCCDDEEFF00112233",
			Receiver: "SPIF11223344556677889900AABBCCDDEEFF1122334455",
			Amount:   big.NewInt(1),
		},
		Status:    StatusPending,
		Validated: validated,
	}
}

func pooledTxIDs(txs []*types.Transaction) []string {
	ids := make([]string, 0, len(txs))
	for _, tx := range txs {
		ids = append(ids, tx.ID)
	}
	return ids
}

// TestOnlyValidatedPendingTxsAreMineable: pendingPool holds both fully
// validated transactions and ones parked there while validationChan was full.
// Only the validated ones may reach a block.
func TestOnlyValidatedPendingTxsAreMineable(t *testing.T) {
	mp := &Mempool{pendingPool: map[string]*PooledTransaction{
		"validated": pooledPendingTx("validated", true),
		"parked":    pooledPendingTx("parked", false),
	}}

	got := mp.GetPendingTransactions()
	if len(got) != 1 || got[0].ID != "validated" {
		t.Fatalf("GetPendingTransactions must return only validated txs, got %v", pooledTxIDs(got))
	}

	sel, _ := mp.SelectTransactionsForBlock(1<<20, 1<<20)
	if len(sel) != 1 || sel[0].ID != "validated" {
		t.Fatalf("block selection must exclude unvalidated txs, got %v", pooledTxIDs(sel))
	}
}

// TestDrainPendingPoolDoesNotChurnValidatedTxs guards the "0 pending tx"
// regression: drainPendingPool used to remove and re-validate EVERY pending
// transaction on each 500ms tick, so an already-validated transaction kept
// vanishing from the pendingPool the block producer reads — the producer
// logged "Mempool pendingPool empty ... pending=0" and shipped empty blocks
// forever while a perfectly valid broadcast anchor sat in the mempool.
func TestDrainPendingPoolDoesNotChurnValidatedTxs(t *testing.T) {
	mp := &Mempool{
		pendingPool: map[string]*PooledTransaction{
			"validated": pooledPendingTx("validated", true),
			"parked":    pooledPendingTx("parked", false),
		},
		validationChan: make(chan *PooledTransaction, 4),
	}

	mp.drainPendingPool()

	if _, ok := mp.pendingPool["validated"]; !ok {
		t.Fatal("drainPendingPool must leave validated pending txs mineable")
	}
	if _, ok := mp.pendingPool["parked"]; ok {
		t.Fatal("drainPendingPool must re-queue the unvalidated parked tx")
	}
	if len(mp.validationChan) != 1 {
		t.Fatalf("parked tx must be queued for validation, chan len=%d", len(mp.validationChan))
	}
	if got := mp.GetPendingTransactions(); len(got) != 1 || got[0].ID != "validated" {
		t.Fatalf("validated tx must still be mineable after a drain, got %v", pooledTxIDs(got))
	}
}

// TestRepeatedDrainsAreIdempotentForValidatedTxs: the validation ticker fires
// every 500ms forever, so a validated transaction must survive an arbitrary
// number of drains without ever leaving the mineable pool.
func TestRepeatedDrainsAreIdempotentForValidatedTxs(t *testing.T) {
	mp := &Mempool{
		pendingPool:    map[string]*PooledTransaction{"validated": pooledPendingTx("validated", true)},
		validationChan: make(chan *PooledTransaction, 4),
	}
	for i := 0; i < 10; i++ {
		mp.drainPendingPool()
		if len(mp.pendingPool) != 1 || len(mp.validationChan) != 0 {
			t.Fatalf("drain %d disturbed a validated pending tx (pending=%d chan=%d)",
				i, len(mp.pendingPool), len(mp.validationChan))
		}
	}
}
