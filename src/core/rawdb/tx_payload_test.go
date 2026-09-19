// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/tx_payload_test.go
package rawdb

import (
	"errors"
	"math/big"
	"testing"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

func payloadTx(id, sender, receiver string) *types.Transaction {
	return &types.Transaction{
		ID:        id,
		Sender:    sender,
		Receiver:  receiver,
		Amount:    big.NewInt(1234),
		Timestamp: 1712345678,
		GasPrice:  big.NewInt(7),
	}
}

func TestReadTxPayloadRoundTrip(t *testing.T) {
	db := newTestDB(t)
	tx := payloadTx("tx-payload", "xAlice", "xBob")
	mustWriteBlock(t, db, testBlock(1, tx))

	got, err := ReadTxPayload(db, tx.ID)
	if err != nil {
		t.Fatalf("ReadTxPayload: %v", err)
	}
	if got.ID != tx.ID || got.Sender != tx.Sender || got.Receiver != tx.Receiver {
		t.Fatalf("payload = %+v, want id/sender/receiver from %+v", got, tx)
	}
	if got.Amount == nil || got.Amount.Cmp(tx.Amount) != 0 {
		t.Fatalf("payload amount = %v, want %v", got.Amount, tx.Amount)
	}
	if got.Timestamp != tx.Timestamp {
		t.Fatalf("payload timestamp = %d, want %d", got.Timestamp, tx.Timestamp)
	}
	if got.Nonce != tx.Nonce {
		t.Fatalf("payload nonce = %d, want %d", got.Nonce, tx.Nonce)
	}
	if got.GasPrice == nil || got.GasPrice.Cmp(tx.GasPrice) != 0 {
		t.Fatalf("payload gas price = %v, want %v", got.GasPrice, tx.GasPrice)
	}
}

func TestReadTxPayloadMissingIsErrNotFound(t *testing.T) {
	db := newTestDB(t)

	_, err := ReadTxPayload(db, "tx-unknown")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadTxPayload on a missing key returned %v, want ErrNotFound", err)
	}
}

func TestReadTxPayloadEmptyIDIsRejected(t *testing.T) {
	db := newTestDB(t)

	if _, err := ReadTxPayload(db, ""); err == nil {
		t.Fatal("ReadTxPayload with an empty ID returned no error")
	}
}

// TestTxPayloadSurvivesBodyDeletion is the point of the separate key: a
// transaction stays resolvable by ID without its block body. That is what
// makes a by-ID read cheap, and what keeps it working after pruning.
func TestTxPayloadSurvivesBodyDeletion(t *testing.T) {
	db := newTestDB(t)
	tx := payloadTx("tx-survivor", "xAlice", "xBob")
	block := testBlock(1, tx)
	mustWriteBlock(t, db, block)

	if err := DeleteBody(db, block.GetHash()); err != nil {
		t.Fatalf("DeleteBody: %v", err)
	}
	if HasBody(db, block.GetHash()) {
		t.Fatal("body still present after DeleteBody")
	}

	got, err := ReadTxPayload(db, tx.ID)
	if err != nil {
		t.Fatalf("ReadTxPayload after body deletion: %v", err)
	}
	if got.ID != tx.ID {
		t.Fatalf("payload ID = %q, want %q", got.ID, tx.ID)
	}

	// The block-based path is now unusable, which is exactly why the
	// payload path exists.
	if _, err := ReadBlock(db, block.GetHash()); err == nil {
		t.Fatal("ReadBlock unexpectedly succeeded after the body was deleted")
	}
}

func TestWriteBlockWritesPayloadForEveryTx(t *testing.T) {
	db := newTestDB(t)
	block := testBlock(2,
		payloadTx("tx-one", "xAlice", "xBob"),
		payloadTx("tx-two", "xBob", "xCarol"),
	)
	mustWriteBlock(t, db, block)

	keys, err := db.ListKeysWithPrefix(txBodyPrefix)
	if err != nil {
		t.Fatalf("ListKeysWithPrefix: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 tx payload keys, got %d: %v", len(keys), keys)
	}

	for _, id := range []string{"tx-one", "tx-two"} {
		if _, err := ReadTxPayload(db, id); err != nil {
			t.Fatalf("ReadTxPayload(%s): %v", id, err)
		}
	}
}

func TestWriteTxPayloadsSkipsNilAndEmptyIDs(t *testing.T) {
	db := newTestDB(t)
	mustWriteBlock(t, db, testBlock(1, nil, payloadTx("", "xAlice", "xBob"), payloadTx("tx-real", "xBob", "xCarol")))

	keys, err := db.ListKeysWithPrefix(txBodyPrefix)
	if err != nil {
		t.Fatalf("ListKeysWithPrefix: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected only the one named transaction to get a payload, got %v", keys)
	}
}

func TestDeleteBlockRemovesTxPayloads(t *testing.T) {
	db := newTestDB(t)
	block := testBlock(1, payloadTx("tx-gone", "xAlice", "xBob"))
	mustWriteBlock(t, db, block)

	if err := DeleteBlock(db, block.GetHash()); err != nil {
		t.Fatalf("DeleteBlock: %v", err)
	}

	if _, err := ReadTxPayload(db, "tx-gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("payload survived DeleteBlock: %v", err)
	}
	keys, err := db.ListKeysWithPrefix(txBodyPrefix)
	if err != nil {
		t.Fatalf("ListKeysWithPrefix: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("DeleteBlock left payload keys behind: %v", keys)
	}
}

// TestTxPayloadIsSmallerThanTheBody records the actual win: the payload is
// one transaction, not the whole block.
func TestTxPayloadIsSmallerThanTheBody(t *testing.T) {
	db := newTestDB(t)

	txs := make([]*types.Transaction, 0, 200)
	for i := 0; i < 200; i++ {
		txs = append(txs, payloadTx(
			"tx-"+string(rune('a'+i%26))+string(rune('a'+i/26)),
			"xSender",
			"xReceiver",
		))
	}
	block := testBlock(1, txs...)
	mustWriteBlock(t, db, block)

	payload, err := db.GetQuiet(txBodyKey(txs[0].ID))
	if err != nil {
		t.Fatalf("GetQuiet payload: %v", err)
	}
	body, err := db.GetQuiet(bodyKey(block.GetHash()))
	if err != nil {
		t.Fatalf("GetQuiet body: %v", err)
	}

	if len(payload) >= len(body) {
		t.Fatalf("payload is %d bytes and the body %d — the payload should be far smaller",
			len(payload), len(body))
	}
	t.Logf("200-tx block: body %d bytes, single-tx payload %d bytes (%.1fx smaller)",
		len(body), len(payload), float64(len(body))/float64(len(payload)))
}
