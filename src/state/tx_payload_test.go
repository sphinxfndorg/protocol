// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/state/tx_payload_test.go
package state

import (
	"errors"
	"testing"

	"github.com/sphinxfndorg/protocol/src/core/rawdb"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// TestGetTransactionResolvesFromPayloadWithoutTheBody proves the payload
// key is what serves the read, and is not just a redundant copy of the body
// path: the body is deleted first, so the lookup→block path cannot work, and
// the in-memory maps are empty, so the legacy scan cannot either.
func TestGetTransactionResolvesFromPayloadWithoutTheBody(t *testing.T) {
	h := newCrashTestHarness(t)

	tx := makeSimpleTx("tx-payload-only", "xAlice", "xBob", 5)
	block := makeBlock(1, nil, []*types.Transaction{tx})

	if err := rawdb.WriteBlock(h.db, block); err != nil {
		t.Fatalf("WriteBlock: %v", err)
	}
	if err := rawdb.DeleteBody(h.db, block.GetHash()); err != nil {
		t.Fatalf("DeleteBody: %v", err)
	}

	// The body-based paths are genuinely unusable now.
	if _, err := rawdb.ReadBlock(h.db, block.GetHash()); err == nil {
		t.Fatal("ReadBlock unexpectedly succeeded after the body was deleted")
	}

	got, err := h.store.GetTransaction(tx.ID)
	if err != nil {
		t.Fatalf("GetTransaction: %v — the payload key should have resolved it", err)
	}
	if got.ID != tx.ID || got.Sender != tx.Sender || got.Receiver != tx.Receiver {
		t.Fatalf("resolved tx = %+v, want id/sender/receiver from %+v", got, tx)
	}
}

// TestGetTransactionFallsBackForPayloadLessData reproduces a node whose
// chain was written before payloads existed: header, body and lookup entry
// are present, the payload key is not. The block-based path must still
// resolve the transaction, so an un-migrated node does not regress.
func TestGetTransactionFallsBackForPayloadLessData(t *testing.T) {
	h := newCrashTestHarness(t)

	tx := makeSimpleTx("tx-legacy", "xAlice", "xBob", 7)
	block := makeBlock(1, nil, []*types.Transaction{tx})

	if err := rawdb.WriteHeader(h.db, block.Header); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if err := rawdb.WriteBody(h.db, block.GetHash(), &block.Body); err != nil {
		t.Fatalf("WriteBody: %v", err)
	}
	if err := rawdb.WriteTxLookupEntries(h.db, block); err != nil {
		t.Fatalf("WriteTxLookupEntries: %v", err)
	}

	// Confirm the fixture really is payload-less.
	if _, err := rawdb.ReadTxPayload(h.db, tx.ID); !errors.Is(err, rawdb.ErrNotFound) {
		t.Fatalf("fixture unexpectedly has a payload for %s: %v", tx.ID, err)
	}

	got, err := h.store.GetTransaction(tx.ID)
	if err != nil {
		t.Fatalf("GetTransaction: %v — the block-based fallback should have resolved it", err)
	}
	if got.ID != tx.ID {
		t.Fatalf("resolved tx ID = %q, want %q", got.ID, tx.ID)
	}
}

func TestGetTransactionUnknownIDIsNotFound(t *testing.T) {
	h := newCrashTestHarness(t)

	if _, err := h.store.GetTransaction("tx-never-existed"); err == nil {
		t.Fatal("GetTransaction for an unknown ID returned no error")
	}
}

// TestGetTransactionPayloadRemovedWithBlock checks the payload is deleted
// alongside the block it belongs to, so a rolled-back block cannot keep
// answering by-ID lookups.
func TestGetTransactionPayloadRemovedWithBlock(t *testing.T) {
	h := newCrashTestHarness(t)

	tx := makeSimpleTx("tx-rolled-back", "xAlice", "xBob", 9)
	block := makeBlock(1, nil, []*types.Transaction{tx})

	if err := rawdb.WriteBlock(h.db, block); err != nil {
		t.Fatalf("WriteBlock: %v", err)
	}
	if _, err := h.store.GetTransaction(tx.ID); err != nil {
		t.Fatalf("GetTransaction before delete: %v", err)
	}

	if err := rawdb.DeleteBlock(h.db, block.GetHash()); err != nil {
		t.Fatalf("DeleteBlock: %v", err)
	}

	if _, err := h.store.GetTransaction(tx.ID); err == nil {
		t.Fatal("GetTransaction still resolves a transaction whose block was deleted")
	}
}
