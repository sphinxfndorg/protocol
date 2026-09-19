// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/state_db_history_test.go
package core

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/sphinxfndorg/protocol/src/core/rawdb"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	storage "github.com/sphinxfndorg/protocol/src/state"
)

// shortAddress must tolerate addresses shorter than its trim width; the
// inline slice it replaced panicked on anything under 16 characters, and
// addresses arrive from RPC callers.
func TestShortAddressHandlesShortInput(t *testing.T) {
	for _, address := range []string{"", "a", "xAlice", "0123456789abcdef", "0123456789abcdef0"} {
		got := func() (out string) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("shortAddress(%q) panicked: %v", address, r)
				}
			}()
			return shortAddress(address)
		}()

		if len(address) <= 16 && got != address {
			t.Fatalf("shortAddress(%q) = %q, want it unchanged", address, got)
		}
		if len(address) > 16 && got == address {
			t.Fatalf("shortAddress(%q) = %q, want it trimmed", address, got)
		}
	}
}

// hexHashFor returns a 64-character hex hash for height h, which
// Block.GetHash passes through unchanged.
func hexHashFor(h uint64) string {
	const hexDigits = "0123456789abcdef"
	buf := make([]byte, 64)
	for i := 63; i >= 0; i-- {
		buf[i] = hexDigits[h&0xf]
		h >>= 4
	}
	return string(buf)
}

func txIDAt(height uint64) string { return fmt.Sprintf("tx-%016x", height) }

// newHistoryTestStateDB builds a StateDB wired to a real Storage over a
// throwaway LevelDB, with `blocks` blocks written through rawdb.
func newHistoryTestStateDB(t *testing.T, blocks int, txsAt map[uint64]*types.Transaction) *StateDB {
	t.Helper()

	dir := t.TempDir()
	db, err := database.NewLevelDB(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatalf("NewLevelDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	st, err := storage.NewStorage(filepath.Join(dir, "node"))
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	st.SetDB(db)

	for h := uint64(1); h <= uint64(blocks); h++ {
		var txs []*types.Transaction
		if tx := txsAt[h]; tx != nil {
			txs = append(txs, tx)
		}
		block := &types.Block{
			Header: &types.BlockHeader{Hash: []byte(hexHashFor(h)), Block: h, Height: h},
			Body:   types.BlockBody{TxsList: txs},
		}
		if err := rawdb.WriteBlock(db, block); err != nil {
			t.Fatalf("WriteBlock(%d): %v", h, err)
		}
	}

	s := NewStateDB(db)
	s.SetBlockchain(&Blockchain{storage: st})
	return s
}

// TestGetTransactionHistoryFindsActivityOlderThanScanWindow pins the
// correctness gap the index closes: xAlice's only transaction sits at
// height 1 while the chain runs to 1100, so the old newest-to-oldest walk
// (capped at 1000 blocks) never reached it and reported no history at all.
func TestGetTransactionHistoryFindsActivityOlderThanScanWindow(t *testing.T) {
	const blocks = 1100

	ancient := &types.Transaction{
		ID:        txIDAt(1),
		Sender:    "xAlice",
		Receiver:  "xBob",
		Timestamp: 1,
	}

	s := newHistoryTestStateDB(t, blocks, map[uint64]*types.Transaction{1: ancient})

	history, err := s.GetTransactionHistory("xAlice", 20)
	if err != nil {
		t.Fatalf("GetTransactionHistory: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("history has %d entries, want 1 (the height-1 transaction)", len(history))
	}
	if history[0].ID != ancient.ID {
		t.Fatalf("history[0].ID = %q, want %q", history[0].ID, ancient.ID)
	}
}

// TestGetTransactionHistoryReturnsNewestFirst checks ordering and the
// receiver side of the index through the public API.
func TestGetTransactionHistoryReturnsNewestFirst(t *testing.T) {
	const blocks = 20

	txsByHeight := make(map[uint64]*types.Transaction, blocks)
	for h := uint64(1); h <= blocks; h++ {
		txsByHeight[h] = &types.Transaction{
			ID:        txIDAt(h),
			Sender:    "xCarol",
			Receiver:  "xAlice",
			Timestamp: int64(h),
		}
	}

	s := newHistoryTestStateDB(t, blocks, txsByHeight)

	history, err := s.GetTransactionHistory("xAlice", 3)
	if err != nil {
		t.Fatalf("GetTransactionHistory: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("history has %d entries, want 3", len(history))
	}
	for i, want := range []uint64{20, 19, 18} {
		if history[i].ID != txIDAt(want) {
			t.Fatalf("history[%d].ID = %q, want %q", i, history[i].ID, txIDAt(want))
		}
	}
}

// TestGetTransactionHistoryEmptyAddress confirms the guard survives the
// rewrite.
func TestGetTransactionHistoryEmptyAddress(t *testing.T) {
	s := newHistoryTestStateDB(t, 1, nil)

	if _, err := s.GetTransactionHistory("", 20); err == nil {
		t.Fatal("GetTransactionHistory with an empty address returned no error")
	}
}

// TestGetTransactionHistoryUnknownAddressIsEmpty checks the fallback path
// does not invent history for an address with none.
func TestGetTransactionHistoryUnknownAddressIsEmpty(t *testing.T) {
	s := newHistoryTestStateDB(t, 5, nil)

	history, err := s.GetTransactionHistory("xNobody", 20)
	if err != nil {
		t.Fatalf("GetTransactionHistory: %v", err)
	}
	if len(history) != 0 {
		t.Fatalf("history for an unknown address has %d entries, want 0", len(history))
	}
}
