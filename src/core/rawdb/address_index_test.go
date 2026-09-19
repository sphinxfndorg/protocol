// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/address_index_test.go
package rawdb

import (
	"fmt"
	"strings"
	"testing"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// aliceBlock is a block holding two transactions sent by xAlice, one to
// xBob and one to xCarol.
func aliceBlock(height uint64) *types.Block {
	return testBlock(height,
		testTx(fmt.Sprintf("tx-%d-a", height), "xAlice", "xBob"),
		testTx(fmt.Sprintf("tx-%d-b", height), "xAlice", "xCarol"),
	)
}

func entryIDs(entries []AddressTxEntry) []string {
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.TxID)
	}
	return ids
}

func TestAddressTxHistoryAccumulates(t *testing.T) {
	db := newTestDB(t)

	const blocks = 3
	for h := uint64(1); h <= blocks; h++ {
		mustWriteBlock(t, db, aliceBlock(h))
	}

	// Two transactions per block, for every block: the old address-only key
	// meant each block overwrote the previous block's entry, so this
	// returned one entry instead of six.
	history, err := ReadAddressTxHistory(db, "xAlice", 0)
	if err != nil {
		t.Fatalf("ReadAddressTxHistory: %v", err)
	}
	if len(history) != blocks*2 {
		t.Fatalf("history has %d entries, want %d: %v", len(history), blocks*2, entryIDs(history))
	}
}

func TestAddressTxHistoryIsNewestFirst(t *testing.T) {
	db := newTestDB(t)

	for h := uint64(1); h <= 3; h++ {
		mustWriteBlock(t, db, aliceBlock(h))
	}

	history, err := ReadAddressTxHistory(db, "xAlice", 0)
	if err != nil {
		t.Fatalf("ReadAddressTxHistory: %v", err)
	}

	want := []string{"tx-3-b", "tx-3-a", "tx-2-b", "tx-2-a", "tx-1-b", "tx-1-a"}
	got := entryIDs(history)
	if len(got) != len(want) {
		t.Fatalf("history = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("history = %v, want %v", got, want)
		}
	}
}

func TestAddressTxHistoryLimit(t *testing.T) {
	db := newTestDB(t)

	for h := uint64(1); h <= 5; h++ {
		mustWriteBlock(t, db, aliceBlock(h))
	}

	history, err := ReadAddressTxHistory(db, "xAlice", 3)
	if err != nil {
		t.Fatalf("ReadAddressTxHistory: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("limit 3 returned %d entries: %v", len(history), entryIDs(history))
	}

	// The limited read must be the newest three, not an arbitrary three.
	want := []string{"tx-5-b", "tx-5-a", "tx-4-b"}
	for i, id := range want {
		if history[i].TxID != id {
			t.Fatalf("limit 3 returned %v, want %v", entryIDs(history), want)
		}
	}
}

// TestAddressTxHistoryExcludesLongerAddresses covers the prefix-collision
// bug: scanning "addrtx:xAlice" also matched "addrtx:xAlice2" because
// nothing terminated the address.
func TestAddressTxHistoryExcludesLongerAddresses(t *testing.T) {
	db := newTestDB(t)

	mustWriteBlock(t, db, aliceBlock(1))
	mustWriteBlock(t, db, testBlock(2,
		testTx("tx-2-other", "xAlice2", "xDave"),
		testTx("tx-2-legit", "xAlice", "xDave"),
	))

	history, err := ReadAddressTxHistory(db, "xAlice", 0)
	if err != nil {
		t.Fatalf("ReadAddressTxHistory: %v", err)
	}

	for _, e := range history {
		if strings.HasPrefix(e.Sender, "xAlice2") || strings.HasPrefix(e.Receiver, "xAlice2") {
			t.Fatalf("xAlice history leaked an entry belonging to xAlice2: %+v", e)
		}
	}

	other, err := ReadAddressTxHistory(db, "xAlice2", 0)
	if err != nil {
		t.Fatalf("ReadAddressTxHistory(xAlice2): %v", err)
	}
	if len(other) != 1 || other[0].TxID != "tx-2-other" {
		t.Fatalf("xAlice2 history = %v, want [tx-2-other]", entryIDs(other))
	}
}

func TestAddressTxHistoryIndexesReceiver(t *testing.T) {
	db := newTestDB(t)
	mustWriteBlock(t, db, aliceBlock(1))

	bob, err := ReadAddressTxHistory(db, "xBob", 0)
	if err != nil {
		t.Fatalf("ReadAddressTxHistory(xBob): %v", err)
	}
	if len(bob) != 1 || bob[0].TxID != "tx-1-a" {
		t.Fatalf("xBob history = %v, want [tx-1-a]", entryIDs(bob))
	}
	if bob[0].Sender != "xAlice" || bob[0].Receiver != "xBob" {
		t.Fatalf("xBob entry lost its addresses: %+v", bob[0])
	}
}

func TestAddressTxHistorySkipsEmptyAddresses(t *testing.T) {
	db := newTestDB(t)

	mustWriteBlock(t, db, testBlock(1, testTx("tx-no-address", "", "")))

	keys, err := db.ListKeysWithPrefix(addressTxPrefix)
	if err != nil {
		t.Fatalf("ListKeysWithPrefix: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("a transaction with an empty sender/receiver created keys: %v", keys)
	}
}

func TestAddressTxHistoryEmptyAddressIsRejected(t *testing.T) {
	db := newTestDB(t)

	if _, err := ReadAddressTxHistory(db, "", 0); err == nil {
		t.Fatal("ReadAddressTxHistory with an empty address returned no error")
	}
}

func TestDeleteAddressTxIndexRemovesEveryKey(t *testing.T) {
	db := newTestDB(t)

	block := aliceBlock(1)
	mustWriteBlock(t, db, block)

	if err := DeleteBlock(db, block.GetHash()); err != nil {
		t.Fatalf("DeleteBlock: %v", err)
	}

	// Every key written for the block must be gone — a mismatch between the
	// write and delete key schemes would leave orphans behind, which the
	// old address-only keys did (they also deleted other blocks' entries).
	keys, err := db.ListKeysWithPrefix(addressTxPrefix)
	if err != nil {
		t.Fatalf("ListKeysWithPrefix: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("DeleteBlock left %d address index keys behind: %v", len(keys), keys)
	}
}

func TestDeleteAddressTxIndexLeavesOtherBlocks(t *testing.T) {
	db := newTestDB(t)

	first := aliceBlock(1)
	second := aliceBlock(2)
	mustWriteBlock(t, db, first)
	mustWriteBlock(t, db, second)

	if err := DeleteBlock(db, first.GetHash()); err != nil {
		t.Fatalf("DeleteBlock: %v", err)
	}

	history, err := ReadAddressTxHistory(db, "xAlice", 0)
	if err != nil {
		t.Fatalf("ReadAddressTxHistory: %v", err)
	}
	got := entryIDs(history)
	if len(got) != 2 || got[0] != "tx-2-b" || got[1] != "tx-2-a" {
		t.Fatalf("history after deleting block 1 = %v, want [tx-2-b tx-2-a]", got)
	}
}

func TestAddressTxKeyOrdering(t *testing.T) {
	// Keys for one address must sort by height, then by index within the
	// block, purely lexicographically — that is what makes the reverse scan
	// return newest-first without sorting anything.
	ascending := []string{
		addressTxKey("xAlice", 9, 0),
		addressTxKey("xAlice", 9, 1),
		addressTxKey("xAlice", 10, 0),
		addressTxKey("xAlice", 255, 0),
		addressTxKey("xAlice", 256, 0),
	}
	for i := 1; i < len(ascending); i++ {
		if !(ascending[i-1] < ascending[i]) {
			t.Fatalf("key order broken at %d: %q is not < %q", i, ascending[i-1], ascending[i])
		}
	}
}

func TestAddressTxKeyIsTerminated(t *testing.T) {
	// "xAlice" must not be a prefix of "xAlice2"'s keys.
	if strings.HasPrefix(addressTxKey("xAlice2", 1, 0), addressTxScanPrefix("xAlice")) {
		t.Fatal("xAlice2's key falls inside xAlice's scan prefix")
	}
}

// TestAddressTxHistoryIgnoresForeignKeys covers a stale key from the old
// address-only layout landing inside a new scan range: it must be skipped,
// not decoded and served as history.
func TestAddressTxHistoryIgnoresForeignKeys(t *testing.T) {
	db := newTestDB(t)

	mustWriteBlock(t, db, aliceBlock(1))

	// "addrtx:xAlice:legacy" sorts inside the range opened by
	// "addrtx:xAlice:" but is not shaped like a real key.
	if err := db.Put(addressTxScanPrefix("xAlice")+"legacy", []byte(`{"tx_id":"tx-bogus","sender":"xAlice","receiver":"xMallory"}`)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	history, err := ReadAddressTxHistory(db, "xAlice", 0)
	if err != nil {
		t.Fatalf("ReadAddressTxHistory: %v", err)
	}
	for _, e := range history {
		if e.TxID == "tx-bogus" {
			t.Fatal("a foreign key inside the scan range was served as history")
		}
	}
	if len(history) != 2 {
		t.Fatalf("history has %d entries, want the 2 real ones: %v", len(history), entryIDs(history))
	}
}
