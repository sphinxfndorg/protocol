// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/canonical_test.go
package rawdb

import (
	"testing"
)

// TestReadHeightLookupsRoundTrip pins the reverse index a restarted node
// rebuilds its in-memory blockIndex from: every block written through
// WriteBlock must appear as hash -> height.
func TestReadHeightLookupsRoundTrip(t *testing.T) {
	db := newTestDB(t)
	mustWriteBlock(t, db, testBlock(1, testTx("tx-1", "xAlice", "xBob")))
	mustWriteBlock(t, db, testBlock(2, testTx("tx-2", "xBob", "xCarol")))

	got, err := ReadHeightLookups(db)
	if err != nil {
		t.Fatalf("ReadHeightLookups: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d lookups, want 2: %v", len(got), got)
	}
	if h := got[hashFor(1)]; h != 1 {
		t.Fatalf("height for block 1 = %d, want 1", h)
	}
	if h := got[hashFor(2)]; h != 2 {
		t.Fatalf("height for block 2 = %d, want 2", h)
	}
}

func TestReadHeightLookupsEmpty(t *testing.T) {
	db := newTestDB(t)

	got, err := ReadHeightLookups(db)
	if err != nil {
		t.Fatalf("ReadHeightLookups on an empty DB: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty DB returned %d lookups: %v", len(got), got)
	}
}

func TestReadHeightLookupsReportsClosedDB(t *testing.T) {
	db := newTestDB(t)
	mustWriteBlock(t, db, testBlock(1))
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := ReadHeightLookups(db); err == nil {
		t.Fatal("ReadHeightLookups on a closed DB returned no error")
	}
}