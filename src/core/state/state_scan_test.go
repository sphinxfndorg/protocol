// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/state/state_scan_test.go
package database

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func seedScanKeys(t *testing.T, db *DB, prefix string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := db.Put(fmt.Sprintf("%s%04d", prefix, i), fmt.Appendf(nil, "v%d", i)); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	// A neighbouring keyspace that must never leak into a scan: bump the
	// prefix's last byte so the key sorts just past the scan's upper bound
	// ("acct:" -> "acct;"), rather than inside it.
	if prefix != "" {
		if last := prefix[len(prefix)-1]; last < 0xff {
			neighbour := prefix[:len(prefix)-1] + string(rune(last+1)) + "X-nope"
			if err := db.Put(neighbour, []byte("nope")); err != nil {
				t.Fatalf("Put: %v", err)
			}
		}
	}
}

// TestListKeysWithPrefixSortedAndScoped checks ordering and that the scan
// stays inside the prefix.
func TestListKeysWithPrefixSortedAndScoped(t *testing.T) {
	db := newTestDB(t)
	seedScanKeys(t, db, "acct:", 5)

	keys, err := db.ListKeysWithPrefix("acct:")
	if err != nil {
		t.Fatalf("ListKeysWithPrefix: %v", err)
	}
	if len(keys) != 5 {
		t.Fatalf("got %d keys, want 5: %v", len(keys), keys)
	}
	for i := 1; i < len(keys); i++ {
		if !(keys[i-1] < keys[i]) {
			t.Fatalf("keys are not in ascending order: %v", keys)
		}
	}
	for _, k := range keys {
		if len(k) < len("acct:") || k[:len("acct:")] != "acct:" {
			t.Fatalf("key %q is outside the scanned prefix", k)
		}
	}
}

func TestListKeysWithPrefixMissingPrefixIsEmpty(t *testing.T) {
	db := newTestDB(t)
	seedScanKeys(t, db, "acct:", 3)

	keys, err := db.ListKeysWithPrefix("nothing-here:")
	if err != nil {
		t.Fatalf("ListKeysWithPrefix: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("got %d keys for an unused prefix: %v", len(keys), keys)
	}
}

// TestListKeysWithPrefixOnClosedDBIsEmpty pins the deliberate
// preserve-behavior path for this one method: existing callers probe an
// optional keyspace and treat "no keys" as "nothing to do".
func TestListKeysWithPrefixOnClosedDBIsEmpty(t *testing.T) {
	db := newTestDB(t)
	seedScanKeys(t, db, "acct:", 3)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	keys, err := db.ListKeysWithPrefix("acct:")
	if err != nil {
		t.Fatalf("ListKeysWithPrefix on a closed DB returned an error: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("got %d keys from a closed DB: %v", len(keys), keys)
	}
}

func TestListEntriesWithPrefixReturnsValues(t *testing.T) {
	db := newTestDB(t)
	seedScanKeys(t, db, "acct:", 4)

	keys, values, err := db.ListEntriesWithPrefix("acct:", 0)
	if err != nil {
		t.Fatalf("ListEntriesWithPrefix: %v", err)
	}
	if len(keys) != len(values) {
		t.Fatalf("%d keys but %d values", len(keys), len(values))
	}
	if len(keys) != 4 {
		t.Fatalf("got %d entries, want 4: %v", len(keys), keys)
	}
	if string(values[0]) != "v0" {
		t.Fatalf("first value = %q, want %q", values[0], "v0")
	}
	// The values must outlive the iterator that produced them.
	if keys[3] != "acct:0003" || string(values[3]) != "v3" {
		t.Fatalf("last entry = (%q, %q), want (acct:0003, v3)", keys[3], values[3])
	}
}

func TestListEntriesWithPrefixLimit(t *testing.T) {
	db := newTestDB(t)
	seedScanKeys(t, db, "acct:", 10)

	keys, values, err := db.ListEntriesWithPrefix("acct:", 3)
	if err != nil {
		t.Fatalf("ListEntriesWithPrefix: %v", err)
	}
	if len(keys) != 3 || len(values) != 3 {
		t.Fatalf("limit 3 returned %d keys and %d values", len(keys), len(values))
	}
	// A limited listing must be the first entries in key order.
	if keys[0] != "acct:0000" || keys[1] != "acct:0001" || keys[2] != "acct:0002" {
		t.Fatalf("limit 3 returned %v, want the first three keys in order", keys)
	}
}

func TestListEntriesWithPrefixReportsClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, _, err := db.ListEntriesWithPrefix("acct:", 1)
	if err == nil {
		t.Fatal("ListEntriesWithPrefix on a closed DB returned no error")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("a closed DB must not look like an absent record: %v", err)
	}
}

func TestIterateEntriesWithPrefixForward(t *testing.T) {
	db := newTestDB(t)
	seedScanKeys(t, db, "acct:", 5)

	var seen []string
	err := db.IterateEntriesWithPrefix("acct:", func(key string, value []byte) bool {
		seen = append(seen, key)
		return true
	})
	if err != nil {
		t.Fatalf("IterateEntriesWithPrefix: %v", err)
	}
	if len(seen) != 5 {
		t.Fatalf("visited %d entries, want 5: %v", len(seen), seen)
	}
	for i := 1; i < len(seen); i++ {
		if !(seen[i-1] < seen[i]) {
			t.Fatalf("visit order is not ascending: %v", seen)
		}
	}
}

func TestIterateEntriesWithPrefixStopsEarly(t *testing.T) {
	db := newTestDB(t)
	seedScanKeys(t, db, "acct:", 10)

	count := 0
	err := db.IterateEntriesWithPrefix("acct:", func(string, []byte) bool {
		count++
		return count < 3
	})
	if err != nil {
		t.Fatalf("IterateEntriesWithPrefix: %v", err)
	}
	if count != 3 {
		t.Fatalf("callback ran %d times after returning false, want 3", count)
	}
}

func TestIterateEntriesWithPrefixReverse(t *testing.T) {
	db := newTestDB(t)
	seedScanKeys(t, db, "acct:", 5)

	var seen []string
	err := db.IterateEntriesWithPrefixReverse("acct:", func(key string, value []byte) bool {
		seen = append(seen, key)
		return true
	})
	if err != nil {
		t.Fatalf("IterateEntriesWithPrefixReverse: %v", err)
	}
	if len(seen) != 5 {
		t.Fatalf("visited %d entries, want 5: %v", len(seen), seen)
	}
	for i := 1; i < len(seen); i++ {
		if !(seen[i-1] > seen[i]) {
			t.Fatalf("visit order is not descending: %v", seen)
		}
	}
}

func TestIterateEntriesWithPrefixReverseStopsEarly(t *testing.T) {
	db := newTestDB(t)
	seedScanKeys(t, db, "acct:", 10)

	var seen []string
	err := db.IterateEntriesWithPrefixReverse("acct:", func(key string, value []byte) bool {
		seen = append(seen, key)
		return len(seen) < 2
	})
	if err != nil {
		t.Fatalf("IterateEntriesWithPrefixReverse: %v", err)
	}
	if len(seen) != 2 {
		t.Fatalf("callback ran %d times, want 2: %v", len(seen), seen)
	}
	if seen[0] != "acct:0009" {
		t.Fatalf("reverse scan started at %q, want the highest key", seen[0])
	}
}

// TestScanDoesNotBlockWriters is the property rawDB exists for: a scan holds
// no DB-wide lock, so writes proceed while it is in flight. Under the
// previous implementation, which held the read lock for the whole listing,
// the Put below would deadlock — Put takes the write lock.
func TestScanDoesNotBlockWriters(t *testing.T) {
	db := newTestDB(t)
	seedScanKeys(t, db, "acct:", 50)

	done := make(chan struct{})
	go func() {
		defer close(done)
		err := db.IterateEntriesWithPrefix("acct:", func(key string, value []byte) bool {
			// A write issued while the scan is iterating.
			if err := db.Put("acct:written-during-scan", []byte("x")); err != nil {
				t.Errorf("Put during scan: %v", err)
				return false
			}
			return true
		})
		if err != nil {
			t.Errorf("IterateEntriesWithPrefix: %v", err)
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a write issued during a scan blocked: the scan is holding the DB lock")
	}
}
