// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/state/database_test.go
package database

import (
	"errors"
	"strings"
	"testing"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewLevelDB(t.TempDir() + "/db")
	if err != nil {
		t.Fatalf("NewLevelDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestGetQuietReturnsErrNotFound(t *testing.T) {
	db := newTestDB(t)

	_, err := db.GetQuiet("missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetQuiet on a missing key returned %v, want ErrNotFound", err)
	}
	// Callers that want to compare directly rather than through errors.Is
	// must be able to: the sentinel is returned unwrapped.
	if err != ErrNotFound {
		t.Fatalf("GetQuiet must return the sentinel unwrapped, got %v", err)
	}
}

func TestGetQuietRoundTrip(t *testing.T) {
	db := newTestDB(t)

	if err := db.Put("k", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := db.GetQuiet("k")
	if err != nil {
		t.Fatalf("GetQuiet: %v", err)
	}
	if string(got) != "v" {
		t.Fatalf("GetQuiet = %q, want %q", got, "v")
	}
}

func TestGetQuietOnClosedDBIsNotNotFound(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err := db.GetQuiet("k")
	if err == nil {
		t.Fatal("GetQuiet on a closed DB returned no error")
	}
	// A closed database is a real failure, not an absent key — conflating
	// the two would let a caller treat an outage as "no such record".
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("GetQuiet on a closed DB reported ErrNotFound: %v", err)
	}
}

// TestGetWrapsErrNotFoundAndKeepsMessage pins the historical error text
// (callers string-match it) while making the cause branchable.
func TestGetWrapsErrNotFoundAndKeepsMessage(t *testing.T) {
	db := newTestDB(t)

	_, err := db.Get("missing")
	if err == nil {
		t.Fatal("Get on a missing key returned no error")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get error %v does not wrap ErrNotFound", err)
	}
	if !strings.Contains(err.Error(), "key missing not found in LevelDB") {
		t.Fatalf("Get error %q lost its historical message text", err.Error())
	}
}

func TestGetOnClosedDBIsNotNotFound(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err := db.Get("k")
	if err == nil {
		t.Fatal("Get on a closed DB returned no error")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on a closed DB reported ErrNotFound: %v", err)
	}
}

func TestHasMissingKey(t *testing.T) {
	db := newTestDB(t)

	ok, err := db.Has("missing")
	if err != nil {
		t.Fatalf("Has on a missing key returned an error: %v", err)
	}
	if ok {
		t.Fatal("Has reported a missing key as present")
	}

	if err := db.Put("k", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if ok, err = db.Has("k"); err != nil || !ok {
		t.Fatalf("Has(k) = %v, %v; want true, nil", ok, err)
	}
}

func TestHasValueUsesExistenceCheck(t *testing.T) {
	db := newTestDB(t)

	if err := db.Put("k", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	ok, err := db.hasValue("k")
	if err != nil || !ok {
		t.Fatalf("hasValue(k) = %v, %v; want true, nil", ok, err)
	}
	if ok, err = db.hasValue("missing"); err != nil || ok {
		t.Fatalf("hasValue(missing) = %v, %v; want false, nil", ok, err)
	}
}

func TestHasOnClosedDBReturnsError(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := db.Has("k"); err == nil {
		t.Fatal("Has on a closed DB returned no error")
	}
}

// TestGetQuietDoesNotAllocateMoreThanGet guards the point of the quiet
// path: it must not build the extra formatted error string a miss used to
// produce. A missing key is the case that matters, so it is measured with
// no logger output either way.
func TestGetQuietMissIsCheaperThanGetMiss(t *testing.T) {
	db := newTestDB(t)

	quiet := testing.AllocsPerRun(50, func() {
		_, _ = db.GetQuiet("missing")
	})
	loud := testing.AllocsPerRun(50, func() {
		_, _ = db.Get("missing")
	})

	if quiet >= loud {
		t.Fatalf("GetQuiet miss allocated %.1f objects/op, Get miss %.1f — the quiet path should be cheaper", quiet, loud)
	}
}
