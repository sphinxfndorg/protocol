// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/bloom/bloom_test.go
package bloom

import "testing"

func TestNewDefault(t *testing.T) {
	bf := NewDefault()
	if bf.Config() != DefaultConfig() {
		t.Fatalf("NewDefault() config = %+v, want %+v", bf.Config(), DefaultConfig())
	}
	if bf.CountBits() != 0 {
		t.Fatalf("fresh filter should have 0 bits set, got %d", bf.CountBits())
	}
}

func TestNewInvalidConfig(t *testing.T) {
	if _, err := New(Config{Bits: 0, K: 3}); err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestAddContains(t *testing.T) {
	bf := NewDefault()
	key := []byte("sphinx-address-1")

	if bf.Contains(key) {
		t.Fatal("empty filter must not contain any key")
	}
	bf.Add(key)
	if !bf.Contains(key) {
		t.Fatal("filter must contain a key after Add (no false negatives)")
	}
}

func TestContainsNoFalseNegativesManyKeys(t *testing.T) {
	bf := NewDefault()
	var keys [][]byte
	for i := 0; i < 100; i++ {
		keys = append(keys, []byte{byte(i), byte(i >> 8), 0xAB})
	}
	for _, k := range keys {
		bf.Add(k)
	}
	for _, k := range keys {
		if !bf.Contains(k) {
			t.Fatalf("key %v missing after Add — false negative", k)
		}
	}
}

func TestMerge(t *testing.T) {
	a := NewDefault()
	b := NewDefault()

	keyA := []byte("only-in-a")
	keyB := []byte("only-in-b")
	a.Add(keyA)
	b.Add(keyB)

	a.Merge(b)

	if !a.Contains(keyA) || !a.Contains(keyB) {
		t.Fatal("after merge, a must contain keys from both filters")
	}
	if b.Contains(keyA) {
		t.Fatal("merge must not mutate the other filter")
	}
}

func TestMergeMismatchedConfigIsNoOp(t *testing.T) {
	a := NewDefault()
	small, err := New(Config{Bits: 64, K: 2})
	if err != nil {
		t.Fatal(err)
	}
	small.Add([]byte("x"))
	a.Add([]byte("y"))

	before := a.CountBits()
	a.Merge(small)
	if a.CountBits() != before {
		t.Fatal("merge across mismatched configs must be a no-op")
	}
}

func TestMergeNilIsNoOp(t *testing.T) {
	a := NewDefault()
	a.Add([]byte("y"))
	before := a.CountBits()
	a.Merge(nil)
	if a.CountBits() != before {
		t.Fatal("merge(nil) must be a no-op")
	}
}

func TestReset(t *testing.T) {
	bf := NewDefault()
	bf.Add([]byte("k1"))
	bf.Add([]byte("k2"))
	if bf.CountBits() == 0 {
		t.Fatal("setup failed: expected bits set before reset")
	}
	bf.Reset()
	if bf.CountBits() != 0 {
		t.Fatal("expected 0 bits after Reset")
	}
}

func TestCopyIsIndependent(t *testing.T) {
	bf := NewDefault()
	bf.Add([]byte("k1"))

	cp := bf.Copy()
	cp.Add([]byte("k2"))

	if bf.Contains([]byte("k2")) {
		t.Fatal("mutating a copy must not affect the original filter")
	}
	if !cp.Contains([]byte("k1")) || !cp.Contains([]byte("k2")) {
		t.Fatal("copy must retain original keys plus its own additions")
	}
}

func TestConcurrentAddContains(t *testing.T) {
	bf := NewDefault()
	done := make(chan struct{})

	go func() {
		for i := 0; i < 1000; i++ {
			bf.Add([]byte{byte(i)})
		}
		close(done)
	}()

	for i := 0; i < 1000; i++ {
		bf.Contains([]byte{byte(i)})
	}
	<-done
}

func TestContainsRawMatchesContains(t *testing.T) {
	bf := NewDefault()
	keys := []string{"xAlice", "xBob", "tx-0001", ""}
	for _, k := range keys {
		bf.Add([]byte(k))
	}
	raw := bf.Bytes()
	cfg := bf.Config()

	for _, k := range append(keys, "xMallory", "tx-9999") {
		want := bf.Contains([]byte(k))
		if got := ContainsRaw(raw, cfg, []byte(k)); got != want {
			t.Fatalf("ContainsRaw(%q) = %v, Contains says %v", k, got, want)
		}
	}
}

func TestContainsRawCustomKAboveInlineBuffer(t *testing.T) {
	// k > maxInlineK forces positionsInto onto the heap; the result must
	// still agree with the allocating path.
	cfg, err := NewConfig(1024, maxInlineK+5)
	if err != nil {
		t.Fatal(err)
	}
	bf, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	bf.Add([]byte("xAlice"))

	for _, k := range []string{"xAlice", "xMallory"} {
		want := bf.Contains([]byte(k))
		if got := ContainsRaw(bf.Bytes(), cfg, []byte(k)); got != want {
			t.Fatalf("ContainsRaw(%q) = %v with k=%d, Contains says %v", k, got, cfg.K, want)
		}
	}
}

func TestContainsRawEmptyFilter(t *testing.T) {
	if ContainsRaw(NewDefault().Bytes(), DefaultConfig(), []byte("anything")) {
		t.Fatal("empty filter must not report a match")
	}
}

func TestContainsRawRejectsBadLength(t *testing.T) {
	for _, raw := range [][]byte{nil, {}, make([]byte, BloomBytes-1), make([]byte, BloomBytes+1)} {
		if ContainsRaw(raw, DefaultConfig(), []byte("xAlice")) {
			t.Fatalf("raw of length %d must report false", len(raw))
		}
	}
}

func TestContainsRawRejectsInvalidConfig(t *testing.T) {
	raw := make([]byte, 64)
	cfgs := []Config{
		{Bits: 0, K: 3},
		{Bits: -8, K: 3},
		{Bits: 7, K: 3},
		{Bits: 64, K: 0},
		{Bits: 64, K: -1},
	}
	for _, cfg := range cfgs {
		if ContainsRaw(raw, cfg, []byte("xAlice")) {
			t.Fatalf("invalid config %+v must report false", cfg)
		}
	}
}

func TestContainsRawDoesNotMutateRaw(t *testing.T) {
	bf := NewDefault()
	bf.Add([]byte("xAlice"))
	raw := bf.Bytes()

	before := make([]byte, len(raw))
	copy(before, raw)

	ContainsRaw(raw, DefaultConfig(), []byte("xAlice"))
	ContainsRaw(raw, DefaultConfig(), []byte("xMallory"))

	for i := range before {
		if raw[i] != before[i] {
			t.Fatalf("byte %d changed: %x -> %x", i, before[i], raw[i])
		}
	}
}

func TestContainsRawDoesNotAllocate(t *testing.T) {
	raw := NewDefault().Bytes()
	cfg := DefaultConfig()
	key := []byte("xAlice")

	if allocs := testing.AllocsPerRun(100, func() {
		ContainsRaw(raw, cfg, key)
	}); allocs != 0 {
		t.Fatalf("ContainsRaw allocated %.1f objects/op, want 0", allocs)
	}
}
