// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/hash/spxhash_test.go
package spxhash

import (
	"bytes"
	"testing"
)

// TestBitSizeValidation covers FIX J — invalid bitSize must return an error.
func TestBitSizeValidation(t *testing.T) {
	for _, bad := range []int{0, 128, 255, 257, 1024} {
		if _, err := NewSphinxHash(bad, nil); err == nil {
			t.Errorf("NewSphinxHash(%d) expected error, got nil", bad)
		}
	}
	for _, good := range []int{256, 384, 512} {
		if _, err := NewSphinxHash(good, nil); err != nil {
			t.Errorf("NewSphinxHash(%d) unexpected error: %v", good, err)
		}
	}
}

// TestOutputLength covers FIX C — output length must match Size() for all bitSizes.
func TestOutputLength(t *testing.T) {
	cases := []struct {
		bitSize int
		want    int
	}{
		{256, 32},
		{384, 48},
		{512, 64},
	}
	for _, tc := range cases {
		s, err := NewSphinxHash(tc.bitSize, []byte("test"))
		if err != nil {
			t.Fatalf("NewSphinxHash(%d): %v", tc.bitSize, err)
		}
		// Short input (was affected by the removed fast path)
		for _, input := range [][]byte{[]byte("hi"), []byte("hello world this is longer")} {
			out := s.GetHash(input)
			if len(out) != tc.want {
				t.Errorf("bitSize=%d input=%q: got len=%d, want %d", tc.bitSize, input, len(out), tc.want)
			}
		}
	}
}

// TestDeterminismWithinInstance — same input on same instance must return same hash.
func TestDeterminismWithinInstance(t *testing.T) {
	s, _ := NewSphinxHash(256, []byte("seed"))
	input := []byte("the quick brown fox")
	h1 := s.GetHash(input)
	h2 := s.GetHash(input)
	if !bytes.Equal(h1, h2) {
		t.Error("same instance, same input: got different hashes")
	}
}

// TestNonDeterminismAcrossInstances covers FIX #2 — different instances must
// (with overwhelming probability) produce different hashes for the same input.
func TestNonDeterminismAcrossInstances(t *testing.T) {
	input := []byte("the quick brown fox")
	s1, _ := NewSphinxHash(256, input)
	s2, _ := NewSphinxHash(256, input)
	h1 := s1.GetHash(input)
	h2 := s2.GetHash(input)
	if bytes.Equal(h1, h2) {
		t.Error("different instances produced identical hashes — salt is not random")
	}
}

// TestCacheCorrectness — a cache hit must return the same value as a fresh computation.
func TestCacheCorrectness(t *testing.T) {
	s, _ := NewSphinxHash(256, []byte("seed"))
	input := []byte("cache test input")
	first := s.GetHash(input)  // miss — computed and stored
	second := s.GetHash(input) // hit — retrieved from cache
	if !bytes.Equal(first, second) {
		t.Error("cache hit returned different value from initial computation")
	}
}

// TestCacheMutationSafety covers FIX G — mutating the returned slice must not
// corrupt the cached entry.
func TestCacheMutationSafety(t *testing.T) {
	s, _ := NewSphinxHash(256, []byte("seed"))
	input := []byte("mutation test")
	first := s.GetHash(input)
	// Corrupt the returned slice.
	for i := range first {
		first[i] = 0xff
	}
	second := s.GetHash(input) // should still return the original correct value
	if bytes.Equal(first, second) {
		t.Error("cache entry was corrupted by mutation of a previously returned slice")
	}
}

// TestWriteSumReset — Write/Sum/Reset must behave consistently.
func TestWriteSumReset(t *testing.T) {
	s, _ := NewSphinxHash(256, []byte("seed"))
	input := []byte("streaming input")

	s.Write(input)
	sum1 := s.Sum(nil)

	s.Reset()
	s.Write(input)
	sum2 := s.Sum(nil)

	if !bytes.Equal(sum1, sum2) {
		t.Error("Sum after Reset+Write returned different result from first Sum")
	}
}

// TestEncodedSalt covers FIX E — EncodedSalt must return non-empty, consistent bytes.
func TestEncodedSalt(t *testing.T) {
	s, _ := NewSphinxHash(256, []byte("seed"))
	salt := s.EncodedSalt()
	if len(salt) == 0 {
		t.Error("EncodedSalt returned empty slice")
	}
	// Mutating the returned salt must not affect future calls.
	for i := range salt {
		salt[i] = 0x00
	}
	salt2 := s.EncodedSalt()
	allZero := true
	for _, b := range salt2 {
		if b != 0x00 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("EncodedSalt appears to return a reference into internal state")
	}
}

// TestClone covers FIX M — a cloned instance must hash identically to the original.
func TestClone(t *testing.T) {
	s, _ := NewSphinxHash(256, []byte("seed"))
	input := []byte("clone test")
	original := s.GetHash(input)

	c := s.Clone()
	cloned := c.GetHash(input)

	if !bytes.Equal(original, cloned) {
		t.Error("Clone produced an instance that hashes differently from the original")
	}
}

// TestNoInputMutation covers FIX A+B — GetHash must not modify the caller's slice.
func TestNoInputMutation(t *testing.T) {
	s, _ := NewSphinxHash(256, []byte("seed"))
	input := []byte("mutation check")
	snapshot := make([]byte, len(input))
	copy(snapshot, input)
	s.GetHash(input)
	if !bytes.Equal(input, snapshot) {
		t.Error("GetHash mutated the caller's input slice")
	}
}

// TestLRUEviction — cache must respect capacity and evict LRU entries.
func TestLRUEviction(t *testing.T) {
	cache := NewLRUCache(2)
	cache.Put(1, []byte("one"))
	cache.Put(2, []byte("two"))
	cache.Put(3, []byte("three")) // should evict key 1 (LRU)

	if _, ok := cache.Get(1); ok {
		t.Error("key 1 should have been evicted")
	}
	if _, ok := cache.Get(2); !ok {
		t.Error("key 2 should still be present")
	}
	if _, ok := cache.Get(3); !ok {
		t.Error("key 3 should be present")
	}
}

// TestLRUSingleNodeEviction covers FIX #6 — evicting the only node must leave
// the cache in a clean empty state (no dangling l.head pointer).
func TestLRUSingleNodeEviction(t *testing.T) {
	cache := NewLRUCache(1)
	cache.Put(1, []byte("one"))
	cache.Put(2, []byte("two")) // evicts key 1; cache now has only key 2

	if _, ok := cache.Get(1); ok {
		t.Error("key 1 should have been evicted")
	}
	// Put a third entry — would corrupt the list if l.head was left dangling.
	cache.Put(3, []byte("three"))
	if _, ok := cache.Get(3); !ok {
		t.Error("key 3 should be present after single-node eviction + re-insert")
	}
}
