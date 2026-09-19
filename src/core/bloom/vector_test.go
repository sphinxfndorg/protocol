// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/bloom/vector_test.go
package bloom

import (
	"encoding/hex"
	"testing"
)

// The values in this file are consensus-frozen. positions() feeds
// BlockHeader.LogsBloom, and LogsBloom is part of the block hash
// (GenerateBlockHash / FinalizeHash), so breaking any assertion here means
// every node would produce a different header for the same block body —
// i.e. a coordinated hard fork. Update these values only as part of that
// decision, never to make a refactor pass.

func TestFrozenPositions(t *testing.T) {
	cases := []struct {
		key  string
		want []int
	}{
		{"xAlice", []int{545, 1484, 375}},
		{"tx-0003", []int{1179, 285, 1439}},
		{"", []int{1044, 890, 736}},
	}

	for _, tc := range cases {
		got := positions([]byte(tc.key), BloomBits, HashFunctions)
		if len(got) != len(tc.want) {
			t.Fatalf("positions(%q) = %v, want %v", tc.key, got, tc.want)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Fatalf("positions(%q) = %v, want %v", tc.key, got, tc.want)
			}
		}
	}
}

// frozenKeys is the key multiset — duplicates included, matching what a
// real 5-transaction block contributes — whose filter bytes are pinned in
// frozenFilterHex.
var frozenKeys = []string{
	"tx-0001", "xAlice", "xBob",
	"tx-0002", "xCarol", "xDave",
	"tx-0003", "xEve", "xContract123", "xContract123",
	"tx-0004", "xAlice", "xBob",
	"tx-0005", // its Sender/Receiver are empty, but a non-empty ID is still a key
}

const frozenFilterHex = "00000000000000000000000000080000000000000000080000000000000000000000040400000000000000000000010000000000000001000000000000000000008000004000000000000000000000000008080100000000000000000000100020000000000008000040000000000000000000400000000000000000000000000000000000000000000000000000000001000010000100000000000000000000000000000000000000000000000000000002000100000000200800000000000001000000000000000002000000000000800000000000000000400008000000000000000001000000400000000000000000000000000000000000000000100048"

const frozenFilterBits = 33

func TestFrozenFilterBytes(t *testing.T) {
	bf := NewDefault()
	for _, k := range frozenKeys {
		bf.Add([]byte(k))
	}

	got := hex.EncodeToString(bf.Bytes())
	if got != frozenFilterHex {
		t.Fatalf("filter bytes changed:\n got %s\nwant %s", got, frozenFilterHex)
	}
	if n := bf.CountBits(); n != frozenFilterBits {
		t.Fatalf("CountBits() = %d, want %d", n, frozenFilterBits)
	}
}

// TestFrozenFilterBytesAreOrderIndependent documents that key order does
// not matter, which is what lets BuildBlockBloomFilter dedupe/reorder keys
// without changing the block hash.
func TestFrozenFilterBytesAreOrderIndependent(t *testing.T) {
	forward := NewDefault()
	for _, k := range frozenKeys {
		forward.Add([]byte(k))
	}

	reversed := NewDefault()
	for i := len(frozenKeys) - 1; i >= 0; i-- {
		reversed.Add([]byte(frozenKeys[i]))
	}

	if hex.EncodeToString(forward.Bytes()) != hex.EncodeToString(reversed.Bytes()) {
		t.Fatal("filter bytes depend on insertion order")
	}
}
