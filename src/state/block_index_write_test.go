// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/state/block_index_write_test.go
package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// readIndexFile parses block_index.json into hash -> height.
func readIndexFile(t *testing.T, store *Storage) map[string]uint64 {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(store.indexDir, "block_index.json"))
	if err != nil {
		t.Fatalf("reading block_index.json: %v", err)
	}
	var index struct {
		Blocks map[string]uint64 `json:"blocks"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		t.Fatalf("unmarshal block_index.json: %v", err)
	}
	return index.Blocks
}

// TestBlockIndexWrittenOnEveryStoreBlock pins the guarantee that
// block_index.json tracks the full set of stored blocks immediately, without
// waiting for a checkpoint interval or a clean Close. GetGenesisHash and
// GetAllBlocks read this file directly, so a batched or stale file presents a
// truncated chain to them.
func TestBlockIndexWrittenOnEveryStoreBlock(t *testing.T) {
	h := newCrashTestHarness(t)

	blocks := h.storeBlocks(4)

	index := readIndexFile(t, h.store)
	if len(index) != len(blocks) {
		t.Fatalf("block_index.json has %d entries, want %d (one per StoreBlock)", len(index), len(blocks))
	}
	for _, b := range blocks {
		height, ok := index[b.GetHash()]
		if !ok {
			t.Errorf("block at height %d (hash %s) missing from block_index.json", b.GetHeight(), b.GetHash()[:16])
			continue
		}
		if height != b.GetHeight() {
			t.Errorf("height mismatch for %s: want %d, got %d", b.GetHash()[:16], b.GetHeight(), height)
		}
	}
}

// TestSetDBRebuildsIndexFromRawdbAfterMissingFile reproduces the node layout
// that exposed this: blocks exist on disk and in rawdb, but block_index.json
// is missing because the node was killed before Close and no checkpoint had
// fired. NewStorage runs before any db handle exists, so it can only consult
// the (missing) file; SetDB is what makes rawdb reachable, so the index must
// be rebuilt — and the file rewritten from those rawdb entries — at that point.
func TestSetDBRebuildsIndexFromRawdbAfterMissingFile(t *testing.T) {
	h := newCrashTestHarness(t)

	blocks := h.storeBlocks(4)

	// Simulate the killed-before-Close state: no block_index.json at all.
	indexFile := filepath.Join(h.store.indexDir, "block_index.json")
	if err := os.Remove(indexFile); err != nil {
		t.Fatalf("removing block_index.json: %v", err)
	}

	// Restart in the same order production uses: NewStorage first (no db
	// handle yet, so only the missing file is available), then SetDB.
	store2, err := NewStorage(h.node)
	if err != nil {
		t.Fatalf("NewStorage (restart): %v", err)
	}
	if got := len(store2.heightIndex); got != 0 {
		t.Fatalf("before SetDB the in-memory index should be empty (no file, no db); got %d entries", got)
	}

	store2.SetDB(h.db)

	// Every block must be back in memory, rebuilt from rawdb.
	for _, b := range blocks {
		got, err := store2.GetBlockByHash(b.GetHash())
		if err != nil {
			t.Errorf("after SetDB, GetBlockByHash(%s): %v", b.GetHash()[:16], err)
			continue
		}
		if got.GetHeight() != b.GetHeight() {
			t.Errorf("after SetDB, height mismatch for %s: want %d, got %d",
				b.GetHash()[:16], b.GetHeight(), got.GetHeight())
		}
	}

	// block_index.json must have been materialized from those rawdb entries.
	index := readIndexFile(t, store2)
	if len(index) != len(blocks) {
		t.Fatalf("block_index.json after SetDB has %d entries, want %d", len(index), len(blocks))
	}
	for _, b := range blocks {
		height, ok := index[b.GetHash()]
		if !ok || height != b.GetHeight() {
			t.Errorf("block_index.json after SetDB: entry for height %d (hash %s) = %d/%v, want %d",
				b.GetHeight(), b.GetHash()[:16], height, ok, b.GetHeight())
		}
	}
}
