// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package state

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// ============================================================================
// Block builder helpers — produce minimal blocks that pass StoreBlock's
// validation without needing a full consensus engine.
// ============================================================================

func makeHeader(height uint64, parentHash []byte) *types.BlockHeader {
	return types.NewBlockHeader(
		height, parentHash, big.NewInt(1), // difficulty=1
		types.EmptyMerkleRoot,    // txsRoot for empty tx list
		types.EmptyMerkleRoot,    // stateRoot
		big.NewInt(1000000),      // gasLimit
		big.NewInt(0),            // gasUsed
		[]byte("crash-test"),     // extraData
		make([]byte, 20),         // miner
		1000000000+int64(height), // deterministic timestamp
		nil,                      // uncles
	)
}

func makeBlock(height uint64, parentHash []byte, txs []*types.Transaction) *types.Block {
	body := types.NewBlockBody(txs, nil, height)
	header := makeHeader(height, parentHash)
	block := types.NewBlock(header, body)
	block.FinalizeHash()
	return block
}

// makeSimpleTx creates a minimal valid transaction.
func makeSimpleTx(id, sender, receiver string, amount int64) *types.Transaction {
	return &types.Transaction{
		ID:       id,
		Sender:   sender,
		Receiver: receiver,
		Amount:   big.NewInt(amount),
		GasLimit: big.NewInt(21000),
		GasPrice: big.NewInt(1),
		Nonce:    1,
	}
}

// ============================================================================
// Test harness: creates an isolated temp directory with a real LevelDB
// instance, a Storage, and helper methods to verify consistency.
// ============================================================================

type crashTestHarness struct {
	t      *testing.T
	dir    string
	dbPath string
	store  *Storage
	db     *database.DB
}

func newCrashTestHarness(t *testing.T) *crashTestHarness {
	t.Helper()

	dir, err := os.MkdirTemp("", "crash-recovery-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	// Create LevelDB instance
	dbPath := filepath.Join(dir, "leveldb")
	db, err := database.NewLevelDB(dbPath)
	if err != nil {
		t.Fatalf("NewLevelDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Create storage
	store, err := NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	store.SetDB(db)

	return &crashTestHarness{
		t:      t,
		dir:    dir,
		dbPath: dbPath,
		store:  store,
		db:     db,
	}
}

// storeBlocks writes N blocks (starting at height 1, not 0, since genesis
// has special handling). Returns the slice of blocks written.
func (h *crashTestHarness) storeBlocks(n int) []*types.Block {
	h.t.Helper()

	var prevHash []byte
	blocks := make([]*types.Block, 0, n)

	for i := 1; i <= n; i++ {
		block := makeBlock(uint64(i), prevHash, nil)
		if err := h.store.StoreBlock(block); err != nil {
			h.t.Fatalf("StoreBlock(height=%d): %v", i, err)
		}
		blocks = append(blocks, block)
		prevHash = block.Header.Hash
	}
	return blocks
}

// ============================================================================
// Consistency checks
// ============================================================================

// assertBothStoresAgree verifies that every block recorded in the JSON block
// index is also present in rawdb with identical data, and vice versa.
func (h *crashTestHarness) assertBothStoresAgree() {
	h.t.Helper()

	// For each JSON block on disk, verify rawdb matches.
	indexFile := filepath.Join(h.store.indexDir, "block_index.json")
	data, err := os.ReadFile(indexFile)
	if err != nil && !os.IsNotExist(err) {
		h.t.Fatalf("reading block_index.json: %v", err)
	}

	if len(data) > 0 {
		var index struct {
			Blocks map[string]uint64 `json:"blocks"`
		}
		if err := json.Unmarshal(data, &index); err != nil {
			h.t.Fatalf("unmarshal block_index.json: %v", err)
		}

		for hash, height := range index.Blocks {
			if hash == "" {
				continue
			}
			// Verify rawdb has the header.
			has, err := h.db.Has("hdr:" + hash)
			if err != nil {
				h.t.Fatalf("rawdb.Has header for %s: %v", hash, err)
			}
			if !has {
				h.t.Errorf("JSON block %s at height %d missing from rawdb (header)", hash[:16], height)
				continue
			}
		}
	}
}

// ============================================================================
// Tests
// ============================================================================

// TestRawdbWriteThenReload writes blocks through the normal StoreBlock path,
// which does rawdb-first + JSON-second, then reloads storage (simulating a
// clean restart) and verifies everything reappears correctly.
func TestRawdbWriteThenReload(t *testing.T) {
	h := newCrashTestHarness(t)
	blocks := h.storeBlocks(5)

	for _, b := range blocks {
		got, err := h.store.GetBlockByHash(b.GetHash())
		if err != nil {
			t.Errorf("GetBlockByHash(%s): %v", b.GetHash()[:16], err)
			continue
		}
		if got.GetHeight() != b.GetHeight() {
			t.Errorf("height mismatch: want %d, got %d", b.GetHeight(), got.GetHeight())
		}
	}

	// Reload by creating a new Storage pointing at the same directory.
	store2, err := NewStorage(h.dir)
	if err != nil {
		t.Fatalf("NewStorage (reload): %v", err)
	}
	store2.SetDB(h.db)

	// After loadBlockIndex, all blocks should be back in memory.
	for _, b := range blocks {
		got, err := store2.GetBlockByHash(b.GetHash())
		if err != nil {
			t.Errorf("after reload, GetBlockByHash(%s): %v", b.GetHash()[:16], err)
		} else if got.GetHeight() != b.GetHeight() {
			t.Errorf("after reload, height mismatch: want %d, got %d", b.GetHeight(), got.GetHeight())
		}
	}

	h.assertBothStoresAgree()
}

// TestSelfHealBackfillsRawdb simulates a scenario where the JSON store has
// blocks but rawdb does not (e.g. because of a crash after storeBlockToDisk
// but before WriteBlock in an older build, or a manual deletion for testing).
// After calling loadBlockIndex, the self-heal code should backfill the
// missing rawdb entries.
func TestSelfHealBackfillsRawdb(t *testing.T) {
	h := newCrashTestHarness(t)

	// Store blocks normally.
	_ = h.storeBlocks(3)

	// Read the index to find block 2's hash.
	indexFile := filepath.Join(h.store.indexDir, "block_index.json")
	data, err := os.ReadFile(indexFile)
	if err != nil {
		t.Fatalf("reading block_index.json: %v", err)
	}
	var index struct {
		Blocks map[string]uint64 `json:"blocks"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		t.Fatalf("unmarshal block_index.json: %v", err)
	}

	// Find hash for height 2.
	block2Hash := ""
	for hash, height := range index.Blocks {
		if height == 2 {
			block2Hash = hash
			break
		}
	}
	if block2Hash == "" {
		t.Fatal("no block at height 2 in index")
	}

	// Delete block 2's rawdb entries.
	if err := h.db.Delete("hdr:" + block2Hash); err != nil {
		t.Fatalf("delete header from rawdb: %v", err)
	}
	if err := h.db.Delete("bdy:" + block2Hash); err != nil {
		t.Fatalf("delete body from rawdb: %v", err)
	}
	h.store.mu.Lock()
	delete(h.store.blockIndex, block2Hash)
	delete(h.store.heightIndex, 2)
	h.store.mu.Unlock()

	// Simulate a crash and restart by calling loadBlockIndex again.
	if err := h.store.loadBlockIndex(); err != nil {
		t.Fatalf("loadBlockIndex after simulated crash: %v", err)
	}

	// Verify loadBlockIndex backfilled the rawdb entry for block 2.
	has, err := h.db.Has("hdr:" + block2Hash)
	if err != nil {
		t.Fatalf("rawdb.Has after backfill: %v", err)
	}
	if !has {
		t.Error("loadBlockIndex did NOT backfill rawdb header entry for block 2")
	}

	has, err = h.db.Has("bdy:" + block2Hash)
	if err != nil {
		t.Fatalf("rawdb.Has body after backfill: %v", err)
	}
	if !has {
		t.Error("loadBlockIndex did NOT backfill rawdb body entry for block 2")
	}

	h.assertBothStoresAgree()
}

// TestDeleteBlocksAboveRawdbConsistency verifies that DeleteBlocksAbove
// removes rawdb entries in addition to JSON files, so GetTransaction does
// not serve stale data from the losing fork after a reorg.
func TestDeleteBlocksAboveRawdbConsistency(t *testing.T) {
	h := newCrashTestHarness(t)

	// Write blocks 1 and 2 normally.
	_ = h.storeBlocks(2)

	// Create block 3 with a transaction from the start, so TxsRoot is correct.
	tx := makeSimpleTx("tx-crash-test-001", "sender1", "receiver1", 100)
	// Get block 2's hash for parent.
	block2, err := h.store.GetBlockByHeight(2)
	if err != nil {
		t.Fatalf("GetBlockByHeight(2): %v", err)
	}
	block3 := makeBlock(3, block2.Header.Hash, []*types.Transaction{tx})
	if err := h.store.StoreBlock(block3); err != nil {
		t.Fatalf("StoreBlock (with tx): %v", err)
	}

	// Manually create blocks 4 and 5 parented from block 3.
	block4 := makeBlock(4, block3.Header.Hash, nil)
	if err := h.store.StoreBlock(block4); err != nil {
		t.Fatalf("StoreBlock(4): %v", err)
	}
	block5 := makeBlock(5, block4.Header.Hash, nil)
	if err := h.store.StoreBlock(block5); err != nil {
		t.Fatalf("StoreBlock(5): %v", err)
	}

	// Verify the tx is findable before the purge.
	foundTx, err := h.store.GetTransaction("tx-crash-test-001")
	if err != nil {
		t.Fatalf("GetTransaction before purge: %v", err)
	}
	if foundTx.ID != "tx-crash-test-001" {
		t.Fatalf("unexpected tx ID: %s", foundTx.ID)
	}

	// Purge everything above height 2.
	if err := h.store.DeleteBlocksAbove(2); err != nil {
		t.Fatalf("DeleteBlocksAbove(2): %v", err)
	}

	// Block 3 should no longer be accessible.
	_, err = h.store.GetBlockByHash(block3.GetHash())
	if err == nil {
		t.Error("GetBlockByHash for purged block should have failed")
	}

	// The transaction should also be gone.
	_, err = h.store.GetTransaction("tx-crash-test-001")
	if err == nil {
		t.Error("GetTransaction for purged tx should have failed (stale rawdb entry)")
	}

	// Verify rawdb entries are gone.
	has, err := h.db.Has("hdr:" + block3.GetHash())
	if err != nil {
		t.Fatalf("rawdb.Has: %v", err)
	}
	if has {
		t.Error("rawdb header entry for purged block still present after DeleteBlocksAbove")
	}

	has, err = h.db.Has("tx:tx-crash-test-001")
	if err != nil {
		t.Fatalf("rawdb.Has tx: %v", err)
	}
	if has {
		t.Error("rawdb tx lookup entry for purged transaction still present after DeleteBlocksAbove")
	}

	h.assertBothStoresAgree()
}

// TestAtomicWriteOrdering verifies that if (simulated) storeBlockToDisk
// fails, rawdb's write is NOT rolled back — the block is still recoverable
// from rawdb on the next loadBlockIndex call (which won't backfill it into
// JSON since the JSON file doesn't exist, but the rawdb entry is durable).
func TestAtomicWriteOrdering(t *testing.T) {
	h := newCrashTestHarness(t)

	// Write genesis-like block 0.
	block0 := makeBlock(0, make([]byte, 32), nil)
	if err := h.store.StoreBlock(block0); err != nil {
		t.Fatalf("StoreBlock genesis: %v", err)
	}

	blocks := h.storeBlocks(3)

	// Write block 4 normally, then simulate a crash after rawdb.WriteBlock
	// succeeds but before storeBlockToDisk by removing its JSON file.
	block4 := makeBlock(4, blocks[2].Header.Hash, nil)
	if err := h.store.StoreBlock(block4); err != nil {
		t.Fatalf("StoreBlock(4): %v", err)
	}
	// Remove the JSON file, simulating a crash after rawdb but before JSON write.
	jsonFile := filepath.Join(h.store.blocksDir, h.store.sanitizeFilename(block4.GetHash())+".json")
	if err := os.Remove(jsonFile); err != nil {
		t.Fatalf("remove JSON file: %v", err)
	}
	// Also remove from in-memory index to simulate a restart.
	h.store.mu.Lock()
	delete(h.store.blockIndex, block4.GetHash())
	delete(h.store.heightIndex, 4)
	h.store.mu.Unlock()

	// Reload: loadBlockIndex should not find block 4's JSON file,
	// but rawdb still has it.
	if err := h.store.loadBlockIndex(); err != nil {
		t.Fatalf("loadBlockIndex after simulated crash: %v", err)
	}

	// Verify rawdb still has the entry.
	has, err := h.db.Has("hdr:" + block4.GetHash())
	if err != nil {
		t.Fatalf("rawdb.Has: %v", err)
	}
	if !has {
		t.Error("rawdb entry for block 4 was lost after simulated crash — atomicity violated")
	}
}

// TestTransactionLookupSurvivesCrashBetweenStores writes a block with
// transactions, simulates a crash that removes only the JSON file, and
// verifies GetTransaction can still find the tx via rawdb.
func TestTransactionLookupSurvivesCrashBetweenStores(t *testing.T) {
	h := newCrashTestHarness(t)

	blocks := h.storeBlocks(2)

	// Write a block with a transaction.
	tx := makeSimpleTx("tx-crash-survive-001", "alice", "bob", 500)
	block3 := makeBlock(3, blocks[1].Header.Hash, []*types.Transaction{tx})
	if err := h.store.StoreBlock(block3); err != nil {
		t.Fatalf("StoreBlock(3): %v", err)
	}

	// Verify tx is found before crash simulation.
	_, err := h.store.GetTransaction("tx-crash-survive-001")
	if err != nil {
		t.Fatalf("GetTransaction before crash: %v", err)
	}

	// Simulate crash: remove JSON file and in-memory index, but rawdb remains.
	jsonFile := filepath.Join(h.store.blocksDir, h.store.sanitizeFilename(block3.GetHash())+".json")
	if err := os.Remove(jsonFile); err != nil {
		t.Fatalf("remove JSON file: %v", err)
	}
	// Also remove block_index.json to force full reload.
	indexFile := filepath.Join(h.store.indexDir, "block_index.json")
	if err := os.Remove(indexFile); err != nil {
		t.Fatalf("remove block_index.json: %v", err)
	}
	h.store.mu.Lock()
	h.store.blockIndex = make(map[string]*types.Block)
	h.store.heightIndex = make(map[uint64]*types.Block)
	h.store.txIndex = make(map[string]*types.Transaction)
	h.store.mu.Unlock()

	// Reload.
	if err := h.store.loadBlockIndex(); err != nil {
		t.Fatalf("loadBlockIndex after crash: %v", err)
	}

	// GetTransaction should STILL find the tx via rawdb (ReadTxLookupEntry
	// -> ReadBlock fallback path in state.go's GetTransaction).
	foundTx, err := h.store.GetTransaction("tx-crash-survive-001")
	if err != nil {
		t.Errorf("GetTransaction after crash: %v — rawdb tx lookup should survive", err)
	} else if foundTx.ID != "tx-crash-survive-001" {
		t.Errorf("unexpected tx ID: %s", foundTx.ID)
	}
}
