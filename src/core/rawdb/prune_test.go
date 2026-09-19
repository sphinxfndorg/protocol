// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/prune_test.go
package rawdb

import (
	"errors"
	"fmt"
	"testing"

	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// pruneTestDB writes n blocks each holding one transaction and returns the
// handle plus the blocks.
func pruneTestDB(t *testing.T, n int) (*database.DB, []*types.Block) {
	t.Helper()
	db := newTestDB(t)
	blocks := make([]*types.Block, 0, n)
	for h := uint64(1); h <= uint64(n); h++ {
		block := testBlock(h, testTx(
			fmt.Sprintf("tx-%d", h),
			fmt.Sprintf("xSender-%d", h),
			fmt.Sprintf("xRecv-%d", h),
		))
		mustWriteBlock(t, db, block)
		blocks = append(blocks, block)
	}
	return db, blocks
}

func TestPruneBodiesRemovesBodiesBelowHeight(t *testing.T) {
	const blocks = 10
	const pruneHeight = 5

	db, chain := pruneTestDB(t, blocks)

	pruned, err := PruneBodies(db, pruneHeight)
	if err != nil {
		t.Fatalf("PruneBodies: %v", err)
	}
	if pruned != pruneHeight {
		t.Fatalf("PruneBodies reported %d pruned, want %d", pruned, pruneHeight)
	}

	for _, block := range chain {
		height := block.GetHeight()
		hash := block.GetHash()
		prunedAway := height <= pruneHeight

		if got := !HasBody(db, hash); got != prunedAway {
			t.Errorf("height %d: body missing = %v, want %v", height, got, prunedAway)
		}
		// Headers, canonical pointers and height lookups survive so range
		// scans can still resolve block existence.
		if !HasHeader(db, hash) {
			t.Errorf("height %d: header was pruned, it must be retained", height)
		}
		if got, err := ReadCanonicalHash(db, height); err != nil || got != hash {
			t.Errorf("height %d: canonical pointer = %q, %v; want %q", height, got, err, hash)
		}
		if got, err := ReadHeightByHash(db, hash); err != nil || got != height {
			t.Errorf("height %d: height lookup = %d, %v; want %d", height, got, err, height)
		}
	}
}

// TestPruneBodiesRemovesTransactionRecords covers the records that only
// exist to serve whole-body reads: leaving them behind would keep a pruned
// transaction resolvable and would not reclaim the space pruning promises.
func TestPruneBodiesRemovesTransactionRecords(t *testing.T) {
	const blocks = 6
	const pruneHeight = 3

	db, chain := pruneTestDB(t, blocks)

	if _, err := PruneBodies(db, pruneHeight); err != nil {
		t.Fatalf("PruneBodies: %v", err)
	}

	for _, block := range chain {
		txID := block.Body.TxsList[0].ID
		prunedAway := block.GetHeight() <= pruneHeight

		_, lookupErr := ReadTxLookupEntry(db, txID)
		_, payloadErr := ReadTxPayload(db, txID)

		if prunedAway {
			if !errors.Is(lookupErr, ErrNotFound) {
				t.Errorf("tx %s: lookup entry survived pruning (%v)", txID, lookupErr)
			}
			if !errors.Is(payloadErr, ErrNotFound) {
				t.Errorf("tx %s: payload survived pruning (%v)", txID, payloadErr)
			}
			continue
		}
		if lookupErr != nil {
			t.Errorf("tx %s: lookup entry was pruned above the prune height: %v", txID, lookupErr)
		}
		if payloadErr != nil {
			t.Errorf("tx %s: payload was pruned above the prune height: %v", txID, payloadErr)
		}
	}
}

func TestPruneBodiesIsIdempotent(t *testing.T) {
	db, _ := pruneTestDB(t, 5)

	first, err := PruneBodies(db, 3)
	if err != nil {
		t.Fatalf("first PruneBodies: %v", err)
	}
	if first != 3 {
		t.Fatalf("first run pruned %d, want 3", first)
	}

	second, err := PruneBodies(db, 3)
	if err != nil {
		t.Fatalf("second PruneBodies: %v", err)
	}
	if second != 0 {
		t.Fatalf("second run pruned %d, want 0 (nothing left to prune)", second)
	}
}

func TestPruneBodiesEmptyDatabase(t *testing.T) {
	db := newTestDB(t)

	pruned, err := PruneBodies(db, 100)
	if err != nil {
		t.Fatalf("PruneBodies on an empty database: %v", err)
	}
	if pruned != 0 {
		t.Fatalf("pruned %d blocks from an empty database, want 0", pruned)
	}
}

// TestPruneBodiesBeyondTipIsNoOp covers a prune height past the chain tip:
// the walk must stop at the last canonical pointer rather than probing
// heights that do not exist.
func TestPruneBodiesBeyondTipIsNoOp(t *testing.T) {
	db, chain := pruneTestDB(t, 4)

	pruned, err := PruneBodies(db, 10000)
	if err != nil {
		t.Fatalf("PruneBodies: %v", err)
	}
	if pruned != len(chain) {
		t.Fatalf("pruned %d, want %d", pruned, len(chain))
	}
	for _, block := range chain {
		if HasBody(db, block.GetHash()) {
			t.Fatalf("height %d still has a body after pruning everything", block.GetHeight())
		}
	}
}

// TestPruneBodiesLeavesGapsAlone checks that a chain with missing heights
// (nothing canonical stored) is handled by the single ordered walk.
func TestPruneBodiesLeavesGapsAlone(t *testing.T) {
	db := newTestDB(t)

	// Heights 1, 2, 10 exist; 3..9 do not.
	blocks := []*types.Block{
		testBlock(1, testTx("tx-1", "xS1", "xR1")),
		testBlock(2, testTx("tx-2", "xS2", "xR2")),
		testBlock(10, testTx("tx-10", "xS10", "xR10")),
	}
	for _, block := range blocks {
		mustWriteBlock(t, db, block)
	}

	pruned, err := PruneBodies(db, 5)
	if err != nil {
		t.Fatalf("PruneBodies: %v", err)
	}
	if pruned != 2 {
		t.Fatalf("pruned %d, want 2 (heights 1 and 2 only)", pruned)
	}
	if !HasBody(db, blocks[2].GetHash()) {
		t.Fatal("height 10 is above the prune height and must keep its body")
	}
	if HasBody(db, blocks[0].GetHash()) || HasBody(db, blocks[1].GetHash()) {
		t.Fatal("heights 1 and 2 are at or below the prune height and must lose their bodies")
	}
}
