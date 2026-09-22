// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	txtypes "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// TestBurnFeeStatePersistsAcrossCommitAndReload verifies the deterministic
// policy-state namespace: the rolled burn rate and the previous block's gas
// footprint survive Commit + reload (the path every replaying node reads),
// and default to the static policy rate when nothing is committed yet.
func TestBurnFeeStatePersistsAcrossCommitAndReload(t *testing.T) {
	dir := t.TempDir()
	db, err := database.NewLevelDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	s := NewStateDB(db)
	if got := s.GetBurnFeeBPS(500); got != 500 {
		t.Fatalf("fresh state must default to the policy rate 500, got %d", got)
	}
	used, limit := s.GetPrevBlockGas()
	if used.Sign() != 0 || limit.Sign() != 0 {
		t.Fatalf("fresh state must report zero prev gas, got used=%s limit=%s", used, limit)
	}

	s.SetBurnFeeBPS(495)
	s.SetPrevBlockGas(big.NewInt(24_200), big.NewInt(10_000_000))
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	reloaded := NewStateDB(db)
	if got := reloaded.GetBurnFeeBPS(500); got != 495 {
		t.Fatalf("after reload: burn fee = %d, want 495", got)
	}
	gotUsed, gotLimit := reloaded.GetPrevBlockGas()
	if gotUsed.Cmp(big.NewInt(24_200)) != 0 || gotLimit.Cmp(big.NewInt(10_000_000)) != 0 {
		t.Fatalf("after reload: prev gas = (%s, %s), want (24200, 10000000)", gotUsed, gotLimit)
	}

	// Corrupt records fall back to safe defaults rather than poisoning the roll.
	db.Put("contract:"+policyStateBurnFeeKey, []byte("not-a-number"))
	broken := NewStateDB(db)
	if got := broken.GetBurnFeeBPS(500); got != 500 {
		t.Fatalf("corrupt burn-fee record must fall back to the default, got %d", got)
	}
}

// TestBurnFeeRollReplayDeterministic executes blocks 1..3 (through the first
// epoch boundary) on two independent in-memory chains with gas-paying
// transfers and asserts:
//  1. byte-identical state roots at every height on both instances, and
//  2. the committed burn rate rolls 500 → 495 → 490 from the PREVIOUS
//     block's committed gas (each ~24k of 10M gas is far below the 50%
//     utilization target), and
//  3. the prev-gas snapshot persists the executed block's header values.
func TestBurnFeeRollReplayDeterministic(t *testing.T) {
	gasLimit := big.NewInt(10_000_000)

	mkChain := func(t *testing.T) (*Blockchain, *database.DB) {
		t.Helper()
		dir := t.TempDir()
		db, err := database.NewLevelDB(dir + "/state")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return mkIB(t, dir, db), db
	}
	payTx := func(id string, nonce uint64) *txtypes.Transaction {
		return &txtypes.Transaction{
			ID: id, Sender: "payer", Receiver: "receiver", Nonce: nonce,
			Amount: big.NewInt(1), Timestamp: common.GetCurrentTimestamp(),
			GasLimit: big.NewInt(24_200), GasPrice: big.NewInt(1_000_000_000),
		}
	}

	bcA, dbA := mkChain(t)
	bcB, dbB := mkChain(t)
	// Fund the payer identically on both chains.
	for _, db := range []*database.DB{dbA, dbB} {
		s := NewStateDB(db)
		s.SetBalance("payer", new(big.Int).Mul(big.NewInt(10_000), big.NewInt(1_000_000_000_000_000_000)))
		if _, err := s.Commit(); err != nil {
			t.Fatal(err)
		}
	}

	wantBurnFee := []uint64{500, 495, 490} // committed after blocks 1, 2, 3
	for h := uint64(1); h <= 3; h++ {
		blockA := blockWith(t, h, payTx("tx-a-"+string(rune('0'+h)), h-1))
		blockB := blockWith(t, h, payTx("tx-b-"+string(rune('0'+h)), h-1))
		blockA.Header.ProposerID = "validator-1"
		blockB.Header.ProposerID = "validator-1"

		rootA, err := bcA.ExecuteBlock(blockA)
		if err != nil {
			t.Fatalf("chain A ExecuteBlock(%d): %v", h, err)
		}
		rootB, err := bcB.ExecuteBlock(blockB)
		if err != nil {
			t.Fatalf("chain B ExecuteBlock(%d): %v", h, err)
		}
		if !bytes.Equal(rootA, rootB) {
			t.Fatalf("height %d: state roots diverged between independent instances:\nA=%x\nB=%x", h, rootA, rootB)
		}

		// Committed policy state after this block: the rolled burn rate and
		// this block's finalized gas footprint.
		for name, db := range map[string]*database.DB{"A": dbA, "B": dbB} {
			s := NewStateDB(db)
			if got := s.GetBurnFeeBPS(500); got != wantBurnFee[h-1] {
				t.Fatalf("chain %s height %d: committed burn fee = %d, want %d", name, h, got, wantBurnFee[h-1])
			}
			used, limit := s.GetPrevBlockGas()
			if used.Cmp(big.NewInt(24_200)) != 0 || limit.Cmp(gasLimit) != 0 {
				t.Fatalf("chain %s height %d: prev gas = (%s, %s), want (24200, %s)", name, h, used, limit, gasLimit)
			}
		}
	}
}
