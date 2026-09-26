// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/cge_test.go
//
// Core-side CGE (coins event generation) tests: the genesis split built into
// the block body and the per-block escrow → recipient release driven by
// sealed block timestamps. The pure schedule math lives with the schedules
// themselves in src/policy/cge_test.go.
package core

import (
	"math/big"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
)

// nspx converts whole SPX to nSPX for concise expectations.
func nspx(spx int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(spx), big.NewInt(1e18))
}

// cgeTestBlock builds the minimal block applyCGEReleases inspects — it only
// reads Header.Block (height) and Header.Timestamp.
func cgeTestBlock(height uint64, timestamp int64) *types.Block {
	return &types.Block{
		Header: &types.BlockHeader{
			Block:     height,
			Timestamp: timestamp,
		},
	}
}

// ============================================================================
// 1. Genesis split — what block 0 funds vs what the escrow holds
// ============================================================================

func TestDefaultCGESplit(t *testing.T) {
	escrowedLabels := map[string]bool{
		"Founder":      true,
		"CoFounder":    true,
		"Development":  true,
		"Contributors": true,
		"Airdrops":     true,
	}

	unlockedTotal := new(big.Int)
	lockedTotal := new(big.Int)
	for _, alloc := range DefaultGenesisAllocations() {
		unlocked := policy.CGEUnlockedAmount(alloc.Label, alloc.BalanceNSPX)
		locked := policy.CGELockedAmount(alloc.Label, alloc.BalanceNSPX)

		// Conservation: CGE + locked == total.
		sum := new(big.Int).Add(unlocked, locked)
		if sum.Cmp(alloc.BalanceNSPX) != 0 {
			t.Errorf("%s: CGE %s + locked %s != total %s",
				alloc.Label, unlocked.String(), locked.String(), alloc.BalanceNSPX.String())
		}

		if escrowedLabels[alloc.Label] {
			if unlocked.Sign() != 0 {
				t.Errorf("%s: want 0 unlocked at CGE, got %s", alloc.Label, unlocked.String())
			}
			if locked.Cmp(alloc.BalanceNSPX) != 0 {
				t.Errorf("%s: want full %s escrowed, got %s", alloc.Label, alloc.BalanceNSPX.String(), locked.String())
			}
		} else {
			if unlocked.Cmp(alloc.BalanceNSPX) != 0 {
				t.Errorf("%s: want full %s liquid at CGE, got %s", alloc.Label, alloc.BalanceNSPX.String(), unlocked.String())
			}
			if locked.Sign() != 0 {
				t.Errorf("%s: want 0 escrowed, got %s", alloc.Label, locked.String())
			}
		}

		unlockedTotal.Add(unlockedTotal, unlocked)
		lockedTotal.Add(lockedTotal, locked)
	}

	// Locked at genesis: 25M + 85M + 150M + 75M + 90M = 425,000,000 SPX.
	if lockedTotal.Cmp(nspx(425_000_000)) != 0 {
		t.Errorf("escrowed total: want 425,000,000 SPX, got %s", lockedTotal.String())
	}
	// Liquid at CGE: 300M + 15M + 100M + 200M = 615,000,000 SPX.
	if unlockedTotal.Cmp(nspx(615_000_000)) != 0 {
		t.Errorf("CGE total: want 615,000,000 SPX, got %s", unlockedTotal.String())
	}
	// Grand total: 1,040,000,000 SPX.
	grand := new(big.Int).Add(unlockedTotal, lockedTotal)
	if grand.Cmp(nspx(1_040_000_000)) != 0 {
		t.Errorf("grand total: want 1,040,000,000 SPX, got %s", grand.String())
	}
}

func TestCGEEscrowAddress_IsValidSystemAddress(t *testing.T) {
	if len(policy.CGEEscrowAddress) != 40 {
		t.Errorf("escrow address length: want 40, got %d", len(policy.CGEEscrowAddress))
	}
	if policy.CGEEscrowAddress == GenesisVaultAddress {
		t.Error("escrow address must differ from the genesis vault address")
	}
	if _, err := common.NormalizeSPIFAddress(policy.CGEEscrowAddress); err != nil {
		t.Errorf("escrow address must normalise as a valid SPIF address: %v", err)
	}
}

// TestAllocationsToTxList_CGESplit verifies the genesis funding transactions
// under the sold + escrow model: each allocation emits up to two transactions
// (its always-liquid direct slice, then its escrowed remainder), sent from the
// vault with a gap-free nonce sequence. The direct slice goes to the recipient,
// the escrowed slice to policy.CGEEscrowAddress, and the total funds the full
// 1,170,000,000 SPX gross (130,000,000 sold + 1,040,000,000 remainder).
func TestAllocationsToTxList_CGESplit(t *testing.T) {
	gs := &GenesisState{
		Timestamp:   CanonicalGenesisTimestamp,
		Allocations: DefaultGenesisAllocations(),
	}
	txs := gs.allocationsToTxList()

	// Expected shape, derived independently from the same policy helpers: one
	// direct part and/or one escrow part per allocation, in allocation order.
	type part struct {
		receiver string
		amount   *big.Int
	}
	var wantParts []part
	for _, a := range gs.Allocations {
		if a == nil || a.BalanceNSPX == nil || a.BalanceNSPX.Sign() <= 0 {
			continue
		}
		if d := policy.CGEGenesisDirectAmount(a.Label, a.BalanceNSPX); d.Sign() > 0 {
			wantParts = append(wantParts, part{a.Address, d})
		}
		if e := policy.CGEGenesisEscrowAmount(a.Label, a.BalanceNSPX); e.Sign() > 0 {
			wantParts = append(wantParts, part{policy.CGEEscrowAddress, e})
		}
	}
	if len(txs) != len(wantParts) {
		t.Fatalf("tx count: want %d, got %d", len(wantParts), len(txs))
	}

	total := new(big.Int)
	for i, tx := range txs {
		if tx.Sender != GenesisVaultAddress {
			t.Errorf("tx[%d]: sender = %q, want vault", i, tx.Sender)
		}
		if uint64(i) != tx.Nonce {
			t.Errorf("tx[%d]: nonce = %d, want %d (gap-free vault sequence)", i, tx.Nonce, i)
		}
		if tx.Receiver != wantParts[i].receiver {
			t.Errorf("tx[%d]: receiver = %q, want %q", i, tx.Receiver, wantParts[i].receiver)
		}
		if tx.Amount == nil || tx.Amount.Cmp(wantParts[i].amount) != 0 {
			t.Errorf("tx[%d]: amount = %v, want %s", i, tx.Amount, wantParts[i].amount.String())
		}
		total.Add(total, tx.Amount)
	}

	// Sold amounts are direct, so the funded total is the gross supply, not the
	// 1,040,000,000 remainder that the schedules apply to.
	if total.Cmp(nspx(1_170_000_000)) != 0 {
		t.Errorf("funded total: want 1,170,000,000 SPX, got %s", total.String())
	}
	if policy.CGEGenesisGrossSPX != 1_170_000_000 {
		t.Errorf("CGEGenesisGrossSPX = %d, want 1,170,000,000", policy.CGEGenesisGrossSPX)
	}
}

// TestGenesisVaultFundingCoversFullGross pins the vault-funding side of the
// sold + escrow model: block 0 pays out the full 1,170,000,000 SPX gross, so the
// vault must be funded with exactly that — not the 1,040,000,000 post-sale
// remainder. Otherwise ExecuteGenesisBlock's applyTransactions aborts with
// "insufficient balance" once cumulative payouts exceed the remainder.
func TestGenesisVaultFundingCoversFullGross(t *testing.T) {
	block := DefaultGenesisState().BuildBlock()

	funding := genesisVaultFundingNSPX(block)
	if funding.Cmp(nspx(1_170_000_000)) != 0 {
		t.Fatalf("vault funding: want 1,170,000,000 SPX, got %s", funding.String())
	}

	// Every payout must be drawn from the funding, so the funded vault drains to
	// zero and IsDistributionComplete() becomes true after block 0.
	payouts := new(big.Int)
	for i, tx := range block.Body.TxsList {
		if tx.Sender != GenesisVaultAddress {
			t.Errorf("txs_list[%d].Sender = %q, want the genesis vault", i, tx.Sender)
			continue
		}
		if tx.Amount == nil {
			t.Fatalf("txs_list[%d].Amount is nil", i)
		}
		payouts.Add(payouts, tx.Amount)
	}
	if payouts.Cmp(funding) != 0 {
		t.Fatalf("payouts %s != vault funding %s", payouts.String(), funding.String())
	}
}

// ============================================================================
// 2. applyCGEReleases — escrow → recipient, driven by block timestamps
// ============================================================================

// newCGEStateDB opens a throwaway LevelDB-backed StateDB and seeds the
// escrow exactly as block 0 would: with the full locked remainder
// (425,000,000 SPX). Releases are asserted against pending (uncommitted)
// state, so no state-root hashing is needed.
func newCGEStateDB(t *testing.T) *StateDB {
	t.Helper()
	db, err := database.NewLevelDB(t.TempDir())
	if err != nil {
		t.Fatalf("NewLevelDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := NewStateDB(db)
	s.SetBalance(policy.CGEEscrowAddress, nspx(425_000_000))
	return s
}

// allocByLabel returns the canonical allocation for a label.
func allocByLabel(t *testing.T, label string) *GenesisAllocation {
	t.Helper()
	for _, a := range DefaultGenesisAllocations() {
		if a.Label == label {
			return a
		}
	}
	t.Fatalf("no canonical allocation with label %q", label)
	return nil
}

func TestApplyCGEReleases_Milestones(t *testing.T) {
	s := newCGEStateDB(t)
	genesisTS := CanonicalGenesisTimestamp

	founder := allocByLabel(t, "Founder")
	cofounder := allocByLabel(t, "CoFounder")
	dev := allocByLabel(t, "Development")
	contributors := allocByLabel(t, "Contributors")
	airdrops := allocByLabel(t, "Airdrops")
	foundation := allocByLabel(t, "Foundation")

	// Block 0 persists the clock origin.
	applyCGEReleases(cgeTestBlock(0, genesisTS), s)
	if got := s.GetCGEGenesisTimestamp(); got != genesisTS {
		t.Fatalf("genesis timestamp: want %d, got %d", genesisTS, got)
	}

	balanceOf := func(addr string) *big.Int {
		bal, err := s.GetBalance(addr)
		if err != nil {
			t.Fatalf("GetBalance(%s): %v", addr, err)
		}
		return bal
	}

	// ── Before the first milestone: nothing moves ────────────────────────
	applyCGEReleases(cgeTestBlock(1, genesisTS+12*policy.CGEMonthSeconds-1), s)
	if bal := balanceOf(founder.Address); bal.Sign() != 0 {
		t.Errorf("founder before cliff: want 0, got %s", bal.String())
	}

	// ── Month 12: first founder tranche + contributors/airdrops progress ─
	applyCGEReleases(cgeTestBlock(2, genesisTS+12*policy.CGEMonthSeconds), s)

	if bal := balanceOf(founder.Address); bal.Cmp(nspx(6_250_000)) != 0 {
		t.Errorf("founder at 12mo: want 6,250,000 SPX (25%%), got %s", bal.String())
	}
	if bal := balanceOf(cofounder.Address); bal.Cmp(nspx(21_250_000)) != 0 {
		t.Errorf("cofounder at 12mo: want 21,250,000 SPX (25%%), got %s", bal.String())
	}
	if bal := balanceOf(contributors.Address); bal.Cmp(nspx(25_000_000)) != 0 {
		t.Errorf("contributors at 12mo: want 25,000,000 SPX (12/36), got %s", bal.String())
	}
	if bal := balanceOf(airdrops.Address); bal.Cmp(nspx(90_000_000)) != 0 {
		t.Errorf("airdrops at 12mo: want full 90,000,000 SPX (12/12), got %s", bal.String())
	}
	if bal := balanceOf(dev.Address); bal.Sign() != 0 {
		t.Errorf("development fund must never release by time, got %s", bal.String())
	}
	if bal := balanceOf(foundation.Address); bal.Sign() != 0 {
		t.Errorf("liquid categories never touch the escrow, got %s", bal.String())
	}

	// Idempotency: replaying the same block timestamp releases nothing more.
	applyCGEReleases(cgeTestBlock(3, genesisTS+12*policy.CGEMonthSeconds), s)
	if bal := balanceOf(founder.Address); bal.Cmp(nspx(6_250_000)) != 0 {
		t.Errorf("founder after replay: want unchanged 6,250,000 SPX, got %s", bal.String())
	}

	// ── Month 48: founders fully released; escrow keeps only the dev fund ─
	applyCGEReleases(cgeTestBlock(4, genesisTS+48*policy.CGEMonthSeconds), s)

	if bal := balanceOf(founder.Address); bal.Cmp(nspx(25_000_000)) != 0 {
		t.Errorf("founder at 48mo: want full 25,000,000 SPX, got %s", bal.String())
	}
	if bal := balanceOf(cofounder.Address); bal.Cmp(nspx(85_000_000)) != 0 {
		t.Errorf("cofounder at 48mo: want full 85,000,000 SPX, got %s", bal.String())
	}
	if bal := balanceOf(contributors.Address); bal.Cmp(nspx(75_000_000)) != 0 {
		t.Errorf("contributors at 48mo: want full 75,000,000 SPX, got %s", bal.String())
	}
	if bal := balanceOf(dev.Address); bal.Sign() != 0 {
		t.Errorf("development fund must still be untouched, got %s", bal.String())
	}

	// Escrow retains exactly the module-gated Development Fund: 150,000,000.
	if bal := balanceOf(policy.CGEEscrowAddress); bal.Cmp(nspx(150_000_000)) != 0 {
		t.Errorf("escrow after full release: want 150,000,000 SPX (dev fund), got %s", bal.String())
	}

	// Conservation: escrow + recipients == the 425,000,000 escrowed at genesis.
	total := new(big.Int).Set(balanceOf(policy.CGEEscrowAddress))
	for _, a := range []*GenesisAllocation{founder, cofounder, contributors, airdrops, dev} {
		total.Add(total, balanceOf(a.Address))
	}
	if total.Cmp(nspx(425_000_000)) != 0 {
		t.Errorf("escrowed supply conservation: want 425,000,000 SPX, got %s", total.String())
	}
}

func TestApplyCGEReleases_EscrowShortfallIsSkipped(t *testing.T) {
	s := newCGEStateDB(t)
	// Drain the escrow so no delta can be paid.
	if err := s.Transfer(policy.CGEEscrowAddress, "ffffffffffffffffffffffffffffffffffffffff", nspx(425_000_000)); err != nil {
		t.Fatalf("drain escrow: %v", err)
	}

	genesisTS := CanonicalGenesisTimestamp
	applyCGEReleases(cgeTestBlock(0, genesisTS), s)
	applyCGEReleases(cgeTestBlock(1, genesisTS+48*policy.CGEMonthSeconds), s)

	founder := allocByLabel(t, "Founder")
	bal, err := s.GetBalance(founder.Address)
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if bal.Sign() != 0 {
		t.Errorf("no release may happen from an empty escrow, founder got %s", bal.String())
	}
}

// ============================================================================
// 3. ReleaseDevelopmentModule through core.StateDB — escrow → canonical
// Development recipient, tracked in deterministic contract state
// ============================================================================

func TestReleaseDevelopmentModule_StateBacked(t *testing.T) {
	s := newCGEStateDB(t)
	dev := allocByLabel(t, "Development")

	// Sanity: 150M SPX = 3,000 modules × 50,000 SPX exactly, so draining the
	// whole module schedule must drain exactly the dev-fund escrow remainder.
	reward := policy.CGEModuleRewardNSPX()
	wantTotal := new(big.Int).Mul(reward, big.NewInt(int64(policy.CGEMaxModules)))
	if wantTotal.Cmp(nspx(150_000_000)) != 0 {
		t.Fatalf("module schedule total: want 150,000,000 SPX, got %s nSPX", wantTotal.String())
	}

	// Nothing released yet.
	if got := policy.CGEDevModulesReleased(s); got != 0 {
		t.Fatalf("initial released modules: want 0, got %d", got)
	}

	// Release module 1 to the canonical Development recipient.
	if err := policy.ReleaseDevelopmentModule(s, dev.Address, 1); err != nil {
		t.Fatalf("release module 1: %v", err)
	}
	if got := policy.CGEDevModulesReleased(s); got != 1 {
		t.Fatalf("released after module 1: want 1, got %d", got)
	}
	if bal, _ := s.GetBalance(dev.Address); bal.Cmp(reward) != 0 {
		t.Fatalf("dev balance after module 1: want %s, got %s", reward.String(), bal.String())
	}

	// Bounds: module 0 and anything above CGEMaxModules are rejected.
	if err := policy.ReleaseDevelopmentModule(s, dev.Address, 0); err == nil {
		t.Error("module 0 must be rejected")
	}
	if err := policy.ReleaseDevelopmentModule(s, dev.Address, policy.CGEMaxModules+1); err == nil {
		t.Error("module above CGEMaxModules must be rejected")
	}

	// Replay: re-releasing module 1 is rejected.
	if err := policy.ReleaseDevelopmentModule(s, dev.Address, 1); err == nil {
		t.Error("double-release of module 1 must be rejected")
	}

	// Out-of-order: skipping ahead to module 3 is rejected.
	if err := policy.ReleaseDevelopmentModule(s, dev.Address, 3); err == nil {
		t.Error("out-of-order release (skip to 3) must be rejected")
	}

	// Release the remaining modules 2..3000.
	for id := uint64(2); id <= policy.CGEMaxModules; id++ {
		if err := policy.ReleaseDevelopmentModule(s, dev.Address, id); err != nil {
			t.Fatalf("release module %d: %v", id, err)
		}
	}
	if got := policy.CGEDevModulesReleased(s); got != policy.CGEMaxModules {
		t.Fatalf("final released modules: want %d, got %d", policy.CGEMaxModules, got)
	}

	// Recipient holds exactly 150,000,000 SPX; escrow holds 150M − 150M = 0
	// from the dev portion... i.e. 425M − 150M(dev released) − 275M(time
	// releases not run here) = 275M still escrowed in this fixture, which
	// seeded the full 425M. Assert the dev balance and conservation instead.
	if bal, _ := s.GetBalance(dev.Address); bal.Cmp(nspx(150_000_000)) != 0 {
		t.Fatalf("dev balance after all modules: want 150,000,000 SPX, got %s", bal.String())
	}
	escrowBal, _ := s.GetBalance(policy.CGEEscrowAddress)
	devBal, _ := s.GetBalance(dev.Address)
	total := new(big.Int).Add(escrowBal, devBal)
	if total.Cmp(nspx(425_000_000)) != 0 {
		t.Fatalf("escrow + dev conservation: want 425,000,000 SPX, got %s", total.String())
	}

	// One past the cap is rejected even though escrow accounting is exact.
	if err := policy.ReleaseDevelopmentModule(s, dev.Address, policy.CGEMaxModules+1); err == nil {
		t.Error("module beyond CGEMaxModules must be rejected after full release")
	}
}
