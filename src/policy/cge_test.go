// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/policy/cge_test.go
package policy

import (
	"fmt"
	"math/big"
	"testing"
)

// cgeNSPX converts whole SPX to nSPX for concise expectations.
func cgeNSPX(spx int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(spx), big.NewInt(1e18))
}

// TestCGEScheduleAnnualTranches pins the 25%-at-months-12/24/36/48 curve,
// the 12-month cliff, the cap at total, and the negative-elapsed guard.
func TestCGEScheduleAnnualTranches(t *testing.T) {
	sched := CGESchedule{Kind: CGEAnnualTranches}
	total := cgeNSPX(1000)

	cases := []struct {
		name       string
		elapsedSec int64
		wantSPX    int64
	}{
		{"genesis", 0, 0},
		{"1 month", CGEMonthSeconds, 0},
		{"12 months minus 1s (cliff not reached)", 12*CGEMonthSeconds - 1, 0},
		{"12 months exactly (first tranche)", 12 * CGEMonthSeconds, 250},
		{"23 months", 23 * CGEMonthSeconds, 250},
		{"24 months (second tranche)", 24 * CGEMonthSeconds, 500},
		{"36 months (third tranche)", 36 * CGEMonthSeconds, 750},
		{"48 months (fully released)", 48 * CGEMonthSeconds, 1000},
		{"60 months (capped at total)", 60 * CGEMonthSeconds, 1000},
		{"negative elapsed clamps to 0", -100, 0},
	}
	for _, tc := range cases {
		got := sched.UnlockedAt(tc.elapsedSec, total)
		want := cgeNSPX(tc.wantSPX)
		if got.Cmp(want) != 0 {
			t.Errorf("%s: want %s nSPX, got %s", tc.name, want.String(), got.String())
		}
	}
}

// TestCGEScheduleLinear verifies exact big.Int proportions for the 36-month
// contributors schedule and the 12-month airdrops schedule.
func TestCGEScheduleLinear(t *testing.T) {
	// Contributors: linear over 36 months, exact big.Int proportions.
	contrib := CGEScheduleForLabel("Contributors")
	total := cgeNSPX(75)
	if got := contrib.UnlockedAt(0, total); got.Sign() != 0 {
		t.Errorf("contributors at CGE: want 0, got %s", got.String())
	}
	want18mo := new(big.Int).Div(
		new(big.Int).Mul(total, big.NewInt(18*CGEMonthSeconds)),
		big.NewInt(36*CGEMonthSeconds))
	if got := contrib.UnlockedAt(18*CGEMonthSeconds, total); got.Cmp(want18mo) != 0 {
		t.Errorf("contributors at 18mo: want %s, got %s", want18mo.String(), got.String())
	}
	if got := contrib.UnlockedAt(36*CGEMonthSeconds, total); got.Cmp(total) != 0 {
		t.Errorf("contributors at 36mo: want full %s, got %s", total.String(), got.String())
	}
	if got := contrib.UnlockedAt(48*CGEMonthSeconds, total); got.Cmp(total) != 0 {
		t.Errorf("contributors at 48mo: want capped %s, got %s", total.String(), got.String())
	}

	// Airdrops: linear over 12 months, exact halves.
	air := CGEScheduleForLabel("Airdrops")
	airTotal := cgeNSPX(90)
	if got := air.UnlockedAt(6*CGEMonthSeconds, airTotal); got.Cmp(cgeNSPX(45)) != 0 {
		t.Errorf("airdrops at 6mo: want 45 SPX, got %s", got.String())
	}
	if got := air.UnlockedAt(12*CGEMonthSeconds, airTotal); got.Cmp(airTotal) != 0 {
		t.Errorf("airdrops at 12mo: want full %s, got %s", airTotal.String(), got.String())
	}
}

// TestCGEScheduleLiquidAndModuleGated covers the two non-time-based kinds:
// liquid categories are always fully available, module-gated never releases
// through the passage of time.
func TestCGEScheduleLiquidAndModuleGated(t *testing.T) {
	liquid := CGEScheduleForLabel("Foundation")
	if liquid.IsTimeBased() {
		t.Error("Foundation schedule must not be time-based")
	}
	total := cgeNSPX(300)
	for _, elapsed := range []int64{0, 1, CGEMonthSeconds, 100 * 12 * CGEMonthSeconds} {
		if got := liquid.UnlockedAt(elapsed, total); got.Cmp(total) != 0 {
			t.Errorf("liquid at %ds: want full %s, got %s", elapsed, total.String(), got.String())
		}
	}

	mod := CGEScheduleForLabel("Development")
	if mod.IsTimeBased() {
		t.Error("Development schedule must NOT be time-based (module-gated only)")
	}
	devTotal := cgeNSPX(150)
	for _, elapsed := range []int64{0, CGEMonthSeconds, 1000 * 12 * CGEMonthSeconds} {
		if got := mod.UnlockedAt(elapsed, devTotal); got.Sign() != 0 {
			t.Errorf("module-gated at %ds: want 0, got %s", elapsed, got.String())
		}
	}
}

// TestCGEScheduleForLabelMapping pins the label → schedule mapping that is
// part of the consensus specification, including the liquid fallback for
// unknown labels.
func TestCGEScheduleForLabelMapping(t *testing.T) {
	cases := []struct {
		label       string
		wantKind    CGEKind
		wantTimeBas bool
	}{
		{"Founder", CGEAnnualTranches, true},
		{"CoFounder", CGEAnnualTranches, true},
		{"Development", CGEModuleGated, false},
		{"Contributors", CGELinear, true},
		{"Airdrops", CGELinear, true},
		{"Foundation", CGELiquid, false},
		{"Campaigns", CGELiquid, false},
		{"PublicICOPool", CGELiquid, false},
		{"Reserve", CGELiquid, false},
		{"UnknownLabel", CGELiquid, false}, // ad-hoc labels stay liquid
	}
	for _, tc := range cases {
		s := CGEScheduleForLabel(tc.label)
		if s.Kind != tc.wantKind {
			t.Errorf("%s: kind = %d, want %d", tc.label, s.Kind, tc.wantKind)
		}
		if s.IsTimeBased() != tc.wantTimeBas {
			t.Errorf("%s: IsTimeBased = %v, want %v", tc.label, s.IsTimeBased(), tc.wantTimeBas)
		}
	}
}

// TestCGEUnlockedAndLockedAmounts verifies the genesis split helpers: CGE + locked
// always equals the total, liquid labels unlock everything at CGE, and
// escrowed labels lock everything.
func TestCGEUnlockedAndLockedAmounts(t *testing.T) {
	if got := CGEUnlockedAmount("Foundation", cgeNSPX(300)); got.Cmp(cgeNSPX(300)) != 0 {
		t.Errorf("liquid CGE amount: want full 300 SPX, got %s", got.String())
	}
	if got := CGELockedAmount("Foundation", cgeNSPX(300)); got.Sign() != 0 {
		t.Errorf("liquid locked amount: want 0, got %s", got.String())
	}
	if got := CGEUnlockedAmount("Founder", cgeNSPX(25)); got.Sign() != 0 {
		t.Errorf("founder CGE amount: want 0, got %s", got.String())
	}
	if got := CGELockedAmount("Founder", cgeNSPX(25)); got.Cmp(cgeNSPX(25)) != 0 {
		t.Errorf("founder locked amount: want full 25 SPX, got %s", got.String())
	}
	// nil totals never panic.
	if got := CGEUnlockedAmount("Founder", nil); got.Sign() != 0 {
		t.Errorf("nil total must unlock 0, got %s", got.String())
	}
	if got := CGELockedAmount("Founder", nil); got.Sign() != 0 {
		t.Errorf("nil total must lock 0, got %s", got.String())
	}
}

// TestCGEGenesisAmounts_Conservation verifies the policy-owned genesis
// amounts conserve: per-label values sum to the canonical total, and the
// escrowed/liquid splits match the schedule math.
func TestCGEGenesisAmounts_Conservation(t *testing.T) {
	labels := []string{"Founder", "CoFounder", "Development", "Contributors", "Foundation", "Campaigns", "Airdrops", "PublicICOPool", "Reserve"}
	var total int64
	for _, label := range labels {
		amt := CGEGenesisAmountSPX(label)
		if amt <= 0 {
			t.Fatalf("CGEGenesisAmountSPX(%q): want positive, got %d", label, amt)
		}
		if sched := CGEScheduleForLabel(label); sched.IsTimeBased() || label == "Development" {
			// escrowed categories must fully lock at CGE
			locked := CGELockedAmount(label, cgeNSPX(amt))
			if locked.Cmp(cgeNSPX(amt)) != 0 {
				t.Fatalf("%s: want fully escrowed %d SPX, got %s nSPX", label, amt, locked.String())
			}
		} else {
			// liquid categories must fully unlock at CGE
			unlocked := CGEUnlockedAmount(label, cgeNSPX(amt))
			if unlocked.Cmp(cgeNSPX(amt)) != 0 {
				t.Fatalf("%s: want fully liquid %d SPX, got %s nSPX", label, amt, unlocked.String())
			}
		}
		total += amt
	}
	if total != CGEGenesisTotalSPX {
		t.Fatalf("genesis total: want %d SPX, got %d", CGEGenesisTotalSPX, total)
	}
	if CGEFounderSPX+CGECoFounderSPX+CGEDevelopmentSPX+CGEContributorsSPX+CGEAirdropsSPX != CGEGenesisEscrowedSPX {
		t.Fatalf("escrowed total: want %d SPX", CGEGenesisEscrowedSPX)
	}
	if CGEFoundationSPX+CGECampaignsSPX+CGEPublicICOPoolSPX+CGEReserveSPX != CGEGenesisLiquidSPX {
		t.Fatalf("liquid total: want %d SPX", CGEGenesisLiquidSPX)
	}
	if CGEGenesisEscrowedSPX+CGEGenesisLiquidSPX != CGEGenesisTotalSPX {
		t.Fatalf("escrowed + liquid must equal total genesis")
	}
	// Development module economics must exactly fund the Development amount.
	if got := CGEModuleRewardSPX * int64(CGEMaxModules); got != CGEDevelopmentSPX {
		t.Fatalf("module economics: want reward×max = %d SPX, got %d", CGEDevelopmentSPX, got)
	}
	if CGEGenesisAmountSPX("Unknown-label") != 0 {
		t.Fatal("unknown label must return 0")
	}
}

// TestCGESoldAmounts_Conservation verifies the sold-at-genesis amounts sum to
// the Angel Round / Public ICO totals, and that sold + remainder == gross for
// every category, gross summing to 1,170,000,000 SPX.
func TestCGESoldAmounts_Conservation(t *testing.T) {
	labels := []string{"Founder", "CoFounder", "Development", "Contributors", "Foundation", "Campaigns", "Airdrops", "PublicICOPool", "Reserve"}
	var gross, sold int64
	for _, label := range labels {
		remainder := CGEGenesisAmountSPX(label)
		s := CGESoldAmountSPX(label)
		if got := CGEGrossGenesisAmountSPX(label); got != remainder+s {
			t.Fatalf("%s: gross = %d, want remainder(%d) + sold(%d) = %d", label, got, remainder, s, remainder+s)
		}
		gross += remainder + s
		sold += s
	}
	if sold != CGEGenesisSoldSPX {
		t.Fatalf("total sold: want %d, got %d", CGEGenesisSoldSPX, sold)
	}
	if gross != CGEGenesisGrossSPX {
		t.Fatalf("gross total: want %d, got %d", CGEGenesisGrossSPX, gross)
	}
	if CGEFounderSoldSPX+CGECoFounderSoldSPX+CGEDevelopmentSoldSPX/2+CGEContributorsSoldSPX != 30_000_000 {
		t.Fatalf("Angel Round total: want 30,000,000")
	}
	if CGEDevelopmentSoldSPX/2+CGEPublicICOPoolSoldSPX != 100_000_000 {
		t.Fatalf("Public ICO total: want 100,000,000")
	}
}

// TestCGEGenesisDirectAndEscrowAmounts verifies the split helpers: the sold
// amount is always direct/liquid, module-gated Development escrows its full
// remainder, and direct+escrow always equals sold+remainder for every label.
func TestCGEGenesisDirectAndEscrowAmounts(t *testing.T) {
	cases := []struct {
		label         string
		remainderSPX  int64
		wantDirectSPX int64
	}{
		{"Founder", CGEFounderSPX, CGEFounderSoldSPX},                                         // annual tranches: 0 unlocked at CGE
		{"Development", CGEDevelopmentSPX, CGEDevelopmentSoldSPX},                             // module-gated: 0 unlocked at CGE
		{"Foundation", CGEFoundationSPX, CGEFoundationSPX},                                    // liquid: all unlocked at CGE, nothing sold
		{"PublicICOPool", CGEPublicICOPoolSPX, CGEPublicICOPoolSoldSPX + CGEPublicICOPoolSPX}, // sold (90M) + liquid remainder (100M) = 190M direct
	}
	for _, tc := range cases {
		remainder := cgeNSPX(tc.remainderSPX)
		direct := CGEGenesisDirectAmount(tc.label, remainder)
		escrow := CGEGenesisEscrowAmount(tc.label, remainder)
		if sum := new(big.Int).Add(direct, escrow); sum.Cmp(new(big.Int).Add(cgeNSPX(CGESoldAmountSPX(tc.label)), remainder)) != 0 {
			t.Fatalf("%s: direct+escrow = %s, want sold+remainder", tc.label, sum.String())
		}
		want := cgeNSPX(tc.wantDirectSPX)
		if direct.Cmp(want) != 0 {
			t.Fatalf("%s: direct = %s, want %s", tc.label, direct.String(), want.String())
		}
	}
}

// ----------------------------------------------------------------------------
// Test fake state for Development module releases
// ----------------------------------------------------------------------------

type fakeCGEState struct {
	balances  map[string]*big.Int
	contracts map[string][]byte
}

func newFakeCGEState() *fakeCGEState {
	return &fakeCGEState{
		balances:  make(map[string]*big.Int),
		contracts: make(map[string][]byte),
	}
}

func (f *fakeCGEState) GetBalance(address string) (*big.Int, error) {
	if b, ok := f.balances[address]; ok {
		return new(big.Int).Set(b), nil
	}
	return big.NewInt(0), nil
}

func (f *fakeCGEState) Transfer(from, to string, amount *big.Int) error {
	if amount == nil || amount.Sign() <= 0 {
		return fmt.Errorf("transfer: non-positive amount")
	}
	fromBal, _ := f.GetBalance(from)
	if fromBal.Cmp(amount) < 0 {
		return fmt.Errorf("transfer: insufficient balance (%s < %s)", fromBal, amount)
	}
	toBal, _ := f.GetBalance(to)
	f.balances[from] = new(big.Int).Sub(fromBal, amount)
	f.balances[to] = new(big.Int).Add(toBal, amount)
	return nil
}

func (f *fakeCGEState) GetContractValue(key string) ([]byte, error) {
	if v, ok := f.contracts[key]; ok {
		return append([]byte(nil), v...), nil
	}
	return nil, fmt.Errorf("key not found: %s", key)
}

func (f *fakeCGEState) SetContractValue(key string, value []byte) {
	f.contracts[key] = append([]byte(nil), value...)
}

func TestReleaseDevelopmentModule_SequentialExecution(t *testing.T) {
	state := newFakeCGEState()
	// Seed escrow with exactly 150M SPX (the development fund portion)
	state.balances[CGEEscrowAddress] = cgeNSPX(150_000_000)
	devRecipient := "0xDEVRECIPIENT00000000000000000000000000"

	// 1. Initial count must be 0
	if got := CGEDevModulesReleased(state); got != 0 {
		t.Fatalf("initial released modules: want 0, got %d", got)
	}

	reward := CGEModuleRewardNSPX()

	// 2. Release module 1
	if err := ReleaseDevelopmentModule(state, devRecipient, 1); err != nil {
		t.Fatalf("release module 1 failed: %v", err)
	}
	if got := CGEDevModulesReleased(state); got != 1 {
		t.Fatalf("released modules after 1: want 1, got %d", got)
	}
	recipBal, _ := state.GetBalance(devRecipient)
	if recipBal.Cmp(reward) != 0 {
		t.Fatalf("recipient balance after module 1: want %s, got %s", reward, recipBal)
	}

	// 3. Double-releasing module 1 must fail and leave state unchanged
	if err := ReleaseDevelopmentModule(state, devRecipient, 1); err == nil {
		t.Fatal("double-releasing module 1 must return error")
	}

	// 4. Skipping to module 3 must fail (out-of-order)
	if err := ReleaseDevelopmentModule(state, devRecipient, 3); err == nil {
		t.Fatal("skipping to module 3 out of order must return error")
	}

	// 5. Release through the remaining 2..3000 modules
	for id := uint64(2); id <= CGEMaxModules; id++ {
		if err := ReleaseDevelopmentModule(state, devRecipient, id); err != nil {
			t.Fatalf("release module %d failed: %v", id, err)
		}
	}

	// Escrow should be completely drained of its 150M SPX
	escrowBal, _ := state.GetBalance(CGEEscrowAddress)
	if escrowBal.Sign() != 0 {
		t.Fatalf("escrow balance after 3000 modules: want 0, got %s", escrowBal)
	}

	// Recipient should hold exactly 150,000,000 SPX
	wantTotal := cgeNSPX(150_000_000)
	recipBal, _ = state.GetBalance(devRecipient)
	if recipBal.Cmp(wantTotal) != 0 {
		t.Fatalf("recipient total balance: want %s, got %s", wantTotal, recipBal)
	}

	if got := CGEDevModulesReleased(state); got != CGEMaxModules {
		t.Fatalf("final released modules: want %d, got %d", CGEMaxModules, got)
	}

	// 6. Attempting module 3001 must fail (exceeds cap)
	if err := ReleaseDevelopmentModule(state, devRecipient, CGEMaxModules+1); err == nil {
		t.Fatal("releasing module beyond CGEMaxModules must return error")
	}
}

func TestReleaseDevelopmentModule_ValidationAndErrors(t *testing.T) {
	state := newFakeCGEState()
	state.balances[CGEEscrowAddress] = cgeNSPX(150_000_000)
	devRecipient := "0xDEVRECIPIENT00000000000000000000000000"

	// Nil state
	if err := ReleaseDevelopmentModule(nil, devRecipient, 1); err == nil {
		t.Error("nil state must return error")
	}

	// Empty recipient
	if err := ReleaseDevelopmentModule(state, "", 1); err == nil {
		t.Error("empty recipient must return error")
	}

	// Module 0 out of range
	if err := ReleaseDevelopmentModule(state, devRecipient, 0); err == nil {
		t.Error("module ID 0 must return error")
	}

	// Module > 3000 out of range
	if err := ReleaseDevelopmentModule(state, devRecipient, 3001); err == nil {
		t.Error("module ID 3001 must return error")
	}

	// Escrow shortfall
	emptyEscrowState := newFakeCGEState()
	if err := ReleaseDevelopmentModule(emptyEscrowState, devRecipient, 1); err == nil {
		t.Error("release with empty escrow must return error")
	}
}
