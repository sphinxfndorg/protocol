// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package policy

import (
	"bytes"
	"math/big"
	"testing"
)

// supplyForTests is 1,000,000 nSPX; small enough that every expected value in
// these tests is hand-computable.
var supplyForTests = big.NewInt(1_000_000)

// TestCalculateStakeAdjustedMultiplierBPSBoundaries pins the boundary values:
// 0% staked, exactly-on-target 70% (must yield exactly 10000 BPS = 1.0x),
// 100% staked, an over-100% ratio, and the genesis guards.
func TestCalculateStakeAdjustedMultiplierBPSBoundaries(t *testing.T) {
	p := NewPolicyParameters()

	cases := []struct {
		name   string
		staked int64
		want   uint64
	}{
		{"0% staked boosts inflation to 1.7x", 0, 17000},
		{"70% staked is exactly 1.0x", 700_000, 10000},
		{"100% staked dampens inflation to 0.7x", 1_000_000, 7000},
		{"150% staked clamps at the 0.5x floor", 1_500_000, 5000},
	}
	for _, c := range cases {
		if got := p.CalculateStakeAdjustedMultiplierBPS(big.NewInt(c.staked), new(big.Int).Set(supplyForTests)); got != c.want {
			t.Fatalf("%s: multiplier = %d, want %d", c.name, got, c.want)
		}
	}

	// Genesis guards: no supply or zero supply → exactly 1.0x regardless of stake.
	if got := p.CalculateStakeAdjustedMultiplierBPS(big.NewInt(123), nil); got != 10000 {
		t.Fatalf("nil supply must return 10000, got %d", got)
	}
	if got := p.CalculateStakeAdjustedMultiplierBPS(big.NewInt(123), big.NewInt(0)); got != 10000 {
		t.Fatalf("zero supply must return 10000, got %d", got)
	}
	if got := p.CalculateStakeAdjustedMultiplierBPS(nil, new(big.Int).Set(supplyForTests)); got != 17000 {
		t.Fatalf("nil staked must be a 0%% ratio, got %d", got)
	}
	if got := p.CalculateStakeAdjustedMultiplierBPS(big.NewInt(-5), new(big.Int).Set(supplyForTests)); got != 17000 {
		t.Fatalf("negative staked must be treated as 0%%, got %d", got)
	}

	// Integer BPS granularity: one BPS below target → exactly one BPS of
	// boost at 1:1 sensitivity (6,999,999/10,000,000 floors to 6999 BPS).
	tiny := new(big.Int).Set(supplyForTests)
	tiny.Mul(tiny, big.NewInt(10)) // 10,000,000
	if got := p.CalculateStakeAdjustedMultiplierBPS(big.NewInt(6_999_999), tiny); got != 10001 {
		t.Fatalf("one BPS below target must yield 10001, got %d", got)
	}
}

// TestCalculateStakeAdjustedMultiplierBPSClamp pins the 0.5x/2.0x clamp edges
// with a 2:1 sensitivity (which pushes the unclamped multiplier past both
// bounds at 0% and 100% stake).
func TestCalculateStakeAdjustedMultiplierBPSClamp(t *testing.T) {
	p := NewPolicyParameters()
	p.StakeInflationSensitivityBPS = 20000

	if got := p.CalculateStakeAdjustedMultiplierBPS(big.NewInt(0), new(big.Int).Set(supplyForTests)); got != 20000 {
		t.Fatalf("0%% staked at 2x sensitivity must clamp at the 20000 ceiling, got %d", got)
	}
	if got := p.CalculateStakeAdjustedMultiplierBPS(big.NewInt(1_000_000), new(big.Int).Set(supplyForTests)); got != 5000 {
		t.Fatalf("100%% staked at 2x sensitivity must clamp at the 5000 floor, got %d", got)
	}
	// 80% staked at 2x: deviation -1000 → 10000 - 2000 = 8000, inside the window.
	if got := p.CalculateStakeAdjustedMultiplierBPS(big.NewInt(800_000), new(big.Int).Set(supplyForTests)); got != 8000 {
		t.Fatalf("80%% staked at 2x sensitivity must be unclamped 8000, got %d", got)
	}

	// Zero sensitivity falls back to the documented 1:1 default.
	zero := NewPolicyParameters()
	zero.StakeInflationSensitivityBPS = 0
	if got := zero.CalculateStakeAdjustedMultiplierBPS(big.NewInt(0), new(big.Int).Set(supplyForTests)); got != 17000 {
		t.Fatalf("zero sensitivity must fall back to 1:1 (17000 at 0%%), got %d", got)
	}

	// An inverted window is swapped rather than producing a dead zone.
	inverted := NewPolicyParameters()
	inverted.StakeMultiplierFloorBPS = 20000
	inverted.StakeMultiplierCeilingBPS = 5000
	if got := inverted.CalculateStakeAdjustedMultiplierBPS(big.NewInt(0), new(big.Int).Set(supplyForTests)); got != 17000 {
		t.Fatalf("inverted window must stay inside [floor, ceiling], got %d", got)
	}
}

// TestCalculateStakeAdjustedMultiplierBPSDeterminism locks PBFT determinism:
// byte-identical results across repeated calls and two independent policy
// instances, with no mutation of the inputs.
func TestCalculateStakeAdjustedMultiplierBPSDeterminism(t *testing.T) {
	p := NewPolicyParameters()
	q := NewPolicyParameters()

	staked := big.NewInt(432_109)
	supply := new(big.Int).Set(supplyForTests)
	for i := 0; i < 64; i++ {
		a := p.CalculateStakeAdjustedMultiplierBPS(staked, supply)
		b := q.CalculateStakeAdjustedMultiplierBPS(new(big.Int).Set(staked), new(big.Int).Set(supply))
		if a != b {
			t.Fatalf("two independent policy instances diverged: %d vs %d", a, b)
		}
	}
	if staked.Int64() != 432_109 || supply.Cmp(supplyForTests) != 0 {
		t.Fatal("CalculateStakeAdjustedMultiplierBPS must not mutate its inputs")
	}
}

// TestCalculateEpochInflationExactStakeAdjustment verifies the wiring: the
// multiplier is applied to the decayed base amount (multiply-before-divide)
// and reported on the distribution.
func TestCalculateEpochInflationExactStakeAdjustment(t *testing.T) {
	p := NewPolicyParameters()
	p.BlocksPerEpoch = p.GetBlocksPerYear() // one epoch per year → epochsPerYear = 1

	// Base (decayed) amount at year 1: 1,000,000 * 500 / 10000 = 50,000.
	// On target (70%): exactly 1.0x → 50,000 minted, 80/20 split 40,000/10,000.
	onTarget := p.CalculateEpochInflationExact(new(big.Int).Set(supplyForTests), big.NewInt(700_000), 1)
	if onTarget.StakeMultiplierBPS != 10000 || onTarget.TotalMinted.Cmp(big.NewInt(50000)) != 0 {
		t.Fatalf("on-target: multiplier=%d minted=%s, want 10000/50000", onTarget.StakeMultiplierBPS, onTarget.TotalMinted)
	}
	if onTarget.StakingRewards.Cmp(big.NewInt(40000)) != 0 || onTarget.CommunityFund.Cmp(big.NewInt(10000)) != 0 {
		t.Fatalf("on-target split: %s/%s, want 40000/10000", onTarget.StakingRewards, onTarget.CommunityFund)
	}

	// 0% staked: 1.7x → 50,000 * 17000 / 10000 = 85,000 (multiply-before-divide).
	boosted := p.CalculateEpochInflationExact(new(big.Int).Set(supplyForTests), big.NewInt(0), 1)
	if boosted.StakeMultiplierBPS != 17000 || boosted.TotalMinted.Cmp(big.NewInt(85000)) != 0 {
		t.Fatalf("0%% staked: multiplier=%d minted=%s, want 17000/85000", boosted.StakeMultiplierBPS, boosted.TotalMinted)
	}
	if boosted.StakingRewards.Cmp(big.NewInt(68000)) != 0 || boosted.CommunityFund.Cmp(big.NewInt(17000)) != 0 {
		t.Fatalf("boosted split: %s/%s, want 68000/17000", boosted.StakingRewards, boosted.CommunityFund)
	}

	// 100% staked: 0.7x → 50,000 * 7000 / 10000 = 35,000.
	damped := p.CalculateEpochInflationExact(new(big.Int).Set(supplyForTests), big.NewInt(1_000_000), 1)
	if damped.StakeMultiplierBPS != 7000 || damped.TotalMinted.Cmp(big.NewInt(35000)) != 0 {
		t.Fatalf("100%% staked: multiplier=%d minted=%s, want 7000/35000", damped.StakeMultiplierBPS, damped.TotalMinted)
	}

	// Determinism across two independent instances: byte-identical big.Int.
	again := NewPolicyParameters()
	again.BlocksPerEpoch = again.GetBlocksPerYear()
	other := again.CalculateEpochInflationExact(new(big.Int).Set(supplyForTests), big.NewInt(0), 1)
	if other.TotalMinted.Cmp(boosted.TotalMinted) != 0 || !bytes.Equal(other.TotalMinted.Bytes(), boosted.TotalMinted.Bytes()) {
		t.Fatalf("independent instances diverged: %s vs %s", other.TotalMinted, boosted.TotalMinted)
	}

	// Degenerate supply → all-zero distribution.
	empty := p.CalculateEpochInflationExact(nil, big.NewInt(700_000), 1)
	if empty.TotalMinted.Sign() != 0 {
		t.Fatalf("nil supply must yield a zero distribution, got %s", empty.TotalMinted)
	}
}
