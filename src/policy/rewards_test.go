// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package policy

import (
	"bytes"
	"math/big"
	"testing"
)

// e18 is 1 SPX expressed in nSPX.
var e18 = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)

// TestCalculateBlockRewardDeterministicAtHeight locks the PBFT determinism
// contract: the reward is a pure function of (policy, height), so repeated
// calls at the same height — and calls from two independent policy instances —
// must produce byte-identical big.Int values.
func TestCalculateBlockRewardDeterministicAtHeight(t *testing.T) {
	heights := []uint64{0, 1, 2, 1000, 2_628_000, 13_140_000}
	p := NewPolicyParameters()
	q := NewPolicyParameters() // independent instance, same policy

	for _, h := range heights {
		first := p.CalculateBlockReward(h)
		if first == nil || first.Sign() <= 0 {
			t.Fatalf("height %d: reward must be positive, got %v", h, first)
		}
		for i := 0; i < 32; i++ {
			again := p.CalculateBlockReward(h)
			if again.Cmp(first) != 0 || !bytes.Equal(again.Bytes(), first.Bytes()) {
				t.Fatalf("height %d: reward not byte-identical across repeated calls: %s vs %s", h, first, again)
			}
			other := q.CalculateBlockReward(h)
			if other.Cmp(first) != 0 || !bytes.Equal(other.Bytes(), first.Bytes()) {
				t.Fatalf("height %d: two independent policy instances diverged: %s vs %s", h, first, other)
			}
		}
		// The returned value must be a copy: mutating it must not corrupt
		// the active policy for the next call.
		first.SetInt64(0)
		if fresh := p.CalculateBlockReward(h); fresh.Sign() <= 0 {
			t.Fatalf("height %d: CalculateBlockReward returned a live policy reference", h)
		}
	}
}

// TestCalculateBlockRewardDecayCurveSnapshot pins the height-derived decay
// curve at every blocks-per-year boundary through year 5. The expected values
// are derived here from the rate(y) = 5% × 0.8^(y-1) shape — the same integer
// decay the epoch-inflation path uses — NOT by calling CalculateBlockReward.
func TestCalculateBlockRewardDecayCurveSnapshot(t *testing.T) {
	p := NewPolicyParameters()
	blocksPerYear := p.GetBlocksPerYear()
	if blocksPerYear == 0 {
		t.Fatal("policy must define a usable blocks-per-year")
	}

	// Year N covers heights [blocksPerYear*(N-1), blocksPerYear*N). The
	// reference multiplier walks 10000 → 8000 → 6400 → 5120 → 4096 BPS
	// (InflationDecayBPS = 8000), always multiply-before-divide.
	prevMultiplier := uint64(0)
	multiplierBPS := uint64(10000)
	for year := uint64(1); year <= 5; year++ {
		firstHeight := blocksPerYear * (year - 1)
		wantReward := new(big.Int).Mul(p.BlockReward, new(big.Int).SetUint64(multiplierBPS))
		wantReward.Div(wantReward, big.NewInt(10000))

		if got := p.CalculateBlockReward(firstHeight); got.Cmp(wantReward) != 0 {
			t.Fatalf("year %d first block (height %d): reward = %s, want %s (multiplier %d BPS)",
				year, firstHeight, got, wantReward, multiplierBPS)
		}
		// Determinism at the boundary too: byte-identical across repeated calls.
		a := p.CalculateBlockReward(firstHeight)
		b := p.CalculateBlockReward(firstHeight)
		if !bytes.Equal(a.Bytes(), b.Bytes()) {
			t.Fatalf("year %d first block: repeated calls diverged: %s vs %s", year, a, b)
		}

		if year > 1 {
			// The last block of the previous year must still pay the
			// previous (higher) step of the curve.
			wantPrev := new(big.Int).Mul(p.BlockReward, new(big.Int).SetUint64(prevMultiplier))
			wantPrev.Div(wantPrev, big.NewInt(10000))
			if got := p.CalculateBlockReward(firstHeight - 1); got.Cmp(wantPrev) != 0 {
				t.Fatalf("last block of year %d (height %d): reward = %s, want %s (multiplier %d BPS)",
					year-1, firstHeight-1, got, wantPrev, prevMultiplier)
			}
		}

		prevMultiplier = multiplierBPS
		multiplierBPS = multiplierBPS * 8000 / 10000
	}

	// Named spot checks so a silent constant change fails loudly with
	// human-readable numbers (5 SPX base, 0.8 decay per year):
	// 5 → 4 → 3.2 → 2.56 → 2.048 SPX. Values are in units of 1e15 nSPX so
	// every literal fits int64.
	snapshots := []struct {
		year      uint64
		wantFemto int64 // reward in 1e15 nSPX units
	}{
		{1, 5000},
		{2, 4000},
		{3, 3200},
		{4, 2560},
		{5, 2048},
	}
	for _, s := range snapshots {
		h := blocksPerYear * (s.year - 1)
		want := new(big.Int).Mul(big.NewInt(s.wantFemto), new(big.Int).Exp(big.NewInt(10), big.NewInt(15), nil))
		if got := p.CalculateBlockReward(h); got.Cmp(want) != 0 {
			t.Fatalf("year %d (height %d): reward = %s nSPX, want %s nSPX", s.year, h, got, want)
		}
	}
}

// TestCalculateBlockRewardGuards covers the degenerate inputs: nil policy,
// nil base reward, and height zero — all must return the un-decayed policy
// reward or a safe zero without panicking.
func TestCalculateBlockRewardGuards(t *testing.T) {
	var nilPolicy *PolicyParameters
	if got := nilPolicy.CalculateBlockReward(42); got.Sign() != 0 {
		t.Fatalf("nil policy must yield zero reward, got %s", got)
	}

	p := NewPolicyParameters()
	p.BlockReward = nil
	if got := p.CalculateBlockReward(42); got.Sign() != 0 {
		t.Fatalf("nil base reward must yield zero reward, got %s", got)
	}

	p = NewPolicyParameters()
	fiveSPX := new(big.Int).Mul(big.NewInt(5), e18)
	p.BlockReward = new(big.Int).Set(fiveSPX)
	if got := p.CalculateBlockReward(0); got.Cmp(fiveSPX) != 0 {
		t.Fatalf("height 0 must pay the un-decayed base reward: got %s, want %s", got, fiveSPX)
	}
	if got := p.CalculateBlockReward(1); got.Cmp(fiveSPX) != 0 {
		t.Fatalf("height 1 is still year 1: got %s, want full 5 SPX base", got)
	}
}
