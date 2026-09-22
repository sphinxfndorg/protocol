// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package policy

import (
	"math/big"
	"testing"
)

// gasLimitForTests is the block gas limit used across these tests
// (matches the devnet default of 10,000,000 gas).
var gasLimitForTests = big.NewInt(10_000_000)

// TestNextBurnFeeBPSStepDirection verifies the EIP-1559-style feedback
// direction: utilization above the target steps the burn rate UP, below
// steps it DOWN, exactly at the target holds it — one fixed step per roll.
func TestNextBurnFeeBPSStepDirection(t *testing.T) {
	p := NewPolicyParameters()

	cases := []struct {
		name       string
		currentBPS uint64
		used       int64
		want       uint64
	}{
		{"above target steps up", 500, 6_000_000, 505},
		{"below target steps down", 500, 4_000_000, 495},
		{"exactly at target holds", 500, 5_000_000, 500},
		{"empty block steps down", 500, 0, 495},
		{"full block steps up", 500, 10_000_000, 505},
		{"tiny utilization rounds below target", 500, 24_200, 495},
	}
	for _, c := range cases {
		if got := p.NextBurnFeeBPS(c.currentBPS, big.NewInt(c.used), gasLimitForTests); got != c.want {
			t.Fatalf("%s: NextBurnFeeBPS(%d, %d, limit) = %d, want %d", c.name, c.currentBPS, c.used, got, c.want)
		}
	}

	// Monotonic walk: repeated above-target rolls climb one step at a time
	// until the ceiling; repeated below-target rolls descend until the floor.
	rate := uint64(500)
	for rate < 1000 {
		next := p.NextBurnFeeBPS(rate, big.NewInt(10_000_000), gasLimitForTests)
		if next != rate+5 && next != 1000 {
			t.Fatalf("upward walk must move by +5 or clamp at 1000, got %d -> %d", rate, next)
		}
		if next < rate {
			t.Fatalf("upward walk must be monotonic non-decreasing, got %d -> %d", rate, next)
		}
		rate = next
	}
	if rate != 1000 {
		t.Fatalf("upward walk must reach the 1000 BPS ceiling, stopped at %d", rate)
	}
	rate = 500
	for rate > 200 {
		next := p.NextBurnFeeBPS(rate, big.NewInt(0), gasLimitForTests)
		if next != rate-5 && next != 200 {
			t.Fatalf("downward walk must move by -5 or clamp at 200, got %d -> %d", rate, next)
		}
		if next > rate {
			t.Fatalf("downward walk must be monotonic non-increasing, got %d -> %d", rate, next)
		}
		rate = next
	}
	if rate != 200 {
		t.Fatalf("downward walk must reach the 200 BPS floor, stopped at %d", rate)
	}
}

// TestNextBurnFeeBPSClampBehavior pins the [floor, ceiling] clamps and the
// edge cases around them.
func TestNextBurnFeeBPSClampBehavior(t *testing.T) {
	p := NewPolicyParameters()

	if got := p.NextBurnFeeBPS(998, big.NewInt(10_000_000), gasLimitForTests); got != 1000 {
		t.Fatalf("998 + 5 must clamp to the 1000 ceiling, got %d", got)
	}
	if got := p.NextBurnFeeBPS(1000, big.NewInt(10_000_000), gasLimitForTests); got != 1000 {
		t.Fatalf("at the ceiling an above-target block must hold 1000, got %d", got)
	}
	if got := p.NextBurnFeeBPS(202, big.NewInt(0), gasLimitForTests); got != 200 {
		t.Fatalf("202 - 5 must clamp to the 200 floor, got %d", got)
	}
	if got := p.NextBurnFeeBPS(200, big.NewInt(0), gasLimitForTests); got != 200 {
		t.Fatalf("at the floor a below-target block must hold 200, got %d", got)
	}
	// An out-of-range incoming rate is clamped into the window on the
	// first roll (also the path for a policy that just tightened its window).
	if got := p.NextBurnFeeBPS(5000, big.NewInt(5_000_000), gasLimitForTests); got != 1000 {
		t.Fatalf("out-of-range rate must clamp to the window, got %d", got)
	}
	if got := p.NextBurnFeeBPS(10, big.NewInt(5_000_000), gasLimitForTests); got != 200 {
		t.Fatalf("below-floor rate must clamp to the floor, got %d", got)
	}

	// A zero step freezes the rate regardless of utilization.
	frozen := NewPolicyParameters()
	frozen.BurnFeeStepBPS = 0
	if got := frozen.NextBurnFeeBPS(500, big.NewInt(10_000_000), gasLimitForTests); got != 500 {
		t.Fatalf("zero step must freeze the rate, got %d", got)
	}

	// Custom windows are honored.
	custom := NewPolicyParameters()
	custom.BurnFeeFloorBPS = 300
	custom.BurnFeeCeilingBPS = 700
	custom.BurnFeeStepBPS = 10
	custom.BurnFeeTargetUtilizationBPS = 8000
	if got := custom.NextBurnFeeBPS(300, big.NewInt(8_000_000), gasLimitForTests); got != 300 {
		t.Fatalf("exactly at the custom 80%% target must hold, got %d", got)
	}
	if got := custom.NextBurnFeeBPS(300, big.NewInt(8_001_000), gasLimitForTests); got != 310 {
		t.Fatalf("above the custom target must step by 10, got %d", got)
	}
	if got := custom.NextBurnFeeBPS(300, big.NewInt(0), gasLimitForTests); got != 300 {
		t.Fatalf("custom floor must hold, got %d", got)
	}
}

// TestNextBurnFeeBPSDegenerateInputs covers unusable gas inputs: with no
// usable limit the roll must hold the (clamped) rate rather than divide by
// zero, and nil/negative usage is treated as an empty block.
func TestNextBurnFeeBPSDegenerateInputs(t *testing.T) {
	p := NewPolicyParameters()

	if got := p.NextBurnFeeBPS(500, big.NewInt(1_000_000), nil); got != 500 {
		t.Fatalf("nil limit must hold the rate, got %d", got)
	}
	if got := p.NextBurnFeeBPS(500, big.NewInt(1_000_000), big.NewInt(0)); got != 500 {
		t.Fatalf("zero limit must hold the rate, got %d", got)
	}
	if got := p.NextBurnFeeBPS(500, nil, gasLimitForTests); got != 495 {
		t.Fatalf("nil usage must be treated as an empty block, got %d", got)
	}
	if got := p.NextBurnFeeBPS(500, big.NewInt(-5), gasLimitForTests); got != 495 {
		t.Fatalf("negative usage must be treated as an empty block, got %d", got)
	}
	// A utilization beyond 100% (used > limit) still just steps up by one.
	if got := p.NextBurnFeeBPS(500, new(big.Int).Mul(gasLimitForTests, big.NewInt(3)), gasLimitForTests); got != 505 {
		t.Fatalf("over-limit usage must step up exactly one step, got %d", got)
	}
}

// TestNextBurnFeeBPSDeterminism locks PBFT determinism: identical inputs must
// produce the identical rate across repeated calls and across two independent
// policy instances, and the roll must not mutate the policy or its inputs.
func TestNextBurnFeeBPSDeterminism(t *testing.T) {
	p := NewPolicyParameters()
	q := NewPolicyParameters()

	used := big.NewInt(7_777_777)
	if p.NextBurnFeeBPS(500, used, gasLimitForTests) != p.NextBurnFeeBPS(500, used, gasLimitForTests) {
		t.Fatal("repeated rolls with identical inputs diverged")
	}
	if p.NextBurnFeeBPS(500, used, gasLimitForTests) != q.NextBurnFeeBPS(500, new(big.Int).Set(used), new(big.Int).Set(gasLimitForTests)) {
		t.Fatal("two independent policy instances diverged")
	}
	if used.Int64() != 7_777_777 || gasLimitForTests.Int64() != 10_000_000 {
		t.Fatal("NextBurnFeeBPS must not mutate its inputs")
	}
	if p.BurnFeeBPS != 500 || p.BlockRewardBurnBPS != 500 || p.BurnFeeStepBPS != 5 {
		t.Fatal("NextBurnFeeBPS must not mutate the policy")
	}
	// The mint-side burn share is a separate lever and must be untouched by
	// any burn-rate roll.
	before := p.BlockRewardBurnBPS
	p.NextBurnFeeBPS(500, big.NewInt(0), gasLimitForTests)
	if p.BlockRewardBurnBPS != before {
		t.Fatal("mint-side BlockRewardBurnBPS must never be touched by the burn-rate roll")
	}
}

// TestDistributeFeesWithBurnBPS verifies the dynamic-rate fee split: exact
// conservation, dust to treasury, and identical output to the static
// DistributeFees when the configured shares and rate are consistent.
func TestDistributeFeesWithBurnBPS(t *testing.T) {
	p := NewPolicyParameters()

	// At defaults (burn 500 = 10000 - 6000 - 2500 - 1000) the dynamic split
	// must reproduce the static one exactly.
	static := p.DistributeFees(big.NewInt(10_000))
	dynamic := p.DistributeFeesWithBurnBPS(big.NewInt(10_000), p.BurnFeeBPS)
	for _, pair := range [][2]*big.Int{
		{static.Validators, dynamic.Validators},
		{static.Stakers, dynamic.Stakers},
		{static.Treasury, dynamic.Treasury},
		{static.Burned, dynamic.Burned},
	} {
		if pair[0].Cmp(pair[1]) != 0 {
			t.Fatalf("default-config dynamic split must equal static: static=%s dynamic=%s", pair[0], pair[1])
		}
	}

	// Conservation and dust handling at odd rates and odd totals.
	cases := []struct {
		total   int64
		burnBPS uint64
	}{
		{10_001, 495},
		{7, 203},
		{1_000_000_000_000_000_000, 617},
	}
	for _, c := range cases {
		d := p.DistributeFeesWithBurnBPS(big.NewInt(c.total), c.burnBPS)
		sum := new(big.Int).Add(d.Validators, d.Stakers)
		sum.Add(sum, d.Treasury)
		sum.Add(sum, d.Burned)
		if sum.Cmp(big.NewInt(c.total)) != 0 {
			t.Fatalf("total=%d burn=%d: split must sum to the fee, got %s", c.total, c.burnBPS, sum)
		}
		wantBurned := new(big.Int).Mul(big.NewInt(c.total), new(big.Int).SetUint64(c.burnBPS))
		wantBurned.Div(wantBurned, big.NewInt(10_000))
		if d.Burned.Cmp(wantBurned) != 0 {
			t.Fatalf("total=%d burn=%d: burned = %s, want floor(total*bps/10000) = %s", c.total, c.burnBPS, d.Burned, wantBurned)
		}
		if d.Burned.Sign() < 0 || d.Validators.Sign() < 0 || d.Stakers.Sign() < 0 || d.Treasury.Sign() < 0 {
			t.Fatalf("total=%d burn=%d: no share may go negative: %+v", c.total, c.burnBPS, d)
		}
	}

	// Extreme rates: zero burn pays everything to the split shares; 100%
	// burn sends everything to DEAD.
	zero := p.DistributeFeesWithBurnBPS(big.NewInt(10_000), 0)
	if zero.Burned.Sign() != 0 {
		t.Fatalf("zero burn rate must burn nothing, got %s", zero.Burned)
	}
	full := p.DistributeFeesWithBurnBPS(big.NewInt(10_000), 10_000)
	if full.Burned.Cmp(big.NewInt(10_000)) != 0 || full.Validators.Sign() != 0 ||
		full.Stakers.Sign() != 0 || full.Treasury.Sign() != 0 {
		t.Fatalf("10000 BPS burn must send everything to DEAD: %+v", full)
	}

	// Degenerate fees return an all-zero split.
	empty := p.DistributeFeesWithBurnBPS(nil, 500)
	if empty.TotalFees == nil || empty.TotalFees.Sign() != 0 {
		t.Fatalf("nil fees must yield a zero distribution, got %+v", empty)
	}
}
