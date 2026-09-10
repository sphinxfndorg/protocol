// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package policy

import (
	"math/big"
	"testing"

	denom "github.com/sphinxfndorg/protocol/src/params/denom"
)

// testBasisPoints mirrors the policy-internal basis-point scale
// (10_000 BPS = 100%). The production constant lives as a local
// const in fees.go, so tests restate the scale explicitly.
const testBasisPoints = uint64(10000)

// TestGetDefaultValidatorEconomicsSharesMinStake locks the 32 SPX
// single-source-of-truth: policy's MinSelfDelegation must be exactly
// denom.MinValidatorStakeNSPX() so core, consensus and policy all
// agree on the default validator stake.
func TestGetDefaultValidatorEconomicsSharesMinStake(t *testing.T) {
	val := GetDefaultValidatorEconomics()
	if val == nil {
		t.Fatal("nil validator economics")
	}
	want := denom.MinValidatorStakeNSPX()
	if val.MinSelfDelegation == nil || val.MinSelfDelegation.Cmp(want) != 0 {
		t.Fatalf("MinSelfDelegation must equal denom.MinValidatorStakeNSPX() (32 SPX), got %v", val.MinSelfDelegation)
	}
	expected := new(big.Int).Mul(big.NewInt(denom.MinValidatorStakeSPX), big.NewInt(int64(denom.SPX)))
	if want.Cmp(expected) != 0 {
		t.Fatalf("MinValidatorStakeNSPX() = %v nSPX, want %v (32 SPX)", want, expected)
	}
}

func TestSlashBPSConstants(t *testing.T) {
	// The string-keyed mapping drives CalculateSlashingPenalty, and the
	// same constants feed consensus's BPS-based SlashValidator.
	cases := map[string]uint64{
		"double_sign": SlashDoubleSignBPS,
		"downtime":    SlashDowntimeBPS,
		"liveness":    SlashLivenessBPS,
	}
	for typ, want := range cases {
		if got := GetSlashBPS(typ); got != want {
			t.Errorf("GetSlashBPS(%q): want %d, got %d", typ, want, got)
		}
	}
	if got := GetSlashBPS("unknown"); got != SlashDowntimeBPS {
		t.Errorf("unknown slash type must fall back to downtime rate: got %d", got)
	}
}

func TestCalculateSlashingPenaltyMatchesBPS(t *testing.T) {
	p := NewPolicyParameters()
	stake := big.NewInt(100000)
	// (stake * BPS / 10000) in pure integer math, exactly what
	// consensus's SlashValidator applies via CalculateSlashingPenaltyBPS.
	cases := map[string]uint64{
		"double_sign": uint64(stake.Int64()) * SlashDoubleSignBPS / testBasisPoints,
		"downtime":    uint64(stake.Int64()) * SlashDowntimeBPS / testBasisPoints,
		"liveness":    uint64(stake.Int64()) * SlashLivenessBPS / testBasisPoints,
	}
	for typ, want := range cases {
		got := p.CalculateSlashingPenalty(stake, typ)
		if got == nil || got.Int64() != int64(want) {
			t.Errorf("CalculateSlashingPenalty(%q): want %d, got %v", typ, want, got)
		}
	}
}

func TestCalculateSlashingPenaltyBPSGuards(t *testing.T) {
	stake := big.NewInt(1000000)
	want := big.NewInt(100000) // 10% of 1M
	if got := CalculateSlashingPenaltyBPS(stake, 1000); got.Cmp(want) != 0 {
		t.Fatalf("penalty (1M, 1000): want %v, got %v", want, got)
	}
	if got := CalculateSlashingPenaltyBPS(nil, 1000); got.Sign() != 0 {
		t.Fatalf("nil stake must yield zero, got %v", got)
	}
	if got := CalculateSlashingPenaltyBPS(stake, 0); got.Sign() != 0 {
		t.Fatalf("zero BPS must yield zero, got %v", got)
	}
	if got := CalculateSlashingPenaltyBPS(stake, testBasisPoints+1); got.Sign() != 0 {
		t.Fatalf("out-of-range BPS must yield zero, got %v", got)
	}
}
