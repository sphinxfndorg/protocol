// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/policy/validators.go
package policy

import (
	"math/big"
	"time"

	denom "github.com/sphinxfndorg/protocol/src/params/denom"
)

// Slashing penalties are policy-owned economics expressed in integer basis
// points (10 000 BPS = 100 %). Consensus imports these constants so the
// slashing schedule lives in exactly one place — policy — instead of being
// re-declared as a float fraction in one module and a raw BPS literal in
// another. See CalculateSlashingPenaltyBPS / CalculateSlashingPenalty.
const (
	// SlashDoubleSignBPS is the penalty for signing conflicting blocks.
	SlashDoubleSignBPS = uint64(500) // 5%
	// SlashDowntimeBPS is the penalty for missed VDF reveals / attestations.
	SlashDowntimeBPS = uint64(100) // 1%
	// SlashLivenessBPS is the penalty for liveness issues (rare micro-slash).
	SlashLivenessBPS = uint64(10) // 0.1%
)

// DefaultCommissionBPS is the validator commission expressed in basis points.
// It mirrors ValidatorEconomics.CommissionRate (0.05 = 5%) in the integer form
// that consensus/execution can use without float math.
const DefaultCommissionBPS = uint64(500) // 5%

// ValidatorEconomics defines economic parameters for validators
type ValidatorEconomics struct {
	CommissionRate    float64       `json:"commission_rate"`
	CommissionBPS     uint64        `json:"commission_bps"` // integer counterpart of CommissionRate (e.g. 500 = 5%)
	MinSelfDelegation *big.Int      `json:"min_self_delegation"`
	MaxValidators     uint64        `json:"max_validators"`
	UnbondingPeriod   time.Duration `json:"unbonding_period"`
	SlashFraction     float64       `json:"slash_fraction"`
}

// GetDefaultValidatorEconomics returns default validator economics
func GetDefaultValidatorEconomics() *ValidatorEconomics {
	// Minimum self delegation: 32 SPX (same as min stake) — the shared
	// constant lives in the denom package so core, consensus and policy
	// all read the same "32 SPX" single source of truth.
	val := &ValidatorEconomics{
		CommissionRate:    0.05, // 5% commission
		MaxValidators:     100,  // Maximum 100 validators
		UnbondingPeriod:   14 * 24 * time.Hour,
		SlashFraction:     0.01, // 1% slashing for downtime
		MinSelfDelegation: denom.MinValidatorStakeNSPX(),
	}
	// Always keep the BPS form consistent with the float form so economics
	// consumers can pick whichever representation fits their caller.
	val.CommissionBPS = uint64(val.CommissionRate * float64(basisPoints))
	return val
}

// GetSlashBPS returns the basis-point penalty for the named offence. Unknown
// offence types fall back to the downtime rate. This is the single mapping
// from slash-type strings to penalty rates; CalculateSlashingPenalty uses it
// and consensus consumes the same constants for the BPS-based SlashValidator.
func GetSlashBPS(slashType string) uint64 {
	switch slashType {
	case "double_sign":
		return SlashDoubleSignBPS
	case "downtime":
		return SlashDowntimeBPS
	case "liveness":
		return SlashLivenessBPS
	default:
		return SlashDowntimeBPS
	}
}

// CalculateSlashingPenaltyBPS computes the exact penalty (in nSPX) for stake
// at a given basis-point rate using integer math only. Returns zero for nil /
// non-positive stakes or out-of-range rates. Consensus's SlashValidator uses
// this helper so its penalty matches policy exactly.
func CalculateSlashingPenaltyBPS(stake *big.Int, penaltyBps uint64) *big.Int {
	if stake == nil || stake.Sign() <= 0 || penaltyBps == 0 || penaltyBps > basisPoints {
		return big.NewInt(0)
	}
	penalty := new(big.Int).Mul(stake, new(big.Int).SetUint64(penaltyBps))
	penalty.Div(penalty, new(big.Int).SetUint64(basisPoints))
	return penalty
}

// CalculateSlashingPenalty calculates the penalty for validator misbehavior
func (p *PolicyParameters) CalculateSlashingPenalty(
	stake *big.Int,
	slashType string,
) *big.Int {
	return CalculateSlashingPenaltyBPS(stake, GetSlashBPS(slashType))
}
