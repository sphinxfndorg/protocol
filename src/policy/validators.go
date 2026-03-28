// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/policy/validators.go
package policy

import (
	"math/big"
	"time"
)

// ValidatorEconomics defines economic parameters for validators
type ValidatorEconomics struct {
	CommissionRate    float64       `json:"commission_rate"`
	MinSelfDelegation *big.Int      `json:"min_self_delegation"`
	MaxValidators     uint64        `json:"max_validators"`
	UnbondingPeriod   time.Duration `json:"unbonding_period"`
	SlashFraction     float64       `json:"slash_fraction"`
}

// GetDefaultValidatorEconomics returns default validator economics
func GetDefaultValidatorEconomics() *ValidatorEconomics {
	// Minimum self delegation: 32 SPX (same as min stake)
	minSelfDelegation := new(big.Int).Mul(big.NewInt(32), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))

	return &ValidatorEconomics{
		CommissionRate:    0.05,                // 5% commission
		MinSelfDelegation: minSelfDelegation,   // 32 SPX minimum
		MaxValidators:     100,                 // Maximum 100 validators
		UnbondingPeriod:   14 * 24 * time.Hour, // 14 days unbonding
		SlashFraction:     0.01,                // 1% slashing for downtime
	}
}

// CalculateSlashingPenalty calculates the penalty for validator misbehavior
func (p *PolicyParameters) CalculateSlashingPenalty(
	stake *big.Int,
	slashType string,
) *big.Int {
	var slashFraction float64

	switch slashType {
	case "double_sign":
		slashFraction = 0.05 // 5% for double signing
	case "downtime":
		slashFraction = 0.01 // 1% for downtime
	case "liveness":
		slashFraction = 0.001 // 0.1% for liveness issues
	default:
		slashFraction = 0.01
	}

	penalty := new(big.Int).Mul(stake, new(big.Int).SetUint64(uint64(slashFraction*1e18)))
	penalty.Div(penalty, new(big.Int).SetUint64(1e18))

	return penalty
}
