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

// consensus/staking.go
package consensus

import (
	"fmt"
	"math/big"
	"sort"

	logger "github.com/sphinxorg/protocol/src/log"
	denom "github.com/sphinxorg/protocol/src/params/denom"
)

// NewValidatorSet creates a validator set with minimum stake configuration
func NewValidatorSet(minStakeAmount *big.Int) *ValidatorSet {
	if minStakeAmount == nil {
		panic("minStakeAmount cannot be nil - must be provided from chain parameters")
	}

	return &ValidatorSet{
		validators:     make(map[string]*StakedValidator),
		totalStake:     big.NewInt(0),
		minStakeAmount: minStakeAmount,
	}
}

// GetMinStakeAmount returns the minimum stake amount for this validator set
func (vs *ValidatorSet) GetMinStakeAmount() *big.Int {
	return new(big.Int).Set(vs.minStakeAmount)
}

// GetMinStakeSPX returns the minimum stake in SPX (human-readable)
func (vs *ValidatorSet) GetMinStakeSPX() uint64 {
	minSPX := new(big.Int).Div(vs.minStakeAmount, big.NewInt(1e18))
	return minSPX.Uint64()
}

// AddValidator adds or updates a validator's stake (in SPX)
func (vs *ValidatorSet) AddValidator(id string, stakeSPX uint64) error {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	// Convert SPX to nSPX
	stakeNSPX := new(big.Int).Mul(
		big.NewInt(int64(stakeSPX)),
		big.NewInt(denom.SPX),
	)

	// Check minimum stake using the stored value
	if stakeNSPX.Cmp(vs.minStakeAmount) < 0 {
		minStakeSPX := vs.GetMinStakeSPX()
		return fmt.Errorf("stake %d SPX below minimum %d SPX",
			stakeSPX, minStakeSPX)
	}

	if val, exists := vs.validators[id]; exists {
		vs.totalStake.Sub(vs.totalStake, val.StakeAmount)
		val.StakeAmount = stakeNSPX
		vs.totalStake.Add(vs.totalStake, stakeNSPX)
	} else {
		vs.validators[id] = &StakedValidator{
			ID:          id,
			StakeAmount: stakeNSPX,
		}
		vs.totalStake.Add(vs.totalStake, stakeNSPX)
	}

	logger.Info("✅ Validator %s added/updated with %d SPX stake", id, stakeSPX)
	return nil
}

// IsValidStakeAmount checks if a stake amount meets the minimum requirement
func (vs *ValidatorSet) IsValidStakeAmount(stakeNSPX *big.Int) bool {
	if stakeNSPX == nil {
		return false
	}
	return stakeNSPX.Cmp(vs.minStakeAmount) >= 0
}

// GetMinimumStakeInSPX returns the minimum stake in SPX as float64
func (vs *ValidatorSet) GetMinimumStakeInSPX() float64 {
	minStakeSPX := new(big.Float).Quo(
		new(big.Float).SetInt(vs.minStakeAmount),
		new(big.Float).SetFloat64(denom.SPX),
	)
	result, _ := minStakeSPX.Float64()
	return result
}

// GetActiveValidators returns validators active at given epoch
func (vs *ValidatorSet) GetActiveValidators(epoch uint64) []*StakedValidator {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	active := make([]*StakedValidator, 0)
	for _, v := range vs.validators {
		if v.ActivationEpoch <= epoch &&
			(v.ExitEpoch == 0 || v.ExitEpoch > epoch) &&
			!v.IsSlashed {
			active = append(active, v)
		}
	}

	// Sort by ID for deterministic ordering when stakes equal
	sort.Slice(active, func(i, j int) bool {
		return active[i].ID < active[j].ID
	})

	return active
}

// GetTotalStake returns total active stake in nSPX
func (vs *ValidatorSet) GetTotalStake() *big.Int {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	if vs.totalStake == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(vs.totalStake)
}

// GetStakeInSPX returns human-readable stake amount
func (v *StakedValidator) GetStakeInSPX() float64 {
	stakeSPX := new(big.Float).Quo(
		new(big.Float).SetInt(v.StakeAmount),
		new(big.Float).SetFloat64(denom.SPX),
	)
	result, _ := stakeSPX.Float64()
	return result
}

// Add to consensus.go - a public method to access validator set
func (c *Consensus) GetValidatorSet() *ValidatorSet {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.validatorSet
}
