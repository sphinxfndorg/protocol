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
// This initializes the validator management system with the minimum stake requirement
// from chain parameters
func NewValidatorSet(minStakeAmount *big.Int) *ValidatorSet {
	// Validate that minimum stake amount is provided (should never be nil in production)
	if minStakeAmount == nil {
		panic("minStakeAmount cannot be nil - must be provided from chain parameters")
	}

	// Return new validator set with initialized maps and stake tracking
	return &ValidatorSet{
		validators:     make(map[string]*StakedValidator), // Map of validator ID to validator data
		totalStake:     big.NewInt(0),                     // Total stake across all validators (in nSPX)
		minStakeAmount: minStakeAmount,                    // Minimum stake required to be a validator
	}
}

// GetMinStakeAmount returns the minimum stake amount for this validator set
// Returns a copy to prevent external modification of the internal value
func (vs *ValidatorSet) GetMinStakeAmount() *big.Int {
	return new(big.Int).Set(vs.minStakeAmount) // Create a copy of the big.Int
}

// GetMinStakeSPX returns the minimum stake in SPX (human-readable)
// Converts from nSPX (internal) to SPX (display) for user-friendly output
func (vs *ValidatorSet) GetMinStakeSPX() uint64 {
	// Divide by 1e18 to convert from nSPX to SPX
	minSPX := new(big.Int).Div(vs.minStakeAmount, big.NewInt(1e18))
	return minSPX.Uint64()
}

// AddValidator adds or updates a validator's stake (in SPX)
// This function is used to register new validators or update existing ones
func (vs *ValidatorSet) AddValidator(id string, stakeSPX uint64) error {
	vs.mu.Lock()         // Lock for thread-safe map access
	defer vs.mu.Unlock() // Ensure unlock on function return

	// Convert SPX to nSPX (internal unit) by multiplying by denomination
	// SPX (1e18) is the main unit, nSPX (1e0) is the smallest unit
	stakeNSPX := new(big.Int).Mul(
		big.NewInt(int64(stakeSPX)), // Stake amount in SPX
		big.NewInt(denom.SPX),       // Denomination (1e18)
	)

	// Check minimum stake using the stored value
	// Validators must stake at least the minimum amount to participate
	if stakeNSPX.Cmp(vs.minStakeAmount) < 0 {
		minStakeSPX := vs.GetMinStakeSPX() // Get human-readable minimum
		return fmt.Errorf("stake %d SPX below minimum %d SPX",
			stakeSPX, minStakeSPX)
	}

	// Check if validator already exists
	if val, exists := vs.validators[id]; exists {
		// Update existing validator: subtract old stake from total
		vs.totalStake.Sub(vs.totalStake, val.StakeAmount)
		// Update stake amount
		val.StakeAmount = stakeNSPX
		// Add new stake to total
		vs.totalStake.Add(vs.totalStake, stakeNSPX)
	} else {
		// Create new validator entry
		vs.validators[id] = &StakedValidator{
			ID:          id,
			StakeAmount: stakeNSPX,
		}
		// Add new stake to total
		vs.totalStake.Add(vs.totalStake, stakeNSPX)
	}

	logger.Info("✅ Validator %s added/updated with %d SPX stake", id, stakeSPX)
	return nil
}

// IsValidStakeAmount checks if a stake amount meets the minimum requirement
// Used to validate stakes before accepting new validators
func (vs *ValidatorSet) IsValidStakeAmount(stakeNSPX *big.Int) bool {
	if stakeNSPX == nil {
		return false // Nil stake is invalid
	}
	// Check if stake meets or exceeds minimum requirement
	return stakeNSPX.Cmp(vs.minStakeAmount) >= 0
}

// GetMinimumStakeInSPX returns the minimum stake in SPX as float64
// Provides human-readable minimum stake for display purposes
func (vs *ValidatorSet) GetMinimumStakeInSPX() float64 {
	// Convert from nSPX (big.Int) to SPX (big.Float) for floating-point division
	minStakeSPX := new(big.Float).Quo(
		new(big.Float).SetInt(vs.minStakeAmount), // Minimum stake in nSPX
		new(big.Float).SetFloat64(denom.SPX),     // Denomination as float
	)
	result, _ := minStakeSPX.Float64() // Convert to float64
	return result
}

// GetActiveValidators returns a sorted slice of validators that are active
// in the given epoch.  A validator is active when:
//   - its ActivationEpoch <= epoch, and
//   - its ExitEpoch == 0 (not exited) OR its ExitEpoch > epoch, and
//   - it has not been slashed.
//
// IMPORTANT: the returned slice is sorted by validator ID (lexicographic).
// Callers MUST NOT rely on any other ordering.  Sorting here is defence-in-depth;
// SelectProposer also sorts its own copy, but having a deterministic source
// slice makes bugs easier to detect.
func (vs *ValidatorSet) GetActiveValidators(epoch uint64) []*StakedValidator {
	vs.mu.RLock()         // Read lock for thread safety
	defer vs.mu.RUnlock() // Ensure unlock on return

	// Pre-allocate with the full capacity to avoid repeated re-allocations.
	active := make([]*StakedValidator, 0, len(vs.validators))

	// Iterate through all validators to find active ones
	for _, v := range vs.validators {
		// Skip slashed validators — they lose their right to propose or attest.
		// Slashing is a penalty for malicious behavior
		if v.IsSlashed {
			continue
		}

		// Skip validators that have not yet reached their activation epoch.
		// Validators become active only after their activation epoch
		if v.ActivationEpoch > epoch {
			continue
		}

		// Skip validators that have already exited (ExitEpoch == 0 means "never exits").
		// Validators who have exited cannot participate in consensus
		if v.ExitEpoch != 0 && v.ExitEpoch <= epoch {
			continue
		}

		// Validator passed all checks - add to active set
		active = append(active, v)
	}

	// Sort by ID so every node produces the same ordering.
	// Without this sort, Go map iteration order is randomised per-process and
	// per-map, meaning each node iterates validators in a different order.
	// SelectProposer's cumulative-stake walk then finds a different winner on
	// each node, causing the "Invalid leader" rejection.
	sort.Slice(active, func(i, j int) bool {
		return active[i].ID < active[j].ID // Lexicographic string comparison
	})

	return active
}

// GetTotalStake returns total active stake in nSPX
// Returns the sum of all validator stakes for the current epoch
func (vs *ValidatorSet) GetTotalStake() *big.Int {
	vs.mu.RLock()         // Read lock for thread safety
	defer vs.mu.RUnlock() // Ensure unlock on return

	// Handle nil total stake (should not happen in normal operation)
	if vs.totalStake == nil {
		return big.NewInt(0) // Return zero if nil
	}
	// Return a copy to prevent external modification
	return new(big.Int).Set(vs.totalStake)
}

// GetStakeInSPX returns human-readable stake amount
// Converts from internal nSPX to display SPX with proper decimal handling
func (v *StakedValidator) GetStakeInSPX() float64 {
	// Convert from nSPX (big.Int) to SPX (big.Float) for floating-point division
	stakeSPX := new(big.Float).Quo(
		new(big.Float).SetInt(v.StakeAmount), // Stake in nSPX
		new(big.Float).SetFloat64(denom.SPX), // Denomination as float (1e18)
	)
	result, _ := stakeSPX.Float64() // Convert to float64
	return result
}

// GetValidatorSet returns this consensus instance's validator set
// Provides access to the validator set from the consensus engine
func (c *Consensus) GetValidatorSet() *ValidatorSet {
	// Handle nil consensus instance (safety check)
	if c == nil {
		return nil
	}
	c.mu.RLock()          // Read lock for thread safety
	defer c.mu.RUnlock()  // Ensure unlock on return
	return c.validatorSet // Return the validator set
}
