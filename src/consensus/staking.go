// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// consensus/staking.go
package consensus

import (
	"fmt"
	"math/big"
	"sort"

	logger "github.com/sphinxorg/protocol/src/log"
	denom "github.com/sphinxorg/protocol/src/params/denom"
)

// sips0013 https://github.com/sphinxorg/SIPS/blob/main/.github/workflows/sips0013/sips0013.md

// NewValidatorSet creates a validator set with minimum stake configuration.
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

// GetMinStakeAmount returns a copy of the minimum stake amount.
func (vs *ValidatorSet) GetMinStakeAmount() *big.Int {
	return new(big.Int).Set(vs.minStakeAmount)
}

// GetMinStakeSPX returns the minimum stake in SPX (human-readable).
func (vs *ValidatorSet) GetMinStakeSPX() uint64 {
	minSPX := new(big.Int).Div(vs.minStakeAmount, big.NewInt(1e18))
	return minSPX.Uint64()
}

// AddValidator adds or updates a validator's stake (in SPX).
// AddValidator adds or updates a validator's stake (in SPX).
// This is the primary method for setting stakes - it handles both add and update
func (vs *ValidatorSet) AddValidator(id string, stakeSPX uint64) error {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	stakeNSPX := new(big.Int).Mul(
		big.NewInt(int64(stakeSPX)),
		big.NewInt(denom.SPX),
	)

	// If below minimum, use minimum
	if stakeNSPX.Cmp(vs.minStakeAmount) < 0 {
		minStakeSPX := vs.GetMinStakeSPX()
		logger.Warn("Stake %d SPX below minimum %d SPX, using minimum", stakeSPX, minStakeSPX)
		stakeSPX = minStakeSPX
		stakeNSPX = new(big.Int).Mul(
			big.NewInt(int64(stakeSPX)),
			big.NewInt(denom.SPX),
		)
	}

	// Check if validator already exists
	if val, exists := vs.validators[id]; exists {
		// Update existing validator
		vs.totalStake.Sub(vs.totalStake, val.StakeAmount)
		val.StakeAmount = stakeNSPX
		vs.totalStake.Add(vs.totalStake, stakeNSPX)
		logger.Info("✅ Validator %s updated to %d SPX stake", id, stakeSPX)
	} else {
		// Add new validator
		vs.validators[id] = &StakedValidator{
			ID:          id,
			StakeAmount: stakeNSPX,
		}
		vs.totalStake.Add(vs.totalStake, stakeNSPX)
		logger.Info("✅ Validator %s added with %d SPX stake", id, stakeSPX)
	}

	return nil
}

// IsValidStakeAmount checks if a stake amount meets the minimum requirement.
func (vs *ValidatorSet) IsValidStakeAmount(stakeNSPX *big.Int) bool {
	if stakeNSPX == nil {
		return false
	}
	return stakeNSPX.Cmp(vs.minStakeAmount) >= 0
}

// GetMinimumStakeInSPX returns the minimum stake in SPX as float64.
func (vs *ValidatorSet) GetMinimumStakeInSPX() float64 {
	minStakeSPX := new(big.Float).Quo(
		new(big.Float).SetInt(vs.minStakeAmount),
		new(big.Float).SetFloat64(denom.SPX),
	)
	result, _ := minStakeSPX.Float64()
	return result
}

// GetActiveValidators returns a sorted slice of validators active in epoch.
// Sort order is by validator ID (lexicographic) so every node producing the
// same slice is deterministic — required for consistent VDF slash tracking.
func (vs *ValidatorSet) GetActiveValidators(epoch uint64) []*StakedValidator {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	active := make([]*StakedValidator, 0, len(vs.validators))
	for _, v := range vs.validators {
		if v.IsSlashed {
			continue
		}
		if v.ActivationEpoch > epoch {
			continue
		}
		if v.ExitEpoch != 0 && v.ExitEpoch <= epoch {
			continue
		}
		active = append(active, v)
	}

	sort.Slice(active, func(i, j int) bool {
		return active[i].ID < active[j].ID
	})

	return active
}

// ActiveValidatorIDs is a convenience wrapper used by the VDF epoch finaliser.
// It returns just the IDs of active validators for epoch, in the same
// deterministic order as GetActiveValidators.
func (vs *ValidatorSet) ActiveValidatorIDs(epoch uint64) []string {
	active := vs.GetActiveValidators(epoch)
	ids := make([]string, len(active))
	for i, v := range active {
		ids[i] = v.ID
	}
	return ids
}

// GetTotalStake returns total active stake in nSPX.
func (vs *ValidatorSet) GetTotalStake() *big.Int {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	if vs.totalStake == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(vs.totalStake)
}

// GetStakeInSPX returns a validator's stake in SPX as float64.
func (v *StakedValidator) GetStakeInSPX() float64 {
	stakeSPX := new(big.Float).Quo(
		new(big.Float).SetInt(v.StakeAmount),
		new(big.Float).SetFloat64(denom.SPX),
	)
	result, _ := stakeSPX.Float64()
	return result
}

// GetValidatorSet returns this consensus instance's validator set.
func (c *Consensus) GetValidatorSet() *ValidatorSet {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.validatorSet
}

// SlashValidator reduces a validator's stake by penaltyBps basis points
// and marks them slashed if their remaining stake drops below the minimum.
// penaltyBps: 100 = 1 %, 1000 = 10 %.
func (vs *ValidatorSet) SlashValidator(id, reason string, penaltyBps uint64) {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	v, exists := vs.validators[id]
	if !exists {
		logger.Warn("SlashValidator: unknown validator %s", id)
		return
	}

	penalty := new(big.Int).Mul(v.StakeAmount, new(big.Int).SetUint64(penaltyBps))
	penalty.Div(penalty, big.NewInt(10000))

	vs.totalStake.Sub(vs.totalStake, penalty)
	v.StakeAmount.Sub(v.StakeAmount, penalty)

	if v.StakeAmount.Cmp(vs.minStakeAmount) < 0 {
		v.IsSlashed = true
		logger.Warn("🔪 Validator %s SLASHED and ejected — reason: %s (stake now %.2f SPX)",
			id, reason, v.GetStakeInSPX())
	} else {
		logger.Warn("🔪 Validator %s slashed %.2f SPX — reason: %s (remaining %.2f SPX)",
			id, new(big.Float).Quo(
				new(big.Float).SetInt(penalty),
				new(big.Float).SetFloat64(denom.SPX),
			), reason, v.GetStakeInSPX())
	}
}

// FinaliseEpochAndSlash is the epoch-boundary hook that ties the VDF beacon
// and the validator set together.
//
// Call this from the Consensus engine at slot 0 of each new epoch:
//
//	slashList := c.randao.FinaliseEpoch(epoch, c.validatorSet.ActiveValidatorIDs(epoch))
//	for _, id := range slashList {
//	    c.validatorSet.SlashValidator(id, "missed VDF submission", SlashBps)
//	}
//
// The helper below wraps that pattern for convenience.
func (c *Consensus) FinaliseEpochAndSlash(epoch uint64) {
	c.mu.RLock()
	vs := c.validatorSet
	r := c.randao
	c.mu.RUnlock()

	if vs == nil || r == nil {
		return
	}

	activeIDs := vs.ActiveValidatorIDs(epoch)
	slashList := r.FinaliseEpoch(epoch, activeIDs)

	for _, id := range slashList {
		vs.SlashValidator(id, "missed VDF submission", SlashBps)
	}
}

// UpdateStake updates a validator's stake amount (in SPX)
// This is useful for updating stakes after distribution transactions are processed
func (vs *ValidatorSet) UpdateStake(id string, stakeSPX uint64) error {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	// Check if validator exists
	v, exists := vs.validators[id]
	if !exists {
		return fmt.Errorf("validator %s not found", id)
	}

	// Calculate stake in nSPX
	stakeNSPX := new(big.Int).Mul(
		big.NewInt(int64(stakeSPX)),
		big.NewInt(denom.SPX),
	)

	// Validate minimum stake
	if stakeNSPX.Cmp(vs.minStakeAmount) < 0 {
		minStakeSPX := vs.GetMinStakeSPX()
		return fmt.Errorf("stake %d SPX below minimum %d SPX", stakeSPX, minStakeSPX)
	}

	// Update total stake (remove old, add new)
	oldStake := v.StakeAmount
	vs.totalStake.Sub(vs.totalStake, oldStake)

	// Update validator's stake
	v.StakeAmount = stakeNSPX
	vs.totalStake.Add(vs.totalStake, stakeNSPX)

	oldSPX := new(big.Int).Div(oldStake, big.NewInt(denom.SPX))
	logger.Info("✅ Validator %s stake updated from %d SPX to %d SPX",
		id, oldSPX.Uint64(), stakeSPX)

	return nil
}

// SetStakeFromBalance sets a validator's stake from their actual balance
func (vs *ValidatorSet) SetStakeFromBalance(validatorID string, balanceNSPX *big.Int) error {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	if balanceNSPX == nil || balanceNSPX.Sign() < 0 {
		return fmt.Errorf("invalid balance for validator %s", validatorID)
	}

	// Convert balance to SPX for stake
	stakeSPX := new(big.Int).Div(balanceNSPX, big.NewInt(denom.SPX))
	if stakeSPX.Sign() == 0 {
		// If balance is less than 1 SPX, use minimum stake
		stakeSPX = new(big.Int).Set(vs.minStakeAmount)
		logger.Warn("Validator %s balance %s nSPX is less than 1 SPX, using minimum stake",
			validatorID, balanceNSPX.String())
	}

	// Get stake amount in SPX as uint64
	stakeSPXUint := stakeSPX.Uint64()
	minStakeSPX := vs.GetMinStakeSPX()

	// Ensure minimum stake
	if stakeSPXUint < minStakeSPX {
		logger.Warn("Validator %s stake %d SPX below minimum %d SPX, using minimum",
			validatorID, stakeSPXUint, minStakeSPX)
		stakeSPXUint = minStakeSPX
	}

	// Check if validator exists
	v, exists := vs.validators[validatorID]
	if !exists {
		v = &StakedValidator{
			ID:          validatorID,
			StakeAmount: new(big.Int),
		}
		vs.validators[validatorID] = v
	}

	// Calculate stake in nSPX
	stakeNSPX := new(big.Int).Mul(
		big.NewInt(int64(stakeSPXUint)),
		big.NewInt(denom.SPX),
	)

	// Update total stake
	oldStake := v.StakeAmount
	if oldStake != nil && oldStake.Sign() > 0 {
		vs.totalStake.Sub(vs.totalStake, oldStake)
	}

	v.StakeAmount = stakeNSPX
	vs.totalStake.Add(vs.totalStake, stakeNSPX)

	logger.Info("✅ Validator %s stake set to %d SPX from balance",
		validatorID, stakeSPXUint)
	return nil
}
