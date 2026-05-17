// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/policy/rewards.go
package policy

import (
	"math/big"
)

// CalculateValidatorReward calculates reward for a validator based on their stake
func (p *PolicyParameters) CalculateValidatorReward(
	validatorStake *big.Int,
	totalStake *big.Int,
	epochRewards *big.Int,
	commissionRate float64,
) *big.Int {
	// Validator's share of total stake
	share := new(big.Int).Mul(validatorStake, new(big.Int).SetUint64(1e18))
	share.Div(share, totalStake)

	// Calculate base reward
	baseReward := new(big.Int).Mul(epochRewards, share)
	baseReward.Div(baseReward, new(big.Int).SetUint64(1e18))

	// Apply commission
	commission := new(big.Int).Mul(baseReward, new(big.Int).SetUint64(uint64(commissionRate*1e18)))
	commission.Div(commission, new(big.Int).SetUint64(1e18))

	// Validator keeps commission, delegators get the rest
	return commission
}

// CalculateDelegatorReward calculates reward for a delegator
func (p *PolicyParameters) CalculateDelegatorReward(
	delegatorStake *big.Int,
	validatorStake *big.Int,
	validatorRewards *big.Int,
	commissionRate float64,
) *big.Int {
	// Delegator's share of validator's stake (excluding commission)
	delegatorShare := new(big.Int).Mul(delegatorStake, new(big.Int).SetUint64(1e18))
	delegatorShare.Div(delegatorShare, validatorStake)

	// Rewards after commission
	afterCommission := new(big.Int).Mul(validatorRewards, new(big.Int).SetUint64(uint64((1-commissionRate)*1e18)))
	afterCommission.Div(afterCommission, new(big.Int).SetUint64(1e18))

	// Delegator's reward
	delegatorReward := new(big.Int).Mul(afterCommission, delegatorShare)
	delegatorReward.Div(delegatorReward, new(big.Int).SetUint64(1e18))

	return delegatorReward
}

// CalculateAPY calculates the estimated APY for staking
// year: current year number (1-indexed)
// currentStakeRatio: current ratio of staked tokens to total supply
func (p *PolicyParameters) CalculateAPY(
	totalStake *big.Int,
	totalSupply *big.Int,
	year uint64,
	currentStakeRatio float64,
) float64 {
	annualMinting := p.GetAnnualMinting(totalSupply, year, currentStakeRatio)

	// Staking rewards = γ * annualMinting
	stakingRewards := new(big.Int).Mul(annualMinting, new(big.Int).SetUint64(uint64(p.StakingRewardShare*1e18)))
	stakingRewards.Div(stakingRewards, new(big.Int).SetUint64(1e18))

	// APY = stakingRewards / totalStake
	apy := new(big.Float).SetInt(stakingRewards)
	apy.Quo(apy, new(big.Float).SetInt(totalStake))

	result, _ := apy.Float64()
	return result
}

// CalculateAPYWithDecay calculates APY considering the geometric decay of inflation
// This provides a more accurate long-term projection
func (p *PolicyParameters) CalculateAPYWithDecay(
	totalStake *big.Int,
	totalSupply *big.Int,
	startYear uint64,
	endYear uint64,
	initialStakeRatio float64,
) float64 {
	totalRewards := big.NewInt(0)
	currentSupply := new(big.Int).Set(totalSupply)
	currentStakeRatio := initialStakeRatio

	for year := startYear; year <= endYear; year++ {
		annualMinting := p.GetAnnualMinting(currentSupply, year, currentStakeRatio)

		// Add staking rewards for this year
		stakingRewards := new(big.Int).Mul(annualMinting, new(big.Int).SetUint64(uint64(p.StakingRewardShare*1e18)))
		stakingRewards.Div(stakingRewards, new(big.Int).SetUint64(1e18))
		totalRewards.Add(totalRewards, stakingRewards)

		// Update supply for next year (assuming all rewards are reinvested)
		currentSupply.Add(currentSupply, annualMinting)

		// Update stake ratio (assuming stakers reinvest and maintain same ratio)
		// This is a simplification; actual ratio may vary
	}

	// Average annual APY over the period
	years := float64(endYear - startYear + 1)
	avgRewardsPerYear := new(big.Float).SetInt(totalRewards)
	avgRewardsPerYear.Quo(avgRewardsPerYear, big.NewFloat(years))

	apy := new(big.Float).Quo(avgRewardsPerYear, new(big.Float).SetInt(totalStake))
	result, _ := apy.Float64()

	return result
}
