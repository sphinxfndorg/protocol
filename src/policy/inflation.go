// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/policy/inflation.go
package policy

import (
	"math/big"
)

// CalculateAnnualInflation calculates the annual inflation rate for a given year
// Formula: Inflation(y) = Infl₀ * γ^(y-1)
// where:
//
//	Infl₀ = initial inflation rate (0.05 = 5%)
//	γ = decay factor (0.8)
//	y = year number (1-indexed)
//
// CalculateAnnualInflation calculates the annual inflation rate for a given year
func (p *PolicyParameters) CalculateAnnualInflation(year uint64) float64 {
	if year == 0 {
		year = 1
	}

	// Use direct calculation without math.Pow for better precision
	rate := p.InitialInflationRate
	for i := uint64(1); i < year; i++ {
		rate *= p.InflationDecayFactor
	}
	return rate
}

// CalculateAnnualInflationWithStakeAdjustment calculates inflation with stake ratio adjustment
// This adds a feedback mechanism based on staking participation
func (p *PolicyParameters) CalculateAnnualInflationWithStakeAdjustment(year uint64, currentStakeRatio float64) float64 {
	baseInflation := p.CalculateAnnualInflation(year)

	// Adjust inflation based on stake ratio deviation from target
	// If stake ratio is below target, increase inflation to incentivize staking
	// If above target, decrease inflation
	deviation := p.TargetStakeRatio - currentStakeRatio

	// Adjust inflation rate (max 2x, min 0.5x of base)
	adjustment := 1.0 + deviation
	if adjustment > 2.0 {
		adjustment = 2.0
	}
	if adjustment < 0.5 {
		adjustment = 0.5
	}

	return baseInflation * adjustment
}

// GetBlocksPerYear calculates approximate number of blocks per year
// BlockPerYear = (365 * 24 * 3600) / BlockTime
// With BlockTime = 12 seconds: 31,536,000 / 12 = 2,628,000 blocks per year
func (p *PolicyParameters) GetBlocksPerYear() uint64 {
	secondsPerYear := uint64(365 * 24 * 3600) // 31,536,000 seconds
	blocksPerYear := secondsPerYear / uint64(p.BlockTime.Seconds())
	return blocksPerYear
}

// GetEpochsPerYear calculates number of epochs per year
// EpochsPerYear = BlocksPerYear / BlocksPerEpoch
func (p *PolicyParameters) GetEpochsPerYear() uint64 {
	blocksPerYear := p.GetBlocksPerYear()
	return blocksPerYear / p.BlocksPerEpoch
}

// CalculateEpochInflation calculates inflation for a single epoch in a given year
func (p *PolicyParameters) CalculateEpochInflation(
	totalSupply *big.Int,
	year uint64,
	currentStakeRatio float64,
) *InflationDistribution {
	// Get annual inflation rate for this year
	annualRate := p.CalculateAnnualInflationWithStakeAdjustment(year, currentStakeRatio)

	// Calculate number of epochs in a year
	epochsPerYear := p.GetEpochsPerYear()

	// Calculate per-epoch inflation rate
	epochRate := annualRate / float64(epochsPerYear)

	// Calculate total minted in this epoch
	// totalMinted = totalSupply * epochRate
	totalMinted := new(big.Int).Mul(totalSupply, new(big.Int).SetUint64(uint64(epochRate*1e18)))
	totalMinted.Div(totalMinted, new(big.Int).SetUint64(1e18))

	// Distribute between stakers and community pool
	// Stakers get γ% (80%), community pool gets (1-γ)% (20%)
	stakingRewards := new(big.Int).Mul(totalMinted, new(big.Int).SetUint64(uint64(p.StakingRewardShare*1e18)))
	stakingRewards.Div(stakingRewards, new(big.Int).SetUint64(1e18))

	communityFund := new(big.Int).Sub(totalMinted, stakingRewards)

	return &InflationDistribution{
		Year:                year,
		AnnualInflationRate: annualRate,
		StakersShare:        p.StakingRewardShare,
		CommunityPoolShare:  1 - p.StakingRewardShare,
		TotalMinted:         totalMinted,
		StakingRewards:      stakingRewards,
		CommunityFund:       communityFund,
	}
}

// CalculateCumulativeInflation calculates total inflation over multiple years
// Useful for long-term supply projections
func (p *PolicyParameters) CalculateCumulativeInflation(years uint64) float64 {
	cumulative := 0.0
	for year := uint64(1); year <= years; year++ {
		cumulative += p.CalculateAnnualInflation(year)
	}
	return cumulative
}

// GetAnnualMinting calculates total tokens minted in a specific year
func (p *PolicyParameters) GetAnnualMinting(
	totalSupply *big.Int,
	year uint64,
	currentStakeRatio float64,
) *big.Int {
	annualRate := p.CalculateAnnualInflationWithStakeAdjustment(year, currentStakeRatio)

	minted := new(big.Int).Mul(totalSupply, new(big.Int).SetUint64(uint64(annualRate*1e18)))
	minted.Div(minted, new(big.Int).SetUint64(1e18))

	return minted
}

// GetRemainingSupply calculates remaining supply after N years
// Useful for understanding long-term tokenomics
func (p *PolicyParameters) GetRemainingSupply(
	initialSupply *big.Int,
	years uint64,
	yearlyStakeRatios []float64,
) *big.Int {
	currentSupply := new(big.Int).Set(initialSupply)

	for year := uint64(1); year <= years; year++ {
		var stakeRatio float64
		if year <= uint64(len(yearlyStakeRatios)) {
			stakeRatio = yearlyStakeRatios[year-1]
		} else {
			stakeRatio = p.TargetStakeRatio
		}

		annualMinting := p.GetAnnualMinting(currentSupply, year, stakeRatio)
		currentSupply.Add(currentSupply, annualMinting)
	}

	return currentSupply
}
