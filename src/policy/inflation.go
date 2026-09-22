// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/policy/inflation.go
package policy

import (
	"math/big"
	"time"
)

const basisPoints = uint64(10000)

// CalculateStakeAdjustedMultiplierBPS ports the stake-ratio responsiveness of
// CalculateAnnualInflationWithStakeAdjustment to pure integer basis-point
// math. It is a pure function of its two arguments and policy constants — no
// state DB reads, no wall-clock time, no peer state — so every replaying node
// derives the identical multiplier and state root.
//
//	stakedRatioBPS  = totalStaked * 10000 / totalSupply   (multiply-before-divide)
//	deviationBPS    = TargetStakeBPS - stakedRatioBPS      (signed)
//	multiplierBPS   = 10000 + deviationBPS * SensitivityBPS / 10000
//
// The multiplier is clamped to [StakeMultiplierFloorBPS, StakeMultiplierCeilingBPS]
// (0.5x–2.0x by default). A zero or nil totalSupply (the genesis guard)
// returns exactly 10000 (1.0x); a zero/nil/negative totalStaked is a 0% stake
// ratio. All math is big.Int / uint64 with multiply-before-divide ordering.
func (p *PolicyParameters) CalculateStakeAdjustedMultiplierBPS(totalStaked, totalSupply *big.Int) uint64 {
	if totalSupply == nil || totalSupply.Sign() <= 0 {
		return basisPoints // genesis guard: 1.0x
	}

	sensitivityBPS := p.StakeInflationSensitivityBPS
	if sensitivityBPS == 0 {
		sensitivityBPS = basisPoints
	}
	floorBPS, ceilingBPS := p.StakeMultiplierFloorBPS, p.StakeMultiplierCeilingBPS
	if floorBPS == 0 {
		floorBPS = 5000
	}
	if ceilingBPS == 0 {
		ceilingBPS = 20000
	}
	if floorBPS > ceilingBPS {
		floorBPS, ceilingBPS = ceilingBPS, floorBPS
	}
	targetBPS := p.TargetStakeBPS
	if targetBPS > basisPoints {
		targetBPS = basisPoints
	}

	// stakedRatioBPS = totalStaked * 10000 / totalSupply — always multiply
	// before divide so the ratio is computed identically on every node.
	stakedRatioBPS := big.NewInt(0)
	if totalStaked != nil && totalStaked.Sign() > 0 {
		stakedRatioBPS = new(big.Int).Mul(totalStaked, new(big.Int).SetUint64(basisPoints))
		stakedRatioBPS.Div(stakedRatioBPS, totalSupply)
	}

	// deviationBPS = target - stakedRatio (signed, big.Int so an over-100%
	// ratio cannot overflow anything).
	deviationBPS := new(big.Int).Sub(new(big.Int).SetUint64(targetBPS), stakedRatioBPS)

	// multiplierBPS = 10000 + deviationBPS * SensitivityBPS / 10000.
	adjustment := new(big.Int).Mul(deviationBPS, new(big.Int).SetUint64(sensitivityBPS))
	adjustment.Div(adjustment, new(big.Int).SetUint64(basisPoints))
	multiplierBPS := new(big.Int).SetUint64(basisPoints)
	multiplierBPS.Add(multiplierBPS, adjustment)

	// Clamp to [floor, ceiling] (0.5x–2.0x by default).
	if multiplierBPS.Sign() < 0 || multiplierBPS.Cmp(new(big.Int).SetUint64(floorBPS)) < 0 {
		return floorBPS
	}
	if multiplierBPS.Cmp(new(big.Int).SetUint64(ceilingBPS)) > 0 {
		return ceilingBPS
	}
	return multiplierBPS.Uint64()
}

// CalculateEpochInflationExact calculates issuance using only integer policy
// values. It is the consensus-safe counterpart to CalculateEpochInflation,
// whose float values are retained for estimates and legacy callers.
//
// totalStaked must come from the epoch-boundary validator snapshot — the
// deterministic validator-stake records already committed to the state DB
// (the same snapshot the epoch staking-reward distribution reads) — never
// from a live or mid-epoch consensus read. That is what keeps the
// stake-responsive multiplier immune to stake-timing griefing: a stake or
// unstake can only influence an epoch boundary once its block is actually
// committed, identically on every node.
func (p *PolicyParameters) CalculateEpochInflationExact(totalSupply, totalStaked *big.Int, year uint64) *InflationDistribution {
	if totalSupply == nil || totalSupply.Sign() <= 0 || p == nil || p.GetEpochsPerYear() == 0 {
		return &InflationDistribution{Year: year, TotalMinted: big.NewInt(0), StakingRewards: big.NewInt(0), CommunityFund: big.NewInt(0)}
	}
	if year == 0 {
		year = 1
	}
	rateBPS := p.InitialInflationBPS
	for i := uint64(1); i < year; i++ {
		rateBPS = rateBPS * p.InflationDecayBPS / basisPoints
	}
	denominator := new(big.Int).SetUint64(basisPoints * p.GetEpochsPerYear())
	totalMinted := new(big.Int).Mul(totalSupply, new(big.Int).SetUint64(rateBPS))
	totalMinted.Div(totalMinted, denominator)

	// Stake-responsive scaling on top of the decayed base amount, always
	// multiply-before-divide:
	//
	//	adjustedAmount = baseDecayedAmount * multiplierBPS / 10000
	multiplierBPS := p.CalculateStakeAdjustedMultiplierBPS(totalStaked, totalSupply)
	totalMinted.Mul(totalMinted, new(big.Int).SetUint64(multiplierBPS))
	totalMinted.Div(totalMinted, new(big.Int).SetUint64(basisPoints))

	stakingRewards := new(big.Int).Mul(totalMinted, new(big.Int).SetUint64(p.StakingRewardBPS))
	stakingRewards.Div(stakingRewards, new(big.Int).SetUint64(basisPoints))
	communityFund := new(big.Int).Sub(totalMinted, stakingRewards)
	return &InflationDistribution{
		Year:                year,
		AnnualInflationRate: float64(rateBPS) / float64(basisPoints),
		StakersShare:        float64(p.StakingRewardBPS) / float64(basisPoints),
		CommunityPoolShare:  float64(basisPoints-p.StakingRewardBPS) / float64(basisPoints),
		TotalMinted:         totalMinted,
		StakingRewards:      stakingRewards,
		CommunityFund:       communityFund,
		StakeMultiplierBPS:  multiplierBPS,
	}
}

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
	if p == nil || p.BlockTime < time.Second {
		return 0
	}
	secondsPerYear := uint64(365 * 24 * 3600) // 31,536,000 seconds
	blocksPerYear := secondsPerYear / uint64(p.BlockTime.Seconds())
	return blocksPerYear
}

// GetEpochsPerYear calculates number of epochs per year
// EpochsPerYear = BlocksPerYear / BlocksPerEpoch
func (p *PolicyParameters) GetEpochsPerYear() uint64 {
	if p == nil || p.BlocksPerEpoch == 0 {
		return 0
	}
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
