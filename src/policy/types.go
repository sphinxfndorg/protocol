// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/policy/types.go
package policy

import (
	"math/big"
	"time"
)

// PolicyParameters defines all governance-controlled parameters
type PolicyParameters struct {
	// Fee parameters (in nSPX)
	BaseFeePerByte    *big.Int `json:"base_fee_per_byte"`    // B_w = 20,000 nSPX/byte
	StorageFeePerByte *big.Int `json:"storage_fee_per_byte"` // B_st = 200,000 nSPX/byte
	ComputeFeePerOp   *big.Int `json:"compute_fee_per_op"`   // B_cmp = 5,000,000 nSPX/op

	// Consensus parameters
	BlocksPerEpoch uint64        `json:"blocks_per_epoch"` // R = 3 blocks per epoch
	BlockTime      time.Duration `json:"block_time"`       // BlockTime ≈ 12 seconds

	// Storage parameters
	HashFee        *big.Int `json:"hash_fee"`         // α = 10,000 nSPX/hash
	BaseStorageFee *big.Int `json:"base_storage_fee"` // β = 200,000 nSPX
	TransactionFee *big.Int `json:"transaction_fee"`  // K_tx = 1,000 nSPX

	// Storage pricing
	PinRatePerGBMonth *big.Int `json:"pin_rate_per_gb_month"` // PinRate = 0.01 SPX/GB/month

	// Inflation parameters
	InitialInflationRate float64 `json:"initial_inflation_rate"` // Infl₀ = 0.05 (5% annual)
	InflationDecayFactor float64 `json:"inflation_decay_factor"` // γ = 0.8 (decay factor)
	StakingRewardShare   float64 `json:"staking_reward_share"`   // γ = 0.8 (80% to stakers)
	TargetStakeRatio     float64 `json:"target_stake_ratio"`     // Target = 0.70 (70% staked)
}

// InflationDistribution represents inflation allocation
type InflationDistribution struct {
	Year                uint64   `json:"year"`                  // Year number (1-indexed)
	AnnualInflationRate float64  `json:"annual_inflation_rate"` // Inflation rate for the year
	StakersShare        float64  `json:"stakers_share"`         // γ% (80%)
	CommunityPoolShare  float64  `json:"community_pool_share"`  // (1-γ)% (20%)
	TotalMinted         *big.Int `json:"total_minted"`          // Total tokens minted this epoch
	StakingRewards      *big.Int `json:"staking_rewards"`       // Tokens to stakers
	CommunityFund       *big.Int `json:"community_fund"`        // Tokens to community pool
}

// FeeComponents represents the breakdown of transaction fees
type FeeComponents struct {
	WriteFee       *big.Int `json:"write_fee"`       // B_w * bytes
	StorageFee     *big.Int `json:"storage_fee"`     // B_st * bytes
	ComputeFee     *big.Int `json:"compute_fee"`     // B_cmp * ops
	HashFee        *big.Int `json:"hash_fee"`        // α * hashes
	BaseFee        *big.Int `json:"base_fee"`        // β
	TransactionFee *big.Int `json:"transaction_fee"` // K_tx
	TotalFee       *big.Int `json:"total_fee"`
}

// StoragePricing represents storage cost calculations
type StoragePricing struct {
	Bytes        uint64   `json:"bytes"`
	DurationDays uint64   `json:"duration_days"`
	CostPerMonth *big.Int `json:"cost_per_month"`
	TotalCost    *big.Int `json:"total_cost"`
}

// FeeDistribution represents how collected fees are distributed
type FeeDistribution struct {
	TotalFees  *big.Int `json:"total_fees"`
	Validators *big.Int `json:"validators"` // 60% to validators
	Stakers    *big.Int `json:"stakers"`    // 25% to stakers
	Treasury   *big.Int `json:"treasury"`   // 10% to treasury
	Burned     *big.Int `json:"burned"`     // 5% burned (deflationary)
}
