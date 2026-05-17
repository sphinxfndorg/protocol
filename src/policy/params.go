// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/policy/params.go
package policy

import (
	"math/big"
	"time"
)

// NewPolicyParameters creates a new instance with the specified governance parameters
// NewPolicyParameters creates a new instance with the specified governance parameters
func NewPolicyParameters() *PolicyParameters {
	// PinRate: 0.01 SPX/GB/month = 0.01 * 1e18 nSPX = 1e16 nSPX per GB/month
	pinRatePerGBMonth := new(big.Int).Mul(big.NewInt(1), new(big.Int).Exp(big.NewInt(10), big.NewInt(16), nil))

	return &PolicyParameters{
		// Fee parameters (all in nSPX)
		BaseFeePerByte:    big.NewInt(20000),   // 20,000 nSPX/byte
		StorageFeePerByte: big.NewInt(200000),  // 200,000 nSPX/byte
		ComputeFeePerOp:   big.NewInt(5000000), // 5,000,000 nSPX/op

		// Consensus parameters
		BlocksPerEpoch: 3,                // R = 3 blocks per epoch
		BlockTime:      12 * time.Second, // 12 seconds block time

		// Storage parameters
		HashFee:        big.NewInt(10000),  // α = 10,000 nSPX/hash
		BaseStorageFee: big.NewInt(200000), // β = 200,000 nSPX
		TransactionFee: big.NewInt(1000),   // K_tx = 1,000 nSPX

		// Storage pricing
		PinRatePerGBMonth: pinRatePerGBMonth, // 0.01 SPX/GB/month in nSPX

		// Inflation parameters
		InitialInflationRate: 0.05, // 5% annual inflation
		InflationDecayFactor: 0.8,  // γ = 0.8 (decay factor for geometric progression)
		StakingRewardShare:   0.8,  // 80% to stakers
		TargetStakeRatio:     0.70, // 70% target staked ratio
	}
}

// GetDefaultPolicyParams returns the default policy parameters
func GetDefaultPolicyParams() *PolicyParameters {
	return NewPolicyParameters()
}

// Validate validates the policy parameters
func (p *PolicyParameters) Validate() error {
	// Validate fee parameters are positive
	if p.BaseFeePerByte.Sign() <= 0 {
		return ErrInvalidBaseFeePerByte
	}
	if p.StorageFeePerByte.Sign() <= 0 {
		return ErrInvalidStorageFeePerByte
	}
	if p.ComputeFeePerOp.Sign() <= 0 {
		return ErrInvalidComputeFeePerOp
	}

	// Validate consensus parameters
	if p.BlocksPerEpoch == 0 {
		return ErrInvalidBlocksPerEpoch
	}
	if p.BlockTime <= 0 {
		return ErrInvalidBlockTime
	}

	// Validate storage parameters
	if p.HashFee.Sign() <= 0 {
		return ErrInvalidHashFee
	}
	if p.BaseStorageFee.Sign() <= 0 {
		return ErrInvalidBaseStorageFee
	}
	if p.TransactionFee.Sign() <= 0 {
		return ErrInvalidTransactionFee
	}

	// Validate inflation parameters
	if p.InitialInflationRate < 0 || p.InitialInflationRate > 1 {
		return ErrInvalidInflationRate
	}
	if p.StakingRewardShare < 0 || p.StakingRewardShare > 1 {
		return ErrInvalidStakingRewardShare
	}
	if p.TargetStakeRatio < 0 || p.TargetStakeRatio > 1 {
		return ErrInvalidTargetStakeRatio
	}

	return nil
}
