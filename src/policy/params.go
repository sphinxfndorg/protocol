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

	// USI minting: to mint data through src/usi/gui an identity must hold at
	// least 100 SPX, and each mint is priced by CalculateMintDataFee from the
	// payload dimensions (size, compute, storage, gas × replication, IPFS pin)
	// rather than a flat constant. The values below are the deterministic
	// sizing knobs of that calculation.
	e18 := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	minMintBalance := new(big.Int).Mul(big.NewInt(100), e18) // 100 SPX in nSPX

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

		// A simple, deterministic gas schedule. Return data covers data anchors
		// (including USI mint anchors) without giving the wallet a special case.
		BaseTransactionGas:   21000,
		ReturnDataGasPerByte: 100,
		MinimumGasPrice:      big.NewInt(1000000000),                            // 1 gSPX per gas
		BlockReward:          new(big.Int).Mul(big.NewInt(5), big.NewInt(1e18)), // 5 SPX
		BlockRewardBurnBPS:   500,  // 5% of each block reward -> DEAD burn address
		ValidatorFeeBPS:      6000,
		StakerFeeBPS:         2500,
		TreasuryFeeBPS:       1000,
		BurnFeeBPS:           500,
		ContractDeployGas:    100000,
		ContractCallGas:      30000,
		ContractCodeGasByte:  50,
		ContractCallDataByte: 25,
		SVMGasPerOperation:   10,
		WASMMaxCodeBytes:     512 * 1024,
		WASMMemoryPages:      16, // 1 MiB
		WASMGasPerOperation:  3,
		StorageReadGas:       100,
		StorageWriteGas:      20000,
		EventGasPerByte:      8,
		ContractTransferGas:  9000,
		WASMMaxEvents:        64,

		// Storage pricing
		PinRatePerGBMonth: pinRatePerGBMonth, // 0.01 SPX/GB/month in nSPX

		// Minting / data anchoring (USI Mint Data)
		MinMintBalance:     minMintBalance, // 100 SPX in nSPX
		MintAnchorBaseSize: 768,            // serialized anchor tx overhead, excl. return data (bytes)
		MintAnchorBytes:    300,            // estimated anchor payload (ReturnData) size in bytes
		MintBaseOps:        4,              // base compute ops: load key, hash payload, hash anchor, sign
		MintBaseHashes:     5,              // payload hash + sig hash + merkle root + commitment + proof
		MintPinningMonths:  1,              // 1 month default IPFS retention

		// Embedded-economics floor for SIP-721 resale royalties: 0.1 SPX. Low
		// enough not to block ordinary collectibles, high enough that settling
		// at dust prices still yields a real royalty. Royalty = bps ×
		// max(sale_value, floor), capped at the escrowed sale value.
		MinTokenSaleValue: new(big.Int).Mul(big.NewInt(1), new(big.Int).Exp(big.NewInt(10), big.NewInt(17), nil)), // 0.1 SPX = 1e17 nSPX

		// Inflation parameters
		InitialInflationBPS:  500,  // 5.00% annual inflation
		InflationDecayBPS:    8000, // 80.00% of the preceding year's rate
		StakingRewardBPS:     8000, // 80.00% of new issuance to staking
		TargetStakeBPS:       7000, // 70.00% target stake
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
	if p.BaseTransactionGas == 0 || p.MinimumGasPrice == nil || p.MinimumGasPrice.Sign() <= 0 {
		return ErrInvalidTransactionFee
	}
	if p.BlockReward == nil || p.BlockReward.Sign() < 0 {
		return ErrInvalidBlockReward
	}
	if p.BlockRewardBurnBPS > 10000 {
		return ErrInvalidBlockRewardBurn
	}
	if p.ContractDeployGas == 0 || p.ContractCallGas == 0 || p.SVMGasPerOperation == 0 {
		return ErrInvalidTransactionFee
	}
	if p.WASMMaxCodeBytes == 0 || p.WASMMemoryPages == 0 || p.WASMGasPerOperation == 0 ||
		p.StorageReadGas == 0 || p.StorageWriteGas == 0 || p.EventGasPerByte == 0 || p.ContractTransferGas == 0 || p.WASMMaxEvents == 0 {
		return ErrInvalidTransactionFee
	}

	// Validate minting parameters
	if p.MinMintBalance == nil || p.MinMintBalance.Sign() <= 0 {
		return ErrInvalidMinMintBalance
	}
	if p.MintAnchorBaseSize == 0 || p.MintAnchorBytes == 0 || p.MintBaseOps == 0 || p.MintBaseHashes == 0 || p.MintPinningMonths == 0 {
		return ErrInvalidMintParams
	}

	if p.ValidatorFeeBPS+p.StakerFeeBPS+p.TreasuryFeeBPS+p.BurnFeeBPS != 10000 {
		return ErrInvalidFeeDistribution
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
	if p.InitialInflationBPS > 10000 || p.InflationDecayBPS > 10000 ||
		p.StakingRewardBPS > 10000 || p.TargetStakeBPS > 10000 {
		return ErrInvalidInflationRate
	}

	return nil
}
