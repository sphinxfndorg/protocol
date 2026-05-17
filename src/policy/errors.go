// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/policy/errors.go
package policy

import "errors"

var (
	ErrInvalidBaseFeePerByte     = errors.New("invalid base fee per byte")
	ErrInvalidStorageFeePerByte  = errors.New("invalid storage fee per byte")
	ErrInvalidComputeFeePerOp    = errors.New("invalid compute fee per op")
	ErrInvalidBlocksPerEpoch     = errors.New("invalid blocks per epoch")
	ErrInvalidBlockTime          = errors.New("invalid block time")
	ErrInvalidHashFee            = errors.New("invalid hash fee")
	ErrInvalidBaseStorageFee     = errors.New("invalid base storage fee")
	ErrInvalidTransactionFee     = errors.New("invalid transaction fee")
	ErrInvalidInflationRate      = errors.New("invalid inflation rate")
	ErrInvalidStakingRewardShare = errors.New("invalid staking reward share")
	ErrInvalidTargetStakeRatio   = errors.New("invalid target stake ratio")
	ErrInvalidFeeDistribution    = errors.New("invalid fee distribution")
)
