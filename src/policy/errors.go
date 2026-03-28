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
