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

	// Gas schedule. These values are consensus inputs: clients use them to
	// quote a transaction, while core verifies the same quote before admitting
	// and executing it.
	BaseTransactionGas   uint64   `json:"base_transaction_gas"`
	ReturnDataGasPerByte uint64   `json:"return_data_gas_per_byte"`
	MinimumGasPrice      *big.Int `json:"minimum_gas_price"` // nSPX per gas

	// BlockReward is the base nSPX minted for an ordinary (non-genesis) block.
	// It is deliberately policy-owned rather than a node-local chain setting.
	BlockReward *big.Int `json:"block_reward"`

	// BlockRewardBurnBPS is the share of each freshly minted block reward
	// credited to the protocol burn (DEAD) address instead of the proposer.
	// Unlike BurnFeeBPS — which relocates already-circulating fee nSPX —
	// this splits newly minted nSPX, so core must IncrementTotalSupply once
	// for the full reward and then AddBalance each slice (never decrement).
	BlockRewardBurnBPS uint64 `json:"block_reward_burn_bps"`

	// Fee distribution is expressed in basis points and must total 10,000.
	ValidatorFeeBPS uint64 `json:"validator_fee_bps"`
	StakerFeeBPS    uint64 `json:"staker_fee_bps"`
	TreasuryFeeBPS  uint64 `json:"treasury_fee_bps"`
	BurnFeeBPS      uint64 `json:"burn_fee_bps"`

	// Usage-responsive fee-burn policy. BurnFeeBPS above is the STARTING
	// rate; at each block the executor rolls it one fixed step toward or
	// away from a target utilization of the previous finalized block's gas
	// (an EIP-1559-style fee-market feedback on the BURN side only — the
	// mint side, BlockRewardBurnBPS, is deliberately untouched by this).
	// Like BlockReward, these are policy-owned, not chain-config: they are
	// part of the governance/SIPS-governed monetary schedule, never a
	// node-local chain setting, and they are consensus inputs (every node
	// must roll the identical rate from the committed previous block).
	BurnFeeFloorBPS             uint64 `json:"burn_fee_floor_bps"`              // lower clamp, e.g. 200 (2%)
	BurnFeeCeilingBPS           uint64 `json:"burn_fee_ceiling_bps"`            // upper clamp, e.g. 1000 (10%)
	BurnFeeStepBPS              uint64 `json:"burn_fee_step_bps"`               // fixed integer step per block, e.g. 5
	BurnFeeTargetUtilizationBPS uint64 `json:"burn_fee_target_utilization_bps"` // target share of the previous block's gas limit, e.g. 5000 (50%)

	// Contract execution schedule. Core meters native calls and the restricted
	// deterministic SVM against these values.
	ContractDeployGas    uint64 `json:"contract_deploy_gas"`
	ContractCallGas      uint64 `json:"contract_call_gas"`
	ContractCodeGasByte  uint64 `json:"contract_code_gas_byte"`
	ContractCallDataByte uint64 `json:"contract_call_data_gas_byte"`
	SVMGasPerOperation   uint64 `json:"svm_gas_per_operation"`
	WASMMaxCodeBytes     uint64 `json:"wasm_max_code_bytes"`
	WASMMemoryPages      uint32 `json:"wasm_memory_pages"`
	WASMGasPerOperation  uint64 `json:"wasm_gas_per_operation"`
	StorageReadGas       uint64 `json:"storage_read_gas"`
	StorageWriteGas      uint64 `json:"storage_write_gas"`
	EventGasPerByte      uint64 `json:"event_gas_per_byte"`
	ContractTransferGas  uint64 `json:"contract_transfer_gas"`
	WASMMaxEvents        uint64 `json:"wasm_max_events"`

	// Storage pricing
	PinRatePerGBMonth *big.Int `json:"pin_rate_per_gb_month"` // PinRate = 0.01 SPX/GB/month

	// Minting / data anchoring (USI Mint Data)
	// MinMintBalance is the minimum nSPX balance an identity must hold to mint
	// (anchor) data through src/usi/gui (default 100 SPX). The per-mint price is
	// NOT a flat constant: CalculateMintDataFee sizes it from the payload size,
	// anchor/metadata bytes, hash count, gas quote, IPFS pinning duration and
	// the BlocksPerEpoch replication factor. The Mint* fields below are the
	// deterministic sizing knobs of that calculation.
	MinMintBalance     *big.Int `json:"min_mint_balance"`      // 100 SPX in nSPX
	MintAnchorBaseSize uint64   `json:"mint_anchor_base_size"` // serialized anchor tx overhead, excl. return data (bytes)
	MintAnchorBytes    uint64   `json:"mint_anchor_bytes"`     // estimated anchor payload (ReturnData) size in bytes
	MintBaseOps        uint64   `json:"mint_base_ops"`         // base compute operations per mint
	MintBaseHashes     uint64   `json:"mint_base_hashes"`      // hashes committed per mint (SPHINCS+ auth bundle)
	MintPinningMonths  uint64   `json:"mint_pinning_months"`   // default IPFS retention per mint (months)

	// Embedded-economics floor: MinTokenSaleValue is the minimum nSPX a
	// SIP-721 resale may claim as its price for royalty purposes. When a
	// transfer_from settlement carries less than this (dust-price wash
	// trading), the resale royalty is computed on the floor instead of the
	// carried value — so evasion costs real royalties rather than being free.
	// nil disables the floor. Royalty is still capped at the escrowed value,
	// so the seller never pays out of pocket.
	MinTokenSaleValue *big.Int `json:"min_token_sale_value,omitempty"`

	// Inflation parameters
	// The BPS fields are the consensus representation. The float fields below
	// remain for wallet/UI projections and backward-compatible APIs only.
	InitialInflationBPS uint64 `json:"initial_inflation_bps"`
	InflationDecayBPS   uint64 `json:"inflation_decay_bps"`
	StakingRewardBPS    uint64 `json:"staking_reward_bps"`
	TargetStakeBPS      uint64 `json:"target_stake_bps"`

	// Stake-responsive epoch inflation. The stake ratio (committed validator
	// stake over total supply, both read from the state DB at the epoch
	// boundary — never a live or mid-epoch read) scales the decayed base
	// mint by CalculateStakeAdjustedMultiplierBPS. Like BlockReward, these
	// are policy-owned, not chain-config: SIPS-governable monetary levers,
	// never node-local settings, and consensus inputs every node must apply
	// identically.
	StakeInflationSensitivityBPS uint64 `json:"stake_inflation_sensitivity_bps"` // response to a 1.0x deviation, 10000 = 1:1
	StakeMultiplierFloorBPS      uint64 `json:"stake_multiplier_floor_bps"`      // lower clamp, 5000 = 0.5x
	StakeMultiplierCeilingBPS    uint64 `json:"stake_multiplier_ceiling_bps"`    // upper clamp, 20000 = 2.0x

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
	StakeMultiplierBPS  uint64   `json:"stake_multiplier_bps"`  // Stake-responsive multiplier applied to the decayed base (10000 = 1.0x)
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

// MintDataFeeQuote is the policy-computed price of one data mint. Every
// component is deterministic and derived from the payload dimensions and the
// governance fee schedule, so the wallet and the node compute the same number.
type MintDataFeeQuote struct {
	PayloadBytes  uint64 `json:"payload_bytes"`  // raw signed data size in bytes
	AnchorBytes   uint64 `json:"anchor_bytes"`   // on-chain anchor payload bytes
	NumHashes     uint64 `json:"num_hashes"`     // committed hashes / Merkle leaves
	PinningMonths uint64 `json:"pinning_months"` // IPFS retention

	TxFee      *big.Int `json:"tx_fee"`      // on-chain write+compute (× replication R)
	StorageFee *big.Int `json:"storage_fee"` // metadata anchoring (storage schedule)
	GasFee     *big.Int `json:"gas_fee"`     // anchor transaction gas
	IPFSFee    *big.Int `json:"ipfs_fee"`    // IPFS pinning over the retention period
	TotalFee   *big.Int `json:"total_fee"`   // TxFee + StorageFee + GasFee + IPFSFee
}

// FeeDistribution represents how collected fees are distributed
type FeeDistribution struct {
	TotalFees  *big.Int `json:"total_fees"`
	Validators *big.Int `json:"validators"` // 60% to validators
	Stakers    *big.Int `json:"stakers"`    // 25% to stakers
	Treasury   *big.Int `json:"treasury"`   // 10% to treasury
	Burned     *big.Int `json:"burned"`     // 5% burned (deflationary)
}
