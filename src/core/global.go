// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/global.go
// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/global.go
package core

import (
	"math/big"
	"sync"
	"time"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	logger "github.com/sphinxfndorg/protocol/src/log"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
)

// Constants for blockchain status, sync modes, etc.
const (
	StatusInitializing BlockchainStatus = iota
	StatusSyncing
	StatusRunning
	StatusStopped
	StatusForked
)

const (
	SyncModeFull SyncMode = iota
	SyncModeFast
	SyncModeLight
)

const (
	ImportedBest BlockImportResult = iota
	ImportedSide
	ImportedExisting
	ImportInvalid
	ImportError
)

const (
	CacheTypeBlock CacheType = iota
	CacheTypeTransaction
	CacheTypeReceipt
	CacheTypeState
)

// genesisOnce ensures BuildBlock() runs exactly once per process.
// argon2 takes ~134s — running it 3 times (one per node) would hang for 400s+.
var (
	genesisOnce      sync.Once
	genesisHashValue string
	genesisCached    *types.Block
)

// GetGenesisTime returns the genesis block timestamp
func (bc *Blockchain) GetGenesisTime() time.Time {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	if len(bc.chain) == 0 {
		// If no chain, return a default (this shouldn't happen in practice)
		logger.Warn("GetGenesisTime called with empty chain, returning default")
		return time.Unix(1732070400, 0) // Default from your chain params
	}

	// Genesis block is at height 0
	genesis := bc.chain[0]
	return time.Unix(genesis.GetTimestamp(), 0)
}

// GetValidatorStake returns the stake amount for a validator in nSPX
func (bc *Blockchain) GetValidatorStake(validatorID string) *big.Int {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	// This is a placeholder - you need to implement actual stake storage
	// For now, return a default stake for testing
	if bc.chainParams != nil && bc.chainParams.ConsensusConfig != nil {
		// Return minimum stake as default for testing
		return bc.chainParams.ConsensusConfig.MinStakeAmount
	}

	// Default fallback: 32 SPX in nSPX
	return new(big.Int).Mul(
		big.NewInt(32),
		big.NewInt(denom.SPX),
	)
}

// GetTotalStaked returns the total amount staked across all validators
func (bc *Blockchain) GetTotalStaked() *big.Int {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	// Placeholder - you need to implement actual total stake calculation
	// For testing, return a reasonable value
	totalStake := new(big.Int).Mul(
		big.NewInt(1000), // Assume 1000 SPX total staked
		big.NewInt(denom.SPX),
	)
	return totalStake
}

// UpdateValidatorStake updates a validator's stake (for rewards/slashing)
func (bc *Blockchain) UpdateValidatorStake(validatorID string, delta *big.Int) error {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	// Placeholder - implement actual stake update logic
	logger.Info("Updating stake for validator %s by %s nSPX", validatorID, delta.String())
	return nil
}

// GetGenesisBlockDefinition returns the standardized genesis block definition
// DEPRECATED: Use GetCachedGenesisBlock() or DefaultGenesisState().BuildBlock() instead
func GetGenesisBlockDefinition() *types.BlockHeader {
	// Use the canonical genesis block from genesis.go
	canonicalGenesis := DefaultGenesisState().BuildBlock()

	// Return a copy of the header to prevent modification
	header := canonicalGenesis.Header
	return &types.BlockHeader{
		Version:    header.Version,
		Height:     header.Height,
		Timestamp:  header.Timestamp,
		Difficulty: new(big.Int).Set(header.Difficulty),
		Nonce:      header.Nonce,
		TxsRoot:    append([]byte{}, header.TxsRoot...),
		StateRoot:  append([]byte{}, header.StateRoot...),
		GasLimit:   new(big.Int).Set(header.GasLimit),
		GasUsed:    new(big.Int).Set(header.GasUsed),
		ExtraData:  append([]byte{}, header.ExtraData...),
		Miner:      append([]byte{}, header.Miner...),
		ParentHash: append([]byte{}, header.ParentHash...),
		UnclesHash: append([]byte{}, header.UnclesHash...),
	}
}

// CreateStandardGenesisBlock creates a standardized genesis block that all nodes should use
// DEPRECATED: Use DefaultGenesisState().BuildBlock() instead
func CreateStandardGenesisBlock() *types.Block {
	// Delegate to the canonical genesis builder from genesis.go
	return DefaultGenesisState().BuildBlock()
}

// getCachedGenesisBlock builds the genesis block exactly once per process.
// It uses DefaultGenesisState() only for the cryptographic fields (timestamp,
// difficulty, gas limit, extra data) — the ChainName/ChainID in that state
// do NOT affect the block hash, so the same block is valid for all environments.
// The ChainName written to genesis_state.json is controlled by the gs passed
// to ApplyGenesisWithCachedBlock, NOT by this function.
func getCachedGenesisBlock() *types.Block {
	genesisOnce.Do(func() {
		// DefaultGenesisState() provides the canonical cryptographic inputs.
		// ChainName here is irrelevant to the hash — only timestamp, difficulty,
		// gas limit, and extra data feed into BuildBlock() → FinalizeHash().
		gs := DefaultGenesisState()
		genesisCached = gs.BuildBlock()
		genesisHashValue = genesisCached.GetHash()
		logger.Info("Genesis block computed once: %s", genesisHashValue)
	})
	return genesisCached
}

// GetGenesisHash returns the computed genesis hash (computed once, cached forever).
func GetGenesisHash() string {
	getCachedGenesisBlock()
	return genesisHashValue
}

// GenerateGenesisHash is deprecated - use GetGenesisHash instead for consistency
func GenerateGenesisHash() string {
	logger.Warn("GenerateGenesisHash is deprecated, using GetGenesisHash for consistency")
	return GetGenesisHash()
}

// ============================================================================
// SUPPLY STATUS HELPERS - Quick access to supply info
// ============================================================================

// GetMaxSupplySPX returns the maximum supply in whole SPX
func GetMaxSupplySPX() *big.Int {
	return new(big.Int).SetInt64(denom.MaxSupplySPX)
}

// GetMaxSupplyNSPX returns the maximum supply in nSPX
func GetMaxSupplyNSPX() *big.Int {
	return new(big.Int).Mul(
		big.NewInt(denom.MaxSupplySPX),
		big.NewInt(denom.SPX),
	)
}

// GetGenesisVaultAddress returns the genesis vault address constant
func GetGenesisVaultAddress() string {
	return GenesisVaultAddress
}
