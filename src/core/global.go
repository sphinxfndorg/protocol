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

// go/src/core/global.go
package core

import (
	"math/big"
	"strings"
	"time"

	"github.com/sphinxorg/protocol/src/common"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	logger "github.com/sphinxorg/protocol/src/log"
	denom "github.com/sphinxorg/protocol/src/params/denom"
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

// Global genesis block definition with comprehensive data
var genesisBlockDefinition = &types.BlockHeader{
	Version:    1,
	Height:     0,
	Timestamp:  1732070400, // Fixed: Nov 20, 2024 00:00:00 UTC
	Difficulty: big.NewInt(1),
	Nonce:      common.FormatNonce(1),    // FIXED: Start with "0000000000000001"
	TxsRoot:    common.SpxHash([]byte{}), // Empty transactions root
	StateRoot:  common.SpxHash([]byte("sphinx-genesis-state-root")),
	GasLimit:   big.NewInt(5000), // Initial gas limit
	GasUsed:    big.NewInt(0),
	ExtraData:  []byte("Sphinx Network Genesis Block - Decentralized Future"),
	Miner:      make([]byte, 20), // Zero address for genesis
	ParentHash: make([]byte, 32), // Genesis has no parent
	UnclesHash: common.SpxHash([]byte("genesis-no-uncles")),
}

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

// Add to core/blockchain.go

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
func GetGenesisBlockDefinition() *types.BlockHeader {
	// Return a copy to prevent modification
	return &types.BlockHeader{
		Version:    genesisBlockDefinition.Version,
		Height:     genesisBlockDefinition.Height,
		Timestamp:  genesisBlockDefinition.Timestamp,
		Difficulty: new(big.Int).Set(genesisBlockDefinition.Difficulty),
		Nonce:      common.FormatNonce(1), // FIXED: Ensure consistent nonce format "0000000000000001"
		TxsRoot:    append([]byte{}, genesisBlockDefinition.TxsRoot...),
		StateRoot:  append([]byte{}, genesisBlockDefinition.StateRoot...),
		GasLimit:   new(big.Int).Set(genesisBlockDefinition.GasLimit),
		GasUsed:    new(big.Int).Set(genesisBlockDefinition.GasUsed),
		ExtraData:  append([]byte{}, genesisBlockDefinition.ExtraData...),
		Miner:      append([]byte{}, genesisBlockDefinition.Miner...),
		ParentHash: append([]byte{}, genesisBlockDefinition.ParentHash...),
		UnclesHash: append([]byte{}, genesisBlockDefinition.UnclesHash...),
	}
}

// CreateStandardGenesisBlock creates a standardized genesis block that all nodes should use
func CreateStandardGenesisBlock() *types.Block {
	// Create the genesis header directly to ensure all fields are properly set
	genesisHeader := &types.BlockHeader{
		Version:    1,
		Block:      0, // Same as Height
		Height:     0,
		Timestamp:  1732070400,               // Fixed: Nov 20, 2024 00:00:00 UTC
		Difficulty: big.NewInt(17179869184),  // Substantial initial difficulty
		Nonce:      common.FormatNonce(1),    // FIXED: "0000000000000001"
		TxsRoot:    common.SpxHash([]byte{}), // Empty transactions root
		StateRoot:  common.SpxHash([]byte("sphinx-genesis-state-root")),
		GasLimit:   big.NewInt(5000), // Initial gas limit
		GasUsed:    big.NewInt(0),
		ExtraData:  []byte("Sphinx Network Genesis Block - Decentralized Future"),
		Miner:      make([]byte, 20), // Zero address for genesis
		ParentHash: make([]byte, 32), // Genesis has no parent
		UnclesHash: common.SpxHash([]byte("genesis-no-uncles")),
		Hash:       []byte{}, // Will be set by FinalizeHash
	}

	// Create empty uncles slice for genesis
	emptyUncles := []*types.BlockHeader{}

	// Create block body with empty transactions and uncles
	genesisBody := types.NewBlockBody([]*types.Transaction{}, emptyUncles)
	genesis := types.NewBlock(genesisHeader, genesisBody)

	// Finalize the hash
	genesis.FinalizeHash()

	// Log the genesis block details for verification
	logger.Info("✅ Created standardized genesis block:")
	logger.Info("   - Height: %d", genesis.Header.Height)
	logger.Info("   - Nonce: %s", genesis.Header.Nonce)
	logger.Info("   - Hash: %s", genesis.GetHash())
	logger.Info("   - Difficulty: %s", genesis.Header.Difficulty.String())

	return genesis
}

// GetGenesisHash returns the standardized genesis hash that ALL nodes should use
func GetGenesisHash() string {
	genesis := CreateStandardGenesisBlock()
	hash := genesis.GetHash()

	// Ensure it has the GENESIS_ prefix
	if !strings.HasPrefix(hash, "GENESIS_") {
		// Regenerate with proper prefix
		genesis.FinalizeHash()
		hash = genesis.GetHash()
	}

	logger.Info("Standardized genesis hash: %s", hash)
	return hash
}

// GenerateGenesisHash is deprecated - use GetGenesisHash instead for consistency
func GenerateGenesisHash() string {
	logger.Warn("GenerateGenesisHash is deprecated, using GetGenesisHash for consistency")
	return GetGenesisHash()
}
