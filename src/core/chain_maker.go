// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/chain_maker.go
package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sphinxfndorg/protocol/src/common"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	logger "github.com/sphinxfndorg/protocol/src/log"
)

// NOTE: WriteChainCheckpoint is now defined in executor.go
// DO NOT duplicate it here.

// LoadChainCheckpoint reads the checkpoint written by devnet.
// Returns nil if no checkpoint exists (clean start).
// dataDir is the blockchain data directory (e.g., .../blockchain)
func LoadChainCheckpoint(dataDir string) (*ChainCheckpoint, error) {
	// Use centralized path function
	path := common.GetBlockchainCheckpointPath(dataDir)

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil // not an error — just no checkpoint yet
	}
	if err != nil {
		return nil, fmt.Errorf("LoadChainCheckpoint: %w", err)
	}

	var cp ChainCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("LoadChainCheckpoint: unmarshal: %w", err)
	}
	return &cp, nil
}

// LoadChainCheckpointFromAddress loads checkpoint using node address
// Convenience function that uses common package paths
func LoadChainCheckpointFromAddress(address string) (*ChainCheckpoint, error) {
	path := common.GetCheckpointPath(address)

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("LoadChainCheckpointFromAddress: %w", err)
	}

	var cp ChainCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("LoadChainCheckpointFromAddress: unmarshal: %w", err)
	}
	return &cp, nil
}

// ValidateCheckpointContinuity checks that the genesis hash in a checkpoint
// matches this node's expected genesis hash.  Call during testnet/mainnet init.
func ValidateCheckpointContinuity(cp *ChainCheckpoint) error {
	expected := GetGenesisHash()
	if cp.GenesisHash != expected {
		return fmt.Errorf(
			"chain continuity violation: checkpoint genesis=%s, this node expects=%s — "+
				"testnet/mainnet must continue from the same devnet genesis",
			cp.GenesisHash, expected,
		)
	}
	// Check vault balance from the nested structure
	if cp.Vault.BalanceNSPX != "0" {
		return fmt.Errorf(
			"chain continuity violation: checkpoint vault balance=%s (want 0) — "+
				"devnet distribution was not complete when checkpoint was taken",
			cp.Vault.BalanceNSPX,
		)
	}
	return nil
}

// ApplyCheckpointBlocks replays devnet blocks from a checkpoint into a fresh
// testnet/mainnet node so it starts at the correct tip height with correct state.
// blocks is the ordered slice of devnet blocks starting at height 1.
// Block 0 is created via the normal genesis flow and must already be in bc.chain.
func (bc *Blockchain) ApplyCheckpointBlocks(blocks []*types.Block) error {
	if len(blocks) == 0 {
		return nil
	}

	if len(bc.chain) == 0 {
		return fmt.Errorf("ApplyCheckpointBlocks: genesis block must be applied first")
	}

	logger.Info("ApplyCheckpointBlocks: replaying %d devnet blocks into %s",
		len(blocks), bc.chainParams.ChainName)

	for _, block := range blocks {
		// Validate chain linkage before executing.
		prev := bc.GetLatestBlock()
		if prev == nil {
			return fmt.Errorf("ApplyCheckpointBlocks: no previous block at height %d", block.GetHeight())
		}
		if block.GetPrevHash() != prev.GetHash() {
			return fmt.Errorf(
				"ApplyCheckpointBlocks: block %d parent=%s does not match tip=%s",
				block.GetHeight(), block.GetPrevHash(), prev.GetHash(),
			)
		}

		stateRoot, err := bc.ExecuteBlock(block)
		if err != nil {
			return fmt.Errorf("ApplyCheckpointBlocks: execute block %d: %w", block.GetHeight(), err)
		}
		if !bytes.Equal(block.Header.StateRoot, stateRoot) {
			logger.Warn("ApplyCheckpointBlocks: execution state root differs from checkpoint block %d (header=%x executed=%x)",
				block.GetHeight(), block.Header.StateRoot, stateRoot)
		}

		if err := bc.storage.StoreBlock(block); err != nil {
			return fmt.Errorf("ApplyCheckpointBlocks: store block %d: %w", block.GetHeight(), err)
		}

		bc.lock.Lock()
		bc.chain = append(bc.chain, block)
		bc.lock.Unlock()

		logger.Info("  applied block height=%d hash=%s", block.GetHeight(), block.GetHash())
	}

	logger.Info("✅ ApplyCheckpointBlocks: node now at height=%d", blocks[len(blocks)-1].GetHeight())
	return nil
}

// GetCurrentPhase returns the operational phase for this node based on
// chain params and vault state.
func (bc *Blockchain) GetCurrentPhase() ChainPhase {
	// Force devnet for development based on ChainID
	if bc.chainParams != nil && bc.chainParams.ChainID == 73310 {
		return PhaseDevnet
	}

	// Also check if ChainName indicates devnet
	if bc.chainParams != nil && bc.chainParams.ChainName == "Sphinx Devnet" {
		return PhaseDevnet
	}

	switch {
	case bc.chainParams.IsDevnet():
		return PhaseDevnet
	case bc.chainParams.IsTestnet():
		return PhaseTestnet
	default:
		return PhaseMainnet
	}
}

// HasCheckpoint checks if a checkpoint exists for the given address
func HasCheckpoint(address string) bool {
	path := common.GetCheckpointPath(address)
	_, err := os.Stat(path)
	return err == nil
}

// DeleteCheckpoint removes the checkpoint file for the given address
// Use with caution - this should only be used when resetting state
func DeleteCheckpoint(address string) error {
	path := common.GetCheckpointPath(address)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete checkpoint: %w", err)
	}
	return nil
}
