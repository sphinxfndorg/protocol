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

// go/src/core/chain_maker.go
package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sphinxorg/protocol/src/common"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	logger "github.com/sphinxorg/protocol/src/log"
)

const (
	// PhaseDevnet is the bootstrap phase: the vault is being drained via
	// distribution blocks.  The chain must NOT be promoted until
	// IsDistributionComplete() returns true.
	PhaseDevnet ChainPhase = "devnet"

	// PhaseTestnet is the public test phase.  It continues the devnet chain
	// from wherever devnet stopped — same genesis, same block history, higher
	// ChainID, different ports.
	PhaseTestnet ChainPhase = "testnet"

	// PhaseMainnet is production.  Same ancestry as devnet and testnet.
	PhaseMainnet ChainPhase = "mainnet"
)

// WriteChainCheckpoint serialises the current chain tip and vault state to disk.
// Call this from the devnet node manager once IsDistributionComplete() == true.
func (bc *Blockchain) WriteChainCheckpoint() error {
	if bc.chainParams == nil {
		return fmt.Errorf("WriteChainCheckpoint: chainParams not initialised")
	}

	tip := bc.GetLatestBlock()
	if tip == nil {
		return fmt.Errorf("WriteChainCheckpoint: no latest block")
	}

	stateDB, err := bc.newStateDB()
	if err != nil {
		return fmt.Errorf("WriteChainCheckpoint: %w", err)
	}

	vaultBal := stateDB.GetBalance(GenesisVaultAddress)
	totalSupply := stateDB.GetTotalSupply()

	// ── FIX: derive phase from actual chain params, not a hardcoded constant ──
	currentPhase := bc.GetCurrentPhase()
	// ─────────────────────────────────────────────────────────────────────────

	cp := &ChainCheckpoint{
		Phase:           currentPhase, // was: PhaseDevnet (hardcoded)
		GenesisHash:     GetGenesisHash(),
		TipHeight:       tip.GetHeight(),
		TipHash:         tip.GetHash(),
		VaultBalance:    vaultBal.String(),
		TotalSupply:     totalSupply.String(),
		Timestamp:       common.GetTimeService().GetCurrentTimeInfo().ISOUTC,
		DistributedNSPX: TotalAllocatedNSPX().String(),
	}

	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("WriteChainCheckpoint: marshal: %w", err)
	}

	stateDir := bc.storage.GetStateDir()
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return fmt.Errorf("WriteChainCheckpoint: create state directory: %w", err)
	}

	path := filepath.Join(stateDir, "chain_checkpoint.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("WriteChainCheckpoint: write: %w", err)
	}

	logger.Info("✅ WriteChainCheckpoint: %s done at height=%d hash=%s vault=%s",
		currentPhase, cp.TipHeight, cp.TipHash, cp.VaultBalance)
	logger.Info("   Checkpoint saved to: %s", path)
	return nil
}

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
	if cp.VaultBalance != "0" {
		return fmt.Errorf(
			"chain continuity violation: checkpoint vault balance=%s (want 0) — "+
				"devnet distribution was not complete when checkpoint was taken",
			cp.VaultBalance,
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
		block.Header.StateRoot = stateRoot
		block.FinalizeHash()

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
