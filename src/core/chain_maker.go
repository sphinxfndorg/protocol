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

// ChainPhase identifies which operational phase a network is in.
type ChainPhase string

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

// ChainCheckpoint captures the state at the moment devnet finishes distribution.
// It is written to disk so testnet/mainnet nodes can bootstrap from it without
// re-running devnet.
type ChainCheckpoint struct {
	Phase           ChainPhase `json:"phase"`             // "devnet"
	GenesisHash     string     `json:"genesis_hash"`      // canonical genesis hash
	TipHeight       uint64     `json:"tip_height"`        // last devnet block height
	TipHash         string     `json:"tip_hash"`          // last devnet block hash
	VaultBalance    string     `json:"vault_balance"`     // should be "0"
	TotalSupply     string     `json:"total_supply"`      // circulating supply in nSPX
	Timestamp       string     `json:"timestamp"`         // RFC3339 when checkpoint was taken
	DistributedNSPX string     `json:"distributed_n_spx"` // total nSPX distributed
}

// checkpointPath returns the path to the checkpoint file for a node data dir.
func checkpointPath(dataDir string) string {
	return filepath.Join(dataDir, "state", "chain_checkpoint.json")
}

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

	cp := &ChainCheckpoint{
		Phase:           PhaseDevnet,
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

	path := checkpointPath(bc.storage.GetStateDir())
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("WriteChainCheckpoint: write: %w", err)
	}

	logger.Info("✅ WriteChainCheckpoint: devnet done at height=%d hash=%s vault=%s",
		cp.TipHeight, cp.TipHash, cp.VaultBalance)
	return nil
}

// LoadChainCheckpoint reads the checkpoint written by devnet.
// Returns nil if no checkpoint exists (clean start).
func LoadChainCheckpoint(dataDir string) (*ChainCheckpoint, error) {
	path := checkpointPath(filepath.Join(dataDir, "state"))
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
	switch {
	case bc.chainParams.IsDevnet():
		return PhaseDevnet
	case bc.chainParams.IsTestnet():
		return PhaseTestnet
	default:
		return PhaseMainnet
	}
}
