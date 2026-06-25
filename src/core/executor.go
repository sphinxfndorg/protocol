// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/executor.go
package core

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/sphinxorg/protocol/src/consensus"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	logger "github.com/sphinxorg/protocol/src/log"
	denom "github.com/sphinxorg/protocol/src/params/denom"
	"github.com/sphinxorg/protocol/src/pool"
)

// maxSupplyNSPX is the hard cap, expressed in nSPX, derived from the
// canonical denom.MaxSupplySPX / denom.SPX constants rather than a
// hardcoded literal. denom.MaximumSupply itself (5e9 * 1e18 = 5e27) can't
// be passed to big.NewInt directly — it overflows int64 — so we build it
// from the two factors, each of which fits comfortably in int64.
var maxSupplyNSPX = new(big.Int).Mul(
	big.NewInt(int64(denom.MaxSupplySPX)),
	big.NewInt(int64(denom.SPX)),
)

// Ensure Blockchain implements pool.BlockchainStateProvider
var _ pool.BlockchainStateProvider = (*Blockchain)(nil)

// newStateDB opens the StateDB for this blockchain node.
// This is the internal version that returns *StateDB for internal use.
func (bc *Blockchain) newStateDB() (*StateDB, error) {
	// Call the public NewStateDB which returns pool.StateDB
	stateDB, err := bc.NewStateDB()
	if err != nil {
		logger.Error("newStateDB: failed to get StateDB: %v", err)
		return nil, errors.New("failed to get internal StateDB")
	}
	// Type assert back to *StateDB for internal use
	if sdb, ok := stateDB.(*StateDB); ok {
		return sdb, nil
	}
	logger.Error("newStateDB: StateDB type assertion failed")
	return nil, errors.New("failed to get internal StateDB")
}

// IsDistributionComplete returns true when the genesis vault has been fully
// drained — i.e. every allocation has been transferred out of GenesisVaultAddress.
func (bc *Blockchain) IsDistributionComplete() bool {
	stateDB, err := bc.newStateDB()
	if err != nil {
		logger.Warn("IsDistributionComplete: cannot open stateDB: %v", err)
		return false
	}
	bal, err := stateDB.GetBalance(GenesisVaultAddress)
	if err != nil {
		logger.Warn("IsDistributionComplete: failed to get balance: %v", err)
		return false
	}
	complete := bal.Sign() == 0
	if complete {
		logger.Info("✅ IsDistributionComplete: vault %s balance = 0, distribution done", GenesisVaultAddress)
	}
	return complete
}

// TotalAllocatedNSPX returns the sum of all genesis allocations in nSPX.
func TotalAllocatedNSPX() *big.Int {
	allocs := DefaultGenesisAllocations()
	total := new(big.Int)
	for _, a := range allocs {
		if a.BalanceNSPX != nil {
			total.Add(total, a.BalanceNSPX)
		}
	}
	return total
}

// ============================================================================
// CHECKPOINT FUNCTIONS - Supply Tracking
// ============================================================================

// WriteChainCheckpoint writes the current chain state including reward tracking
func (bc *Blockchain) WriteChainCheckpoint() error {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	// ========== FIX: Read from MEMORY first, fallback to storage ==========
	// The in-memory chain is updated immediately in CommitBlock()
	// Storage may lag behind, so prioritize memory for the checkpoint
	var latestBlock *types.Block

	if len(bc.chain) > 0 {
		latestBlock = bc.chain[len(bc.chain)-1]
		logger.Info("WriteChainCheckpoint: using in-memory chain (height=%d)", latestBlock.GetHeight())
	} else {
		// Fallback to storage if memory is empty
		block, err := bc.storage.GetLatestBlock()
		if err != nil || block == nil {
			logger.Error("WriteChainCheckpoint: no blocks in chain or storage")
			return errors.New("no blocks available")
		}
		latestBlock = block
		logger.Info("WriteChainCheckpoint: using storage (height=%d)", latestBlock.GetHeight())
	}
	// =============================================================

	if latestBlock == nil {
		logger.Error("WriteChainCheckpoint: latest block is nil")
		return errors.New("latest block is nil")
	}

	// Get state from DB
	stateDB, err := bc.newStateDB()
	if err != nil {
		logger.Error("WriteChainCheckpoint: failed to open stateDB: %v", err)
		return errors.New("failed to open stateDB")
	}

	vaultBalance, err := stateDB.GetBalance(GenesisVaultAddress)
	if err != nil {
		logger.Error("WriteChainCheckpoint: failed to get vault balance: %v", err)
		return errors.New("failed to get vault balance")
	}

	totalSupply := stateDB.GetTotalSupply()
	genesisSupply := stateDB.GetGenesisSupply()
	rewardsMinted := stateDB.GetRewardsMinted()

	// Calculate max supply in nSPX (5B * 1e18)
	maxSupplyNSPX := new(big.Int).Mul(
		big.NewInt(denom.MaxSupplySPX),
		big.NewInt(denom.SPX),
	)

	// Calculate remaining supply
	remainingSupplyNSPX := new(big.Int).Sub(maxSupplyNSPX, totalSupply)
	if remainingSupplyNSPX.Sign() < 0 {
		remainingSupplyNSPX = big.NewInt(0)
	}

	// Convert to whole SPX for readability
	remainingSPX := new(big.Int).Div(remainingSupplyNSPX, big.NewInt(denom.SPX))
	mintedSPX := new(big.Int).Div(totalSupply, big.NewInt(denom.SPX))
	genesisSPX := new(big.Int).Div(genesisSupply, big.NewInt(denom.SPX))
	rewardsSPX := new(big.Int).Div(rewardsMinted, big.NewInt(denom.SPX))
	vaultSPX := new(big.Int).Div(vaultBalance, big.NewInt(denom.SPX))
	maxSPX := new(big.Int).Div(maxSupplyNSPX, big.NewInt(denom.SPX))

	// Determine if distribution is complete
	distributionComplete := vaultBalance.Sign() == 0
	distributionStatus := "pending"
	if distributionComplete {
		distributionStatus = "complete"
	}

	// Determine phase
	// Determine phase - check network type FIRST, not distribution status
	// Determine phase
	phase := string(PhaseDevnet) // default

	// Get chain name from chainParams - THIS IS THE SINGLE SOURCE OF TRUTH
	chainName := "Sphinx Devnet" // fallback default
	if bc.chainParams != nil {
		chainName = bc.chainParams.ChainName
	}

	if bc.chainParams != nil {
		if bc.chainParams.IsDevnet() {
			phase = string(PhaseDevnet)
		} else if bc.chainParams.IsTestnet() {
			phase = string(PhaseTestnet)
		} else {
			phase = string(PhaseMainnet)
		}
	} else if bc.IsDistributionComplete() {
		phase = string(PhaseMainnet)
	}

	// Get genesis hash - try storage first, then memory
	var genesisHash string
	if len(bc.chain) > 0 && bc.chain[0] != nil {
		genesisHash = bc.chain[0].GetHash()
	} else {
		// Try to get genesis from storage
		if genBlock, err := bc.storage.GetBlockByHeight(0); err == nil && genBlock != nil {
			genesisHash = genBlock.GetHash()
		} else {
			genesisHash = "unknown"
		}
	}

	// Build the checkpoint structure
	checkpoint := &ChainCheckpoint{
		Phase:       phase,
		ChainName:   chainName, // Use chainParams.ChainName
		GenesisHash: genesisHash,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),

		Supply: struct {
			Max struct {
				NSPX string `json:"nspx"`
				SPX  string `json:"spx"`
			} `json:"max"`
			Genesis struct {
				NSPX string `json:"nspx"`
				SPX  string `json:"spx"`
			} `json:"genesis"`
			Minted struct {
				NSPX string `json:"nspx"`
				SPX  string `json:"spx"`
			} `json:"minted"`
			Remaining struct {
				NSPX string `json:"nspx"`
				SPX  string `json:"spx"`
			} `json:"remaining"`
		}{
			Max: struct {
				NSPX string `json:"nspx"`
				SPX  string `json:"spx"`
			}{
				NSPX: maxSupplyNSPX.String(),
				SPX:  maxSPX.String(),
			},
			Genesis: struct {
				NSPX string `json:"nspx"`
				SPX  string `json:"spx"`
			}{
				NSPX: genesisSupply.String(),
				SPX:  genesisSPX.String(),
			},
			Minted: struct {
				NSPX string `json:"nspx"`
				SPX  string `json:"spx"`
			}{
				NSPX: totalSupply.String(),
				SPX:  mintedSPX.String(),
			},
			Remaining: struct {
				NSPX string `json:"nspx"`
				SPX  string `json:"spx"`
			}{
				NSPX: remainingSupplyNSPX.String(),
				SPX:  remainingSPX.String(),
			},
		},

		Vault: struct {
			Address     string `json:"address"`
			BalanceNSPX string `json:"balance_nspx"`
			BalanceSPX  string `json:"balance_spx"`
		}{
			Address:     GenesisVaultAddress,
			BalanceNSPX: vaultBalance.String(),
			BalanceSPX:  vaultSPX.String(),
		},

		Rewards: struct {
			MintedNSPX string `json:"minted_nspx"`
			MintedSPX  string `json:"minted_spx"`
		}{
			MintedNSPX: rewardsMinted.String(),
			MintedSPX:  rewardsSPX.String(),
		},

		Distribution: struct {
			Status            string `json:"status"`
			TotalAllocations  int    `json:"total_allocations"`
			TotalAllocatedSPX string `json:"total_allocated_spx"`
		}{
			Status:            distributionStatus,
			TotalAllocations:  len(DefaultGenesisAllocations()),
			TotalAllocatedSPX: genesisSPX.String(),
		},

		Tip: struct {
			Height uint64 `json:"height"`
			Hash   string `json:"hash"`
		}{
			Height: latestBlock.GetHeight(),
			Hash:   latestBlock.GetHash(),
		},
	}

	// Write to file using the correct path
	checkpointPath := filepath.Join(bc.storage.GetStateDir(), "chain_checkpoint.json")

	if err := writeCheckpointFile(checkpointPath, checkpoint); err != nil {
		logger.Error("WriteChainCheckpoint: failed to write checkpoint: %v", err)
		return errors.New("failed to write checkpoint")
	}

	// Log checkpoint info with detailed breakdown
	logger.Info("✅ CHECKPOINT: %s at height=%d", phase, latestBlock.GetHeight())
	logger.Info("📊 SUPPLY BREAKDOWN:")
	logger.Info("   Genesis Allocation: %s SPX (%s nSPX)",
		genesisSPX.String(), genesisSupply.String())
	logger.Info("   Rewards Minted:     %s SPX (%s nSPX)",
		rewardsSPX.String(), rewardsMinted.String())
	logger.Info("   Total Minted:       %s SPX (%s nSPX)",
		mintedSPX.String(), totalSupply.String())
	logger.Info("   Remaining Supply:   %s SPX (%s nSPX)",
		remainingSPX.String(), remainingSupplyNSPX.String())
	logger.Info("   Vault Balance:      %s nSPX (%s SPX)", vaultBalance.String(), vaultSPX.String())
	logger.Info("   Max Supply:         %s SPX", maxSPX.String())
	logger.Info("   Distribution:       %s (allocations: %d)", distributionStatus, len(DefaultGenesisAllocations()))
	logger.Info("   Checkpoint saved to: %s", checkpointPath)

	return nil
}

// GetRemainingSupplySPX returns the remaining SPX to be mined
func (bc *Blockchain) GetRemainingSupplySPX() (*big.Int, error) {
	stateDB, err := bc.newStateDB()
	if err != nil {
		logger.Error("GetRemainingSupplySPX: failed to open stateDB: %v", err)
		return nil, errors.New("failed to open stateDB")
	}

	totalSupply := stateDB.GetTotalSupply()

	maxSupplyNSPX := new(big.Int).Mul(
		big.NewInt(denom.MaxSupplySPX),
		big.NewInt(denom.SPX),
	)

	remainingNSPX := new(big.Int).Sub(maxSupplyNSPX, totalSupply)
	if remainingNSPX.Sign() < 0 {
		remainingNSPX = big.NewInt(0)
	}

	return new(big.Int).Div(remainingNSPX, big.NewInt(denom.SPX)), nil
}

// GetMintedSPX returns the total minted SPX so far
func (bc *Blockchain) GetMintedSPX() (*big.Int, error) {
	stateDB, err := bc.newStateDB()
	if err != nil {
		logger.Error("GetMintedSPX: failed to open stateDB: %v", err)
		return nil, errors.New("failed to open stateDB")
	}

	totalSupply := stateDB.GetTotalSupply()
	return new(big.Int).Div(totalSupply, big.NewInt(denom.SPX)), nil
}

// GetSupplyStatus returns a summary of the supply status
// GetSupplyStatus returns a comprehensive supply status breakdown
func (bc *Blockchain) GetSupplyStatus() (map[string]interface{}, error) {
	stateDB, err := bc.newStateDB()
	if err != nil {
		logger.Error("GetSupplyStatus: failed to open stateDB: %v", err)
		return nil, errors.New("failed to open stateDB")
	}

	totalSupply := stateDB.GetTotalSupply()
	genesisSupply := stateDB.GetGenesisSupply()
	rewardsMinted := stateDB.GetRewardsMinted()
	vaultBalance, err := stateDB.GetBalance(GenesisVaultAddress)
	if err != nil {
		logger.Error("GetSupplyStatus: failed to get vault balance: %v", err)
		return nil, errors.New("failed to get vault balance")
	}

	maxSupplyNSPX := new(big.Int).Mul(
		big.NewInt(denom.MaxSupplySPX),
		big.NewInt(denom.SPX),
	)

	remainingNSPX := new(big.Int).Sub(maxSupplyNSPX, totalSupply)
	if remainingNSPX.Sign() < 0 {
		remainingNSPX = big.NewInt(0)
	}

	distributedNSPX := new(big.Int).Sub(totalSupply, vaultBalance)
	if distributedNSPX.Sign() < 0 {
		distributedNSPX = big.NewInt(0)
	}

	maxSPX := new(big.Int).Div(maxSupplyNSPX, big.NewInt(denom.SPX))
	mintedSPX := new(big.Int).Div(totalSupply, big.NewInt(denom.SPX))
	genesisSPX := new(big.Int).Div(genesisSupply, big.NewInt(denom.SPX))
	rewardsSPX := new(big.Int).Div(rewardsMinted, big.NewInt(denom.SPX))
	remainingSPX := new(big.Int).Div(remainingNSPX, big.NewInt(denom.SPX))
	distributedSPX := new(big.Int).Div(distributedNSPX, big.NewInt(denom.SPX))

	// Calculate percentages using the helper function
	totalPct := calculateSupplyPercent(mintedSPX, maxSPX)
	rewardPct := calculateSupplyPercent(rewardsSPX, maxSPX)

	return map[string]interface{}{
		"max_supply_spx":           maxSPX.String(),
		"genesis_supply_spx":       genesisSPX.String(),
		"genesis_supply_nspx":      genesisSupply.String(),
		"rewards_minted_spx":       rewardsSPX.String(),
		"rewards_minted_nspx":      rewardsMinted.String(),
		"minted_spx":               mintedSPX.String(),
		"minted_nspx":              totalSupply.String(),
		"remaining_supply_spx":     remainingSPX.String(),
		"remaining_supply_nspx":    remainingNSPX.String(),
		"vault_balance_nspx":       vaultBalance.String(),
		"distributed_spx":          distributedSPX.String(),
		"distributed_nspx":         distributedNSPX.String(),
		"supply_used_percent":      totalPct,
		"rewards_percent":          rewardPct,
		"blocks_mined_rewards":     strconv.FormatUint(bc.GetBlockCount(), 10),
		"is_distribution_complete": bc.IsDistributionComplete(),
	}, nil
}

// calculateSupplyPercent calculates percentage as string
func calculateSupplyPercent(part, total *big.Int) string {
	if total.Sign() == 0 {
		return "0.00"
	}
	pct := new(big.Float).Quo(
		new(big.Float).SetInt(part),
		new(big.Float).SetInt(total),
	)
	pct.Mul(pct, big.NewFloat(100))
	result, _ := pct.Float64()
	// Using strconv for formatting to avoid fmt
	return strconv.FormatFloat(result, 'f', 2, 64)
}

// writeCheckpointFile writes a checkpoint to disk
func writeCheckpointFile(path string, checkpoint *ChainCheckpoint) error {
	data, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		logger.Error("writeCheckpointFile: failed to marshal checkpoint: %v", err)
		return errors.New("failed to marshal checkpoint")
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		logger.Error("writeCheckpointFile: failed to create checkpoint directory: %v", err)
		return errors.New("failed to create checkpoint directory")
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		logger.Error("writeCheckpointFile: failed to write checkpoint: %v", err)
		return errors.New("failed to write checkpoint")
	}

	return nil
}

// applyTransactions applies every transaction in block to stateDB,
// enforcing nonce ordering, balance sufficiency, and gas fee collection.
func (bc *Blockchain) applyTransactions(block *types.Block, stateDB *StateDB) error {
	proposerID := block.Header.ProposerID

	for i, tx := range block.Body.TxsList {
		// ========== FIX: Skip genesis "mint" transactions on block 0 ==========
		// Block 0's genesis transactions with Sender: "genesis" are NOT processed
		// as mints. Instead, mintBlockReward funds the vault with the total
		// allocation amount. Block 1 then distributes from the vault to each
		// allocation address using normal balance checks.
		//
		// This implements the proper "vault and distribute" model:
		//   - Block 0: Vault receives total supply (mintBlockReward)
		//   - Block 1: Vault distributes to allocation addresses (applyTransactions)
		if tx.Sender == "genesis" {
			logger.Info("executor: tx[%d] genesis → skipping (vault will be funded via mintBlockReward)", i)
			continue
		}
		// ====================================================================

		// ========== FIX: Process GenesisVaultAddress as normal sender ==========
		// Block 1 distribution transactions use GenesisVaultAddress as sender.
		// The vault has balance from block 0's mintBlockReward, so normal
		// balance checks apply. This is the correct "vault and distribute" model.
		// After block 1, IsDistributionComplete() returns true.
		// ========================================================================

		expected, err := stateDB.GetNonce(tx.Sender)
		if err != nil {
			logger.Error("applyTransactions: tx[%d] %s: failed to get nonce: %v", i, tx.ID, err)
			return errors.New("failed to get nonce")
		}
		if tx.Nonce != expected {
			logger.Error("applyTransactions: tx[%d] %s: bad nonce: got %d want %d",
				i, tx.ID, tx.Nonce, expected)
			return errors.New("bad nonce")
		}

		gasFee := tx.GetGasFee()
		totalCost := new(big.Int).Add(tx.Amount, gasFee)

		bal, err := stateDB.GetBalance(tx.Sender)
		if err != nil {
			logger.Error("applyTransactions: tx[%d] %s: failed to get balance: %v", i, tx.ID, err)
			return errors.New("failed to get balance")
		}
		if bal.Cmp(totalCost) < 0 {
			logger.Error("applyTransactions: tx[%d] %s: %s has %s nSPX, needs %s nSPX",
				i, tx.ID, tx.Sender, bal.String(), totalCost.String())
			return errors.New("insufficient balance")
		}

		if err := stateDB.SubBalance(tx.Sender, totalCost); err != nil {
			logger.Error("applyTransactions: tx[%d] SubBalance: %v", i, err)
			return errors.New("failed to subtract balance")
		}
		stateDB.AddBalance(tx.Receiver, tx.Amount)

		if proposerID != "" && gasFee.Sign() > 0 {
			stateDB.AddBalance(proposerID, gasFee)
		}

		stateDB.IncrementNonce(tx.Sender)
		logger.Info("executor: tx[%d] %s → %s %s nSPX (gas %s nSPX) ✓",
			i, tx.Sender, tx.Receiver, tx.Amount.String(), gasFee.String())
	}
	return nil
}

// mintBlockReward issues BaseBlockReward to the block proposer, respecting
// the hard 5 billion SPX supply cap.
// mintBlockReward issues block rewards, tracking genesis supply and rewards separately
func (bc *Blockchain) mintBlockReward(block *types.Block, stateDB *StateDB) {
	if bc.chainParams == nil {
		return
	}

	proposerID := block.Header.ProposerID
	if proposerID == "" {
		logger.Warn("mintBlockReward: no proposer_id on block %d", block.GetHeight())
		return
	}

	if block.GetHeight() == 0 {
		// ========== GENESIS BLOCK: Fund the vault and track genesis supply ==========
		totalAllocated := TotalAllocatedNSPX()
		if totalAllocated.Sign() > 0 {
			// Set the vault balance directly
			stateDB.SetBalance(GenesisVaultAddress, totalAllocated)
			stateDB.IncrementTotalSupply(totalAllocated)

			// NEW: Track genesis supply separately
			stateDB.SetGenesisSupply(totalAllocated)
			// Initial rewards minted is 0 at genesis
			stateDB.IncrementRewardsMinted(big.NewInt(0))

			totalSPX := new(big.Int).Div(totalAllocated, big.NewInt(1e18))
			logger.Info("✅ GENESIS: vault %s funded with %s nSPX (%s SPX)",
				GenesisVaultAddress, totalAllocated.String(), totalSPX.String())
			logger.Info("📊 GENESIS SUPPLY: %s nSPX", totalAllocated.String())
		} else {
			logger.Info("mintBlockReward: no allocations to fund vault (test mode)")
		}
		return
	}

	if block.GetHeight() == 1 {
		logger.Info("mintBlockReward: skipping reward for distribution block 1")
		return
	}

	// ========== Blocks 2+ get normal block rewards ==========
	reward := new(big.Int).Set(bc.chainParams.BaseBlockReward)
	if reward.Sign() <= 0 {
		return
	}

	// Check supply cap
	current := stateDB.GetTotalSupply()
	if new(big.Int).Add(current, reward).Cmp(maxSupplyNSPX) > 0 {
		remaining := new(big.Int).Sub(maxSupplyNSPX, current)
		if remaining.Sign() <= 0 {
			logger.Info("mintBlockReward: supply cap reached, block %d", block.GetHeight())
			return
		}
		reward = remaining
	}

	// Apply reward
	stateDB.AddBalance(proposerID, reward)
	stateDB.IncrementTotalSupply(reward)

	// NEW: Track rewards minted separately
	stateDB.IncrementRewardsMinted(reward)

	// Log reward with detailed metrics
	rewardSPX := new(big.Float).Quo(
		new(big.Float).SetInt(reward),
		new(big.Float).SetInt(big.NewInt(1e18)),
	)

	totalMinted := stateDB.GetTotalSupply()
	genesisSupply := stateDB.GetGenesisSupply()
	rewardsMinted := stateDB.GetRewardsMinted()
	remainingNSPX := new(big.Int).Sub(maxSupplyNSPX, totalMinted)

	logger.Info("✅ REWARD: %.6f SPX → %s (block %d)", rewardSPX, proposerID, block.GetHeight())
	logger.Info("📊 SUPPLY: Total=%s nSPX, Genesis=%s nSPX, Rewards=%s nSPX, Remaining=%s nSPX",
		totalMinted.String(), genesisSupply.String(), rewardsMinted.String(), remainingNSPX.String())
}

// ExecuteBlock is called from CommitBlock.
func (bc *Blockchain) ExecuteBlock(block *types.Block) ([]byte, error) {
	stateDB, err := bc.newStateDB()
	if err != nil {
		logger.Error("ExecuteBlock: failed to open stateDB: %v", err)
		return nil, errors.New("failed to open stateDB")
	}

	if err := bc.applyTransactions(block, stateDB); err != nil {
		logger.Error("ExecuteBlock: applyTransactions failed: %v", err)
		return nil, errors.New("applyTransactions failed")
	}

	bc.mintBlockReward(block, stateDB)

	stateRoot, err := stateDB.Commit()
	if err != nil {
		logger.Error("ExecuteBlock: commit failed: %v", err)
		return nil, errors.New("commit failed")
	}
	return stateRoot, nil
}

// ExecuteGenesisBlock runs ExecuteBlock on block 0.
func (bc *Blockchain) ExecuteGenesisBlock() error {
	bc.lock.RLock()
	if len(bc.chain) == 0 || bc.chain[0] == nil {
		bc.lock.RUnlock()
		logger.Error("ExecuteGenesisBlock: genesis block not in memory")
		return errors.New("genesis block not in memory")
	}
	genesisBlock := bc.chain[0]
	bc.lock.RUnlock()

	stateDB, err := bc.newStateDB()
	if err != nil {
		logger.Error("ExecuteGenesisBlock: failed to open stateDB: %v", err)
		return errors.New("failed to open stateDB")
	}
	bal, err := stateDB.GetBalance(GenesisVaultAddress)
	if err != nil {
		logger.Error("ExecuteGenesisBlock: failed to get balance: %v", err)
		return errors.New("failed to get balance")
	}
	if bal.Sign() > 0 {
		logger.Info("ExecuteGenesisBlock: vault already funded, skipping")
		return nil
	}

	if _, err := bc.ExecuteBlock(genesisBlock); err != nil {
		logger.Error("ExecuteGenesisBlock: ExecuteBlock failed: %v", err)
		return errors.New("ExecuteBlock failed")
	}

	logger.Info("✅ ExecuteGenesisBlock: vault %s funded", GenesisVaultAddress)
	return nil
}

// UpdateValidatorStakesFromState updates the consensus validator set with
// stakes from the blockchain state after distribution is complete.
func (bc *Blockchain) UpdateValidatorStakesFromState(validatorIDs []string, validatorSet interface{}) error {
	if validatorSet == nil {
		logger.Error("UpdateValidatorStakesFromState: validatorSet is nil")
		return errors.New("validatorSet is nil")
	}

	stateDB, err := bc.newStateDB()
	if err != nil {
		logger.Error("UpdateValidatorStakesFromState: failed to open stateDB: %v", err)
		return errors.New("failed to open stateDB")
	}

	type stakeUpdater interface {
		UpdateStake(id string, stakeSPX uint64) error
	}

	updater, ok := validatorSet.(stakeUpdater)
	if !ok {
		logger.Error("UpdateValidatorStakesFromState: validatorSet does not support UpdateStake")
		return errors.New("validatorSet does not support UpdateStake")
	}

	for _, vid := range validatorIDs {
		address := vid
		balanceNSPX, err := stateDB.GetBalance(address)
		if err != nil {
			logger.Warn("Failed to get balance for validator %s: %v", vid, err)
			continue
		}
		if balanceNSPX == nil || balanceNSPX.Sign() == 0 {
			logger.Warn("Validator %s has zero balance, using minimum stake", vid)
			continue
		}

		stakeSPX := new(big.Int).Div(balanceNSPX, big.NewInt(1e18))
		if err := updater.UpdateStake(vid, uint64(stakeSPX.Int64())); err != nil {
			logger.Warn("Failed to update stake for %s: %v", vid, err)
		} else {
			logger.Info("✅ Updated validator %s stake to %d SPX", vid, stakeSPX)
		}
	}

	return nil
}

// GetCheckpointMessage returns a CheckpointMessage for the current chain state
func (bc *Blockchain) GetCheckpointMessage() (*consensus.CheckpointMessage, error) {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	if len(bc.chain) == 0 {
		logger.Error("GetCheckpointMessage: no blocks in chain")
		return nil, errors.New("no blocks in chain")
	}

	stateDB, err := bc.newStateDB()
	if err != nil {
		logger.Error("GetCheckpointMessage: failed to open stateDB: %v", err)
		return nil, errors.New("failed to open stateDB")
	}

	vaultBalance, err := stateDB.GetBalance(GenesisVaultAddress)
	if err != nil {
		logger.Error("GetCheckpointMessage: failed to get vault balance: %v", err)
		return nil, errors.New("failed to get vault balance")
	}

	totalSupply := stateDB.GetTotalSupply()
	genesisSupply := stateDB.GetGenesisSupply()
	rewardsMinted := stateDB.GetRewardsMinted()

	maxSupplyNSPX := new(big.Int).Mul(
		big.NewInt(denom.MaxSupplySPX),
		big.NewInt(denom.SPX),
	)

	remainingSupplyNSPX := new(big.Int).Sub(maxSupplyNSPX, totalSupply)
	if remainingSupplyNSPX.Sign() < 0 {
		remainingSupplyNSPX = big.NewInt(0)
	}

	latest := bc.chain[len(bc.chain)-1]
	phase := "devnet"
	if bc.chainParams != nil {
		if bc.chainParams.IsDevnet() {
			phase = "devnet"
		} else if bc.chainParams.IsTestnet() {
			phase = "testnet"
		} else if bc.IsDistributionComplete() {
			phase = "mainnet"
		}
	} else if bc.IsDistributionComplete() {
		phase = "mainnet"
	}

	mintedSPX := new(big.Int).Div(totalSupply, big.NewInt(1e18))

	return &consensus.CheckpointMessage{
		GenesisHash:     bc.chain[0].GetHash(),
		TipHeight:       latest.GetHeight(),
		TipHash:         latest.GetHash(),
		TotalSupply:     totalSupply.String(),
		GenesisSupply:   genesisSupply.String(),
		RewardsMinted:   rewardsMinted.String(),
		RemainingSupply: remainingSupplyNSPX.String(),
		VaultBalance:    vaultBalance.String(),
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Phase:           phase,
		MintedSPX:       mintedSPX.String(), // Make sure this is included
	}, nil
}

// ApplyCheckpointFromPeer applies a checkpoint received from a peer
func (bc *Blockchain) ApplyCheckpointFromPeer(cp *consensus.CheckpointMessage) error {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	if len(bc.chain) == 0 {
		logger.Error("ApplyCheckpointFromPeer: no chain to apply checkpoint to")
		return errors.New("no chain to apply checkpoint to")
	}

	// Verify genesis hash matches
	if cp.GenesisHash != bc.chain[0].GetHash() {
		logger.Error("ApplyCheckpointFromPeer: genesis hash mismatch: peer=%s, local=%s",
			cp.GenesisHash, bc.chain[0].GetHash())
		return errors.New("genesis hash mismatch")
	}

	// Check if peer is ahead
	latest := bc.chain[len(bc.chain)-1]
	if cp.TipHeight <= latest.GetHeight() {
		// Peer is not ahead, nothing to sync
		return nil
	}

	logger.Info("ApplyCheckpointFromPeer: peer is ahead (local=%d, peer=%d, supply=%s SPX)",
		latest.GetHeight(), cp.TipHeight, cp.MintedSPX)

	// Store checkpoint for later sync
	cpData, err := json.Marshal(cp)
	if err != nil {
		logger.Error("ApplyCheckpointFromPeer: failed to marshal checkpoint: %v", err)
		return errors.New("failed to marshal checkpoint")
	}

	// Store in database for recovery
	db, err := bc.storage.GetDB()
	if err != nil {
		logger.Warn("Failed to get database: %v", err)
	} else if db != nil {
		// FIX: db.Put expects (key string, value []byte)
		if err := db.Put("peer_checkpoint", cpData); err != nil { // ← Use string key, not []byte
			logger.Warn("Failed to store peer checkpoint: %v", err)
		}
	}

	return nil
}

// SyncCheckpoints synchronizes checkpoints with a peer
func (bc *Blockchain) SyncCheckpoints(peerAddress string) error {
	if bc.rpcCaller == nil {
		logger.Error("SyncCheckpoints: RPC caller not set - cannot sync checkpoints")
		return errors.New("RPC caller not set - cannot sync checkpoints")
	}

	cp, err := bc.rpcCaller.GetCheckpoint(peerAddress)
	if err != nil {
		logger.Error("SyncCheckpoints: failed to get checkpoint from peer: %v", err)
		return errors.New("failed to get checkpoint from peer")
	}

	return bc.ApplyCheckpointFromPeer(cp)
}

// RPCCaller defines the interface for making RPC calls to peers
type RPCCaller interface {
	GetCheckpoint(peerAddress string) (*consensus.CheckpointMessage, error)
	GetSupplyStatus(peerAddress string) (map[string]interface{}, error)
}

// SetRPCCaller sets the RPC caller for the blockchain
func (bc *Blockchain) SetRPCCaller(caller RPCCaller) {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	bc.rpcCaller = caller
}

// GetRPCCaller returns the current RPC caller
func (bc *Blockchain) GetRPCCaller() RPCCaller {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.rpcCaller
}
