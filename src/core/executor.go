// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/executor.go
package core

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/consensus"
	logger "github.com/sphinxfndorg/protocol/src/console"
	"github.com/sphinxfndorg/protocol/src/contracts"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
	"github.com/sphinxfndorg/protocol/src/policy"
	"github.com/sphinxfndorg/protocol/src/pool"
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

// rewardMapMu guards validatorRewardMap independently of bc.lock.
//
// This is deliberately a package-level lock rather than a bc.lock field,
// so the fix doesn't require editing wherever `type Blockchain struct` is
// declared. ValidatorRewardAddress is reached from CreateBlock's call chain
// (CreateBlock -> previewStateRoot -> mintBlockReward -> ValidatorRewardAddress)
// while CreateBlock still holds bc.lock.Lock(). sync.RWMutex is not
// reentrant, so RLock()'ing bc.lock again on the same goroutine would
// self-deadlock the leader's proposal goroutine forever. Each node runs as
// its own process with its own Blockchain instance, so a package-level
// mutex here is equivalent to a per-instance one.
var rewardMapMu sync.RWMutex

// uiProgress is the optional animated-terminal dashboard that CreateBlock
// reports to (block production started/completed/failed, plus the merkle
// root / state root / nonce sub-steps in between).
//
// This is a package-level var rather than a bc field for the same reason
// as rewardMapMu above: it avoids editing wherever `type Blockchain
// struct` is declared. The dashboard itself is constructed once in
// bind.StartNode (package logger, *logger.BlockchainProgress) and crosses
// the bind -> core package boundary via SetUIProgress. Each node runs as
// its own process with one Blockchain instance, so a package-level var
// here is equivalent to a per-instance field in practice.
var (
	uiProgressMu sync.RWMutex
	uiProgress   *logger.BlockchainProgress
)

// SetUIProgress registers the dashboard CreateBlock reports to. Call once
// during node startup (see bind.StartNode); passing nil disables the
// animated feedback and CreateBlock falls back to its existing plain-text
// logger.Info calls only.
func SetUIProgress(bp *logger.BlockchainProgress) {
	uiProgressMu.Lock()
	defer uiProgressMu.Unlock()
	uiProgress = bp
}

// currentUIProgress returns the registered dashboard, or nil if none has
// been set (e.g. in tests, or tooling that never calls SetUIProgress).
func currentUIProgress() *logger.BlockchainProgress {
	uiProgressMu.RLock()
	defer uiProgressMu.RUnlock()
	return uiProgress
}

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
// funded AND fully drained — i.e. every allocation has been transferred out
// of GenesisVaultAddress.
//
// FIX: previously this only checked bal.Sign() == 0, which is trivially true
// before ExecuteGenesisBlock ever runs (an unfunded vault also has a zero
// balance). That false positive let downstream code believe distribution
// had completed when in fact nothing had ever been funded or distributed,
// which is how every allocation — including validator stake addresses —
// ended up at zero. Requiring genesisSupply > 0 first ensures "complete"
// only means "funded, then drained", not "never funded".
func (bc *Blockchain) IsDistributionComplete() bool {
	stateDB, err := bc.newStateDB()
	if err != nil {
		logger.Warn("IsDistributionComplete: cannot open stateDB: %v", err)
		return false
	}
	genesisSupply := stateDB.GetGenesisSupply()
	if genesisSupply == nil || genesisSupply.Sign() == 0 {
		logger.Warn("IsDistributionComplete: genesis vault has not been funded yet")
		return false
	}
	bal, err := stateDB.GetBalance(GenesisVaultAddress)
	if err != nil {
		logger.Warn("IsDistributionComplete: failed to get balance: %v", err)
		return false
	}
	complete := bal.Sign() == 0
	if complete {
		logger.Info("SUCCESS IsDistributionComplete: vault %s funded with %s nSPX and fully drained, distribution done",
			GenesisVaultAddress, genesisSupply.String())
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

	// Burn accounting: the DEAD address balance is the single auditable burn
	// total (fee burns + block-reward burns + manual user burns). Circulating
	// supply is the minted total minus that permanently unspendable balance.
	burnedNSPX, err := stateDB.GetBalance(common.CanonicalAddress(common.DefaultBurnAddress))
	if err != nil || burnedNSPX == nil {
		burnedNSPX = big.NewInt(0)
	}
	burnedSPX := new(big.Int).Div(burnedNSPX, big.NewInt(denom.SPX))
	circulatingNSPX := new(big.Int).Sub(totalSupply, burnedNSPX)
	if circulatingNSPX.Sign() < 0 {
		circulatingNSPX = big.NewInt(0)
	}
	circulatingSPX := new(big.Int).Div(circulatingNSPX, big.NewInt(denom.SPX))
	policy := bc.ActivePolicy()
	feeBurnBPS := policy.BurnFeeBPS
	rewardBurnBPS := policy.BlockRewardBurnBPS

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
		// Observability-only checkpoint timestamp derived from the chain tip,
		// not wall-clock time, to avoid making checkpoint contents
		// environment-dependent.
		Timestamp: time.Unix(latestBlock.Header.Timestamp, 0).UTC().Format(time.RFC3339),

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

		Burn: struct {
			Address         string `json:"address"`
			BurnedNSPX      string `json:"burned_nspx"`
			BurnedSPX       string `json:"burned_spx"`
			CirculatingNSPX string `json:"circulating_nspx"`
			CirculatingSPX  string `json:"circulating_spx"`
			FeeBurnBPS      uint64 `json:"fee_burn_bps"`
			RewardBurnBPS   uint64 `json:"reward_burn_bps"`
		}{
			Address:         common.DefaultBurnAddress,
			BurnedNSPX:      burnedNSPX.String(),
			BurnedSPX:       burnedSPX.String(),
			CirculatingNSPX: circulatingNSPX.String(),
			CirculatingSPX:  circulatingSPX.String(),
			FeeBurnBPS:      feeBurnBPS,
			RewardBurnBPS:   rewardBurnBPS,
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
	logger.Info("SUCCESS CHECKPOINT: %s at height=%d", phase, latestBlock.GetHeight())
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
	logger.Info("   Burned (DEAD):      %s SPX (%s nSPX) — fee %d bps + reward %d bps",
		burnedSPX.String(), burnedNSPX.String(), feeBurnBPS, rewardBurnBPS)
	logger.Info("   Circulating:        %s SPX (%s nSPX)",
		circulatingSPX.String(), circulatingNSPX.String())
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

	// Burned supply is the DEAD-address balance — the single auditable burn
	// total across fee burns, block-reward burns, and manual user burns.
	// Read it directly (not via GetBurnedBalance, which would reopen stateDB)
	// so this stays a single consistent snapshot.
	burnedNSPX, err := stateDB.GetBalance(common.CanonicalAddress(common.DefaultBurnAddress))
	if err != nil || burnedNSPX == nil {
		burnedNSPX = big.NewInt(0)
	}
	burnedSPX := new(big.Int).Div(burnedNSPX, big.NewInt(denom.SPX))
	circulatingNSPX := new(big.Int).Sub(totalSupply, burnedNSPX)
	if circulatingNSPX.Sign() < 0 {
		circulatingNSPX = big.NewInt(0)
	}
	circulatingSPX := new(big.Int).Div(circulatingNSPX, big.NewInt(denom.SPX))

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
		"burned_nspx":              burnedNSPX.String(),
		"burned_spx":               burnedSPX.String(),
		"circulating_nspx":         circulatingNSPX.String(),
		"circulating_spx":          circulatingSPX.String(),
		"burn_address":             common.DefaultBurnAddress,
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

	// Accumulate gas used across all transactions in this block.
	// GasUsed is set to 0 when the block is created (CreateBlock) and
	// updated here so the explorer and other consumers see the real total.
	var gasUsedAcc *big.Int

	for i, tx := range block.Body.TxsList {
		if tx == nil || tx.Amount == nil {
			return fmt.Errorf("transaction %d is missing amount", i)
		}
		// Accumulate gas used for this transaction.
		if tx.GasLimit != nil {
			if gasUsedAcc == nil {
				gasUsedAcc = new(big.Int)
			}
			gasUsedAcc.Add(gasUsedAcc, tx.GasLimit)
		}

		// Genesis (block 0) distribution transactions have
		// Sender: GenesisVaultAddress and are processed here as normal
		// transfers, same as any other block. ExecuteBlock funds the vault
		// via mintBlockReward BEFORE calling applyTransactions on block 0,
		// so the vault already has balance to cover these by the time this
		// loop runs. There is no separate "block 1" distribution step —
		// funding and distribution both happen while executing block 0.
		// After that, IsDistributionComplete() returns true.

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

		// Transfer the amount to recipient, then deduct gas fee from sender.
		// Both operations are buffered in s.pending and only flushed on Commit,
		// so an abort before Commit leaves no partial state.
		// Resolve the value destination. A contract call pays its contract; a
		// deployment pays the address the contract will occupy (derived exactly
		// as contracts.Deploy derives it); a plain transaction pays Receiver.
		recipient := tx.Receiver
		switch {
		case tx.ToContract != "":
			recipient = tx.ToContract
		case tx.IsContractDeployment():
			recipient = contracts.ContractAddress(tx.Sender, tx.Nonce, tx.Code)
		}
		// A contract deployment or value-less contract call (list / cancel /
		// revoke_license) legitimately carries zero value. StateDB.Transfer
		// requires a strictly positive amount and non-empty addresses, so the
		// only correct action for a zero-value tx is to move nothing at all —
		// transfer(_, _, 0) is a no-op by definition. Skipping it is what makes
		// deploys and zero-value calls executable; gas is still charged below.
		if tx.Amount.Sign() > 0 {
			if err := stateDB.Transfer(tx.Sender, recipient, tx.Amount); err != nil {
				logger.Error("applyTransactions: tx[%d] Transfer: %v", i, err)
				return errors.New("failed to transfer balance")
			}
		}
		if gasFee.Sign() > 0 {
			if err := stateDB.SubBalance(tx.Sender, gasFee); err != nil {
				logger.Error("applyTransactions: tx[%d] SubBalance(gas): %v", i, err)
				return errors.New("failed to deduct gas fee")
			}
		}

		if err := bc.executeContractTransaction(tx, stateDB, block.GetHeight()); err != nil {
			return fmt.Errorf("contract execution for tx[%d]: %w", i, err)
		}

		if gasFee.Sign() > 0 {
			// Fee amounts and their allocation are policy-defined. Core only
			// applies the deterministic allocation to consensus-owned accounts.
			// The burn slice relocates already-circulating nSPX to the
			// protocol burn (DEAD) address so DEAD's balance is the single
			// auditable source of burned supply (fees, slashing, rewards).
			// The burn rate is the usage-responsive per-block rate rolled
			// from the previous finalized block's committed gas — the
			// mint-side BlockRewardBurnBPS split is unaffected by it.
			burnBPS := stateDB.GetBurnFeeBPS(bc.ActivePolicy().BurnFeeBPS)
			distribution := bc.ActivePolicy().DistributeFeesWithBurnBPS(gasFee, burnBPS)
			if distribution.Validators.Sign() > 0 {
				gasAddr := TreasuryFeePoolAddress
				// A valid ordinary block has a proposer. On malformed historical
				// blocks, preserve accounting by routing this share to treasury
				// rather than silently losing it.
				if proposerID != "" {
					gasAddr = bc.ValidatorRewardAddress(proposerID)
				}
				if gasAddr == "" {
					gasAddr = proposerID
				}
				stateDB.AddBalance(gasAddr, distribution.Validators)
			}
			stateDB.AddBalance(StakingFeePoolAddress, distribution.Stakers)
			stateDB.AddBalance(TreasuryFeePoolAddress, distribution.Treasury)
			if distribution.Burned.Sign() > 0 {
				// Record the burn in the commit journal BEFORE crediting DEAD so
				// the journal's "burned before" snapshot is the pre-burn total.
				RecordBurn(distribution.Burned)
				stateDB.AddBalance(common.CanonicalAddress(common.DefaultBurnAddress), distribution.Burned)
			}
		}

		stateDB.IncrementNonce(tx.Sender)
		logger.Info("executor: tx[%d] %s → %s %s nSPX (gas %s nSPX) ✓",
			i, tx.Sender, tx.Receiver, tx.Amount.String(), gasFee.String())
	}

	// Update the block header with the accumulated gas used.
	if gasUsedAcc != nil {
		block.Header.GasUsed = gasUsedAcc
	}
	return nil
}

// mintBlockReward issues the policy-defined reward to the block proposer, respecting
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
			logger.Info("SUCCESS GENESIS: vault %s funded with %s nSPX (%s SPX)",
				GenesisVaultAddress, totalAllocated.String(), totalSPX.String())
			logger.Info("📊 GENESIS SUPPLY: %s nSPX", totalAllocated.String())
		} else {
			logger.Info("mintBlockReward: no allocations to fund vault (test mode)")
		}
		return
	}

	// ========== Blocks 1+ get normal block rewards ==========
	// (There's no separate "distribution block 1" anymore — genesis
	// allocations are distributed inside block 0 itself via
	// ExecuteGenesisBlock, so block 1 is just the first ordinary block.)
	reward := bc.PolicyBlockReward(block.GetHeight())
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

	// Map nodeID → SPIF reward address so rewards go to a real wallet
	rewardAddr := bc.ValidatorRewardAddress(proposerID)
	if rewardAddr == "" {
		rewardAddr = proposerID
	}

	// Split the freshly minted reward: miner share to the proposer, burn
	// share to the protocol burn (DEAD) address. IncrementTotalSupply runs
	// exactly once for the full minted amount — both slices are already-minted
	// value relocated via AddBalance, never decremented.
	split := bc.ActivePolicy().SplitBlockReward(reward)
	reward = split.Total
	stateDB.AddBalance(rewardAddr, split.Miner)
	if split.Burned.Sign() > 0 {
		// Journal the burn before crediting DEAD (see RecordBurn).
		RecordBurn(split.Burned)
		stateDB.AddBalance(common.CanonicalAddress(common.DefaultBurnAddress), split.Burned)
	}
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

	logger.Info("SUCCESS REWARD: %.6f SPX → %s (block %d, miner=%s burned=%s nSPX)", rewardSPX, proposerID, block.GetHeight(), split.Miner.String(), split.Burned.String())
	logger.Info("📊 SUPPLY: Total=%s nSPX, Genesis=%s nSPX, Rewards=%s nSPX, Remaining=%s nSPX",
		totalMinted.String(), genesisSupply.String(), rewardsMinted.String(), remainingNSPX.String())
}

// mintEpochInflation mints policy-defined inflation only at deterministic
// block-height epoch boundaries. It deliberately uses height rather than a
// node clock, so replaying a block produces identical supply everywhere.
func (bc *Blockchain) mintEpochInflation(block *types.Block, stateDB *StateDB) {
	if block == nil || block.GetHeight() == 0 {
		return
	}
	p := bc.ActivePolicy()
	if p.BlocksPerEpoch == 0 || block.GetHeight()%p.BlocksPerEpoch != 0 {
		return
	}
	blocksPerYear := p.GetBlocksPerYear()
	if blocksPerYear == 0 {
		return
	}
	year := block.GetHeight()/blocksPerYear + 1
	// ★ FIX: Do NOT refresh validator stakes from the live consensus set here.
	// The live consensus set is node-specific (different peer discovery timing,
	// connection state), so calling refreshValidatorStakesFromConsensus() here
	// makes every node compute a different stake distribution → different account
	// states → different state roots. This was the root cause of the late joiner
	// state divergence at the first epoch boundary (block 3).
	//
	// Instead, epoch inflation distributes according to the deterministic on-chain
	// stakes already persisted in StateDB (seeded at genesis via
	// seedValidatorStakesFromGenesis, updated via explicit stake transactions).
	// This guarantees every replaying node derives the identical distribution and
	// arrives at the same state root.
	distribution := p.CalculateEpochInflationExact(stateDB.GetTotalSupply(), year)
	if distribution.TotalMinted.Sign() <= 0 {
		return
	}
	remaining := new(big.Int).Sub(maxSupplyNSPX, stateDB.GetTotalSupply())
	if remaining.Sign() <= 0 {
		return
	}
	if distribution.TotalMinted.Cmp(remaining) > 0 {
		// Preserve the policy staking/community ratio as closely as integer
		// arithmetic allows when the hard cap truncates an epoch.
		distribution.TotalMinted.Set(remaining)
		distribution.StakingRewards.Mul(remaining, new(big.Int).SetUint64(p.StakingRewardBPS))
		distribution.StakingRewards.Div(distribution.StakingRewards, big.NewInt(10000))
		distribution.CommunityFund.Sub(remaining, distribution.StakingRewards)
	}
	// Stakers slice → per-validator commission (real stake) + fee pool for the
	// delegator share. Community fund → treasury.
	bc.distributeEpochStakingRewards(stateDB, distribution.StakingRewards)
	stateDB.AddBalance(TreasuryFeePoolAddress, distribution.CommunityFund)
	stateDB.IncrementTotalSupply(distribution.TotalMinted)
	stateDB.IncrementRewardsMinted(distribution.TotalMinted)
	logger.Info("policy inflation: epoch=%d year=%d minted=%s nSPX (staking=%s treasury=%s)", block.GetHeight()/p.BlocksPerEpoch, year, distribution.TotalMinted, distribution.StakingRewards, distribution.CommunityFund)
}

// seedValidatorStakesFromGenesis persists the genesis-defined validator stakes
// (InitialValidators) into StateDB. It runs exactly once, during block-0
// execution, so chains that boot with a known validator set get a
// deterministic on-chain stake snapshot before the first epoch boundary.
func (bc *Blockchain) seedValidatorStakesFromGenesis(stateDB *StateDB) {
	if stateDB == nil || bc.chainParams == nil {
		return
	}
	existing, err := stateDB.GetAllValidatorStakes()
	if err == nil && len(existing) > 0 {
		return // already seeded — never overwrite a committed set
	}
	gs := GenesisStateFromChainParams(bc.chainParams)
	for _, v := range gs.InitialValidators {
		if v == nil || v.NodeID == "" {
			continue
		}
		if v.StakeNSPX != nil && v.StakeNSPX.Sign() > 0 {
			stateDB.SetValidatorStake(v.NodeID, v.StakeNSPX)
		}
	}
}

// distributeEpochStakingRewards credits the epoch's staking-reward slice to
// validators in proportion to their state-persisted stake, using policy's
// exact integer commission math (CalculateValidatorRewardExact). The
// commission portion goes to each validator's reward address (node ID when no
// SPIF reward address is registered); the remaining delegator share and any
// integer rounding dust stays in StakingFeePoolAddress for the staking
// subsystem to claim. With no stake records at all, the full slice is parked
// in the fee pool — identical to the pre-distribution behaviour.
func (bc *Blockchain) distributeEpochStakingRewards(stateDB *StateDB, stakingRewards *big.Int) {
	if stateDB == nil || stakingRewards == nil || stakingRewards.Sign() <= 0 {
		return
	}
	stakes, err := stateDB.GetAllValidatorStakes()
	if err != nil || len(stakes) == 0 {
		stateDB.AddBalance(StakingFeePoolAddress, stakingRewards)
		return
	}

	totalStaked := big.NewInt(0)
	for _, s := range stakes {
		if s != nil {
			totalStaked.Add(totalStaked, s)
		}
	}
	if totalStaked.Sign() <= 0 {
		stateDB.AddBalance(StakingFeePoolAddress, stakingRewards)
		return
	}

	// Deterministic iteration order (sorted IDs) so every replaying node
	// credits addresses in the same order.
	ids := make([]string, 0, len(stakes))
	for id := range stakes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	commissionBPS := policy.DefaultCommissionBPS
	policyParams := bc.ActivePolicy()
	distributed := big.NewInt(0)
	for _, id := range ids {
		stake := stakes[id]
		if stake == nil || stake.Sign() <= 0 {
			continue
		}
		commission := policyParams.CalculateValidatorRewardExact(stake, totalStaked, stakingRewards, commissionBPS)
		if commission.Sign() <= 0 {
			continue
		}
		addr := bc.ValidatorRewardAddress(id)
		if addr == "" {
			addr = id
		}
		stateDB.AddBalance(addr, commission)
		distributed.Add(distributed, commission)
	}

	remainder := new(big.Int).Sub(stakingRewards, distributed)
	if remainder.Sign() > 0 {
		stateDB.AddBalance(StakingFeePoolAddress, remainder)
	}
}

// applyBlockTransitions applies the block's transactions and mints rewards to
// the given stateDB. This is the shared execution path used by both
// ExecuteBlock (during commit) and previewStateRoot (during block creation).
// Keeping these in sync is critical: if previewStateRoot applies operations in
// a different order or with different logic than ExecuteBlock, the state root
// computed during block creation won't match the state root computed during
// block verification on other nodes, causing state divergence on late joiners.
func (bc *Blockchain) applyBlockTransitions(block *types.Block, stateDB *StateDB) error {
	height := block.GetHeight()

	// Roll the usage-responsive fee-burn rate BEFORE this block's
	// transactions are applied. The only inputs are the PREVIOUS finalized
	// block's gas footprint and burn rate exactly as committed to the state
	// DB when that block was executed — never the live consensus set, never
	// wall-clock time, never this block's in-progress state. This is the
	// same determinism discipline as the block-3 ★ FIX: every input is
	// either a committed chain value or derived deterministically from one,
	// so every replaying node rolls the identical rate and state root.
	if height > 0 {
		p := bc.ActivePolicy()
		currentBPS := stateDB.GetBurnFeeBPS(p.BurnFeeBPS)
		prevUsed, prevLimit := stateDB.GetPrevBlockGas()
		stateDB.SetBurnFeeBPS(p.NextBurnFeeBPS(currentBPS, prevUsed, prevLimit))
	}

	// For genesis block, fund the vault BEFORE distributing to allocations.
	if height == 0 {
		bc.mintBlockReward(block, stateDB)
		// Persist the genesis validator stakes so the first epoch-boundary
		// inflation distribution has a deterministic on-chain stake snapshot.
		bc.seedValidatorStakesFromGenesis(stateDB)
	}

	if err := bc.applyTransactions(block, stateDB); err != nil {
		return err
	}

	// Persist THIS block's finalized gas footprint for the next block's
	// burn-rate roll. The values come from the header that execution just
	// finalized (applyTransactions accumulates GasUsed; GasLimit is part of
	// the committed header), so the snapshot is identical on the proposing
	// leader and on every replaying verifier.
	bc.recordBlockGasSnapshot(block, stateDB)

	// For all other blocks, mint reward AFTER transactions.
	if height > 0 {
		bc.mintBlockReward(block, stateDB)
		bc.mintEpochInflation(block, stateDB)
	}

	return nil
}

// recordBlockGasSnapshot persists the block's finalized gas footprint
// (GasUsed, GasLimit) into the deterministic policy-state namespace so the
// next block's usage-responsive burn-rate roll reads it from committed state.
// nil fields are normalized to zero, keeping leader preview and verifier
// execution byte-identical.
func (bc *Blockchain) recordBlockGasSnapshot(block *types.Block, stateDB *StateDB) {
	if block == nil || stateDB == nil || block.Header == nil {
		return
	}
	stateDB.SetPrevBlockGas(block.Header.GasUsed, block.Header.GasLimit)
}

// ExecuteBlock is called from CommitBlock.
func (bc *Blockchain) ExecuteBlock(block *types.Block) ([]byte, error) {
	stateDB, err := bc.newStateDB()
	if err != nil {
		return nil, err
	}

	if err := bc.applyBlockTransitions(block, stateDB); err != nil {
		logger.Error("ExecuteBlock: applyBlockTransitions failed: %v", err)
		return nil, fmt.Errorf("ExecuteBlock: execution failed: %w", err)
	}

	stateRoot, err := stateDB.Commit()
	if err != nil {
		return nil, err
	}
	return stateRoot, nil
}

func (bc *Blockchain) previewStateRoot(height uint64, txs []*types.Transaction, proposerID string) []byte {
	stateDB, err := bc.newStateDB()
	if err != nil {
		logger.Warn("previewStateRoot: failed to open stateDB: %v", err)
		return bc.calculateStateRootFallback()
	}

	block := &types.Block{
		Header: &types.BlockHeader{
			Height:     height,
			Block:      height,
			ProposerID: proposerID,
		},
		Body: types.BlockBody{TxsList: txs},
	}

	// Mirror CreateBlock's gas header fields exactly. The usage-responsive
	// burn-rate roll persists the block's finalized (GasUsed, GasLimit) into
	// the state root, so the leader's preview must write the same snapshot
	// the verifiers' ExecuteBlock will write from the sealed header — or the
	// previewed state root would diverge from the committed one (the same
	// preview/execute class of bug the ★ FIX below guards).
	gasLimit := big.NewInt(0)
	if bc.chainParams != nil && bc.chainParams.BlockGasLimit != nil {
		gasLimit = new(big.Int).Set(bc.chainParams.BlockGasLimit)
	}
	block.Header.GasLimit = gasLimit
	block.Header.GasUsed = big.NewInt(0)

	// ★ FIX: Use the exact same execution path as ExecuteBlock so the state
	// root computed during block creation (on the bootstrap node) matches the
	// state root computed during block verification (on late joiners). The old
	// code applied operations in a slightly different order and used
	// computeStateRoot() instead of Commit(), producing divergent state roots
	// that caused "state root mismatch" errors on late joiners.
	if err := bc.applyBlockTransitions(block, stateDB); err != nil {
		logger.Warn("previewStateRoot: applyBlockTransitions failed: %v", err)
		return bc.calculateStateRootFallback()
	}

	// computeStateRoot() operates on the same pending state that Commit()
	// would flush to LevelDB before computing the root, so the result is
	// identical to what ExecuteBlock returns.
	root, err := stateDB.computeStateRoot()
	if err != nil {
		logger.Warn("previewStateRoot: computeStateRoot failed: %v", err)
		return bc.calculateStateRootFallback()
	}
	return root
}

// calculateStateRootFallback computes a state root from the current state DB.
func (bc *Blockchain) calculateStateRootFallback() []byte {
	stateDB, err := bc.newStateDB()
	if err != nil {
		logger.Warn("calculateStateRootFallback: failed to open state DB: %v", err)
		return types.EmptyMerkleRoot
	}
	root, err := stateDB.computeStateRoot()
	if err != nil {
		logger.Warn("calculateStateRootFallback: failed to compute state root: %v", err)
		return types.EmptyMerkleRoot
	}
	return root
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

	// Use nonce, not balance, to detect prior execution: a *successful*
	// genesis drains the vault to zero, so balance==0 is the expected
	// steady state after distribution, not a signal that genesis hasn't
	// run yet. Nonce only increases, so it's a reliable "already executed"
	// marker across restarts.
	nonce, err := stateDB.GetNonce(GenesisVaultAddress)
	if err != nil {
		logger.Error("ExecuteGenesisBlock: failed to get nonce: %v", err)
		return errors.New("failed to get nonce")
	}
	if nonce > 0 {
		logger.Info("ExecuteGenesisBlock: already executed (vault nonce=%d), skipping", nonce)
		return nil
	}

	if _, err := bc.ExecuteBlock(genesisBlock); err != nil {
		logger.Error("ExecuteGenesisBlock: ExecuteBlock failed: %v", err)
		return errors.New("ExecuteBlock failed")
	}

	logger.Info("SUCCESS ExecuteGenesisBlock: vault %s funded", GenesisVaultAddress)
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
			logger.Info("SUCCESS Updated validator %s stake to %d SPX", vid, stakeSPX)
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

// ValidatorRewardAddress maps a node ID to its SPIF reward address.
// Returns empty string if no mapping is registered.
//
// NOTE: this uses bc.rewardMapMu, a mutex dedicated to validatorRewardMap —
// deliberately NOT bc.lock. This function is reached from CreateBlock's
// call chain (CreateBlock -> previewStateRoot -> mintBlockReward ->
// ValidatorRewardAddress) while CreateBlock is still holding bc.lock.Lock().
// sync.RWMutex is not reentrant, so RLock()'ing bc.lock here would
// self-deadlock the leader's proposal goroutine forever. Keeping this map
// under its own lock avoids that without having to reason about every
// call site that might already hold bc.lock.
func (bc *Blockchain) ValidatorRewardAddress(nodeID string) string {
	rewardMapMu.RLock()
	defer rewardMapMu.RUnlock()
	if bc.validatorRewardMap == nil {
		return ""
	}
	return bc.validatorRewardMap[nodeID]
}

// SetValidatorRewardAddress registers a SPIF reward address for a validator.
// Once set, block rewards and gas fees for this validator will be credited
// to the SPIF address instead of the node ID. DEAD burn addresses are
// rejected: routing a miner's own reward straight into the unspendable burn
// address would silently destroy their payout and poison stake accounting.
func (bc *Blockchain) SetValidatorRewardAddress(nodeID, spifAddr string) {
	rewardMapMu.Lock()
	defer rewardMapMu.Unlock()
	if bc.validatorRewardMap == nil {
		bc.validatorRewardMap = make(map[string]string)
	}
	if spifAddr != "" && nodeID != "" {
		if common.IsBurnAddress(spifAddr) {
			logger.Warn("SetValidatorRewardAddress: refusing DEAD burn address %s for %s", spifAddr, nodeID)
			return
		}
		bc.validatorRewardMap[nodeID] = spifAddr
		logger.Info("SUCCESS Validator reward mapping: %s → %s", nodeID, spifAddr)
	}
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

// ============================================================================
// Block production functions (moved from block_producer.go)
// ============================================================================

// CreateBlock creates a new block with transactions from mempool
// and iterates nonce until consensus using existing functions.
// Returns: New block or error
func (bc *Blockchain) CreateBlock() (block *types.Block, err error) {
	// Validate prerequisites
	if bc.mempool == nil {
		return nil, fmt.Errorf("mempool not initialized")
	}
	if bc.chainParams == nil {
		return nil, fmt.Errorf("chain parameters not initialized")
	}

	// ── UI dashboard: report block production start/stages/outcome ──
	// A single deferred check covers every return path below (including
	// the ones inside selectTransactionsForBlock's error wrapping) without
	// having to touch each one individually.
	bp := currentUIProgress()
	if bp != nil {
		bp.StartBlockProduction()
		defer func() {
			if err != nil {
				bp.FailBlockProduction(err)
			} else {
				bp.CompleteBlockProduction(block.GetHash(), len(block.Body.TxsList))
			}
		}()
	}

	bc.lock.Lock() // Write lock for thread safety
	defer bc.lock.Unlock()

	// Get the latest block to use as parent
	prevBlock, err := bc.storage.GetLatestBlock()
	if err != nil || prevBlock == nil {
		return nil, fmt.Errorf("no previous block found: %v", err)
	}

	// Get previous hash (handles both hex and GENESIS_ formats)
	parentHash := prevBlock.GetHash()
	var parentHashBytes []byte

	// Check if parent hash is in genesis format
	if strings.HasPrefix(parentHash, "GENESIS_") {
		parentHashBytes = []byte(parentHash)
		logger.Info("Using genesis-style parent hash: %s (stored as %d bytes)",
			parentHash, len(parentHashBytes))
	} else {
		parentHashBytes, err = hex.DecodeString(parentHash)
		if err != nil {
			return nil, fmt.Errorf("failed to decode parent hash: %w", err)
		}
		logger.Info("Using normal parent hash: %s (stored as %d bytes)",
			parentHash, len(parentHashBytes))
	}

	// Get pending transactions from mempool
	pendingTxs := bc.mempool.GetPendingTransactions()
	selectedTxs := pendingTxs
	totalSize := uint64(0)
	if len(pendingTxs) > 0 {
		logger.Info("Found %d pending transactions in mempool, max block size: %d bytes",
			len(pendingTxs), bc.chainParams.MaxBlockSize)

		var err error
		selectedTxs, totalSize, err = bc.selectTransactionsForBlock(pendingTxs)
		if err != nil {
			return nil, fmt.Errorf("failed to select transactions: %w", err)
		}
	} else {
		// Dump full pool state so we can tell whether the mempool is truly
		// empty or transactions are stuck mid-pipeline (broadcast/validation).
		broadcast, validating, pending, invalid, all := bc.mempool.MempoolSnapshot()
		logger.Warn("Mempool pendingPool empty — snapshot: broadcast=%d validating=%d pending=%d invalid=%d all=%d",
			broadcast, validating, pending, invalid, all)
	}

	logger.Info("Creating block with %d transactions, estimated size: %d bytes (limit: %d, utilization: %.2f%%)",
		len(selectedTxs), totalSize, bc.chainParams.MaxBlockSize,
		float64(totalSize)/float64(bc.chainParams.MaxBlockSize)*100)

	nextHeight := prevBlock.GetHeight() + 1
	proposerID := ""
	if bc.consensusEngine != nil {
		proposerID = bc.consensusEngine.GetNodeID()
	}

	// Calculate roots for the block
	if bp != nil {
		bp.UpdateBlockProductionStage("calculating merkle root")
	}
	txsRoot := bc.calculateTransactionsRoot(selectedTxs)

	if bp != nil {
		bp.UpdateBlockProductionStage("calculating state root")
	}
	stateRoot := bc.previewStateRoot(nextHeight, selectedTxs, proposerID)

	// ★ FIX: Use the parent block's timestamp + 1 second as the floor for the
	// new block's timestamp, rather than always using the local wall clock.
	// This ensures that:
	//   1. Block timestamps are monotonically increasing (parent_timestamp <
	//      child_timestamp), which is a consensus requirement.
	//   2. All nodes that replay the same sequence of blocks arrive at the
	//      same timestamps, because the timestamp is derived from the chain
	//      itself, not from the local clock.
	//   3. During PBFT, the leader's proposed timestamp is used verbatim
	//      (the block arrives with a timestamp already set). This code path
	//      is only reached during solo-mining (CreateBlock), where there is
	//      no leader to provide a timestamp.
	//
	// Previously, each node used its own wall-clock time (common.GetCurrentTimestamp()),
	// which meant two nodes solo-mining at the same height would produce blocks
	// with different timestamps → different hashes → permanent fork.
	currentTimestamp := prevBlock.Header.Timestamp + 1
	if currentTimestamp == 0 {
		currentTimestamp = time.Now().Unix()
	}

	logger.Info("Creating block with timestamp: %d (%s)",
		currentTimestamp, time.Unix(currentTimestamp, 0).Format(time.RFC3339))

	// Create miner address from proposer ID
	miner := make([]byte, 20)
	if bc.consensusEngine != nil && bc.consensusEngine.GetNodeID() != "" {
		nodeIDHash := common.SpxHash([]byte(bc.consensusEngine.GetNodeID()))
		if len(nodeIDHash) >= 20 {
			miner = nodeIDHash[:20]
		}
	}

	emptyUncles := []*types.BlockHeader{}
	extraData := fmt.Appendf([]byte(nil), "Sphinx Block %d", prevBlock.GetHeight()+1)

	newHeader := types.NewBlockHeader(
		nextHeight,
		parentHashBytes,
		bc.GetDifficulty(),
		txsRoot,
		stateRoot,
		bc.chainParams.BlockGasLimit,
		big.NewInt(0),
		extraData,
		miner,
		currentTimestamp,
		emptyUncles,
	)

	newBody := types.NewBlockBody(selectedTxs, emptyUncles, nextHeight)
	newBlock := types.NewBlock(newHeader, newBody)
	newBlock.Header.ProposerID = proposerID

	// Build the Bloom filter once here, before nonce mining. FinalizeHash
	// runs inside the loop below up to maxAttempts times per block; a
	// filter build (hashing every address/tx-id with 3 hash functions)
	// must never happen per nonce attempt.
	newBlock.PopulateLogsBloom()

	// CRITICAL: Increment nonce multiple times until consensus is achieved
	logger.Info("Starting nonce iteration for consensus: initial nonce=%s", newBlock.Header.Nonce)
	if bp != nil {
		bp.UpdateBlockProductionStage("mining nonce")
	}

	maxAttempts := 1000000
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := newBlock.IncrementNonce(); err != nil {
			logger.Warn("Failed to increment nonce on attempt %d: %v", attempt, err)
			continue
		}
		newBlock.FinalizeHash()
		if bc.checkConsensusRequirements(newBlock) {
			logger.Info("SUCCESS Consensus achieved with nonce %s after %d attempts",
				newBlock.Header.Nonce, attempt+1)
			break
		}
		if (attempt+1)%1000 == 0 {
			logger.Debug("Nonce iteration: attempt %d, current nonce: %s",
				attempt+1, newBlock.Header.Nonce)
		}
		if attempt == maxAttempts-1 {
			logger.Info("WARNING Max nonce attempts reached, using nonce %s", newBlock.Header.Nonce)
		}
	}

	if err := newBlock.ValidateHashFormat(); err != nil {
		logger.Warn("ERROR Block hash format validation failed: %v", err)
		newBlock.SetHash(hex.EncodeToString(newBlock.GenerateBlockHash()))
		if err := newBlock.ValidateHashFormat(); err != nil {
			return nil, fmt.Errorf("failed to generate valid block hash: %w", err)
		}
	}

	if err := newBlock.ValidateTxsRoot(); err != nil {
		return nil, fmt.Errorf("created block has inconsistent TxsRoot: %v", err)
	}

	// Cache merkle root in consensus engine
	merkleRoot := hex.EncodeToString(txsRoot)
	blockHash := newBlock.GetHash()
	logger.Info("SUCCESS Pre-calculated merkle root for new block %s: %s", blockHash, merkleRoot)

	if bc.consensusEngine != nil {
		bc.consensusEngine.CacheMerkleRoot(blockHash, merkleRoot)
		logger.Info("SUCCESS Cached merkle root in consensus engine")
	} else {
		logger.Warn("WARNING No consensus engine available for caching")
	}

	logger.Info("SUCCESS Created new PBFT block: height=%d, transactions=%d, hash=%s, final_nonce=%s",
		newBlock.GetHeight(), len(selectedTxs), newBlock.GetHash(), newBlock.Header.Nonce)

	// FIX: solo-mined blocks used to leave here with an empty
	// ProposerSignature and SigValid=false forever — SignBlock was only ever
	// called from Consensus.ProposeBlock (the PBFT-leader path), so nothing
	// signed a block produced before PBFT started or before this node knew
	// enough peers to run consensus. That's a real authenticity gap during
	// solo mining and the solo→PBFT handoff, not just a cosmetic field: an
	// unsigned block proves nothing about who produced it, so fork-choice
	// between two competing solo-mined blocks (see the weight-tie fix in
	// blockchain.go ImportBlock) had no producer signature to fall back on,
	// only a hash tie-break. Sign every block from genesis onward with this
	// node's own key, the same way a PBFT leader signs its proposal, so
	// authenticity holds even before quorum attestations exist.
	if bc.consensusEngine != nil {
		if cs, ok := bc.consensusEngine.(*consensus.Consensus); ok {
			wrapped := NewBlockHelper(newBlock)
			if err := cs.SignBlockHeader(wrapped); err != nil {
				logger.Warn("CreateBlock: failed to sign solo-mined block height=%d: %v", newBlock.GetHeight(), err)
			} else {
				logger.Info("SUCCESS Solo-mined block height=%d signed by proposer=%s", newBlock.GetHeight(), proposerID)
			}
		} else {
			logger.Warn("CreateBlock: consensusEngine is not *consensus.Consensus (type=%T) — cannot sign solo-mined block height=%d",
				bc.consensusEngine, newBlock.GetHeight())
		}
	} else {
		logger.Warn("CreateBlock: no consensus engine available — solo-mined block height=%d will remain unsigned", newBlock.GetHeight())
	}

	return newBlock, nil
}

// selectTransactionsForBlock selects transactions for the block based on size constraints.
func (bc *Blockchain) selectTransactionsForBlock(pendingTxs []*types.Transaction) ([]*types.Transaction, uint64, error) {
	var selectedTxs []*types.Transaction
	currentSize := uint64(0)
	txCount := 0
	maxTxCount := 10000

	blockOverhead := uint64(1000)
	availableSize := bc.chainParams.MaxBlockSize - blockOverhead

	if availableSize <= 0 {
		return nil, 0, fmt.Errorf("block size too small for overhead")
	}

	logger.Debug("Available block size for transactions: %d bytes (after %d bytes overhead)",
		availableSize, blockOverhead)

	currentGas := big.NewInt(0)

	for _, tx := range pendingTxs {
		if txCount >= maxTxCount {
			logger.Warn("Reached maximum transaction count limit: %d", maxTxCount)
			break
		}

		txSize, err := bc.calculateTxsSize(tx)
		if err != nil {
			logger.Warn("Failed to calculate transaction size: %v, skipping", err)
			continue
		}

		if txSize > bc.chainParams.MaxTransactionSize {
			logger.Warn("Transaction exceeds maximum size: %d > %d", txSize, bc.chainParams.MaxTransactionSize)
			continue
		}

		if err := bc.ValidateTransactionPolicy(tx); err != nil {
			logger.Warn("Transaction %s failed policy validation: %v", tx.ID, err)
			continue
		}

		if currentSize+txSize > availableSize {
			continue
		}

		if bc.chainParams.BlockGasLimit != nil {
			txGas := bc.getTransactionGas(tx)
			proposedGas := new(big.Int).Add(currentGas, txGas)
			if proposedGas.Cmp(bc.chainParams.BlockGasLimit) > 0 {
				logger.Debug("Transaction would exceed gas limit: %s > %s",
					proposedGas.String(), bc.chainParams.BlockGasLimit.String())
				continue
			}
			currentGas = proposedGas
		}

		selectedTxs = append(selectedTxs, tx)
		currentSize += txSize
		txCount++

		if currentSize >= availableSize*95/100 {
			logger.Debug("Reached 95%% of available block size, stopping selection")
			break
		}
	}

	if len(selectedTxs) > 0 {
		utilization := float64(currentSize) / float64(availableSize) * 100
		averageTxSize := float64(currentSize) / float64(len(selectedTxs))
		logger.Info("Selected %d transactions, total size: %d bytes (%.2f%% utilization, avg tx: %.2f bytes)",
			len(selectedTxs), currentSize, utilization, averageTxSize)
		if bc.chainParams.BlockGasLimit != nil {
			gasUtilization := float64(currentGas.Int64()) / float64(bc.chainParams.BlockGasLimit.Int64()) * 100
			logger.Info("Gas usage: %s / %s (%.2f%%)",
				currentGas.String(), bc.chainParams.BlockGasLimit.String(), gasUtilization)
		}
	}

	sort.SliceStable(selectedTxs, func(i, j int) bool {
		a := selectedTxs[i]
		b := selectedTxs[j]
		if a.Sender != b.Sender {
			return a.Sender < b.Sender
		}
		if a.Nonce != b.Nonce {
			return a.Nonce < b.Nonce
		}
		// Final deterministic tie-breaker for complete ordering.
		return a.ID < b.ID
	})

	return selectedTxs, currentSize + blockOverhead, nil
}

// calculateTxsSize calculates the size of a transaction in bytes.
func (bc *Blockchain) calculateTxsSize(tx *types.Transaction) (uint64, error) {
	if bc.mempool != nil {
		return bc.mempool.CalculateTransactionSize(tx), nil
	}

	estimatedSize := uint64(50) // Fixed overhead
	estimatedSize += uint64(len(tx.ID))
	estimatedSize += uint64(len(tx.Sender))
	estimatedSize += uint64(len(tx.Receiver))

	if tx.Amount != nil {
		estimatedSize += uint64(len(tx.Amount.Bytes()))
	}
	if tx.GasLimit != nil {
		estimatedSize += uint64(len(tx.GasLimit.Bytes()))
	}
	if tx.GasPrice != nil {
		estimatedSize += uint64(len(tx.GasPrice.Bytes()))
	}

	estimatedSize += 8 // nonce
	estimatedSize += 8 // timestamp

	estimatedSize += uint64(len(tx.Signature))
	estimatedSize += uint64(len(tx.SignatureHash))
	estimatedSize += uint64(len(tx.PublicKey))
	estimatedSize += uint64(len(tx.AuthTimestamp))
	estimatedSize += uint64(len(tx.AuthNonce))
	estimatedSize += uint64(len(tx.MerkleRootHash))
	estimatedSize += uint64(len(tx.Commitment))
	estimatedSize += uint64(len(tx.Proof))
	estimatedSize += uint64(len(tx.Code))
	estimatedSize += uint64(len(tx.CallData))
	estimatedSize += uint64(len(tx.ToContract))
	estimatedSize += 4 // version

	if tx.HasReturnData() && len(tx.ReturnData) > 0 {
		estimatedSize += uint64(len(tx.ReturnData))
	}

	return estimatedSize, nil
}

// getTransactionGas returns the gas cost for a transaction.
func (bc *Blockchain) getTransactionGas(tx *types.Transaction) *big.Int {
	if tx.GasLimit != nil {
		return tx.GasLimit
	}
	return big.NewInt(21000) // Default gas for a standard transfer
}

// checkConsensusRequirements checks if the block meets consensus requirements.
func (bc *Blockchain) checkConsensusRequirements(_ *types.Block) bool {
	// For PBFT, the nonce iteration is a placeholder for future PoW integration.
	// Currently, any nonce is accepted as valid.
	return true
}

// calculateTransactionsRoot calculates the Merkle root of a set of transactions.
func (bc *Blockchain) calculateTransactionsRoot(txs []*types.Transaction) []byte {
	if len(txs) == 0 {
		return types.EmptyMerkleRoot
	}
	tempBody := types.NewBlockBody(txs, []*types.BlockHeader{}, 0)
	tempBlock := types.NewBlock(&types.BlockHeader{}, tempBody)
	return tempBlock.CalculateTxsRoot()
}

// calculateBlockTime calculates the time between this block and the previous block.
func (bc *Blockchain) calculateBlockTime(block *types.Block) time.Duration {
	if block.GetHeight() <= 1 {
		return 5 * time.Second
	}
	prevBlock := bc.GetBlockByNumber(block.GetHeight() - 1)
	if prevBlock == nil {
		return 5 * time.Second
	}
	blockTime := time.Duration(block.Header.Timestamp-prevBlock.Header.Timestamp) * time.Second
	if blockTime <= 0 {
		blockTime = 1 * time.Second
	}
	return blockTime
}
