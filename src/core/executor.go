// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/executor.go
package core

import (
	"fmt"
	"math/big"

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
		return nil, err
	}
	// Type assert back to *StateDB for internal use
	if sdb, ok := stateDB.(*StateDB); ok {
		return sdb, nil
	}
	return nil, fmt.Errorf("failed to get internal StateDB")
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
			return fmt.Errorf("tx[%d] %s: failed to get nonce: %w", i, tx.ID, err)
		}
		if tx.Nonce != expected {
			return fmt.Errorf("tx[%d] %s: bad nonce: got %d want %d",
				i, tx.ID, tx.Nonce, expected)
		}

		gasFee := tx.GetGasFee()
		totalCost := new(big.Int).Add(tx.Amount, gasFee)

		bal, err := stateDB.GetBalance(tx.Sender)
		if err != nil {
			return fmt.Errorf("tx[%d] %s: failed to get balance: %w", i, tx.ID, err)
		}
		if bal.Cmp(totalCost) < 0 {
			return fmt.Errorf("tx[%d] %s: %s has %s nSPX, needs %s nSPX",
				i, tx.ID, tx.Sender, bal.String(), totalCost.String())
		}

		if err := stateDB.SubBalance(tx.Sender, totalCost); err != nil {
			return fmt.Errorf("tx[%d] SubBalance: %w", i, err)
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
		// ========== FIX: Fund the genesis vault with total allocation ==========
		// This is the ONLY place coins are minted at genesis. The vault receives
		// the entire 100M SPX supply. Block 1 will distribute from the vault to
		// each allocation address via normal transactions with balance checks.
		//
		// This properly implements the "vault and distribute" model where:
		//   1. Vault holds the total supply after block 0
		//   2. Block 1 distributes to allocation addresses
		//   3. After block 1, vault balance = 0, IsDistributionComplete() = true
		totalAllocated := TotalAllocatedNSPX()
		if totalAllocated.Sign() > 0 {
			// Set the vault balance directly (no need to add, it's the first credit)
			stateDB.SetBalance(GenesisVaultAddress, totalAllocated)
			stateDB.IncrementTotalSupply(totalAllocated)

			totalSPX := new(big.Int).Div(totalAllocated, big.NewInt(1e18))
			logger.Info("✅ mintBlockReward: genesis vault %s funded with %s nSPX (%s SPX)",
				GenesisVaultAddress, totalAllocated.String(), totalSPX.String())
		} else {
			logger.Info("mintBlockReward: no allocations to fund vault (test mode)")
		}
		return
		// ======================================================================
	}

	if block.GetHeight() == 1 {
		logger.Info("mintBlockReward: skipping reward for distribution block 1")
		logger.Info("🔒 PHASE 2 STARTING — Next blocks (2+) will use VDF+Stake PBFT")
		return
	}

	// ========== Blocks 2+ get normal block rewards ==========
	reward := new(big.Int).Set(bc.chainParams.BaseBlockReward)
	if reward.Sign() <= 0 {
		return
	}

	current := stateDB.GetTotalSupply()
	if new(big.Int).Add(current, reward).Cmp(maxSupplyNSPX) > 0 {
		remaining := new(big.Int).Sub(maxSupplyNSPX, current)
		if remaining.Sign() <= 0 {
			logger.Info("mintBlockReward: supply cap reached, block %d", block.GetHeight())
			return
		}
		reward = remaining
	}

	stateDB.AddBalance(proposerID, reward)
	stateDB.IncrementTotalSupply(reward)

	rewardSPX := new(big.Float).Quo(
		new(big.Float).SetInt(reward),
		new(big.Float).SetInt(big.NewInt(1e18)),
	)
	logger.Info("✅ mintBlockReward: %.6f SPX → %s (block %d) [PHASE 2]",
		rewardSPX, proposerID, block.GetHeight())
}

// ExecuteBlock is called from CommitBlock.
func (bc *Blockchain) ExecuteBlock(block *types.Block) ([]byte, error) {
	stateDB, err := bc.newStateDB()
	if err != nil {
		return nil, fmt.Errorf("ExecuteBlock: %w", err)
	}

	if err := bc.applyTransactions(block, stateDB); err != nil {
		return nil, fmt.Errorf("ExecuteBlock: applyTransactions: %w", err)
	}

	bc.mintBlockReward(block, stateDB)

	stateRoot, err := stateDB.Commit()
	if err != nil {
		return nil, fmt.Errorf("ExecuteBlock: commit: %w", err)
	}
	return stateRoot, nil
}

// ExecuteGenesisBlock runs ExecuteBlock on block 0.
func (bc *Blockchain) ExecuteGenesisBlock() error {
	bc.lock.RLock()
	if len(bc.chain) == 0 || bc.chain[0] == nil {
		bc.lock.RUnlock()
		return fmt.Errorf("ExecuteGenesisBlock: genesis block not in memory")
	}
	genesisBlock := bc.chain[0]
	bc.lock.RUnlock()

	stateDB, err := bc.newStateDB()
	if err != nil {
		return fmt.Errorf("ExecuteGenesisBlock: %w", err)
	}
	bal, err := stateDB.GetBalance(GenesisVaultAddress)
	if err != nil {
		return fmt.Errorf("ExecuteGenesisBlock: failed to get balance: %w", err)
	}
	if bal.Sign() > 0 {
		logger.Info("ExecuteGenesisBlock: vault already funded, skipping")
		return nil
	}

	if _, err := bc.ExecuteBlock(genesisBlock); err != nil {
		return fmt.Errorf("ExecuteGenesisBlock: %w", err)
	}

	logger.Info("✅ ExecuteGenesisBlock: vault %s funded", GenesisVaultAddress)
	return nil
}

// UpdateValidatorStakesFromState updates the consensus validator set with
// stakes from the blockchain state after distribution is complete.
func (bc *Blockchain) UpdateValidatorStakesFromState(validatorIDs []string, validatorSet interface{}) error {
	if validatorSet == nil {
		return fmt.Errorf("validatorSet is nil")
	}

	stateDB, err := bc.newStateDB()
	if err != nil {
		return fmt.Errorf("failed to open stateDB: %w", err)
	}

	type stakeUpdater interface {
		UpdateStake(id string, stakeSPX uint64) error
	}

	updater, ok := validatorSet.(stakeUpdater)
	if !ok {
		return fmt.Errorf("validatorSet does not support UpdateStake")
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
