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

// go/src/core/executor.go
package core

import (
	"fmt"
	"math/big"

	types "github.com/sphinxorg/protocol/src/core/transaction"
	logger "github.com/sphinxorg/protocol/src/log"
)

// maxSupplyNSPX is the hard cap: 5 billion SPX expressed in nSPX.
var maxSupplyNSPX = new(big.Int).Mul(
	big.NewInt(5_000_000_000),
	big.NewInt(1e18),
)

// newStateDB opens the StateDB for this blockchain node.
// It calls bc.storage.GetDB() which opens (or returns a cached) *database.DB
// against the node's LevelDB directory.
func (bc *Blockchain) newStateDB() (*StateDB, error) {
	db, err := bc.storage.GetDB()
	if err != nil {
		return nil, fmt.Errorf("newStateDB: %w", err)
	}
	return NewStateDB(db), nil
}

// IsDistributionComplete returns true when the genesis vault has been fully
// drained — i.e. every allocation has been transferred out of GenesisVaultAddress.
// This is the signal that devnet's bootstrap phase is finished and the chain
// is ready to be promoted to testnet or mainnet.
func (bc *Blockchain) IsDistributionComplete() bool {
	stateDB, err := bc.newStateDB()
	if err != nil {
		logger.Warn("IsDistributionComplete: cannot open stateDB: %v", err)
		return false
	}
	bal := stateDB.GetBalance(GenesisVaultAddress)
	complete := bal.Sign() == 0
	if complete {
		logger.Info("✅ IsDistributionComplete: vault %s balance = 0, distribution done", GenesisVaultAddress)
	}
	return complete
}

// TotalAllocatedNSPX returns the sum of all genesis allocations in nSPX.
// Used to calculate how many more blocks need to run before distribution is done.
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
// Genesis funding transactions (sender == "genesis") are skipped because
// ApplyGenesisState has already credited them.
// applyTransactions — genesis sender check no longer needed,
// block 0 body is empty. Keep for safety but it will never fire.
func (bc *Blockchain) applyTransactions(block *types.Block, stateDB *StateDB) error {
	proposerID := block.Header.ProposerID

	for i, tx := range block.Body.TxsList {
		if tx.Sender == "genesis" {
			// Should not occur — genesis block body is now empty.
			// Kept as a safety guard.f
			continue
		}

		expected := stateDB.GetNonce(tx.Sender)
		if tx.Nonce != expected {
			return fmt.Errorf("tx[%d] %s: bad nonce: got %d want %d",
				i, tx.ID, tx.Nonce, expected)
		}

		gasFee := tx.GetGasFee()
		totalCost := new(big.Int).Add(tx.Amount, gasFee)

		bal := stateDB.GetBalance(tx.Sender)
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
		// Block 0: mint entire genesis supply to the vault.
		allocs := DefaultGenesisAllocations()
		reward := new(big.Int)
		for _, a := range allocs {
			if a.BalanceNSPX != nil {
				reward.Add(reward, a.BalanceNSPX)
			}
		}
		stateDB.AddBalance(proposerID, reward)
		stateDB.IncrementTotalSupply(reward)
		logger.Info("mintBlockReward: genesis mint %s nSPX → vault %s",
			reward.String(), proposerID)
		return
	}

	// Block 1 is always the genesis distribution block on every environment.
	// Transactions move coins from the vault to allocation addresses.
	// No new coins should be minted here.
	if block.GetHeight() == 1 {
		logger.Info("mintBlockReward: skipping reward for distribution block 1")
		logger.Info("🔒 PHASE 2 STARTING — Next blocks (2+) will use VDF+Stake PBFT")
		return
	}

	// Normal block reward (Blocks 2+)
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

// ExecuteBlock is called from CommitBlock.  It applies transactions, mints the
// block reward, and returns the new StateRoot to stamp into the block header.
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

// ExecuteGenesisBlock runs ExecuteBlock on block 0 so mintBlockReward fires
// and credits GenesisVaultAddress with the full allocation supply.
// Must be called AFTER SetStorageDB — it needs a live DB handle.
// It is idempotent: if the vault already has a non-zero balance it returns nil.
func (bc *Blockchain) ExecuteGenesisBlock() error {
	bc.lock.RLock()
	if len(bc.chain) == 0 || bc.chain[0] == nil {
		bc.lock.RUnlock()
		return fmt.Errorf("ExecuteGenesisBlock: genesis block not in memory")
	}
	genesisBlock := bc.chain[0]
	bc.lock.RUnlock()

	// Idempotency: skip if vault was already funded.
	stateDB, err := bc.newStateDB()
	if err != nil {
		return fmt.Errorf("ExecuteGenesisBlock: %w", err)
	}
	if stateDB.GetBalance(GenesisVaultAddress).Sign() > 0 {
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
// This should be called after Block 1 to enable Phase 2 consensus.
func (bc *Blockchain) UpdateValidatorStakesFromState(validatorIDs []string, validatorSet interface{}) error {
	if validatorSet == nil {
		return fmt.Errorf("validatorSet is nil")
	}

	stateDB, err := bc.newStateDB()
	if err != nil {
		return fmt.Errorf("failed to open stateDB: %w", err)
	}

	// Get the UpdateStake method via reflection or interface
	type stakeUpdater interface {
		UpdateStake(id string, stakeSPX uint64) error
	}

	updater, ok := validatorSet.(stakeUpdater)
	if !ok {
		return fmt.Errorf("validatorSet does not support UpdateStake")
	}

	for _, vid := range validatorIDs {
		// Get stake from blockchain state
		// You'll need to map node ID to address - for now use a mapping
		address := vid // In production, you need proper address mapping

		balanceNSPX := stateDB.GetBalance(address)
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
