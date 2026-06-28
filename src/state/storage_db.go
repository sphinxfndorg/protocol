// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/state/storage_db.go
package state

import (
	"fmt"

	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	logger "github.com/sphinxfndorg/protocol/src/log"
)

// SetDB sets the main database handle (for blocks and transactions)
func (s *Storage) SetDB(db *database.DB) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db = db
	logger.Info("Main DB handle attached to storage: %p", db)
}

// GetDB returns the main database handle
func (s *Storage) GetDB() (*database.DB, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return nil, fmt.Errorf("Storage.GetDB: no shared database handle")
	}
	return s.db, nil
}

// SetStateDB sets the state database handle (for consensus state)
func (s *Storage) SetStateDB(db *database.DB) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateDB = db
	logger.Info("State DB handle attached to storage: %p", db)
}

// GetStateDB returns the state database handle
func (s *Storage) GetStateDB() (*database.DB, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.stateDB == nil {
		return nil, fmt.Errorf("Storage.GetStateDB: no shared state database handle")
	}
	return s.stateDB, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// ACCOUNT SET (replaces UTXO set)
// ─────────────────────────────────────────────────────────────────────────────

// GetAccountSet returns the current account set.
// If not loaded, it initializes a new empty account set.
func (s *Storage) GetAccountSet() *types.AccountSet {
	s.mu.RLock()
	if s.accountSet != nil {
		defer s.mu.RUnlock()
		return s.accountSet
	}
	s.mu.RUnlock()

	// Need to initialize - acquire write lock
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring write lock
	if s.accountSet != nil {
		return s.accountSet
	}

	// Initialize empty account set
	s.accountSet = types.NewAccountSet()
	logger.Info("Initialized new account set")

	// Try to load accounts from blocks if chain exists
	if s.totalBlocks > 0 {
		if err := s.buildAccountSetFromChain(); err != nil {
			logger.Warn("Failed to build account set from chain: %v", err)
		}
	}

	return s.accountSet
}

// buildAccountSetFromChain builds the account set by scanning all blocks.
// This is called once at startup to initialize the account set.
func (s *Storage) buildAccountSetFromChain() error {
	blocks, err := s.GetAllBlocks()
	if err != nil {
		return fmt.Errorf("failed to get blocks for account set: %w", err)
	}

	if len(blocks) == 0 {
		return nil
	}

	logger.Info("Building account set from %d blocks...", len(blocks))

	// Create new account set
	accountSet := types.NewAccountSet()

	for _, block := range blocks {
		// Process each transaction in the block
		for _, tx := range block.Body.TxsList {
			if tx == nil {
				continue
			}

			// Skip system/genesis transactions
			if tx.Sender == "genesis" || tx.Sender == "" {
				continue
			}

			// Add receiver account with the amount
			// Check if receiver account exists, if not create it
			if _, exists := accountSet.GetAccount(tx.Receiver); !exists {
				if err := accountSet.AddAccount(tx.Receiver, tx.Amount.Uint64(), false, block.GetHeight()); err != nil {
					logger.Warn("Failed to add account %s: %v", tx.Receiver, err)
				} else {
					logger.Debug("Added account: address=%s, balance=%d, height=%d",
						tx.Receiver[:8], tx.Amount.Uint64(), block.GetHeight())
				}
			} else {
				// Update existing account balance
				account, _ := accountSet.GetAccount(tx.Receiver)
				newBalance := account.Balance + tx.Amount.Uint64()
				if err := accountSet.UpdateBalance(tx.Receiver, newBalance); err != nil {
					logger.Warn("Failed to update account %s: %v", tx.Receiver, err)
				}
			}
		}
	}

	// Store the built account set
	s.accountSet = accountSet
	logger.Info("Built account set with %d entries", accountSet.Count())

	return nil
}

// UpdateAccountSet updates the account set after a block is committed.
// This should be called after successfully storing a new block.
func (s *Storage) UpdateAccountSet(block *types.Block) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.accountSet == nil {
		s.accountSet = types.NewAccountSet()
	}

	// Process each transaction in the block
	for _, tx := range block.Body.TxsList {
		if tx == nil {
			continue
		}

		// Skip system/genesis transactions
		if tx.Sender == "genesis" || tx.Sender == "" {
			continue
		}

		// Deduct from sender's balance
		if sender, ok := s.accountSet.GetAccount(tx.Sender); ok {
			amount := tx.Amount.Uint64()
			gasFee := tx.GetGasFee().Uint64()
			totalDeduct := amount + gasFee
			if sender.Balance >= totalDeduct {
				newBalance := sender.Balance - totalDeduct
				if err := s.accountSet.UpdateBalance(tx.Sender, newBalance); err != nil {
					logger.Warn("Failed to update sender %s: %v", tx.Sender, err)
				}
				s.accountSet.IncrementNonce(tx.Sender)
				logger.Debug("Updated sender %s: balance=%d, nonce=%d",
					tx.Sender[:8], newBalance, sender.Nonce+1)
			} else {
				logger.Warn("Insufficient balance for sender %s: have %d, need %d",
					tx.Sender[:8], sender.Balance, totalDeduct)
			}
		}

		// Add to receiver's balance
		if receiver, ok := s.accountSet.GetAccount(tx.Receiver); ok {
			newBalance := receiver.Balance + tx.Amount.Uint64()
			if err := s.accountSet.UpdateBalance(tx.Receiver, newBalance); err != nil {
				logger.Warn("Failed to update receiver %s: %v", tx.Receiver, err)
			}
		} else {
			// Create new account for receiver
			if err := s.accountSet.AddAccount(tx.Receiver, tx.Amount.Uint64(), false, block.GetHeight()); err != nil {
				logger.Warn("Failed to add receiver account %s: %v", tx.Receiver, err)
			}
		}
	}

	logger.Debug("Updated account set after block %d", block.GetHeight())
	return nil
}

// GetAccountCount returns the number of accounts in the set.
func (s *Storage) GetAccountCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.accountSet == nil {
		return 0
	}
	return s.accountSet.Count()
}

// ─────────────────────────────────────────────────────────────────────────────
// DEPRECATED UTXO METHODS - Kept for backward compatibility
// ─────────────────────────────────────────────────────────────────────────────

// Deprecated: Use GetAccountSet instead.
func (s *Storage) GetUTXOSet() *types.UTXOSet {
	logger.Warn("GetUTXOSet is deprecated, use GetAccountSet instead")
	return nil
}

// Deprecated: Use UpdateAccountSet instead.
func (s *Storage) UpdateUTXOSet(block *types.Block) error {
	logger.Warn("UpdateUTXOSet is deprecated, use UpdateAccountSet instead")
	return nil
}

// Deprecated: Use GetAccountCount instead.
func (s *Storage) GetUTXOCount() int {
	logger.Warn("GetUTXOCount is deprecated, use GetAccountCount instead")
	return 0
}
