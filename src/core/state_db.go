// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/state_db.go
package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/sphinxorg/protocol/src/common"
	database "github.com/sphinxorg/protocol/src/core/state"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	logger "github.com/sphinxorg/protocol/src/log"
	"github.com/sphinxorg/protocol/src/pool"
)

const (
	accountPrefix  = "acct:"
	totalSupplyKey = "supply:total"
)

// Ensure StateDB implements pool.StateDB
var _ pool.StateDB = (*StateDB)(nil)

// Close implements pool.StateDB - closes the underlying database connection
func (db *StateDB) Close() error {
	if db.db != nil {
		return db.db.Close()
	}
	return nil
}

// GetLastTransactionTimestamp implements pool.StateDB
func (db *StateDB) GetLastTransactionTimestamp(address string) (int64, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// For now, return 0 (no previous transactions)
	// In a real implementation, you would store the last timestamp per address
	// and retrieve it from the state
	return 0, nil
}

// GetLastNonce implements pool.StateDB
func (db *StateDB) GetLastNonce(address string) (uint64, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// Load the account entry
	entry := db.load(address)
	if entry == nil {
		return 0, nil // No previous transactions
	}

	// Get the last nonce from the account
	// For now, return the current nonce (which represents the last used nonce + 1)
	// If you want the last used nonce, subtract 1
	nonce := entry.nonce
	if nonce > 0 {
		return nonce - 1, nil // Return the last used nonce
	}
	return 0, nil // No previous transactions
}

// NewStateDB creates a StateDB backed by the given *database.DB.
func NewStateDB(db *database.DB) *StateDB {
	s := &StateDB{
		db:          db,
		pending:     make(map[string]*accountEntry),
		totalSupply: big.NewInt(0),
	}
	// Restore persisted total supply (stored as decimal string)
	if data, err := db.Get(totalSupplyKey); err == nil && len(data) > 0 {
		n, ok := new(big.Int).SetString(string(data), 10)
		if ok {
			s.totalSupply.Set(n)
		}
	}
	return s
}

// SetBlockchain sets the blockchain reference for mempool access.
func (s *StateDB) SetBlockchain(bc *Blockchain) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockchain = bc
}

// ----------------------------------------------------------------------------
// Internal helpers
// ----------------------------------------------------------------------------

// load returns the accountEntry for address, checking the dirty cache first,
// then LevelDB, then returning a zeroed entry for new addresses.
func (s *StateDB) load(address string) *accountEntry {
	if e, ok := s.pending[address]; ok {
		return e
	}
	key := accountPrefix + address
	data, err := s.db.Get(key)
	if err != nil || len(data) == 0 {
		return &accountEntry{balance: big.NewInt(0)}
	}
	var rec accountRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		logger.Warn("StateDB: unmarshal %s: %v", address, err)
		return &accountEntry{balance: big.NewInt(0)}
	}
	bal, ok := new(big.Int).SetString(rec.Balance, 10)
	if !ok {
		bal = big.NewInt(0)
	}
	return &accountEntry{balance: bal, nonce: rec.Nonce}
}

// dirty returns a mutable *accountEntry for address.
func (s *StateDB) dirty(address string) *accountEntry {
	if e, ok := s.pending[address]; ok {
		return e
	}
	src := s.load(address)
	e := &accountEntry{
		balance: new(big.Int).Set(src.balance),
		nonce:   src.nonce,
	}
	s.pending[address] = e
	return e
}

// ----------------------------------------------------------------------------
// Public read methods - Core Account State
// ----------------------------------------------------------------------------

// GetBalance returns the current balance of address in nSPX.
func (s *StateDB) GetBalance(address string) (*big.Int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if address == "" {
		return nil, errors.New("address cannot be empty")
	}
	return new(big.Int).Set(s.load(address).balance), nil
}

// GetNonce returns the current nonce for address.
func (s *StateDB) GetNonce(address string) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if address == "" {
		return 0, errors.New("address cannot be empty")
	}
	return s.load(address).nonce, nil
}

// GetTotalSupply returns the current circulating supply in nSPX.
func (s *StateDB) GetTotalSupply() *big.Int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return new(big.Int).Set(s.totalSupply)
}

// GetBalanceResult returns the confirmed, pending, and unlocked balance for an address.
func (s *StateDB) GetBalanceResult(address string) (*pool.BalanceResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if address == "" {
		return nil, errors.New("address cannot be empty")
	}

	result := &pool.BalanceResult{
		Confirmed: big.NewInt(0),
		Pending:   big.NewInt(0),
		Unlocked:  big.NewInt(0),
	}

	// Get confirmed balance from StateDB
	balanceNSPX := s.load(address).balance
	if balanceNSPX != nil {
		result.Confirmed.Set(balanceNSPX)
		result.Unlocked.Set(balanceNSPX)
	}

	// Check mempool for pending transactions
	if s.blockchain != nil && s.blockchain.mempool != nil {
		for _, tx := range s.blockchain.mempool.GetPendingTransactions() {
			if tx == nil {
				continue
			}
			if tx.Sender == address {
				amount := tx.Amount
				gasFee := tx.GetGasFee()
				totalOut := new(big.Int).Add(amount, gasFee)
				if result.Pending.Cmp(totalOut) < 0 {
					result.Pending.SetInt64(0)
				} else {
					result.Pending.Sub(result.Pending, totalOut)
				}
			}
			if tx.Receiver == address {
				result.Pending.Add(result.Pending, tx.Amount)
			}
		}
	}

	return result, nil
}

// GetTransactionHistory returns recent transactions involving the given address.
func (s *StateDB) GetTransactionHistory(address string, limit int) ([]*types.Transaction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if address == "" {
		return nil, errors.New("address cannot be empty")
	}
	if limit <= 0 {
		limit = 20
	}

	var txs []*types.Transaction
	txMap := make(map[string]bool)

	if s.blockchain == nil {
		return txs, nil
	}

	// Search blocks from newest to oldest
	height := s.blockchain.GetBlockCount()
	blocksScanned := uint64(0)
	maxBlocksToScan := uint64(1000)

	for height > 0 && len(txs) < limit && blocksScanned < maxBlocksToScan {
		block := s.blockchain.GetBlockByNumber(height)
		if block == nil {
			height--
			continue
		}

		for i := len(block.Body.TxsList) - 1; i >= 0; i-- {
			tx := block.Body.TxsList[i]
			if tx == nil {
				continue
			}
			if tx.Sender == address || tx.Receiver == address {
				if !txMap[tx.ID] {
					txMap[tx.ID] = true
					txs = append(txs, tx)
					if len(txs) >= limit {
						break
					}
				}
			}
		}
		height--
		blocksScanned++
	}

	// Check mempool for pending transactions
	if s.blockchain.mempool != nil {
		for _, tx := range s.blockchain.mempool.GetPendingTransactions() {
			if tx == nil {
				continue
			}
			if (tx.Sender == address || tx.Receiver == address) && len(txs) < limit {
				if !txMap[tx.ID] {
					txMap[tx.ID] = true
					txs = append(txs, tx)
				}
			}
		}
	}

	// Sort by timestamp descending (newest first)
	sort.Slice(txs, func(i, j int) bool {
		return txs[i].Timestamp > txs[j].Timestamp
	})

	logger.Debug("GetTransactionHistory(%s): found %d transactions",
		address[:16]+"...", len(txs))

	return txs, nil
}

// ----------------------------------------------------------------------------
// Public write methods (buffered — flushed on Commit)
// ----------------------------------------------------------------------------

// SetBalance sets the balance of address to amount (nSPX).
// Used during genesis to credit allocations.
func (s *StateDB) SetBalance(address string, amount *big.Int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty(address).balance = new(big.Int).Set(amount)
}

// AddBalance adds amount (nSPX) to address. No-op for zero/nil amount.
func (s *StateDB) AddBalance(address string, amount *big.Int) {
	if amount == nil || amount.Sign() <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.dirty(address)
	e.balance.Add(e.balance, amount)
}

// SubBalance subtracts amount (nSPX) from address.
// Returns an error if the resulting balance would be negative.
func (s *StateDB) SubBalance(address string, amount *big.Int) error {
	if amount == nil || amount.Sign() <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.dirty(address)
	if e.balance.Cmp(amount) < 0 {
		return fmt.Errorf("insufficient balance: %s has %s nSPX, needs %s nSPX",
			address, e.balance.String(), amount.String())
	}
	e.balance.Sub(e.balance, amount)
	return nil
}

// IncrementNonce adds 1 to the nonce of address.
func (s *StateDB) IncrementNonce(address string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty(address).nonce++
}

// IncrementTotalSupply adds amount to the tracked circulating supply.
func (s *StateDB) IncrementTotalSupply(amount *big.Int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totalSupply.Add(s.totalSupply, amount)
}

// ----------------------------------------------------------------------------
// Commit
// ----------------------------------------------------------------------------

// Commit flushes all pending writes to LevelDB and returns the new state root.
func (s *StateDB) Commit() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for address, e := range s.pending {
		rec := accountRecord{
			Balance: e.balance.String(),
			Nonce:   e.nonce,
		}
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, fmt.Errorf("StateDB.Commit: marshal %s: %w", address, err)
		}
		if err := s.db.Put(accountPrefix+address, data); err != nil {
			return nil, fmt.Errorf("StateDB.Commit: put %s: %w", address, err)
		}
	}

	if err := s.db.Put(totalSupplyKey, []byte(s.totalSupply.String())); err != nil {
		return nil, fmt.Errorf("StateDB.Commit: put total supply: %w", err)
	}

	s.pending = make(map[string]*accountEntry)

	stateRoot, err := s.computeStateRoot()
	if err != nil {
		return nil, err
	}

	logger.Info("StateDB committed: state_root=%x total_supply=%s nSPX",
		stateRoot, s.totalSupply.String())
	return stateRoot, nil
}

// computeStateRoot builds a deterministic leaf-hash Merkle root over all
// account records in LevelDB.
func (s *StateDB) computeStateRoot() ([]byte, error) {
	keys, err := s.db.ListKeysWithPrefix(accountPrefix)
	if err != nil {
		return nil, fmt.Errorf("computeStateRoot: %w", err)
	}
	if len(keys) == 0 {
		return common.SpxHash([]byte("empty-state")), nil
	}

	sort.Strings(keys)

	leaves := make([][]byte, 0, len(keys))
	for _, k := range keys {
		data, err := s.db.Get(k)
		if err != nil {
			continue
		}
		leaves = append(leaves, common.SpxHash(append([]byte(k), data...)))
	}

	return merkleRootFromLeaves(leaves), nil
}
