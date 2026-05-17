// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/state_db.go
package core

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/sphinxorg/protocol/src/common"
	database "github.com/sphinxorg/protocol/src/core/state"
	logger "github.com/sphinxorg/protocol/src/log"
)

const (
	accountPrefix  = "acct:"        // LevelDB key prefix for account records
	totalSupplyKey = "supply:total" // LevelDB key for total circulating supply
)

// accountRecord is the JSON shape stored in LevelDB for each address.
// Balance is kept as a decimal string so json.Marshal/Unmarshal round-trips
// correctly without custom big.Int marshaling.
type accountRecord struct {
	Balance string `json:"balance"` // decimal string, nSPX
	Nonce   uint64 `json:"nonce"`
}

// accountEntry is the in-memory mutable form used inside StateDB.
type accountEntry struct {
	balance *big.Int
	nonce   uint64
}

// StateDB is an in-memory account-state cache backed by *database.DB.
// All writes are buffered in `pending` and flushed to LevelDB on Commit().
// Commit() returns a deterministic Merkle root that replaces the placeholder
// StateRoot in block headers.
type StateDB struct {
	mu          sync.RWMutex
	db          *database.DB             // the LevelDB wrapper from src/core/state/database.go
	pending     map[string]*accountEntry // dirty accounts not yet written to disk
	totalSupply *big.Int                 // circulating supply in nSPX
}

// NewStateDB creates a StateDB backed by the given *database.DB.
// Pass bc.storage.GetDB() from blockchain.go (see storage_db.go for GetDB).
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

// dirty returns a mutable *accountEntry for address, copying from storage into
// the pending map the first time so subsequent writes accumulate in memory.
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
// Public read methods
// ----------------------------------------------------------------------------

// GetBalance returns the current balance of address in nSPX.
func (s *StateDB) GetBalance(address string) *big.Int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return new(big.Int).Set(s.load(address).balance)
}

// GetNonce returns the current nonce for address.
func (s *StateDB) GetNonce(address string) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.load(address).nonce
}

// GetTotalSupply returns the current circulating supply in nSPX.
func (s *StateDB) GetTotalSupply() *big.Int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return new(big.Int).Set(s.totalSupply)
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
// The pending cache is cleared after a successful flush.
// The returned []byte should be stored in block.Header.StateRoot.
func (s *StateDB) Commit() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Write each dirty account individually using database.DB.Put.
	// database.DB has no batch API so we call Put per key; for genesis with
	// 14 accounts this is fine. Add a batch method to database.go if needed.
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

	// Persist total supply as a decimal string.
	if err := s.db.Put(totalSupplyKey, []byte(s.totalSupply.String())); err != nil {
		return nil, fmt.Errorf("StateDB.Commit: put total supply: %w", err)
	}

	// Clear dirty cache.
	s.pending = make(map[string]*accountEntry)

	// Compute and return state root.
	stateRoot, err := s.computeStateRoot()
	if err != nil {
		return nil, err
	}

	logger.Info("StateDB committed: state_root=%x total_supply=%s nSPX",
		stateRoot, s.totalSupply.String())
	return stateRoot, nil
}

// computeStateRoot builds a deterministic leaf-hash Merkle root over all
// account records in LevelDB. Leaves are sorted by key before hashing so the
// root is identical regardless of insertion order.
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
