// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/transaction/accounts.go
package types

import (
	"errors"
	"fmt"
	"math/big"

	params "github.com/sphinxfndorg/protocol/src/params/denom"
)

const (
	SPX = 1e18 // 1 SPX equals 1e18 nSPX (10^18)
)

// getSPX retrieves the SPX multiplier from the params package
func getSPX() *big.Int {
	return big.NewInt(params.SPX)
}

// NewAccountSet creates a new empty account set.
func NewAccountSet() *AccountSet {
	return &AccountSet{
		accounts:    make(map[string]*AccountState),
		totalSupply: big.NewInt(0),
	}
}

// AddAccount adds a new account to the account set.
func (s *AccountSet) AddAccount(address string, balance uint64, coinbase bool, height uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if account already exists
	if _, exists := s.accounts[address]; exists {
		return fmt.Errorf("account %s already exists", address)
	}

	// Check maximum supply
	maxSupply := new(big.Int)
	_, ok := maxSupply.SetString(fmt.Sprintf("%.0f", params.MaximumSupply*SPX), 10)
	if !ok {
		return errors.New("failed to set maximum supply")
	}

	amountInSPX := new(big.Int).SetUint64(balance)
	if new(big.Int).Add(s.totalSupply, amountInSPX).Cmp(maxSupply) > 0 {
		return errors.New("exceeding maximum SPX supply")
	}

	s.accounts[address] = &AccountState{
		Address:  address,
		Balance:  balance,
		Nonce:    0,
		Coinbase: coinbase,
		Height:   height,
		Spent:    false,
	}

	s.totalSupply.Add(s.totalSupply, amountInSPX)
	return nil
}

// GetAccount returns the account state for an address.
func (s *AccountSet) GetAccount(address string) (*AccountState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	account, ok := s.accounts[address]
	return account, ok
}

// UpdateBalance updates the balance of an account.
func (s *AccountSet) UpdateBalance(address string, newBalance uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	account, ok := s.accounts[address]
	if !ok {
		return fmt.Errorf("account %s does not exist", address)
	}

	account.Balance = newBalance
	return nil
}

// IncrementNonce increments the nonce of an account.
func (s *AccountSet) IncrementNonce(address string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if account, ok := s.accounts[address]; ok {
		account.Nonce++
	}
}

// MarkSpent marks an account as spent.
func (s *AccountSet) MarkSpent(address string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if account, ok := s.accounts[address]; ok {
		account.Spent = true
	}
}

// IsSpendable checks whether an account can be spent from.
func (s *AccountSet) IsSpendable(address string, currentHeight uint64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	account, ok := s.accounts[address]
	if !ok || account.Spent {
		return false
	}
	// Coinbase accounts need 100 block maturity
	if account.Coinbase && currentHeight < account.Height+100 {
		return false
	}
	return true
}

// Range iterates over all accounts, calling fn for each.
func (s *AccountSet) Range(fn func(string, *AccountState) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for address, account := range s.accounts {
		if !fn(address, account) {
			break
		}
	}
}

// All returns all accounts as a slice.
func (s *AccountSet) All() []*AccountState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*AccountState, 0, len(s.accounts))
	for _, account := range s.accounts {
		result = append(result, account)
	}
	return result
}

// AllMap returns a copy of the accounts map for iteration.
func (s *AccountSet) AllMap() map[string]*AccountState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]*AccountState, len(s.accounts))
	for k, v := range s.accounts {
		result[k] = v
	}
	return result
}

// Count returns the total number of accounts.
func (s *AccountSet) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.accounts)
}

// GetTotalSupply returns the total supply in nSPX.
func (s *AccountSet) GetTotalSupply() *big.Int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return new(big.Int).Set(s.totalSupply)
}
