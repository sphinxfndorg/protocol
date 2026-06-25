// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/transaction/contract.go
package types

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/sphinxorg/protocol/src/common"
)

// CreateContract creates a contract between Alice and Bob based on the validated note.
// Now uses account-based model instead of UTXO.
func CreateContract(note *Note, amountInSPX float64, accountSet *AccountSet, address string, height uint64) (*Contract, error) {
	// Validate amountInSPX to be non-negative
	if amountInSPX < 0 {
		return nil, errors.New("amountInSPX must be non-negative")
	}

	// Validate Timestamp to ensure it's not unrealistic
	if note.Timestamp <= 0 {
		return nil, errors.New("invalid timestamp")
	}

	// Check if account is spendable using the new validation
	if !ValidateAccountSpendability(accountSet, address, height) {
		return nil, errors.New("account is not spendable")
	}

	// Get the account to verify balance
	account, ok := accountSet.GetAccount(address)
	if !ok {
		return nil, errors.New("account not found")
	}

	// Convert amountInSPX to nSPX (big.Int)
	spxMultiplier := getSPX()
	amountRat := new(big.Rat).SetFloat64(amountInSPX)
	amountRat.Mul(amountRat, new(big.Rat).SetInt(spxMultiplier))

	// Convert to big.Int with 1e18 precision
	multiplier := big.NewRat(1e18, 1)
	amountRat.Mul(amountRat, multiplier)
	amount := new(big.Int)
	amount.Set(amountRat.Num())

	// Calculate fee as a big.Int
	feeRat := new(big.Rat).SetFloat64(note.Fee)
	feeRat.Mul(feeRat, amountRat)
	fee := new(big.Int)
	fee.Set(feeRat.Num())

	// Check if account has enough balance
	balanceBig := new(big.Int).SetUint64(account.Balance)
	totalCost := new(big.Int).Add(amount, fee)
	if balanceBig.Cmp(totalCost) < 0 {
		return nil, fmt.Errorf("insufficient balance: have %d, need %s", account.Balance, totalCost.String())
	}

	// Deduct from sender's balance
	newBalance := new(big.Int).Sub(balanceBig, totalCost)
	if err := accountSet.UpdateBalance(address, newBalance.Uint64()); err != nil {
		return nil, fmt.Errorf("failed to update balance: %v", err)
	}

	// Increment nonce
	accountSet.IncrementNonce(address)

	contract := &Contract{
		Sender:    note.From,
		Receiver:  note.To,
		Amount:    amount,
		Fee:       fee,
		Storage:   note.Storage,
		Timestamp: note.Timestamp,
	}

	return contract, nil
}

// CreateAddress generates a unique contract address using sender, recipient, and nonce.
func (v *Validator) CreateAddress(nonce int64) (string, error) {
	contractData := fmt.Sprintf("%s-%s-%d", v.senderAddress, v.recipientAddress, nonce)
	hash := common.SpxHash([]byte(contractData))
	address, err := common.Address(hash)
	if err != nil {
		return "", err
	}
	return address, nil
}
