// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"fmt"
	"math/big"
)

// Vault is a native contract for depositing and withdrawing SIP-20 tokens
type Vault struct{}

// initVault initializes a vault contract's storage
func initVault(store Store, address, sender string, spec *DeploySpec) error {
	store.SetContractStorage(address, "vault:total", []byte("0"))
	return nil
}

// callVault dispatches vault contract method calls
func callVault(store Store, address, caller string, call *CallSpec) (*ExecutionResult, error) {
	switch call.Method {
	case "deposit":
		return vaultDeposit(store, address, caller, call)
	case "withdraw":
		return vaultWithdraw(store, address, caller, call)
	case "balance_of":
		return vaultBalanceOf(store, address, caller, call)
	default:
		return nil, fmt.Errorf("unknown vault method: %s", call.Method)
	}
}

// vaultContractRegistration provides the init/call functions for contract registration
var vaultContractRegistration = struct {
	Init  func(Store, string, string, *DeploySpec) error
	Call  func(Store, string, string, *CallSpec) (*ExecutionResult, error)
}{
	Init:  initVault,
	Call:  callVault,
}

// Ensure the registration is used
var _ = vaultContractRegistration

func vaultDeposit(store Store, address, caller string, call *CallSpec) (*ExecutionResult, error) {
	tokenContract := call.Args["token_contract"]
	if tokenContract == "" {
		return nil, fmt.Errorf("missing token_contract")
	}

	amountStr := call.Args["amount"]
	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok || amount.Sign() <= 0 {
		return nil, fmt.Errorf("invalid amount")
	}

	userBalance := getSIP20Balance(store, tokenContract, caller)
	if userBalance.Cmp(amount) < 0 {
		return nil, fmt.Errorf("insufficient balance")
	}

	tokenCall := &CallSpec{
		Method: "transfer",
		Args: map[string]string{
			"to":     address,
			"amount": amount.String(),
		},
	}

	result, err := callSIP20(store, tokenContract, caller, tokenCall)
	if err != nil || result.Status != "ok" {
		return nil, fmt.Errorf("transfer failed")
	}

	newBalance := new(big.Int).Add(getVaultBalance(store, address, caller), amount)
	setVaultBalance(store, address, caller, newBalance)
	newTotal := new(big.Int).Add(getVaultTotal(store, address), amount)
	setVaultTotal(store, address, newTotal)

	return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
		"method": "deposit", "amount": amount.String(), "new_balance": newBalance.String(),
	}}, nil
}

func vaultWithdraw(store Store, address, caller string, call *CallSpec) (*ExecutionResult, error) {
	amountStr := call.Args["amount"]
	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok || amount.Sign() <= 0 {
		return nil, fmt.Errorf("invalid amount")
	}

	tokenContract := call.Args["token_contract"]
	if tokenContract == "" {
		return nil, fmt.Errorf("missing token_contract")
	}

	userBalance := getVaultBalance(store, address, caller)
	if userBalance.Cmp(amount) < 0 {
		return nil, fmt.Errorf("insufficient vault balance")
	}

	newBalance := new(big.Int).Sub(userBalance, amount)
	setVaultBalance(store, address, caller, newBalance)
	newTotal := new(big.Int).Sub(getVaultTotal(store, address), amount)
	setVaultTotal(store, address, newTotal)

	tokenCall := &CallSpec{
		Method: "transfer",
		Args: map[string]string{
			"to":     caller,
			"amount": amount.String(),
		},
	}

	result, err := callSIP20(store, tokenContract, caller, tokenCall)
	if err != nil || result.Status != "ok" {
		return nil, fmt.Errorf("transfer failed")
	}

	return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
		"method": "withdraw", "amount": amount.String(), "new_balance": newBalance.String(),
	}}, nil
}

func vaultBalanceOf(store Store, address, caller string, call *CallSpec) (*ExecutionResult, error) {
	owner := call.Args["owner"]
	if owner == "" {
		owner = caller
	}
	return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
		"method": "balance_of", "owner": owner, "balance": getVaultBalance(store, address, owner).String(),
	}}, nil
}

func getVaultBalance(store Store, vaultAddress, user string) *big.Int {
	value, _ := store.GetContractStorage(vaultAddress, fmt.Sprintf("vault:balance:%s", user))
	if len(value) == 0 {
		return big.NewInt(0)
	}
	b, _ := new(big.Int).SetString(string(value), 10)
	return b
}

func setVaultBalance(store Store, vaultAddress, user string, balance *big.Int) {
	store.SetContractStorage(vaultAddress, fmt.Sprintf("vault:balance:%s", user), []byte(balance.String()))
}

func getVaultTotal(store Store, vaultAddress string) *big.Int {
	value, _ := store.GetContractStorage(vaultAddress, "vault:total")
	if len(value) == 0 {
		return big.NewInt(0)
	}
	t, _ := new(big.Int).SetString(string(value), 10)
	return t
}

func setVaultTotal(store Store, vaultAddress string, total *big.Int) {
	store.SetContractStorage(vaultAddress, "vault:total", []byte(total.String()))
}