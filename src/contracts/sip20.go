// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

func initSIP20(store Store, address, sender string, spec *DeploySpec) error {
	owner := spec.Owner
	if owner == "" {
		owner = sender
	}
	info := &SIP20Info{
		Name:     spec.Name,
		Symbol:   spec.Symbol,
		Decimals: spec.Decimals,
		Owner:    owner,
	}
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return err
	}
	store.SetContractStorage(address, "sip20:info", infoJSON)
	store.SetContractStorage(address, "sip20:total_supply", []byte("0"))

	if spec.InitialSupply != "" && spec.InitialSupply != "0" {
		amount, err := parseAmount(spec.InitialSupply)
		if err != nil {
			return err
		}
		if err := mintSIP20(store, address, owner, amount); err != nil {
			return err
		}
	}
	return nil
}

func callSIP20(store Store, address, caller string, call *CallSpec) (*ExecutionResult, error) {
	switch call.Method {
	case "mint":
		info, err := getSIP20Info(store, address)
		if err != nil {
			return nil, err
		}
		if caller != info.Owner {
			return nil, errors.New("mint requires token owner")
		}
		to := call.Args["to"]
		amount, err := parseAmount(call.Args["amount"])
		if err != nil {
			return nil, err
		}
		if to == "" {
			return nil, errors.New("missing mint recipient")
		}
		if err := mintSIP20(store, address, to, amount); err != nil {
			return nil, err
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method": "mint",
			"to":     to,
			"amount": amount.String(),
		}}, nil

	case "transfer":
		to := call.Args["to"]
		amount, err := parseAmount(call.Args["amount"])
		if err != nil {
			return nil, err
		}
		if to == "" {
			return nil, errors.New("missing transfer recipient")
		}
		if err := transferSIP20(store, address, caller, to, amount); err != nil {
			return nil, err
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method": "transfer",
			"from":   caller,
			"to":     to,
			"amount": amount.String(),
		}}, nil

	case "balance_of":
		owner := call.Args["owner"]
		if owner == "" {
			owner = caller
		}
		bal := getSIP20Balance(store, address, owner)
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":  "balance_of",
			"owner":   owner,
			"balance": bal.String(),
		}}, nil

	case "info":
		info, err := getSIP20Info(store, address)
		if err != nil {
			return nil, err
		}
		total := getSIP20TotalSupply(store, address)
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":       "info",
			"name":         info.Name,
			"symbol":       info.Symbol,
			"decimals":     fmt.Sprintf("%d", info.Decimals),
			"owner":        info.Owner,
			"total_supply": total.String(),
		}}, nil
	}
	return nil, fmt.Errorf("unsupported sip20 method: %s", call.Method)
}

func mintSIP20(store Store, address, to string, amount *big.Int) error {
	if amount.Sign() <= 0 {
		return errors.New("amount must be positive")
	}
	bal := getSIP20Balance(store, address, to)
	bal.Add(bal, amount)
	setSIP20Balance(store, address, to, bal)
	total := getSIP20TotalSupply(store, address)
	total.Add(total, amount)
	store.SetContractStorage(address, "sip20:total_supply", []byte(total.String()))
	return nil
}

func transferSIP20(store Store, address, from, to string, amount *big.Int) error {
	if amount.Sign() <= 0 {
		return errors.New("amount must be positive")
	}
	fromBal := getSIP20Balance(store, address, from)
	if fromBal.Cmp(amount) < 0 {
		return fmt.Errorf("insufficient token balance: have %s need %s", fromBal.String(), amount.String())
	}
	toBal := getSIP20Balance(store, address, to)
	fromBal.Sub(fromBal, amount)
	toBal.Add(toBal, amount)
	setSIP20Balance(store, address, from, fromBal)
	setSIP20Balance(store, address, to, toBal)
	return nil
}

func getSIP20Info(store Store, address string) (*SIP20Info, error) {
	data, err := store.GetContractStorage(address, "sip20:info")
	if err != nil {
		return nil, err
	}
	var info SIP20Info
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func getSIP20Balance(store Store, address, owner string) *big.Int {
	data, err := store.GetContractStorage(address, "sip20:balance:"+owner)
	if err != nil || len(data) == 0 {
		return big.NewInt(0)
	}
	amount, ok := new(big.Int).SetString(string(data), 10)
	if !ok {
		return big.NewInt(0)
	}
	return amount
}

func setSIP20Balance(store Store, address, owner string, amount *big.Int) {
	store.SetContractStorage(address, "sip20:balance:"+owner, []byte(amount.String()))
}

func getSIP20TotalSupply(store Store, address string) *big.Int {
	data, err := store.GetContractStorage(address, "sip20:total_supply")
	if err != nil || len(data) == 0 {
		return big.NewInt(0)
	}
	amount, ok := new(big.Int).SetString(string(data), 10)
	if !ok {
		return big.NewInt(0)
	}
	return amount
}

func parseAmount(value string) (*big.Int, error) {
	if value == "" {
		return nil, errors.New("missing amount")
	}
	amount, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return nil, fmt.Errorf("invalid amount: %s", value)
	}
	if amount.Sign() < 0 {
		return nil, errors.New("amount cannot be negative")
	}
	return amount, nil
}
