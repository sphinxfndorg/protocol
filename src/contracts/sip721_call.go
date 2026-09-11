// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func callSIP721(store Store, address, caller string, call *CallSpec) (*ExecutionResult, error) {
	switch call.Method {
	case "mint":
		to := strings.TrimSpace(call.Args["to"])
		tokenURI := strings.TrimSpace(call.Args["token_uri"])
		if tokenURI == "" {
			tokenURI = strings.TrimSpace(call.Args["uri"])
		}
		mintID := strings.TrimSpace(call.Args["mint_id"])
		if to == "" {
			return nil, errors.New("missing mint recipient")
		}
		if tokenURI == "" {
			return nil, errors.New("missing token_uri: mint requires a real IPFS tokenURI")
		}
		tokenID, err := mintSIP721(store, address, caller, to, tokenURI, mintID)
		if err != nil {
			return nil, err
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":    "mint",
			"to":        to,
			"token_id":  strconv.FormatUint(tokenID, 10),
			"token_uri": tokenURI,
			"mint_id":   mintID,
		}}, nil
	case "transfer_from":
		from := strings.TrimSpace(call.Args["from"])
		to := strings.TrimSpace(call.Args["to"])
		tokenID, err := parseSIP721TokenID(call.Args["token_id"])
		if err != nil {
			return nil, err
		}
		if from == "" || to == "" {
			return nil, errors.New("missing transfer_from addresses")
		}
		if err := transferSIP721(store, address, caller, from, to, tokenID); err != nil {
			return nil, err
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":   "transfer_from",
			"from":     from,
			"to":       to,
			"token_id": strconv.FormatUint(tokenID, 10),
		}}, nil
	case "approve":
		approved := strings.TrimSpace(call.Args["to"])
		if approved == "" {
			approved = strings.TrimSpace(call.Args["approved"])
		}
		tokenID, err := parseSIP721TokenID(call.Args["token_id"])
		if err != nil {
			return nil, err
		}
		if approved == "" {
			return nil, errors.New("missing approve address")
		}
		if err := approveSIP721(store, address, caller, approved, tokenID); err != nil {
			return nil, err
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":   "approve",
			"approved": approved,
			"token_id": strconv.FormatUint(tokenID, 10),
		}}, nil
	case "owner_of":
		tokenID, err := parseSIP721TokenID(call.Args["token_id"])
		if err != nil {
			return nil, err
		}
		owner := getSIP721Owner(store, address, tokenID)
		if owner == "" {
			return nil, fmt.Errorf("token %d does not exist", tokenID)
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":   "owner_of",
			"owner":    owner,
			"token_id": strconv.FormatUint(tokenID, 10),
		}}, nil
	case "token_uri":
		tokenID, err := parseSIP721TokenID(call.Args["token_id"])
		if err != nil {
			return nil, err
		}
		uri, err := store.GetContractStorage(address, sip721TokenURIKey(tokenID))
		if err != nil || len(uri) == 0 {
			return nil, fmt.Errorf("token %d does not exist", tokenID)
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":    "token_uri",
			"token_uri": string(uri),
			"token_id":  strconv.FormatUint(tokenID, 10),
		}}, nil
	case "token_id_of_mint":
		mintID := strings.TrimSpace(call.Args["mint_id"])
		if mintID == "" {
			return nil, errors.New("missing mint_id")
		}
		raw, err := store.GetContractStorage(address, sip721MintTokenKey(mintID))
		if err != nil || len(raw) == 0 {
			return nil, fmt.Errorf("mint_id %s not anchored on this contract", mintID)
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":   "token_id_of_mint",
			"mint_id":  mintID,
			"token_id": string(raw),
		}}, nil
	case "info":
		info, err := getSIP721Info(store, address)
		if err != nil {
			return nil, err
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":        "info",
			"name":          info.Name,
			"symbol":        info.Symbol,
			"owner":         info.Owner,
			"next_token_id": strconv.FormatUint(info.NextTokenID, 10),
		}}, nil
	}
	return nil, fmt.Errorf("unsupported sip721 method: %s", call.Method)
}
