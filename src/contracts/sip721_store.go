// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

func mintSIP721(store Store, address, caller, to, tokenURI, mintID string) (uint64, error) {
	info, err := getSIP721Info(store, address)
	if err != nil {
		return 0, err
	}
	if caller != info.Owner {
		return 0, errors.New("mint requires collection owner")
	}
	tokenID := info.NextTokenID
	if tokenID == 0 {
		tokenID = 1
	}
	info.NextTokenID = tokenID + 1
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return 0, err
	}
	store.SetContractStorage(address, sip721InfoKey(), infoJSON)
	store.SetContractStorage(address, sip721TokenOwnerKey(tokenID), []byte(to))
	store.SetContractStorage(address, sip721TokenURIKey(tokenID), []byte(tokenURI))
	if mintID != "" {
		if existing, err := store.GetContractStorage(address, sip721MintTokenKey(mintID)); err == nil && len(existing) > 0 {
			return 0, fmt.Errorf("mint_id %s already anchored as token %s", mintID, string(existing))
		}
		store.SetContractStorage(address, sip721TokenMintKey(tokenID), []byte(mintID))
		store.SetContractStorage(address, sip721MintTokenKey(mintID), []byte(strconv.FormatUint(tokenID, 10)))
	}
	return tokenID, nil
}

func transferSIP721(store Store, address, caller, from, to string, tokenID uint64) error {
	owner := getSIP721Owner(store, address, tokenID)
	if owner == "" {
		return fmt.Errorf("token %d does not exist", tokenID)
	}
	if owner != from {
		return fmt.Errorf("transfer_from: token %d owned by %s, not %s", tokenID, owner, from)
	}
	if caller != owner {
		approved, _ := store.GetContractStorage(address, sip721ApprovalKey(tokenID))
		if string(approved) != caller {
			return fmt.Errorf("transfer_from: caller %s is neither owner nor approved", caller)
		}
	}
	store.SetContractStorage(address, sip721TokenOwnerKey(tokenID), []byte(to))
	store.SetContractStorage(address, sip721ApprovalKey(tokenID), []byte{})
	return nil
}

func approveSIP721(store Store, address, caller, approved string, tokenID uint64) error {
	owner := getSIP721Owner(store, address, tokenID)
	if owner == "" {
		return fmt.Errorf("token %d does not exist", tokenID)
	}
	if caller != owner {
		return errors.New("approve requires token owner")
	}
	store.SetContractStorage(address, sip721ApprovalKey(tokenID), []byte(approved))
	return nil
}

func getSIP721Owner(store Store, address string, tokenID uint64) string {
	data, err := store.GetContractStorage(address, sip721TokenOwnerKey(tokenID))
	if err != nil || len(data) == 0 {
		return ""
	}
	return string(data)
}

func getSIP721Info(store Store, address string) (*SIP721Info, error) {
	data, err := store.GetContractStorage(address, sip721InfoKey())
	if err != nil {
		return nil, err
	}
	var info SIP721Info
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func parseSIP721TokenID(value string) (uint64, error) {
	v := ""
	for _, r := range value {
		if r == ' ' || r == '\t' || r == '\n' {
			continue
		}
		v += string(r)
	}
	if v == "" {
		return 0, errors.New("missing token_id")
	}
	id, err := strconv.ParseUint(v, 10, 64)
	if err != nil || id == 0 {
		return 0, fmt.Errorf("invalid token_id: %s", value)
	}
	return id, nil
}
