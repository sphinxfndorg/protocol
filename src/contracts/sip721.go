// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"encoding/json"
	"fmt"
	"strings"
)

type SIP721Info struct {
	Name        string `json:"name"`
	Symbol      string `json:"symbol"`
	Owner       string `json:"owner"`
	NextTokenID uint64 `json:"next_token_id"`
}

func sip721InfoKey() string { return "sip721:info" }
func sip721TokenOwnerKey(tokenID uint64) string {
	return fmt.Sprintf("sip721:token:%d:owner", tokenID)
}
func sip721TokenURIKey(tokenID uint64) string {
	return fmt.Sprintf("sip721:token:%d:uri", tokenID)
}
func sip721TokenMintKey(tokenID uint64) string {
	return fmt.Sprintf("sip721:token:%d:mint", tokenID)
}
func sip721MintTokenKey(mintID string) string { return "sip721:mint:" + mintID }
func sip721ApprovalKey(tokenID uint64) string {
	return fmt.Sprintf("sip721:approval:%d", tokenID)
}

func initSIP721(store Store, address, sender string, spec *DeploySpec) error {
	owner := strings.TrimSpace(spec.Owner)
	if owner == "" {
		owner = sender
	}
	info := &SIP721Info{
		Name:        strings.TrimSpace(spec.Name),
		Symbol:      strings.ToUpper(strings.TrimSpace(spec.Symbol)),
		Owner:       owner,
		NextTokenID: 1,
	}
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return err
	}
	store.SetContractStorage(address, sip721InfoKey(), infoJSON)
	return nil
}
