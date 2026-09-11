// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// Package abi implements the canonical application binary interface used by
// Sphinx native contracts. The first ABI version is canonical JSON rather than
// Ethereum's 32-byte word encoding because native SIP-20 calls already execute
// from contracts.CallSpec JSON. Keeping the encoding here prevents wallets and
// SDKs from hand-rolling incompatible payloads.
package abi

import "fmt"

const SIP20 = "sip20"
const SIP721 = "sip721"

type Argument struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

type Method struct {
	Name   string     `json:"name"`
	Inputs []Argument `json:"inputs"`
}

type Contract struct {
	Name    string   `json:"name"`
	Version uint32   `json:"version"`
	Methods []Method `json:"methods"`
}

// SIP20ABI is the stable client-facing schema for the native SIP-20 runtime.
var SIP20ABI = Contract{
	Name: SIP20, Version: 1,
	Methods: []Method{
		{Name: "mint", Inputs: []Argument{{Name: "to", Type: "address", Required: true}, {Name: "amount", Type: "uint256", Required: true}}},
		{Name: "transfer", Inputs: []Argument{{Name: "to", Type: "address", Required: true}, {Name: "amount", Type: "uint256", Required: true}}},
		{Name: "balance_of", Inputs: []Argument{{Name: "owner", Type: "address", Required: false}}},
		{Name: "info"},
	},
}

// SIP721ABI is the stable client-facing schema for the native SIP-721 runtime.
// Method names mirror contracts/callSIP721 so wallets encode once and every
// node decodes identically: mint/transfer_from/approve/owner_of/token_uri.
var SIP721ABI = Contract{
	Name: SIP721, Version: 1,
	Methods: []Method{
		{Name: "mint", Inputs: []Argument{{Name: "to", Type: "address", Required: true}, {Name: "token_uri", Type: "string", Required: true}, {Name: "mint_id", Type: "string", Required: false}}},
		{Name: "transfer_from", Inputs: []Argument{{Name: "from", Type: "address", Required: true}, {Name: "to", Type: "address", Required: true}, {Name: "token_id", Type: "uint64", Required: true}}},
		{Name: "approve", Inputs: []Argument{{Name: "to", Type: "address", Required: true}, {Name: "token_id", Type: "uint64", Required: true}}},
		{Name: "owner_of", Inputs: []Argument{{Name: "token_id", Type: "uint64", Required: true}}},
		{Name: "token_uri", Inputs: []Argument{{Name: "token_id", Type: "uint64", Required: true}}},
		{Name: "token_id_of_mint", Inputs: []Argument{{Name: "mint_id", Type: "string", Required: true}}},
		{Name: "info"},
	},
}

func (c Contract) Method(name string) (Method, error) {
	for _, method := range c.Methods {
		if method.Name == name {
			return method, nil
		}
	}
	return Method{}, fmt.Errorf("ABI method %q is not defined for %s", name, c.Name)
}
