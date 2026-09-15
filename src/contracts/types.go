// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import "math/big"

type Store interface {
	ContractExists(address string) bool
	SetContractCode(address string, code []byte)
	GetContractCode(address string) ([]byte, error)
	SetContractMeta(address string, meta []byte)
	GetContractMeta(address string) ([]byte, error)
	SetContractStorage(address, key string, value []byte)
	GetContractStorage(address, key string) ([]byte, error)
}

type ContractMeta struct {
	Address   string `json:"address"`
	Creator   string `json:"creator"`
	Runtime   string `json:"runtime"`
	Standard  string `json:"standard"`
	CreatedAt int64  `json:"created_at"`
}

type DeploySpec struct {
	Runtime       string `json:"runtime"`
	Standard      string `json:"standard"`
	Name          string `json:"name,omitempty"`
	Symbol        string `json:"symbol,omitempty"`
	Decimals      uint8  `json:"decimals,omitempty"`
	Owner         string `json:"owner,omitempty"`
	InitialSupply string `json:"initial_supply,omitempty"`
}

type CallSpec struct {
	Method string            `json:"method"`
	Args   map[string]string `json:"args,omitempty"`
}

type ExecutionResult struct {
	ContractAddress string            `json:"contract_address,omitempty"`
	Status          string            `json:"status"`
	Return          map[string]string `json:"return,omitempty"`
	Events          []ContractEvent   `json:"events,omitempty"`
}

// ContractEvent is immutable execution output. Its transaction-scoped key is
// assigned by core before it is committed to StateDB.
type ContractEvent struct {
	Topic string `json:"topic"`
	Data  string `json:"data"`
}

// NativeCallContext hands the native runtime the consensus value carried by the
// calling transaction (tx.Amount — already escrowed at the contract address by
// the executor) plus a balance-movement callback anchored at that contract.
// Native standards (e.g. SIP-721 resale royalties and license fees) split the
// escrow the same deterministic, atomically-buffered way the SVM/WASM
// host-call surface does.
//
// PriceFloor is the policy minimum sale value used to price resale royalties:
// royalty applies to max(amount, floor), which makes settling at dust prices
// cost the evaders real royalties instead of being free. nil disables the
// floor.
type NativeCallContext struct {
	Value      *big.Int                               // tx.Amount as seen at execution
	PriceFloor *big.Int                               // policy MinTokenSaleValue; nil = none
	Transfer   func(to string, amount *big.Int) error // contract address -> to
}

type SIP20Info struct {
	Name     string `json:"name"`
	Symbol   string `json:"symbol"`
	Decimals uint8  `json:"decimals"`
	Owner    string `json:"owner"`
}
