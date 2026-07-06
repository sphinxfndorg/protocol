// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

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
}

type SIP20Info struct {
	Name     string `json:"name"`
	Symbol   string `json:"symbol"`
	Decimals uint8  `json:"decimals"`
	Owner    string `json:"owner"`
}
