// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/params/commit/types.go
package commit

// ChainParameters defines the Sphinx blockchain identification parameters
type ChainParameters struct {
	ChainID       uint64 `json:"chain_id"`
	ChainName     string `json:"chain_name"`
	Symbol        string `json:"symbol"`
	GenesisTime   int64  `json:"genesis_time"`
	GenesisHash   string `json:"genesis_hash"`
	Version       string `json:"version"`
	MagicNumber   uint32 `json:"magic_number"`
	DefaultPort   uint16 `json:"default_port"`
	BIP44CoinType uint32 `json:"bip44_coin_type"`
	LedgerName    string `json:"ledger_name"`
}
