// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/types.go
package gui

import (
	"math/big"
	"time"
)

// WalletClient wraps the RPC client for wallet operations.
//
// nodeAddr must be the node's P2P TCP address (see rpc.CallRPC's doc
// comment in client.go for why) — there is deliberately no NodeID field
// here anymore: rpc.CallRPC now speaks standard JSON-RPC 2.0 over an
// encrypted, handshake-authenticated TCP connection, which has no place
// for a NodeID field the way the old custom binary Message protocol did.
type WalletClient struct {
	nodeAddr string
}

// BalanceResponse represents balance result
type BalanceResponse struct {
	Address  string   `json:"address"`
	Balance  *big.Int `json:"balance"`
	Pending  *big.Int `json:"pending"`
	Unlocked *big.Int `json:"unlocked"`
}

// TransactionResponse represents a transaction
type TransactionResponse struct {
	TxID      string    `json:"txid"`
	Sender    string    `json:"sender"`
	Receiver  string    `json:"receiver"`
	Amount    *big.Int  `json:"amount"`
	Fee       *big.Int  `json:"fee"`
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
}
