// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/types.go
package gui

import (
	"math/big"
	"time"

	"github.com/sphinxfndorg/protocol/src/rpc"
)

// WalletClient wraps the RPC client for wallet operations
type WalletClient struct {
	nodeAddr string
	nodeID   rpc.NodeID
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
