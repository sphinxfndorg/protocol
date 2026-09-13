// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/types.go
package gui

import (
	"fmt"
	"math/big"
	"strings"
	"time"
)

// BigInt wraps *big.Int with JSON unmarshaling that accepts scientific
// notation (e.g. "1e+24") in addition to plain decimal strings. The node's
// gettransactionhistory RPC returns large nSPX amounts in scientific
// notation, which the standard big.Int UnmarshalText rejects.
type BigInt struct {
	*big.Int
}

// UnmarshalJSON accepts either a JSON string ("12345" or "1e+24") or a JSON
// number (12345). Scientific notation is parsed via big.Float and truncated
// to an integer, matching how the node quantizes nSPX values.
func (b *BigInt) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))

	// Handle JSON null
	if s == "null" || s == "" {
		b.Int = new(big.Int)
		return nil
	}

	// Strip surrounding quotes if the value is a JSON string
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}

	// Fast path: plain decimal integer string
	if i, ok := new(big.Int).SetString(s, 10); ok {
		b.Int = i
		return nil
	}

	// Slow path: scientific notation (e.g. "1e+24", "1.5e+20")
	f, _, err := big.ParseFloat(s, 10, 256, big.ToNearestEven)
	if err != nil {
		return fmt.Errorf("cannot parse big integer %q: %w", s, err)
	}
	b.Int, _ = f.Int(nil)
	if b.Int == nil {
		b.Int = new(big.Int)
	}
	return nil
}

func (b BigInt) MarshalJSON() ([]byte, error) {
	if b.Int == nil {
		return []byte("null"), nil
	}
	return fmt.Appendf(nil, "%q", b.Int.String()), nil
}

// WalletClient wraps the RPC client for wallet operations.
//
// ★ NODE-TYPE CONTRACT: the USI wallet is a LIGHTWEIGHT client, NOT a vault
// full node. It holds no blockchain and downloads no block bodies. Full
// chains are synced entirely by full nodes via src/core/sync.go
// (SyncManager → handleSyncingBlocks/pipelined bulk download, started by
// bind.StartNode). A lightweight wallet like USI instead talks to a full
// node's JSON-RPC and — when it needs any chain data at all — pulls block
// HEADERS only (see GetChainTipHeader / GetBlockHeader / GetHeaders).
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
	Address  string `json:"address"`
	Balance  BigInt `json:"balance"`
	Pending  BigInt `json:"pending"`
	Unlocked BigInt `json:"unlocked"`
}

// TransactionResponse represents a transaction
type TransactionResponse struct {
	TxID      string    `json:"txid"`
	Sender    string    `json:"sender"`
	Receiver  string    `json:"receiver"`
	Amount    BigInt    `json:"amount"`
	Fee       BigInt    `json:"fee"`
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
}
