// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MempoolCounts mirrors the pool object of the node's gettransactionreceipt
// response (JSONRPCHandler.getTransactionReceipt, src/rpc/json.go).
type MempoolCounts struct {
	Broadcast  uint64 `json:"broadcast"`
	Validating uint64 `json:"validating"`
	Pending    uint64 `json:"pending"`
	Invalid    uint64 `json:"invalid"`
	Total      uint64 `json:"total"`
}

// TxReceipt is the node's gettransactionreceipt response, field for field. The
// node reports a transaction as committed only through Confirmed/Height/
// BlockHash, and a receipt that is neither confirmed nor invalid is
// indistinguishable from a txid the node has never seen.
type TxReceipt struct {
	TxID      string `json:"txid"`
	Confirmed bool   `json:"confirmed"`
	Height    uint64 `json:"height"`
	BlockHash string `json:"blockhash"`
	// InvalidReason is the node's rejection text; empty unless the tx failed.
	InvalidReason string        `json:"invalid_reason"`
	Pool          MempoolCounts `json:"pool"`
	Events        []Event       `json:"events"`
}

// DefaultPollInterval is the WaitMined interval used when pollInterval is
// non-positive.
const DefaultPollInterval = 2 * time.Second

// GetTransactionReceipt fetches the confirmation provenance of txid from the
// node. The response is decoded straight into TxReceipt instead of through a
// map, so json's number-to-float64 interface{} conversion cannot lose precision
// on Height.
func GetTransactionReceipt(opts *CallOpts, txid string) (*TxReceipt, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	txid = strings.TrimSpace(txid)
	if txid == "" {
		return nil, errors.New("transaction id is required")
	}
	raw, err := opts.Client.CallRPC(opts.NodeAddr, "gettransactionreceipt", []interface{}{txid}, opts.ttl())
	if err != nil {
		return nil, fmt.Errorf("gettransactionreceipt: %w", err)
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, errors.New("gettransactionreceipt: empty response")
	}
	var receipt TxReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return nil, fmt.Errorf("parse gettransactionreceipt response: %w", err)
	}
	if receipt.TxID == "" {
		receipt.TxID = txid
	}
	if receipt.Events == nil {
		receipt.Events = []Event{}
	}
	return &receipt, nil
}

// WaitMined polls gettransactionreceipt until txid is confirmed, rejected, or
// ctx ends, whichever comes first. ctx is REQUIRED and must be cancelable or
// carry a deadline: the node answers "confirmed=false" for a pending
// transaction and for a txid it has never seen alike (GetTxConfirmation simply
// does not find it), so an unbounded context would poll forever. Terminal
// states:
//
//	Confirmed          -> success, the receipt is returned
//	InvalidReason != "" -> failure, error wrapping the node's reason
//	anything else      -> in flight (or unknown), keep polling
//
// Transient RPC errors do not end the wait either; they are remembered and
// reported if the context ends first. When the context ends first the last
// observed receipt (nil if none was ever received) is returned alongside an
// error wrapping ctx.Err().
func WaitMined(ctx context.Context, opts *CallOpts, txid string, pollInterval time.Duration) (*TxReceipt, error) {
	if ctx == nil || ctx.Done() == nil {
		return nil, errors.New("waitmined: a cancelable context (deadline or cancel) is required")
	}
	if pollInterval <= 0 {
		pollInterval = DefaultPollInterval
	}
	var (
		last    *TxReceipt
		lastErr error
	)
	for {
		receipt, err := GetTransactionReceipt(opts, txid)
		if err != nil {
			lastErr = err
		} else {
			last, lastErr = receipt, nil
			if receipt.Confirmed {
				return receipt, nil
			}
			if reason := strings.TrimSpace(receipt.InvalidReason); reason != "" {
				return receipt, fmt.Errorf("transaction %s failed: %s", receipt.TxID, reason)
			}
		}
		select {
		case <-ctx.Done():
			return last, waitEnded(ctx, txid, last, lastErr)
		case <-time.After(pollInterval):
		}
	}
}

// waitEnded describes why a wait stopped without a terminal receipt, keeping
// whatever the last poll saw so a caller can tell "still in flight" from "the
// node never answered".
func waitEnded(ctx context.Context, txid string, last *TxReceipt, lastErr error) error {
	switch {
	case last == nil && lastErr != nil:
		return fmt.Errorf("waitmined: %w (tx %s: %v)", ctx.Err(), txid, lastErr)
	case last == nil:
		return fmt.Errorf("waitmined: %w (tx %s: no receipt observed)", ctx.Err(), txid)
	case lastErr != nil:
		return fmt.Errorf("waitmined: %w (tx %s unconfirmed at last poll, node error: %v)", ctx.Err(), txid, lastErr)
	default:
		return fmt.Errorf("waitmined: %w (tx %s unconfirmed, height=%d, blockhash=%q)", ctx.Err(), txid, last.Height, last.BlockHash)
	}
}
