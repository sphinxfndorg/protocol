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

	"github.com/sphinxfndorg/protocol/src/contracts"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// Event mirrors contracts.ContractEvent — the same wire-identical shape the
// node commits to contract storage and returns through gettransactionevents.
// It lives in abi rather than re-exporting contracts.ContractEvent so the
// binding stays decoupled (src/bind/abi never imports src/bind).
type Event struct {
	Topic string `json:"topic"`
	Data  string `json:"data"`
}

// GetTransactionEvents fetches the events emitted by a confirmed transaction.
// An empty slice means the tx exists but emitted no events; an error means
// the txid is unknown or the node could not be reached.
func GetTransactionEvents(opts *CallOpts, txid string) ([]Event, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	txid = strings.TrimSpace(txid)
	if txid == "" {
		return nil, errors.New("transaction id is required")
	}
	raw, err := opts.Client.CallRPC(opts.NodeAddr, "gettransactionevents", []interface{}{txid}, opts.ttl())
	if err != nil {
		return nil, fmt.Errorf("gettransactionevents: %w", err)
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, errors.New("gettransactionevents: empty response")
	}
	var events []Event
	if err := json.Unmarshal(raw, &events); err != nil {
		return nil, fmt.Errorf("parse gettransactionevents response: %w", err)
	}
	if events == nil {
		return []Event{}, nil
	}
	return events, nil
}

// WatchTransaction polls gettransactionreceipt until txid is confirmed, then
// calls GetTransactionEvents once and hands the result (even if empty) to
// callback. Returns when done or ctx is cancelled. This is the primitive for
// "tell me what happened to the tx I just sent" — callers of Transact can
// compose this themselves for the same effect without a dedicated Deploy*
// wrapper.
func WatchTransaction(ctx context.Context, opts *CallOpts, txid string, pollInterval time.Duration, callback func([]Event)) error {
	if ctx == nil || ctx.Done() == nil {
		return errors.New("watchtransaction: a cancelable context (deadline or cancel) is required")
	}
	if opts == nil {
		return errors.New("watchtransaction: call opts are required")
	}
	if callback == nil {
		return errors.New("watchtransaction: callback is required")
	}
	if pollInterval <= 0 {
		pollInterval = DefaultPollInterval
	}

	// Wait for confirmation via the same polling loop WaitMined uses.
	receipt, err := WaitMined(ctx, opts, txid, pollInterval)
	if err != nil {
		return err
	}
	if receipt == nil {
		return errors.New("watchtransaction: WaitMined returned nil receipt")
	}

	// Transaction is confirmed (or rejected, but then WaitMined returned
	// error). Fetch events once.
	events, err := GetTransactionEvents(opts, txid)
	if err != nil {
		return fmt.Errorf("watchtransaction: get events for confirmed tx %s: %w", txid, err)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		callback(events)
	}
	return nil
}

// WatchContractEvents polls blocks from a tracked height checkpoint forward,
// filtering transactions by contract address, and firing callback per matching
// tx that emitted events.
//
// Block iteration uses the node's getblockcount tip plus getblockbynumber per
// height, which return blocks with full transaction objects (with
// ToContract), so no second gettransaction call per tx is needed. For each
// matching tx, events are fetched via GetTransactionEvents. The callback is invoked with the txid and
// its events only when events are non-empty.
//
// This is a poll-based equivalent of eth_getLogs / FilterLogs, buildable
// today with existing RPC methods. Over a large block range this is
// O(blocks × txs) — a real indexed query (Layer 2) would be needed for
// high-volume production use. Each height from fromHeight to the tip costs
// one getblockbynumber round trip (no batch/range fetch exists on this
// node's RPC surface), so resuming from a stale fromHeight makes that many
// calls before catching up. This is a functional listener, not the
// performant version.
func WatchContractEvents(ctx context.Context, opts *CallOpts, contractAddress string, fromHeight uint64, pollInterval time.Duration, callback func(txid string, events []Event)) error {
	if ctx == nil || ctx.Done() == nil {
		return errors.New("watchcontractevents: a cancelable context is required")
	}
	if opts == nil {
		return errors.New("watchcontractevents: call opts are required")
	}
	if strings.TrimSpace(contractAddress) == "" {
		return errors.New("watchcontractevents: contract address is required")
	}
	if callback == nil {
		return errors.New("watchcontractevents: callback is required")
	}
	if pollInterval <= 0 {
		pollInterval = DefaultPollInterval
	}

	checkpoint := fromHeight
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Fetch current tip height.
		rawTip, err := opts.Client.CallRPC(opts.NodeAddr, "getblockcount", nil, opts.ttl())
		if err != nil {
			if !waitForNextPoll(ctx, pollInterval) {
				return ctx.Err()
			}
			continue
		}
		var tipHeight uint64
		if err := json.Unmarshal(rawTip, &tipHeight); err != nil {
			if !waitForNextPoll(ctx, pollInterval) {
				return ctx.Err()
			}
			continue
		}
		if tipHeight < checkpoint+1 {
			if !waitForNextPoll(ctx, pollInterval) {
				return ctx.Err()
			}
			continue
		}
		// Scan from checkpoint+1 through tip. The checkpoint advances only
		// past a fully processed height, so a fetch/unmarshal failure
		// retries that height on the next poll instead of skipping it.
		for height := checkpoint + 1; height <= tipHeight; height++ {
			rawBlock, err := opts.Client.CallRPC(opts.NodeAddr, "getblockbynumber", []interface{}{float64(height)}, opts.ttl())
			if err != nil {
				break
			}
			var block types.Block
			if err := json.Unmarshal(rawBlock, &block); err != nil || block.Body.TxsList == nil {
				break
			}
			for _, tx := range block.Body.TxsList {
				if tx == nil {
					continue
				}
				match := false
				if tx.ToContract != "" && tx.ToContract == contractAddress {
					match = true
				} else if len(tx.Code) > 0 {
					predicted := contracts.ContractAddress(tx.Sender, tx.Nonce, tx.Code)
					if predicted == contractAddress {
						match = true
					}
				}
				if !match {
					continue
				}
				events, err := GetTransactionEvents(opts, tx.ID)
				if err != nil || len(events) == 0 {
					continue
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					callback(tx.ID, events)
				}
			}
			// Advance checkpoint past the processed height so restarts
			// resume where we left off.
			checkpoint = height
		}
		if !waitForNextPoll(ctx, pollInterval) {
			return ctx.Err()
		}
	}
}

// waitForNextPoll sleeps for pollInterval or returns false if ctx was
// cancelled during the wait.
func waitForNextPoll(ctx context.Context, pollInterval time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(pollInterval):
		return true
	}
}
