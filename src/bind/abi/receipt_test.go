// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const stubNodeAddr = "127.0.0.1:32307"

func receiptOpts(client *stubClient) *CallOpts {
	return &CallOpts{Client: client, NodeAddr: stubNodeAddr}
}

func waitCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func TestGetTransactionReceiptDecodesNodeResponse(t *testing.T) {
	// 9007199254740993 (2^53+1) is not representable as float64: decoding
	// through interface{} would silently round it to ...992.
	client := &stubClient{receipts: []string{`{"txid":"tx-1","confirmed":true,"height":9007199254740993,"blockhash":"0xabc","pool":{"broadcast":1,"validating":2,"pending":3,"invalid":4,"total":10}}`}}

	receipt, err := GetTransactionReceipt(receiptOpts(client), "tx-1")
	if err != nil {
		t.Fatalf("GetTransactionReceipt: %v", err)
	}
	if !receipt.Confirmed || receipt.Height != 9007199254740993 || receipt.BlockHash != "0xabc" || receipt.TxID != "tx-1" {
		t.Fatalf("receipt = %#v", receipt)
	}
	if receipt.Pool != (MempoolCounts{Broadcast: 1, Validating: 2, Pending: 3, Invalid: 4, Total: 10}) {
		t.Fatalf("pool = %#v", receipt.Pool)
	}
	if len(client.calls) != 1 || client.calls[0].method != "gettransactionreceipt" || client.calls[0].params[0].(string) != "tx-1" {
		t.Fatalf("calls = %#v", client.calls)
	}
}

func TestGetTransactionReceiptSurfacesNodeError(t *testing.T) {
	if _, err := GetTransactionReceipt(receiptOpts(&stubClient{}), "tx-1"); err == nil || !strings.Contains(err.Error(), "gettransactionreceipt") {
		t.Fatalf("err = %v, want wrapped gettransactionreceipt error", err)
	}
	if _, err := GetTransactionReceipt(receiptOpts(&stubClient{}), "  "); err == nil {
		t.Fatal("expected blank txid to be rejected before any RPC call")
	}
}

func TestWaitMinedConfirmedOnFirstPoll(t *testing.T) {
	client := &stubClient{receipts: []string{`{"txid":"tx-1","confirmed":true,"height":42,"blockhash":"0xabc"}`}}

	receipt, err := WaitMined(waitCtx(t, time.Second), receiptOpts(client), "tx-1", time.Millisecond)
	if err != nil {
		t.Fatalf("WaitMined: %v", err)
	}
	if !receipt.Confirmed || receipt.Height != 42 {
		t.Fatalf("receipt = %#v", receipt)
	}
	if len(client.calls) != 1 {
		t.Fatalf("polled %d times, want 1", len(client.calls))
	}
}

func TestWaitMinedPendingThenConfirmed(t *testing.T) {
	client := &stubClient{receipts: []string{
		`{"txid":"tx-2","confirmed":false,"height":0,"pool":{"broadcast":1,"validating":0,"pending":0,"invalid":0,"total":1}}`,
		`{"txid":"tx-2","confirmed":true,"height":77,"blockhash":"0xdef"}`,
	}}

	receipt, err := WaitMined(waitCtx(t, time.Second), receiptOpts(client), "tx-2", time.Millisecond)
	if err != nil {
		t.Fatalf("WaitMined: %v", err)
	}
	if !receipt.Confirmed || receipt.Height != 77 || receipt.BlockHash != "0xdef" {
		t.Fatalf("receipt = %#v", receipt)
	}
	if len(client.calls) != 2 {
		t.Fatalf("polled %d times, want 2", len(client.calls))
	}
}

func TestWaitMinedInvalidReasonIsFailure(t *testing.T) {
	client := &stubClient{receipts: []string{
		`{"txid":"tx-3","confirmed":false,"pool":{"invalid":1,"total":1},"invalid_reason":"invalid nonce: 3 must equal 4"}`,
	}}

	receipt, err := WaitMined(waitCtx(t, time.Second), receiptOpts(client), "tx-3", time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "invalid nonce: 3 must equal 4") {
		t.Fatalf("err = %v, want the node's rejection reason", err)
	}
	if receipt == nil || receipt.InvalidReason == "" {
		t.Fatalf("receipt = %#v, want the rejected receipt", receipt)
	}
	if len(client.calls) != 1 {
		t.Fatalf("polled %d times, want 1 (a rejection is terminal)", len(client.calls))
	}
}

func TestWaitMinedContextDeadlineReturnsLastReceipt(t *testing.T) {
	client := &stubClient{receipts: []string{`{"txid":"tx-4","confirmed":false,"pool":{"broadcast":1,"total":1}}`}}

	receipt, err := WaitMined(waitCtx(t, 40*time.Millisecond), receiptOpts(client), "tx-4", 5*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if receipt == nil {
		t.Fatal("receipt = nil, want the last observed pending receipt")
	}
	if receipt.Confirmed || receipt.TxID != "tx-4" {
		t.Fatalf("receipt = %#v", receipt)
	}
}

func TestWaitMinedRequiresCancelableContext(t *testing.T) {
	client := &stubClient{receipts: []string{`{"txid":"tx-5","confirmed":true}`}}
	if _, err := WaitMined(context.Background(), receiptOpts(client), "tx-5", time.Millisecond); err == nil {
		t.Fatal("expected an uncancelable context to be rejected")
	}
	if _, err := WaitMined(context.Background(), receiptOpts(client), "tx-5", time.Millisecond); err == nil {
		t.Fatal("expected a nil context to be rejected")
	}
	if len(client.calls) != 0 {
		t.Fatalf("calls = %#v, want none", client.calls)
	}
}
