// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sphinxfndorg/protocol/src/contracts"
)

// ── Minimal WASM fixture for Q4 ─────────────────────────────────────────────
//
// wasmEventEmitting is a minimal WASM module that imports sphinx.emit_event
// (topic,value i64 -> ()) and calls it once from sphinx_main (topic=1,
// value=42). Used in tests that execute a real event-emitting WASM contract.
var wasmEventEmitting = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
	0x01, 0x09, 0x02, // type section, 9 bytes, 2 types
	0x60, 0x02, 0x7e, 0x7e, 0x00, // type 0: (i64,i64) -> ()
	0x60, 0x00, 0x00, // type 1: () -> ()
	0x02, 0x15, 0x01, // import section, 21 bytes, 1 import
	0x06, 0x73, 0x70, 0x68, 0x69, 0x6e, 0x78, // "sphinx"
	0x0a, 0x65, 0x6d, 0x69, 0x74, 0x5f, 0x65, 0x76, 0x65, 0x6e, 0x74, // "emit_event"
	0x00, 0x00, // func import, type 0
	0x03, 0x02, 0x01, 0x01, // function section, 2 bytes, 1 func of type 1
	0x07, 0x0f, 0x01, // export section, 15 bytes, 1 export
	0x0b, 0x73, 0x70, 0x68, 0x69, 0x6e, 0x78, 0x5f, 0x6d, 0x61, 0x69, 0x6e, // "sphinx_main"
	0x00, 0x01, // export func 1
	0x0a, 0x0a, 0x01, // code section, 10 bytes, 1 entry
	0x08, 0x00, // func body: 8 bytes, 0 locals
	0x42, 0x01, // i64.const 1
	0x42, 0x2a, // i64.const 42
	0x10, 0x00, // call 0 (emit_event)
	0x0b, // end
}

func eventOpts(client *stubClient) *CallOpts {
	return &CallOpts{Client: client, NodeAddr: stubNodeAddr}
}

// eventMemStore is a minimal contracts.Store for executing the Q4 WASM
// fixture; events are execution output, so storage can be inert.
type eventMemStore struct{ values map[string][]byte }

func (s *eventMemStore) ContractExists(address string) bool          { return false }
func (s *eventMemStore) SetContractCode(address string, code []byte) {}
func (s *eventMemStore) GetContractCode(address string) ([]byte, error) {
	return nil, errors.New("missing")
}
func (s *eventMemStore) SetContractMeta(address string, meta []byte) {}
func (s *eventMemStore) GetContractMeta(address string) ([]byte, error) {
	return nil, errors.New("missing")
}
func (s *eventMemStore) SetContractStorage(address, key string, value []byte) {
	s.values[address+":"+key] = value
}
func (s *eventMemStore) GetContractStorage(address, key string) ([]byte, error) {
	v, ok := s.values[address+":"+key]
	if !ok {
		return nil, errors.New("missing")
	}
	return v, nil
}

// The Q4 fixture must validate and emit exactly one event through the real
// WASM runtime; otherwise every downstream RPC round trip tests a fiction.
func TestWASMEventFixtureEmitsOneEvent(t *testing.T) {
	if err := contracts.ValidateWASM(wasmEventEmitting, 1024, 16); err != nil {
		t.Fatalf("ValidateWASM: %v", err)
	}
	result, err := contracts.ExecuteWASMWithContext(&eventMemStore{values: map[string][]byte{}}, "fixture", wasmEventEmitting, nil, 1024, 16, contracts.WASMContext{MaxEvents: 8})
	if err != nil {
		t.Fatalf("ExecuteWASMWithContext: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("got %d events, want 1 (%#v)", len(result.Events), result.Events)
	}
	if result.Events[0].Topic != "0000000000000001" || result.Events[0].Data != "42" {
		t.Fatalf("event = %#v", result.Events[0])
	}
	var asABI []Event
	raw, err := json.Marshal(result.Events)
	if err != nil {
		t.Fatalf("marshal contract events: %v", err)
	}
	if err := json.Unmarshal(raw, &asABI); err != nil {
		t.Fatalf("contract events are not Event-shaped: %v", err)
	}
	if len(asABI) != 1 || asABI[0].Topic != "0000000000000001" || asABI[0].Data != "42" {
		t.Fatalf("abi events = %#v", asABI)
	}
}
func TestGetTransactionEventsReturnsEvents(t *testing.T) {
	client := &stubClient{
		eventResponses: map[string]string{
			"tx-events": `[{"topic":"010203","data":"42"},{"topic":"abcdef","data":"hello"}]`,
		},
	}
	events, err := GetTransactionEvents(eventOpts(client), "tx-events")
	if err != nil {
		t.Fatalf("GetTransactionEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].Topic != "010203" || events[0].Data != "42" {
		t.Fatalf("event[0] = %#v", events[0])
	}
	if events[1].Topic != "abcdef" || events[1].Data != "hello" {
		t.Fatalf("event[1] = %#v", events[1])
	}
	if len(client.calls) != 1 || client.calls[0].method != "gettransactionevents" {
		t.Fatalf("calls = %#v", client.calls)
	}
}

func TestGetTransactionEventsEmptyEvents(t *testing.T) {
	client := &stubClient{
		eventResponses: map[string]string{"tx-empty": `[]`},
	}
	events, err := GetTransactionEvents(eventOpts(client), "tx-empty")
	if err != nil {
		t.Fatalf("GetTransactionEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("got %d events, want 0", len(events))
	}
}

func TestGetTransactionEventsNonexistentTxid(t *testing.T) {
	_, err := GetTransactionEvents(eventOpts(&stubClient{}), "tx-nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent txid")
	}
}

func TestGetTransactionEventsRejectsBlankTxid(t *testing.T) {
	_, err := GetTransactionEvents(eventOpts(&stubClient{}), "  ")
	if err == nil {
		t.Fatal("expected error for blank txid")
	}
}

// ── Receipt events field ─────────────────────────────────────────────────────

func TestTxReceiptEventsField(t *testing.T) {
	client := &stubClient{
		receipts: []string{`{"txid":"tx-rec","confirmed":true,"height":10,"blockhash":"0xabc","pool":{"broadcast":0,"validating":0,"pending":0,"invalid":0,"total":0},"events":[{"topic":"01","data":"a"}]}`},
	}
	receipt, err := GetTransactionReceipt(eventOpts(client), "tx-rec")
	if err != nil {
		t.Fatalf("GetTransactionReceipt: %v", err)
	}
	if len(receipt.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(receipt.Events))
	}
	if receipt.Events[0].Topic != "01" || receipt.Events[0].Data != "a" {
		t.Fatalf("event = %#v", receipt.Events[0])
	}
}

func TestTxReceiptEventsEmptyArray(t *testing.T) {
	client := &stubClient{
		receipts: []string{`{"txid":"tx-noevents","confirmed":true,"height":5,"blockhash":"0xdef","pool":{"broadcast":0,"validating":0,"pending":0,"invalid":0,"total":0},"events":[]}`},
	}
	receipt, err := GetTransactionReceipt(eventOpts(client), "tx-noevents")
	if err != nil {
		t.Fatalf("GetTransactionReceipt: %v", err)
	}
	if len(receipt.Events) != 0 {
		t.Fatalf("got %d events, want 0", len(receipt.Events))
	}
}

// ── WASM deploy->call->WaitMined->GetTransactionEvents round trip ─────────
//
// The stub node below stands in for consensus against the in-tree Q4 fixture:
// NewWASMDeployTx/NewWASMCallTx build the real transactions over
// wasmEventEmitting, WaitMined confirms each txid, and the receipt's events
// field plus GetTransactionEvents return the event the real WASM execution
// above produces (topic 0000000000000001, data 42).
func TestWASMEventsRoundTrip(t *testing.T) {
	nonce := uint64(7)
	deployTx, err := NewWASMDeployTx(TxOptions{ChainID: 7331, Sender: stubDeployFrom, Nonce: nonce}, wasmEventEmitting)
	if err != nil {
		t.Fatalf("NewWASMDeployTx: %v", err)
	}
	deployAddr := contracts.ContractAddress(deployTx.Sender, deployTx.Nonce, deployTx.Code)
	if deployAddr == "" {
		t.Fatal("derived deploy address is empty")
	}
	callTx, err := NewWASMCallTx(TxOptions{ChainID: 7331, Sender: stubDeployFrom, Nonce: nonce + 1}, deployAddr, nil)
	if err != nil {
		t.Fatalf("NewWASMCallTx: %v", err)
	}
	if callTx.ToContract != deployAddr {
		t.Fatalf("call ToContract = %q, want %q", callTx.ToContract, deployAddr)
	}
	client := &stubClient{
		receipts: []string{
			`{"txid":"tx-deploy","confirmed":true,"height":1,"blockhash":"0xb1","events":[]}`,
			`{"txid":"tx-call","confirmed":true,"height":2,"blockhash":"0xb2","events":[{"topic":"0000000000000001","data":"42"}]}`,
		},
		eventResponses: map[string]string{
			"tx-deploy": `[]`,
			"tx-call":   `[{"topic":"0000000000000001","data":"42"}]`,
		},
	}
	for _, txid := range []string{"tx-deploy", "tx-call"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		receipt, err := WaitMined(ctx, eventOpts(client), txid, time.Millisecond)
		cancel()
		if err != nil {
			t.Fatalf("WaitMined(%s): %v", txid, err)
		}
		events, err := GetTransactionEvents(eventOpts(client), txid)
		if err != nil {
			t.Fatalf("GetTransactionEvents(%s): %v", txid, err)
		}
		if len(events) != len(receipt.Events) {
			t.Fatalf("%s: receipt has %d events, dedicated method has %d", txid, len(receipt.Events), len(events))
		}
		for i := range events {
			if events[i] != receipt.Events[i] {
				t.Fatalf("%s event[%d]: receipt %#v != method %#v", txid, i, receipt.Events[i], events[i])
			}
		}
	}
	if len(client.calls) == 0 {
		t.Fatal("no RPC calls recorded")
	}
}

// ── WatchTransaction ────────────────────────────────────────────────────────
func TestWatchTransactionFiresCallbackOnce(t *testing.T) {
	client := &stubClient{
		receipts: []string{`{"txid":"tx-watch","confirmed":true,"height":42,"blockhash":"0xabc","events":[{"topic":"watch-topic","data":"watch-data"}]}`},
		eventResponses: map[string]string{
			"tx-watch": `[{"topic":"watch-topic","data":"watch-data"}]`,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var got []Event
	var mu sync.Mutex
	err := WatchTransaction(ctx, eventOpts(client), "tx-watch", time.Millisecond, func(events []Event) {
		mu.Lock()
		got = events
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("WatchTransaction: %v", err)
	}
	mu.Lock()
	if len(got) != 1 || got[0].Topic != "watch-topic" || got[0].Data != "watch-data" {
		t.Fatalf("got events = %#v", got)
	}
	mu.Unlock()
}

func TestWatchTransactionFiresWithEmptyEvents(t *testing.T) {
	client := &stubClient{
		receipts: []string{`{"txid":"tx-empty","confirmed":true,"height":1,"blockhash":"0x","events":[]}`},
		eventResponses: map[string]string{
			"tx-empty": `[]`,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var got []Event
	var mu sync.Mutex
	err := WatchTransaction(ctx, eventOpts(client), "tx-empty", time.Millisecond, func(events []Event) {
		mu.Lock()
		got = events
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("WatchTransaction: %v", err)
	}
	mu.Lock()
	if len(got) != 0 {
		t.Fatalf("got %d events, want 0", len(got))
	}
	mu.Unlock()
}

func TestWatchTransactionCtxCancellation(t *testing.T) {
	client := &stubClient{
		receipts: []string{`{"txid":"tx-cancel","confirmed":false,"height":0,"pool":{"broadcast":1,"total":1}}`},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var called bool
	err := WatchTransaction(ctx, eventOpts(client), "tx-cancel", time.Millisecond, func(events []Event) {
		called = true
	})
	if err == nil {
		t.Fatal("expected an error from cancelled context")
	}
	if called {
		t.Fatal("callback was invoked despite cancellation")
	}
}

// blockJSON builds a JSON-encoded block with a single transaction list.
func blockJSON(height uint64, txs ...map[string]interface{}) string {
	list := make([]interface{}, len(txs))
	for i, tx := range txs {
		list[i] = tx
	}
	body := map[string]interface{}{"txs_list": list}
	data, _ := json.Marshal(map[string]interface{}{
		"header": map[string]interface{}{"height": height, "nblock": height},
		"body":   body,
	})
	return string(data)
}

func txJSON(id, toContract, sender string, nonce uint64, codeB64 ...string) map[string]interface{} {
	tx := map[string]interface{}{
		"id":          id,
		"sender":      sender,
		"nonce":       nonce,
		"to_contract": toContract,
	}
	// code is a []byte on the wire, so JSON carries it base64-encoded
	// (e.g. "AA==" for a single zero byte), not raw hex.
	if len(codeB64) > 0 && codeB64[0] != "" {
		tx["code"] = codeB64[0]
	}
	return tx
}

func TestWatchContractEventsFiresForMatchingTx(t *testing.T) {
	contractAddr := "SPIF 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111"
	client := &stubClient{
		blockCount: 2,
		blocksByHeight: map[uint64]string{
			1: blockJSON(1, txJSON("tx-1", "", stubDeployFrom, 15, "AA==")),
			2: blockJSON(2, txJSON("tx-2", contractAddr, stubDeployFrom, 16)),
		},
		eventResponses: map[string]string{
			"tx-2": `[{"topic":"hello","data":"world"}]`,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var gotTxid string
	var gotEvents []Event
	var mu sync.Mutex
	err := WatchContractEvents(ctx, eventOpts(client), contractAddr, 0, time.Millisecond, func(txid string, events []Event) {
		mu.Lock()
		gotTxid = txid
		gotEvents = events
		mu.Unlock()
	})
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WatchContractEvents: %v", err)
	}
	mu.Lock()
	if gotTxid != "tx-2" {
		t.Fatalf("got txid = %q, want tx-2", gotTxid)
	}
	if len(gotEvents) != 1 || gotEvents[0].Topic != "hello" || gotEvents[0].Data != "world" {
		t.Fatalf("got events = %#v", gotEvents)
	}
	mu.Unlock()
}

func TestWatchContractEventsSkipsNonMatchingAddress(t *testing.T) {
	client := &stubClient{
		blockCount: 1,
		blocksByHeight: map[uint64]string{
			1: blockJSON(1, txJSON("tx-other", "SPIF 9999 9999 9999 9999 9999 9999 9999 9999 9999 9999 9999 9999 9999 9999 9999 9999", stubDeployFrom, 1)),
		},
		eventResponses: map[string]string{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var called bool
	err := WatchContractEvents(ctx, eventOpts(client), "SPIF 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111", 1, 10*time.Millisecond, func(txid string, events []Event) {
		called = true
	})
	if err == nil {
		t.Fatal("expected context deadline exceeded")
	}
	if called {
		t.Fatal("callback was invoked despite no matching contract address")
	}
}

func TestWatchContractEventsAdvancesCheckpoint(t *testing.T) {
	contractAddr := "SPIF 2222 2222 2222 2222 2222 2222 2222 2222 2222 2222 2222 2222 2222 2222 2222 2222"
	client := &stubClient{
		blockCount: 1,
		blocksByHeight: map[uint64]string{
			1: blockJSON(1, txJSON("tx-m1", contractAddr, stubDeployFrom, 5)),
		},
		eventResponses: map[string]string{
			"tx-m1": `[{"topic":"m1","data":"1"}]`,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var called bool
	err := WatchContractEvents(ctx, eventOpts(client), contractAddr, 1, 10*time.Millisecond, func(txid string, events []Event) {
		called = true
	})
	if err == nil {
		t.Fatal("expected context deadline exceeded")
	}
	if called {
		t.Fatal("callback invoked for block at or below checkpoint")
	}
}

func TestWatchContractEventsCtxCancellation(t *testing.T) {
	client := &stubClient{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := WatchContractEvents(ctx, eventOpts(client), "SPIF AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA", 0, time.Millisecond, func(txid string, events []Event) {})
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

func TestWatchContractEventsValidatesArgs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := WatchContractEvents(ctx, eventOpts(&stubClient{}), "addr", 0, time.Millisecond, nil)
	if err == nil || !strings.Contains(err.Error(), "callback is required") {
		t.Fatalf("err = %v, want callback validation error", err)
	}
	err = WatchContractEvents(nil, eventOpts(&stubClient{}), "addr", 0, time.Millisecond, func(txid string, events []Event) {})
	if err == nil {
		t.Fatal("expected error for nil/uncancelable context")
	}
}

// Fires once per matching tx across a multi-block range, collects each tx's
// events, and never re-fires for a block already advanced past: the second
// poll sees the checkpoint at the tip and stops without a repeat callback.
func TestWatchContractEventsMultiBlockRange(t *testing.T) {
	contractAddr := "SPIF 3333 3333 3333 3333 3333 3333 3333 3333 3333 3333 3333 3333 3333 3333 3333 3333"
	client := &stubClient{
		blockCount: 3,
		blocksByHeight: map[uint64]string{
			1: blockJSON(1, txJSON("tx-a", contractAddr, stubDeployFrom, 1)),
			2: blockJSON(2,
				txJSON("tx-skip", "SPIF 9999 9999 9999 9999 9999 9999 9999 9999 9999 9999 9999 9999 9999 9999 9999 9999", stubDeployFrom, 2),
				txJSON("tx-b", contractAddr, stubDeployFrom, 3)),
			3: blockJSON(3, txJSON("tx-quiet", contractAddr, stubDeployFrom, 4)),
		},
		eventResponses: map[string]string{
			"tx-a":     `[{"topic":"a","data":"1"}]`,
			"tx-b":     `[{"topic":"b","data":"2"}]`,
			"tx-quiet": `[]`,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	var mu sync.Mutex
	fired := map[string][]Event{}
	err := WatchContractEvents(ctx, eventOpts(client), contractAddr, 0, 5*time.Millisecond, func(txid string, events []Event) {
		mu.Lock()
		fired[txid] = append([]Event(nil), events...)
		mu.Unlock()
	})
	if err == nil {
		t.Fatal("expected context deadline exceeded")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(fired) != 2 {
		t.Fatalf("fired = %v, want exactly tx-a and tx-b once each", fired)
	}
	if len(fired["tx-a"]) != 1 || fired["tx-a"][0].Topic != "a" || fired["tx-a"][0].Data != "1" {
		t.Fatalf("tx-a events = %#v", fired["tx-a"])
	}
	if len(fired["tx-b"]) != 1 || fired["tx-b"][0].Topic != "b" || fired["tx-b"][0].Data != "2" {
		t.Fatalf("tx-b events = %#v", fired["tx-b"])
	}
}

// ── WatchContractEvents (multi-block range, stub client) ───────────────────
