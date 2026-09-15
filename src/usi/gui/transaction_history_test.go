// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/transaction_history_test.go
package gui

import (
	"testing"
	"time"
)

// TestParseTransactionHistoryAcceptsScientificNotation locks in the fix for
// the wallet screen's failure to render recent activity:
//
//	[Wallet] Failed to fetch transaction history: parse response:
//	math/big: cannot unmarshal "1e+25" into a *big.Int
//
// That error came from decoding the RPC result into types.Transaction, whose
// Amount is a plain *big.Int and therefore rejects any non-plain-decimal
// rendering of a number. Large nSPX amounts (a genesis-sized balance is ~10^25
// nSPX) can arrive in exponent notation, and a single such transaction used to
// discard the ENTIRE history — so the wallet showed no activity at all.
// parseTransactionHistory must instead recover the exact amount for every
// rendering the node can emit.
func TestParseTransactionHistoryAcceptsScientificNotation(t *testing.T) {
	payload := []byte(`[
		{"id":"aa11","sender":"SPIF AABB","receiver":"SPIF CCDD","amount":1e+25,"timestamp":1757894400,"return_data":"bWVtbw=="},
		{"id":"bb22","sender":"SPIF AABB","receiver":"SPIF EEFF","amount":"1.5e+20","timestamp":"1757894300","fee":1e+18},
		{"id":"cc33","sender":"SPIF CCDD","receiver":"SPIF AABB","amount":"19999999999705000000000000","timestamp":1757894200}
	]`)

	txs, err := parseTransactionHistory(payload)
	if err != nil {
		t.Fatalf("exponent-notation history must decode, got: %v", err)
	}
	if len(txs) != 3 {
		t.Fatalf("expected 3 transactions, got %d", len(txs))
	}

	// The exponent-notation amount must be recovered EXACTLY (1e+25 is not a
	// float64 round trip, so a parse that went through float64 would be wrong
	// for the third case below).
	if got := txs[0].Amount.String(); got != "10000000000000000000000000" {
		t.Fatalf("1e+25 must decode to 10^25 nSPX, got %q", got)
	}
	if got := txs[1].Amount.String(); got != "150000000000000000000" {
		t.Fatalf("\"1.5e+20\" must decode to 1.5e20 nSPX, got %q", got)
	}
	if got := txs[2].Amount.String(); got != "19999999999705000000000000" {
		t.Fatalf("plain-digit amounts must stay exact, got %q", got)
	}
	if got := txs[1].Fee.String(); got != "1000000000000000000" {
		t.Fatalf("1e+18 fee must decode to 10^18 nSPX, got %q", got)
	}

	// Non-numeric fields still map across, including the "id" -> txid rename
	// and the base64-decoded OP_RETURN memo.
	if txs[0].TxID != "aa11" || txs[2].TxID != "cc33" {
		t.Fatalf("tx ids must be preserved, got %q and %q", txs[0].TxID, txs[2].TxID)
	}
	if string(txs[0].ReturnData) != "memo" {
		t.Fatalf("return_data must decode to the memo bytes, got %q", txs[0].ReturnData)
	}
	if txs[1].ReturnData != nil {
		t.Fatalf("absent return_data must stay nil, got %q", txs[1].ReturnData)
	}
	if txs[0].Status != "confirmed" {
		t.Fatalf("a history row with no status is confirmed, got %q", txs[0].Status)
	}

	// Timestamps arrive as unix seconds — as a JSON number or a quoted string
	// — and must render, not fall back to the zero time.
	if want := time.Unix(1757894400, 0); !txs[0].Timestamp.Equal(want) {
		t.Fatalf("timestamp must decode from unix seconds: got %s want %s", txs[0].Timestamp, want)
	}
	if !txs[1].Timestamp.Equal(time.Unix(1757894300, 0)) {
		t.Fatalf("quoted timestamps must decode too, got %s", txs[1].Timestamp)
	}
}

// TestParseTransactionHistoryEdgeCases covers the shapes an empty or unusual
// response takes: no transactions, a null result, an unknown timestamp (which
// must stay the zero time so the wallet hides it instead of printing 1970),
// and a malformed payload (which must error rather than silently reporting an
// empty history).
func TestParseTransactionHistoryEdgeCases(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
	}{
		{"empty array", `[]`},
		{"null", `null`},
		{"no bytes", ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			txs, err := parseTransactionHistory([]byte(tc.payload))
			if err != nil {
				t.Fatalf("empty history must not error, got: %v", err)
			}
			if len(txs) != 0 {
				t.Fatalf("expected no transactions, got %d", len(txs))
			}
		})
	}

	txs, err := parseTransactionHistory([]byte(`[{"id":"dd44","amount":0,"timestamp":0}]`))
	if err != nil {
		t.Fatalf("zero-valued row must decode, got: %v", err)
	}
	if len(txs) != 1 {
		t.Fatalf("expected 1 transaction, got %d", len(txs))
	}
	if !txs[0].Timestamp.IsZero() {
		t.Fatalf("a zero/missing timestamp must stay the zero time, got %s", txs[0].Timestamp)
	}

	if _, err := parseTransactionHistory([]byte(`{"not":"an array"}`)); err == nil {
		t.Fatal("a malformed history payload must surface an error")
	}
	if _, err := parseTransactionHistory([]byte(`[{"amount":"not-a-number"}]`)); err == nil {
		t.Fatal("a non-numeric amount must surface an error")
	}
}

// TestBigIntScientificNotationRoundTrip documents the tolerance the history
// parser relies on: BigInt must accept every rendering a node can produce for
// a large nSPX amount (plain digits, exponent notation, quoted) and keep the
// digits exact whenever the wire form carried them.
func TestBigIntScientificNotationRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{`1e+25`, "10000000000000000000000000"},
		{`"1e+25"`, "10000000000000000000000000"},
		{`1.5e+20`, "150000000000000000000"},
		{`"19999999999705000000000000"`, "19999999999705000000000000"},
		{`19999999999705000000000000`, "19999999999705000000000000"},
		{`null`, "0"},
	} {
		var b BigInt
		if err := b.UnmarshalJSON([]byte(tc.in)); err != nil {
			t.Fatalf("UnmarshalJSON(%s): %v", tc.in, err)
		}
		if b.Int == nil {
			t.Fatalf("UnmarshalJSON(%s) left a nil Int", tc.in)
		}
		if got := b.String(); got != tc.want {
			t.Fatalf("UnmarshalJSON(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
}
