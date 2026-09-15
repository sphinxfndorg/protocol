// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/rpc/client_test.go
package rpc

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDecodeRPCResultPreservesBigIntegers locks in the fix for the USI wallet's
//
//	[Wallet] Failed to fetch transaction history: parse response:
//	math/big: cannot unmarshal "1e+25" into a *big.Int
//
// CallRPC used to decode the response envelope into JSONRPCResponse, whose
// Result is an interface{}, and then json.Marshal that interface{} again.
// Every JSON number therefore became a float64: a node-side nSPX amount of
// 19999999999705000000000000 came back out of that round trip as `1e+25`
// (exponent notation, and rounded to float64's ~15 significant digits). The
// wallet's strongly typed *big.Int fields only accept plain decimal text, so
// the reply was rejected and the whole transaction history failed to render.
//
// decodeRPCResult must return the server's `result` bytes verbatim, so no
// amount is ever reformatted or rounded on the way to the caller.
func TestDecodeRPCResultPreservesBigIntegers(t *testing.T) {
	const amount = "19999999999705000000000000"
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":[{"id":"aa11","amount":` + amount + `,"gas_limit":21000}]}`)

	raw, err := decodeRPCResult(body)
	if err != nil {
		t.Fatalf("decodeRPCResult: %v", err)
	}

	if strings.Contains(string(raw), "e+") {
		t.Fatalf("result numbers must not be rewritten in exponent notation, got %s", raw)
	}
	if !strings.Contains(string(raw), amount) {
		t.Fatalf("the exact amount digits must survive, got %s", raw)
	}

	// The round trip through the returned bytes must still unmarshal into the
	// node's transaction shape (plain *big.Int, which rejects "1e+25").
	var out []struct {
		ID       string          `json:"id"`
		Amount   json.RawMessage `json:"amount"`
		GasLimit json.RawMessage `json:"gas_limit"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("returned result must stay valid JSON: %v", err)
	}
	if len(out) != 1 || out[0].ID != "aa11" {
		t.Fatalf("transaction payload must survive decoding, got %v", out)
	}
	if string(out[0].Amount) != amount || string(out[0].GasLimit) != "21000" {
		t.Fatalf("numeric fields must be untouched, got amount=%s gas_limit=%s", out[0].Amount, out[0].GasLimit)
	}

	// A result the server itself renders in exponent notation must also pass
	// through untouched (the wallet tolerates it; nothing rewrites it).
	exp, err := decodeRPCResult([]byte(`{"jsonrpc":"2.0","id":2,"result":{"amount":1e+25}}`))
	if err != nil {
		t.Fatalf("exponent-notation result must decode: %v", err)
	}
	if string(exp) != `{"amount":1e+25}` {
		t.Fatalf("exponent-notation result must pass through verbatim, got %s", exp)
	}
}

// TestDecodeRPCResultEnvelopeShapes covers the non-numeric contract of
// decodeRPCResult: string results (getcontractstorage's hex payload), a
// missing/null result, an error member, and malformed JSON.
func TestDecodeRPCResultEnvelopeShapes(t *testing.T) {
	raw, err := decodeRPCResult([]byte(`{"jsonrpc":"2.0","id":1,"result":"0xdeadbeef"}`))
	if err != nil {
		t.Fatalf("string result: %v", err)
	}
	if string(raw) != `"0xdeadbeef"` {
		t.Fatalf("string result must pass through verbatim, got %s", raw)
	}

	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1}`,
		`{"jsonrpc":"2.0","id":1,"result":null}`,
	} {
		raw, err := decodeRPCResult([]byte(body))
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if string(raw) != "null" {
			t.Fatalf("%s must report a null result, got %s", body, raw)
		}
	}

	_, err = decodeRPCResult([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`))
	if err == nil {
		t.Fatal("an error envelope must surface an error")
	}
	if !strings.Contains(err.Error(), "method not found") || !strings.Contains(err.Error(), "-32601") {
		t.Fatalf("error must carry the node's code and message, got %v", err)
	}

	if _, err := decodeRPCResult([]byte(`{not json`)); err == nil {
		t.Fatal("malformed JSON must surface an error")
	}
}
