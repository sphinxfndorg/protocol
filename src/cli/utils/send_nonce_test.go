// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/send_nonce_test.go
package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// stubSigningNode answers the JSON-RPC methods a CLI broadcast can reach and
// records every method it was asked for. getnonce answers a bare number,
// exactly like the node's handler, because abi.Transact unmarshals it as one.
func stubSigningNode(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		methods = append(methods, req.Method)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if req.Method == "getnonce" {
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":5}`)
			return
		}
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"txid":"tx-stub"}}`)
	}))
	t.Cleanup(server.Close)
	return server, &methods
}

// bogusKeyFile is a path that exists but cannot be parsed as a signing key, so
// a broadcast stops at signing — after any nonce lookup, before any broadcast.
func bogusKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bogus.key")
	if err := os.WriteFile(path, []byte("not a key file"), 0o600); err != nil {
		t.Fatalf("write bogus key file: %v", err)
	}
	return path
}

func requireMethods(t *testing.T, methods *[]string, want ...string) {
	t.Helper()
	if len(*methods) != len(want) {
		t.Fatalf("node RPC methods = %v, want %v", *methods, want)
	}
	for i, method := range want {
		if (*methods)[i] != method {
			t.Fatalf("node RPC methods = %v, want %v", *methods, want)
		}
	}
}

// The CLI used to pre-fill the nonce via spx_getTransactionCount, which the node
// does not register, so a broadcast without --nonce silently went out with nonce
// 0 and was rejected. It must leave the nonce to abi.Transact, which asks the
// node's registered getnonce.
func TestSendTransactionResolvesTheNonceThroughGetnonce(t *testing.T) {
	server, methods := stubSigningNode(t)

	err := SendTransaction(SendTxOptions{
		RPCURL: server.URL, From: "alice", To: "bob", Amount: "1", KeyFile: bogusKeyFile(t),
	})
	if err == nil {
		t.Fatal("expected a bogus key file to fail signing")
	}
	requireMethods(t, methods, "getnonce")
}

// An explicit --nonce still wins: it must be used as-is, without consulting the
// node for the account nonce at all.
func TestSendTransactionExplicitNonceSkipsTheNodeLookup(t *testing.T) {
	server, methods := stubSigningNode(t)

	err := SendTransaction(SendTxOptions{
		RPCURL: server.URL, From: "alice", To: "bob", Amount: "1", Nonce: 7, KeyFile: bogusKeyFile(t),
	})
	if err == nil {
		t.Fatal("expected a bogus key file to fail signing")
	}
	requireMethods(t, methods)
}

// The NFT anchor path took the same fix.
func TestSendReturnDataTransactionResolvesTheNonceThroughGetnonce(t *testing.T) {
	server, methods := stubSigningNode(t)

	if _, err := sendReturnDataTransaction(SendTxOptions{
		RPCURL: server.URL, From: "alice", To: "alice", Amount: "0", KeyFile: bogusKeyFile(t),
	}, []byte(`{"mint_id":"m1"}`)); err == nil {
		t.Fatal("expected a bogus key file to fail signing")
	}
	requireMethods(t, methods, "getnonce")
}
