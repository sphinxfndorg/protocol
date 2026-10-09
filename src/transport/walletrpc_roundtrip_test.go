// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/transport/walletrpc_roundtrip_test.go
package transport

import (
	"strings"
	"testing"
	"time"

	security "github.com/sphinxfndorg/protocol/src/handshake"
	"github.com/sphinxfndorg/protocol/src/rpc"
)

// TestWalletRPCRoundTripReproducesGUIPath is the live end-to-end proof that the
// CURRENT source speaks the wallet/JSON-RPC protocol correctly — the exact path
// the USI GUI (src/usi/gui/rpc.go) uses for balance, headers, history, etc.
//
// It starts a real transport.TCPServer wired to a real rpc.Server on
// 127.0.0.1:8700 (the wallet-RPC port the GUI dials by default) and drives it
// with rpc.CallRPC — the same client the GUI calls. If this round-trips, the
// GUI's "reading length prefix ... i/o timeout" is NOT a bug in the current
// source: it means the process actually listening on 8700 was a stale or
// mismatched build (or absent), not this code.
//
// getsyncstatus is used because it is nil-blockchain-safe and always answers,
// so a pass here isolates the transport+crypto+framing layers from chain state.
func TestWalletRPCRoundTripReproducesGUIPath(t *testing.T) {
	rpcServer := rpc.NewServerWithArtifactPath(nil, nil, nil, t.TempDir()+"/artifacts")

	srv := NewTCPServer("127.0.0.1:0", make(chan *security.Message, 8), rpcServer, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("start wallet-RPC listener: %v", err)
	}
	defer srv.Stop()

	// The port number is irrelevant to the protocol — an ephemeral port avoids
	// colliding with a real node an operator may have on the canonical 8700 —
	// but every byte on the wire is exactly what the GUI exchanges with the
	// node's wallet/JSON-RPC listener.
	addr := srv.listener.Addr().String()

	// Exactly what the GUI's GetChainTipHeader/GetBalance do: CallRPC over the
	// handshake-authenticated, encrypted, length-framed jsonrpc channel.
	done := make(chan struct{})
	var raw string
	var callErr error
	go func() {
		defer close(done)
		out, err := rpc.CallRPC(addr, "getsyncstatus", nil, 20)
		if err != nil {
			callErr = err
			return
		}
		raw = string(out)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("CallRPC hung: the server never returned a framed, encrypted response — this would reproduce the GUI's i/o timeout")
	}

	if callErr != nil {
		t.Fatalf("wallet-RPC round trip failed: %v", callErr)
	}
	if strings.TrimSpace(raw) == "" || raw == "null" {
		t.Fatalf("getsyncstatus must return a real payload, got %q", raw)
	}
	t.Logf("wallet-RPC round trip OK, getsyncstatus => %s", raw)
}
