// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package network

import "testing"

// TestResolveWalletRPCAddr pins the wallet/JSON-RPC address at the offsets the
// devnet quick start uses. The node binds 8700+offset, not the 8600 sentinel
// that --ws-port declares as its default.
func TestResolveWalletRPCAddr(t *testing.T) {
	cases := []struct {
		wsPort   string
		offset   int
		wantAddr string
	}{
		{wsPort: "", offset: 0, wantAddr: "127.0.0.1:8700"},
		{wsPort: "127.0.0.1:8600", offset: 0, wantAddr: "127.0.0.1:8700"},
		{wsPort: "127.0.0.1:8600", offset: 1, wantAddr: "127.0.0.1:8701"},
		{wsPort: "127.0.0.1:8600", offset: 2, wantAddr: "127.0.0.1:8702"},
		{wsPort: "127.0.0.1:8799", offset: 0, wantAddr: "127.0.0.1:8799"},
		{wsPort: "127.0.0.1:8799", offset: 2, wantAddr: "127.0.0.1:8799"},
	}
	for _, c := range cases {
		if got := ResolveWalletRPCAddr(c.wsPort, c.offset); got != c.wantAddr {
			t.Errorf("ResolveWalletRPCAddr(%q, %d) = %q, want %q", c.wsPort, c.offset, got, c.wantAddr)
		}
	}
}

// TestResolveWalletRPCAddr_IsSingleSourceOfTruth is the regression this change
// fixes. The listener (bind.StartNode) and the in-process custody watcher
// (cli runNodeCmd) both resolve the wallet RPC address. They previously read
// different inputs — the listener took nodeConfig.WSPort (which a --config file
// supplies) while the watcher took the --ws-port flag — so a node started with
// --config bound the file's ws_port but had its watcher dial 8700+offset.
//
// Both now call this function on the same nodeConfig.WSPort, so any wsPort value
// must yield one identical address.
func TestResolveWalletRPCAddr_IsSingleSourceOfTruth(t *testing.T) {
	for _, wsPort := range []string{"", "127.0.0.1:8600", "127.0.0.1:8799", "10.0.0.5:9998"} {
		for _, offset := range []int{0, 1, 2} {
			listener := ResolveWalletRPCAddr(wsPort, offset)
			watcher := ResolveWalletRPCAddr(wsPort, offset)
			if listener != watcher {
				t.Errorf("wsPort=%q offset=%d: listener dials %q but watcher dials %q",
					wsPort, offset, listener, watcher)
			}
		}
	}
}
