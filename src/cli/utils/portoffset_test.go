// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package utils

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/network"
)

// TestApplyPortOffset_MatchesNodeIdentity pins the local addressing arithmetic
// used by the quick start. Offsets select unique listen ports/datadirs without
// changing the node ID derivation rule.
func TestApplyPortOffset_MatchesNodeIdentity(t *testing.T) {
	// nodeID is how bind derives a validator identity from the TCP address.
	nodeID := func(tcp string) string { return "Node-" + tcp }

	cases := []struct {
		offset   int
		wantTCP  string
		wantHTTP string
		wantWS   string
		wantDir  string
	}{
		{offset: 0, wantTCP: defaultTCPAddr, wantHTTP: defaultHTTPAddr, wantWS: defaultWSAddr, wantDir: "data"},
		{offset: 1, wantTCP: "127.0.0.1:30304", wantHTTP: "127.0.0.1:8546", wantWS: "127.0.0.1:8701", wantDir: "data/node1"},
		{offset: 2, wantTCP: "127.0.0.1:30305", wantHTTP: "127.0.0.1:8547", wantWS: "127.0.0.1:8702", wantDir: "data/node2"},
	}
	for _, c := range cases {
		// Start from the flag defaults exactly as the `node` subcommand does.
		tcp, http, ws, dir := defaultTCPAddr, defaultHTTPAddr, defaultWSAddr, defaultDataDir
		applyPortOffset(c.offset, &tcp, &http, &ws, &dir)

		if tcp != c.wantTCP {
			t.Errorf("offset %d: tcp = %q, want %q (node ID %q)", c.offset, tcp, c.wantTCP, nodeID(tcp))
		}
		if http != c.wantHTTP {
			t.Errorf("offset %d: http = %q, want %q", c.offset, http, c.wantHTTP)
		}
		if ws != c.wantWS {
			t.Errorf("offset %d: wallet rpc = %q, want %q (8700 + offset)", c.offset, ws, c.wantWS)
		}
		if dir != c.wantDir {
			t.Errorf("offset %d: datadir = %q, want %q", c.offset, dir, c.wantDir)
		}
	}
}

// TestApplyPortOffset_RespectsExplicitValues pins the second half of the
// contract: --port-offset shifts DEFAULTS only. An explicit --tcp-addr or
// --datadir always wins, so a node ID can never be silently rewritten by the
// offset.
func TestApplyPortOffset_RespectsExplicitValues(t *testing.T) {
	tcp, http, ws, dir := "10.0.0.5:40000", "10.0.0.5:9999", "10.0.0.5:9998", "/var/lib/sphinx"
	applyPortOffset(7, &tcp, &http, &ws, &dir)

	if tcp != "10.0.0.5:40000" {
		t.Errorf("explicit --tcp-addr was shifted: %q", tcp)
	}
	if http != "10.0.0.5:9999" {
		t.Errorf("explicit --http-port was shifted: %q", http)
	}
	if ws != "10.0.0.5:9998" {
		t.Errorf("explicit --ws-port was shifted: %q", ws)
	}
	if dir != "/var/lib/sphinx" {
		t.Errorf("explicit --datadir was shifted: %q", dir)
	}
}

// TestConfigFileEntry_NeverIndexesByPortOffset pins decision 2: --port-offset is
// file this process uses. A multi-entry file is a de-facto pre-agreed node
// roster, which is exactly the knowledge this design deletes, so it is refused
// rather than silently resolved.
func TestConfigFileEntry_NeverIndexesByPortOffset(t *testing.T) {
	single := []network.NodePortConfig{{ID: "a", TCPAddr: "127.0.0.1:30303"}}

	// A single entry is used whatever the offset is — the offset has already
	// shifted the flag defaults, and --config wins over them.
	for _, offset := range []int{0, 1, 2, 7, 99} {
		got, err := configFileEntry(single, offset)
		if err != nil {
			t.Errorf("offset %d: single-entry config must be accepted, got %v", offset, err)
			continue
		}
		if got.TCPAddr != "127.0.0.1:30303" {
			t.Errorf("offset %d: got TCPAddr %q, want the single entry's 127.0.0.1:30303", offset, got.TCPAddr)
		}
	}

	// A multi-entry file is refused, for EVERY offset — including offset 0,
	// which under the old indexing behaviour would have silently picked
	// configs[0].
	multi := []network.NodePortConfig{
		{ID: "a", TCPAddr: "127.0.0.1:30303"},
		{ID: "b", TCPAddr: "127.0.0.1:30304"},
	}
	for _, offset := range []int{0, 1, 5} {
		_, err := configFileEntry(multi, offset)
		if err == nil {
			t.Errorf("offset %d: a %d-entry --config file must be refused, not indexed", offset, len(multi))
			continue
		}
		// The message must explain the rule, not just fail.
		if !strings.Contains(err.Error(), "ONE node") {
			t.Errorf("offset %d: error should explain that a config file describes ONE node, got: %v", offset, err)
		}
	}

	// An empty file is refused too.
	if _, err := configFileEntry(nil, 0); err == nil {
		t.Error("an empty --config file must be refused")
	}
}

func TestValidateProductionNodeStart_RejectsDevelopmentShapes(t *testing.T) {
	t.Setenv("SPHINX_MAINNET_GENESIS_DIGEST", strings.Repeat("a", 64))

	cases := []struct {
		name string
		args struct {
			network    string
			tcp        string
			dataDir    string
			seeds      string
			portOffset int
		}
		want string
	}{
		{
			name: "devnet",
			args: struct {
				network    string
				tcp        string
				dataDir    string
				seeds      string
				portOffset int
			}{network: "devnet", tcp: "203.0.113.10:30303", dataDir: "/var/lib/sphinx/mainnet", seeds: "203.0.113.1:30303"},
			want: "devnet",
		},
		{
			name: "portOffset",
			args: struct {
				network    string
				tcp        string
				dataDir    string
				seeds      string
				portOffset int
			}{network: "mainnet", tcp: "203.0.113.10:30303", dataDir: "/var/lib/sphinx/mainnet", seeds: "203.0.113.1:30303", portOffset: 1},
			want: "--port-offset",
		},
		{
			name: "localhost",
			args: struct {
				network    string
				tcp        string
				dataDir    string
				seeds      string
				portOffset int
			}{network: "mainnet", tcp: "127.0.0.1:30303", dataDir: "/var/lib/sphinx/mainnet", seeds: "203.0.113.1:30303"},
			want: "public --tcp-addr",
		},
		{
			name: "defaultDatadir",
			args: struct {
				network    string
				tcp        string
				dataDir    string
				seeds      string
				portOffset int
			}{network: "mainnet", tcp: "203.0.113.10:30303", dataDir: "data", seeds: "203.0.113.1:30303"},
			want: "persistent --datadir",
		},
		{
			name: "missingSeeds",
			args: struct {
				network    string
				tcp        string
				dataDir    string
				seeds      string
				portOffset int
			}{network: "mainnet", tcp: "203.0.113.10:30303", dataDir: "/var/lib/sphinx/mainnet"},
			want: "--seeds",
		},
		{
			name: "relativeDatadir",
			args: struct {
				network    string
				tcp        string
				dataDir    string
				seeds      string
				portOffset int
			}{network: "mainnet", tcp: "203.0.113.10:30303", dataDir: "prod/mainnet", seeds: "203.0.113.1:30303"},
			want: "absolute persistent --datadir",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProductionNodeStart("production", tc.args.network, tc.args.tcp, tc.args.dataDir, tc.args.seeds, tc.args.portOffset)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateProductionNodeStart error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestValidateProductionNodeStart_RequiresDigestPin(t *testing.T) {
	t.Setenv("SPHINX_TESTNET_GENESIS_DIGEST", "")
	err := validateProductionNodeStart("production", "testnet", "203.0.113.10:30303", "/var/lib/sphinx/testnet", "203.0.113.1:30303", 0)
	if err == nil || !strings.Contains(err.Error(), "SPHINX_TESTNET_GENESIS_DIGEST") {
		t.Fatalf("validateProductionNodeStart error = %v, want missing testnet digest", err)
	}
}

func TestValidateProductionNodeStart_AcceptsProductionShape(t *testing.T) {
	t.Setenv("SPHINX_MAINNET_GENESIS_DIGEST", strings.Repeat("a", 64))
	err := validateProductionNodeStart("production", "mainnet", "validator-1.example.org:30303", "/var/lib/sphinx/mainnet", "boot-1.example.org:30303", 0)
	if err != nil {
		t.Fatalf("validateProductionNodeStart rejected production shape: %v", err)
	}
}

func TestValidateProductionNodeStart_DevelopmentModeNoops(t *testing.T) {
	t.Setenv("SPHINX_MAINNET_GENESIS_DIGEST", "")
	err := validateProductionNodeStart("development", "devnet", "127.0.0.1:30303", "data", "", 2)
	if err != nil {
		t.Fatalf("development mode should not apply production guardrails: %v", err)
	}
}

func TestIsLocalProductionHost(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "::1", "0.0.0.0", "[::]"} {
		if !isLocalProductionHost(host) {
			t.Fatalf("%s should be treated as local", host)
		}
	}
	for _, host := range []string{"203.0.113.10", "validator.example.org"} {
		if isLocalProductionHost(host) {
			t.Fatalf("%s should not be treated as local", host)
		}
	}
}

func TestValidateProductionNodeStart_RejectsInvalidMode(t *testing.T) {
	err := validateProductionNodeStart("prod", "mainnet", "203.0.113.10:30303", "/var/lib/sphinx/mainnet", "203.0.113.1:30303", 0)
	if err == nil || !strings.Contains(err.Error(), "--mode") {
		t.Fatalf("validateProductionNodeStart error = %v, want invalid mode", err)
	}
}

func TestValidateProductionNodeStart_ErrorMentionsResolvedDatadir(t *testing.T) {
	t.Setenv("SPHINX_MAINNET_GENESIS_DIGEST", strings.Repeat("a", 64))
	dir := fmt.Sprintf("data%snode1", string(os.PathSeparator))
	err := validateProductionNodeStart("production", "mainnet", "203.0.113.10:30303", dir, "203.0.113.1:30303", 0)
	if err == nil || !strings.Contains(err.Error(), dir) {
		t.Fatalf("validateProductionNodeStart error = %v, want resolved datadir mentioned", err)
	}
}
