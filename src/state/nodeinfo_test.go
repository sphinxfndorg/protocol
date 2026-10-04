// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/state/nodeinfo_test.go
package state

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// newStateTestBlock builds a minimal block for the SMR final-state tests.
// createFinalStateFromBlock slices GetHash()[:16], so Hash must be populated.
func newStateTestBlock(t *testing.T, height uint64) *types.Block {
	t.Helper()
	return &types.Block{
		Header: &types.BlockHeader{
			Hash:       bytes.Repeat([]byte{0xAB}, 32),
			Height:     height,
			Block:      height,
			Timestamp:  1784143998,
			Difficulty: big.NewInt(1),
			GasLimit:   big.NewInt(1),
			GasUsed:    big.NewInt(0),
		},
	}
}

// newStateTestStorage builds a Storage rooted in a temp dir for these tests.
//
// It also redirects the process-wide common data dir, because src/state has no
// TestMain and common.GetDataDir() otherwise defaults to the relative "data",
// which writes chain_state.json into the package directory.
func newStateTestStorage(t *testing.T) *Storage {
	t.Helper()
	root := t.TempDir()

	previous := common.GetDataDir()
	common.SetDataDir(root)
	t.Cleanup(func() { common.SetDataDir(previous) })

	store, err := NewStorage(filepath.Join(root, "node"))
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestSaveCompleteChainState_NilFallbackOmitsFabricatedAddress pins that the
// nil-slot fallback writes an EMPTY node_address rather than an invented one.
//
// The fallback used to write "127.0.0.1:<32307+index>", a port derived from the
// array index that named no socket this node ever bound.
func TestSaveCompleteChainState_NilFallbackOmitsFabricatedAddress(t *testing.T) {
	store := newStateTestStorage(t)

	real := &NodeInfo{
		NodeID:      "Node-127.0.0.1:30303",
		NodeName:    "Node-127.0.0.1:30303",
		NodeAddress: "127.0.0.1:30303",
	}
	chainState := &ChainState{Nodes: []*NodeInfo{real, nil}}
	params := &ChainParams{
		ChainID:       73310,
		ChainName:     "Sphinx Devnet",
		Symbol:        "SPX",
		GenesisTime:   "2026-07-15T19:33:18Z",
		GenesisHash:   "GENESIS_test",
		DefaultPort:   32309,
		BIP44CoinType: 1,
		LedgerName:    "Sphinx Devnet",
	}

	if err := store.SaveCompleteChainState(chainState, params, nil, nil); err != nil {
		t.Fatalf("SaveCompleteChainState: %v", err)
	}

	raw, err := os.ReadFile(store.GetChainStatePath())
	if err != nil {
		t.Fatalf("read chain_state.json: %v", err)
	}

	// Check node_address specifically, not the whole file: the NodeID fallback
	// still contains "Node-127.0.0.1:32307" and is deliberately out of scope
	// here (it is the subject of the option-(b) review).
	var decoded struct {
		Nodes []map[string]json.RawMessage `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode chain_state.json: %v", err)
	}

	for i, node := range decoded.Nodes {
		addrRaw, present := node["node_address"]
		if !present {
			continue // omitted when unknown, which is the intended shape
		}
		var addr string
		if err := json.Unmarshal(addrRaw, &addr); err != nil {
			t.Fatalf("nodes[%d].node_address is not a string: %v", i, err)
		}
		if addr == "" {
			continue
		}
		if strings.HasPrefix(addr, "127.0.0.1:3230") {
			t.Errorf("nodes[%d].node_address = %q, a fabricated index-derived address", i, addr)
		}
	}

	// The real entry's address must survive verbatim.
	if !strings.Contains(string(raw), `"127.0.0.1:30303"`) {
		t.Errorf("chain_state.json lost the real address:\n%s", raw)
	}

	reloaded, err := store.LoadCompleteChainState()
	if err != nil {
		t.Fatalf("LoadCompleteChainState: %v", err)
	}
	if reloaded == nil {
		t.Fatal("LoadCompleteChainState returned nil")
	}

	// The nil slot is still replaced (the NodeID fallback is unchanged in this
	// task), but its address must be empty rather than fabricated. The real
	// entry must keep its own address.
	var sawFallback, sawReal bool
	for i, node := range reloaded.Nodes {
		if node == nil {
			t.Fatalf("nodes[%d] is nil", i)
		}
		switch {
		case strings.HasPrefix(node.NodeID, "Node-127.0.0.1:30303"):
			sawReal = true
			if node.NodeAddress != "127.0.0.1:30303" {
				t.Errorf("nodes[%d].NodeAddress = %q, want the real 127.0.0.1:30303", i, node.NodeAddress)
			}
		default:
			// The entry that replaced the nil slot.
			sawFallback = true
			if node.NodeAddress != "" {
				t.Errorf("nodes[%d].NodeAddress = %q, want \"\" (no fabricated address)", i, node.NodeAddress)
			}
		}
	}
	if !sawReal {
		t.Error("the real node entry disappeared")
	}
	if !sawFallback {
		t.Error("the nil slot was not replaced; the fallback path changed unexpectedly")
	}
}

// TestNodeAddress_OmitsWhenEmpty pins the JSON shape: an unknown address is
// omitted entirely rather than serialising an empty string.
func TestNodeAddress_OmitsWhenEmpty(t *testing.T) {
	store := newStateTestStorage(t)

	chainState := &ChainState{Nodes: []*NodeInfo{{NodeID: "Node-127.0.0.1:30303"}}}
	params := &ChainParams{ChainID: 73310, GenesisTime: "2026-07-15T19:33:18Z", GenesisHash: "GENESIS_test"}
	if err := store.SaveCompleteChainState(chainState, params, nil, nil); err != nil {
		t.Fatalf("SaveCompleteChainState: %v", err)
	}

	raw, err := os.ReadFile(store.GetChainStatePath())
	if err != nil {
		t.Fatalf("read chain_state.json: %v", err)
	}
	if strings.Contains(string(raw), `"node_address"`) {
		t.Errorf("chain_state.json serialised node_address for an unknown address:\n%s", raw)
	}
}

// TestNodeAddressFromID pins that a Node-<host:port> identity yields its address,
// and that anything else yields "" instead of a mangled value.
func TestNodeAddressFromID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Node-127.0.0.1:30303", "127.0.0.1:30303"},
		{"Node-127.0.0.1:30304", "127.0.0.1:30304"},
		{"Node-10.0.0.5:8545", "10.0.0.5:8545"},
		// Malformed / unqualified: empty, never "127.0.0.1:Node-...".
		{"Node-no-port", ""},
		{"Node-", ""},
		{"some-legacy-id", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := nodeAddressFromID(c.in); got != c.want {
			t.Errorf("nodeAddressFromID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestCreateFinalStateFromBlock_NoFabricatedAddress pins the SMR block path: the
// address comes from this node's real identity, never a hardcoded 32307.
func TestCreateFinalStateFromBlock_NoFabricatedAddress(t *testing.T) {
	store := newStateTestStorage(t)
	sm := NewStateMachine(store, "Node-127.0.0.1:30304")

	block := newStateTestBlock(t, 1)
	fs := sm.createFinalStateFromBlock(block)

	if fs.NodeAddress == "127.0.0.1:32307" {
		t.Fatal("createFinalStateFromBlock returned the fabricated 32307 address")
	}
	if got, want := fs.NodeAddress, "127.0.0.1:30304"; got != want {
		t.Errorf("NodeAddress = %q, want %q (derived from the node identity)", got, want)
	}
}

// TestCreateFinalStateFromBlock_EmptyIdentityOmitsAddress pins that a node with
// no usable identity writes no address at all.
func TestCreateFinalStateFromBlock_EmptyIdentityOmitsAddress(t *testing.T) {
	store := newStateTestStorage(t)
	sm := NewStateMachine(store, "")

	fs := sm.createFinalStateFromBlock(newStateTestBlock(t, 1))
	if fs.NodeAddress != "" {
		t.Errorf("NodeAddress = %q, want \"\" for a node with no identity", fs.NodeAddress)
	}
}
