// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/cli/utils/types.go
package utils

import (
	"github.com/sphinxorg/protocol/src/params/commit"
	params "github.com/sphinxorg/protocol/src/params/denom"
)

// Config holds CLI configuration parameters.
// This struct is used to store all command-line flag values for node configuration
type Config struct {
	configFile string // Path to JSON configuration file
	numNodes   int    // Number of nodes to initialize in the network
	roles      string // Comma-separated list of node roles (validator, sender, receiver, none)
	tcpAddr    string // TCP address for P2P communication (e.g., "127.0.0.1:30303")
	udpPort    string // UDP port for node discovery (e.g., "30304")
	httpPort   string // HTTP port for JSON-RPC API (e.g., "127.0.0.1:8545")
	wsPort     string // WebSocket port for real-time subscriptions (e.g., "127.0.0.1:8600")
	seedNodes  string // Comma-separated list of seed node UDP addresses for network bootstrap
	dataDir    string // Directory path for LevelDB storage (default: "data")
	nodeIndex  int    // Index of the node to run when managing multiple nodes (0 to numNodes-1)
}

// TestConfig holds the parameters that the test harness uses.
// This struct is specifically for the PBFT integration test configuration
type TestConfig struct {
	NumNodes int // number of validator nodes to spin up for the consensus test (default 3)
	// Minimum of 3 nodes required for PBFT consensus to function properly
}

// Update the ChainIdentificationJSON struct - FIXED THE TYPE ISSUE
// ChainIdentificationJSON represents the structure for chain identification output
// Used for JSON serialization when displaying blockchain identification information
type ChainIdentificationJSON struct {
	// Timestamp when this chain identification was generated
	Timestamp string `json:"timestamp"`

	// ChainParams contains the core blockchain parameters (chain ID, name, magic number, etc.)
	// Changed from commit.SphinxChainParams to *commit.ChainParameters to fix type compatibility
	ChainParams *commit.ChainParameters `json:"chain_parameters"`

	// TokenInfo contains details about the native token (SPX) including name, symbol, decimals, total supply
	TokenInfo *params.TokenInfo `json:"token_info"`

	// WalletPaths maps wallet derivation path names to their actual BIP paths
	// Examples: "BIP44": "m/44'/60'/0'/0/0", "Ledger": "m/44'/60'/0'"
	WalletPaths map[string]string `json:"wallet_derivation_paths"`

	// NetworkInfo contains network-specific information like network type (mainnet/testnet)
	// and any other dynamic network properties
	NetworkInfo map[string]interface{} `json:"network_info"`
}

// NodeChainInfoJSON represents the structure for per-node chain information
// Used when capturing and serializing the state of individual nodes
type NodeChainInfoJSON struct {
	// NodeID is the unique identifier for this node
	NodeID string `json:"node_id"`

	// ChainInfo contains the blockchain parameters for this specific node
	ChainInfo map[string]interface{} `json:"chain_info"`

	// BlockHeight is the current height of the blockchain on this node
	BlockHeight uint64 `json:"block_height"`

	// BlockHash is the hash of the latest block on this node
	BlockHash string `json:"block_hash"`

	// Timestamp when this node information was captured
	Timestamp string `json:"timestamp"`
}
