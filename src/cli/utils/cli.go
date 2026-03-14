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

// go/src/cli/utils/cli.go
package utils

import (
	"flag"
	"fmt"

	"github.com/sphinxorg/protocol/src/bind"
	"github.com/sphinxorg/protocol/src/network"
)

// ---------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------
// Execute is the main entry point for the Sphinx blockchain CLI
// It handles command-line flag parsing and dispatches to the appropriate
// execution mode: test mode, normal mode, or config-based mode
func Execute() error {
	// Create configuration structs for standard and test modes
	cfg := &Config{}         // Standard node configuration
	testCfg := &TestConfig{} // Test-specific configuration

	// ----- standard CLI flags ------------------------------------------------
	// Define all command-line flags for node configuration

	// Configuration file flag - path to JSON config file
	flag.StringVar(&cfg.configFile, "config", "", "Path to node configuration JSON file")

	// Number of nodes to initialize in the network
	flag.IntVar(&cfg.numNodes, "nodes", 1, "Number of nodes to initialise")

	// Roles for each node (sender, receiver, validator, none)
	flag.StringVar(&cfg.roles, "roles", "none", "Comma-separated node roles (sender,receiver,validator,none)")

	// TCP address for P2P communication
	flag.StringVar(&cfg.tcpAddr, "tcp-addr", "", "TCP address (e.g., 127.0.0.1:30303)")

	// UDP port for node discovery
	flag.StringVar(&cfg.udpPort, "udp-port", "", "UDP port for discovery (e.g., 30304)")

	// HTTP port for JSON-RPC API
	flag.StringVar(&cfg.httpPort, "http-port", "", "HTTP port for API (e.g., 127.0.0.1:8545)")

	// WebSocket port for real-time subscriptions
	flag.StringVar(&cfg.wsPort, "ws-port", "", "WebSocket port (e.g., 127.0.0.1:8600)")

	// Seed nodes for network bootstrap (comma-separated UDP addresses)
	flag.StringVar(&cfg.seedNodes, "seeds", "", "Comma-separated seed node UDP addresses")

	// Directory for LevelDB storage
	flag.StringVar(&cfg.dataDir, "datadir", "data", "Directory for LevelDB storage")

	// Index of the node to run (when running multiple nodes)
	flag.IntVar(&cfg.nodeIndex, "node-index", 0, "Index of the node to run (0 to numNodes-1)")

	// ----- test-only flag ----------------------------------------------------
	// Special flag for running the PBFT integration test
	flag.IntVar(&testCfg.NumNodes, "test-nodes", 0,
		"Run the PBFT integration test with N validator nodes (0 = disabled)")

	// Parse all defined command-line flags
	flag.Parse()

	// ------------------------------------------------------------------------
	// 1. Test mode – no other flags allowed
	// ------------------------------------------------------------------------
	// If test-nodes flag is provided with a positive number, run in test mode
	if testCfg.NumNodes > 0 {
		// Ensure no other flags are combined with test mode
		if flag.NFlag() > 1 {
			return fmt.Errorf("-test-nodes cannot be combined with other flags")
		}
		// Call the PBFT consensus test with the specified number of nodes
		return CallConsensus(testCfg.NumNodes)
	}

	// ------------------------------------------------------------------------
	// 2. Normal mode (unchanged)
	// ------------------------------------------------------------------------
	// If no flags were provided, run the default multi-node setup
	if flag.NFlag() == 0 {
		// Use the bind package's RunTwoNodes function to start a default network
		// This is the simplest way to run the blockchain with default settings
		return bind.RunMultipleNodesInternal()
	}

	// ------------------------------------------------------------------------
	// 3. Config file or generated config
	// ------------------------------------------------------------------------
	// If flags were provided, configure and start a specific node
	var nodeConfig network.NodePortConfig

	// Check if a config file was specified
	if cfg.configFile != "" {
		// Load node configurations from JSON file
		configs, err := network.LoadFromFile(cfg.configFile)
		if err != nil {
			return fmt.Errorf("failed to load config file: %v", err)
		}

		// Validate that the requested node index is within range
		if cfg.nodeIndex < 0 || cfg.nodeIndex >= len(configs) {
			return fmt.Errorf("node-index %d out of range for %d configs", cfg.nodeIndex, len(configs))
		}

		// Select the configuration for the specified node index
		nodeConfig = configs[cfg.nodeIndex]
	} else {
		// Generate configurations programmatically based on flags

		// Parse the roles string into a slice of roles for each node
		// Example: "validator,validator,validator" for 3 validator nodes
		roles := bind.ParseRoles(cfg.roles, cfg.numNodes)

		// Create map for flag overrides to customize node configuration
		flagOverrides := make(map[string]string)

		// Add TCP address override if provided
		if cfg.tcpAddr != "" {
			flagOverrides[fmt.Sprintf("tcpAddr%d", cfg.nodeIndex)] = cfg.tcpAddr
		}

		// Add UDP port override if provided
		if cfg.udpPort != "" {
			flagOverrides[fmt.Sprintf("udpPort%d", cfg.nodeIndex)] = cfg.udpPort
		}

		// Add HTTP port override if provided
		if cfg.httpPort != "" {
			flagOverrides[fmt.Sprintf("httpPort%d", cfg.nodeIndex)] = cfg.httpPort
		}

		// Add WebSocket port override if provided
		if cfg.wsPort != "" {
			flagOverrides[fmt.Sprintf("wsPort%d", cfg.nodeIndex)] = cfg.wsPort
		}

		// Add seed nodes override if provided
		if cfg.seedNodes != "" {
			flagOverrides["seeds"] = cfg.seedNodes
		}

		// Generate node configurations using the bind package
		configs, err := network.GetNodePortConfigs(cfg.numNodes, roles, flagOverrides)
		if err != nil {
			return fmt.Errorf("failed to generate node configs: %v", err)
		}

		// Validate that the requested node index is within range
		if cfg.nodeIndex < 0 || cfg.nodeIndex >= len(configs) {
			return fmt.Errorf("node-index %d out of range for %d nodes", cfg.nodeIndex, cfg.numNodes)
		}

		// Select the configuration for the specified node index
		nodeConfig = configs[cfg.nodeIndex]
	}

	// Start a single node with the selected configuration
	// Use the bind package's StartSingleNode function to initialize and run the node
	return bind.StartSingleNodeInternal(nodeConfig, cfg.dataDir)
}
