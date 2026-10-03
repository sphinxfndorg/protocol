// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/network/port.go
package network

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
)

// Global configuration store
var (
	// NodeConfigs maps node IDs to their port configurations
	// This global store allows nodes to share configuration across the network
	NodeConfigs = make(map[string]NodePortConfig) // Map node ID to config

	// NodeConfigsLock provides thread-safe access to the global configuration store
	NodeConfigsLock sync.RWMutex // Mutex for thread-safe access
)

// ClearNodeConfigs clears the global node configurations in a thread-safe manner.
// This is typically used during testing or when resetting the network configuration.
func ClearNodeConfigs() {
	// Acquire write lock to modify the global config map
	NodeConfigsLock.Lock()
	defer NodeConfigsLock.Unlock()
	// Reinitialize the map to empty state
	NodeConfigs = make(map[string]NodePortConfig)
}

// UpdateNodeConfig updates the global configuration for a node.
// Parameters:
//   - config: The node port configuration to store
func UpdateNodeConfig(config NodePortConfig) {
	// Acquire write lock to modify the global config map
	NodeConfigsLock.Lock()
	defer NodeConfigsLock.Unlock()
	// Store the configuration using the node ID as the key
	NodeConfigs[config.ID] = config
}

// GetNodeConfig retrieves the configuration for a node by ID.
// Parameters:
//   - id: The node ID to look up
//
// Returns:
//   - config: The node configuration if found
//   - exists: Boolean indicating whether the configuration was found
func GetNodeConfig(id string) (NodePortConfig, bool) {
	// Acquire read lock for concurrent access
	NodeConfigsLock.RLock()
	defer NodeConfigsLock.RUnlock()
	// Retrieve configuration and existence flag
	config, exists := NodeConfigs[id]
	return config, exists
}

// LoadFromFile reads a JSON configuration file and unmarshals it into a slice of NodePortConfig.
// Parameters:
//   - file: Path to the JSON configuration file
//
// Returns:
//   - Slice of node port configurations
//   - Error if file reading or parsing fails
func LoadFromFile(file string) ([]NodePortConfig, error) {
	// Read the entire file contents
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse JSON into slice of NodePortConfig
	var configs []NodePortConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// Store loaded configs in global store
	// Acquire write lock to update the global config map
	NodeConfigsLock.Lock()
	for _, config := range configs {
		NodeConfigs[config.ID] = config // Store each configuration
	}
	NodeConfigsLock.Unlock()

	return configs, nil
}

// ★ PORT BASES. The 32307-family arithmetic that used to live here
// (baseTCPPort/baseUDPPort/baseHTTPPort/portStep, used only by the deleted
// GetNodePortConfigs) is GONE: GetNodePortConfigs had zero callers, and its
// 32307 base contradicted the real CLI default of 127.0.0.1:30303, so it was a
// second, wrong port base that nothing used. --port-offset now derives
// addresses from the CLI defaults alone (30303 + offset), and the devnet flow
// is 30303 / 30304 / 30305.
//
// baseWSPort is kept because it names the wallet/JSON-RPC base (8700) and is
// cited by name in bind, transport and gui comments as the canonical value.
// It is documentation, not an allocator: the node computes 8700 + portOffset
// directly in bind.
const baseWSPort = 8700

// unsetWSPortDefault is the literal default the CLI declares for --ws-port. It
// is a sentinel meaning "unset", not a port the node listens on.
const unsetWSPortDefault = "127.0.0.1:8600"

// ResolveWalletRPCAddr returns the wallet/JSON-RPC address for one node.
//
// Both the listener (bind.StartNode) and every in-process client that dials the
// wallet RPC (the custody watcher) must resolve through this one function, so a
// --config-supplied address cannot bind the listener while a caller dials
// 8700+offset. An unset or sentinel value yields baseWSPort+portOffset; any
// explicit value is honoured verbatim.
func ResolveWalletRPCAddr(wsPort string, portOffset int) string {
	if wsPort == "" || wsPort == unsetWSPortDefault {
		return fmt.Sprintf("127.0.0.1:%d", baseWSPort+portOffset)
	}
	return wsPort
}

// FindFreePort finds an available port starting from basePort.
// Parameters:
//   - basePort: Starting port number to check
//   - protocol: Protocol type ("tcp" or "udp")
//
// Returns:
//   - Available port number
//   - Error if no free port is found
func FindFreePort(basePort int, protocol string) (int, error) {
	// Iterate through ports starting from basePort up to maximum (65535)
	for port := basePort; port <= 65535; port++ {
		var ln interface{} // Listener interface (TCP or UDP)
		var err error

		// Attempt to listen on the port based on protocol
		if protocol == "tcp" {
			// Create TCP listener on all interfaces (0.0.0.0)
			tcpAddr := &net.TCPAddr{Port: port, IP: net.ParseIP("0.0.0.0")}
			ln, err = net.ListenTCP("tcp", tcpAddr)
		} else {
			// Create UDP listener on all interfaces (0.0.0.0)
			udpAddr := &net.UDPAddr{Port: port, IP: net.ParseIP("0.0.0.0")}
			ln, err = net.ListenUDP("udp", udpAddr)
		}

		// If listening succeeded, the port is available
		if err == nil {
			// Close the listener based on its type
			switch conn := ln.(type) {
			case *net.TCPListener:
				conn.Close() // Close TCP listener
			case *net.UDPConn:
				conn.Close() // Close UDP connection
			}
			return port, nil // Return the available port
		}
	}
	// No free port found in the entire range
	return 0, fmt.Errorf("no free %s ports available starting from %d", protocol, basePort)
}

