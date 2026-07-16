// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/network/port.go
package network

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
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

const (
	// Base port numbers for different services
	// These are starting points for port allocation
	baseTCPPort  = 32307 // Base TCP port for P2P communication
	baseUDPPort  = 32418 // Base UDP port for DHT communication
	baseHTTPPort = 8645  // Base HTTP port for RPC API
	baseWSPort   = 8700  // Base WebSocket port for real-time updates
	portStep     = 10    // Increased to reduce localhost conflicts
)

// isPortInUse checks whether a TCP or UDP port is already bound on localhost.
func isPortInUse(port int) bool {
	// Try TCP first
	if ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
		_ = ln.Close()
	} else {
		return true
	}
	// Try UDP
	if ln, err := net.Listen("udp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
		_ = ln.Close()
	} else {
		return true
	}
	return false
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

// GetNodePortConfigs generates or retrieves a list of node port configurations.
// Parameters:
//   - numNodes: Number of nodes to configure
//   - roles: Slice of node roles (length should match numNodes)
//   - overrides: Map of port overrides (e.g., "tcpAddr0": "127.0.0.1:32307")
//
// Returns:
//   - Slice of node port configurations
//   - Error if configuration fails
func GetNodePortConfigs(numNodes int, roles []NodeRole, overrides map[string]string) ([]NodePortConfig, error) {
	// First, check if configurations already exist in the global store
	// Acquire read lock to check existing configs
	NodeConfigsLock.RLock()
	if len(NodeConfigs) >= numNodes {
		// We have enough configurations in the store, retrieve them
		configs := make([]NodePortConfig, 0, numNodes)
		for i := 0; i < numNodes; i++ {
			id := fmt.Sprintf("Node-%d", i) // Generate node ID
			if config, exists := NodeConfigs[id]; exists {
				configs = append(configs, config) // Add existing config
			} else {
				// Configuration missing for required node
				NodeConfigsLock.RUnlock()
				return nil, fmt.Errorf("configuration for node %s not found", id)
			}
		}
		NodeConfigsLock.RUnlock()
		return configs, nil // Return existing configs
	}
	NodeConfigsLock.RUnlock()

	// Generate new configurations if none exist or insufficient
	configs := make([]NodePortConfig, numNodes)

	// ★ FIX: Track used ports globally across all nodes to prevent conflicts
	// even when nodes are started independently in seed-based mode
	usedPorts := make(map[int]bool)

	// Pre-populate with currently used ports to avoid conflicts with
	// already-running nodes
	checkBasePorts := []int{baseTCPPort, baseUDPPort, baseHTTPPort, baseWSPort}
	scannedCount := 0
	for _, base := range checkBasePorts {
		for port := base; port < base+numNodes*portStep+100; port++ {
			scannedCount++
			if isPortInUse(port) {
				usedPorts[port] = true
			}
		}
	}
	log.Printf("GetNodePortConfigs: scanned %d candidate ports, %d already in use", scannedCount, len(usedPorts))

	// Generate configuration for each node
	for i := 0; i < numNodes; i++ {
		// Generate node name and ID
		name := fmt.Sprintf("Node-%d", i)
		id := name // Use name as ID for consistency

		// Determine node role (default to RoleNone if not specified)
		role := RoleNone
		if i < len(roles) {
			role = roles[i] // Use provided role
		}

		// Default ports based on node index
		tcpPort := baseTCPPort + i*portStep // TCP port increments by portStep
		udpPort := baseUDPPort + i*portStep // UDP port increments by portStep
		httpPort := baseHTTPPort + i        // HTTP port increments by 1
		wsPort := baseWSPort + i            // WebSocket port increments by 1

		// Override keys for each port type
		tcpAddrKey := fmt.Sprintf("tcpAddr%d", i)   // Key for TCP address override
		udpPortKey := fmt.Sprintf("udpPort%d", i)   // Key for UDP port override
		httpPortKey := fmt.Sprintf("httpPort%d", i) // Key for HTTP port override
		wsPortKey := fmt.Sprintf("wsPort%d", i)     // Key for WebSocket port override

		// TCP port configuration
		var tcpAddr string
		if override, ok := overrides[tcpAddrKey]; ok {
			// Use override if provided
			tcpAddr = override
		} else {
			// Find a free port if the default is in use
			for usedPorts[tcpPort] {
				var err error
				tcpPort, err = FindFreePort(tcpPort+portStep, "tcp")
				if err != nil {
					return nil, fmt.Errorf("failed to find free TCP port for node %s: %v", id, err)
				}
			}
			usedPorts[tcpPort] = true                      // Mark port as used
			tcpAddr = fmt.Sprintf("127.0.0.1:%d", tcpPort) // Format TCP address
		}

		// UDP port configuration
		var udpPortStr string
		if override, ok := overrides[udpPortKey]; ok {
			// Use override if provided
			udpPortStr = override
		} else {
			// Find a free port if the default is in use
			for usedPorts[udpPort] {
				var err error
				udpPort, err = FindFreePort(udpPort+portStep, "udp")
				if err != nil {
					return nil, fmt.Errorf("failed to find free UDP port for node %s: %v", id, err)
				}
			}
			usedPorts[udpPort] = true               // Mark port as used
			udpPortStr = fmt.Sprintf("%d", udpPort) // Format UDP port as string
		}

		// HTTP port configuration
		var httpAddr string
		if override, ok := overrides[httpPortKey]; ok {
			// Use override if provided
			httpAddr = override
		} else {
			// Find a free port if the default is in use
			for usedPorts[httpPort] {
				var err error
				httpPort, err = FindFreePort(httpPort+1, "tcp")
				if err != nil {
					return nil, fmt.Errorf("failed to find free HTTP port for node %s: %v", id, err)
				}
			}
			usedPorts[httpPort] = true                       // Mark port as used
			httpAddr = fmt.Sprintf("127.0.0.1:%d", httpPort) // Format HTTP address
		}

		// WebSocket port configuration
		var wsAddr string
		if override, ok := overrides[wsPortKey]; ok {
			// Use override if provided
			wsAddr = override
		} else {
			// Find a free port if the default is in use
			for usedPorts[wsPort] {
				var err error
				wsPort, err = FindFreePort(wsPort+1, "tcp")
				if err != nil {
					return nil, fmt.Errorf("failed to find free WebSocket port for node %s: %v", id, err)
				}
			}
			usedPorts[wsPort] = true                     // Mark port as used
			wsAddr = fmt.Sprintf("127.0.0.1:%d", wsPort) // Format WebSocket address
		}

		// Seed nodes configuration (for peer discovery)
		seedNodes := []string{}
		if seeds, ok := overrides["seeds"]; ok {
			// Split comma-separated seed list
			seedNodes = strings.Split(seeds, ",")
			// Validate seed nodes
			validSeeds := []string{}
			for _, seed := range seedNodes {
				// Verify seed address is valid UDP address
				if _, err := net.ResolveUDPAddr("udp", seed); err == nil {
					validSeeds = append(validSeeds, seed) // Keep valid seed
				} else {
					log.Printf("GetNodePortConfigs: Invalid seed address %s for node %s: %v", seed, id, err)
				}
			}
			seedNodes = validSeeds // Use only valid seeds
		} else {
			// Generate default seeds (all other nodes in the network)
			for j := 0; j < numNodes; j++ {
				if j != i { // Exclude self
					seedPort := baseUDPPort + j*portStep
					// Ensure seed port is not already used
					for usedPorts[seedPort] && seedPort != udpPort {
						var err error
						seedPort, err = FindFreePort(seedPort+portStep, "udp")
						if err != nil {
							return nil, fmt.Errorf("failed to find free seed UDP port for node %s: %v", id, err)
						}
					}
					// Add seed node to list
					seedNodes = append(seedNodes, fmt.Sprintf("127.0.0.1:%d", seedPort))
				}
			}
		}

		// Create node configuration
		configs[i] = NodePortConfig{
			ID:        id,         // Node identifier
			Name:      name,       // Node name
			TCPAddr:   tcpAddr,    // TCP address for P2P
			UDPPort:   udpPortStr, // UDP port for DHT
			HTTPPort:  httpAddr,   // HTTP address for RPC
			WSPort:    wsAddr,     // WebSocket address for real-time
			Role:      role,       // Node role
			SeedNodes: seedNodes,  // Seed nodes for discovery
		}
	}

	// Store generated configs in global store for future use
	// Acquire write lock to update the global config map
	NodeConfigsLock.Lock()
	for _, config := range configs {
		NodeConfigs[config.ID] = config // Store each configuration
	}
	NodeConfigsLock.Unlock()

	return configs, nil
}
