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

// go/src/network/node.go
package network

import (
	"crypto/rand"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/sphinxorg/protocol/src/common"
	"github.com/sphinxorg/protocol/src/consensus"
	database "github.com/sphinxorg/protocol/src/core/state"
)

// Add chain identification constants
const (
	SphinxChainID       = 7331       // Unique identifier for Sphinx chain
	SphinxChainName     = "Sphinx"   // Human-readable chain name
	SphinxSymbol        = "SPX"      // Currency symbol
	SphinxBIP44CoinType = 7331       // BIP44 coin type for wallet derivation
	SphinxMagicNumber   = 0x53504858 // Network magic bytes "SPHX" in hex
	SphinxDefaultPort   = 32307      // Default P2P network port
)

// Add method to Node for chain identification
// GetChainInfo returns comprehensive chain information for this node
func (n *Node) GetChainInfo() map[string]interface{} {
	// Return map with chain identification parameters
	return map[string]interface{}{
		"chain_id":        SphinxChainID,       // Unique chain identifier
		"chain_name":      SphinxChainName,     // Human-readable chain name
		"symbol":          SphinxSymbol,        // Currency symbol
		"bip44_coin_type": SphinxBIP44CoinType, // BIP44 coin type for wallets
		"magic_number":    SphinxMagicNumber,   // Network magic bytes
		"default_port":    SphinxDefaultPort,   // Default P2P port
		"node_id":         n.ID,                // Node identifier
		"node_role":       n.Role,              // Node role (validator, full node, etc.)
	}
}

// GenerateChainHandshake generates handshake message with chain identification
// Used during peer connection to verify chain compatibility
func (n *Node) GenerateChainHandshake() string {
	// Get current chain information
	chainInfo := n.GetChainInfo()
	// Format handshake message with chain and node details
	return fmt.Sprintf(
		"SPHINX_HANDSHAKE\n"+
			"Chain: %s\n"+ // Chain name
			"Chain ID: %d\n"+ // Chain identifier
			"Node: %s\n"+ // Node ID
			"Role: %s\n"+ // Node role
			"Protocol: 1.0.0\n"+ // Protocol version
			"Timestamp: %d", // Current timestamp
		chainInfo["chain_name"],
		chainInfo["chain_id"],
		n.ID,
		n.Role,
		time.Now().Unix(), // Unix timestamp for freshness
	)
}

// Global registry for tracking consensus instances across all nodes
// This is used for message broadcasting in test environments
var (
	// consensusRegistry stores all active consensus instances keyed by node ID
	consensusRegistry = make(map[string]*consensus.Consensus)
	// registryMu provides thread-safe access to the consensus registry
	registryMu sync.RWMutex
)

// CallPeer represents a peer node in the consensus call system
// Implements the consensus.Peer interface for test environments
type CallPeer struct{ id string }

// GetNode returns the node associated with this call peer
// Implements the consensus.Peer interface
func (p *CallPeer) GetNode() consensus.Node {
	return &CallNode{id: p.id} // Return node with same ID
}

// CallNode represents a node in the consensus call system
// Implements the consensus.Node interface for test environments
type CallNode struct{ id string }

// GetID returns the unique identifier for this call node
// Implements the consensus.Node interface
func (n *CallNode) GetID() string {
	return n.id
}

// GetRole returns the role of this call node (always validator in test environment)
// Implements the consensus.Node interface
func (n *CallNode) GetRole() consensus.NodeRole {
	return consensus.RoleValidator // Test nodes are always validators
}

// GetStatus returns the status of this call node (always active in test environment)
// Implements the consensus.Node interface
func (n *CallNode) GetStatus() consensus.NodeStatus {
	return consensus.NodeStatusActive // Test nodes are always active
}

// CallNodeManager manages call nodes and provides broadcast functionality
// This is used in test environments to simulate network communication
type CallNodeManager struct {
	// Use proper peer storage with node ID as key and CallPeer as value
	peers map[string]consensus.Peer // Map of registered peers
	mu    sync.Mutex                // Mutex for thread-safe access
}

// NewCallNodeManager creates a new call node manager instance
// Returns a pointer to an initialized CallNodeManager
func NewCallNodeManager() *CallNodeManager {
	return &CallNodeManager{
		peers: make(map[string]consensus.Peer), // Initialize empty peer map
	}
}

// GetPeers returns all registered peers as consensus.Peer interfaces
func (m *CallNodeManager) GetPeers() map[string]consensus.Peer {
	m.mu.Lock() // Lock for thread safety
	defer m.mu.Unlock()

	// Return a copy of the peers map to prevent external modification
	peers := make(map[string]consensus.Peer)
	for id, peer := range m.peers {
		peers[id] = peer // Copy each peer
	}
	return peers
}

// GetPeerIDs returns the list of peer IDs for debugging
func (m *CallNodeManager) GetPeerIDs() []string {
	m.mu.Lock() // Lock for thread safety
	defer m.mu.Unlock()

	// Create slice of peer IDs
	ids := make([]string, 0, len(m.peers))
	for id := range m.peers {
		ids = append(ids, id) // Add each ID to slice
	}
	sort.Strings(ids) // Sort for consistent output
	return ids
}

// GetNode retrieves a specific node by its ID
// Returns a consensus.Node interface for the requested node
func (m *CallNodeManager) GetNode(nodeID string) consensus.Node {
	return &CallNode{id: nodeID} // Return new call node instance
}

// BroadcastMessage broadcasts consensus messages to all registered nodes
// This simulates network broadcast in test environments and delivers messages
// to all consensus instances including the sender (necessary for PBFT)
func (m *CallNodeManager) BroadcastMessage(messageType string, data interface{}) error {
	// Acquire read lock to safely access the consensus registry
	registryMu.RLock()
	defer registryMu.RUnlock()

	log.Printf("[CALL] Broadcasting %s message to %d peers", messageType, len(consensusRegistry))

	deliveredCount := 0   // Counter for successful deliveries
	var wg sync.WaitGroup // WaitGroup for concurrent message delivery

	// Deliver message to ALL consensus instances including self
	// This is required for PBFT to work correctly in test environment
	for nodeID, cons := range consensusRegistry {
		wg.Add(1) // Increment WaitGroup counter
		// Process each consensus instance in a separate goroutine
		go func(c *consensus.Consensus, typ string, d interface{}, nid string) {
			defer wg.Done() // Decrement counter when done

			var err error
			// Route message based on type and call appropriate handler
			switch typ {
			case "proposal":
				// Handle block proposal message
				prop, ok := d.(*consensus.Proposal)
				if !ok {
					log.Printf("[CALL] Invalid proposal type: %T", d)
					return
				}
				log.Printf("[CALL] Delivering proposal to %s from %s", nid, prop.ProposerID)
				err = c.HandleProposal(prop) // Call proposal handler

			case "prepare":
				// Handle prepare vote message
				vote, ok := d.(*consensus.Vote)
				if !ok {
					log.Printf("[CALL] Invalid prepare vote type: %T", d)
					return
				}
				log.Printf("[CALL] Delivering prepare vote to %s from %s", nid, vote.VoterID)
				err = c.HandlePrepareVote(vote) // Call prepare vote handler

			case "vote":
				// Handle commit vote message
				vote, ok := d.(*consensus.Vote)
				if !ok {
					log.Printf("[CALL] Invalid commit vote type: %T", d)
					return
				}
				log.Printf("[CALL] Delivering commit vote to %s from %s", nid, vote.VoterID)
				err = c.HandleVote(vote) // Call commit vote handler

			case "timeout":
				// Handle timeout message
				timeout, ok := d.(*consensus.TimeoutMsg)
				if !ok {
					log.Printf("[CALL] Invalid timeout type: %T", d)
					return
				}
				log.Printf("[CALL] Delivering timeout to %s from %s", nid, timeout.VoterID)
				err = c.HandleTimeout(timeout) // Call timeout handler

			default:
				log.Printf("[CALL] Unknown message type: %s", typ)
				return
			}

			// Log delivery result
			if err != nil {
				log.Printf("[CALL] Failed to deliver %s to %s: %v", typ, nid, err)
			} else {
				log.Printf("[CALL] Successfully delivered %s to %s", typ, nid)
				deliveredCount++ // Increment successful delivery counter
			}
		}(cons, messageType, data, nodeID)
	}

	// Wait for all message deliveries to complete
	wg.Wait()
	log.Printf("[CALL] Broadcast completed: %d/%d successful deliveries for %s",
		deliveredCount, len(consensusRegistry), messageType)

	return nil
}

// AddPeer registers a new peer node with the call node manager
func (m *CallNodeManager) AddPeer(id string) {
	m.mu.Lock() // Lock for thread safety
	defer m.mu.Unlock()

	// Check if peer already exists
	if _, exists := m.peers[id]; exists {
		log.Printf("[CALL] Peer %s already exists, skipping duplicate", id)
		return // Skip duplicate
	}

	// Create new peer and add to map
	m.peers[id] = &CallPeer{id: id}
	log.Printf("[CALL] Added peer: %s (total peers: %d)", id, len(m.peers))
}

// RemovePeer unregisters a peer node from the call node manager
func (m *CallNodeManager) RemovePeer(id string) {
	m.mu.Lock() // Lock for thread safety
	defer m.mu.Unlock()
	delete(m.peers, id) // Remove from map
	log.Printf("[CALL] Removed peer: %s", id)
}

// RegisterConsensus adds a consensus instance to the global registry
// This allows the consensus instance to receive broadcast messages
func RegisterConsensus(nodeID string, cons *consensus.Consensus) {
	registryMu.Lock() // Lock for thread safety
	defer registryMu.Unlock()
	consensusRegistry[nodeID] = cons // Add to registry
	log.Printf("Registered consensus for node %s", nodeID)
}

// UnregisterConsensus removes a consensus instance from the global registry
// This should be called when a consensus instance is shutting down
func UnregisterConsensus(nodeID string) {
	registryMu.Lock() // Lock for thread safety
	defer registryMu.Unlock()
	delete(consensusRegistry, nodeID) // Remove from registry
	log.Printf("Unregistered consensus for node %s", nodeID)
}

// GetConsensusRegistry returns the current consensus registry
// Primarily used for testing and debugging purposes
func GetConsensusRegistry() map[string]*consensus.Consensus {
	registryMu.RLock() // Read lock for thread safety
	defer registryMu.RUnlock()
	return consensusRegistry // Return registry (caller should not modify)
}

// NewNode creates a new node with the specified parameters
// Generates cryptographic keys and initializes node with provided configuration
// Updated NewNode function using only network address format
func NewNode(address, ip, port, udpPort string, isLocal bool, role NodeRole, db *database.DB) *Node {
	// Node ID is now the network address identifier
	nodeID := fmt.Sprintf("Node-%s", address)

	// Try to load existing keys using network address
	privateKey, publicKey, err := loadNodeKeysFromConfig(address)
	if err != nil {
		log.Printf("No existing keys found for node %s, generating new keys: %v", nodeID, err)

		// Generate new key pair
		privateKey, publicKey, err = generateFallbackKeys()
		if err != nil {
			log.Printf("Failed to generate key pair: %v", err)
			return nil // Critical failure, cannot create node
		}

		// Store keys using network address
		if err := storeNodeKeysToConfig(address, privateKey, publicKey); err != nil {
			log.Printf("Failed to store keys in config directory: %v", err)
			return nil // Critical failure, cannot proceed
		}

		log.Printf("Generated and stored new keys for node %s", nodeID)
	} else {
		log.Printf("Loaded existing keys for node %s", nodeID)
	}

	// Create node information structure for storage
	nodeInfo := map[string]interface{}{
		"id":          nodeID,                          // Node identifier
		"address":     address,                         // Network address
		"ip":          ip,                              // IP address
		"port":        port,                            // TCP port
		"udp_port":    udpPort,                         // UDP port for DHT
		"kademlia_id": GenerateKademliaID(address),     // Kademlia ID from address
		"role":        string(role),                    // Node role as string
		"is_local":    isLocal,                         // Local node flag
		"created_at":  time.Now().Format(time.RFC3339), // Creation timestamp
	}

	// Store node information using network address
	if err := common.WriteNodeInfo(address, nodeInfo); err != nil {
		log.Printf("Failed to store node info: %v", err)
		// Continue anyway, not critical
	}

	// Create and return node instance
	node := &Node{
		ID:         nodeID,                      // Node identifier
		Address:    address,                     // Network address
		IP:         ip,                          // IP address
		Port:       port,                        // TCP port
		UDPPort:    udpPort,                     // UDP port
		KademliaID: GenerateKademliaID(address), // Kademlia ID
		PrivateKey: privateKey,                  // Private key bytes
		PublicKey:  publicKey,                   // Public key bytes
		IsLocal:    isLocal,                     // Local node flag
		Role:       role,                        // Node role
		Status:     NodeStatusActive,            // Initial status (active)
		db:         db,                          // Database reference
	}

	return node
}

// Update key management functions to use network address
// storeNodeKeysToConfig saves cryptographic keys to the config directory
func storeNodeKeysToConfig(address string, privateKey, publicKey []byte) error {
	return common.WriteKeysToFile(address, privateKey, publicKey)
}

// loadNodeKeysFromConfig loads cryptographic keys from the config directory
func loadNodeKeysFromConfig(address string) ([]byte, []byte, error) {
	// Check if keys exist before attempting to load
	if !common.KeysExist(address) {
		return nil, nil, fmt.Errorf("keys do not exist for node %s", address)
	}
	return common.ReadKeysFromFile(address)
}

// generateFallbackKeys provides a simple key generation fallback
// Used when the primary key generation method fails
func generateFallbackKeys() ([]byte, []byte, error) {
	// Allocate byte slices for keys
	privateKey := make([]byte, 32) // 256-bit private key
	publicKey := make([]byte, 32)  // 256-bit public key

	// Generate random bytes for private key
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	// Generate random bytes for public key
	if _, err := rand.Read(publicKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate public key: %w", err)
	}

	return privateKey, publicKey, nil
}

// loadNodeKeys loads cryptographic keys from the database
// Used for backward compatibility with database storage
func loadNodeKeys(db *database.DB, nodeID string) ([]byte, []byte, error) {
	// Load private key from database
	privateKeyKey := fmt.Sprintf("node:%s:private_key", nodeID)
	privateKey, err := db.Get(privateKeyKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load private key: %w", err)
	}

	// Load public key from database
	publicKeyKey := fmt.Sprintf("node:%s:public_key", nodeID)
	publicKey, err := db.Get(publicKeyKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load public key: %w", err)
	}

	return privateKey, publicKey, nil
}

// GenerateNodeID creates a node ID from the node's public key
// Uses Kademlia ID generation for consistent node identification
func (n *Node) GenerateNodeID() NodeID {
	return GenerateKademliaID(string(n.PublicKey))
}

// UpdateStatus updates the node's status and last seen timestamp
// Used for node health monitoring and network management
func (n *Node) UpdateStatus(status NodeStatus) {
	n.Status = status       // Update status
	n.LastSeen = time.Now() // Update last seen timestamp
	log.Printf("Node %s (Role=%s) status updated to %s", n.ID, n.Role, status)
}

// UpdateRole changes the node's role in the network
// Allows dynamic role assignment during node operation
func (n *Node) UpdateRole(role NodeRole) {
	n.Role = role // Update role
	log.Printf("Node %s updated role to %s", n.ID, role)
}

// NewPeer creates a new peer instance from a node
// Initializes connection state with default values
func NewPeer(node *Node) *Peer {
	return &Peer{
		Node:             node,           // Reference to the node
		ConnectionStatus: "disconnected", // Initial connection status
		ConnectedAt:      time.Time{},    // Zero time (not connected)
		LastPing:         time.Time{},    // Zero time (no ping sent)
		LastPong:         time.Time{},    // Zero time (no pong received)
	}
}

// ConnectPeer establishes a connection to the peer
// Returns error if the node is not in active status
func (p *Peer) ConnectPeer() error {
	// Check if node is active before connecting
	if p.Node.Status != NodeStatusActive {
		return fmt.Errorf("cannot connect to node %s: status is %s", p.Node.ID, p.Node.Status)
	}
	p.ConnectionStatus = "connected" // Update status
	p.ConnectedAt = time.Now()       // Record connection time
	log.Printf("Peer %s (Role=%s) connected at %s", p.Node.ID, p.Node.Role, p.ConnectedAt)
	return nil
}

// DisconnectPeer terminates the connection to the peer
// Resets all connection-related timestamps
func (p *Peer) DisconnectPeer() {
	p.ConnectionStatus = "disconnected" // Update status
	p.ConnectedAt = time.Time{}         // Reset connection time
	p.LastPing = time.Time{}            // Reset ping time
	p.LastPong = time.Time{}            // Reset pong time
	log.Printf("Peer %s (Role=%s) disconnected", p.Node.ID, p.Node.Role)
}

// SendPing sends a ping message to the peer
// Updates the last ping timestamp for connection health monitoring
func (p *Peer) SendPing() {
	p.LastPing = time.Now() // Record ping time
	log.Printf("Sent PING to peer %s (Role=%s)", p.Node.ID, p.Node.Role)
}

// ReceivePong processes a pong response from the peer
// Updates the last pong timestamp for connection health monitoring
func (p *Peer) ReceivePong() {
	p.LastPong = time.Now() // Record pong time
	log.Printf("Received PONG from peer %s (Role=%s)", p.Node.ID, p.Node.Role)
}

// GetPeerInfo returns comprehensive information about the peer
// Used for peer discovery, monitoring, and network diagnostics
func (p *Peer) GetPeerInfo() PeerInfo {
	return PeerInfo{
		NodeID:          p.Node.ID,         // Node identifier
		KademliaID:      p.Node.KademliaID, // Kademlia ID
		Address:         p.Node.Address,    // Network address
		IP:              p.Node.IP,         // IP address
		Port:            p.Node.Port,       // TCP port
		UDPPort:         p.Node.UDPPort,    // UDP port
		Status:          p.Node.Status,     // Node status
		Role:            p.Node.Role,       // Node role
		Timestamp:       time.Now(),        // Current timestamp
		ProtocolVersion: "1.0",             // Protocol version
		PublicKey:       p.Node.PublicKey,  // Public key for verification
	}
}
