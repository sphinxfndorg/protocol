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

// go/src/network/manager.go
package network

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/sphinxorg/protocol/src/common"
	sphincsKey "github.com/sphinxorg/protocol/src/core/sphincs/key/backend"
	database "github.com/sphinxorg/protocol/src/core/state"
)

// Add this method to NodeManager for chain recognition
// GetChainInfo returns information about the current blockchain network
func (nm *NodeManager) GetChainInfo() map[string]interface{} {
	// Return map with chain identification parameters
	return map[string]interface{}{
		"chain_id":         7331,         // Unique chain identifier
		"chain_name":       "Sphinx",     // Human-readable chain name
		"symbol":           "SPX",        // Currency symbol
		"protocol_version": "1.0.0",      // Protocol version
		"network_magic":    "0x53504858", // Network magic bytes ("SPHX" in hex)
		"default_port":     32307,        // Default P2P port
		"bip44_coin_type":  7331,         // BIP44 coin type for wallets
	}
}

// GenerateNodeIdentification generates node identification with chain info
// Parameters:
//   - nodeID: Unique identifier for the node
//
// Returns: Formatted string with node and chain information
func (nm *NodeManager) GenerateNodeIdentification(nodeID string) string {
	// Get current chain information
	chainInfo := nm.GetChainInfo()
	// Format identification string with node and chain details
	return fmt.Sprintf(
		"Sphinx Node: %s\n"+ // Node identifier
			"Network: %s\n"+ // Network name
			"Chain ID: %d\n"+ // Chain identifier
			"Protocol: %s\n"+ // Protocol version
			"User Agent: SphinxNode/%s", // User agent string
		nodeID,
		chainInfo["chain_name"],
		chainInfo["chain_id"],
		chainInfo["protocol_version"],
		chainInfo["protocol_version"],
	)
}

// ValidateChainCompatibility checks if remote node is compatible with Sphinx chain
// Parameters:
//   - remoteChainInfo: Chain information from remote node
//
// Returns: true if chains are compatible
func (nm *NodeManager) ValidateChainCompatibility(remoteChainInfo map[string]interface{}) bool {
	// Get local chain information
	localInfo := nm.GetChainInfo()

	// Check chain ID compatibility
	// Attempt to extract remote chain ID as integer
	remoteChainID, ok := remoteChainInfo["chain_id"].(int)
	if !ok {
		return false // Invalid or missing chain ID
	}

	// Compare remote chain ID with local chain ID
	return remoteChainID == localInfo["chain_id"]
}

// EXISTING FUNCTIONS CONTINUE UNCHANGED...
// NewNodeManager creates a new NodeManager with Kademlia buckets and a DHT implementation.
// Parameters:
//   - bucketSize: Size of each Kademlia bucket (default 16 if <=0)
//   - dht: DHT implementation for distributed hash table operations
//   - db: Database instance for persistent storage
//
// Returns: Initialized NodeManager pointer
func NewNodeManager(bucketSize int, dht DHT, db *database.DB) *NodeManager {
	// Set default bucket size if invalid
	if bucketSize <= 0 {
		bucketSize = 16
	}
	// Return initialized NodeManager
	return &NodeManager{
		nodes:       make(map[string]*Node),  // Map of all known nodes by ID
		peers:       make(map[string]*Peer),  // Map of connected peers by ID
		seenMsgs:    make(map[string]bool),   // Set of seen message IDs to prevent duplicates
		kBuckets:    [256][]*KBucket{},       // Kademlia routing table (256 buckets)
		K:           bucketSize,              // Bucket size (k parameter in Kademlia)
		PingTimeout: 10 * time.Second,        // Timeout for ping operations
		ResponseCh:  make(chan []*Peer, 100), // Channel for async responses
		DHT:         dht,                     // DHT implementation
		db:          db,                      // Database reference for persistence
	}
}

// Add method to create local node with database
// CreateLocalNode initializes and adds a local node to the manager
// Parameters:
//   - address: Network address
//   - ip: IP address
//   - port: TCP port
//   - udpPort: UDP port for DHT
//   - role: Node role (Validator, FullNode, etc.)
//
// Returns: Error if creation fails
func (nm *NodeManager) CreateLocalNode(address, ip, port, udpPort string, role NodeRole) error {
	// Create new local node instance
	localNode := NewNode(address, ip, port, udpPort, true, role, nm.db)
	if localNode == nil {
		return fmt.Errorf("failed to create local node")
	}

	// Set local node ID and add to manager
	nm.LocalNodeID = localNode.KademliaID
	nm.AddNode(localNode)

	// Log successful creation
	log.Printf("Created local node: ID=%s, Role=%s, Keys stored in database", localNode.ID, role)
	return nil
}

// Update BackupNodeInfo to use config directory
// BackupNodeInfo saves node information to both config directory and database
// Parameters:
//   - node: Node to backup
//
// Returns: Error if backup fails
func (nm *NodeManager) BackupNodeInfo(node *Node) error {
	// Prepare node data structure for serialization
	nodeData := map[string]interface{}{
		"id":          node.ID,                            // Node identifier
		"address":     node.Address,                       // Network address
		"ip":          node.IP,                            // IP address
		"port":        node.Port,                          // TCP port
		"udp_port":    node.UDPPort,                       // UDP port
		"kademlia_id": node.KademliaID[:],                 // Kademlia ID as bytes
		"role":        string(node.Role),                  // Node role as string
		"status":      string(node.Status),                // Node status as string
		"last_seen":   node.LastSeen.Format(time.RFC3339), // Last seen timestamp
		"public_key":  node.PublicKey,                     // Public key bytes
	}

	// Store in config directory (primary storage)
	if err := common.WriteNodeInfo(node.ID, nodeData); err != nil {
		return fmt.Errorf("failed to backup node info to config directory: %w", err)
	}

	// Also store in database for backward compatibility
	// Serialize node data to bytes
	data, err := serializeNodeData(nodeData)
	if err != nil {
		return fmt.Errorf("failed to serialize node data: %w", err)
	}

	// Store in database with key prefix
	key := fmt.Sprintf("node_info:%s", node.ID)
	if err := nm.db.Put(key, data); err != nil {
		return fmt.Errorf("failed to backup node info to database: %w", err)
	}

	return nil
}

// Update RestoreNodeFromDB to also check config directory
// RestoreNodeFromDB attempts to restore a node from config directory, falling back to database
// Parameters:
//   - nodeID: ID of node to restore
//
// Returns: Restored Node or error if not found
func (nm *NodeManager) RestoreNodeFromDB(nodeID string) (*Node, error) {
	// First try to restore from config directory (preferred)
	node, err := nm.restoreNodeFromConfig(nodeID)
	if err == nil {
		log.Printf("Restored node %s from config directory", nodeID)
		return node, nil
	}

	// Log config restoration failure and try database
	log.Printf("Failed to restore node %s from config directory: %v, trying database", nodeID, err)

	// Fall back to database
	key := fmt.Sprintf("node_info:%s", nodeID)
	data, err := nm.db.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to load node info from database: %w", err)
	}

	// Deserialize node data from database
	nodeData, err := deserializeNodeData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize node data: %w", err)
	}

	// Load keys from config directory first, then database
	privateKey, publicKey, err := loadNodeKeysFromConfig(nodeID)
	if err != nil {
		log.Printf("Failed to load keys from config directory: %v, trying database", err)
		privateKey, publicKey, err = loadNodeKeys(nm.db, nodeID)
		if err != nil {
			return nil, fmt.Errorf("failed to load node keys: %w", err)
		}
	}

	// Reconstruct node from deserialized data
	node = &Node{
		ID:         nodeData["id"].(string),             // Node ID
		Address:    nodeData["address"].(string),        // Network address
		IP:         nodeData["ip"].(string),             // IP address
		Port:       nodeData["port"].(string),           // TCP port
		UDPPort:    nodeData["udp_port"].(string),       // UDP port
		PrivateKey: privateKey,                          // Private key
		PublicKey:  publicKey,                           // Public key
		IsLocal:    false,                               // Restored nodes are not local
		Role:       NodeRole(nodeData["role"].(string)), // Node role
		Status:     NodeStatusActive,                    // Start as active
		db:         nm.db,                               // Database reference
	}

	// Restore Kademlia ID if available
	if kademliaID, ok := nodeData["kademlia_id"].([]byte); ok {
		copy(node.KademliaID[:], kademliaID) // Copy bytes to fixed-size array
	}

	// Restore last seen timestamp if available
	if lastSeenStr, ok := nodeData["last_seen"].(string); ok {
		if lastSeen, err := time.Parse(time.RFC3339, lastSeenStr); err == nil {
			node.LastSeen = lastSeen
		}
	}

	return node, nil
}

// New method to restore node from config directory
// restoreNodeFromConfig restores node information from the config directory
// Parameters:
//   - nodeID: ID of node to restore
//
// Returns: Restored Node or error if not found
func (nm *NodeManager) restoreNodeFromConfig(nodeID string) (*Node, error) {
	// Read node info from config directory
	nodeInfo, err := common.ReadNodeInfo(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to read node info from config: %w", err)
	}

	// Load cryptographic keys from config
	privateKey, publicKey, err := loadNodeKeysFromConfig(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to load keys from config: %w", err)
	}

	// Reconstruct node from config data
	node := &Node{
		ID:         nodeInfo["id"].(string),             // Node ID
		Address:    nodeInfo["address"].(string),        // Network address
		IP:         nodeInfo["ip"].(string),             // IP address
		Port:       nodeInfo["port"].(string),           // TCP port
		UDPPort:    nodeInfo["udp_port"].(string),       // UDP port
		PrivateKey: privateKey,                          // Private key
		PublicKey:  publicKey,                           // Public key
		IsLocal:    nodeInfo["is_local"].(bool),         // Local node flag
		Role:       NodeRole(nodeInfo["role"].(string)), // Node role
		Status:     NodeStatusActive,                    // Start as active
		db:         nm.db,                               // Database reference
	}

	// Restore Kademlia ID if available
	if kademliaID, ok := nodeInfo["kademlia_id"].([]byte); ok {
		copy(node.KademliaID[:], kademliaID) // Copy bytes to fixed-size array
	} else {
		// Generate from address if not stored
		node.KademliaID = GenerateKademliaID(node.Address)
	}

	// Restore creation time if available
	if createdAtStr, ok := nodeInfo["created_at"].(string); ok {
		if createdAt, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			node.LastSeen = createdAt
		}
	}

	return node, nil
}

// NewNetworkKeyManager creates a new network key manager with database integration
// Parameters:
//   - db: Database instance for key storage
//
// Returns: NetworkKeyManager or error if initialization fails
func NewNetworkKeyManager(db *database.DB) (*NetworkKeyManager, error) {
	// Initialize SPHINCS+ key manager
	km, err := sphincsKey.NewKeyManager()
	if err != nil {
		return nil, err
	}

	// Return initialized network key manager
	return &NetworkKeyManager{
		db:         db, // Database for key storage
		keyManager: km, // SPHINCS+ key manager
	}, nil
}

// GetCurrentKeys retrieves the current active keys for a node
// Parameters:
//   - nodeID: ID of the node
//
// Returns: Private key bytes, public key bytes, and error
func (nkm *NetworkKeyManager) GetCurrentKeys(nodeID string) ([]byte, []byte, error) {
	// Get current key references from database
	// These references point to the actual key storage locations
	currentPrivateKey := fmt.Sprintf("node:%s:private_key:current", nodeID)
	currentPublicKey := fmt.Sprintf("node:%s:public_key:current", nodeID)

	// Retrieve private key reference
	privateKeyRef, err := nkm.db.Get(currentPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get current private key reference: %w", err)
	}

	// Retrieve public key reference
	publicKeyRef, err := nkm.db.Get(currentPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get current public key reference: %w", err)
	}

	// Get actual keys using references
	// Use the reference strings as keys to fetch the actual key data
	privateKey, err := nkm.db.Get(string(privateKeyRef))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get current private key: %w", err)
	}
	publicKey, err := nkm.db.Get(string(publicKeyRef))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get current public key: %w", err)
	}

	return privateKey, publicKey, nil
}

// AddNode adds a new node to the manager and updates k-buckets.
// Parameters:
//   - node: Node to add to the network
func (nm *NodeManager) AddNode(node *Node) {
	// Acquire write lock for thread safety
	nm.mu.Lock()
	defer nm.mu.Unlock()

	// Check for existing node by ID or KademliaID to prevent duplicates
	// Check if node with same ID and KademliaID already exists
	if existingNode, exists := nm.nodes[node.ID]; exists && existingNode.KademliaID == node.KademliaID {
		log.Printf("Node %s (KademliaID: %x) already exists, skipping addition", node.ID, node.KademliaID[:8])
		return
	}

	// Check for any node with same KademliaID but different ID
	for _, n := range nm.nodes {
		if n.KademliaID == node.KademliaID && n.ID != node.ID {
			log.Printf("Node with KademliaID %x already exists as %s, skipping addition", node.KademliaID[:8], n.ID)
			return
		}
	}

	// Add new node to nodes map
	nm.nodes[node.ID] = node

	// Add to appropriate k-bucket if not local node
	// Local nodes are not added to routing table
	if !node.IsLocal {
		// Calculate XOR distance between local node and new node
		distance := nm.CalculateDistance(nm.LocalNodeID, node.KademliaID)
		// Determine which bucket this node belongs in based on distance
		bucketIndex := nm.logDistance(distance)

		// Check if bucket index is valid
		if bucketIndex >= 0 && bucketIndex < 256 {
			// Initialize bucket slice if needed
			if nm.kBuckets[bucketIndex] == nil {
				nm.kBuckets[bucketIndex] = make([]*KBucket, 0)
			}

			// Check existing buckets at this index
			for _, b := range nm.kBuckets[bucketIndex] {
				// Check if node already exists in this bucket
				for _, p := range b.Peers {
					if p.Node.ID == node.ID || p.Node.KademliaID == node.KademliaID {
						log.Printf("Peer %s (KademliaID: %x) already in k-bucket, skipping addition", node.ID, node.KademliaID[:8])
						return
					}
				}

				// If bucket has space, add node
				if len(b.Peers) < nm.K {
					b.Peers = append(b.Peers, NewPeer(node))
					b.LastUpdated = time.Now()
					log.Printf("Added node to k-bucket: ID=%s, Address=%s, Role=%s, KademliaID=%x",
						node.ID, node.Address, node.Role, node.KademliaID[:8])
					return
				}

				// Bucket is full, try to evict inactive peer
				if evicted := nm.evictInactivePeer(b, node); evicted {
					return
				}
			}

			// No existing bucket with space, create new bucket
			nm.kBuckets[bucketIndex] = append(nm.kBuckets[bucketIndex], &KBucket{
				Peers:       []*Peer{NewPeer(node)},
				LastUpdated: time.Now(),
			})
			log.Printf("Created new k-bucket for node: ID=%s, Address=%s, Role=%s, KademliaID=%x",
				node.ID, node.Address, node.Role, node.KademliaID[:8])
		}
	}

	// Log successful node addition
	log.Printf("Added node: ID=%s, Address=%s, Role=%s, KademliaID=%x",
		node.ID, node.Address, node.Role, node.KademliaID[:8])
}

// UpdateNode updates the attributes of an existing node.
// Parameters:
//   - node: Node with updated information
//
// Returns: Error if node not found
func (nm *NodeManager) UpdateNode(node *Node) error {
	// Acquire write lock for thread safety
	nm.mu.Lock()
	defer nm.mu.Unlock()

	// Find existing node
	existingNode, exists := nm.nodes[node.ID]
	if !exists {
		return fmt.Errorf("node %s not found", node.ID)
	}

	// Update node attributes
	existingNode.Address = node.Address
	existingNode.IP = node.IP
	existingNode.Port = node.Port
	existingNode.UDPPort = node.UDPPort
	existingNode.Role = node.Role
	existingNode.Status = node.Status
	existingNode.LastSeen = node.LastSeen

	// Update Kademlia ID if provided
	if node.KademliaID != [32]byte{} {
		existingNode.KademliaID = node.KademliaID
	}

	// Update k-bucket entry if node exists in routing table
	distance := nm.CalculateDistance(nm.LocalNodeID, existingNode.KademliaID)
	bucketIndex := nm.logDistance(distance)
	if bucketIndex >= 0 && bucketIndex < 256 {
		// Find and update peer in k-bucket
		for _, bucket := range nm.kBuckets[bucketIndex] {
			for _, peer := range bucket.Peers {
				if peer.Node.ID == node.ID {
					peer.Node = existingNode
					bucket.LastUpdated = time.Now()
					log.Printf("Updated node in k-bucket: ID=%s, Address=%s, Role=%s, KademliaID=%x",
						node.ID, node.Address, node.Role, node.KademliaID[:8])
					break
				}
			}
		}
	}

	// Update peer entry if node is a connected peer
	if peer, ok := nm.peers[node.ID]; ok {
		peer.Node = existingNode
		peer.LastSeen = node.LastSeen
		log.Printf("Updated peer: ID=%s, Address=%s, Role=%s", node.ID, node.Address, node.Role)
	}

	// Log successful update
	log.Printf("Updated node: ID=%s, Address=%s, Role=%s, KademliaID=%x",
		node.ID, node.Address, node.Role, node.KademliaID[:8])
	return nil
}

// evictInactivePeer attempts to evict an inactive peer from a bucket.
// Parameters:
//   - bucket: Kademlia bucket to check
//   - newNode: New node to potentially add
//
// Returns: true if peer was evicted and new node added
func (nm *NodeManager) evictInactivePeer(bucket *KBucket, newNode *Node) bool {
	// Find the least recently seen peer
	var oldestPeer *Peer
	var oldestIndex int
	minTime := time.Now()

	// Iterate through peers to find oldest
	for i, peer := range bucket.Peers {
		if peer.LastPong.Before(minTime) {
			minTime = peer.LastPong
			oldestPeer = peer
			oldestIndex = i
		}
	}

	// No peers found
	if oldestPeer == nil {
		return false
	}

	// Ping the oldest peer to check liveness
	if nm.pingPeer(oldestPeer) {
		return false // Peer is still active, keep it
	}

	// Evict the oldest peer and add the new node
	// Remove oldest peer by slicing it out
	bucket.Peers = append(bucket.Peers[:oldestIndex], bucket.Peers[oldestIndex+1:]...)
	// Add new node to bucket
	bucket.Peers = append(bucket.Peers, NewPeer(newNode))
	bucket.LastUpdated = time.Now()

	log.Printf("Evicted inactive peer %s, added new node %s", oldestPeer.Node.ID, newNode.ID)
	return true
}

// pingPeer sends a ping and waits for a pong response.
// Parameters:
//   - peer: Peer to ping
//
// Returns: true if peer responded
func (nm *NodeManager) pingPeer(peer *Peer) bool {
	// Send ping message to peer
	peer.SendPing()

	// Resolve UDP address for the peer
	addr, err := net.ResolveUDPAddr("udp", peer.Node.UDPPort)
	if err != nil {
		log.Printf("Failed to resolve UDP address for peer %s: %v", peer.Node.ID, err)
		return false
	}

	// Send ping via DHT
	nm.DHT.PingNode(peer.Node.KademliaID, *addr)

	// Wait for response with timeout
	time.Sleep(10 * time.Second) // Increase timeout

	// Check if peer responded (LastPong not zero and recent)
	return !peer.LastPong.IsZero() && time.Since(peer.LastPong) < 10*time.Second
}

// RemoveNode removes a node and its peer entry.
// Parameters:
//   - nodeID: ID of node to remove
func (nm *NodeManager) RemoveNode(nodeID string) {
	// Acquire write lock for thread safety
	nm.mu.Lock()
	defer nm.mu.Unlock()

	// Check if node exists
	if node, exists := nm.nodes[nodeID]; exists {
		// Remove from nodes map
		delete(nm.nodes, nodeID)
		// Remove from peers map if present
		delete(nm.peers, nodeID)

		// Remove from k-buckets
		distance := nm.CalculateDistance(nm.LocalNodeID, node.KademliaID)
		bucketIndex := nm.logDistance(distance)

		if bucketIndex >= 0 && bucketIndex < 256 {
			// Iterate through buckets at this index
			for i, bucket := range nm.kBuckets[bucketIndex] {
				for j, peer := range bucket.Peers {
					if peer.Node.ID == nodeID {
						// Remove peer from bucket
						bucket.Peers = append(bucket.Peers[:j], bucket.Peers[j+1:]...)
						bucket.LastUpdated = time.Now()

						// Remove empty bucket if no peers left
						if len(bucket.Peers) == 0 {
							nm.kBuckets[bucketIndex] = append(nm.kBuckets[bucketIndex][:i], nm.kBuckets[bucketIndex][i+1:]...)
						}
						break
					}
				}
			}
		}

		log.Printf("Removed node: ID=%s, Address=%s, Role=%s", nodeID, node.Address, node.Role)
	}
}

// PruneInactivePeers disconnects peers with no recent pong.
// Parameters:
//   - timeout: Maximum time since last pong before considering inactive
func (nm *NodeManager) PruneInactivePeers(timeout time.Duration) {
	// Acquire write lock for thread safety
	nm.mu.Lock()
	defer nm.mu.Unlock()

	// Prune peers with no recent pong
	for id, peer := range nm.peers {
		if time.Since(peer.LastPong) > timeout {
			nm.RemovePeer(id) // Remove inactive peer
		}
	}

	// Prune nodes with no recent activity (excluding local nodes)
	for id, node := range nm.nodes {
		if time.Since(node.LastSeen) > timeout && !node.IsLocal {
			nm.RemoveNode(id) // Remove inactive node
		}
	}

	// Prune stale k-buckets (older than 1 hour)
	for i, buckets := range nm.kBuckets {
		for j, bucket := range buckets {
			if time.Since(bucket.LastUpdated) > time.Hour {
				// Remove stale bucket
				nm.kBuckets[i] = append(nm.kBuckets[i][:j], nm.kBuckets[i][j+1:]...)
			}
		}
	}
}

// HasSeenMessage checks if a message ID has been seen.
// Parameters:
//   - msgID: Message ID to check
//
// Returns: true if message has been processed before
func (nm *NodeManager) HasSeenMessage(msgID string) bool {
	// Acquire read lock for thread safety
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return nm.seenMsgs[msgID]
}

// MarkMessageSeen marks a message ID as seen.
// Parameters:
//   - msgID: Message ID to mark
func (nm *NodeManager) MarkMessageSeen(msgID string) {
	// Acquire write lock for thread safety
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.seenMsgs[msgID] = true // Add to seen messages set
}

// AddPeer adds a node as a peer, marking it as connected.
// Parameters:
//   - node: Node to add as peer
//
// Returns: Error if peer cannot be added
func (nm *NodeManager) AddPeer(node *Node) error {
	// Acquire write lock for thread safety
	nm.mu.Lock()
	defer nm.mu.Unlock()

	// Validate peer has required connection information
	if node.IP == "" || node.Port == "" {
		log.Printf("Cannot add peer %s: empty IP or port", node.ID)
		return fmt.Errorf("cannot add peer %s: empty IP or port", node.ID)
	}

	// Check for existing peer by ID
	if _, exists := nm.peers[node.ID]; exists {
		log.Printf("Peer %s already exists in peers map, skipping addition", node.ID)
		return nil // Not an error, just already present
	}

	// Check for existing peer by Kademlia ID (different node ID)
	for _, p := range nm.peers {
		if p.Node.KademliaID == node.KademliaID && p.Node.ID != node.ID {
			log.Printf("Peer with KademliaID %x already exists as %s, skipping addition",
				node.KademliaID[:8], p.Node.ID)
			return nil
		}
	}

	// Add to nodes map if not already present
	if _, exists := nm.nodes[node.ID]; !exists {
		nm.nodes[node.ID] = node
	}

	// Create and connect peer
	peer := NewPeer(node)
	if err := peer.ConnectPeer(); err != nil {
		return err // Connection failed
	}

	// Add to peers map
	nm.peers[node.ID] = peer
	log.Printf("Node %s (Role=%s) became peer at %s", node.ID, node.Role, peer.ConnectedAt)
	return nil
}

// RemovePeer disconnects a peer.
// Parameters:
//   - nodeID: ID of peer to remove
func (nm *NodeManager) RemovePeer(nodeID string) {
	// Acquire write lock for thread safety
	nm.mu.Lock()
	defer nm.mu.Unlock()

	// Check if peer exists
	if peer, exists := nm.peers[nodeID]; exists {
		peer.DisconnectPeer()    // Close connection
		delete(nm.peers, nodeID) // Remove from map
		log.Printf("Removed peer: ID=%s, Role=%s", nodeID, peer.Node.Role)
	}
}

// GetNode returns a node by its ID.
// Parameters:
//   - nodeID: ID of node to retrieve
//
// Returns: Node or nil if not found
func (nm *NodeManager) GetNode(nodeID string) *Node {
	// Acquire read lock for thread safety
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return nm.nodes[nodeID]
}

// GetNodeByKademliaID returns a node by its Kademlia ID.
// Parameters:
//   - kademliaID: Kademlia ID to search for
//
// Returns: Node or nil if not found
func (nm *NodeManager) GetNodeByKademliaID(kademliaID NodeID) *Node {
	// Acquire read lock for thread safety
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	// Linear search through nodes
	for _, node := range nm.nodes {
		if node.KademliaID == kademliaID {
			return node
		}
	}
	return nil
}

// GetPeers returns all connected peers.
// Returns: Copy of peers map
func (nm *NodeManager) GetPeers() map[string]*Peer {
	// Acquire read lock for thread safety
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	// Create copy of peers map
	peers := make(map[string]*Peer)
	for id, peer := range nm.peers {
		peers[id] = peer
	}
	return peers
}

// BroadcastPeerInfo sends PeerInfo to all connected peers.
// Parameters:
//   - sender: Peer that originated the info
//   - sendFunc: Function to send the info to a specific peer
//
// Returns: Error if broadcasting fails
func (nm *NodeManager) BroadcastPeerInfo(sender *Peer, sendFunc func(string, *PeerInfo) error) error {
	// Acquire read lock for thread safety
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	// Get peer info from sender
	peerInfo := sender.GetPeerInfo()

	// Send to all peers except the sender
	for _, peer := range nm.peers {
		if peer.Node.ID != sender.Node.ID {
			if err := sendFunc(peer.Node.Address, &peerInfo); err != nil {
				log.Printf("Failed to send PeerInfo to %s (Role=%s): %v",
					peer.Node.ID, peer.Node.Role, err)
			}
		}
	}
	return nil
}

// SelectValidator selects a node with RoleValidator for transaction validation.
// Returns: Selected validator node or nil if none available
func (nm *NodeManager) SelectValidator() *Node {
	// Acquire read lock for thread safety
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	// Find first active validator
	for _, node := range nm.nodes {
		if node.Role == RoleValidator && node.Status == NodeStatusActive {
			log.Printf("Selected validator: ID=%s, Address=%s", node.ID, node.Address)
			return node
		}
	}

	log.Println("No active validator found")
	return nil
}

// CalculateDistance computes the XOR distance between two node IDs.
// Parameters:
//   - id1: First node ID
//   - id2: Second node ID
//
// Returns: XOR distance as NodeID
func (nm *NodeManager) CalculateDistance(id1, id2 NodeID) NodeID {
	var result NodeID
	// XOR each byte of the IDs
	for i := 0; i < 32; i++ {
		result[i] = id1[i] ^ id2[i]
	}
	return result
}

// logDistance returns the log2 of the distance (bucket index).
// Parameters:
//   - distance: XOR distance
//
// Returns: Bucket index (0-255)
func (nm *NodeManager) logDistance(distance NodeID) int {
	// Find the most significant non-zero bit
	for i := 31; i >= 0; i-- {
		if distance[i] != 0 {
			// Find the highest set bit in this byte
			for bit := 7; bit >= 0; bit-- {
				if (distance[i]>>uint(bit))&1 != 0 {
					// Calculate bucket index based on bit position
					return i*8 + bit
				}
			}
		}
	}
	return 0 // Distance is zero (same node)
}

// FindClosestPeers returns the k closest peers to a target ID, using the DHT interface.
// Parameters:
//   - targetID: Target Kademlia ID to find closest peers to
//   - k: Number of closest peers to return
//
// Returns: Slice of closest peers
func (nm *NodeManager) FindClosestPeers(targetID NodeID, k int) []*Peer {
	// Acquire read lock for thread safety
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	// Use DHT interface to find nearest nodes
	remotes := nm.DHT.KNearest(targetID)
	result := make([]*Peer, 0, k)

	// Process each remote node from DHT
	for _, remote := range remotes {
		// Try to find existing node by Kademlia ID
		node := nm.GetNodeByKademliaID(remote.NodeID)
		if node == nil {
			// Create new node from remote information
			// Parse remote.Address (format: "IP:port") to extract IP and port
			addrParts := strings.Split(remote.Address.String(), ":")
			if len(addrParts) != 2 {
				log.Printf("FindClosestPeers: Invalid remote address format %s", remote.Address.String())
				continue
			}
			port := addrParts[1] // Port number as string
			ip := addrParts[0]

			// Create new node instance
			node = &Node{
				ID:         fmt.Sprintf("Node-%s", remote.NodeID.String()[:8]), // Generate node ID from Kademlia ID
				KademliaID: remote.NodeID,
				Address:    fmt.Sprintf("%s:%d", ip, remote.Address.Port-1), // Assume TCP port is UDP port - 1
				IP:         ip,
				UDPPort:    port, // Store port number as string
				Status:     NodeStatusActive,
				Role:       RoleNone,
				LastSeen:   time.Now(),
			}
			// Add to nodes map
			nm.nodes[node.ID] = node
		}

		// Create and connect peer
		peer := NewPeer(node)
		if err := peer.ConnectPeer(); err == nil {
			// Add to peers map if connection successful
			nm.peers[node.ID] = peer
			result = append(result, peer)
		}

		// Stop if we have enough peers
		if len(result) >= k {
			break
		}
	}
	return result
}

// CompareDistance compares two distances (returns -1, 0, or 1).
// Parameters:
//   - d1: First distance
//   - d2: Second distance
//
// Returns: -1 if d1 < d2, 0 if equal, 1 if d1 > d2
func (nm *NodeManager) CompareDistance(d1, d2 NodeID) int {
	// Compare from most significant byte to least
	for i := 31; i >= 0; i-- {
		if d1[i] < d2[i] {
			return -1 // d1 is smaller
		} else if d1[i] > d2[i] {
			return 1 // d1 is larger
		}
		// Continue to next byte if equal
	}
	return 0 // Distances are equal
}
