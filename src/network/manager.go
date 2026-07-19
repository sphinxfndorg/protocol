// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/network/manager.go
package network

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/consensus"

	database "github.com/sphinxfndorg/protocol/src/core/state"
	sthincs "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
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
		"Sphinx Node: %s\n"+
			"Network: %s\n"+
			"Chain ID: %d\n"+
			"Protocol: %s\n"+
			"User Agent: SphinxNode/%s",
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
		nodes:           make(map[string]*Node),  // Map of all known nodes by ID
		peers:           make(map[string]*Peer),  // Map of connected peers by ID
		seenMsgs:        make(map[string]bool),   // Set of seen message IDs to prevent duplicates
		kBuckets:        [256][]*KBucket{},       // Kademlia routing table (256 buckets)
		K:               bucketSize,              // Bucket size (k parameter in Kademlia)
		PingTimeout:     10 * time.Second,        // Timeout for ping operations
		ResponseCh:      make(chan []*Peer, 100), // Channel for async responses
		DHT:             dht,                     // DHT implementation
		db:              db,                      // Database reference for persistence
		responseWaiters: make(map[string]chan []*Peer),
	}
}

// DB exposes the NodeManager's database handle so other packages (e.g. p2p)
// can pass a real database reference into network.NewNode instead of nil.
func (nm *NodeManager) DB() *database.DB {
	return nm.db
}

// RegisterResponseWaiter creates and registers a dedicated response channel
// for a specific outgoing request, keyed by the nonce that was sent with it.
// Callers must call RemoveResponseWaiter (directly or via defer) once they're
// done waiting, whether or not a response arrived, to avoid leaking entries.
func (nm *NodeManager) RegisterResponseWaiter(nonce []byte) chan []*Peer {
	key := hex.EncodeToString(nonce)
	ch := make(chan []*Peer, 1)

	nm.waitersMu.Lock()
	nm.responseWaiters[key] = ch
	nm.waitersMu.Unlock()

	return ch
}

// RemoveResponseWaiter unregisters and closes the response channel associated
// with the given nonce, if one exists. Safe to call more than once.
func (nm *NodeManager) RemoveResponseWaiter(nonce []byte) {
	key := hex.EncodeToString(nonce)

	nm.waitersMu.Lock()
	ch, ok := nm.responseWaiters[key]
	if ok {
		delete(nm.responseWaiters, key)
	}
	nm.waitersMu.Unlock()

	if ok {
		close(ch)
	}
}

// DeliverResponse routes a PONG/NEIGHBORS response to the specific caller
// that is waiting on the matching nonce, if any. It returns true when a
// waiter was found and the response was delivered directly to it. When no
// waiter is registered (e.g. an unsolicited NEIGHBORS push), it falls back
// to the legacy broadcast ResponseCh so existing passive listeners keep
// working, without ever letting two independent requests race over the
// same response.
func (nm *NodeManager) DeliverResponse(nonce []byte, peers []*Peer) bool {
	key := hex.EncodeToString(nonce)

	nm.waitersMu.Lock()
	ch, ok := nm.responseWaiters[key]
	nm.waitersMu.Unlock()

	if ok {
		select {
		case ch <- peers:
		default:
			// Waiter's buffer is already full (shouldn't happen, buffer is 1),
			// drop rather than block the UDP receive loop.
		}
		return true
	}

	// No specific waiter registered - fall back to the broadcast channel so
	// unsolicited responses aren't silently discarded.
	select {
	case nm.ResponseCh <- peers:
	default:
	}
	return false
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
		"id":          node.ID,
		"address":     node.Address,
		"ip":          node.IP,
		"port":        node.Port,
		"udp_port":    node.UDPPort,
		"kademlia_id": node.KademliaID[:],
		"role":        string(node.Role),
		"status":      string(node.Status),
		"last_seen":   node.LastSeen.Format(time.RFC3339),
		"public_key":  node.PublicKey,
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

// loadNodeKeysFromConfig loads cryptographic keys from the config directory
func loadNodeKeysFromConfig(address string) ([]byte, []byte, error) {
	// Check if keys exist before attempting to load
	if !common.KeysExist(address) {
		return nil, nil, fmt.Errorf("keys do not exist for node %s", address)
	}
	return common.ReadKeysFromFile(address)
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

// GetOrCreateKeys is the single entry point for all node key operations.
// Resolution order: config file → LevelDB → generate new real SPHINCS+ keys.
//
// The address parameter is the node's network address (e.g. "127.0.0.1:30303")
// which is used as the storage key via common.GetPrivateKeyPath / GetPublicKeyPath.
func (nkm *NetworkKeyManager) GetOrCreateKeys(address string) ([]byte, []byte, error) {
	// ── 1. Config file (fastest, survives restarts) ──────────────────────────
	if common.KeysExist(address) {
		privateKey, publicKey, err := common.ReadKeysFromFile(address)
		if err == nil {
			log.Printf("GetOrCreateKeys: Loaded keys from config for %s (sk=%d pk=%d bytes)",
				address, len(privateKey), len(publicKey))
			return privateKey, publicKey, nil
		}
		// File corrupt or unreadable — fall through to regenerate
		log.Printf("GetOrCreateKeys: Config keys unreadable for %s (%v), regenerating", address, err)
	}

	// ── 2. LevelDB (migration path for nodes that stored keys there before) ──
	privateKey, publicKey, err := nkm.loadKeysFromDB(address)
	if err == nil {
		log.Printf("GetOrCreateKeys: Loaded keys from DB for %s (sk=%d pk=%d bytes)",
			address, len(privateKey), len(publicKey))
		// Migrate to config file so future startups use the fast path
		if writeErr := common.WriteKeysToFile(address, privateKey, publicKey); writeErr != nil {
			log.Printf("GetOrCreateKeys: Warning — could not migrate DB keys to config for %s: %v",
				address, writeErr)
		}
		return privateKey, publicKey, nil
	}

	// ── 3. Generate fresh real SPHINCS+ keys ─────────────────────────────────
	log.Printf("GetOrCreateKeys: No existing keys for %s — generating real SPHINCS+ key pair", address)
	privateKey, publicKey, err = nkm.generateSPHINCSKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("GetOrCreateKeys: key generation failed for %s: %w", address, err)
	}

	// Persist to config file (primary, required)
	if err := common.WriteKeysToFile(address, privateKey, publicKey); err != nil {
		return nil, nil, fmt.Errorf("GetOrCreateKeys: failed to persist keys to config for %s: %w",
			address, err)
	}

	// Persist to LevelDB (secondary, non-fatal)
	if err := nkm.saveKeysToDB(address, privateKey, publicKey); err != nil {
		log.Printf("GetOrCreateKeys: Warning — could not persist keys to DB for %s: %v", address, err)
	}

	log.Printf("GetOrCreateKeys: Generated and stored SPHINCS+ keys for %s (sk=%d pk=%d bytes)",
		address, len(privateKey), len(publicKey))
	return privateKey, publicKey, nil
}

// generateSPHINCSKeys generates a real SPHINCS+ key pair and serializes it.
//
// Internally calls key.go's GenerateKey() → SerializeKeyPair():
//
//	Private key  = SKseed || SKprf || PKseed || PKroot  (4×n bytes, n=16 → 64 bytes)
//	Public key   = PKseed || PKroot                     (2×n bytes, n=16 → 32 bytes)
//
// The size invariant sk = 2×pk is validated before returning.
func (nkm *NetworkKeyManager) generateSPHINCSKeys() ([]byte, []byte, error) {
	// nkm.keyManager is already a *sthincs.KeyManager, use it directly
	// GenerateKey uses the STHINCSParameters already embedded in nkm.keyManager
	sk, pk, err := nkm.keyManager.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generateSPHINCSKeys: GenerateKey failed: %w", err)
	}
	if sk == nil || pk == nil {
		return nil, nil, fmt.Errorf("generateSPHINCSKeys: GenerateKey returned nil keys")
	}

	// SerializeKeyPair produces the flat byte representations
	skBytes, pkBytes, err := nkm.keyManager.SerializeKeyPair(sk, pk)
	if err != nil {
		return nil, nil, fmt.Errorf("generateSPHINCSKeys: SerializeKeyPair failed: %w", err)
	}

	// Invariant: sk must be exactly twice the length of pk
	// sk = SKseed(n) + SKprf(n) + PKseed(n) + PKroot(n) = 4n
	// pk = PKseed(n) + PKroot(n) = 2n
	if len(skBytes) != 2*len(pkBytes) {
		return nil, nil, fmt.Errorf(
			"generateSPHINCSKeys: size invariant violated — sk=%d bytes, pk=%d bytes (expected sk=2×pk)",
			len(skBytes), len(pkBytes),
		)
	}

	log.Printf("generateSPHINCSKeys: sk=%d bytes, pk=%d bytes", len(skBytes), len(pkBytes))
	return skBytes, pkBytes, nil
}

// loadKeysFromDB loads serialized SPHINCS+ keys from LevelDB.
// Key format: "node:{address}:private_key" / "node:{address}:public_key"
func (nkm *NetworkKeyManager) loadKeysFromDB(address string) ([]byte, []byte, error) {
	privateKey, err := nkm.db.Get(fmt.Sprintf("node:%s:private_key", address))
	if err != nil {
		return nil, nil, fmt.Errorf("loadKeysFromDB: no private key in DB for %s: %w", address, err)
	}
	publicKey, err := nkm.db.Get(fmt.Sprintf("node:%s:public_key", address))
	if err != nil {
		return nil, nil, fmt.Errorf("loadKeysFromDB: no public key in DB for %s: %w", address, err)
	}
	return privateKey, publicKey, nil
}

// saveKeysToDB persists serialized SPHINCS+ keys to LevelDB.
// Key format: "node:{address}:private_key" / "node:{address}:public_key"
func (nkm *NetworkKeyManager) saveKeysToDB(address string, privateKey, publicKey []byte) error {
	if err := nkm.db.Put(fmt.Sprintf("node:%s:private_key", address), privateKey); err != nil {
		return fmt.Errorf("saveKeysToDB: failed to save private key for %s: %w", address, err)
	}
	if err := nkm.db.Put(fmt.Sprintf("node:%s:public_key", address), publicKey); err != nil {
		return fmt.Errorf("saveKeysToDB: failed to save public key for %s: %w", address, err)
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
		ID:         nodeData["id"].(string),
		Address:    nodeData["address"].(string),
		IP:         nodeData["ip"].(string),
		Port:       nodeData["port"].(string),
		UDPPort:    nodeData["udp_port"].(string),
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		IsLocal:    false,
		Role:       NodeRole(nodeData["role"].(string)),
		Status:     NodeStatusActive,
		db:         nm.db,
	}

	// Restore Kademlia ID if available
	if kademliaID, ok := nodeData["kademlia_id"].([]byte); ok {
		copy(node.KademliaID[:], kademliaID)
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
		ID:         nodeInfo["id"].(string),
		Address:    nodeInfo["address"].(string),
		IP:         nodeInfo["ip"].(string),
		Port:       nodeInfo["port"].(string),
		UDPPort:    nodeInfo["udp_port"].(string),
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		IsLocal:    nodeInfo["is_local"].(bool),
		Role:       NodeRole(nodeInfo["role"].(string)),
		Status:     NodeStatusActive,
		db:         nm.db,
	}

	// Restore Kademlia ID if available
	if kademliaID, ok := nodeInfo["kademlia_id"].([]byte); ok {
		copy(node.KademliaID[:], kademliaID)
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
	km, err := sthincs.NewKeyManager()
	if err != nil {
		return nil, err
	}

	// Return initialized network key manager
	return &NetworkKeyManager{
		db:         db,
		keyManager: km,
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

// ========== P2PConsensusNodeManager - NO P2P IMPORT ==========

// P2PConsensusNodeManager implements consensus.NodeManager using real P2P networking
type P2PConsensusNodeManager struct {
	localNodeID     string
	nodeManager     *NodeManager
	consensusEngine *consensus.Consensus
	mu              sync.RWMutex
	sendMessageFunc func(nodeAddress string, msgType string, data []byte) error
	peerList        map[string]consensus.Peer
	peerAddresses   map[string]string // Store addresses by peer ID
}

// NewP2PConsensusNodeManager creates a new P2P consensus node manager
func NewP2PConsensusNodeManager(nodeMgr *NodeManager, localNodeID string) *P2PConsensusNodeManager {
	return &P2PConsensusNodeManager{
		localNodeID:   localNodeID,
		nodeManager:   nodeMgr,
		peerList:      make(map[string]consensus.Peer),
		peerAddresses: make(map[string]string),
	}
}

// SetSendMessageFunc sets the callback function for sending messages
func (m *P2PConsensusNodeManager) SetSendMessageFunc(fn func(nodeAddress string, msgType string, data []byte) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendMessageFunc = fn
}

// SetNodeManager sets the node manager for peer discovery
func (m *P2PConsensusNodeManager) SetNodeManager(nodeMgr *NodeManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodeManager = nodeMgr
}

// SetConsensusEngine sets the consensus engine
func (m *P2PConsensusNodeManager) SetConsensusEngine(cons *consensus.Consensus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.consensusEngine = cons
}

// BroadcastMessage using sendMessageFunc
func (m *P2PConsensusNodeManager) BroadcastMessage(messageType string, data interface{}) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.sendMessageFunc == nil {
		return fmt.Errorf("send message function not set")
	}

	if len(m.peerAddresses) == 0 {
		log.Printf("[P2PConsensus] No peers to broadcast to")
		return nil
	}

	log.Printf("[P2PConsensus] Broadcasting %s message to %d peers", messageType, len(m.peerAddresses))

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal consensus data: %v", err)
	}

	for peerID, peerAddr := range m.peerAddresses {
		go func(addr string, pID string) {
			if err := m.sendMessageFunc(addr, messageType, dataBytes); err != nil {
				log.Printf("[P2PConsensus] Failed to send %s to %s: %v", messageType, pID, err)
			}
		}(peerAddr, peerID)
	}

	return nil
}

// GetValidatorSet returns the validator set (needed for leader election)
func (m *P2PConsensusNodeManager) GetValidatorSet() *consensus.ValidatorSet {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.consensusEngine == nil {
		return nil
	}
	return m.consensusEngine.GetValidatorSet()
}

// BroadcastRANDAOState implements consensus.NodeManager
func (m *P2PConsensusNodeManager) BroadcastRANDAOState(mix [32]byte, submissions map[uint64]map[string]*consensus.VDFSubmission) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.sendMessageFunc == nil {
		log.Printf("[P2PConsensus] No send function set, RANDAO state not sent")
		return nil
	}

	if len(m.peerAddresses) == 0 {
		log.Printf("[P2PConsensus] No peers to broadcast RANDAO state to")
		return nil
	}

	log.Printf("[P2PConsensus] Broadcasting RANDAO state to %d peers", len(m.peerAddresses))

	ranDAOData := struct {
		Mix         [32]byte                                       `json:"mix"`
		Submissions map[uint64]map[string]*consensus.VDFSubmission `json:"submissions"`
	}{
		Mix:         mix,
		Submissions: submissions,
	}

	dataBytes, err := json.Marshal(ranDAOData)
	if err != nil {
		return fmt.Errorf("failed to marshal RANDAO data: %v", err)
	}

	for peerID, peerAddr := range m.peerAddresses {
		go func(addr string, pID string) {
			if err := m.sendMessageFunc(addr, "randao_sync", dataBytes); err != nil {
				log.Printf("[P2PConsensus] Failed to send RANDAO state to %s: %v", pID, err)
			}
		}(peerAddr, peerID)
	}

	return nil
}

// GetPeers returns all registered peers
func (m *P2PConsensusNodeManager) GetPeers() map[string]consensus.Peer {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peers := make(map[string]consensus.Peer)

	// Return peers from peerList
	for id, peer := range m.peerList {
		peers[id] = peer
	}
	return peers
}

// GetNode returns a node by ID
func (m *P2PConsensusNodeManager) GetNode(nodeID string) consensus.Node {
	return &p2pConsensusNode{id: nodeID}
}

// HandleIncomingMessage processes a consensus message received from the network
func (m *P2PConsensusNodeManager) HandleIncomingMessage(msgType string, data []byte, fromNode string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.consensusEngine == nil {
		return fmt.Errorf("consensus engine not initialized")
	}

	log.Printf("[P2PConsensus] Handling incoming %s message from %s", msgType, fromNode)

	switch msgType {
	case "proposal":
		var proposal consensus.Proposal
		if err := json.Unmarshal(data, &proposal); err != nil {
			return fmt.Errorf("failed to unmarshal proposal: %v", err)
		}
		return m.consensusEngine.HandleProposal(&proposal)

	case "prepare":
		var vote consensus.Vote
		if err := json.Unmarshal(data, &vote); err != nil {
			return fmt.Errorf("failed to unmarshal prepare vote: %v", err)
		}
		return m.consensusEngine.HandlePrepareVote(&vote)

	case "vote":
		var vote consensus.Vote
		if err := json.Unmarshal(data, &vote); err != nil {
			return fmt.Errorf("failed to unmarshal commit vote: %v", err)
		}
		return m.consensusEngine.HandleVote(&vote)

	case "timeout":
		var timeout consensus.TimeoutMsg
		if err := json.Unmarshal(data, &timeout); err != nil {
			return fmt.Errorf("failed to unmarshal timeout: %v", err)
		}
		return m.consensusEngine.HandleTimeout(&timeout)

	case "commit_certificate":
		var cert consensus.CommitCertificate
		if err := json.Unmarshal(data, &cert); err != nil {
			return fmt.Errorf("failed to unmarshal commit certificate: %v", err)
		}
		return m.consensusEngine.HandleCommitCertificate(&cert)

	case "prepare_certificate":
		var cert consensus.PrepareCertificate
		if err := json.Unmarshal(data, &cert); err != nil {
			return fmt.Errorf("failed to unmarshal prepare certificate: %v", err)
		}
		return m.consensusEngine.HandlePrepareCertificate(&cert)

	case "checkpoint":
		return m.consensusEngine.HandleCheckpointMessage(data, fromNode)

	case "randao_sync":
		var randaoData struct {
			Mix         [32]byte                                       `json:"mix"`
			Submissions map[uint64]map[string]*consensus.VDFSubmission `json:"submissions"`
		}
		if err := json.Unmarshal(data, &randaoData); err != nil {
			return fmt.Errorf("failed to unmarshal RANDAO data: %v", err)
		}
		return m.consensusEngine.HandleRANDAOSync(randaoData.Mix, randaoData.Submissions)

	case "sync_request":
		// Request missing blocks during PBFT catch-up.
		// This must be correlated with consensus' pendingSyncRequests.
		// Consensus.fetchBlockFromPeers currently broadcasts a payload:
		// {"method":"blockchain.getBlockByHeight","params":[height]}
		var req struct {
			Method string        `json:"method"`
			Params []interface{} `json:"params"`
		}
		if err := json.Unmarshal(data, &req); err != nil {
			return fmt.Errorf("failed to unmarshal sync_request: %v", err)
		}
		if req.Method != "blockchain.getBlockByHeight" || len(req.Params) < 1 {
			return nil
		}
		// Parse height from params
		heightF, ok := req.Params[0].(float64)
		if !ok {
			return nil
		}
		height := uint64(heightF)

		block := m.consensusEngine.GetBlockByHeight(height)
		if block == nil {
			return fmt.Errorf("cannot serve sync_request: block %d is not available", height)
		}

		// The legacy bind transport does not supply an origin node ID, so send
		// the response through the same broadcast transport as the request. Only
		// the requester has a pending channel for this height; other nodes ignore
		// the response in HandleSyncResponse.
		resp := map[string]interface{}{
			"height": height,
			"block":  block,
		}
		if err := m.BroadcastMessage("sync_response", resp); err != nil {
			return fmt.Errorf("failed to broadcast sync_response for block %d: %w", height, err)
		}
		return nil

	case "sync_response":
		var resp struct {
			Height uint64          `json:"height"`
			Block  json.RawMessage `json:"block"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			return fmt.Errorf("failed to unmarshal sync_response: %v", err)
		}
		// Deliver to consensus waiting channel.
		return m.consensusEngine.HandleSyncResponse(resp.Height, resp.Block)

	default:
		log.Printf("[P2PConsensus] Unknown message type: %s", msgType)
		return nil
	}
}

// p2pConsensusPeer implements consensus.Peer
type p2pConsensusPeer struct{ id string }

func (p *p2pConsensusPeer) GetNode() consensus.Node { return &p2pConsensusNode{id: p.id} }

// p2pConsensusNode implements consensus.Node
type p2pConsensusNode struct{ id string }

func (n *p2pConsensusNode) GetID() string                   { return n.id }
func (n *p2pConsensusNode) GetRole() consensus.NodeRole     { return consensus.RoleValidator }
func (n *p2pConsensusNode) GetStatus() consensus.NodeStatus { return consensus.NodeStatusActive }

// AddPeer adds a peer to the P2PConsensusNodeManager
func (m *P2PConsensusNodeManager) AddPeer(peerID string, peerAddress string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Initialize maps if nil
	if m.peerList == nil {
		m.peerList = make(map[string]consensus.Peer)
	}
	if m.peerAddresses == nil {
		m.peerAddresses = make(map[string]string)
	}

	// Check if already exists
	if _, exists := m.peerList[peerID]; exists {
		log.Printf("[P2PConsensus] Peer %s already exists, skipping", peerID)
		return
	}

	// Add peer
	m.peerList[peerID] = &p2pConsensusPeer{id: peerID}
	m.peerAddresses[peerID] = peerAddress
	log.Printf("[P2PConsensus] Added peer: %s at %s (total peers: %d)", peerID, peerAddress, len(m.peerList))
}
