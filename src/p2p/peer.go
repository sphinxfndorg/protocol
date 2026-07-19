// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/p2p/peer.go
package p2p

import (
	"context"
	"crypto/rand"

	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"time"

	logger "github.com/sphinxfndorg/protocol/src/console"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	"github.com/sphinxfndorg/protocol/src/network"
	"lukechampine.com/blake3"
)

// NewPeerManager creates a new peer manager.
// Initializes the peer manager with empty maps for tracking peers, scores, and bans.
// Sets default connection limits for inbound and outbound connections.
func NewPeerManager(server *Server, bucketSize int) *PeerManager {
	return &PeerManager{
		server:      server,                         // Reference to the P2P server
		peers:       make(map[string]*network.Peer), // Map of peer ID to peer struct
		scores:      make(map[string]int),           // Map of peer ID to reputation score
		bans:        make(map[string]time.Time),     // Map of peer ID to ban expiry time
		maxPeers:    50,                             // Maximum total peer connections
		maxInbound:  30,                             // Maximum inbound connections
		maxOutbound: 20,                             // Maximum outbound connections
	}
}

// ConnectPeer establishes a connection to a peer and performs handshake.
// This function handles the entire peer connection lifecycle including:
// - Ban check
// - Connection limit validation
// - TCP connection establishment
// - Peer registration
// - Protocol handshake
// - Peer information broadcast
func (pm *PeerManager) ConnectPeer(node *network.Node) error {
	pm.mu.Lock() // Lock for thread safety
	defer pm.mu.Unlock()

	// Check if peer is banned
	if banExpiry, banned := pm.bans[node.ID]; banned && time.Now().Before(banExpiry) {
		logger.Info("Peer %s is banned until %v", node.ID, banExpiry)
		return fmt.Errorf("peer %s is banned until %v", node.ID, banExpiry)
	}

	// Check if we've reached maximum peer limit
	if len(pm.peers) >= pm.maxPeers {
		logger.Info("Maximum peer limit reached: %d", pm.maxPeers)
		return errors.New("maximum peer limit reached")
	}

	logger.Info("Connecting to node %s via TCP: %s", node.ID, node.Address)

	// Establish TCP connection to the peer
	_, err := pm.server.tcpConnect(node.Address, pm.server.messageCh)
	if err != nil {
		logger.Warn("Failed to connect to %s: %v", node.ID, err)
		return fmt.Errorf("failed to connect to %s: %v", node.ID, err)
	}
	logger.Info("TCP connection established to %s", node.Address)

	// Create peer object before handshake
	peer := &network.Peer{
		Node:             node,
		ConnectionStatus: "connected",
		ConnectedAt:      time.Now(),
		LastSeen:         time.Now(),
	}

	// Add peer to node manager's peer list
	if err := pm.server.nodeManager.AddPeer(node); err != nil {
		logger.Warn("Failed to add peer %s: %v", node.ID, err)
		pm.server.tcpDisconnect(node) // Clean up connection
		return fmt.Errorf("failed to add peer %s: %v", node.ID, err)
	}

	// Add to local peer tracking maps
	pm.peers[node.ID] = peer
	pm.scores[node.ID] = 50 // Initial default score

	// Perform handshake after adding peer
	if err := pm.performHandshake(node); err != nil {
		logger.Info("Handshake failed with %s: %v", node.ID, err)
		pm.server.tcpDisconnect(node) // Clean up connection
		// Rollback peer addition
		pm.server.nodeManager.RemovePeer(node.ID)
		delete(pm.peers, node.ID)
		delete(pm.scores, node.ID)
		return fmt.Errorf("handshake failed with %s: %v", node.ID, err)
	}

	// Store peer information in database for persistence
	if err := pm.server.StorePeer(peer); err != nil {
		logger.Warn("Failed to store peer %s in DB: %v", node.ID, err)
	}

	logger.Info("Connected to peer %s (Role=%s)", node.ID, node.Role)

	// Send initial ping to check liveness
	peer.SendPing()

	// Broadcast our peer information to the network
	// Marshal PeerInfo to JSON first
	peerInfo := network.PeerInfo{
		NodeID:          pm.server.localNode.ID,
		KademliaID:      pm.server.localNode.KademliaID,
		Address:         pm.server.localNode.Address,
		IP:              pm.server.localNode.IP,
		Port:            pm.server.localNode.Port,
		UDPPort:         pm.server.localNode.UDPPort,
		Role:            pm.server.localNode.Role,
		Status:          network.NodeStatusActive,
		Timestamp:       time.Now(),
		ProtocolVersion: "1.0",
		PublicKey:       pm.server.localNode.PublicKey,
	}

	peerInfoBytes, err := json.Marshal(peerInfo)
	if err != nil {
		logger.Warn("Failed to marshal peer info: %v", err)
		return fmt.Errorf("failed to marshal peer info: %v", err)
	}

	pm.server.Broadcast(&security.Message{
		Type: "peer_info",
		Data: peerInfoBytes,
	})

	return nil
}

// performHandshake negotiates protocol version and capabilities.
func (pm *PeerManager) performHandshake(node *network.Node) error {
	logger.Info("Starting handshake with %s (ID=%s)", node.Address, node.ID)

	// Ensure peer exists in our tracking maps before sending version
	pm.mu.Lock()
	if _, exists := pm.peers[node.ID]; !exists {
		pm.peers[node.ID] = &network.Peer{
			Node:             node,
			ConnectionStatus: "pending",
			ConnectedAt:      time.Now(),
			LastSeen:         time.Now(),
		}
		logger.Info("Added peer %s to nodeManager.peers before handshake", node.ID)
	}
	pm.mu.Unlock()

	// Generate random nonce for this handshake to prevent replay attacks
	nonce := make([]byte, 8)
	rand.Read(nonce)

	// Create version message with our information
	versionData := map[string]interface{}{
		"version":      "0.1.0",
		"node_id":      pm.server.localNode.ID,
		"chain_id":     "sphinx-mainnet",
		"block_height": pm.server.blockchain.GetBlockCount(),
		"nonce":        hex.EncodeToString(nonce),
		"address":      pm.server.localNode.Address,
	}

	// Marshal version data to JSON
	versionBytes, err := json.Marshal(versionData)
	if err != nil {
		logger.Warn("Failed to marshal version message: %v", err)
		return fmt.Errorf("failed to marshal version message: %v", err)
	}

	versionMsg := &security.Message{
		Type: "version",
		Data: versionBytes,
	}

	// Get existing TCP connection
	conn, err := pm.server.tcpGetConn(node.Address)
	if err != nil {
		logger.Info("No active connection to %s: %v", node.Address, err)
		return fmt.Errorf("no active connection to %s: %v", node.Address, err)
	}

	// Flush the connection if it's TCP
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		tcpConn.Write([]byte{}) // Flush to ensure clean state
	}

	// Send version message
	if err := pm.server.tcp(node.Address, versionMsg); err != nil {
		logger.Warn("Failed to send version message to %s: %v", node.Address, err)
		return err
	}
	logger.Info("Version message sent to %s, waiting for verack response", node.Address)

	// Wait for verack response with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for {
		select {
		case msg := <-pm.server.messageCh:
			logger.Info("Received message in handshake for %s: Type=%s, Data=%v, ChannelLen=%d",
				node.Address, msg.Type, msg.Data, len(pm.server.messageCh))

			if msg.Type == "verack" {
				// Unmarshal verack data
				var peerID string
				if err := json.Unmarshal(msg.Data, &peerID); err != nil {
					logger.Warn("Failed to unmarshal verack data: %v", err)
					continue
				}

				// Check if verack matches expected peer
				if peerID == node.ID {
					logger.Info("Received valid verack from %s for node_id: %s, Address: %s",
						node.Address, peerID, node.Address)

					// Update peer status to active
					pm.mu.Lock()
					if peer, exists := pm.peers[node.ID]; exists {
						peer.ConnectionStatus = "active"
						peer.LastSeen = time.Now()
					} else {
						logger.Warn("Peer %s not found in nodeManager.peers during verack", node.ID)
					}
					pm.mu.Unlock()
					return nil // Handshake successful
				} else {
					logger.Warn("Invalid verack from %s: peerID=%v, expected=%s, Address: %s",
						node.Address, peerID, node.ID, node.Address)
				}
			} else {
				logger.Info("Unexpected message type in handshake for %s: %s", node.Address, msg.Type)
			}

		case <-ctx.Done():
			// Timeout waiting for verack
			logger.Warn("Timeout waiting for verack from %s: %v", node.Address, ctx.Err())
			return fmt.Errorf("timeout waiting for verack from %s", node.Address)
		}
	}
}

// DisconnectPeer terminates a peer connection.
// DisconnectPeer gracefully disconnects from a peer and cleans up all associated resources.
func (pm *PeerManager) DisconnectPeer(peerID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.disconnectPeerLocked(peerID)
}

// disconnectPeerLocked does the actual disconnect work. Callers must already
// hold pm.mu — sync.Mutex is not reentrant, so this must never be called from
// a path that also tries to lock pm.mu.
func (pm *PeerManager) disconnectPeerLocked(peerID string) error {
	// Check if peer exists
	peer, exists := pm.peers[peerID]
	if !exists {
		return fmt.Errorf("peer %s not found", peerID)
	}

	// Close the underlying connection
	if err := pm.server.tcpDisconnect(peer.Node); err != nil {
		logger.Warn("Failed to disconnect peer %s: %v", peerID, err)
	}

	// Remove from all tracking maps
	delete(pm.peers, peerID)
	delete(pm.scores, peerID)
	pm.server.nodeManager.RemovePeer(peerID)

	logger.Info("Disconnected peer %s", peerID)
	return nil
}

// BanPeer bans a peer for misbehavior.
// Imposes a temporary ban on a peer, preventing reconnection for the specified duration.
func (pm *PeerManager) BanPeer(peerID string, duration time.Duration) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.banPeerLocked(peerID, duration)
}

// banPeerLocked does the actual ban work. Callers must already hold pm.mu.
func (pm *PeerManager) banPeerLocked(peerID string, duration time.Duration) error {
	// Check if peer exists
	if _, exists := pm.peers[peerID]; !exists {
		return fmt.Errorf("peer %s not found", peerID)
	}

	// Set ban expiry time
	pm.bans[peerID] = time.Now().Add(duration)

	// Disconnect the peer
	return pm.disconnectPeerLocked(peerID)
}

// UpdatePeerScore adjusts a peer's score based on behavior.
// Implements a reputation system to track peer reliability and trustworthiness.
// Low scores can lead to automatic bans, high scores improve peer selection.
func (pm *PeerManager) UpdatePeerScore(peerID string, delta int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Ignore updates for unknown peers
	if _, exists := pm.peers[peerID]; !exists {
		return
	}

	// Update score
	pm.scores[peerID] += delta

	// Enforce score boundaries and handle low scores
	if pm.scores[peerID] < 0 {
		pm.scores[peerID] = 0
		// Automatically ban peers with persistent low scores
		pm.banPeerLocked(peerID, 1*time.Hour)
	} else if pm.scores[peerID] > 100 {
		pm.scores[peerID] = 100 // Cap maximum score
	}

	logger.Info("Updated score for peer %s: %d", peerID, pm.scores[peerID])
}

// PropagateMessage implements gossip protocol for message propagation.
// Uses a randomized selection algorithm to efficiently broadcast messages
// while avoiding redundant transmissions and network flooding.
func (pm *PeerManager) PropagateMessage(msg *security.Message, originID string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Generate unique message ID to detect duplicates
	msgID := generateMessageID(msg)

	// Check if we've already seen this message (anti-flood)
	if pm.server.nodeManager.HasSeenMessage(msgID) {
		return
	}

	// Mark message as seen to prevent repropagation
	pm.server.nodeManager.MarkMessageSeen(msgID)

	// Structure to hold peer candidates with their scores
	type peerScore struct {
		peer  *network.Peer
		score int
	}

	// Collect eligible peers for propagation
	var candidates []peerScore
	for id, peer := range pm.peers {
		// Skip origin peer and disconnected peers
		if id == originID || peer.ConnectionStatus != "connected" {
			continue
		}
		candidates = append(candidates, peerScore{peer, pm.scores[id]})
	}

	// Calculate number of peers to propagate to (sqrt(n) for optimal gossip)
	n := int(math.Sqrt(float64(len(candidates))))
	if n < 3 {
		n = 3 // Minimum propagation to 3 peers
	} else if n > 10 {
		n = 10 // Maximum propagation to 10 peers
	}

	// Randomly select peers for propagation using cryptographically secure random
	if len(candidates) > n {
		for i := 0; i < n; i++ {
			j, _ := rand.Int(rand.Reader, big.NewInt(int64(len(candidates)-i)))
			idx := i + int(j.Int64())
			// Swap elements for random selection
			candidates[i], candidates[idx] = candidates[idx], candidates[i]
		}
		candidates = candidates[:n] // Keep only selected candidates
	}

	// Send message to selected peers
	for _, candidate := range candidates {
		peer := candidate.peer
		if err := pm.server.tcp(peer.Node.Address, msg); err != nil {
			logger.Warn("Failed to propagate %s to %s: %v", msg.Type, peer.Node.ID, err)
			// Penalize peer that failed to receive message
			pm.UpdatePeerScore(peer.Node.ID, -10)
		} else {
			// Reward peer for successful message delivery
			pm.UpdatePeerScore(peer.Node.ID, 5)
		}
	}
}

// SyncBlockchain synchronizes the blockchain with a peer.
// Requests block headers from a peer to synchronize chain state.
// SyncBlockchain synchronizes the blockchain with a peer.
// Requests block headers from a peer to synchronize chain state.
func (pm *PeerManager) SyncBlockchain(peerID string) error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Check if peer exists
	peer, exists := pm.peers[peerID]
	if !exists {
		return fmt.Errorf("peer %s not found", peerID)
	}

	// Create getheaders message data
	headersData := map[string]interface{}{
		"start_height": pm.server.blockchain.GetBlockCount(), // Request headers from current height
	}

	// Marshal to JSON
	headersBytes, err := json.Marshal(headersData)
	if err != nil {
		return fmt.Errorf("failed to marshal getheaders data: %v", err)
	}

	// Create getheaders message
	headersMsg := &security.Message{
		Type: "getheaders",
		Data: headersBytes,
	}

	// Send request to peer
	if err := pm.server.tcp(peer.Node.Address, headersMsg); err != nil {
		return fmt.Errorf("failed to request headers from %s: %v", peerID, err)
	}

	logger.Info("Requested headers from peer %s", peerID)
	return nil
}

// MaintainPeers ensures optimal peer connections.
// Background maintenance routine that:
// - Disconnects low-scoring peers when we have enough connections
// - Actively seeks new peers when connection count is low
// - Runs periodically to maintain healthy peer set
func (pm *PeerManager) MaintainPeers() {
	for {
		pm.mu.Lock()

		// Disconnect low-scoring peers if we have enough connections
		for id, score := range pm.scores {
			if score < 20 && len(pm.peers) > pm.maxPeers/2 {
				pm.disconnectPeerLocked(id) // Drop underperforming peer
			}
		}

		// Seek new peers if connection count is low
		if len(pm.peers) < pm.maxPeers/2 {
			// Find closest nodes to us in the DHT
			peers := pm.server.nodeManager.FindClosestPeers(
				pm.server.localNode.KademliaID,
				pm.maxPeers-len(pm.peers),
			)

			// Attempt to connect to discovered peers
			for _, peer := range peers {
				// Skip if already connected or self
				if _, exists := pm.peers[peer.Node.ID]; !exists && peer.Node.Address != pm.server.localNode.Address {
					// Connect in background to avoid blocking maintenance loop
					go pm.ConnectPeer(peer.Node)
				}
			}
		}

		pm.mu.Unlock()

		// Sleep before next maintenance cycle
		time.Sleep(30 * time.Second)
	}
}

// generateMessageID creates a unique ID for a message.
// Uses BLAKE3 hash of the marshaled message to create a deterministic
// but unique identifier for duplicate detection.
func generateMessageID(msg *security.Message) string {
	// Marshal message to JSON
	data, _ := json.Marshal(msg)

	// Calculate BLAKE3 hash (256-bit)
	hash := blake3.Sum256(data)

	// Return hex-encoded hash as string ID
	return hex.EncodeToString(hash[:])
}
