// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/p2p/p2p.go
package p2p

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/core"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	params "github.com/sphinxfndorg/protocol/src/core/sthincs/config"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/dht"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	"github.com/sphinxfndorg/protocol/src/network"
	"github.com/sphinxfndorg/protocol/src/transport"
	"github.com/syndtr/goleveldb/leveldb"
	"go.uber.org/zap"
)

// NewServer creates a new P2P server.
// This initializes all components needed for peer-to-peer communication including:
// - Local node representation
// - DHT for peer discovery
// - Node manager for peer tracking
// - Peer manager for connection management
func NewServer(config network.NodePortConfig, blockchain *core.Blockchain, db *leveldb.DB) *Server {
	// Standard bucket size for Kademlia routing (k=16)
	bucketSize := 16

	// Parse TCP address to extract IP and port components
	parts := strings.Split(config.TCPAddr, ":")
	if len(parts) != 2 {
		log.Fatalf("Invalid TCPAddr format: %s", config.TCPAddr)
	}

	// Parse UDP port from configuration
	udpPort, err := strconv.Atoi(config.UDPPort)
	if err != nil {
		log.Fatalf("Invalid UDPPort format: %s, %v", config.UDPPort, err)
	}

	// Convert leveldb.DB to database.DB interface for compatibility
	nodeDB := &database.DB{} // You'll need to adapt this based on your database interface
	// If your database.DB wraps leveldb.DB, you might need something like:
	// nodeDB := database.NewDBFromLevelDB(db)

	// Create local node representation with provided configuration
	// FIX: Add the database parameter
	localNode := network.NewNode(
		config.TCPAddr, // Full TCP address
		parts[0],       // IP address
		parts[1],       // TCP port
		config.UDPPort, // UDP port for discovery
		true,           // This is the local node
		config.Role,    // Node role (validator, sender, receiver)
		nodeDB,         // Database instance
	)

	// Initialize logger for DHT using Uber's zap logging library
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Generate or use DHT secret for message authentication
	var secret uint16

	// Check if secret is provided in config
	if config.DHTSecret != 0 {
		secret = config.DHTSecret
		log.Printf("Using DHT secret from config: %d", secret)
	} else {
		// Generate random 2-byte secret
		secretBytes := make([]byte, 2)
		if _, err := rand.Read(secretBytes); err != nil {
			log.Fatalf("Failed to generate random secret for DHT: %v", err)
		}
		secret = binary.BigEndian.Uint16(secretBytes)
	}

	// Allow override via environment variable for testing/development
	if envSecret := os.Getenv("DHT_SECRET"); envSecret != "" {
		if parsedSecret, err := strconv.ParseUint(envSecret, 10, 16); err == nil {
			secret = uint16(parsedSecret)
			log.Printf("Using DHT secret from environment variable: %d", secret)
		} else {
			log.Printf("Invalid DHT_SECRET environment variable: %v, generating random secret", err)
			// Generate new random secret if env var is invalid
			secretBytes := make([]byte, 2)
			if _, err := rand.Read(secretBytes); err != nil {
				log.Fatalf("Failed to generate random secret for DHT: %v", err)
			}
			secret = binary.BigEndian.Uint16(secretBytes)
		}
	} else {
		log.Printf("No DHT_SECRET provided, using config secret: %d", secret)
	}

	// Configure DHT with network parameters
	dhtConfig := dht.Config{
		Proto:   "udp",                                                 // Use UDP protocol
		Address: net.UDPAddr{IP: net.ParseIP(parts[0]), Port: udpPort}, // Local UDP address
		Routers: make([]net.UDPAddr, 0, len(config.SeedNodes)),         // Bootstrap routers
		Secret:  secret,                                                // Authentication secret
	}

	// Parse seed nodes into UDP addresses
	for _, seed := range config.SeedNodes {
		seedParts := strings.Split(seed, ":")
		if len(seedParts) == 2 {
			port, err := strconv.Atoi(seedParts[1])
			if err != nil {
				log.Printf("Invalid seed node port %s: %v", seed, err)
				continue
			}
			dhtConfig.Routers = append(dhtConfig.Routers, net.UDPAddr{
				IP:   net.ParseIP(seedParts[0]),
				Port: port,
			})
		}
	}

	// Create DHT instance for peer discovery
	dhtInstance, err := dht.NewDHT(dhtConfig, logger)
	if err != nil {
		log.Fatalf("Failed to initialize DHT: %v", err)
	}

	// Create node manager to track all known nodes
	// FIX: Add the database parameter
	nodeManager := network.NewNodeManager(bucketSize, dhtInstance, nodeDB)

	// Initialize SPHINCS+ key manager (needed for sign manager)
	keyManager, err := key.NewKeyManager()
	if err != nil {
		log.Fatalf("Failed to initialize SPHINCS+ key manager: %v", err)
	}

	// Initialize SPHINCS+ parameters
	sphincsParams, err := params.NewSTHINCSParameters()
	if err != nil {
		log.Fatalf("Failed to initialize SPHINCS+ parameters: %v", err)
	}

	// Initialize SPHINCS+ sign manager with all three required parameters
	sphincsMgr := sign.NewSTHINCSManager(db, keyManager, sphincsParams)

	// Return fully initialized server instance
	return &Server{
		localNode:   localNode,                         // Local node information
		nodeManager: nodeManager,                       // Node tracking manager
		seedNodes:   config.SeedNodes,                  // Bootstrap seed nodes
		dht:         dhtInstance,                       // DHT for discovery
		peerManager: NewPeerManager(nil, bucketSize),   // Peer connection manager
		sphincsMgr:  sphincsMgr,                        // SPHINCS+ crypto manager (now initialized)
		db:          db,                                // LevelDB database
		udpReadyCh:  make(chan struct{}, 1),            // Channel to signal UDP ready
		messageCh:   make(chan *security.Message, 100), // Message processing channel
		blockchain:  blockchain,                        // Blockchain instance
		stopCh:      make(chan struct{}),               // Stop signal channel
	}
}

// UpdateSeedNodes updates the server's seed nodes.
// This allows dynamic updating of bootstrap nodes at runtime
func (s *Server) UpdateSeedNodes(seedNodes []string) {
	s.mu.Lock() // Lock for thread safety
	defer s.mu.Unlock()
	s.seedNodes = seedNodes
	log.Printf("UpdateSeedNodes: Set seed nodes for %s to %v", s.localNode.Address, s.seedNodes)
}

// SetServer sets the server field for the peer manager.
// Creates a bidirectional link between server and peer manager
func (s *Server) SetServer() {
	s.peerManager.server = s
}

// Start starts the P2P server and initializes peer discovery.
// Launches UDP discovery and message handling goroutines
func (s *Server) Start() error {
	s.SetServer() // Set server for peerManager

	// Start UDP discovery service
	if err := s.StartUDPDiscovery(s.localNode.UDPPort); err != nil {
		return fmt.Errorf("failed to start UDP discovery: %v", err)
	}

	// Start message handler goroutine
	go s.handleMessages()

	return nil
}

// Close shuts down the P2P server.
// Gracefully stops all services and closes connections
func (s *Server) Close() error {
	var errs []error // Collect errors for reporting

	// Stop UDP discovery service
	if err := s.StopUDPDiscovery(); err != nil {
		errs = append(errs, fmt.Errorf("failed to stop UDP discovery: %v", err))
	}

	// Close message channel if it exists
	if s.messageCh != nil {
		select {
		case <-s.messageCh:
			// Channel already closed
		default:
			close(s.messageCh)
		}
	}

	// Allow time for sockets to release properly
	time.Sleep(1 * time.Second)

	// Return combined errors if any occurred
	if len(errs) > 0 {
		return fmt.Errorf("errors during P2P server shutdown: %v", errs)
	}
	return nil
}

// CloseDB closes the LevelDB instance.
// Ensures database is properly closed to prevent corruption
func (s *Server) CloseDB() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// StorePeer stores peer information in LevelDB.
// Persists peer data for recovery after restart
func (s *Server) StorePeer(peer *network.Peer) error {
	// Get peer information
	peerInfo := peer.GetPeerInfo()

	// Marshal to JSON for storage
	data, err := json.Marshal(peerInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal peer info: %v", err)
	}

	// Store in database with key "peer-<nodeID>"
	key := []byte("peer-" + peer.Node.ID)
	return s.db.Put(key, data, nil)
}

// FetchPeer retrieves peer information from LevelDB.
// Loads previously stored peer data
func (s *Server) FetchPeer(nodeID string) (*network.PeerInfo, error) {
	// Construct database key
	key := []byte("peer-" + nodeID)

	// Retrieve from database
	data, err := s.db.Get(key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch peer %s: %v", nodeID, err)
	}

	// Unmarshal from JSON
	var peerInfo network.PeerInfo
	if err := json.Unmarshal(data, &peerInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal peer info: %v", err)
	}
	return &peerInfo, nil
}

// handleMessages processes incoming messages.
// This is the main message dispatcher that routes different message types
// to their appropriate handlers
// handleMessages processes incoming messages.
func (s *Server) handleMessages() {
	for msg := range s.messageCh {
		log.Printf("Processing message from channel: Type=%s, Data=%v, ChannelLen=%d",
			msg.Type, msg.Data, len(s.messageCh))

		originID := ""

		switch msg.Type {

		case "transaction":
			// Need to unmarshal the json.RawMessage first
			var tx types.Transaction
			if err := json.Unmarshal(msg.Data, &tx); err != nil {
				log.Printf("Failed to unmarshal transaction: %v", err)
				continue
			}
			// Assign sender/receiver roles
			s.assignTransactionRoles(&tx)

			if !tx.IsSystemTransaction() && !tx.HasFullAuthBundle() {
				log.Printf("Transaction rejected: missing full SPHINCS auth bundle")
				continue
			}

			if err := s.validateTransaction(&tx); err != nil {
				log.Printf("Transaction validation failed: %v", err)
				continue
			}

			if err := s.blockchain.AddTransaction(&tx); err != nil {
				log.Printf("Failed to add transaction: %v", err)
				if originID != "" {
					s.peerManager.UpdatePeerScore(originID, -10)
				}
				continue
			}

			s.peerManager.PropagateMessage(msg, originID)

			if originID != "" {
				s.peerManager.UpdatePeerScore(originID, 5)
			}

		case "block":
			var block types.Block
			if err := json.Unmarshal(msg.Data, &block); err != nil {
				log.Printf("Failed to unmarshal block: %v", err)
				continue
			}

			if err := block.Validate(); err != nil {
				log.Printf("Block validation failed: %v", err)
				if originID != "" {
					s.peerManager.UpdatePeerScore(originID, -10)
				}
				continue
			}

			for _, tx := range block.Body.TxsList {
				if err := s.blockchain.AddTransaction(tx); err != nil {
					log.Printf("Failed to add block transaction %s: %v", tx.ID, err)
					if originID != "" {
						s.peerManager.UpdatePeerScore(originID, -5)
					}
				}
			}

			if err := s.blockchain.CommitBlock(&block); err != nil {
				log.Printf("Failed to commit block: %v", err)
				if originID != "" {
					s.peerManager.UpdatePeerScore(originID, -10)
				}
				continue
			}

			s.peerManager.PropagateMessage(msg, originID)

			if originID != "" {
				s.peerManager.UpdatePeerScore(originID, 10)
			}

		case "proposal":
			var proposal consensus.Proposal
			if err := json.Unmarshal(msg.Data, &proposal); err != nil {
				log.Printf("Failed to unmarshal proposal: %v", err)
				continue
			}
			if s.consensus != nil {
				if err := s.consensus.HandleProposal(&proposal); err != nil {
					log.Printf("Failed to handle consensus proposal: %v", err)
				}
			}

		case "vote":
			var vote consensus.Vote
			if err := json.Unmarshal(msg.Data, &vote); err != nil {
				log.Printf("Failed to unmarshal vote: %v", err)
				continue
			}
			if s.consensus != nil {
				if err := s.consensus.HandleVote(&vote); err != nil {
					log.Printf("Failed to handle consensus vote: %v", err)
				}
			}

		case "prepare":
			var vote consensus.Vote
			if err := json.Unmarshal(msg.Data, &vote); err != nil {
				log.Printf("Failed to unmarshal prepare vote: %v", err)
				continue
			}
			if s.consensus != nil {
				if err := s.consensus.HandlePrepareVote(&vote); err != nil {
					log.Printf("Failed to handle consensus prepare vote: %v", err)
				}
			}

		case "timeout":
			var timeout consensus.TimeoutMsg
			if err := json.Unmarshal(msg.Data, &timeout); err != nil {
				log.Printf("Failed to unmarshal timeout: %v", err)
				continue
			}
			if s.consensus != nil {
				if err := s.consensus.HandleTimeout(&timeout); err != nil {
					log.Printf("Failed to handle consensus timeout: %v", err)
				}
			}

		case "ping":
			var pingData network.PingData
			if err := json.Unmarshal(msg.Data, &pingData); err != nil {
				log.Printf("Failed to unmarshal ping data: %v", err)
				continue
			}
			if peer := s.nodeManager.GetNodeByKademliaID(pingData.FromID); peer != nil {
				if p, ok := s.nodeManager.GetPeers()[peer.ID]; ok {
					p.ReceivePong()

					// Marshal pong response
					pongData := network.PongData{
						FromID:    s.localNode.KademliaID,
						ToID:      pingData.FromID,
						Timestamp: time.Now(),
						Nonce:     pingData.Nonce,
					}
					pongBytes, _ := json.Marshal(pongData)

					transport.SendMessage(peer.Address, &security.Message{
						Type: "pong",
						Data: pongBytes,
					})

					s.peerManager.UpdatePeerScore(peer.ID, 2)
				}
			}

		case "pong":
			var pongData network.PongData
			if err := json.Unmarshal(msg.Data, &pongData); err != nil {
				log.Printf("Failed to unmarshal pong data: %v", err)
				continue
			}
			if peer := s.nodeManager.GetNodeByKademliaID(pongData.FromID); peer != nil {
				if p, ok := s.nodeManager.GetPeers()[peer.ID]; ok {
					p.ReceivePong()
					s.peerManager.UpdatePeerScore(peer.ID, 2)
				}
			}

		case "peer_info":
			var peerInfo network.PeerInfo
			if err := json.Unmarshal(msg.Data, &peerInfo); err != nil {
				log.Printf("Failed to unmarshal peer info: %v", err)
				continue
			}
			node := network.NewNode(
				peerInfo.Address,
				peerInfo.IP,
				peerInfo.Port,
				peerInfo.UDPPort,
				false,
				peerInfo.Role,
				nil,
			)
			node.KademliaID = peerInfo.KademliaID
			node.UpdateStatus(peerInfo.Status)

			s.nodeManager.AddNode(node)

			if len(s.peerManager.peers) < s.peerManager.maxPeers {
				s.peerManager.ConnectPeer(node)
			}
			log.Printf("Received PeerInfo: NodeID=%s, Address=%s, Role=%s",
				peerInfo.NodeID, peerInfo.Address, peerInfo.Role)

		case "version":
			var versionData map[string]interface{}
			if err := json.Unmarshal(msg.Data, &versionData); err != nil {
				log.Printf("Failed to unmarshal version data: %v", err)
				continue
			}
			peerID, ok := versionData["node_id"].(string)
			if !ok {
				log.Printf("Invalid node_id in version message")
				continue
			}

			var publicKeyBytes []byte
			if pkStr, ok := versionData["public_key"].(string); ok {
				publicKeyBytes, _ = hex.DecodeString(pkStr)
			}

			node := s.nodeManager.GetNode(peerID)
			if node == nil {
				node = &network.Node{
					ID:         peerID,
					Address:    "",
					Status:     network.NodeStatusActive,
					LastSeen:   time.Now(),
					KademliaID: network.GenerateKademliaID(peerID),
					PublicKey:  publicKeyBytes,
				}
				s.nodeManager.AddNode(node)
			} else if len(publicKeyBytes) > 0 {
				node.PublicKey = publicKeyBytes
			}

			if s.consensus != nil && len(publicKeyBytes) > 0 {
				signingService := s.consensus.GetSigningService()
				if signingService != nil {
					signingService.DeserializeAndRegisterPublicKey(peerID, publicKeyBytes)
				}
			}

			verackMsg := &security.Message{
				Type: "verack",
				Data: []byte(s.localNode.ID),
			}

			sourceAddr := node.Address
			if sourceAddr == "" {
				if addr, ok := versionData["address"].(string); ok && addr != "" {
					sourceAddr = addr
				}
			}

			if sourceAddr != "" {
				transport.SendMessage(sourceAddr, verackMsg)
				s.peerManager.UpdatePeerScore(peerID, 5)
			}

			if addr, ok := versionData["address"].(string); ok && addr != "" && node.Address == "" {
				node.Address = addr
				s.nodeManager.UpdateNode(node)
			}

		case "getheaders":
			var data map[string]interface{}
			if err := json.Unmarshal(msg.Data, &data); err != nil {
				log.Printf("Failed to unmarshal getheaders data: %v", err)
				continue
			}
			startHeight, ok := data["start_height"].(float64)
			if !ok {
				continue
			}

			blocks := s.blockchain.GetBlocks()
			var headers []*types.BlockHeader
			for _, block := range blocks {
				if block.Header.Block >= uint64(startHeight) {
					headers = append(headers, block.Header)
				}
			}

			headersBytes, _ := json.Marshal(headers)
			if peer, ok := s.nodeManager.GetPeers()[originID]; ok && originID != "" {
				transport.SendMessage(peer.Node.Address, &security.Message{
					Type: "headers",
					Data: headersBytes,
				})
			}

		case "headers":
			var headers []types.BlockHeader
			if err := json.Unmarshal(msg.Data, &headers); err != nil {
				log.Printf("Failed to unmarshal headers: %v", err)
				continue
			}
			log.Printf("Received %d headers from peer %s", len(headers), originID)
			if originID != "" {
				s.peerManager.UpdatePeerScore(originID, 10)
			}

		default:
			log.Printf("Unknown message type: %s", msg.Type)
			if originID != "" {
				s.peerManager.UpdatePeerScore(originID, -5)
			}
		}
	}
}

// InitializeConsensus initializes the consensus module for this server
// Links the consensus engine with the P2P server for message routing
func (s *Server) InitializeConsensus(consensus *consensus.Consensus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consensus = consensus
	log.Printf("Consensus module initialized for node %s", s.localNode.ID)
}

// GetConsensus returns the consensus instance (if initialized)
// Provides access to the consensus engine from other components
func (s *Server) GetConsensus() *consensus.Consensus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.consensus
}

// assignTransactionRoles assigns Sender and Receiver roles based on transaction.
// Updates node roles when they appear as sender or receiver in a transaction
func (s *Server) assignTransactionRoles(tx *types.Transaction) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check all known nodes for role assignment
	for _, node := range s.nodeManager.GetPeers() {
		switch node.Node.Address {
		case tx.Sender:
			// Node is the sender in this transaction
			node.Node.UpdateRole(network.RoleSender)

		case tx.Receiver:
			// Node is the receiver in this transaction
			node.Node.UpdateRole(network.RoleReceiver)

			// Ensure receiver is in peer list
			if _, exists := s.nodeManager.GetPeers()[node.Node.ID]; !exists {
				if err := s.nodeManager.AddPeer(node.Node); err != nil {
					log.Printf("Failed to make %s a peer: %v", node.Node.ID, err)
				} else {
					log.Printf("Node %s (receiver) became peer for transaction", node.Node.ID)
				}
			}
		}
	}
}

// validateTransaction sends a transaction to a validator node.
// Selects a validator and forwards the transaction for validation
func (s *Server) validateTransaction(tx *types.Transaction) error {
	if tx == nil {
		return errors.New("nil transaction")
	}
	if !tx.IsSystemTransaction() && !tx.HasFullAuthBundle() {
		return errors.New("missing full SPHINCS transaction auth bundle")
	}

	// Select a validator node from available nodes
	validatorNode := s.nodeManager.SelectValidator()
	if validatorNode == nil {
		return errors.New("no validator available")
	}

	// Ensure we're connected to the validator
	if _, exists := s.nodeManager.GetPeers()[validatorNode.ID]; !exists {
		if err := s.peerManager.ConnectPeer(validatorNode); err != nil {
			return fmt.Errorf("failed to connect to validator %s: %v", validatorNode.ID, err)
		}
		log.Printf("Node %s (validator) became peer for validation", validatorNode.ID)
	}

	// Get peer connection
	peer := s.nodeManager.GetPeers()[validatorNode.ID]

	// Marshal transaction to JSON
	txData, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %v", err)
	}

	// Send transaction to validator
	if err := transport.SendMessage(peer.Node.Address, &security.Message{
		Type: "transaction",
		Data: txData, // Use marshaled bytes
	}); err != nil {
		return fmt.Errorf("failed to send transaction to validator %s: %v", validatorNode.ID, err)
	}

	log.Printf("Transaction sent to validator %s for validation", validatorNode.ID)
	return nil
}

// Broadcast sends a message to all peers.
// Simple wrapper around peer manager's propagation function
// Broadcast sends a message to all peers.
func (s *Server) Broadcast(msg *security.Message) {
	// Make a copy and ensure Data is marshaled properly
	msgCopy := &security.Message{
		Type: msg.Type,
		Data: msg.Data, // Already should be json.RawMessage
	}
	s.peerManager.PropagateMessage(msgCopy, s.localNode.ID)
}
