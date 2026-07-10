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

			// Check if this is a response to a sync request
			requestID := ""
			if msgID, ok := msg.Metadata["request_id"].(string); ok {
				requestID = msgID
			}

			// If this is a requested block response, route to sync manager
			if requestID != "" && s.blockchain.GetSyncManager() != nil {
				if err := s.blockchain.GetSyncManager().HandleBlockResponse(requestID, &block); err != nil {
					log.Printf("Failed to handle block response: %v", err)
				}
				continue
			}

			// Otherwise, process as new block broadcast
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

		// ========== SYNC PROTOCOL HANDLERS (Phase A) ==========
		// These handlers implement the Bitcoin-style sync protocol:
		//   getchaininfo → chaininfo  (exchange chain state)
		//   getblocks    → inv        (batch block inventory)
		//   getdata      → block      (individual block delivery)

		case "getchaininfo":
			// Peer is requesting our chain information.
			// Respond with current height, genesis hash, best hash, etc.
			var reqData map[string]interface{}
			if err := json.Unmarshal(msg.Data, &reqData); err != nil {
				log.Printf("Failed to unmarshal getchaininfo request: %v", err)
				continue
			}

			// Build chain info response
			chainParams := s.blockchain.GetChainParams()
			genesisBlock := s.blockchain.GetBlockByNumber(0)
			latestBlock := s.blockchain.GetLatestBlock()
			currentHeight := s.blockchain.GetBlockCount()

			genesisHash := ""
			if genesisBlock != nil {
				genesisHash = genesisBlock.GetHash()
			}

			latestHash := ""
			if latestBlock != nil {
				latestHash = latestBlock.GetHash()
			}

			// Get consensus state if available
			currentView := uint64(0)
			leaderID := ""
			if s.consensus != nil {
				currentView, _, _ = s.consensus.RefreshLeaderStatus()
				leaderID = s.consensus.GetNodeID()
			}

			// Calculate current epoch from chain height (100 blocks per epoch)
			currentEpoch := currentHeight / 100

			chainInfo := map[string]interface{}{
				"chain_id":         chainParams.ChainID,
				"genesis_hash":     genesisHash,
				"genesis_time":     chainParams.GenesisTime,
				"current_height":   currentHeight,
				"latest_block":     latestHash,
				"finalized_height": currentHeight, // Simplified: all blocks are finalized
				"finalized_hash":   latestHash,
				"protocol_version": chainParams.Version,
				"current_view":     currentView,
				"current_epoch":    currentEpoch,
				"leader_id":        leaderID,
				"node_id":          s.localNode.ID,
			}

			chainInfoData, err := json.Marshal(chainInfo)
			if err != nil {
				log.Printf("Failed to marshal chain info: %v", err)
				continue
			}

			// Send response back to requesting peer
			if peer, ok := s.nodeManager.GetPeers()[originID]; ok && originID != "" {
				transport.SendMessage(peer.Node.Address, &security.Message{
					Type: "chaininfo",
					Data: chainInfoData,
				})
				s.peerManager.UpdatePeerScore(originID, 5)
				log.Printf("📤 Sent chaininfo to peer %s: height=%d, genesis=%s",
					originID, currentHeight, genesisHash[:16])
			}

		case "chaininfo":
			// Received chain info from a peer — route to SyncManager
			var chainInfo map[string]interface{}
			if err := json.Unmarshal(msg.Data, &chainInfo); err != nil {
				log.Printf("Failed to unmarshal chaininfo: %v", err)
				continue
			}

			if s.blockchain.GetSyncManager() != nil {
				s.blockchain.GetSyncManager().HandleChainInfoResponse(originID, chainInfo)
			}
			if originID != "" {
				s.peerManager.UpdatePeerScore(originID, 10)
			}

		case "getblocks":
			// Peer is requesting a batch of blocks (inventory-style).
			// Respond with an inv message containing block hashes in the requested range.
			var reqData map[string]interface{}
			if err := json.Unmarshal(msg.Data, &reqData); err != nil {
				log.Printf("Failed to unmarshal getblocks request: %v", err)
				continue
			}

			startHeight, _ := reqData["start_height"].(float64)
			count, _ := reqData["count"].(float64)

			if count <= 0 || count > 1024 {
				count = 1024 // Cap at 1024 blocks per request
			}

			// Build inventory response
			inv := make([]map[string]interface{}, 0)
			for h := uint64(startHeight); h < uint64(startHeight+count); h++ {
				block := s.blockchain.GetBlockByNumber(h)
				if block == nil {
					break // Reached end of chain
				}
				inv = append(inv, map[string]interface{}{
					"type":   "block",
					"hash":   block.GetHash(),
					"height": h,
				})
			}

			invResponse := map[string]interface{}{
				"inventory": inv,
			}

			invData, err := json.Marshal(invResponse)
			if err != nil {
				log.Printf("Failed to marshal inv response: %v", err)
				continue
			}

			// Send inv response back
			if peer, ok := s.nodeManager.GetPeers()[originID]; ok && originID != "" {
				transport.SendMessage(peer.Node.Address, &security.Message{
					Type: "inv",
					Data: invData,
				})
				s.peerManager.UpdatePeerScore(originID, 5)
				log.Printf("📤 Sent inv to peer %s: %d blocks (heights %d-%d)",
					originID, len(inv), uint64(startHeight), uint64(startHeight)+uint64(len(inv))-1)
			}

		case "inv":
			// Received inventory from a peer — contains block hashes/heights.
			// For each block in the inventory, send a getdata request.
			var invData map[string]interface{}
			if err := json.Unmarshal(msg.Data, &invData); err != nil {
				log.Printf("Failed to unmarshal inv: %v", err)
				continue
			}

			inventory, _ := invData["inventory"].([]interface{})
			log.Printf("📥 Received inv from peer %s: %d blocks", originID, len(inventory))

			// For each unknown block, request it via getdata
			for _, entry := range inventory {
				entryMap, ok := entry.(map[string]interface{})
				if !ok {
					continue
				}
				height, _ := entryMap["height"].(float64)
				blockType, _ := entryMap["type"].(string)

				if blockType != "block" {
					continue
				}

				// Check if we already have this block
				existing := s.blockchain.GetBlockByNumber(uint64(height))
				if existing != nil {
					continue // Already have it
				}

				// Request this block via getdata
				requestID := fmt.Sprintf("inv-block-%d-%s", uint64(height), originID)
				getdataReq := map[string]interface{}{
					"method":     "getdata",
					"request_id": requestID,
					"params": []map[string]interface{}{
						{
							"type":   "block",
							"height": uint64(height),
						},
					},
				}

				getdataData, _ := json.Marshal(getdataReq)
				if peer, ok := s.nodeManager.GetPeers()[originID]; ok && originID != "" {
					transport.SendMessage(peer.Node.Address, &security.Message{
						Type: "getdata",
						Data: getdataData,
					})
				}
			}

			if originID != "" {
				s.peerManager.UpdatePeerScore(originID, 10)
			}

		case "getdata":
			// Peer is requesting specific data (blocks, transactions, etc.)
			// Respond with the requested data.
			var reqData map[string]interface{}
			if err := json.Unmarshal(msg.Data, &reqData); err != nil {
				log.Printf("Failed to unmarshal getdata request: %v", err)
				continue
			}

			requestID, _ := reqData["request_id"].(string)
			params, _ := reqData["params"].([]interface{})

			for _, param := range params {
				paramMap, ok := param.(map[string]interface{})
				if !ok {
					continue
				}

				dataType, _ := paramMap["type"].(string)
				height, _ := paramMap["height"].(float64)

				if dataType == "block" {
					block := s.blockchain.GetBlockByNumber(uint64(height))
					if block == nil {
						log.Printf("Block %d not found for peer %s", uint64(height), originID)
						continue
					}

					// Serialize block
					blockData, err := json.Marshal(block)
					if err != nil {
						log.Printf("Failed to marshal block %d: %v", uint64(height), err)
						continue
					}

					// Send block response with request_id for matching
					response := &security.Message{
						Type: "block",
						Data: blockData,
					}
					response.Metadata = map[string]interface{}{
						"request_id": requestID,
					}

					if peer, ok := s.nodeManager.GetPeers()[originID]; ok && originID != "" {
						transport.SendMessage(peer.Node.Address, response)
						s.peerManager.UpdatePeerScore(originID, 5)
						log.Printf("📤 Sent block %d to peer %s (request_id=%s)",
							uint64(height), originID, requestID)
					}
				}
			}

		// ========== STATE SNAPSHOT / CHECKPOINT SYNC (Phase B+C) ==========
		// These handlers implement snapshot-based state sync:
		//   getsnapshot  → snapshot     (download full state snapshot)
		//   checkpoint  → checkpoint   (exchange checkpoint messages)

		case "getsnapshot":
			// Peer is requesting a state snapshot at a given height.
			var reqData map[string]interface{}
			if err := json.Unmarshal(msg.Data, &reqData); err != nil {
				log.Printf("Failed to unmarshal getsnapshot request: %v", err)
				continue
			}

			height, _ := reqData["height"].(float64)
			log.Printf("📥 Received getsnapshot request from peer %s for height %d", originID, uint64(height))

			// Get the snapshot manager from the blockchain
			snapshotMgr := s.blockchain.GetSnapshotManager()
			if snapshotMgr == nil {
				log.Printf("No snapshot manager available — cannot serve getsnapshot request")
				continue
			}

			// Load the snapshot data
			snapshotData, err := snapshotMgr.LoadSnapshot(uint64(height))
			if err != nil {
				log.Printf("Snapshot at height %d not found: %v", uint64(height), err)
				// Send error response
				errResp := map[string]interface{}{
					"error":  fmt.Sprintf("snapshot at height %d not available", uint64(height)),
					"height": uint64(height),
				}
				errData, _ := json.Marshal(errResp)
				if peer, ok := s.nodeManager.GetPeers()[originID]; ok && originID != "" {
					transport.SendMessage(peer.Node.Address, &security.Message{
						Type: "snapshot_error",
						Data: errData,
					})
				}
				continue
			}

			// Serialize and send snapshot data
			snapshotBytes, err := json.Marshal(snapshotData)
			if err != nil {
				log.Printf("Failed to marshal snapshot: %v", err)
				continue
			}

			if peer, ok := s.nodeManager.GetPeers()[originID]; ok && originID != "" {
				msg := &security.Message{
					Type: "snapshot",
					Data: snapshotBytes,
				}
				msg.Metadata = map[string]interface{}{
					"height":        uint64(height),
					"block_hash":    snapshotData.BlockHash,
					"account_count": len(snapshotData.Accounts),
				}
				transport.SendMessage(peer.Node.Address, msg)
				s.peerManager.UpdatePeerScore(originID, 10)
				log.Printf("📤 Sent snapshot at height %d to peer %s (%d accounts, %d validators)",
					uint64(height), originID, len(snapshotData.Accounts), len(snapshotData.Validators))
			}

		case "snapshot":
			// Received a state snapshot from a peer.
			var snapshotData core.StateSnapshotData
			if err := json.Unmarshal(msg.Data, &snapshotData); err != nil {
				log.Printf("Failed to unmarshal snapshot data: %v", err)
				continue
			}

			log.Printf("📥 Received snapshot from peer %s at height %d (%d accounts, %d validators)",
				originID, snapshotData.BlockHeight, len(snapshotData.Accounts), len(snapshotData.Validators))

			// Store the snapshot locally
			snapshotMgr := s.blockchain.GetSnapshotManager()
			if snapshotMgr == nil {
				log.Printf("No snapshot manager available — cannot store received snapshot")
				continue
			}

			// Write snapshot to disk
			if err := snapshotMgr.StoreReceivedSnapshot(&snapshotData); err != nil {
				log.Printf("Failed to store received snapshot: %v", err)
				continue
			}

			// Create checkpoint from snapshot metadata
			cp := &core.CheckpointMessage{
				BlockHeight: snapshotData.BlockHeight,
				BlockHash:   snapshotData.BlockHash,
				StateRoot:   snapshotData.StateRoot,
				Epoch:       snapshotData.BlockHeight / 100,
				Signatures:  make(map[string]string),
				Timestamp:   time.Now().Unix(),
			}
			snapshotMgr.AddCheckpointFromPeer(cp)

			if originID != "" {
				s.peerManager.UpdatePeerScore(originID, 15)
			}

		case "snapshot_error":
			// Peer could not serve the requested snapshot
			var errData map[string]interface{}
			if err := json.Unmarshal(msg.Data, &errData); err != nil {
				log.Printf("Failed to unmarshal snapshot_error: %v", err)
				continue
			}
			height, _ := errData["height"].(float64)
			errMsg, _ := errData["error"].(string)
			log.Printf("⚠️ Snapshot error from peer %s for height %d: %s", originID, uint64(height), errMsg)

		case "checkpoint_sync":
			// Peer is sharing checkpoint information for state sync discovery
			var cpMsg core.CheckpointMessage
			if err := json.Unmarshal(msg.Data, &cpMsg); err != nil {
				log.Printf("Failed to unmarshal checkpoint message: %v", err)
				continue
			}

			snapshotMgr := s.blockchain.GetSnapshotManager()
			if snapshotMgr != nil {
				if snapshotMgr.AddCheckpointFromPeer(&cpMsg) {
					log.Printf("📥 Stored checkpoint from peer %s at height %d", originID, cpMsg.BlockHeight)
				}
			}
			if originID != "" {
				s.peerManager.UpdatePeerScore(originID, 5)
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

// SendMessageToPeer sends a message to a specific peer by ID.
// This implements the P2PServerInterface required by the SyncManager.
// It looks up the peer by ID and sends the message via transport.
func (s *Server) SendMessageToPeer(peerID string, messageType string, data []byte) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	peer, exists := s.nodeManager.GetPeers()[peerID]
	if !exists {
		return fmt.Errorf("peer %s not found", peerID)
	}

	msg := &security.Message{
		Type: messageType,
		Data: data,
	}

	return transport.SendMessage(peer.Node.Address, msg)
}

// Broadcast sends a message to all peers.
// Simple wrapper around peer manager's propagation function
func (s *Server) Broadcast(msg *security.Message) {
	// Make a copy and ensure Data is marshaled properly
	msgCopy := &security.Message{
		Type: msg.Type,
		Data: msg.Data, // Already should be json.RawMessage
	}
	s.peerManager.PropagateMessage(msgCopy, s.localNode.ID)
}
