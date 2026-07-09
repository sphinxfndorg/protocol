// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/network/node.go
package network

import (
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/consensus"
	database "github.com/sphinxfndorg/protocol/src/core/state"
)

// Chain identification constants
const (
	SphinxChainID       = 7331
	SphinxChainName     = "Sphinx"
	SphinxSymbol        = "SPX"
	SphinxBIP44CoinType = 7331
	SphinxMagicNumber   = 0x53504858
	SphinxDefaultPort   = 32307
)

func (n *Node) GetChainInfo() map[string]interface{} {
	return map[string]interface{}{
		"chain_id":        SphinxChainID,
		"chain_name":      SphinxChainName,
		"symbol":          SphinxSymbol,
		"bip44_coin_type": SphinxBIP44CoinType,
		"magic_number":    SphinxMagicNumber,
		"default_port":    SphinxDefaultPort,
		"node_id":         n.ID,
		"node_role":       n.Role,
	}
}

func (n *Node) GenerateChainHandshake() string {
	chainInfo := n.GetChainInfo()
	return fmt.Sprintf(
		"SPHINX_HANDSHAKE\nChain: %s\nChain ID: %d\nNode: %s\nRole: %s\nProtocol: 1.0.0\nTimestamp: %d",
		chainInfo["chain_name"],
		chainInfo["chain_id"],
		n.ID,
		n.Role,
		time.Now().Unix(),
	)
}

// Global consensus registry
var (
	consensusRegistry = make(map[string]*consensus.Consensus)
	registryMu        sync.RWMutex
)

type CallPeer struct{ id string }

func (p *CallPeer) GetNode() consensus.Node {
	return &CallNode{id: p.id}
}

type CallNode struct{ id string }

func (n *CallNode) GetID() string                   { return n.id }
func (n *CallNode) GetRole() consensus.NodeRole     { return consensus.RoleValidator }
func (n *CallNode) GetStatus() consensus.NodeStatus { return consensus.NodeStatusActive }

type CallNodeManager struct {
	peers map[string]consensus.Peer
	mu    sync.Mutex
}

func NewCallNodeManager() *CallNodeManager {
	return &CallNodeManager{peers: make(map[string]consensus.Peer)}
}

func (m *CallNodeManager) GetPeers() map[string]consensus.Peer {
	m.mu.Lock()
	defer m.mu.Unlock()
	peers := make(map[string]consensus.Peer)
	for id, peer := range m.peers {
		peers[id] = peer
	}
	return peers
}

func (m *CallNodeManager) GetPeerIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.peers))
	for id := range m.peers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (m *CallNodeManager) GetNode(nodeID string) consensus.Node {
	return &CallNode{id: nodeID}
}

func (m *CallNodeManager) BroadcastMessage(messageType string, data interface{}) error {
	registryMu.RLock()
	defer registryMu.RUnlock()

	log.Printf("[CALL] Broadcasting %s message to %d peers", messageType, len(consensusRegistry))

	var wg sync.WaitGroup
	deliveredCount := 0

	for nodeID, cons := range consensusRegistry {
		wg.Add(1)
		go func(c *consensus.Consensus, typ string, d interface{}, nid string) {
			defer wg.Done()
			var err error
			switch typ {
			case "proposal":
				prop, ok := d.(*consensus.Proposal)
				if !ok {
					log.Printf("[CALL] Invalid proposal type: %T", d)
					return
				}
				err = c.HandleProposal(prop)
			case "prepare":
				vote, ok := d.(*consensus.Vote)
				if !ok {
					log.Printf("[CALL] Invalid prepare vote type: %T", d)
					return
				}
				err = c.HandlePrepareVote(vote)
			case "vote":
				vote, ok := d.(*consensus.Vote)
				if !ok {
					log.Printf("[CALL] Invalid commit vote type: %T", d)
					return
				}
				err = c.HandleVote(vote)
			case "timeout":
				timeout, ok := d.(*consensus.TimeoutMsg)
				if !ok {
					log.Printf("[CALL] Invalid timeout type: %T", d)
					return
				}
				err = c.HandleTimeout(timeout)
			default:
				log.Printf("[CALL] Unknown message type: %s", typ)
				return
			}
			if err != nil {
				log.Printf("[CALL] Failed to deliver %s to %s: %v", typ, nid, err)
			} else {
				log.Printf("[CALL] Successfully delivered %s to %s", typ, nid)
				deliveredCount++
			}
		}(cons, messageType, data, nodeID)
	}

	wg.Wait()
	log.Printf("[CALL] Broadcast completed: %d/%d successful deliveries for %s",
		deliveredCount, len(consensusRegistry), messageType)
	return nil
}

func (m *CallNodeManager) AddPeer(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.peers[id]; exists {
		log.Printf("[CALL] Peer %s already exists, skipping duplicate", id)
		return
	}
	m.peers[id] = &CallPeer{id: id}
	log.Printf("[CALL] Added peer: %s (total peers: %d)", id, len(m.peers))
}

func (m *CallNodeManager) RemovePeer(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.peers, id)
	log.Printf("[CALL] Removed peer: %s", id)
}

func RegisterConsensus(nodeID string, cons *consensus.Consensus) {
	registryMu.Lock()
	defer registryMu.Unlock()
	consensusRegistry[nodeID] = cons
	log.Printf("Registered consensus for node %s", nodeID)
}

func UnregisterConsensus(nodeID string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	delete(consensusRegistry, nodeID)
	log.Printf("Unregistered consensus for node %s", nodeID)
}

func GetConsensusRegistry() map[string]*consensus.Consensus {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return consensusRegistry
}

// NewNode creates a new node with real SPHINCS+ keys.
// All key generation and persistence is handled by NetworkKeyManager in manager.go.
// No key logic lives here.
//
// IMPORTANT: Filesystem writes (keys, node-info) are performed ONLY for LOCAL nodes
// (isLocal=true). PEER nodes (isLocal=false) do NOT need their own key material stored
// in this node's data directory — they exchange real keys over the wire via the
// key-exchange handshake. Skipping filesystem writes for peers prevents each node
// from creating directory trees for every other node it discovers.
func NewNode(address, ip, port, udpPort string, isLocal bool, role NodeRole, db *database.DB) *Node {
	nodeID := fmt.Sprintf("Node-%s", address)

	var privateKey, publicKey []byte

	if isLocal {
		// NetworkKeyManager is the single source of truth for all key operations.
		// Only invoked for LOCAL nodes — peers get their keys via key exchange.
		nkm, err := NewNetworkKeyManager(db)
		if err != nil {
			log.Printf("NewNode: Failed to create NetworkKeyManager for %s: %v", nodeID, err)
			return nil
		}

		// GetOrCreateKeys handles: config file → DB → generate fresh SPHINCS+ keys
		privateKey, publicKey, err = nkm.GetOrCreateKeys(address)
		if err != nil {
			log.Printf("NewNode: Failed to get/create SPHINCS+ keys for %s: %v", nodeID, err)
			return nil
		}

		// Write node metadata (non-critical, log and continue on failure).
		// Only for local nodes — peer metadata is transient.
		nodeInfo := map[string]interface{}{
			"id":          nodeID,
			"address":     address,
			"ip":          ip,
			"port":        port,
			"udp_port":    udpPort,
			"kademlia_id": GenerateKademliaID(address),
			"role":        string(role),
			"is_local":    isLocal,
			"created_at":  time.Now().Format(time.RFC3339),
		}
		if err := common.WriteNodeInfo(address, nodeInfo); err != nil {
			log.Printf("NewNode: Failed to write node info for %s: %v", nodeID, err)
		}
	} else {
		log.Printf("NewNode: Skipping key generation for peer node %s — keys will be received via key exchange", nodeID)
	}

	return &Node{
		ID:         nodeID,
		Address:    address,
		IP:         ip,
		Port:       port,
		UDPPort:    udpPort,
		KademliaID: GenerateKademliaID(address),
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		IsLocal:    isLocal,
		Role:       role,
		Status:     NodeStatusActive,
		db:         db,
	}
}

// GenerateNodeID creates a node ID from the node's public key
func (n *Node) GenerateNodeID() NodeID {
	return GenerateKademliaID(string(n.PublicKey))
}

func (n *Node) UpdateStatus(status NodeStatus) {
	n.Status = status
	n.LastSeen = time.Now()
	log.Printf("Node %s (Role=%s) status updated to %s", n.ID, n.Role, status)
}

func (n *Node) UpdateRole(role NodeRole) {
	n.Role = role
	log.Printf("Node %s updated role to %s", n.ID, role)
}

func NewPeer(node *Node) *Peer {
	return &Peer{
		Node:             node,
		ConnectionStatus: "disconnected",
		ConnectedAt:      time.Time{},
		LastPing:         time.Time{},
		LastPong:         time.Time{},
	}
}

func (p *Peer) ConnectPeer() error {
	if p.Node.Status != NodeStatusActive {
		return fmt.Errorf("cannot connect to node %s: status is %s", p.Node.ID, p.Node.Status)
	}
	p.ConnectionStatus = "connected"
	p.ConnectedAt = time.Now()
	log.Printf("Peer %s (Role=%s) connected at %s", p.Node.ID, p.Node.Role, p.ConnectedAt)
	return nil
}

func (p *Peer) DisconnectPeer() {
	p.ConnectionStatus = "disconnected"
	p.ConnectedAt = time.Time{}
	p.LastPing = time.Time{}
	p.LastPong = time.Time{}
	log.Printf("Peer %s (Role=%s) disconnected", p.Node.ID, p.Node.Role)
}

func (p *Peer) SendPing() {
	p.LastPing = time.Now()
	log.Printf("Sent PING to peer %s (Role=%s)", p.Node.ID, p.Node.Role)
}

func (p *Peer) ReceivePong() {
	p.LastPong = time.Now()
	log.Printf("Received PONG from peer %s (Role=%s)", p.Node.ID, p.Node.Role)
}

func (p *Peer) GetPeerInfo() PeerInfo {
	return PeerInfo{
		NodeID:          p.Node.ID,
		KademliaID:      p.Node.KademliaID,
		Address:         p.Node.Address,
		IP:              p.Node.IP,
		Port:            p.Node.Port,
		UDPPort:         p.Node.UDPPort,
		Status:          p.Node.Status,
		Role:            p.Node.Role,
		Timestamp:       time.Now(),
		ProtocolVersion: "1.0",
		PublicKey:       p.Node.PublicKey,
	}
}

func (m *CallNodeManager) BroadcastRANDAOState(mix [32]byte, submissions map[uint64]map[string]*consensus.VDFSubmission) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Printf("[CALL] Broadcasting RANDAO state to %d peers", len(consensusRegistry))

	var wg sync.WaitGroup
	deliveredCount := 0

	for nodeID, cons := range consensusRegistry {
		wg.Add(1)
		go func(c *consensus.Consensus, nid string, mx [32]byte, subs map[uint64]map[string]*consensus.VDFSubmission) {
			defer wg.Done()
			if err := c.HandleRANDAOSync(mx, subs); err != nil {
				log.Printf("[CALL] Failed to sync RANDAO state to %s: %v", nid, err)
			} else {
				deliveredCount++
				log.Printf("[CALL] Successfully synced RANDAO state to %s", nid)
			}
		}(cons, nodeID, mix, submissions)
	}

	wg.Wait()
	log.Printf("[CALL] RANDAO state broadcast completed: %d/%d successful deliveries",
		deliveredCount, len(consensusRegistry))
	return nil
}
