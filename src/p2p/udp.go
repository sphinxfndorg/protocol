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

// go/src/p2p/udp.go
package p2p

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/core/hashtree"
	sigproof "github.com/sphinxfndorg/protocol/src/core/proof"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	"github.com/sphinxfndorg/protocol/src/network"
	"golang.org/x/sys/unix"
)

// CheckPort checks if a UDP port is available.
// Attempts to bind to the port to verify it's not already in use.
func CheckPort(port string) error {
	// Attempt to listen on the UDP port
	ln, err := net.ListenUDP("udp", &net.UDPAddr{Port: parsePort(port), IP: net.ParseIP("0.0.0.0")})
	if err != nil {
		// Port is already in use
		return fmt.Errorf("port %s is in use: %v", port, err)
	}
	ln.Close() // Close immediately since we only wanted to check
	return nil
}

// StartUDPDiscovery starts the UDP server for peer discovery.
// This function attempts to bind to the specified UDP port with retry logic
// if the port is unavailable. It also sets up SO_REUSEADDR for socket reuse.
func (s *Server) StartUDPDiscovery(udpPort string) error {
	const maxRetries = 5 // Maximum number of port finding attempts

	// Parse the original port from string to int
	originalPort := parsePort(udpPort)
	currentPort := originalPort
	var lastErr error

	// Retry loop to find an available port
	for retry := 0; retry < maxRetries; retry++ {
		// Check if current port is available
		if err := CheckPort(strconv.Itoa(currentPort)); err != nil {
			log.Printf("StartUDPDiscovery: Port %d in use for node %s: %v", currentPort, s.localNode.Address, err)

			// Find next free port
			newPort, err := network.FindFreePort(currentPort+1, "udp")
			if err != nil {
				lastErr = fmt.Errorf("failed to find free UDP port after %s: %v", udpPort, err)
				time.Sleep(1 * time.Second) // Add delay to avoid rapid retries
				continue
			}
			currentPort = newPort
			continue
		}

		// Create UDP socket with SO_REUSEADDR to allow address reuse
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
		if err != nil {
			lastErr = fmt.Errorf("failed to create UDP socket: %v", err)
			continue
		}

		// Set SO_REUSEADDR option to allow binding to recently used ports
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			unix.Close(fd)
			lastErr = fmt.Errorf("failed to set SO_REUSEADDR: %v", err)
			continue
		}

		// Convert file descriptor to *os.File for use with net package
		file := os.NewFile(uintptr(fd), "")
		defer file.Close() // Ensure file is closed if ListenUDP fails

		// Create UDP connection from file descriptor
		udpConn, err := net.FileConn(file)
		if err != nil {
			unix.Close(fd)
			lastErr = fmt.Errorf("failed to create net.Conn: %v", err)
			continue
		}
		conn, ok := udpConn.(*net.UDPConn)
		if !ok {
			udpConn.Close()
			lastErr = fmt.Errorf("failed to cast to UDPConn")
			continue
		}

		// Bind the UDP connection to the address
		listener, err := net.ListenUDP("udp", &net.UDPAddr{Port: currentPort, IP: net.ParseIP("0.0.0.0")})
		if err != nil {
			conn.Close()
			lastErr = fmt.Errorf("failed to bind UDP port %d: %v", currentPort, err)
			continue
		}

		// Store the UDP connection and start handler goroutine
		s.udpConn = listener
		s.stopCh = make(chan struct{})
		go s.handleUDP() // Start UDP message handler

		log.Printf("UDP discovery started on :%d for node %s", currentPort, s.localNode.Address)

		// Signal that UDP is ready (if channel exists)
		if s.udpReadyCh != nil {
			s.udpReadyCh <- struct{}{}
		}

		// Update local node UDP port and global config if port changed
		if currentPort != originalPort {
			s.localNode.UDPPort = strconv.Itoa(currentPort)
			log.Printf("StartUDPDiscovery: Updated node %s UDP port to %d", s.localNode.Address, currentPort)

			// Update global configuration
			config, exists := network.GetNodeConfig(s.localNode.ID)
			if exists {
				config.UDPPort = strconv.Itoa(currentPort)
				network.UpdateNodeConfig(config)
			} else {
				log.Printf("StartUDPDiscovery: No configuration found for node ID %s", s.localNode.ID)
			}
		}
		return nil // Success
	}

	// All retries failed
	return fmt.Errorf("failed to start UDP discovery after %d retries: %v", maxRetries, lastErr)
}

// parsePort converts a string port to an integer.
// Returns 0 if parsing fails.
func parsePort(portStr string) int {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Printf("Invalid port %s: %v", portStr, err)
		return 0
	}
	return port
}

// StopUDPDiscovery closes the UDP connection.
// Gracefully shuts down the UDP server and releases the port.
func (s *Server) StopUDPDiscovery() error {
	if s.udpConn != nil {
		// Close stop channel to signal handler goroutine to exit
		select {
		case <-s.stopCh:
			// Channel already closed
		default:
			close(s.stopCh)
		}

		// Close the UDP connection
		if err := s.udpConn.Close(); err != nil {
			log.Printf("StopUDPDiscovery: Failed to close UDP connection for %s: %v", s.localNode.Address, err)
			return fmt.Errorf("failed to close UDP connection: %v", err)
		}
		s.udpConn = nil
		log.Printf("StopUDPDiscovery: UDP connection closed for %s", s.localNode.Address)
	}
	return nil
}

// handleUDP processes incoming UDP messages.
// This is the main UDP message loop that runs in a goroutine.
func (s *Server) handleUDP() {
	// Check if UDP connection exists
	if s.udpConn == nil {
		log.Printf("handleUDP: No UDP connection for %s", s.localNode.Address)
		return
	}

	// Create buffer for receiving messages (64KB max UDP size)
	buffer := make([]byte, 65535)

	for {
		select {
		case <-s.stopCh:
			// Stop signal received
			log.Printf("handleUDP: Stopping UDP handler for %s", s.localNode.Address)
			return
		default:
			// Read incoming UDP message
			n, addr, err := s.udpConn.ReadFromUDP(buffer)
			if err != nil {
				// Handle connection closed error
				if strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("handleUDP: UDP connection closed for %s", s.localNode.Address)
					return
				}
				log.Printf("handleUDP: Error reading UDP message for %s: %v", s.localNode.Address, err)
				continue
			}

			log.Printf("handleUDP: Received UDP message from %s for %s: %s",
				addr.String(), s.localNode.Address, string(buffer[:n]))

			// Parse discovery message from JSON
			var msg network.DiscoveryMessage
			if err := json.Unmarshal(buffer[:n], &msg); err != nil {
				log.Printf("handleUDP: Error decoding UDP message from %s for %s: %v",
					addr.String(), s.localNode.Address, err)
				continue
			}

			// Handle the message in a separate goroutine to avoid blocking
			go s.handleDiscoveryMessage(&msg, addr)
		}
	}
}

// handleDiscoveryMessage processes discovery messages (PING, PONG, FINDNODE, NEIGHBORS).
// This function handles the core Kademlia protocol messages with cryptographic verification.
func (s *Server) handleDiscoveryMessage(msg *network.DiscoveryMessage, addr *net.UDPAddr) {
	log.Printf("handleDiscoveryMessage: Received %s message from %s for node %s: Timestamp=%x, Nonce=%x",
		msg.Type, addr.String(), s.localNode.Address, msg.Timestamp, msg.Nonce[:8])

	// Log message size for debugging
	msgBytes, _ := json.Marshal(msg)
	log.Printf("handleDiscoveryMessage: Message size: %d bytes", len(msgBytes))
	if len(msgBytes) > 1472 {
		log.Printf("handleDiscoveryMessage: Warning: Message size (%d bytes) exceeds typical UDP MTU (1472 bytes)", len(msgBytes))
	}

	// Check timestamp freshness (5-minute window to prevent replay attacks)
	timestampInt := binary.BigEndian.Uint64(msg.Timestamp)
	currentTimestamp := uint64(time.Now().Unix())
	if currentTimestamp-timestampInt > 300 {
		log.Printf("handleDiscoveryMessage: Message %s from %s for %s has old timestamp (%d), possible replay",
			msg.Type, addr.String(), s.localNode.Address, currentTimestamp-timestampInt)
		return
	}

	// Check for signature reuse (prevent replay attacks)
	exists, err := s.sphincsMgr.CheckTimestampNonce(msg.Timestamp, msg.Nonce)
	if err != nil {
		log.Printf("handleDiscoveryMessage: Failed to check timestamp-nonce pair for %s from %s: %v",
			msg.Type, addr.String(), err)
		return
	}
	if exists {
		log.Printf("handleDiscoveryMessage: Signature reuse detected for %s message from %s for %s",
			msg.Type, addr.String(), s.localNode.Address)
		return
	}

	// Validate public key presence
	if len(msg.PublicKey) == 0 {
		log.Printf("handleDiscoveryMessage: Empty public key in %s message from %s for %s",
			msg.Type, addr.String(), s.localNode.Address)
		return
	}

	// Validate commitment presence (32 bytes required).
	// The commitment = H(sigBytes||pk||timestamp||nonce||message) proves that the
	// Merkle root was derived from a genuine SPHINCS+ signing operation.
	if len(msg.Commitment) != 32 {
		log.Printf("handleDiscoveryMessage: Missing or malformed commitment in %s message from %s for %s",
			msg.Type, addr.String(), s.localNode.Address)
		return
	}

	// Verify the cryptographic proof.
	// Regenerate the proof using the same leaves the sender used:
	//   leaves = [merkleRootHash, commitment]
	// This keeps GenerateSigProof at 3 arguments while binding the commitment
	// to the proof so it cannot be swapped out without proof verification failing.
	dataBytes := msg.Data
	proofData := append(msg.Timestamp, append(msg.Nonce, dataBytes...)...)
	proofLeaves := [][]byte{msg.MerkleRoot.Bytes(), msg.Commitment}
	regeneratedProof, err := sigproof.GenerateSigProof(
		[][]byte{proofData},
		proofLeaves,
		msg.PublicKey,
	)
	if err != nil {
		log.Printf("handleDiscoveryMessage: Failed to regenerate proof for %s message from %s for %s: %v",
			msg.Type, addr.String(), s.localNode.Address, err)
		return
	}

	// Verify the proof matches
	isValidProof := sigproof.VerifySigProof(msg.Proof, regeneratedProof)
	if !isValidProof {
		log.Printf("handleDiscoveryMessage: Invalid proof for %s message from %s for %s",
			msg.Type, addr.String(), s.localNode.Address)
		return
	}

	// Store message data in database
	if err := s.StoreDiscoveryMessage(msg); err != nil {
		log.Printf("handleDiscoveryMessage: Failed to store discovery message for %s from %s: %v",
			msg.Type, addr.String(), err)
	}

	// Store timestamp-nonce pair after successful verification
	err = s.sphincsMgr.StoreTimestampNonce(msg.Timestamp, msg.Nonce)
	if err != nil {
		log.Printf("handleDiscoveryMessage: Failed to store timestamp-nonce pair for %s from %s: %v",
			msg.Type, addr.String(), err)
		return
	}

	// Helper function to get TCP address from UDP port
	getTCPAddress := func(udpPort string) (string, string) {
		network.NodeConfigsLock.RLock()
		defer network.NodeConfigsLock.RUnlock()

		// Normalize udpPort (strip IP if present)
		udpParts := strings.Split(udpPort, ":")
		udpPortNorm := udpParts[len(udpParts)-1]

		// Look for matching configuration
		for _, cfg := range network.NodeConfigs {
			cfgParts := strings.Split(cfg.UDPPort, ":")
			cfgUDPPortNorm := cfgParts[len(cfgParts)-1]

			if cfgUDPPortNorm == udpPortNorm && cfg.ID != s.localNode.ID { // Avoid self-mapping
				if cfg.TCPAddr != "" {
					parts := strings.Split(cfg.TCPAddr, ":")
					if len(parts) == 2 {
						log.Printf("handleDiscoveryMessage: Found TCP address %s for UDP port %s", cfg.TCPAddr, udpPort)
						return cfg.TCPAddr, parts[1]
					}
				}
			}
		}
		log.Printf("handleDiscoveryMessage: No TCP address found for UDP port %s", udpPort)
		return "", ""
	}

	// Process different message types
	switch msg.Type {
	case "FINDNODE":
		// Handle FINDNODE request - return closest nodes to target
		var findNodeData network.FindNodeData
		if err := json.Unmarshal(msg.Data, &findNodeData); err != nil {
			log.Printf("handleDiscoveryMessage: Invalid FINDNODE data from %s for %s: %v",
				addr.String(), s.localNode.Address, err)
			return
		}
		log.Printf("handleDiscoveryMessage: Received FINDNODE from %s for target %x",
			addr.String(), findNodeData.TargetID[:8])

		// Send NEIGHBORS response with closest nodes
		s.sendUDPNeighbors(addr, findNodeData.TargetID, msg.Nonce)
		log.Printf("handleDiscoveryMessage: Sent NEIGHBORS in response to FINDNODE from %s", addr.String())

	case "PING":
		// Handle PING request - verify liveness
		var pingData network.PingData
		if err := json.Unmarshal(msg.Data, &pingData); err != nil {
			log.Printf("handleDiscoveryMessage: Invalid PING data from %s for %s: %v",
				addr.String(), s.localNode.Address, err)
			return
		}

		// Get TCP address for this node
		tcpAddr, tcpPort := getTCPAddress(fmt.Sprintf("%d", addr.Port))
		if tcpAddr == "" {
			log.Printf("handleDiscoveryMessage: No TCP address found for PING from %s, skipping", addr.String())
			return
		}

		// Skip self-pings
		if tcpAddr == s.localNode.Address {
			log.Printf("handleDiscoveryMessage: Skipping PING from self (%s) for %s", addr.String(), s.localNode.Address)
			return
		}

		// Find or create node
		node := s.nodeManager.GetNodeByKademliaID(pingData.FromID)
		if node == nil {
			// Create new node
			// FIX: Add database parameter (use nil since we don't have database access here)
			node = network.NewNode(tcpAddr, addr.IP.String(), tcpPort, fmt.Sprintf("%d", addr.Port), false, network.RoleNone, nil)
			node.KademliaID = pingData.FromID
			node.PublicKey = msg.PublicKey
			s.nodeManager.AddNode(node)
			log.Printf("handleDiscoveryMessage: Added node: ID=%s, Address=%s, Role=%s, KademliaID=%x",
				node.ID, node.Address, node.Role, node.KademliaID[:8])
		} else {
			// Update existing node
			node.Address = tcpAddr
			node.Port = tcpPort
			node.IP = addr.IP.String()
			node.UDPPort = fmt.Sprintf("%d", addr.Port)
			node.PublicKey = msg.PublicKey
			s.nodeManager.UpdateNode(node)
			log.Printf("handleDiscoveryMessage: Updated node: ID=%s, Address=%s, Role=%s, KademliaID=%x",
				node.ID, node.Address, node.Role, node.KademliaID[:8])
		}

		// Send PONG response
		s.sendUDPPong(addr, pingData.FromID, msg.Nonce)
		log.Printf("handleDiscoveryMessage: Sent PONG to %s for PING from %s", addr.String(), s.localNode.Address)

	case "PONG":
		// Handle PONG response - update node information
		var pongData network.PongData
		if err := json.Unmarshal(msg.Data, &pongData); err != nil {
			log.Printf("handleDiscoveryMessage: Invalid PONG data from %s for %s: %v",
				addr.String(), s.localNode.Address, err)
			return
		}
		log.Printf("handleDiscoveryMessage: Received PONG from %s (KademliaID: %x) for %s",
			addr.String(), pongData.FromID[:8], s.localNode.Address)

		// Get TCP address
		tcpAddr, tcpPort := getTCPAddress(fmt.Sprintf("%d", addr.Port))
		if tcpAddr == "" {
			log.Printf("handleDiscoveryMessage: No TCP address found for PONG from %s, skipping", addr.String())
			return
		}

		// Skip self-pongs
		if tcpAddr == s.localNode.Address {
			log.Printf("handleDiscoveryMessage: Skipping PONG from self (%s) for %s", addr.String(), s.localNode.Address)
			return
		}

		// Find or create node
		node := s.nodeManager.GetNodeByKademliaID(pongData.FromID)
		if node == nil {
			// Create new node
			// FIX: Add database parameter (use nil since we don't have database access here)
			node = network.NewNode(tcpAddr, addr.IP.String(), tcpPort, fmt.Sprintf("%d", addr.Port), false, network.RoleNone, nil)
			node.KademliaID = pongData.FromID
			node.PublicKey = msg.PublicKey
			s.nodeManager.AddNode(node)
			log.Printf("handleDiscoveryMessage: Added node: ID=%s, Address=%s, Role=%s, KademliaID=%x",
				node.ID, node.Address, node.Role, node.KademliaID[:8])
		} else {
			// Update existing node
			node.Address = tcpAddr
			node.Port = tcpPort
			node.IP = addr.IP.String()
			node.UDPPort = fmt.Sprintf("%d", addr.Port)
			node.PublicKey = msg.PublicKey
			log.Printf("handleDiscoveryMessage: Updated node: ID=%s, Address=%s, Role=%s, KademliaID=%x",
				node.ID, node.Address, node.Role, node.KademliaID[:8])
		}

		// Mark node as active and create peer
		node.UpdateStatus(network.NodeStatusActive)
		peer := network.NewPeer(node)
		peer.ReceivePong()

		// Add to node manager
		if err := s.nodeManager.AddPeer(node); err != nil {
			log.Printf("handleDiscoveryMessage: Failed to add peer %s to nodeManager.peers for %s: %v",
				node.ID, s.localNode.Address, err)
		} else {
			log.Printf("handleDiscoveryMessage: Added peer %s to nodeManager.peers for %s", node.ID, s.localNode.Address)
		}

		// Connect via TCP
		if node.Address != s.localNode.Address {
			if err := s.peerManager.ConnectPeer(node); err != nil {
				log.Printf("handleDiscoveryMessage: Failed to connect to peer %s via TCP for %s: %v",
					node.ID, s.localNode.Address, err)
			} else {
				log.Printf("handleDiscoveryMessage: Successfully connected to peer %s via ConnectPeer for %s",
					node.ID, s.localNode.Address)
			}
		}

		// Send to response channel for discovery
		log.Printf("handleDiscoveryMessage: Sending peer %s to ResponseCh for %s (ChannelLen=%d)",
			node.ID, s.localNode.Address, len(s.nodeManager.ResponseCh))
		s.nodeManager.ResponseCh <- []*network.Peer{peer}
		log.Printf("handleDiscoveryMessage: Sent peer %s to ResponseCh for %s (ChannelLen=%d)",
			node.ID, s.localNode.Address, len(s.nodeManager.ResponseCh))

	case "NEIGHBORS":
		// Handle NEIGHBORS response - process list of nearby nodes
		var neighborsData network.NeighborsData
		if err := json.Unmarshal(msg.Data, &neighborsData); err != nil {
			log.Printf("handleDiscoveryMessage: Invalid NEIGHBORS data from %s for %s: %v",
				addr.String(), s.localNode.Address, err)
			return
		}
		log.Printf("handleDiscoveryMessage: Received NEIGHBORS from %s with %d peers for %s",
			addr.String(), len(neighborsData.Nodes), s.localNode.Address)

		// Process each node in the neighbors list
		peers := make([]*network.Peer, 0, len(neighborsData.Nodes))
		for _, nodeInfo := range neighborsData.Nodes {
			// Create node from neighbor info
			// FIX: Add database parameter (use nil since we don't have database access here)
			node := network.NewNode(
				nodeInfo.Address,
				nodeInfo.IP,
				nodeInfo.Port,
				nodeInfo.UDPPort,
				false,
				nodeInfo.Role,
				nil,
			)
			node.KademliaID = nodeInfo.KademliaID
			node.PublicKey = nodeInfo.PublicKey
			node.UpdateStatus(nodeInfo.Status)

			// Add to node manager
			s.nodeManager.AddNode(node)
			log.Printf("handleDiscoveryMessage: Added node from NEIGHBORS: ID=%s, Address=%s, Role=%s, KademliaID=%x",
				node.ID, node.Address, node.Role, node.KademliaID[:8])

			peers = append(peers, network.NewPeer(node))
		}

		// Send discovered peers to response channel
		log.Printf("handleDiscoveryMessage: Sending %d peers to ResponseCh for %s (ChannelLen=%d)",
			len(peers), s.localNode.Address, len(s.nodeManager.ResponseCh))
		s.nodeManager.ResponseCh <- peers
		log.Printf("handleDiscoveryMessage: Sent %d peers to ResponseCh for %s (ChannelLen=%d)",
			len(peers), s.localNode.Address, len(s.nodeManager.ResponseCh))
	}
}

// sendUDPPing sends a PING message to a node.
// Used for liveness checks and initial discovery.
func (s *Server) sendUDPPing(addr *net.UDPAddr, toID network.NodeID, nonce []byte) {
	// Initialize key manager for signing
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("sendUDPPing: Failed to initialize KeyManager for %s: %v", s.localNode.Address, err)
		return
	}

	log.Printf("sendUDPPing: Deserializing keys for node %s: PrivateKey length=%d, PublicKey length=%d",
		s.localNode.Address, len(s.localNode.PrivateKey), len(s.localNode.PublicKey))

	// Deserialize key pair.
	// FIX: capture publicKey so it can be passed to SignMessage.
	privateKey, publicKey, err := km.DeserializeKeyPair(s.localNode.PrivateKey, s.localNode.PublicKey)
	if err != nil {
		log.Printf("sendUDPPing: Failed to deserialize key pair for %s: %v", s.localNode.Address, err)
		return
	}

	// Prepare ping data
	data := network.PingData{
		FromID:    s.localNode.KademliaID,
		ToID:      toID,
		Timestamp: time.Now(),
		Nonce:     nonce,
	}

	// Marshal data to JSON
	dataBytes, err := json.Marshal(data)
	if err != nil {
		log.Printf("sendUDPPing: Failed to marshal PING data for %s to %s: %v",
			s.localNode.Address, addr.String(), err)
		return
	}

	log.Printf("sendUDPPing: PING data for %s to %s: %s", s.localNode.Address, addr.String(), string(dataBytes))

	// Sign the message.
	// FIX: pass publicKey as third arg; capture all 6 return values including commitment.
	signature, merkleRootNode, sigTimestamp, sigNonce, commitment, err := s.sphincsMgr.SignMessage(dataBytes, privateKey, publicKey)
	if err != nil {
		log.Printf("sendUDPPing: Failed to sign PING message for %s to %s: %v",
			s.localNode.Address, addr.String(), err)
		return
	}

	// Serialize signature
	signatureBytes, err := signature.SerializeSignature()
	if err != nil {
		log.Printf("sendUDPPing: Failed to serialize signature for %s to %s: %v",
			s.localNode.Address, addr.String(), err)
		return
	}

	// Store signature in database
	err = hashtree.SaveLeavesToDB(s.db, [][]byte{dataBytes, signatureBytes})
	if err != nil {
		log.Printf("sendUDPPing: Failed to store signature for %s to %s: %v",
			s.localNode.Address, addr.String(), err)
		return
	}

	// Generate cryptographic proof.
	// FIX: fold commitment into proof leaves so GenerateSigProof stays at 3 args.
	// Receiver regenerates with the same leaves = [merkleRootHash, commitment].
	proofData := append(sigTimestamp, append(sigNonce, dataBytes...)...)
	proofLeaves := [][]byte{merkleRootNode.Hash.Bytes(), commitment}
	proof, err := sigproof.GenerateSigProof(
		[][]byte{proofData},
		proofLeaves,
		s.localNode.PublicKey,
	)
	if err != nil {
		log.Printf("sendUDPPing: Failed to generate proof for PING for %s to %s: %v",
			s.localNode.Address, addr.String(), err)
		return
	}

	// Create and send discovery message.
	// Nonce and Timestamp use the values from SignMessage (bound inside commitment)
	// so the receiver can verify them consistently.
	msg := network.DiscoveryMessage{
		Type:       "PING",
		Data:       dataBytes,
		PublicKey:  s.localNode.PublicKey,
		MerkleRoot: merkleRootNode.Hash, // Use *uint256.Int directly
		Proof:      proof,
		Nonce:      sigNonce,     // use nonce from SignMessage (bound inside commitment)
		Timestamp:  sigTimestamp, // use timestamp from SignMessage (bound inside commitment)
		Commitment: commitment,   // 32-byte commitment transmitted to receiver
	}

	log.Printf("sendUDPPing: Sending PING message from %s to %s: Type=%s, Nonce=%x, Timestamp=%x",
		s.localNode.Address, addr.String(), msg.Type, msg.Nonce[:8], msg.Timestamp)

	s.sendUDPMessage(addr, msg)
	log.Printf("sendUDPPing: Sent PING to %s (KademliaID: %x) from %s",
		addr.String(), toID[:8], s.localNode.Address)
}

// sendUDPPong sends a PONG message in response to a PING.
// Confirms liveness and provides node information.
func (s *Server) sendUDPPong(addr *net.UDPAddr, toID network.NodeID, nonce []byte) {
	// Initialize key manager for signing
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("sendUDPPong: Failed to initialize KeyManager for %s: %v", s.localNode.Address, err)
		return
	}

	log.Printf("sendUDPPong: Deserializing keys for node %s: PrivateKey length=%d, PublicKey length=%d",
		s.localNode.Address, len(s.localNode.PrivateKey), len(s.localNode.PublicKey))

	// Deserialize key pair.
	// FIX: capture publicKey so it can be passed to SignMessage.
	privateKey, publicKey, err := km.DeserializeKeyPair(s.localNode.PrivateKey, s.localNode.PublicKey)
	if err != nil {
		log.Printf("sendUDPPong: Failed to deserialize key pair for %s: %v", s.localNode.Address, err)
		return
	}

	// Prepare pong data
	data := network.PongData{
		FromID:    s.localNode.KademliaID,
		ToID:      toID,
		Timestamp: time.Now(),
		Nonce:     nonce,
	}

	// Marshal data to JSON
	dataBytes, err := json.Marshal(data)
	if err != nil {
		log.Printf("sendUDPPong: Failed to marshal PONG data for %s to %s: %v",
			s.localNode.Address, addr.String(), err)
		return
	}

	log.Printf("sendUDPPong: PONG data for %s to %s: %s", s.localNode.Address, addr.String(), string(dataBytes))

	// Sign the message.
	// FIX: pass publicKey as third arg; capture all 6 return values including commitment.
	signature, merkleRootNode, sigTimestamp, sigNonce, commitment, err := s.sphincsMgr.SignMessage(dataBytes, privateKey, publicKey)
	if err != nil {
		log.Printf("sendUDPPong: Failed to sign PONG message for %s to %s: %v",
			s.localNode.Address, addr.String(), err)
		return
	}

	// Serialize signature
	signatureBytes, err := signature.SerializeSignature()
	if err != nil {
		log.Printf("sendUDPPong: Failed to serialize signature for %s to %s: %v",
			s.localNode.Address, addr.String(), err)
		return
	}

	// Store signature in database
	err = hashtree.SaveLeavesToDB(s.db, [][]byte{dataBytes, signatureBytes})
	if err != nil {
		log.Printf("sendUDPPong: Failed to store signature for %s to %s: %v",
			s.localNode.Address, addr.String(), err)
		return
	}

	// Generate cryptographic proof.
	// FIX: fold commitment into proof leaves.
	proofData := append(sigTimestamp, append(sigNonce, dataBytes...)...)
	proofLeaves := [][]byte{merkleRootNode.Hash.Bytes(), commitment}
	proof, err := sigproof.GenerateSigProof(
		[][]byte{proofData},
		proofLeaves,
		s.localNode.PublicKey,
	)
	if err != nil {
		log.Printf("sendUDPPong: Failed to generate proof for PONG for %s to %s: %v",
			s.localNode.Address, addr.String(), err)
		return
	}

	// Create and send discovery message
	msg := network.DiscoveryMessage{
		Type:       "PONG",
		Data:       dataBytes,
		PublicKey:  s.localNode.PublicKey,
		MerkleRoot: merkleRootNode.Hash,
		Proof:      proof,
		Nonce:      sigNonce,
		Timestamp:  sigTimestamp,
		Commitment: commitment,
	}

	s.sendUDPMessage(addr, msg)
	log.Printf("sendUDPPong: Sent PONG to %s (KademliaID: %x) from %s",
		addr.String(), toID[:8], s.localNode.Address)
}

// sendUDPNeighbors sends a NEIGHBORS message with closest peers.
// Responds to FINDNODE requests with the k-closest nodes to the target.
func (s *Server) sendUDPNeighbors(addr *net.UDPAddr, targetID network.NodeID, nonce []byte) {
	// Check cache first for efficiency
	s.cacheMutex.RLock()
	cachedNeighbors, cacheValid := s.neighborsCache[targetID]
	cacheFresh := time.Since(s.neighborsCacheTime) < 30*time.Second
	s.cacheMutex.RUnlock()

	var neighbors []network.PeerInfo
	if cacheValid && cacheFresh {
		// Use cached neighbors
		neighbors = cachedNeighbors
		log.Printf("sendUDPNeighbors: Using cached neighbors for target %x", targetID[:8])
	} else {
		// Find closest peers from node manager
		peers := s.nodeManager.FindClosestPeers(targetID, s.nodeManager.K)
		neighbors = make([]network.PeerInfo, 0, len(peers))
		for _, peer := range peers {
			neighbors = append(neighbors, peer.GetPeerInfo())
		}

		// Update cache
		s.cacheMutex.Lock()
		if s.neighborsCache == nil {
			s.neighborsCache = make(map[network.NodeID][]network.PeerInfo)
		}
		s.neighborsCache[targetID] = neighbors
		s.neighborsCacheTime = time.Now()
		s.cacheMutex.Unlock()
	}

	// Check if we found any neighbors
	if len(neighbors) == 0 {
		log.Printf("sendUDPNeighbors: No neighbors found for target %x", targetID[:8])
		return
	}

	// Initialize key manager for signing
	km, err := key.NewKeyManager()
	if err != nil {
		log.Printf("sendUDPNeighbors: Failed to initialize KeyManager: %v", err)
		return
	}

	log.Printf("sendUDPNeighbors: Deserializing keys for node %s: PrivateKey length=%d, PublicKey length=%d",
		s.localNode.Address, len(s.localNode.PrivateKey), len(s.localNode.PublicKey))

	// Deserialize key pair.
	// FIX: capture publicKey so it can be passed to SignMessage.
	privateKey, publicKey, err := km.DeserializeKeyPair(s.localNode.PrivateKey, s.localNode.PublicKey)
	if err != nil {
		log.Printf("sendUDPNeighbors: Failed to deserialize key pair: %v", err)
		return
	}

	// Refresh neighbor list (cache may have been stale).
	// Find closest peers (again, in case cache wasn't used)
	peers := s.nodeManager.FindClosestPeers(targetID, s.nodeManager.K)
	neighbors = make([]network.PeerInfo, 0, len(peers))
	for _, peer := range peers {
		neighbors = append(neighbors, peer.GetPeerInfo())
	}

	// Prepare neighbors data
	data := network.NeighborsData{
		Nodes:     neighbors,
		Timestamp: time.Now(),
		Nonce:     nonce,
	}

	// Marshal data to JSON
	dataBytes, err := json.Marshal(data)
	if err != nil {
		log.Printf("sendUDPNeighbors: Failed to marshal NEIGHBORS data: %v", err)
		return
	}

	// Sign the message.
	// FIX: pass publicKey as third arg; capture all 6 return values including commitment.
	signature, merkleRootNode, sigTimestamp, sigNonce, commitment, err := s.sphincsMgr.SignMessage(dataBytes, privateKey, publicKey)
	if err != nil {
		log.Printf("sendUDPNeighbors: Failed to sign NEIGHBORS message: %v", err)
		return
	}

	// Serialize signature
	signatureBytes, err := signature.SerializeSignature()
	if err != nil {
		log.Printf("sendUDPNeighbors: Failed to serialize signature: %v", err)
		return
	}

	// Store signature in database
	err = hashtree.SaveLeavesToDB(s.db, [][]byte{dataBytes, signatureBytes})
	if err != nil {
		log.Printf("sendUDPNeighbors: Failed to store signature: %v", err)
		return
	}

	// Generate cryptographic proof.
	// FIX: fold commitment into proof leaves.
	proofData := append(sigTimestamp, append(sigNonce, dataBytes...)...)
	proofLeaves := [][]byte{merkleRootNode.Hash.Bytes(), commitment}
	proof, err := sigproof.GenerateSigProof(
		[][]byte{proofData},
		proofLeaves,
		s.localNode.PublicKey,
	)
	if err != nil {
		log.Printf("sendUDPNeighbors: Failed to generate proof for NEIGHBORS: %v", err)
		return
	}

	// Create and send discovery message
	msg := network.DiscoveryMessage{
		Type:       "NEIGHBORS",
		Data:       dataBytes,
		PublicKey:  s.localNode.PublicKey,
		MerkleRoot: merkleRootNode.Hash, // Use *uint256.Int directly
		Proof:      proof,
		Nonce:      sigNonce,
		Timestamp:  sigTimestamp,
		Commitment: commitment,
	}

	s.sendUDPMessage(addr, msg)
	log.Printf("sendUDPNeighbors: Sent NEIGHBORS to %s with %d peers", addr.String(), len(neighbors))
}

// sendUDPMessage sends a discovery message over UDP.
// Handles the low-level UDP transmission of discovery messages.
func (s *Server) sendUDPMessage(addr *net.UDPAddr, msg network.DiscoveryMessage) {
	// Marshal message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("sendUDPMessage: Failed to marshal message for %s to %s: %v",
			s.localNode.Address, addr.String(), err)
		return
	}

	log.Printf("sendUDPMessage: Sending message from %s to %s: %s",
		s.localNode.Address, addr.String(), string(data))

	// Log message size for MTU considerations
	log.Printf("sendUDPMessage: Message size: %d bytes", len(data))
	if len(data) > 1472 {
		log.Printf("sendUDPMessage: Warning: Message size (%d bytes) exceeds typical UDP MTU (1472 bytes)", len(data))
	}

	// Write to UDP socket
	_, err = s.udpConn.WriteToUDP(data, addr)
	if err != nil {
		log.Printf("sendUDPMessage: Failed to send message from %s to %s: %v",
			s.localNode.Address, addr.String(), err)
		return
	}

	log.Printf("sendUDPMessage: Successfully sent message from %s to %s",
		s.localNode.Address, addr.String())
}

// StoreDiscoveryMessage stores discovery message leaves in the database.
// Persists discovery messages for auditing and replay protection.
func (s *Server) StoreDiscoveryMessage(msg *network.DiscoveryMessage) error {
	// Save message data to hashtree database
	return hashtree.SaveLeavesToDB(s.db, [][]byte{msg.Data})
}
