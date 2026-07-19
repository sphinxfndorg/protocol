// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/transport/ip.go
package transport

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	security "github.com/sphinxfndorg/protocol/src/handshake"
	"github.com/sphinxfndorg/protocol/src/network"
)

// ValidateIP checks whether the provided IP and port are valid.
func ValidateIP(ip, port string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip) // Validate the IP address format
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return fmt.Errorf("invalid port: %s", port) // Validate the TCP port
	}
	return nil // Return nil if both IP and port are valid
}

// ResolveAddress constructs a full address string from a validated IP and port.
func ResolveAddress(ip, port string) (string, error) {
	if err := ValidateIP(ip, port); err != nil {
		return "", err // Return an error if validation fails
	}
	return fmt.Sprintf("%s:%s", ip, port), nil // Return formatted address string
}

// NodeToAddress converts a network.Node's IP and Port into a usable address string.
// NodeToAddress converts a Node to a TCP address.
func NodeToAddress(node *network.Node) (string, error) {
	if node.IP == "" || node.Port == "" {
		log.Printf("NodeToAddress: node %s has empty IP=%s or Port=%s", node.ID, node.IP, node.Port)
		return "", fmt.Errorf("node %s has empty IP or port", node.ID)
	}
	return fmt.Sprintf("%s:%s", node.IP, node.Port), nil
}

// ConnectNode attempts to connect to a node using TCP and WebSocket up to 3 times.
func ConnectNode(node *network.Node, messageCh chan *security.Message) error {
	addr, err := NodeToAddress(node) // Convert node to address string
	if err != nil {
		return err // Return if address resolution fails
	}

	for attempt := 1; attempt <= 3; attempt++ { // Retry up to 3 times
		conn, err := ConnectTCP(addr, messageCh)
		if err == nil {
			defer conn.Close()
			node.UpdateStatus(network.NodeStatusActive)
			log.Printf("Connected to node %s via TCP: %s", node.ID, addr)
			return nil
		}
		log.Printf("TCP connection to node %s (%s) attempt %d failed: %v", node.ID, addr, attempt, err) // Log TCP failure

		// Resolve the node's *actual* WebSocket address from its registered
		// port configuration instead of guessing via port arithmetic
		// (node.Port+553) — that formula doesn't correspond to how
		// WebSocket ports are actually assigned (see port.go's baseWSPort /
		// NodePortConfig.WSPort) and only ever matched a few hardcoded
		// addresses that ConnectWebSocket special-cased for testing.
		wsAddr, ok := resolveWebSocketAddress(node)
		if !ok {
			log.Printf("No WebSocket address configured for node %s, skipping WebSocket fallback", node.ID)
			if attempt < 3 {
				time.Sleep(time.Second * time.Duration(attempt)) // Exponential backoff between retries
			}
			continue
		}
		if err := ConnectWebSocket(wsAddr, messageCh); err == nil {
			node.UpdateStatus(network.NodeStatusActive)                           // Mark node as active on WebSocket success
			log.Printf("Connected to node %s via WebSocket: %s", node.ID, wsAddr) // Log WebSocket connection success
			return nil
		}
		log.Printf("WebSocket connection to node %s (%s) attempt %d failed: %v", node.ID, wsAddr, attempt, err) // Log WebSocket failure

		if attempt < 3 {
			time.Sleep(time.Second * time.Duration(attempt)) // Exponential backoff between retries
		}
	}
	return fmt.Errorf("failed to connect to node %s (%s) after 3 attempts", node.ID, addr) // Return error after 3 failed attempts
}

// resolveWebSocketAddress looks up a node's real WebSocket address from the
// global NodeConfigs registry (populated by port.go for locally-configured
// nodes). Returns ok=false when the node has no registered config — e.g. a
// peer discovered dynamically over UDP that never went through
// GetNodePortConfigs — in which case there's no reliable way to guess its
// WebSocket port and the caller should skip the WebSocket fallback rather
// than dial a port that's almost certainly wrong.
func resolveWebSocketAddress(node *network.Node) (string, bool) {
	cfg, exists := network.GetNodeConfig(node.ID)
	if !exists || cfg.WSPort == "" {
		return "", false
	}
	return cfg.WSPort, true
}

// SendPeerInfo sends a PeerInfo message to the given address over a secure TCP connection.
func SendPeerInfo(address string, peerInfo *network.PeerInfo) error {
	conn, err := net.Dial("tcp", address) // Dial TCP connection to the address
	if err != nil {
		return fmt.Errorf("failed to dial connection to %s: %v", address, err) // Return error if dialing fails
	}
	defer conn.Close() // Ensure connection is closed after function ends

	handshake := security.NewHandshake()                     // Initialize new Kyber768 handshake
	ek, err := handshake.PerformHandshake(conn, "tcp", true) // Perform key exchange as initiator
	if err != nil {
		return err // Return error if handshake fails
	}

	// Marshal peerInfo to JSON first
	peerInfoBytes, err := json.Marshal(peerInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal peer info: %v", err)
	}

	msg := &security.Message{
		Type: "peer_info",
		Data: peerInfoBytes, // Use marshaled bytes
	}

	data, err := security.SecureMessage(msg, ek) // Encrypt and encode the message using the handshake key
	if err != nil {
		return fmt.Errorf("failed to encode PeerInfo message: %v", err) // Return error if encryption fails
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write PeerInfo to %s: %v", address, err) // Return error if write fails
	}
	log.Printf("Sent PeerInfo to %s", address) // Log successful PeerInfo send
	return nil                                 // Return nil on success
}
