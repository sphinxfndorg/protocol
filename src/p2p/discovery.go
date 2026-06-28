// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/p2p/discovery.go
package p2p

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/core/hashtree"
	sigproof "github.com/sphinxfndorg/protocol/src/core/proof"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	"github.com/sphinxfndorg/protocol/src/network"
)

// DiscoverPeers initiates Kademlia-based peer discovery.
// This function attempts to find and connect to peers using seed nodes
// as entry points into the network. It implements retry logic with
// exponential backoff and multiple seed nodes for redundancy.
func (s *Server) DiscoverPeers() error {
	// Configuration constants for discovery process
	const maxOverallRetries = 3             // Maximum number of complete discovery attempts
	const retryDelay = 5 * time.Second      // Base delay between retries
	const seedTimeout = 90 * time.Second    // Timeout waiting for response from a single seed node
	const globalTimeout = 180 * time.Second // Total timeout for the entire discovery process

	// Outer retry loop - will attempt discovery up to maxOverallRetries times
	for overallRetry := 1; overallRetry <= maxOverallRetries; overallRetry++ {
		// Log the current attempt with seed node information
		log.Printf("DiscoverPeers: Attempt %d/%d for node %s with %d seed nodes: %v",
			overallRetry, maxOverallRetries, s.localNode.Address, len(s.seedNodes), s.seedNodes)

		// Check if any seed nodes were provided
		if len(s.seedNodes) == 0 {
			log.Printf("DiscoverPeers: No seed nodes provided for node %s, skipping peer discovery", s.localNode.Address)
			return nil // No seeds available, but this isn't an error
		}

		// Track peers we've already received to avoid duplicates
		receivedPeers := make(map[string]bool)

		// Set up global timeout timer for this discovery attempt
		timeout := time.After(globalTimeout)

		// Maximum retries per seed node
		maxRetries := 3

		// Start a goroutine to continuously drain ResponseCh
		// This prevents blocking when responses arrive
		peerCh := make(chan []*network.Peer, 100) // Buffered channel to hold incoming peers
		go func() {
			for {
				select {
				case peers := <-s.nodeManager.ResponseCh:
					// Received peers from node manager
					log.Printf("DiscoverPeers: Received %d peers from ResponseCh for %s", len(peers), s.localNode.Address)
					select {
					case peerCh <- peers:
						// Successfully forwarded peers to processing channel
						log.Printf("DiscoverPeers: Sent %d peers to peerCh for %s", len(peers), s.localNode.Address)
					default:
						// Channel is full - drop peers to avoid blocking
						log.Printf("DiscoverPeers: peerCh full, dropping %d peers for %s", len(peers), s.localNode.Address)
					}
				case <-timeout:
					// Global timeout reached, stop draining
					log.Printf("DiscoverPeers: Global timeout reached, stopping ResponseCh drain for %s", s.localNode.Address)
					close(peerCh)
					return
				}
			}
		}()

		// Iterate through all seed nodes
		for _, seed := range s.seedNodes {
			// Normalize seed to just "port" (strip IP if present)
			// Seeds can be in format "ip:port" or just "port"
			seedPort := strings.Split(seed, ":")
			seedPortStr := seedPort[len(seedPort)-1]
			log.Printf("DiscoverPeers: Normalized seed %s to port %s for %s", seed, seedPortStr, s.localNode.Address)

			// Resolve seed address to UDP address
			addr, err := net.ResolveUDPAddr("udp", seed)
			if err != nil {
				log.Printf("DiscoverPeers: Failed to resolve seed address %s for %s: %v", seed, s.localNode.Address, err)
				continue // Skip this seed and try next one
			}

			// Retry loop for this specific seed node
			for retry := 1; retry <= maxRetries; retry++ {
				// Generate random nonce for this ping to prevent replay attacks
				nonce := make([]byte, 8)
				_, err := rand.Read(nonce)
				if err != nil {
					log.Printf("DiscoverPeers: Failed to generate nonce for %s for %s: %v", seed, s.localNode.Address, err)
					continue
				}

				// Send UDP ping to seed node
				s.sendUDPPing(addr, s.localNode.KademliaID, nonce)

				// Set up timer for this specific seed request
				seedTimer := time.NewTimer(seedTimeout)

				// Wait for response or timeout
				select {
				case peers, ok := <-peerCh:
					// Received response from seed
					if !ok {
						log.Printf("DiscoverPeers: peerCh closed for %s", s.localNode.Address)
						break
					}
					log.Printf("DiscoverPeers: Received %d peers from seed %s for %s", len(peers), seed, s.localNode.Address)
					seedTimer.Stop() // Stop timer since we got response

					// Process each received peer
					for _, peer := range peers {
						// Skip if already processed
						if receivedPeers[peer.Node.ID] {
							log.Printf("DiscoverPeers: Skipping already processed peer %s for %s", peer.Node.Address, s.localNode.Address)
							continue
						}

						// Skip invalid peers (empty address or self)
						if peer.Node.Address == "" || peer.Node.Address == s.localNode.Address {
							log.Printf("DiscoverPeers: Skipping peer %s (empty address or self) for %s", peer.Node.Address, s.localNode.Address)
							continue
						}

						// Mark peer as received
						receivedPeers[peer.Node.ID] = true
						log.Printf("DiscoverPeers: Processing peer %s (KademliaID: %x) for %s",
							peer.Node.Address, peer.Node.KademliaID[:8], s.localNode.Address)

						// Attempt to connect to the peer
						if err := s.peerManager.ConnectPeer(peer.Node); err != nil {
							log.Printf("DiscoverPeers: Failed to connect to peer %s for %s: %v", peer.Node.Address, s.localNode.Address, err)
							continue
						}
						log.Printf("DiscoverPeers: Successfully connected to peer %s for %s", peer.Node.Address, s.localNode.Address)

						// Start iterative find node for this peer to discover more nodes
						go s.iterativeFindNode(peer.Node.KademliaID)
					}

					// If we found any peers, consider discovery successful
					if len(receivedPeers) > 0 {
						return nil // Success
					}

				case <-seedTimer.C:
					// Timeout waiting for response from this seed
					log.Printf("DiscoverPeers: Timeout waiting for response from seed %s (attempt %d/%d) for %s",
						seed, retry, maxRetries, s.localNode.Address)

				case <-timeout:
					// Global timeout reached
					log.Printf("DiscoverPeers: Global timeout reached for node %s", s.localNode.Address)

					// Check if we have any peers despite timeout
					s.nodeManager.Lock()
					peers := s.nodeManager.GetPeers()
					s.nodeManager.Unlock()

					if len(peers) > 0 {
						log.Printf("DiscoverPeers: Found %d peers in nodeManager.GetPeers() for %s despite timeout: %v",
							len(peers), s.localNode.Address, peers)
						return nil // Success if peers are found
					}

					// If this was our last overall retry, return error
					if overallRetry == maxOverallRetries {
						return errors.New("global timeout reached with no peers found")
					}
				}

				// Stop timer to prevent resource leak
				seedTimer.Stop()

				// If we need to retry this seed, use exponential backoff
				if retry < maxRetries {
					// Exponential backoff: 5s, 10s, 20s
					backoff := retryDelay * time.Duration(math.Pow(2, float64(retry-1)))
					log.Printf("DiscoverPeers: Retrying seed %s after %v for %s", seed, backoff, s.localNode.Address)
					time.Sleep(backoff)
				}
			}

			// Check nodeManager.peers after each seed attempt
			s.nodeManager.Lock()
			peers := s.nodeManager.GetPeers()
			s.nodeManager.Unlock()

			if len(peers) > 0 {
				log.Printf("DiscoverPeers: Found %d peers in nodeManager.peers after seed %s for %s: %v",
					len(peers), seed, s.localNode.Address, peers)
				return nil // Success
			}
		}

		// After processing all seeds, check for late-arriving peers
		select {
		case peers, ok := <-peerCh:
			// Received late peers (after seed processing)
			if !ok {
				log.Printf("DiscoverPeers: peerCh closed for %s", s.localNode.Address)
				break
			}
			log.Printf("DiscoverPeers: Received %d late-arriving peers for %s", len(peers), s.localNode.Address)

			// Process late peers
			for _, peer := range peers {
				// Skip if already processed
				if receivedPeers[peer.Node.ID] {
					continue
				}

				// Skip invalid peers
				if peer.Node.Address == "" || peer.Node.Address == s.localNode.Address {
					continue
				}

				// Mark and connect to late peer
				receivedPeers[peer.Node.ID] = true
				log.Printf("DiscoverPeers: Processing late peer %s (KademliaID: %x) for %s",
					peer.Node.Address, peer.Node.KademliaID[:8], s.localNode.Address)

				if err := s.peerManager.ConnectPeer(peer.Node); err != nil {
					log.Printf("DiscoverPeers: Failed to connect to late peer %s for %s: %v", peer.Node.Address, s.localNode.Address, err)
					continue
				}
				log.Printf("DiscoverPeers: Successfully connected to late peer %s for %s", peer.Node.Address, s.localNode.Address)

				// Start iterative find node for this peer
				go s.iterativeFindNode(peer.Node.KademliaID)
			}

			// If we found any late peers, consider discovery successful
			if len(receivedPeers) > 0 {
				return nil // Success
			}

		case <-timeout:
			// Global timeout reached, no late peers
			log.Printf("DiscoverPeers: Global timeout reached, no late peers for %s", s.localNode.Address)
		}

		// Final check of nodeManager.peers after all processing
		s.nodeManager.Lock()
		peers := s.nodeManager.GetPeers()
		s.nodeManager.Unlock()

		if len(peers) > 0 {
			log.Printf("DiscoverPeers: Found %d peers in nodeManager.peers after seed loop for %s: %v",
				len(peers), s.localNode.Address, peers)
			return nil // Success
		}

		// No peers found on this attempt, prepare for next overall retry
		log.Printf("DiscoverPeers: No peers found on attempt %d, retrying after %v for %s",
			overallRetry, retryDelay, s.localNode.Address)
		time.Sleep(retryDelay)
	}

	// All retries exhausted - final check
	s.nodeManager.Lock()
	peers := s.nodeManager.GetPeers()
	s.nodeManager.Unlock()

	if len(peers) > 0 {
		log.Printf("DiscoverPeers: Found %d peers in nodeManager.peers after retries for %s: %v",
			len(peers), s.localNode.Address, peers)
		return nil
	}

	// No peers found after all retries
	return errors.New("no peers found after retries")
}

// iterativeFindNode performs iterative FINDNODE queries with hop tracking and error handling.
// This implements Kademlia's iterative node lookup algorithm to find nodes closest to a target ID.
// It continues querying closer nodes until no closer nodes can be found or max hops reached.
func (s *Server) iterativeFindNode(targetID network.NodeID) {
	// Configuration constants
	const maxAttempts = 5                // Maximum number of full lookup attempts
	const queryTimeout = 5 * time.Second // Timeout for each individual FINDNODE query
	const maxHops = 20                   // Maximum number of lookup hops to prevent infinite loops

	// Outer retry loop - will attempt lookup up to maxAttempts times
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Track hop count to prevent infinite loops
		hopCount := 0

		// Track visited peers to avoid querying same peer multiple times
		visited := make(map[string]bool)

		// Calculate initial distance to target from local node
		closestDistance := s.nodeManager.CalculateDistance(s.localNode.KademliaID, targetID)

		// Get initial set of closest peers from routing table
		closestPeers := s.nodeManager.FindClosestPeers(targetID, s.nodeManager.K)

		// Main lookup loop - continues as long as we have peers to query and haven't exceeded max hops
		for len(closestPeers) > 0 && hopCount < maxHops {
			// Track new closest distance found in this hop
			newClosestDistance := closestDistance

			// Track new closest peers found in this hop
			newClosestPeers := make([]*network.Peer, 0, s.nodeManager.K)

			// Channels for collecting responses and errors
			responseCh := make(chan []*network.Peer, len(closestPeers))
			errorCh := make(chan error, len(closestPeers))

			// Query each peer in parallel
			for _, peer := range closestPeers {
				// Skip already visited peers
				if visited[peer.Node.ID] {
					continue
				}
				visited[peer.Node.ID] = true

				// Resolve peer's UDP address
				addr, err := net.ResolveUDPAddr("udp", peer.Node.UDPPort)
				if err != nil {
					log.Printf("Failed to resolve UDP address %s: %v", peer.Node.UDPPort, err)
					continue
				}

				// Launch goroutine to query this peer
				go func(peer *network.Peer, addr *net.UDPAddr) {
					// Generate random nonce for this query
					nonce := make([]byte, 32)
					_, err := rand.Read(nonce)
					if err != nil {
						errorCh <- err
						return
					}

					// Initialize key manager for cryptographic operations
					km, err := key.NewKeyManager()
					if err != nil {
						errorCh <- err
						return
					}

					// Deserialize local node's key pair.
					// We need both sk (for signing) and pk (for the commitment).
					privateKey, publicKey, err := km.DeserializeKeyPair(s.localNode.PrivateKey, s.localNode.PublicKey)
					if err != nil {
						log.Printf("iterativeFindNode: Failed to deserialize key pair: %v", err)
						errorCh <- fmt.Errorf("failed to deserialize key pair: %v", err)
						return
					}

					// Prepare FINDNODE request data
					data := network.FindNodeData{
						TargetID:  targetID,
						Timestamp: time.Now(),
						Nonce:     nonce,
					}

					// Marshal data to JSON
					dataBytes, err := json.Marshal(data)
					if err != nil {
						errorCh <- err
						return
					}

					// Create timestamp bytes
					timestamp := make([]byte, 8)
					binary.BigEndian.PutUint64(timestamp, uint64(data.Timestamp.Unix()))

					// Sign the message using SPHINCS+ post-quantum signature.
					// FIX: pass publicKey as third argument; capture all 6 return values
					// including the new commitment.
					signature, merkleRoot, sigTimestamp, sigNonce, commitment, err := s.sphincsMgr.SignMessage(dataBytes, privateKey, publicKey)
					if err != nil {
						errorCh <- err
						return
					}

					// Serialize signature for storage
					// Serialize signature for storage
					// SerializeSignature is a method on the signature object, not the manager
					signatureBytes, err := signature.SerializeSignature()
					if err != nil {
						errorCh <- err
						return
					}

					// Store signature in database for later verification
					err = hashtree.SaveLeavesToDB(s.db, [][]byte{dataBytes, signatureBytes})
					if err != nil {
						log.Printf("iterativeFindNode: Failed to store signature: %v", err)
						errorCh <- err
						return
					}

					// Generate signature proof.
					// FIX: fold commitment into leaves so GenerateSigProof stays at 3 args.
					// Both sender and receiver must use leaves = [merkleRootHash, commitment].
					// sigTimestamp and sigNonce come from SignMessage (bound inside commitment).
					proofData := append(sigTimestamp, append(sigNonce, dataBytes...)...)
					proofLeaves := [][]byte{merkleRoot.Hash.Bytes(), commitment}
					proof, err := sigproof.GenerateSigProof(
						[][]byte{proofData},
						proofLeaves,
						s.localNode.PublicKey,
					)
					if err != nil {
						errorCh <- err
						return
					}

					// Create discovery message.
					// Timestamp and Nonce fields carry the values SignMessage generated
					// (which are bound inside commitment) so the receiver can verify them.
					msg := network.DiscoveryMessage{
						Type:       "FINDNODE",
						Data:       dataBytes,
						PublicKey:  s.localNode.PublicKey,
						MerkleRoot: merkleRoot.Hash,
						Proof:      proof,
						Nonce:      sigNonce,
						Timestamp:  sigTimestamp,
						Commitment: commitment, // 32-byte commitment transmitted to receiver
					}

					// Suppress unused variable warning for outer timestamp var
					_ = timestamp

					// Send UDP message to peer
					s.sendUDPMessage(addr, msg)

					// Wait for response or timeout
					select {
					case peers := <-s.nodeManager.ResponseCh:
						// Response received
						responseCh <- peers
					case <-time.After(queryTimeout):
						// Timeout - send nil to indicate no response
						errorCh <- nil // Timeout, no error
					}
				}(peer, addr)
			}

			// Collect responses from all queried peers with overall timeout
			for i := 0; i < len(closestPeers); i++ {
				select {
				case peers := <-responseCh:
					// Process successful response
					for _, p := range peers {
						// Calculate distance of discovered peer to target
						distance := s.nodeManager.CalculateDistance(p.Node.KademliaID, targetID)

						// Compare with current closest distance
						cmp := s.nodeManager.CompareDistance(distance, newClosestDistance)
						if cmp < 0 {
							// Found closer peer - reset new closest set
							newClosestDistance = distance
							newClosestPeers = []*network.Peer{p}
						} else if cmp == 0 {
							// Found peer at same distance - add to set
							newClosestPeers = append(newClosestPeers, p)
						}

						// Attempt to connect to newly discovered peer
						if p.Node.Address != s.localNode.Address {
							if err := s.peerManager.ConnectPeer(p.Node); err != nil {
								log.Printf("iterativeFindNode: Failed to connect to peer %s: %v", p.Node.Address, err)
								continue
							}
							log.Printf("iterativeFindNode: Successfully connected to peer %s", p.Node.Address)
						}
					}

				case err := <-errorCh:
					// Handle error or timeout
					if err != nil {
						log.Printf("Error in FINDNODE query: %v", err)
					}

				case <-time.After(queryTimeout):
					// Overall timeout for response collection
					log.Printf("Timeout waiting for FINDNODE response")
				}
			}

			// Check if we found any closer peers
			if s.nodeManager.CompareDistance(newClosestDistance, closestDistance) >= 0 {
				// No closer peers found - we've reached the closest nodes
				break
			}

			// Update closest distance and peers for next hop
			closestDistance = newClosestDistance
			closestPeers = newClosestPeers
			hopCount++

			log.Printf("FINDNODE hop %d: %d peers queried, closest distance updated", hopCount, len(closestPeers))
		}

		// Log completion of this attempt
		log.Printf("Completed FINDNODE for target %x after %d hops (%d peers visited)",
			targetID[:8], hopCount, len(visited))

		// Check if we made any progress
		if hopCount > 0 || len(closestPeers) > 0 {
			// Success or partial success - we found some peers
			return
		}

		// No progress in this attempt, wait and retry
		log.Printf("No progress in attempt %d, retrying after delay", attempt)
		time.Sleep(10 * time.Second)
	}

	// All attempts failed
	log.Printf("Failed to find peers for target %x after %d attempts", targetID[:8], maxAttempts)
}
