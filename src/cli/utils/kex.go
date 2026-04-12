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

// go/src/cli/utils/kex.go
package utils

import (
	"github.com/sphinxorg/protocol/src/consensus"
	logger "github.com/sphinxorg/protocol/src/log"
)

// exchangePublicKeys handles the distribution and registration of public keys between nodes
// This is a critical step for establishing trust and enabling signature verification in the consensus protocol
// The function performs two main operations:
// 1. Collects and validates public keys from all signing services
// 2. Registers each node's public key with all other nodes' signing services
func exchangePublicKeys(signingServices map[string]*consensus.SigningService, nodeIDs []string) {
	logger.Info("=== EXCHANGING PUBLIC KEYS BETWEEN %d NODES ===", len(nodeIDs))

	// First phase: Collect and validate all public keys
	// This ensures all keys are properly formatted before distribution
	publicKeys := make(map[string][]byte) // Store as bytes for validation and later registration

	// Iterate through each node to extract its public key
	for _, nodeID := range nodeIDs {
		// Retrieve the signing service for this node
		signingService := signingServices[nodeID]
		if signingService == nil {
			// Node doesn't have a signing service configured - log warning and skip
			logger.Warn("No signing service for node %s", nodeID)
			continue
		}

		// Get public key as raw bytes from the signing service
		// The public key is used for SPHINCS+ signature verification
		pkBytes, err := signingService.GetPublicKey()
		if err != nil {
			logger.Warn("Failed to get public key for %s: %v", nodeID, err)
			continue
		}

		// Validate public key length - SPHINCS+ requires exactly 32 bytes
		// Incorrect length will cause ALL signature verifications to fail
		if len(pkBytes) != 32 {
			logger.Error("❌ Public key for %s has incorrect length: expected 32, got %d",
				nodeID, len(pkBytes))
			logger.Error("   This will cause ALL signature verifications to fail!")
			continue
		}

		// Public key is valid - log success and store for distribution
		logger.Info("✅ Valid public key for %s (32 bytes)", nodeID)
		logger.Debug("   Public key fingerprint: %x", pkBytes[:8]) // Show first 8 bytes as fingerprint
		publicKeys[nodeID] = pkBytes
	}

	// Second phase: Register public keys with each node's signing service
	// This allows each node to verify signatures from other nodes
	for _, nodeID := range nodeIDs {
		// Get the signing service for this node (the receiving node)
		signingService := signingServices[nodeID]
		if signingService == nil {
			// Skip nodes without signing services
			continue
		}

		registeredCount := 0 // Track successful registrations for logging

		// Register every other node's public key with this node's signing service
		for otherNodeID, pkBytes := range publicKeys {
			// Skip self-registration - a node doesn't need to verify its own signatures
			if nodeID == otherNodeID {
				continue
			}

			// Deserialize the raw bytes back into a SPHINCS_PK object and register it
			// The signing service stores this public key for future signature verification
			err := signingService.DeserializeAndRegisterPublicKey(otherNodeID, pkBytes)
			if err != nil {
				logger.Warn("Failed to register %s's public key with %s: %v",
					otherNodeID, nodeID, err)
			} else {
				registeredCount++
				logger.Debug("Registered %s's public key with %s", otherNodeID, nodeID)
			}
		}

		// Log summary of registrations for this node
		logger.Info("Node %s registered %d public keys", nodeID, registeredCount)
	}

	// Final summary: Report success rate of key exchange
	// This indicates how many nodes successfully participated in the key exchange
	logger.Info("✅ Public key exchange completed: %d/%d nodes exchanged keys",
		len(publicKeys), len(nodeIDs))
}
