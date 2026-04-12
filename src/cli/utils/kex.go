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

func exchangePublicKeys(signingServices map[string]*consensus.SigningService, nodeIDs []string) {
	logger.Info("=== EXCHANGING PUBLIC KEYS BETWEEN %d NODES ===", len(nodeIDs))

	// First, collect and validate all public keys
	publicKeys := make(map[string][]byte) // Store as bytes for validation

	for _, nodeID := range nodeIDs {
		signingService := signingServices[nodeID]
		if signingService == nil {
			logger.Warn("No signing service for node %s", nodeID)
			continue
		}

		// Get public key as bytes
		pkBytes, err := signingService.GetPublicKey()
		if err != nil {
			logger.Warn("Failed to get public key for %s: %v", nodeID, err)
			continue
		}

		// Validate public key length (must be 32 bytes)
		if len(pkBytes) != 32 {
			logger.Error("❌ Public key for %s has incorrect length: expected 32, got %d",
				nodeID, len(pkBytes))
			logger.Error("   This will cause ALL signature verifications to fail!")
			continue
		}

		logger.Info("✅ Valid public key for %s (32 bytes)", nodeID)
		logger.Debug("   Public key fingerprint: %x", pkBytes[:8])
		publicKeys[nodeID] = pkBytes
	}

	// Register public keys with each node's signing service
	for _, nodeID := range nodeIDs {
		signingService := signingServices[nodeID]
		if signingService == nil {
			continue
		}

		registeredCount := 0
		for otherNodeID, pkBytes := range publicKeys {
			if nodeID == otherNodeID {
				continue
			}

			// Deserialize bytes to SPHINCS_PK object and register
			err := signingService.DeserializeAndRegisterPublicKey(otherNodeID, pkBytes)
			if err != nil {
				logger.Warn("Failed to register %s's public key with %s: %v",
					otherNodeID, nodeID, err)
			} else {
				registeredCount++
				logger.Debug("Registered %s's public key with %s", otherNodeID, nodeID)
			}
		}

		logger.Info("Node %s registered %d public keys", nodeID, registeredCount)
	}

	logger.Info("✅ Public key exchange completed: %d/%d nodes exchanged keys",
		len(publicKeys), len(nodeIDs))
}
