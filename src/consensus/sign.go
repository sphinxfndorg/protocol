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

// go/src/consensus/signing.go
package consensus

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/holiman/uint256"
	key "github.com/sphinxorg/protocol/src/core/sphincs/key/backend"
	sign "github.com/sphinxorg/protocol/src/core/sphincs/sign/backend"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	"github.com/sphinxorg/protocol/src/crypto/SPHINCSPLUS-golang/sphincs"
	logger "github.com/sphinxorg/protocol/src/log"
)

// Add this method to register public keys from other nodes
// This enables cross-node signature verification by maintaining a registry of public keys
func (s *SigningService) RegisterPublicKey(nodeID string, publicKey *sphincs.SPHINCS_PK) {
	s.registryMutex.Lock()         // Lock for thread-safe map access
	defer s.registryMutex.Unlock() // Ensure unlock on function return

	// Initialize registry map if it doesn't exist
	if s.publicKeyRegistry == nil {
		s.publicKeyRegistry = make(map[string]*sphincs.SPHINCS_PK)
	}
	// Store the public key for this node ID
	s.publicKeyRegistry[nodeID] = publicKey
	fmt.Printf("Registered public key for node %s\n", nodeID)
}

// BytesToUint256 converts a byte slice to uint256.Int
// This is useful for handling large integers in the EVM-compatible format
func BytesToUint256(data []byte) *uint256.Int {
	return uint256.NewInt(0).SetBytes(data) // Create new uint256 and set from bytes
}

// NewSigningService creates a new signing service
// This service handles all cryptographic operations for consensus messages
func NewSigningService(sphincsManager *sign.SphincsManager, keyManager *key.KeyManager, nodeID string) *SigningService {
	// Create new signing service instance with provided components
	service := &SigningService{
		sphincsManager: sphincsManager, // SPHINCS+ manager for signature operations
		keyManager:     keyManager,     // Key manager for key generation/storage
		nodeID:         nodeID,         // Unique identifier for this node
	}

	// Generate keys for this node if not already available
	service.initializeKeys()

	return service
}

// initializeKeys generates or loads keys for this node
// This ensures the node has a valid keypair for signing operations
// In initializeKeys method, add this debug:
func (s *SigningService) initializeKeys() error {
	fmt.Printf("=== KEY GENERATION DEBUG for node %s ===\n", s.nodeID)

	// Generate a new keypair using the key manager
	skWrapper, pk, err := s.keyManager.GenerateKey()
	if err != nil {
		return err // Return error if key generation fails
	}

	// Debug logging to verify keys are generated correctly
	fmt.Printf("SKseed fingerprint: %x...\n", skWrapper.SKseed[:8]) // First 8 bytes of seed
	fmt.Printf("PKroot fingerprint: %x...\n", skWrapper.PKroot[:8]) // First 8 bytes of root

	// Store private key components in the expected SPHINCS+ format
	s.privateKey = &sphincs.SPHINCS_SK{
		SKseed: skWrapper.SKseed, // Secret key seed
		SKprf:  skWrapper.SKprf,  // Secret key PRF (pseudo-random function)
		PKseed: skWrapper.PKseed, // Public key seed
		PKroot: skWrapper.PKroot, // Public key root
	}
	s.publicKey = pk // Store public key

	// Verify public key is unique by checking its fingerprint
	pkBytes, err := pk.SerializePK()
	if err == nil {
		fmt.Printf("Public key fingerprint: %x...\n", pkBytes[:8])
	}

	fmt.Printf("=== END KEY DEBUG ===\n")
	return nil
}

// SignMessage signs a consensus message
// This is the core signing function that creates SPHINCS+ signatures
func (s *SigningService) SignMessage(data []byte) ([]byte, error) {
	// Verify that signing service is properly initialized
	if s.sphincsManager == nil || s.privateKey == nil {
		return nil, errors.New("not initialized")
	}

	// Generate SPHINCS+ signature with timestamp and nonce for replay protection
	sig, merkleRoot, timestamp, nonce, err := s.sphincsManager.SignMessage(data, s.privateKey)
	if err != nil {
		return nil, err // Return error if signing fails
	}

	// DEBUG: Log the actual nonce size for debugging
	fmt.Printf("DEBUG: Generated nonce size: %d bytes\n", len(nonce))
	fmt.Printf("DEBUG: Generated timestamp size: %d bytes\n", len(timestamp))

	// Serialize just the SPHINCS+ signature (not the entire message)
	sigBytes, err := s.sphincsManager.SerializeSignature(sig)
	if err != nil {
		return nil, err
	}

	// Create a structured signed message containing all verification data
	signedMsg := &SignedMessage{
		Signature:  sigBytes,   // The actual SPHINCS+ signature
		Timestamp:  timestamp,  // Timestamp for replay protection
		Nonce:      nonce,      // Random nonce for uniqueness
		MerkleRoot: merkleRoot, // Merkle root for tree authentication
		Data:       data,       // Include the original message data
	}

	// Serialize the entire signed message into a byte array
	return signedMsg.Serialize()
}

// VerifySignature verifies a signature for a message
// This validates that a signature was created by the claimed node
func (s *SigningService) VerifySignature(signedData []byte, nodeID string) (bool, error) {
	// Deserialize the signed message structure to extract components
	signedMsg, err := DeserializeSignedMessage(signedData)
	if err != nil {
		return false, err // Return error if deserialization fails
	}

	// Deserialize just the SPHINCS+ signature part
	sig, err := s.sphincsManager.DeserializeSignature(signedMsg.Signature)
	if err != nil {
		return false, err
	}

	// Get the public key for the claimed signer
	pk, err := s.getPublicKeyForNode(nodeID)
	if err != nil {
		return false, err
	}

	// Verify the signature using all original components
	return s.sphincsManager.VerifySignature(
		signedMsg.Data,       // Original message data
		signedMsg.Timestamp,  // Timestamp used in signing
		signedMsg.Nonce,      // Nonce used in signing
		sig,                  // The signature itself
		pk,                   // Signer's public key
		signedMsg.MerkleRoot, // Merkle root for authentication
	), nil
}

// getPublicKeyForNode gets the public key for a node
// Retrieves the registered public key for a given node ID
// Update getPublicKeyForNode to use the registry
func (s *SigningService) getPublicKeyForNode(nodeID string) (*sphincs.SPHINCS_PK, error) {
	s.registryMutex.RLock() // Read lock for thread safety
	defer s.registryMutex.RUnlock()

	// Check if we have a registered public key for this node
	if publicKey, exists := s.publicKeyRegistry[nodeID]; exists {
		return publicKey, nil // Return the registered key
	}

	// Fallback: if it's our own node, return our public key
	if nodeID == s.nodeID && s.publicKey != nil {
		return s.publicKey, nil
	}

	// No public key available for this node
	return nil, fmt.Errorf("public key not available for node %s", nodeID)
}

// GenerateMessageHash generates a hash for consensus messages
// Creates a SHA-256 hash of message type and data for verification
func (s *SigningService) GenerateMessageHash(messageType string, data []byte) []byte {
	hasher := crypto.SHA256.New()     // Create new SHA-256 hasher
	hasher.Write([]byte(messageType)) // Add message type to hash
	hasher.Write(data)                // Add message data to hash
	return hasher.Sum(nil)            // Return the final hash
}

// SignProposal signs a block proposal
// Creates a signature for a consensus proposal message
func (s *SigningService) SignProposal(proposal *Proposal) error {
	// Serialize the proposal into bytes for signing
	data := s.serializeProposalForSigning(proposal)

	// DEBUG: Log what we're signing
	logger.Info("🔐 SIGNING PROPOSAL for node %s - Data: %s", s.nodeID, string(data))

	// Sign the serialized data
	signedData, err := s.SignMessage(data)
	if err != nil {
		return err
	}

	// Attach the signature to the proposal
	proposal.Signature = signedData

	// DEBUG: Log the resulting signature for debugging
	signatureHex := hex.EncodeToString(signedData)
	logger.Info("🔐 CREATED PROPOSAL SIGNATURE for node %s: %s... (length: %d chars)",
		s.nodeID,
		signatureHex[:min(64, len(signatureHex))], // Show first 64 chars only
		len(signatureHex))

	return nil
}

// VerifyProposal verifies a proposal signature
// Validates that a proposal was signed by the claimed proposer
func (s *SigningService) VerifyProposal(proposal *Proposal) (bool, error) {
	// Verify the signature using the proposal's signature and proposer ID
	return s.VerifySignature(proposal.Signature, proposal.ProposerID)
}

// SignVote signs a vote (prepare or commit)
// Creates a signature for consensus votes (both prepare and commit phases)
func (s *SigningService) SignVote(vote *Vote) error {
	// Serialize the vote into bytes for signing
	data := s.serializeVoteForSigning(vote)

	// DEBUG: Log what we're signing
	logger.Info("🔐 SIGNING VOTE for node %s - Data: %s", s.nodeID, string(data))

	// Sign the serialized data
	signature, err := s.SignMessage(data)
	if err != nil {
		return err
	}

	// Attach the signature to the vote
	vote.Signature = signature

	// DEBUG: Log the resulting signature for debugging
	signatureHex := hex.EncodeToString(signature)
	logger.Info("🔐 CREATED VOTE SIGNATURE for node %s: %s... (length: %d chars)",
		s.nodeID,
		signatureHex[:min(64, len(signatureHex))], // Show first 64 chars only
		len(signatureHex))

	return nil
}

// VerifyVote verifies a vote signature
// Validates that a vote was signed by the claimed voter
func (s *SigningService) VerifyVote(vote *Vote) (bool, error) {
	// Verify the signature using the vote's signature and voter ID
	return s.VerifySignature(vote.Signature, vote.VoterID) // CORRECT - 2 arguments
}

// SignTimeout signs a timeout message
// Creates a signature for view change timeout messages
func (s *SigningService) SignTimeout(timeout *TimeoutMsg) error {
	// Serialize the timeout message into bytes for signing
	data := s.serializeTimeoutForSigning(timeout)

	// Sign the serialized data
	signature, err := s.SignMessage(data)
	if err != nil {
		return err
	}

	// Attach the signature to the timeout message
	timeout.Signature = signature
	return nil
}

// VerifyTimeout verifies a timeout signature
// Validates that a timeout message was signed by the claimed node
func (s *SigningService) VerifyTimeout(timeout *TimeoutMsg) (bool, error) {
	// Verify the signature using the timeout's signature and voter ID
	return s.VerifySignature(timeout.Signature, timeout.VoterID) // CORRECT - 2 arguments
}

// Serialization methods for signing
// These methods create deterministic byte representations of consensus messages
// that can be signed and verified

// serializeProposalForSigning creates a deterministic byte string from a proposal
// This ensures all critical fields are included in the signature
func (s *SigningService) serializeProposalForSigning(proposal *Proposal) []byte {
	// Include all critical fields in the signed data
	data := fmt.Sprintf("PROPOSAL:%d:%s:%s:%d",
		proposal.View,                 // Consensus view number
		proposal.Block.GetHash(),      // Block hash being proposed
		proposal.ProposerID,           // ID of the proposing node
		proposal.Block.GetTimestamp()) // Block timestamp
	return []byte(data)
}

// serializeVoteForSigning creates a deterministic byte string from a vote
// This ensures all critical fields are included in the signature
func (s *SigningService) serializeVoteForSigning(vote *Vote) []byte {
	data := fmt.Sprintf("VOTE:%d:%s:%s",
		vote.View,      // Consensus view number
		vote.BlockHash, // Block hash being voted on
		vote.VoterID)   // ID of the voting node
	return []byte(data)
}

// serializeTimeoutForSigning creates a deterministic byte string from a timeout
// This ensures all critical fields are included in the signature
func (s *SigningService) serializeTimeoutForSigning(timeout *TimeoutMsg) []byte {
	data := fmt.Sprintf("TIMEOUT:%d:%s:%d",
		timeout.View,      // New view being requested
		timeout.VoterID,   // ID of the node requesting view change
		timeout.Timestamp) // Timestamp for replay protection
	return []byte(data)
}

// GetPublicKey returns the public key for this node as bytes
// Useful for transmitting the public key to other nodes
func (s *SigningService) GetPublicKey() ([]byte, error) {
	if s.publicKey == nil {
		return nil, fmt.Errorf("public key not available")
	}

	// Serialize the public key into bytes
	return s.publicKey.SerializePK()
}

// GetPublicKeyObject returns the public key object for this node
// Returns the actual SPHINCS_PK object for cryptographic operations
func (s *SigningService) GetPublicKeyObject() *sphincs.SPHINCS_PK {
	return s.publicKey
}

// SignBlock signs the block header hash. block must implement Block interface
// and wrap a *types.Block underneath.
// This creates a signature for the entire block header
func (s *SigningService) SignBlock(block Block) error {
	// Type-assert to get the underlying *types.Block
	tb, ok := block.(*types.Block)
	if !ok {
		// Try unwrapping via helper interface if direct assertion fails
		type underlyingBlockGetter interface {
			GetUnderlyingBlock() *types.Block
		}
		if getter, ok2 := block.(underlyingBlockGetter); ok2 {
			tb = getter.GetUnderlyingBlock()
		}
	}
	if tb == nil {
		return fmt.Errorf("SignBlock: cannot unwrap *types.Block from interface")
	}
	if tb.Header == nil || len(tb.Header.Hash) == 0 {
		return fmt.Errorf("block must be hashed before signing")
	}

	// Sign the block header hash
	signedData, err := s.SignMessage(tb.Header.Hash)
	if err != nil {
		return fmt.Errorf("failed to sign block: %w", err)
	}

	// Attach signature and proposer ID to the block header
	tb.Header.ProposerSignature = signedData
	tb.Header.ProposerID = s.nodeID
	return nil
}

// VerifyBlockSignature verifies the proposer's signature on a block.
// This validates that the block was signed by the claimed proposer
func (s *SigningService) VerifyBlockSignature(block Block) (bool, error) {
	// Extract underlying block, similar to SignBlock
	tb, ok := block.(*types.Block)
	if !ok {
		type underlyingBlockGetter interface {
			GetUnderlyingBlock() *types.Block
		}
		if getter, ok2 := block.(underlyingBlockGetter); ok2 {
			tb = getter.GetUnderlyingBlock()
		}
	}
	if tb == nil {
		return false, fmt.Errorf("VerifyBlockSignature: cannot unwrap *types.Block from interface")
	}
	if tb.Header == nil {
		return false, fmt.Errorf("block header is nil")
	}
	if len(tb.Header.ProposerSignature) == 0 {
		return false, fmt.Errorf("block has no proposer signature")
	}
	if tb.Header.ProposerID == "" {
		return false, fmt.Errorf("block has no proposer ID")
	}

	// Deserialize the signature to get the signed message structure
	signedMsg, err := DeserializeSignedMessage(tb.Header.ProposerSignature)
	if err != nil {
		return false, fmt.Errorf("failed to deserialize block signature: %w", err)
	}

	// Verify that the signed data matches the block hash
	if string(signedMsg.Data) != string(tb.Header.Hash) {
		return false, fmt.Errorf("signature data does not match block hash")
	}

	// Verify the signature using the proposer's public key
	return s.VerifySignature(tb.Header.ProposerSignature, tb.Header.ProposerID)
}
