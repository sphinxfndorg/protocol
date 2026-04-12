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
	svm "github.com/sphinxorg/protocol/src/core/svm/opcodes"
	vmachine "github.com/sphinxorg/protocol/src/core/svm/vm"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	"github.com/sphinxorg/protocol/src/crypto/SPHINCSPLUS-golang/sphincs"
	logger "github.com/sphinxorg/protocol/src/log"
)

// SigningService handles all signing and verification operations for consensus messages.
// It uses SVM for signature verification to ensure security and consistency across nodes.
// The service maintains a registry of public keys for other nodes to enable cross-node verification.
//
// The signing flow is as follows:
// SignProposal() → SignMessage() → SphincsManager.SignMessage() → Sphincs.Sign()
// VerifyProposal() → VerifySignature() → verifyWithVM() → VM execution with OP_CHECK_SPHINCS
//
// The same flow applies to votes and timeouts, with the respective signing and verification methods.
//
// Verification call chain:
// VerifyProposal()
//    ↓
//   calls → VerifySignature()
//                ↓
//                calls → verifyWithVM()
//                            ↓
//                            creates VM with OP_CHECK_SPHINCS
//                            ↓
//                            VM executes and returns result
//                            ↓
//                returns result to VerifySignature
//    ↓
//    returns result to Consensus

// RegisterPublicKey registers a public key for another node.
// This enables cross-node signature verification by maintaining a registry of public keys.
// The registry is protected by a mutex for thread-safe concurrent access.
func (s *SigningService) RegisterPublicKey(nodeID string, publicKey *sphincs.SPHINCS_PK) {
	// Lock the mutex to prevent concurrent writes to the registry
	s.registryMutex.Lock()
	defer s.registryMutex.Unlock()

	// Initialize the registry map if it doesn't exist yet
	if s.publicKeyRegistry == nil {
		s.publicKeyRegistry = make(map[string]*sphincs.SPHINCS_PK)
	}
	// Store the public key associated with the node ID
	s.publicKeyRegistry[nodeID] = publicKey
	fmt.Printf("Registered public key for node %s\n", nodeID)
}

// BytesToUint256 converts a byte slice to uint256.Int.
// This utility function is used for converting between different numeric representations
// when working with the SVM or transaction values.
func BytesToUint256(data []byte) *uint256.Int {
	// Create a new uint256 integer and set its value from the byte slice
	// NewInt(0) creates a zero value, then SetBytes populates it
	return uint256.NewInt(0).SetBytes(data)
}

// NewSigningService creates a new signing service.
// This initializes all the components needed for cryptographic operations:
// - SPHINCS+ manager for signing operations
// - Key manager for key generation and serialization
// - Node identification for tracking which node this service belongs to
func NewSigningService(sphincsManager *sign.SphincsManager, keyManager *key.KeyManager, nodeID string) *SigningService {
	// Create the service struct with provided dependencies
	service := &SigningService{
		sphincsManager: sphincsManager,
		keyManager:     keyManager,
		nodeID:         nodeID,
	}
	// Generate or load the cryptographic keys for this node
	service.initializeKeys()
	return service
}

// initializeKeys generates or loads keys for this node.
// This is called during service creation to set up the node's identity.
// The keys are used for signing all consensus messages from this node.
func (s *SigningService) initializeKeys() error {
	fmt.Printf("=== KEY GENERATION DEBUG for node %s ===\n", s.nodeID)

	// Generate a new key pair using the key manager
	// Returns: secret key wrapper, public key, and any error
	skWrapper, pk, err := s.keyManager.GenerateKey()
	if err != nil {
		return err
	}

	// Debug output showing key fingerprints (first 8 bytes)
	fmt.Printf("SKseed fingerprint: %x...\n", skWrapper.SKseed[:8])
	fmt.Printf("PKroot fingerprint: %x...\n", skWrapper.PKroot[:8])

	// Store the private key components in SPHINCS+ format
	s.privateKey = &sphincs.SPHINCS_SK{
		SKseed: skWrapper.SKseed, // Secret seed for signing
		SKprf:  skWrapper.SKprf,  // Secret PRF key
		PKseed: skWrapper.PKseed, // Public seed (part of public key)
		PKroot: skWrapper.PKroot, // Root public key
	}
	// Store the public key object
	s.publicKey = pk

	// Debug: show public key fingerprint if serialization succeeds
	pkBytes, err := pk.SerializePK()
	if err == nil {
		fmt.Printf("Public key fingerprint: %x...\n", pkBytes[:8])
	}

	fmt.Printf("=== END KEY DEBUG ===\n")
	return nil
}

// SignMessage signs a consensus message.
// This is the core signing function that all other signing methods call.
// It handles the complete signing process including:
// - Generating the SPHINCS+ signature
// - Creating the signature hash for verification
// - Packaging everything into a SignedMessage structure
func (s *SigningService) SignMessage(data []byte) ([]byte, error) {
	// Validate that all required components are initialized
	if s.sphincsManager == nil || s.privateKey == nil || s.publicKey == nil {
		return nil, errors.New("not initialized")
	}

	// Sign the message using the SPHINCS+ manager
	// Returns: signature object, merkle root, timestamp, nonce, commitment, and error
	sig, merkleRoot, timestamp, nonce, commitment, err := s.sphincsManager.SignMessage(data, s.privateKey, s.publicKey)
	if err != nil {
		return nil, err
	}

	// Debug output for tracking signature components
	fmt.Printf("DEBUG: Generated nonce size: %d bytes\n", len(nonce))
	fmt.Printf("DEBUG: Generated timestamp size: %d bytes\n", len(timestamp))
	fmt.Printf("DEBUG: Generated commitment size: %d bytes\n", len(commitment))

	// Serialize the signature object to raw bytes
	sigBytes, err := s.sphincsManager.SerializeSignature(sig)
	if err != nil {
		return nil, err
	}

	// Compute signature hash using the sphincsManager method
	// This hash is used for replay protection and quick verification
	signatureHash := s.sphincsManager.ComputeSignatureHash(sigBytes)

	// Create the signed message structure containing all components
	signedMsg := &SignedMessage{
		Signature:     sigBytes,      // The actual SPHINCS+ signature
		SignatureHash: signatureHash, // Hash of the signature for replay protection
		Timestamp:     timestamp,     // Timestamp when signature was created
		Nonce:         nonce,         // One-time nonce for this signature
		MerkleRoot:    merkleRoot,    // Merkle tree root for verification
		Commitment:    commitment,    // Commitment value from signing process
		Data:          data,          // Original message data that was signed
	}

	// Serialize the entire signed message to bytes for transmission
	return signedMsg.Serialize()
}

// uint32ToBytes converts a uint32 to big-endian 4-byte representation.
// This is used for pushing 32-bit values as operands to SVM instructions.
func uint32ToBytes(n uint32) []byte {
	return []byte{
		byte(n >> 24), // Most significant byte
		byte(n >> 16),
		byte(n >> 8),
		byte(n), // Least significant byte
	}
}

// verifyWithVM uses SVM to verify SPHINCS+ signature.
// This is the core verification function that executes the signature check
// inside the Secure Virtual Machine for security and consistency.
// The VM executes OP_CHECK_SPHINCS opcode which performs the cryptographic verification.
func (s *SigningService) verifyWithVM(signature, signatureHash, publicKey, message []byte) bool {
	// First, verify the signature hash matches the signature
	// This prevents replay attacks by ensuring the signature hasn't been tampered with
	computedHash := s.sphincsManager.ComputeSignatureHash(signature)
	if len(signatureHash) != 32 {
		logger.Warn("Invalid signature hash length: %d", len(signatureHash))
		return false
	}
	// Compare each byte of the computed hash with the provided hash
	for i := range computedHash {
		if computedHash[i] != signatureHash[i] {
			logger.Warn("Signature hash mismatch — possible tampering")
			return false
		}
	}

	// Validate public key length
	// SPHINCS+ public keys must be exactly 32 bytes
	expectedPKLen := 32
	if len(publicKey) != expectedPKLen {
		logger.Warn("Invalid public key length: expected %d, got %d", expectedPKLen, len(publicKey))
		return false
	}

	// Calculate lengths for memory layout
	sigLen := len(signature)
	pkLen := len(publicKey)
	msgLen := len(message)

	logger.Debug("VM verification: sigLen=%d, pkLen=%d, msgLen=%d", sigLen, pkLen, msgLen)

	// Calculate memory pointers (offsets) for each component in the VM memory
	sigPtr := uint32(0)              // Signature starts at offset 0
	pkPtr := uint32(sigLen)          // Public key starts right after signature
	msgPtr := uint32(sigLen + pkLen) // Message starts after public key

	// Build VM bytecode for OP_CHECK_SPHINCS
	// IMPORTANT: Push in REVERSE order so that when OP_CHECK_SPHINCS pops,
	// it gets: sig_ptr, sig_len, pk_ptr, pk_len, msg_ptr, msg_len
	// But OP_CHECK_SPHINCS actually expects: msg_len, msg_ptr, pk_len, pk_ptr, sig_len, sig_ptr
	// So we need to push in this order (bottom to top):
	//   sig_ptr, sig_len, pk_ptr, pk_len, msg_ptr, msg_len

	vmBytecode := []byte{}

	// Push signature pointer (will be popped first by the VM)
	vmBytecode = append(vmBytecode, byte(svm.PUSH4))
	vmBytecode = append(vmBytecode, uint32ToBytes(sigPtr)...)

	// Push signature length
	vmBytecode = append(vmBytecode, byte(svm.PUSH4))
	vmBytecode = append(vmBytecode, uint32ToBytes(uint32(sigLen))...)

	// Push public key pointer
	vmBytecode = append(vmBytecode, byte(svm.PUSH4))
	vmBytecode = append(vmBytecode, uint32ToBytes(pkPtr)...)

	// Push public key length
	vmBytecode = append(vmBytecode, byte(svm.PUSH4))
	vmBytecode = append(vmBytecode, uint32ToBytes(uint32(pkLen))...)

	// Push message pointer
	vmBytecode = append(vmBytecode, byte(svm.PUSH4))
	vmBytecode = append(vmBytecode, uint32ToBytes(msgPtr)...)

	// Push message length (will be popped last by the VM)
	vmBytecode = append(vmBytecode, byte(svm.PUSH4))
	vmBytecode = append(vmBytecode, uint32ToBytes(uint32(msgLen))...)

	// Add CHECK opcode - this performs the actual SPHINCS+ verification
	vmBytecode = append(vmBytecode, byte(svm.OP_CHECK_SPHINCS))

	// Prepare memory layout: contiguous memory block containing signature, public key, and message
	memoryLayout := make([]byte, sigLen+pkLen+msgLen)
	copy(memoryLayout[0:], signature)          // Copy signature to start
	copy(memoryLayout[sigLen:], publicKey)     // Copy public key after signature
	copy(memoryLayout[sigLen+pkLen:], message) // Copy message after public key

	// Create a new VM instance with the verification bytecode
	vm := vmachine.NewVM(vmBytecode)

	// Set the memory layout in the VM
	if err := vm.SetMemoryBytes(0, memoryLayout); err != nil {
		logger.Warn("VM memory setup failed: %v", err)
		return false
	}

	// Execute the VM program
	if err := vm.Run(); err != nil {
		logger.Warn("VM execution failed: %v", err)
		return false
	}

	// Get the verification result (1 for success, 0 for failure)
	result, err := vm.GetResult()
	if err != nil {
		logger.Warn("VM result error: %v", err)
		return false
	}

	// Return true only if the VM returned 1 (success)
	return result == 1
}

// VerifySignature verifies a signature for a message using VM ONLY.
// This is the main verification function called by all consensus verification methods.
// It deserializes the signed message, retrieves the appropriate public key,
// and performs the cryptographic verification inside the SVM.
func (s *SigningService) VerifySignature(signedData []byte, nodeID string) (bool, error) {
	// Deserialize the signed message from bytes back into a structured format
	signedMsg, err := DeserializeSignedMessage(signedData)
	if err != nil {
		return false, err
	}

	// Retrieve the public key for the specified node from the registry
	pk, err := s.getPublicKeyForNode(nodeID)
	if err != nil {
		return false, err
	}

	// Serialize public key to bytes for VM consumption
	pkBytes, err := pk.SerializePK()
	if err != nil {
		return false, err
	}

	// CRITICAL DEBUG: Log verification details for troubleshooting
	logger.Info("🔍 Verifying signature for node %s:", nodeID)
	logger.Info("   Public key length: %d bytes", len(pkBytes))
	logger.Info("   Public key (first 8): %x", pkBytes[:min(8, len(pkBytes))])
	logger.Info("   Signature length: %d bytes", len(signedMsg.Signature))
	logger.Info("   Signature hash length: %d bytes", len(signedMsg.SignatureHash))
	logger.Info("   Message length: %d bytes", len(signedMsg.Data))

	// Validate public key length before proceeding
	// Incorrect length will cause VM verification to fail
	if len(pkBytes) != 32 {
		logger.Error("❌ Invalid public key length for node %s: expected 32, got %d",
			nodeID, len(pkBytes))
		return false, fmt.Errorf("invalid public key length: %d", len(pkBytes))
	}

	// Build the full message that was signed
	// Format: timestamp + nonce + original data
	// This ensures uniqueness and prevents replay attacks
	fullMsg := make([]byte, 0, len(signedMsg.Timestamp)+len(signedMsg.Nonce)+len(signedMsg.Data))
	fullMsg = append(fullMsg, signedMsg.Timestamp...)
	fullMsg = append(fullMsg, signedMsg.Nonce...)
	fullMsg = append(fullMsg, signedMsg.Data...)

	// DIRECT VM VERIFICATION with signature hash check
	// Execute the verification inside the Secure Virtual Machine
	result := s.verifyWithVM(signedMsg.Signature, signedMsg.SignatureHash, pkBytes, fullMsg)

	// Log the verification result
	if result {
		sigHashHex := hex.EncodeToString(signedMsg.SignatureHash)
		logger.Info("✅ VM verification passed for node %s (signature hash: %s...)",
			nodeID, sigHashHex[:min(16, len(sigHashHex))])
	} else {
		logger.Warn("❌ VM verification failed for node %s", nodeID)
	}

	return result, nil
}

// getPublicKeyForNode retrieves the registered public key for a given node ID.
// It first checks the registry for other nodes' keys, then falls back to its own key.
// This method is thread-safe due to the read lock on the registry mutex.
func (s *SigningService) getPublicKeyForNode(nodeID string) (*sphincs.SPHINCS_PK, error) {
	// Acquire read lock (allows concurrent reads, blocks writes)
	s.registryMutex.RLock()
	defer s.registryMutex.RUnlock()

	// Check if we have this node's public key in the registry
	if publicKey, exists := s.publicKeyRegistry[nodeID]; exists {
		// Validate the public key serialization to ensure it's usable
		pkBytes, err := publicKey.SerializePK()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize public key for %s: %w", nodeID, err)
		}

		// Check if the serialized key has the expected length
		expectedLen := 32 // SPHINCS+ public keys are 32 bytes
		if len(pkBytes) != expectedLen {
			logger.Warn("Public key for %s has incorrect length: expected %d, got %d",
				nodeID, expectedLen, len(pkBytes))
			return nil, fmt.Errorf("invalid public key length for node %s", nodeID)
		}

		return publicKey, nil
	}

	// If the requested node is this node itself, return our own public key
	if nodeID == s.nodeID && s.publicKey != nil {
		pkBytes, err := s.publicKey.SerializePK()
		if err == nil {
			logger.Debug("Using self public key for %s (len=%d)", nodeID, len(pkBytes))
		}
		return s.publicKey, nil
	}

	// Public key not found in registry and not our own node
	return nil, fmt.Errorf("public key not available for node %s", nodeID)
}

// GetExpectedPublicKeyLength returns the expected SPHINCS+ public key length
// SPHINCS+-128s (SPHINXHASH128s) uses 32-byte public keys
// This is confirmed by test output: "Serialized public key (32 bytes)"
func (s *SigningService) GetExpectedPublicKeyLength() int {
	return 32
}

// GenerateMessageHash generates a SHA-256 hash for consensus messages.
// This is used for creating unique identifiers for messages and for
// certain verification scenarios where a hash of the message is needed.
func (s *SigningService) GenerateMessageHash(messageType string, data []byte) []byte {
	// Create a new SHA-256 hasher
	hasher := crypto.SHA256.New()
	// Write the message type as a discriminator (prevents cross-type hash collisions)
	hasher.Write([]byte(messageType))
	// Write the message data
	hasher.Write(data)
	// Return the final hash
	return hasher.Sum(nil)
}

// SignProposal signs a block proposal.
// This creates a cryptographic signature for the proposal that can be verified
// by other nodes in the consensus protocol.
func (s *SigningService) SignProposal(proposal *Proposal) error {
	// Serialize the proposal to a deterministic byte string for signing
	data := s.serializeProposalForSigning(proposal)
	logger.Info("🔐 SIGNING PROPOSAL for node %s - Data: %s", s.nodeID, string(data))

	// Sign the serialized data using the SignMessage function
	signedData, err := s.SignMessage(data)
	if err != nil {
		return err
	}
	// Attach the signature to the proposal
	proposal.Signature = signedData

	// Log the signature for debugging
	signatureHex := hex.EncodeToString(signedData)
	logger.Info("🔐 CREATED PROPOSAL SIGNATURE for node %s: %s... (length: %d chars)",
		s.nodeID,
		signatureHex[:min(64, len(signatureHex))],
		len(signatureHex))

	return nil
}

// VerifyProposal verifies a proposal signature using VM.
// This validates that the proposal was signed by the claimed proposer
// and that the signature is cryptographically valid.
func (s *SigningService) VerifyProposal(proposal *Proposal) (bool, error) {
	// Check that a signature exists
	if len(proposal.Signature) == 0 {
		return false, fmt.Errorf("empty signature")
	}

	// Deserialize the signature back into a SignedMessage
	signedMsg, err := DeserializeSignedMessage(proposal.Signature)
	if err != nil {
		return false, fmt.Errorf("failed to deserialize signature: %w", err)
	}

	logger.Info("🔍 Verifying proposal: signed data = %s", string(signedMsg.Data))

	// Recompute what the signed data should be based on the proposal content
	expectedData := s.serializeProposalForSigning(proposal)
	logger.Info("🔍 Expected data = %s", string(expectedData))

	// Verify that the signed data matches the proposal content
	// This prevents signature reuse attacks
	if string(signedMsg.Data) != string(expectedData) {
		logger.Warn("❌ Signed data mismatch: got=%s, want=%s",
			string(signedMsg.Data), string(expectedData))
		return false, fmt.Errorf("signed data does not match proposal content")
	}

	// Verify the cryptographic signature using the proposer's public key
	valid, err := s.VerifySignature(proposal.Signature, proposal.ProposerID)
	if err != nil {
		return false, err
	}

	// Log success with signature hash for traceability
	if valid {
		sigHashHex := hex.EncodeToString(signedMsg.SignatureHash)
		logger.Info("✅ Valid signature for proposal from %s (signature hash: %s...)",
			proposal.ProposerID, sigHashHex[:min(16, len(sigHashHex))])
	}

	return valid, nil
}

// SignVote signs a vote (prepare or commit).
// Votes are used in the consensus protocol to indicate agreement on a block.
func (s *SigningService) SignVote(vote *Vote) error {
	// Serialize the vote to a deterministic byte string for signing
	data := s.serializeVoteForSigning(vote)
	logger.Info("🔐 SIGNING VOTE for node %s - Data: %s", s.nodeID, string(data))

	// Sign the serialized data
	signature, err := s.SignMessage(data)
	if err != nil {
		return err
	}
	// Attach the signature to the vote
	vote.Signature = signature

	// Log the signature for debugging
	signatureHex := hex.EncodeToString(signature)
	logger.Info("🔐 CREATED VOTE SIGNATURE for node %s: %s... (length: %d chars)",
		s.nodeID,
		signatureHex[:min(64, len(signatureHex))],
		len(signatureHex))

	return nil
}

// VerifyVote verifies a vote signature using VM.
// This ensures that a vote was actually signed by the claimed voter.
func (s *SigningService) VerifyVote(vote *Vote) (bool, error) {
	// Verify the cryptographic signature using the voter's public key
	valid, err := s.VerifySignature(vote.Signature, vote.VoterID)
	if err != nil {
		return false, err
	}

	// Log success with signature hash for traceability
	if valid {
		// Deserialize to get signature hash for logging
		signedMsg, err := DeserializeSignedMessage(vote.Signature)
		if err == nil && len(signedMsg.SignatureHash) > 0 {
			sigHashHex := hex.EncodeToString(signedMsg.SignatureHash)
			logger.Info("✅ Valid vote signature from %s (signature hash: %s...)",
				vote.VoterID, sigHashHex[:min(16, len(sigHashHex))])
		} else {
			logger.Info("✅ Valid vote signature from %s", vote.VoterID)
		}
	}

	return valid, nil
}

// SignTimeout signs a timeout message.
// Timeout messages are used in consensus to signal that a round has timed out.
func (s *SigningService) SignTimeout(timeout *TimeoutMsg) error {
	// Serialize the timeout message to a deterministic byte string for signing
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

// VerifyTimeout verifies a timeout signature using VM.
// This ensures that a timeout message was actually signed by the claimed voter.
func (s *SigningService) VerifyTimeout(timeout *TimeoutMsg) (bool, error) {
	// Verify the cryptographic signature using the voter's public key
	valid, err := s.VerifySignature(timeout.Signature, timeout.VoterID)
	if err != nil {
		return false, err
	}

	// Log success with signature hash for traceability
	if valid {
		// Deserialize to get signature hash for logging
		signedMsg, err := DeserializeSignedMessage(timeout.Signature)
		if err == nil && len(signedMsg.SignatureHash) > 0 {
			sigHashHex := hex.EncodeToString(signedMsg.SignatureHash)
			logger.Info("✅ Valid timeout signature from %s (signature hash: %s...)",
				timeout.VoterID, sigHashHex[:min(16, len(sigHashHex))])
		} else {
			logger.Info("✅ Valid timeout signature from %s", timeout.VoterID)
		}
	}

	return valid, nil
}

// serializeProposalForSigning creates a deterministic byte string from a proposal.
// This ensures that the same proposal always produces the same bytes for signing.
// The format includes: message type, view number, block hash, proposer ID, and either slot number or timestamp.
func (s *SigningService) serializeProposalForSigning(proposal *Proposal) []byte {
	// Check if this proposal has a slot number (post-aggregation)
	if proposal.SlotNumber > 0 {
		// Format: PROPOSAL:VIEW:BLOCKHASH:PROPOSERID:SLOTNUMBER
		data := fmt.Sprintf("PROPOSAL:%d:%s:%s:%d",
			proposal.View,
			proposal.Block.GetHash(),
			proposal.ProposerID,
			proposal.SlotNumber)
		return []byte(data)
	}

	// Fallback: use block timestamp instead of slot number
	// Format: PROPOSAL:VIEW:BLOCKHASH:PROPOSERID:TIMESTAMP
	data := fmt.Sprintf("PROPOSAL:%d:%s:%s:%d",
		proposal.View,
		proposal.Block.GetHash(),
		proposal.ProposerID,
		proposal.Block.GetTimestamp())
	return []byte(data)
}

// serializeVoteForSigning creates a deterministic byte string from a vote.
// Format: VOTE:VIEW:BLOCKHASH:VOTERID
// This ensures votes for the same view and block produce consistent signing bytes.
func (s *SigningService) serializeVoteForSigning(vote *Vote) []byte {
	data := fmt.Sprintf("VOTE:%d:%s:%s",
		vote.View,
		vote.BlockHash,
		vote.VoterID)
	return []byte(data)
}

// serializeTimeoutForSigning creates a deterministic byte string from a timeout.
// Format: TIMEOUT:VIEW:VOTERID:TIMESTAMP
// The timestamp ensures each timeout message is unique even for the same view.
func (s *SigningService) serializeTimeoutForSigning(timeout *TimeoutMsg) []byte {
	data := fmt.Sprintf("TIMEOUT:%d:%s:%d",
		timeout.View,
		timeout.VoterID,
		timeout.Timestamp)
	return []byte(data)
}

// GetPublicKey returns the public key for this node as bytes.
// This is used for exchanging public keys between nodes during initialization.
func (s *SigningService) GetPublicKey() ([]byte, error) {
	if s.publicKey == nil {
		return nil, fmt.Errorf("public key not available")
	}
	// Serialize the public key object to raw bytes
	return s.publicKey.SerializePK()
}

// GetPublicKeyObject returns the public key object for this node.
// This provides direct access to the SPHINCS_PK object for operations
// that need the structured key rather than raw bytes.
func (s *SigningService) GetPublicKeyObject() *sphincs.SPHINCS_PK {
	return s.publicKey
}

// SignBlock signs the block header hash.
// This creates a proposer signature for the entire block,
// which is stored in the block header for verification by other nodes.
func (s *SigningService) SignBlock(block Block) error {
	// Try to unwrap the block to get the underlying types.Block
	tb, ok := block.(*types.Block)
	if !ok {
		// Check if the block implements the underlying block getter interface
		type underlyingBlockGetter interface {
			GetUnderlyingBlock() *types.Block
		}
		if getter, ok2 := block.(underlyingBlockGetter); ok2 {
			tb = getter.GetUnderlyingBlock()
		}
	}
	// Validate we successfully unwrapped the block
	if tb == nil {
		return fmt.Errorf("SignBlock: cannot unwrap *types.Block from interface")
	}
	// Ensure the block has been hashed before signing
	if tb.Header == nil || len(tb.Header.Hash) == 0 {
		return fmt.Errorf("block must be hashed before signing")
	}

	// Sign the block header hash
	signedData, err := s.SignMessage(tb.Header.Hash)
	if err != nil {
		return fmt.Errorf("failed to sign block: %w", err)
	}

	// Attach the signature and proposer ID to the block header
	tb.Header.ProposerSignature = signedData
	tb.Header.ProposerID = s.nodeID
	return nil
}

// VerifyBlockSignature verifies the proposer's signature on a block using VM.
// This validates that the block was actually proposed and signed by the claimed proposer.
func (s *SigningService) VerifyBlockSignature(block Block) (bool, error) {
	// Unwrap the block to access the underlying types.Block
	tb, ok := block.(*types.Block)
	if !ok {
		type underlyingBlockGetter interface {
			GetUnderlyingBlock() *types.Block
		}
		if getter, ok2 := block.(underlyingBlockGetter); ok2 {
			tb = getter.GetUnderlyingBlock()
		}
	}
	// Validate block structure
	if tb == nil {
		return false, fmt.Errorf("VerifyBlockSignature: cannot unwrap *types.Block from interface")
	}
	if tb.Header == nil {
		return false, fmt.Errorf("block header is nil")
	}
	// Check that a signature exists
	if len(tb.Header.ProposerSignature) == 0 {
		return false, fmt.Errorf("block has no proposer signature")
	}
	// Check that proposer ID is present
	if tb.Header.ProposerID == "" {
		return false, fmt.Errorf("block has no proposer ID")
	}

	// Deserialize the signature from the block header
	signedMsg, err := DeserializeSignedMessage(tb.Header.ProposerSignature)
	if err != nil {
		return false, fmt.Errorf("failed to deserialize block signature: %w", err)
	}

	// Verify that the signed data matches the block hash
	if string(signedMsg.Data) != string(tb.Header.Hash) {
		return false, fmt.Errorf("signature data does not match block hash")
	}

	// Verify the cryptographic signature using the proposer's public key
	valid, err := s.VerifySignature(tb.Header.ProposerSignature, tb.Header.ProposerID)
	if err != nil {
		return false, err
	}

	// Log success with signature hash for traceability
	if valid {
		sigHashHex := hex.EncodeToString(signedMsg.SignatureHash)
		logger.Info("✅ Valid block signature from %s (signature hash: %s...)",
			tb.Header.ProposerID, sigHashHex[:min(16, len(sigHashHex))])
	}

	return valid, nil
}

// GetSigningService returns the signing service instance from the Consensus object.
// This provides a thread-safe way to access the signing service.
func (c *Consensus) GetSigningService() *SigningService {
	c.mu.RLock() // Acquire read lock for thread safety
	defer c.mu.RUnlock()
	return c.signingService
}
