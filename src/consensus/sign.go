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
// The signing flow is as follows:
// SignProposal() → SignMessage() → SphincsManager.SignMessage() → Sphincs.Sign()
// VerifyProposal() → VerifySignature() → verifyWithVM() → VM execution with OP_CHECK_SPHINCS
// The same flow applies to votes and timeouts, with the respective signing and verification methods.
//
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
func (s *SigningService) RegisterPublicKey(nodeID string, publicKey *sphincs.SPHINCS_PK) {
	s.registryMutex.Lock()
	defer s.registryMutex.Unlock()

	if s.publicKeyRegistry == nil {
		s.publicKeyRegistry = make(map[string]*sphincs.SPHINCS_PK)
	}
	s.publicKeyRegistry[nodeID] = publicKey
	fmt.Printf("Registered public key for node %s\n", nodeID)
}

// BytesToUint256 converts a byte slice to uint256.Int.
func BytesToUint256(data []byte) *uint256.Int {
	return uint256.NewInt(0).SetBytes(data)
}

// NewSigningService creates a new signing service.
func NewSigningService(sphincsManager *sign.SphincsManager, keyManager *key.KeyManager, nodeID string) *SigningService {
	service := &SigningService{
		sphincsManager: sphincsManager,
		keyManager:     keyManager,
		nodeID:         nodeID,
	}
	service.initializeKeys()
	return service
}

// initializeKeys generates or loads keys for this node.
func (s *SigningService) initializeKeys() error {
	fmt.Printf("=== KEY GENERATION DEBUG for node %s ===\n", s.nodeID)

	skWrapper, pk, err := s.keyManager.GenerateKey()
	if err != nil {
		return err
	}

	fmt.Printf("SKseed fingerprint: %x...\n", skWrapper.SKseed[:8])
	fmt.Printf("PKroot fingerprint: %x...\n", skWrapper.PKroot[:8])

	s.privateKey = &sphincs.SPHINCS_SK{
		SKseed: skWrapper.SKseed,
		SKprf:  skWrapper.SKprf,
		PKseed: skWrapper.PKseed,
		PKroot: skWrapper.PKroot,
	}
	s.publicKey = pk

	pkBytes, err := pk.SerializePK()
	if err == nil {
		fmt.Printf("Public key fingerprint: %x...\n", pkBytes[:8])
	}

	fmt.Printf("=== END KEY DEBUG ===\n")
	return nil
}

// SignMessage signs a consensus message.
func (s *SigningService) SignMessage(data []byte) ([]byte, error) {
	if s.sphincsManager == nil || s.privateKey == nil || s.publicKey == nil {
		return nil, errors.New("not initialized")
	}

	sig, merkleRoot, timestamp, nonce, commitment, err := s.sphincsManager.SignMessage(data, s.privateKey, s.publicKey)
	if err != nil {
		return nil, err
	}

	fmt.Printf("DEBUG: Generated nonce size: %d bytes\n", len(nonce))
	fmt.Printf("DEBUG: Generated timestamp size: %d bytes\n", len(timestamp))
	fmt.Printf("DEBUG: Generated commitment size: %d bytes\n", len(commitment))

	sigBytes, err := s.sphincsManager.SerializeSignature(sig)
	if err != nil {
		return nil, err
	}

	// Compute signature hash using the sphincsManager method
	signatureHash := s.sphincsManager.ComputeSignatureHash(sigBytes)

	signedMsg := &SignedMessage{
		Signature:     sigBytes,
		SignatureHash: signatureHash,
		Timestamp:     timestamp,
		Nonce:         nonce,
		MerkleRoot:    merkleRoot,
		Commitment:    commitment,
		Data:          data,
	}

	return signedMsg.Serialize()
}

func uint32ToBytes(n uint32) []byte {
	return []byte{
		byte(n >> 24),
		byte(n >> 16),
		byte(n >> 8),
		byte(n),
	}
}

// verifyWithVM uses SVM to verify SPHINCS+ signature
func (s *SigningService) verifyWithVM(signature, signatureHash, publicKey, message []byte) bool {
	// First, verify the signature hash matches the signature
	computedHash := s.sphincsManager.ComputeSignatureHash(signature)
	if len(signatureHash) != 32 {
		logger.Warn("Invalid signature hash length: %d", len(signatureHash))
		return false
	}
	for i := range computedHash {
		if computedHash[i] != signatureHash[i] {
			logger.Warn("Signature hash mismatch — possible tampering")
			return false
		}
	}

	// Validate public key length
	expectedPKLen := 32
	if len(publicKey) != expectedPKLen {
		logger.Warn("Invalid public key length: expected %d, got %d", expectedPKLen, len(publicKey))
		return false
	}

	sigLen := len(signature)
	pkLen := len(publicKey)
	msgLen := len(message)

	logger.Debug("VM verification: sigLen=%d, pkLen=%d, msgLen=%d", sigLen, pkLen, msgLen)

	// Calculate memory pointers
	sigPtr := uint32(0)
	pkPtr := uint32(sigLen)
	msgPtr := uint32(sigLen + pkLen)

	// Build VM bytecode for OP_CHECK_SPHINCS
	// IMPORTANT: Push in REVERSE order so that when OP_CHECK_SPHINCS pops,
	// it gets: sig_ptr, sig_len, pk_ptr, pk_len, msg_ptr, msg_len
	// But OP_CHECK_SPHINCS actually expects: msg_len, msg_ptr, pk_len, pk_ptr, sig_len, sig_ptr
	// So we need to push in this order (bottom to top):
	//   sig_ptr, sig_len, pk_ptr, pk_len, msg_ptr, msg_len

	vmBytecode := []byte{}

	// Push signature pointer (will be popped first)
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

	// Push message length (will be popped last)
	vmBytecode = append(vmBytecode, byte(svm.PUSH4))
	vmBytecode = append(vmBytecode, uint32ToBytes(uint32(msgLen))...)

	// Add CHECK opcode
	vmBytecode = append(vmBytecode, byte(svm.OP_CHECK_SPHINCS))

	// Prepare memory layout
	memoryLayout := make([]byte, sigLen+pkLen+msgLen)
	copy(memoryLayout[0:], signature)
	copy(memoryLayout[sigLen:], publicKey)
	copy(memoryLayout[sigLen+pkLen:], message)

	vm := vmachine.NewVM(vmBytecode)
	if err := vm.SetMemoryBytes(0, memoryLayout); err != nil {
		logger.Warn("VM memory setup failed: %v", err)
		return false
	}
	if err := vm.Run(); err != nil {
		logger.Warn("VM execution failed: %v", err)
		return false
	}
	result, err := vm.GetResult()
	if err != nil {
		logger.Warn("VM result error: %v", err)
		return false
	}
	return result == 1
}

// VerifySignature verifies a signature for a message using VM ONLY.
// VerifySignature verifies a signature for a message using VM ONLY.
func (s *SigningService) VerifySignature(signedData []byte, nodeID string) (bool, error) {
	signedMsg, err := DeserializeSignedMessage(signedData)
	if err != nil {
		return false, err
	}

	pk, err := s.getPublicKeyForNode(nodeID)
	if err != nil {
		return false, err
	}

	// Serialize public key for VM
	pkBytes, err := pk.SerializePK()
	if err != nil {
		return false, err
	}

	// CRITICAL DEBUG: Log the public key length and first few bytes
	logger.Info("🔍 Verifying signature for node %s:", nodeID)
	logger.Info("   Public key length: %d bytes", len(pkBytes))
	logger.Info("   Public key (first 8): %x", pkBytes[:min(8, len(pkBytes))])
	logger.Info("   Signature length: %d bytes", len(signedMsg.Signature))
	logger.Info("   Signature hash length: %d bytes", len(signedMsg.SignatureHash))
	logger.Info("   Message length: %d bytes", len(signedMsg.Data))

	// Validate public key length before proceeding
	if len(pkBytes) != 32 {
		logger.Error("❌ Invalid public key length for node %s: expected 32, got %d",
			nodeID, len(pkBytes))
		return false, fmt.Errorf("invalid public key length: %d", len(pkBytes))
	}

	// Build the full message (timestamp + nonce + data)
	fullMsg := make([]byte, 0, len(signedMsg.Timestamp)+len(signedMsg.Nonce)+len(signedMsg.Data))
	fullMsg = append(fullMsg, signedMsg.Timestamp...)
	fullMsg = append(fullMsg, signedMsg.Nonce...)
	fullMsg = append(fullMsg, signedMsg.Data...)

	// DIRECT VM VERIFICATION with signature hash check
	result := s.verifyWithVM(signedMsg.Signature, signedMsg.SignatureHash, pkBytes, fullMsg)

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
func (s *SigningService) getPublicKeyForNode(nodeID string) (*sphincs.SPHINCS_PK, error) {
	s.registryMutex.RLock()
	defer s.registryMutex.RUnlock()

	if publicKey, exists := s.publicKeyRegistry[nodeID]; exists {
		// Validate the public key serialization
		pkBytes, err := publicKey.SerializePK()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize public key for %s: %w", nodeID, err)
		}

		// Check if the serialized key has the expected length
		expectedLen := 32 // Adjust based on your SPHINCS+ parameters
		if len(pkBytes) != expectedLen {
			logger.Warn("Public key for %s has incorrect length: expected %d, got %d",
				nodeID, expectedLen, len(pkBytes))
			return nil, fmt.Errorf("invalid public key length for node %s", nodeID)
		}

		return publicKey, nil
	}

	if nodeID == s.nodeID && s.publicKey != nil {
		pkBytes, err := s.publicKey.SerializePK()
		if err == nil {
			logger.Debug("Using self public key for %s (len=%d)", nodeID, len(pkBytes))
		}
		return s.publicKey, nil
	}

	return nil, fmt.Errorf("public key not available for node %s", nodeID)
}

// GetExpectedPublicKeyLength returns the expected SPHINCS+ public key length
func (s *SigningService) GetExpectedPublicKeyLength() int {
	// SPHINCS+-128s (SPHINXHASH128s) uses 32-byte public keys
	// Confirmed by test output: "Serialized public key (32 bytes)"
	return 32
}

// GenerateMessageHash generates a SHA-256 hash for consensus messages.
func (s *SigningService) GenerateMessageHash(messageType string, data []byte) []byte {
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(messageType))
	hasher.Write(data)
	return hasher.Sum(nil)
}

// SignProposal signs a block proposal.
func (s *SigningService) SignProposal(proposal *Proposal) error {
	data := s.serializeProposalForSigning(proposal)
	logger.Info("🔐 SIGNING PROPOSAL for node %s - Data: %s", s.nodeID, string(data))

	signedData, err := s.SignMessage(data)
	if err != nil {
		return err
	}
	proposal.Signature = signedData

	signatureHex := hex.EncodeToString(signedData)
	logger.Info("🔐 CREATED PROPOSAL SIGNATURE for node %s: %s... (length: %d chars)",
		s.nodeID,
		signatureHex[:min(64, len(signatureHex))],
		len(signatureHex))

	return nil
}

// VerifyProposal verifies a proposal signature using VM.
func (s *SigningService) VerifyProposal(proposal *Proposal) (bool, error) {
	if len(proposal.Signature) == 0 {
		return false, fmt.Errorf("empty signature")
	}

	signedMsg, err := DeserializeSignedMessage(proposal.Signature)
	if err != nil {
		return false, fmt.Errorf("failed to deserialize signature: %w", err)
	}

	logger.Info("🔍 Verifying proposal: signed data = %s", string(signedMsg.Data))

	expectedData := s.serializeProposalForSigning(proposal)
	logger.Info("🔍 Expected data = %s", string(expectedData))

	if string(signedMsg.Data) != string(expectedData) {
		logger.Warn("❌ Signed data mismatch: got=%s, want=%s",
			string(signedMsg.Data), string(expectedData))
		return false, fmt.Errorf("signed data does not match proposal content")
	}

	valid, err := s.VerifySignature(proposal.Signature, proposal.ProposerID)
	if err != nil {
		return false, err
	}

	if valid {
		// Print the signature hash value when signature is valid
		sigHashHex := hex.EncodeToString(signedMsg.SignatureHash)
		logger.Info("✅ Valid signature for proposal from %s (signature hash: %s...)",
			proposal.ProposerID, sigHashHex[:min(16, len(sigHashHex))])
	}

	return valid, nil
}

// SignVote signs a vote (prepare or commit).
func (s *SigningService) SignVote(vote *Vote) error {
	data := s.serializeVoteForSigning(vote)
	logger.Info("🔐 SIGNING VOTE for node %s - Data: %s", s.nodeID, string(data))

	signature, err := s.SignMessage(data)
	if err != nil {
		return err
	}
	vote.Signature = signature

	signatureHex := hex.EncodeToString(signature)
	logger.Info("🔐 CREATED VOTE SIGNATURE for node %s: %s... (length: %d chars)",
		s.nodeID,
		signatureHex[:min(64, len(signatureHex))],
		len(signatureHex))

	return nil
}

// VerifyVote verifies a vote signature using VM.
func (s *SigningService) VerifyVote(vote *Vote) (bool, error) {
	valid, err := s.VerifySignature(vote.Signature, vote.VoterID)
	if err != nil {
		return false, err
	}

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
func (s *SigningService) SignTimeout(timeout *TimeoutMsg) error {
	data := s.serializeTimeoutForSigning(timeout)

	signature, err := s.SignMessage(data)
	if err != nil {
		return err
	}
	timeout.Signature = signature
	return nil
}

// VerifyTimeout verifies a timeout signature using VM.
func (s *SigningService) VerifyTimeout(timeout *TimeoutMsg) (bool, error) {
	valid, err := s.VerifySignature(timeout.Signature, timeout.VoterID)
	if err != nil {
		return false, err
	}

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
func (s *SigningService) serializeProposalForSigning(proposal *Proposal) []byte {
	if proposal.SlotNumber > 0 {
		data := fmt.Sprintf("PROPOSAL:%d:%s:%s:%d",
			proposal.View,
			proposal.Block.GetHash(),
			proposal.ProposerID,
			proposal.SlotNumber)
		return []byte(data)
	}

	data := fmt.Sprintf("PROPOSAL:%d:%s:%s:%d",
		proposal.View,
		proposal.Block.GetHash(),
		proposal.ProposerID,
		proposal.Block.GetTimestamp())
	return []byte(data)
}

// serializeVoteForSigning creates a deterministic byte string from a vote.
func (s *SigningService) serializeVoteForSigning(vote *Vote) []byte {
	data := fmt.Sprintf("VOTE:%d:%s:%s",
		vote.View,
		vote.BlockHash,
		vote.VoterID)
	return []byte(data)
}

// serializeTimeoutForSigning creates a deterministic byte string from a timeout.
func (s *SigningService) serializeTimeoutForSigning(timeout *TimeoutMsg) []byte {
	data := fmt.Sprintf("TIMEOUT:%d:%s:%d",
		timeout.View,
		timeout.VoterID,
		timeout.Timestamp)
	return []byte(data)
}

// GetPublicKey returns the public key for this node as bytes.
func (s *SigningService) GetPublicKey() ([]byte, error) {
	if s.publicKey == nil {
		return nil, fmt.Errorf("public key not available")
	}
	return s.publicKey.SerializePK()
}

// GetPublicKeyObject returns the public key object for this node.
func (s *SigningService) GetPublicKeyObject() *sphincs.SPHINCS_PK {
	return s.publicKey
}

// SignBlock signs the block header hash.
func (s *SigningService) SignBlock(block Block) error {
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
		return fmt.Errorf("SignBlock: cannot unwrap *types.Block from interface")
	}
	if tb.Header == nil || len(tb.Header.Hash) == 0 {
		return fmt.Errorf("block must be hashed before signing")
	}

	signedData, err := s.SignMessage(tb.Header.Hash)
	if err != nil {
		return fmt.Errorf("failed to sign block: %w", err)
	}

	tb.Header.ProposerSignature = signedData
	tb.Header.ProposerID = s.nodeID
	return nil
}

// VerifyBlockSignature verifies the proposer's signature on a block using VM.
func (s *SigningService) VerifyBlockSignature(block Block) (bool, error) {
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

	signedMsg, err := DeserializeSignedMessage(tb.Header.ProposerSignature)
	if err != nil {
		return false, fmt.Errorf("failed to deserialize block signature: %w", err)
	}

	if string(signedMsg.Data) != string(tb.Header.Hash) {
		return false, fmt.Errorf("signature data does not match block hash")
	}

	valid, err := s.VerifySignature(tb.Header.ProposerSignature, tb.Header.ProposerID)
	if err != nil {
		return false, err
	}

	if valid {
		sigHashHex := hex.EncodeToString(signedMsg.SignatureHash)
		logger.Info("✅ Valid block signature from %s (signature hash: %s...)",
			tb.Header.ProposerID, sigHashHex[:min(16, len(sigHashHex))])
	}

	return valid, nil
}

// GetSigningService returns the signing service instance
func (c *Consensus) GetSigningService() *SigningService {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.signingService
}

// DeserializeAndRegisterPublicKey deserializes a public key from bytes and registers it
func (s *SigningService) DeserializeAndRegisterPublicKey(nodeID string, publicKeyBytes []byte) error {
	if s.keyManager == nil {
		return fmt.Errorf("key manager not available")
	}

	pk, err := s.keyManager.DeserializePublicKey(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to deserialize public key: %w", err)
	}

	s.RegisterPublicKey(nodeID, pk)
	return nil
}
