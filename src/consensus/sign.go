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
//
// FIX: SignMessage now requires both sk and pk, and returns 6 values including
// the 32-byte commitment. The commitment is stored in SignedMessage so that
// VerifySignature can pass it to sphincsManager.VerifySignature.
func (s *SigningService) SignMessage(data []byte) ([]byte, error) {
	if s.sphincsManager == nil || s.privateKey == nil || s.publicKey == nil {
		return nil, errors.New("not initialized")
	}

	// FIX: pass s.publicKey as third argument.
	// Capture all 6 return values: sig, merkleRoot, timestamp, nonce, commitment, err.
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

	// FIX: store commitment in SignedMessage so VerifySignature can retrieve it.
	// Without this field the commitment is lost and VerifySignature cannot pass
	// it to sphincsManager.VerifySignature.
	signedMsg := &SignedMessage{
		Signature:  sigBytes,
		Timestamp:  timestamp,
		Nonce:      nonce,
		MerkleRoot: merkleRoot,
		Commitment: commitment, // 32-byte binding: H(sigBytes||pk||timestamp||nonce||data)
		Data:       data,
	}

	return signedMsg.Serialize()
}

// VerifySignature verifies a signature for a message.
//
// FIX: sphincsManager.VerifySignature now requires a 7th argument: commitment.
// We extract it from SignedMessage (where it was stored at signing time) and
// pass it through. If commitment is missing or wrong length the call returns false.
func (s *SigningService) VerifySignature(signedData []byte, nodeID string) (bool, error) {
	signedMsg, err := DeserializeSignedMessage(signedData)
	if err != nil {
		return false, err
	}

	sig, err := s.sphincsManager.DeserializeSignature(signedMsg.Signature)
	if err != nil {
		return false, err
	}

	pk, err := s.getPublicKeyForNode(nodeID)
	if err != nil {
		return false, err
	}

	// FIX: pass signedMsg.Commitment as the required 7th argument.
	// commitment = H(sigBytes||pk||timestamp||nonce||data), 32 bytes.
	// A missing or zeroed commitment will cause the inner commitment-equality
	// check to fail, so no special nil-guard is needed here.
	return s.sphincsManager.VerifySignature(
		signedMsg.Data,
		signedMsg.Timestamp,
		signedMsg.Nonce,
		sig,
		pk,
		signedMsg.MerkleRoot,
		signedMsg.Commitment, // FIX: was missing
	), nil
}

// getPublicKeyForNode retrieves the registered public key for a given node ID.
func (s *SigningService) getPublicKeyForNode(nodeID string) (*sphincs.SPHINCS_PK, error) {
	s.registryMutex.RLock()
	defer s.registryMutex.RUnlock()

	if publicKey, exists := s.publicKeyRegistry[nodeID]; exists {
		return publicKey, nil
	}

	if nodeID == s.nodeID && s.publicKey != nil {
		return s.publicKey, nil
	}

	return nil, fmt.Errorf("public key not available for node %s", nodeID)
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

// VerifyProposal verifies a proposal signature.
func (s *SigningService) VerifyProposal(proposal *Proposal) (bool, error) {
	return s.VerifySignature(proposal.Signature, proposal.ProposerID)
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

// VerifyVote verifies a vote signature.
func (s *SigningService) VerifyVote(vote *Vote) (bool, error) {
	return s.VerifySignature(vote.Signature, vote.VoterID)
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

// VerifyTimeout verifies a timeout signature.
func (s *SigningService) VerifyTimeout(timeout *TimeoutMsg) (bool, error) {
	return s.VerifySignature(timeout.Signature, timeout.VoterID)
}

// serializeProposalForSigning creates a deterministic byte string from a proposal.
func (s *SigningService) serializeProposalForSigning(proposal *Proposal) []byte {
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

// VerifyBlockSignature verifies the proposer's signature on a block.
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

	return s.VerifySignature(tb.Header.ProposerSignature, tb.Header.ProposerID)
}
