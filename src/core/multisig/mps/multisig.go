// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/multisig/multisig.go
package multisig

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/holiman/uint256"
	"github.com/sphinxfndorg/protocol/src/core/hashtree"
	sigproof "github.com/sphinxfndorg/protocol/src/core/proof"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"

	"github.com/syndtr/goleveldb/leveldb"
)

// SIPS0008 https://github.com/sphinx-core/sips/wiki/SIPS0008

// MultisigManager manages the SPHINCS+ multisig functionalities, including
// key generation, signing, and verification.
type MultisigManager struct {
	km          *key.KeyManager
	manager     *sign.STHINCSManager // FIXED: changed from SphincsManager to STHINCSManager
	quorum      int
	signatures  map[string][]byte
	partyPK     map[string][]byte
	proofs      map[string][]byte
	timestamps  map[string][]byte
	nonces      map[string][]byte
	merkleRoots map[string][]byte
	// FIX: store the 32-byte commitment per party so VerifySignature can use it.
	// commitment = H(sigBytes||pk||timestamp||nonce||message); produced by SignMessage.
	commitments map[string][]byte
	storedPK    [][]byte
	storedSK    [][]byte
	mu          sync.RWMutex
}

// GetStoredPK returns the stored public keys of all participants.
func (m *MultisigManager) GetStoredPK() [][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.storedPK
}

// GetStoredSK returns the stored private keys of all participants.
func (m *MultisigManager) GetStoredSK() [][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.storedSK
}

// NewMultiSig initializes a new multisig with a specified number of participants.
func NewMultiSig(n int) (*MultisigManager, error) {
	km, err := key.NewKeyManager()
	if err != nil {
		return nil, fmt.Errorf("error initializing KeyManager: %v", err)
	}

	parameters := km.GetSPHINCSParameters()
	db, err := leveldb.OpenFile("src/core/sphincs/hashtree/leaves_db", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open LevelDB: %v", err)
	}

	// FIXED: NewSTHINCSManager returns *sign.STHINCSManager, which matches the struct field type
	manager := sign.NewSTHINCSManager(db, km, parameters)

	pubKeys := make([][]byte, n)
	privKeys := make([][]byte, n)

	for i := 0; i < n; i++ {
		sk, pk, err := km.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("error generating keys for participant %d: %v", i, err)
		}

		skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
		if err != nil {
			return nil, fmt.Errorf("error serializing key pair for participant %d: %v", i, err)
		}

		pubKeys[i] = pkBytes
		privKeys[i] = skBytes

		log.Printf("Participant %d Public Key: %x", i+1, pkBytes)
		log.Printf("Participant %d Private Key: %x", i+1, skBytes)

		deserializedSK, deserializedPK, err := km.DeserializeKeyPair(skBytes, pkBytes)
		if err != nil {
			return nil, fmt.Errorf("error deserializing key pair for participant %d: %v", i, err)
		}

		if !bytes.Equal(deserializedSK.SKseed, sk.SKseed) || !bytes.Equal(deserializedSK.SKprf, sk.SKprf) ||
			!bytes.Equal(deserializedSK.PKseed, sk.PKseed) || !bytes.Equal(deserializedSK.PKroot, sk.PKroot) {
			return nil, fmt.Errorf("deserialized private key does not match original for participant %d", i)
		}
		if !bytes.Equal(deserializedPK.PKseed, pk.PKseed) || !bytes.Equal(deserializedPK.PKroot, pk.PKroot) {
			return nil, fmt.Errorf("deserialized public key does not match original for participant %d", i)
		}
		log.Printf("Deserialization check passed for participant %d!", i+1)
	}

	return &MultisigManager{
		km:          km,
		manager:     manager,
		quorum:      n,
		signatures:  make(map[string][]byte),
		partyPK:     make(map[string][]byte),
		proofs:      make(map[string][]byte),
		timestamps:  make(map[string][]byte),
		nonces:      make(map[string][]byte),
		merkleRoots: make(map[string][]byte),
		commitments: make(map[string][]byte), // FIX: initialise new map
		storedPK:    pubKeys,
		storedSK:    privKeys,
	}, nil
}

// SignMessage signs a given message for a party and stores all verification
// material including the new 32-byte commitment.
func (m *MultisigManager) SignMessage(message []byte, privKey []byte, partyID string) ([]byte, []byte, []byte, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Printf("Private Key Length: %d", len(privKey))

	// Find matching public key bytes for this private key.
	var matchingPKBytes []byte
	for i, skBytes := range m.storedSK {
		if bytes.Equal(skBytes, privKey) {
			matchingPKBytes = m.storedPK[i]
			break
		}
	}
	if matchingPKBytes == nil {
		return nil, nil, nil, nil, fmt.Errorf("no matching public key found for the provided private key")
	}

	// Deserialize both sk and pk so we can pass pk to SignMessage.
	sk, pk, err := m.km.DeserializeKeyPair(privKey, matchingPKBytes)
	if err != nil {
		log.Printf("Failed to deserialize key pair: %v", err)
		return nil, nil, nil, nil, fmt.Errorf("failed to deserialize key pair: %v", err)
	}

	// FIXED: SignMessage returns 6 values
	sig, merkleRoot, timestamp, nonce, commitment, err := m.manager.SignMessage(message, sk, pk)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to sign message: %v", err)
	}

	// FIXED: SerializeSignature is a method on the signature object, not the manager
	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to serialize signature: %v", err)
	}

	merkleRootBytes := merkleRoot.Hash.Bytes()

	pkBytes, err := pk.SerializePK()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to serialize public key: %v", err)
	}

	// Check for signature reuse before storing anything.
	exists, err := m.manager.CheckTimestampNonce(timestamp, nonce)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to check timestamp-nonce pair for %s: %v", partyID, err)
	}
	if exists {
		return nil, nil, nil, nil, fmt.Errorf("signature reuse detected for %s: timestamp-nonce pair already exists", partyID)
	}

	err = m.manager.StoreTimestampNonce(timestamp, nonce)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to store timestamp-nonce pair: %v", err)
	}

	// Store all per-party material.
	m.signatures[partyID] = sigBytes
	m.partyPK[partyID] = pkBytes
	m.timestamps[partyID] = timestamp
	m.nonces[partyID] = nonce
	m.merkleRoots[partyID] = merkleRootBytes
	m.commitments[partyID] = commitment

	// Fold commitment into proof leaves
	proofLeaves := [][]byte{merkleRootBytes, commitment}
	proof, err := sigproof.GenerateSigProof(
		[][]byte{append(timestamp, append(nonce, message...)...)},
		proofLeaves,
		pkBytes,
	)
	if err != nil {
		log.Printf("Failed to generate proof for partyID %s: %v", partyID, err)
		return nil, nil, nil, nil, fmt.Errorf("failed to generate proof for %s: %v", partyID, err)
	}
	m.proofs[partyID] = proof

	return sigBytes, merkleRootBytes, timestamp, nonce, nil
}

// VerifySignatures checks if enough valid signatures have been collected.
// VerifySignatures checks if enough valid signatures have been collected.
func (m *MultisigManager) VerifySignatures(message []byte) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.signatures) < m.quorum {
		return false, fmt.Errorf("not enough signatures, need at least %d", m.quorum)
	}

	validSignatures := 0

	for partyID, sigBytes := range m.signatures {
		publicKey := m.partyPK[partyID]
		timestamp := m.timestamps[partyID]
		nonce := m.nonces[partyID]
		merkleRootBytes := m.merkleRoots[partyID]
		commitment := m.commitments[partyID]

		if publicKey == nil || timestamp == nil || nonce == nil || merkleRootBytes == nil {
			return false, fmt.Errorf("missing public key, timestamp, nonce, or Merkle root for %s", partyID)
		}
		if len(commitment) != 32 {
			return false, fmt.Errorf("missing or malformed commitment for %s", partyID)
		}

		// Freshness check (5-minute window).
		timestampInt := binary.BigEndian.Uint64(timestamp)
		currentTimestamp := uint64(time.Now().Unix())
		if currentTimestamp-timestampInt > 300 {
			return false, fmt.Errorf("timestamp for %s is too old, possible reuse attempt", partyID)
		}

		deserializedPK, err := m.km.DeserializePublicKey(publicKey)
		if err != nil {
			return false, fmt.Errorf("error deserializing public key for %s: %v", partyID, err)
		}

		// FIXED: Use sthincs.DeserializeSignature instead of sign.DeserializeSignature
		// You need to import the sthincs package at the top of the file
		sig, err := sthincs.DeserializeSignature(m.km.GetSPHINCSParameters().Params, sigBytes)
		if err != nil {
			return false, fmt.Errorf("error deserializing signature for %s: %v", partyID, err)
		}

		merkleRoot := &hashtree.HashTreeNode{Hash: uint256.NewInt(0).SetBytes(merkleRootBytes)}

		// Verify the signature
		isValidSig := m.manager.VerifySignature(message, timestamp, nonce, sig, deserializedPK, merkleRoot, commitment, false)
		if isValidSig {
			validSignatures++
		} else {
			return false, fmt.Errorf("signature from participant %s is invalid", partyID)
		}
	}

	if validSignatures < m.quorum {
		return false, fmt.Errorf("not enough valid signatures to meet the quorum")
	}

	return true, nil
}

// ValidateProof validates the proof for a specific participant.
func (m *MultisigManager) ValidateProof(partyID string, message []byte) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	storedProof, exists := m.proofs[partyID]
	if !exists {
		return false, fmt.Errorf("no proof found for participant %s", partyID)
	}

	merkleRootHash := m.merkleRoots[partyID]
	timestamp := m.timestamps[partyID]
	nonce := m.nonces[partyID]
	commitment := m.commitments[partyID]
	if merkleRootHash == nil || timestamp == nil || nonce == nil {
		return false, fmt.Errorf("missing Merkle root, timestamp, or nonce for %s", partyID)
	}
	if len(commitment) != 32 {
		return false, fmt.Errorf("missing or malformed commitment for %s", partyID)
	}

	resultChan := make(chan bool, 1)

	go func() {
		proofLeaves := [][]byte{merkleRootHash, commitment}
		regeneratedProof, err := sigproof.GenerateSigProof(
			[][]byte{append(timestamp, append(nonce, message...)...)},
			proofLeaves,
			m.partyPK[partyID],
		)
		if err != nil {
			log.Printf("Failed to regenerate proof for participant %s: %v", partyID, err)
			resultChan <- false
			return
		}
		resultChan <- sigproof.VerifySigProof(storedProof, regeneratedProof)
	}()

	isValidProof := <-resultChan
	if !isValidProof {
		return false, fmt.Errorf("proof for participant %s is invalid", partyID)
	}
	return true, nil
}
