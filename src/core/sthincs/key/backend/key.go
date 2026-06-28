// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/sphincs/key/backend/key.go
package key

import (
	"errors"
	"fmt"
	"log"

	params "github.com/sphinxfndorg/protocol/src/core/sthincs/config"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
)

// NewKeyManager initializes a new KeyManager instance using SPHINCS+ parameters.
func NewKeyManager() (*KeyManager, error) {
	spxParams, err := params.NewSTHINCSParameters()
	if err != nil {
		log.Printf("NewKeyManager: Failed to initialize SPHINCS parameters: %v", err)
		return nil, err
	}
	return &KeyManager{Params: spxParams}, nil
}

// Getter method for SPHINCS parameters
func (km *KeyManager) GetSPHINCSParameters() *params.STHINCSParameters {
	return km.Params
}

// GenerateKey generates a new SPHINCS+ private and public key pair.
func (km *KeyManager) GenerateKey() (*SPHINCS_SK, *sthincs.SPHINCS_PK, error) {
	// Ensure parameters are initialized.
	if km.Params == nil || km.Params.Params == nil {
		log.Printf("GenerateKey: Missing SPHINCS+ parameters in KeyManager")
		return nil, nil, errors.New("missing SPHINCS+ parameters in KeyManager")
	}

	// Generate the SPHINCS+ key pair using the configured parameters.
	// FIX: Capture all 3 return values from Spx_keygen
	sk, pk, err := sthincs.Spx_keygen(km.Params.Params)
	if err != nil {
		log.Printf("GenerateKey: Key generation failed: %v", err)
		return nil, nil, fmt.Errorf("key generation failed: %w", err)
	}

	if sk == nil || pk == nil {
		log.Printf("GenerateKey: Key generation failed: returned nil for SK or PK")
		return nil, nil, errors.New("key generation failed: returned nil for SK or PK")
	}

	// Ensure the keys have valid fields.
	if len(sk.SKseed) == 0 || len(sk.SKprf) == 0 || len(sk.PKseed) == 0 || len(sk.PKroot) == 0 {
		log.Printf("GenerateKey: Invalid key fields: SKseed=%d, SKprf=%d, PKseed=%d, PKroot=%d",
			len(sk.SKseed), len(sk.SKprf), len(sk.PKseed), len(sk.PKroot))
		return nil, nil, errors.New("key generation failed: empty key fields")
	}

	log.Printf("GenerateKey: Generated keys: SKseed=%d, SKprf=%d, PKseed=%d, PKroot=%d, PKseed(pub)=%d, PKroot(pub)=%d",
		len(sk.SKseed), len(sk.SKprf), len(sk.PKseed), len(sk.PKroot), len(pk.PKseed), len(pk.PKroot))

	// Wrap and return the generated private and public keys.
	return &SPHINCS_SK{
		SKseed: sk.SKseed,
		SKprf:  sk.SKprf,
		PKseed: sk.PKseed,
		PKroot: sk.PKroot,
	}, pk, nil
}

// SerializeSK serializes the SPHINCS private key to a byte slice.
func (sk *SPHINCS_SK) SerializeSK() ([]byte, error) {
	if sk == nil {
		log.Printf("SerializeSK: Private key is nil")
		return nil, errors.New("private key is nil")
	}

	// Validate key fields
	if len(sk.SKseed) == 0 || len(sk.SKprf) == 0 || len(sk.PKseed) == 0 || len(sk.PKroot) == 0 {
		log.Printf("SerializeSK: Invalid private key fields: SKseed=%d, SKprf=%d, PKseed=%d, PKroot=%d",
			len(sk.SKseed), len(sk.SKprf), len(sk.PKseed), len(sk.PKroot))
		return nil, errors.New("invalid private key: empty fields")
	}

	// Combine the SKseed, SKprf, PKseed, and PKroot into a single byte slice.
	data := append(sk.SKseed, sk.SKprf...)
	data = append(data, sk.PKseed...)
	data = append(data, sk.PKroot...)

	log.Printf("SerializeSK: Serialized private key: length=%d", len(data))
	return data, nil
}

// SerializeKeyPair serializes a SPHINCS private and public key pair to byte slices.
func (km *KeyManager) SerializeKeyPair(sk *SPHINCS_SK, pk *sthincs.SPHINCS_PK) ([]byte, []byte, error) {
	if sk == nil || pk == nil {
		log.Printf("SerializeKeyPair: Private or public key is nil")
		return nil, nil, errors.New("private or public key is nil")
	}

	// Serialize the private key.
	skBytes, err := sk.SerializeSK()
	if err != nil {
		log.Printf("SerializeKeyPair: Failed to serialize private key: %v", err)
		return nil, nil, fmt.Errorf("failed to serialize private key: %v", err)
	}

	// Serialize the public key.
	pkBytes, err := pk.SerializePK()
	if err != nil {
		log.Printf("SerializeKeyPair: Failed to serialize public key: %v", err)
		return nil, nil, fmt.Errorf("failed to serialize public key: %v", err)
	}

	log.Printf("SerializeKeyPair: Serialized keys: PrivateKey length=%d, PublicKey length=%d", len(skBytes), len(pkBytes))
	return skBytes, pkBytes, nil
}

// DeserializeKeyPair reconstructs a SPHINCS private and public key pair from byte slices.
func (km *KeyManager) DeserializeKeyPair(skBytes, pkBytes []byte) (*sthincs.SPHINCS_SK, *sthincs.SPHINCS_PK, error) {
	if km.Params == nil || km.Params.Params == nil {
		log.Printf("DeserializeKeyPair: Missing parameters in KeyManager")
		return nil, nil, errors.New("missing parameters in KeyManager")
	}
	log.Printf("DeserializeKeyPair: PrivateKey length=%d, PublicKey length=%d", len(skBytes), len(pkBytes))
	if len(skBytes) == 0 {
		log.Printf("DeserializeKeyPair: Empty private key bytes")
		return nil, nil, errors.New("empty private key bytes")
	}
	sk, err := sthincs.DeserializeSK(km.Params.Params, skBytes)
	if err != nil {
		log.Printf("DeserializeKeyPair: Failed to deserialize private key: %v", err)
		return nil, nil, fmt.Errorf("failed to deserialize private key: %v", err)
	}
	pk, err := sthincs.DeserializePK(km.Params.Params, pkBytes)
	if err != nil {
		log.Printf("DeserializeKeyPair: Failed to deserialize public key: %v", err)
		return nil, nil, fmt.Errorf("failed to deserialize public key: %v", err)
	}
	log.Printf("DeserializeKeyPair: Successfully deserialized keys: SKseed=%d, SKprf=%d, PKseed=%d, PKroot=%d",
		len(sk.SKseed), len(sk.SKprf), len(sk.PKseed), len(sk.PKroot))
	return sk, pk, nil
}

// DeserializePublicKey deserializes only the public key from byte slices.
func (km *KeyManager) DeserializePublicKey(pkBytes []byte) (*sthincs.SPHINCS_PK, error) {
	if km.Params == nil || km.Params.Params == nil {
		log.Printf("DeserializePublicKey: Missing parameters in KeyManager")
		return nil, errors.New("missing parameters in KeyManager")
	}
	if len(pkBytes) == 0 {
		log.Printf("DeserializePublicKey: Empty public key bytes")
		return nil, errors.New("empty public key bytes")
	}
	// Deserialize the public key from bytes.
	pk, err := sthincs.DeserializePK(km.Params.Params, pkBytes)
	if err != nil {
		log.Printf("DeserializePublicKey: Failed to deserialize public key: %v", err)
		return nil, fmt.Errorf("failed to deserialize public key: %v", err)
	}
	log.Printf("DeserializePublicKey: Successfully deserialized public key: PKseed=%d, PKroot=%d",
		len(pk.PKseed), len(pk.PKroot))
	return pk, nil
}
