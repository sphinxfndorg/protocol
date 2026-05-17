// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/stark/zk/sign.go
package zk

import (
	"encoding/hex"
	"fmt"

	params "github.com/sphinxorg/protocol/src/core/sthincs/config"
	key "github.com/sphinxorg/protocol/src/core/sthincs/key/backend"

	// FIXED: Change from SPHINCSPLUS-golang to STHINCS
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/sthincs"
)

// NewSignWrapper initializes a new SignWrapper.
func NewSigner() *Signer {
	return &Signer{}
}

// SignMessage signs a message using the provided SPHINCS+ parameters and secret key.
// FIXED: Changed parameter type from *params.SPHINCSParameters to *params.STHINCSParameters
func (sw *Signer) SignMessage(sphincsParams *params.STHINCSParameters, message []byte, sk *key.SPHINCS_SK) (*sthincs.SPHINCS_SIG, error) {
	// FIXED: Use sthincs.SPHINCS_SK
	sphincsSK := &sthincs.SPHINCS_SK{
		SKseed: sk.SKseed,
		SKprf:  sk.SKprf,
		PKseed: sk.PKseed,
		PKroot: sk.PKroot,
	}
	// FIXED: Use sthincs.Spx_sign
	sig, err := sthincs.Spx_sign(sphincsParams.Params, message, sphincsSK)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %v", err)
	}
	if sig == nil {
		return nil, fmt.Errorf("failed to sign message: signature is nil")
	}
	return sig, nil
}

// VerifySignature verifies a SPHINCS+ signature for a given message and public key.
// FIXED: Changed parameter type from *params.SPHINCSParameters to *params.STHINCSParameters
func (sw *Signer) VerifySignature(sphincsParams *params.STHINCSParameters, message []byte, sig *sthincs.SPHINCS_SIG, pk *sthincs.SPHINCS_PK) (bool, error) {
	// FIXED: Use sthincs.Spx_verify
	valid := sthincs.Spx_verify(sphincsParams.Params, message, sig, pk)
	return valid, nil
}

// SerializeSignature serializes a SPHINCS+ signature and returns its hex representation and size.
func (sw *Signer) SerializeSignature(sig *sthincs.SPHINCS_SIG) (sigHex string, sigSize float64, err error) {
	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		return "", 0, fmt.Errorf("failed to serialize signature: %v", err)
	}
	return hex.EncodeToString(sigBytes), float64(len(sigBytes)) / 1024.0, nil
}

// DeserializeSignature deserializes a SPHINCS+ signature from bytes.
// FIXED: Changed parameter type from *params.SPHINCSParameters to *params.STHINCSParameters
func (sw *Signer) DeserializeSignature(sphincsParams *params.STHINCSParameters, sigBytes []byte) (*sthincs.SPHINCS_SIG, error) {
	sig, err := sthincs.DeserializeSignature(sphincsParams.Params, sigBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize signature: %v", err)
	}
	return sig, nil
}
