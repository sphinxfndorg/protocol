// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/sphincs/sign/backend/serialize.go
package sign

import (
	"errors"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
)

// SIPS-0011 https://github.com/sphinxorg/SIPS/wiki/sips0011

// SerializeSignature serializes the SPHINCS+ signature into a byte slice.
func (sm *SphincsManager) SerializeSignature(sig *sthincs.SPHINCS_SIG) ([]byte, error) {
	return sig.SerializeSignature()
}

// DeserializeSignature deserializes a byte slice back into a SPHINCS_SIG struct.
func (sm *SphincsManager) DeserializeSignature(sigBytes []byte) (*sthincs.SPHINCS_SIG, error) {
	if sm.parameters == nil || sm.parameters.Params == nil {
		return nil, errors.New("SPHINCSParameters are not initialized")
	}
	return sthincs.DeserializeSignature(sm.parameters.Params, sigBytes)
}
