// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/sphincs/key/backend/types.go
package key

import params "github.com/sphinxorg/protocol/src/core/sthincs/config"

// SPHINCS_SK represents a SPHINCS private key structure.
type SPHINCS_SK struct {
	SKseed []byte
	SKprf  []byte
	PKseed []byte
	PKroot []byte
}

// KeyManager is responsible for managing key generation using SPHINCS+ parameters.
type KeyManager struct {
	Params *params.STHINCSParameters // Holds SPHINCS+ parameters.
}
