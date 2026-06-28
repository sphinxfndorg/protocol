// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/sign/types.go
package sign

import "github.com/sphinxfndorg/protocol/src/usi/core/types"

// Re-export Meta from types package for backward compatibility
type Meta = types.Meta

// Signature holds the raw SPHINCS+ signature bytes together with the
// public key that should be used for verification.
type Signature struct {
	Signature []byte `json:"sig"`
	PublicKey []byte `json:"pk,omitempty"`
}
