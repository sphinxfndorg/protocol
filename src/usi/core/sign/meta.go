// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/sign/meta.go
package sign

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// NewMeta creates a new Meta with random nonce
func NewMeta(sig *Signature, fileHash []byte) (*Meta, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &Meta{
		Signature: hex.EncodeToString(sig.Signature),
		PublicKey: hex.EncodeToString(sig.PublicKey),
		Nonce:     hex.EncodeToString(nonce),
		Timestamp: time.Now().Unix(),
		FileHash:  hex.EncodeToString(fileHash),
	}, nil
}
