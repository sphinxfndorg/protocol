// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/crypter/key/types.go
package crypter

// KeyDerivationParams holds parameters for Argon2id key derivation
type KeyDerivationParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

// SecureBuffer provides a way to manage sensitive data in memory
type SecureBuffer struct {
	data []byte
}
