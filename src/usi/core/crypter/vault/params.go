// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/crypter/vault/params.go
package vault

// DefaultKeyDerivationParams provides secure default parameters for Argon2id
var DefaultKeyDerivationParams = KeyDerivationParams{
	Time:    3,
	Memory:  64 * 1024, // 64 MB
	Threads: 4,
	KeyLen:  32, // 256 bits for AES-256
}
