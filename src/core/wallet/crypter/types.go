// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/wallet/crypter/types.go
package crypter

import "github.com/holiman/uint256"

// MasterKey represents the structure of a master key,
// used in cryptographic operations for deriving encryption keys.
type MasterKey struct {
	// VchCryptedKey holds the encrypted version of the private key or master key.
	// "Vch" stands for "vector of characters" (or bytes) often used for byte slices in cryptographic contexts.
	VchCryptedKey []byte `json:"vchCryptedKey"`

	// VchSalt contains the salt used during key derivation to add randomness and strengthen security.
	// "Vch" again refers to a byte slice (vector of characters).
	VchSalt []byte `json:"vchSalt"`

	// NDerivationMethod specifies the method used for deriving keys (e.g., PBKDF2, scrypt).
	// "N" is a common notation for numeric values or counts.
	NDerivationMethod uint32 `json:"nDerivationMethod"`

	// NDeriveIterations defines how many iterations are applied during key derivation,
	// typically used to increase computational cost and security.
	NDeriveIterations uint32 `json:"nDeriveIterations"`

	// VchOtherDerivationParameters is an additional byte slice that holds any other parameters
	// required by the derivation method, if applicable.
	VchOtherDerivationParameters []byte `json:"vchOtherDerivationParameters"`
}

// CCrypter handles AES encryption and decryption with key and IV.
type CCrypter struct {
	vchKey  []byte
	vchIV   []byte
	fKeySet bool
}

// Uint256 represents a 256-bit unsigned integer.
type Uint256 struct {
	uint256 *uint256.Int
}
