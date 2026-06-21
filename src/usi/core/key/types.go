// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/key/types.go
package keys

// KeyPair holds the SPHINCS+ public key, the passphrase-encrypted private key,
// the organisation code, and the address.
// Note: Salt is no longer stored separately - it's embedded in the encrypted blob
// by diskStorage.EncryptData (matching the wallet pattern).
type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
	Path       string

	// OrgCode identifies which organisation this key belongs to.
	// It is persisted and used to format the human-readable address.
	// Empty string means a legacy key created before the org-address system.
	OrgCode string

	// Address is the human-readable address derived from the public key and org code
	Address string
}
