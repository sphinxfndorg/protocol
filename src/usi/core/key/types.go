// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/key/types.go
package keys

// KeyPair holds the SPHINCS+ public key, the passphrase-encrypted private key,
// the salt used for key derivation, and the organisation code chosen at
// registration time.
type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
	Salt       []byte
	Path       string

	// OrgCode identifies which organisation this key belongs to.
	// It is persisted in LevelDB and used to format the human-readable address.
	// Empty string means a legacy key created before the org-address system.
	OrgCode string
}
