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

	// KEM keys (Kyber768+X25519) for post-quantum key exchange
	// These are stored in the same encrypted file as the SPHINCS+ key
	KEMPublicKey  []byte `json:"kem_public_key,omitempty"`
	KEMPrivateKey []byte `json:"kem_private_key,omitempty"`
}
