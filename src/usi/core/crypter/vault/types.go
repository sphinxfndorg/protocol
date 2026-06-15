// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/crypter/vault/types.go
package vault

// -----------------------------------------------------------------------------
// Shared vault types — single source of truth for the entire vault package.
// No other file in this package should redeclare these types.
// -----------------------------------------------------------------------------

// fileEntry records the path and integrity hash of one file inside a vault.
type fileEntry struct {
	Path     string `json:"path"`
	Size     int64  `json:"size,omitempty"`
	ModTime  string `json:"modTime,omitempty"`
	FileHash string `json:"fileHash"`
}

// RecipientEntry stores per-recipient key material in the vault manifest.
//
//   - V2 vaults: Fingerprint + WrappedKey only.
//   - V3 vaults: Fingerprint + X25519Ciphertext + KyberCiphertext.
//
// X25519Ciphertext layout (V3):
//
//	ephemeralSenderPub (32 B) || nonce (12 B) || AES-256-GCM(sessionKey)+tag
type RecipientEntry struct {
	// Fingerprint is the hex-encoded SHA3-256 of the recipient's public key.
	Fingerprint string `json:"fingerprint"`

	// V2: session key wrapped with fingerprint-as-KEK (AES-256-GCM).
	WrappedKey []byte `json:"wrapped_key,omitempty"`

	// V3: hybrid KEM ciphertext components.
	X25519Ciphertext []byte `json:"x25519_ciphertext,omitempty"`
	KyberCiphertext  []byte `json:"kyber_ciphertext,omitempty"`
}

// manifest is the JSON header prepended to every vault file.
//
// JSON tag naming convention: snake_case throughout.
// Legacy vaults may use camelCase tags — the decoder tolerates both because
// Go's encoding/json matches field names case-insensitively.
type manifest struct {
	Version      int              `json:"version,omitempty"`
	Timestamp    string           `json:"timestamp"`
	OriginalName string           `json:"original_name"`
	Checksum     []byte           `json:"checksum"`
	Signature    []byte           `json:"signature,omitempty"`
	PublicKey    []byte           `json:"public_key,omitempty"`
	Recipients   []RecipientEntry `json:"recipients,omitempty"`
	Files        []fileEntry      `json:"files"`

	// Legacy / V1-V2 fields — kept for backward-compatible decryption.
	Salt      []byte `json:"salt,omitempty"`
	FolderKey []byte `json:"folder_key,omitempty"`
}

// HybridPublicKey carries a recipient's ephemeral public keys for one
// encryption session.  It is never persisted; it is exchanged out-of-band
// (e.g. over the wire) and discarded after encryption.
type HybridPublicKey struct {
	// Fingerprint is set by the sender after ValidateAndNormalizeRecipients.
	Fingerprint string

	// X25519Pub is the 32-byte Curve25519 public key.
	X25519Pub []byte

	// KyberPub is the Kyber768 public key bytes.
	KyberPub []byte
}

// SecureBuffer wraps a sensitive byte slice so it can be explicitly zeroed.
type SecureBuffer struct {
	data []byte
}

// KeyDerivationParams is reserved for future Argon2id tuning.
// The vault currently delegates to keys.DeriveKeyFromPassphrase, which has
// its own fixed parameters, so these fields are intentionally unused.
type KeyDerivationParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}
