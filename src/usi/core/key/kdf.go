// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/key/kdf.go
package keys

import (
	"log"

	"golang.org/x/crypto/argon2"
)

// ─────────────────────────────────────────────────────────────────────────────
// Passphrase-based key derivation (Argon2id) — used by vault ONLY
// ─────────────────────────────────────────────────────────────────────────────
//
// This KDF is used by vault only. key.go / kem.go go through diskStorage,
// which (see src/accounts/key/keysafe) derives Argon2id(passphrase, random
// 16-byte salt, time=3, memory=64MiB, threads=4) -> 32-byte master key and
// then encrypts with crypter.EncryptSecret. Salt is stored in the blob.
//
// Parameters here match vault.DefaultKeyDerivationParams; keep them in sync.
const (
	kdfArgon2Time    uint32 = 3
	kdfArgon2Memory  uint32 = 64 * 1024 // 64 MiB
	kdfArgon2Threads uint8  = 4
	kdfArgon2KeyLen  uint32 = 32 // 256 bits, for AES-256
)

// DeriveKeyFromPassphrase derives a 32-byte AES-256 key from a passphrase and
// a caller-supplied salt, using Argon2id. salt must be at least 16 bytes —
// callers (vault.deriveKey) are expected to validate this before calling.
//
// Used by package vault only — see the package-level note above for why
// key.go / kem.go in this package do NOT use this function.
func DeriveKeyFromPassphrase(passphrase string, salt []byte) []byte {
	log.Printf("[DEBUG] DeriveKeyFromPassphrase: deriving key via Argon2id (salt size: %d bytes)", len(salt))

	key := argon2.IDKey(
		[]byte(passphrase),
		salt,
		kdfArgon2Time,
		kdfArgon2Memory,
		kdfArgon2Threads,
		kdfArgon2KeyLen,
	)

	log.Printf("[DEBUG] DeriveKeyFromPassphrase: derived key size: %d bytes", len(key))
	return key
}
