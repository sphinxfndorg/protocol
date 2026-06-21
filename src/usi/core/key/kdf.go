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
// IMPORTANT — this is NOT the KDF used by key.go / kem.go in this package.
// Those two route through diskStorage (disk.DiskKeyStore, see local.go),
// which derives its key very differently:
//
//	disk.DiskKeyStore.generateSalt(passphrase):
//	    Argon2id(passphrase, "sphinx-disk-keystore-salt", time=3,
//	             memory=64MiB, threads=2, outLen=16)   -> a 16-byte SALT,
//	             deterministically re-derived from the passphrase alone
//	             (never random, never stored/passed in by the caller)
//	then:
//	    CCrypter.SetKeyFromPassphrase(passphrase, thatSalt, 1000)
//	    -> BytesToKeySHA512AES: 1000 rounds of SHA3-512(passphrase||salt)
//	    -> split into a 32-byte AES key + 16-byte IV
//
// That's Argon2id feeding a second SHA3-512-stretching stage, with threads=2
// and a 16-byte output used only as a salt — structurally different from
// (and not parameter-compatible with) this function. Do not call this
// function expecting it to match what diskStorage encrypted, and vice versa.
//
// DeriveKeyFromPassphrase exists solely for vault.deriveKey (see
// vault/utils.go), which — unlike disk.DiskKeyStore — generates its own
// random salt up front and persists it in the manifest (manifest.Salt),
// then passes that same salt back in here on decrypt. Because vault owns
// and stores its salt itself, this function does not need disk.go's
// self-deriving-salt trick; it only needs to be a deterministic function of
// (passphrase, salt) — which Argon2id already is, given fixed parameters.
//
// Parameters here intentionally match vault.DefaultKeyDerivationParams
// (time=3, memory=64 MiB, threads=4, keyLen=32). Keep the two in sync if
// either changes, since vault.deriveKey ignores its own params argument and
// defers entirely to the constants below.
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
