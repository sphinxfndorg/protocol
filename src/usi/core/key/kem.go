// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/key/kem.go
package keys

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	crypter "github.com/sphinxorg/protocol/src/usi/core/crypter/key"
	db "github.com/sphinxorg/protocol/src/usi/core/dbkey"
	"golang.org/x/crypto/curve25519"
)

const (
	kemPublicDBKey = "kem_public" // merged X25519+Kyber768 public key blob
	kemSaltDBKey   = "kem_salt"   // shared salt for the hybrid keypair
)

// Hybrid KEM private key wire format (stored in KEMDatPath after encryption):
//
//	[ 2 bytes: X25519 len (little-endian uint16) ]
//	[ X25519 private key  (32 bytes)             ]
//	[ Kyber768 private key (remaining bytes)     ]
//
// Hybrid KEM public key wire format (stored in KEMDBPath):
//
//	[ 2 bytes: X25519 len (little-endian uint16) ]
//	[ X25519 public key  (32 bytes)              ]
//	[ Kyber768 public key (remaining bytes)      ]

// ─────────────────────────────────────────────
// GENERATE & STORE
// ─────────────────────────────────────────────

// GenerateAndStoreKEMKey generates a hybrid X25519+Kyber768 KEM keypair,
// merges both halves into a single blob, and encrypts it with a single
// passphrase-derived key — one salt, one .dat file, one DB entry.
//
// Derivation mirrors key.go:
//
//	GeneratePureSalt → DeriveKeyFromPassphrase → SecureEncryptWithKey
func GenerateAndStoreKEMKey(passphrase string) error {
	// ── 1. Generate Kyber768 keypair ─────────────────────────────────────────
	scheme := kyber768.Scheme()
	kyberPub, kyberPriv, err := scheme.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate Kyber768 key pair: %w", err)
	}
	kyberPubBytes, err := kyberPub.MarshalBinary()
	if err != nil {
		return fmt.Errorf("serialize Kyber768 public key: %w", err)
	}
	kyberPrivBytes, err := kyberPriv.MarshalBinary()
	if err != nil {
		return fmt.Errorf("serialize Kyber768 private key: %w", err)
	}
	defer zeroBytes(kyberPrivBytes)

	// ── 2. Generate X25519 keypair ───────────────────────────────────────────
	x25519Priv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(x25519Priv); err != nil {
		return fmt.Errorf("generate X25519 private key: %w", err)
	}
	defer zeroBytes(x25519Priv)

	// Clamp scalar per RFC 7748 §5
	x25519Priv[0] &= 248
	x25519Priv[31] &= 127
	x25519Priv[31] |= 64

	x25519Pub, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("derive X25519 public key: %w", err)
	}

	// ── 3. Merge into single blobs ───────────────────────────────────────────
	privBlob := marshalHybridKey(x25519Priv, kyberPrivBytes)
	defer zeroBytes(privBlob)

	pubBlob := marshalHybridKey(x25519Pub, kyberPubBytes)

	// ── 4. Derive single encryption key ─────────────────────────────────────
	salt, err := GeneratePureSalt(32)
	if err != nil {
		return fmt.Errorf("generate KEM salt: %w", err)
	}

	derivedKey := DeriveKeyFromPassphrase(passphrase, salt)
	secureKey := crypter.NewSecureBuffer(derivedKey)
	defer secureKey.Clear()

	// ── 5. Encrypt merged private key blob ───────────────────────────────────
	encPrivBlob, err := crypter.SecureEncryptWithKey(privBlob, secureKey)
	if err != nil {
		return fmt.Errorf("encrypt hybrid KEM private key: %w", err)
	}

	// ── 6. Persist to disk (single file) ─────────────────────────────────────
	if err := os.MkdirAll(KEMKeyDir, 0700); err != nil {
		return fmt.Errorf("create KEM key directory: %w", err)
	}
	if err := os.WriteFile(KEMDatPath, encPrivBlob, 0600); err != nil {
		return fmt.Errorf("write hybrid KEM private key: %w", err)
	}

	// ── 7. Persist merged public key blob and salt to database ───────────────
	database, err := db.Open(KEMDBPath)
	if err != nil {
		return fmt.Errorf("open KEM database: %w", err)
	}
	defer database.Close()

	if err := database.Put([]byte(kemPublicDBKey), pubBlob); err != nil {
		return fmt.Errorf("store hybrid KEM public key: %w", err)
	}
	if err := database.Put([]byte(kemSaltDBKey), salt); err != nil {
		return fmt.Errorf("store KEM salt: %w", err)
	}

	return nil
}

// ─────────────────────────────────────────────
// LOAD
// ─────────────────────────────────────────────

// LoadRegistrarKEMPublicKey is an alias for LoadKEMPublicKey.
// Deprecated: use LoadKEMPublicKey.
func LoadRegistrarKEMPublicKey() ([]byte, error) {
	return LoadKEMPublicKey()
}

// LoadKEMPublicKey returns the merged X25519+Kyber768 public key blob.
// Use SplitHybridKey to extract each half.
func LoadKEMPublicKey() ([]byte, error) {
	database, err := db.Open(KEMDBPath)
	if err != nil {
		return nil, fmt.Errorf("open KEM database: %w", err)
	}
	defer database.Close()

	pub, err := database.Get([]byte(kemPublicDBKey))
	if err != nil {
		return nil, fmt.Errorf("retrieve hybrid KEM public key: %w", err)
	}
	return pub, nil
}

// LoadKEMPrivateKey decrypts the single kem.dat blob and returns both halves
// of the hybrid keypair.
//
// fingerprint is reserved for future per-recipient key selection and is
// currently unused in the lookup.
//
// Returns (x25519PrivateKey, kyber768PrivateKey, error).
func LoadKEMPrivateKey(passphrase, fingerprint string) ([]byte, []byte, error) {
	// ── Recover shared salt ──────────────────────────────────────────────────
	database, err := db.Open(KEMDBPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open KEM database: %w", err)
	}
	defer database.Close()

	salt, err := database.Get([]byte(kemSaltDBKey))
	if err != nil {
		return nil, nil, fmt.Errorf("retrieve KEM salt: %w", err)
	}

	// ── Re-derive encryption key and decrypt blob ─────────────────────────────
	derivedKey := DeriveKeyFromPassphrase(passphrase, salt)
	secureKey := crypter.NewSecureBuffer(derivedKey)
	defer secureKey.Clear()

	encPrivBlob, err := os.ReadFile(KEMDatPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read hybrid KEM private key: %w", err)
	}

	privBlob, err := crypter.SecureDecryptWithKey(encPrivBlob, secureKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt hybrid KEM private key (wrong passphrase or corrupted key): %w", err)
	}
	defer zeroBytes(privBlob)

	// ── Split merged blob into X25519 and Kyber768 halves ────────────────────
	x25519Priv, kyberPriv, err := SplitHybridKey(privBlob)
	if err != nil {
		return nil, nil, fmt.Errorf("malformed hybrid KEM private key: %w", err)
	}

	if len(x25519Priv) != curve25519.ScalarSize {
		zeroBytes(x25519Priv)
		zeroBytes(kyberPriv)
		return nil, nil, fmt.Errorf("X25519 private key has wrong length: got %d, want %d",
			len(x25519Priv), curve25519.ScalarSize)
	}

	return x25519Priv, kyberPriv, nil
}

// ─────────────────────────────────────────────
// HYBRID KEY ENCODING
// ─────────────────────────────────────────────

// marshalHybridKey encodes two key halves into a single blob:
//
//	[ uint16 LE: len(first) ] [ first ] [ second ]
func marshalHybridKey(first, second []byte) []byte {
	buf := make([]byte, 2+len(first)+len(second))
	binary.LittleEndian.PutUint16(buf[0:2], uint16(len(first)))
	copy(buf[2:], first)
	copy(buf[2+len(first):], second)
	return buf
}

// SplitHybridKey decodes a blob produced by marshalHybridKey.
// Returns (first, second, error).
func SplitHybridKey(blob []byte) ([]byte, []byte, error) {
	if len(blob) < 2 {
		return nil, nil, errors.New("blob too short for hybrid key header")
	}
	firstLen := int(binary.LittleEndian.Uint16(blob[0:2]))
	if len(blob) < 2+firstLen {
		return nil, nil, fmt.Errorf("blob too short: need %d bytes for first key, have %d",
			2+firstLen, len(blob))
	}
	first := make([]byte, firstLen)
	copy(first, blob[2:2+firstLen])
	second := make([]byte, len(blob)-(2+firstLen))
	copy(second, blob[2+firstLen:])
	return first, second, nil
}

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

// zeroBytes overwrites a byte slice with zeros to clear sensitive data from memory.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
