// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/key/kem.go
package keys

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/sphinxorg/protocol/src/accounts/key"
	"golang.org/x/crypto/curve25519"
)

// Hybrid KEM private key wire format (stored after encryption):
//
//	[ 2 bytes: X25519 len (little-endian uint16) ]
//	[ X25519 private key  (32 bytes)             ]
//	[ Kyber768 private key (remaining bytes)     ]
//
// Hybrid KEM public key wire format:
//
//	[ 2 bytes: X25519 len (little-endian uint16) ]
//	[ X25519 public key  (32 bytes)              ]
//	[ Kyber768 public key (remaining bytes)      ]

// ─────────────────────────────────────────────
// GENERATE & STORE
// ─────────────────────────────────────────────

// GenerateAndStoreKEMKey generates a hybrid X25519+Kyber768 KEM keypair,
// merges both halves into a single blob, and encrypts it using the storage
// manager pattern (diskStorage.EncryptData).
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

	// ── 4. Encrypt merged private key blob using diskStorage.EncryptData ─────
	// This matches the pattern in test_encrypt.go
	encPrivBlob, err := diskStorage.EncryptData(privBlob, passphrase)
	if err != nil {
		return fmt.Errorf("encrypt hybrid KEM private key: %w", err)
	}

	// ── 5. Store encrypted key using diskStorage.StoreEncryptedKey ──────────
	// Generate an address for the KEM key
	address := "kem_" + fmt.Sprintf("%x", pubBlob[:8])

	storedKeyPair, err := diskStorage.StoreEncryptedKey(
		encPrivBlob,
		pubBlob,
		address,
		key.WalletTypeDisk,
		7331, // Sphinx Mainnet chain ID
		"",   // derivation path
		nil,  // additional data
	)
	if err != nil {
		return fmt.Errorf("store encrypted KEM key: %w", err)
	}

	// Store public key blob in a separate entry
	_, err = diskStorage.StoreEncryptedKey(
		pubBlob,
		pubBlob,
		"kem_public",
		key.WalletTypeDisk,
		7331,
		"",
		nil,
	)
	if err != nil {
		log.Printf("Warning: failed to store KEM public key separately: %v", err)
	}

	log.Printf("KEM key stored successfully with ID: %s", storedKeyPair.ID)
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
	// Try to load the KEM public key by ID
	keys, err := ListKeys()
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}

	for _, keyID := range keys {
		if len(keyID) > 11 && keyID[:11] == "kem_public_" {
			loadedKey, err := diskStorage.GetKey(keyID)
			if err != nil {
				continue
			}
			return loadedKey.PublicKey, nil
		}
	}

	return nil, fmt.Errorf("KEM public key not found")
}

// LoadKEMPrivateKey decrypts the stored KEM key and returns both halves
// of the hybrid keypair using the storage manager pattern.
//
// fingerprint is reserved for future per-recipient key selection and is
// currently unused in the lookup.
//
// Returns (x25519PrivateKey, kyber768PrivateKey, error).
func LoadKEMPrivateKey(passphrase, fingerprint string) ([]byte, []byte, error) {
	// ── Find the KEM key ──────────────────────────────────────────────────
	keys, err := ListKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("list keys: %w", err)
	}

	var kemKeyID string
	for _, keyID := range keys {
		if len(keyID) > 4 && keyID[:4] == "kem_" && keyID != "kem_public" {
			kemKeyID = keyID
			break
		}
	}

	if kemKeyID == "" {
		return nil, nil, fmt.Errorf("KEM private key not found")
	}

	// ── Load the encrypted key ──────────────────────────────────────────────
	loadedKeyPair, err := diskStorage.GetKey(kemKeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("load KEM key: %w", err)
	}

	// ── Decrypt using diskStorage.DecryptKey ─────────────────────────────────
	privBlob, err := diskStorage.DecryptKey(loadedKeyPair, passphrase)
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
