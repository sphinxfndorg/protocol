// go/src/usi/core/key/kem.go
package keys

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
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
// GENERATE KEM KEYS
// ─────────────────────────────────────────────

// GenerateKEMKeys generates a hybrid X25519+Kyber768 KEM keypair.
// Returns (kemPublicKey, kemPrivateKey, error) as merged blobs.
func GenerateKEMKeys() ([]byte, []byte, error) {
	log.Println("[KEM] Generating hybrid X25519+Kyber768 keypair")

	// ── 1. Generate Kyber768 keypair ─────────────────────────────────────────
	scheme := kyber768.Scheme()
	kyberPub, kyberPriv, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generate Kyber768 key pair: %w", err)
	}
	kyberPubBytes, err := kyberPub.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("serialize Kyber768 public key: %w", err)
	}
	kyberPrivBytes, err := kyberPriv.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("serialize Kyber768 private key: %w", err)
	}
	defer zeroBytes(kyberPrivBytes)

	// ── 2. Generate X25519 keypair ───────────────────────────────────────────
	x25519Priv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(x25519Priv); err != nil {
		return nil, nil, fmt.Errorf("generate X25519 private key: %w", err)
	}
	defer zeroBytes(x25519Priv)

	// Clamp scalar per RFC 7748 §5
	x25519Priv[0] &= 248
	x25519Priv[31] &= 127
	x25519Priv[31] |= 64

	x25519Pub, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("derive X25519 public key: %w", err)
	}

	// ── 3. Merge into single blobs ───────────────────────────────────────────
	pubBlob := marshalHybridKey(x25519Pub, kyberPubBytes)
	privBlob := marshalHybridKey(x25519Priv, kyberPrivBytes)
	defer zeroBytes(privBlob)

	log.Printf("[KEM] KEM keys generated successfully (public: %d bytes, private: %d bytes)",
		len(pubBlob), len(privBlob))

	return pubBlob, privBlob, nil
}

// ─────────────────────────────────────────────
// LOAD KEM KEYS
// ─────────────────────────────────────────────

// LoadKEMPublicKey returns the merged X25519+Kyber768 public key blob.
// This function looks for KEM public key in the SPHINCS+ key file metadata first.
func LoadKEMPublicKey() ([]byte, error) {
	log.Println("[KEM] Loading KEM public key")

	// Try to load from SPHINCS+ key file metadata first
	keyIDs, err := ListKeys()
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}

	if len(keyIDs) > 0 {
		// Find the main SPHINCS+ key (skip KEM-only keys)
		var mainKeyID string
		for _, id := range keyIDs {
			if len(id) > 4 && id[:4] == "kem_" {
				continue
			}
			mainKeyID = id
			break
		}

		if mainKeyID != "" {
			loadedKeyPair, err := diskStorage.GetKey(mainKeyID)
			if err == nil && loadedKeyPair.Metadata != nil {
				if kemPubB64, ok := loadedKeyPair.Metadata["kem_public"].(string); ok {
					kemPub, err := base64.StdEncoding.DecodeString(kemPubB64)
					if err == nil && len(kemPub) > 0 {
						log.Printf("[KEM] KEM public key loaded from SPHINCS+ key file (%d bytes)", len(kemPub))
						return kemPub, nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("KEM public key not found")
}

// LoadKEMPrivateKey decrypts the stored KEM key and returns both halves
// of the hybrid keypair.
// This function looks for KEM private key in the combined SPHINCS+ key file.
//
// Returns (x25519PrivateKey, kyber768PrivateKey, error).
func LoadKEMPrivateKey(passphrase, fingerprint string) ([]byte, []byte, error) {
	log.Println("[KEM] Loading KEM private key")

	// Load from SPHINCS+ key file (combined storage)
	kp, _, err := LoadKeyFromDisk(passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("load key pair: %w", err)
	}

	if len(kp.KEMPrivateKey) == 0 {
		return nil, nil, fmt.Errorf("KEM private key not found in key file")
	}

	x25519Priv, kyberPriv, err := SplitHybridKey(kp.KEMPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("malformed hybrid KEM private key: %w", err)
	}

	if len(x25519Priv) != curve25519.ScalarSize {
		zeroBytes(x25519Priv)
		zeroBytes(kyberPriv)
		return nil, nil, fmt.Errorf("X25519 private key has wrong length: got %d, want %d",
			len(x25519Priv), curve25519.ScalarSize)
	}

	log.Println("[KEM] KEM private key loaded from combined SPHINCS+ key file")
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
