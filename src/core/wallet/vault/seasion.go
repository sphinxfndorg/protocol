// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/wallet/vault/seasion.go
package vault

// All shared types (HybridPublicKey, RecipientEntry, manifest, SecureBuffer,
// KeyDerivationParams, ManifestVersionVN constants) are declared in types.go.
// Do NOT redeclare them here.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"log"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/curve25519"
)

// -----------------------------------------------------------------------------
// Hybrid KEM — Encrypt session key for one recipient (V3 vaults)
// -----------------------------------------------------------------------------

// EncryptSessionKeyForRecipient wraps sessionKey for a single recipient using
// a hybrid X25519 + Kyber768 KEM.
//
// Output stored in RecipientEntry.X25519Ciphertext:
//
//	ephemeralSenderPub (32 B) || nonce (12 B) || AES-256-GCM(sessionKey)+tag
//
// RecipientEntry.KyberCiphertext holds the raw Kyber768 ciphertext.
// The Kyber shared secret is XORed with the X25519 shared secret to form the
// 32-byte AES key used to encrypt sessionKey.
func EncryptSessionKeyForRecipient(sessionKey []byte, pub *HybridPublicKey) (*RecipientEntry, error) {
	log.Printf("[INFO] EncryptSessionKeyForRecipient: starting hybrid KEM encryption for recipient: %.16s...", pub.Fingerprint[:16])
	log.Printf("[DEBUG] EncryptSessionKeyForRecipient: session key length: %d bytes", len(sessionKey))
	log.Printf("[DEBUG] EncryptSessionKeyForRecipient: X25519 public key length: %d bytes", len(pub.X25519Pub))
	log.Printf("[DEBUG] EncryptSessionKeyForRecipient: Kyber public key length: %d bytes", len(pub.KyberPub))

	if pub == nil {
		log.Printf("[ERROR] EncryptSessionKeyForRecipient: nil public key")
		return nil, errors.New("EncryptSessionKeyForRecipient: nil public key")
	}
	if len(pub.X25519Pub) != 32 {
		log.Printf("[ERROR] EncryptSessionKeyForRecipient: X25519 public key must be 32 bytes, got %d", len(pub.X25519Pub))
		return nil, fmt.Errorf("EncryptSessionKeyForRecipient: X25519 public key must be 32 bytes, got %d", len(pub.X25519Pub))
	}

	// ── X25519 half ──────────────────────────────────────────────────────────

	log.Printf("[DEBUG] EncryptSessionKeyForRecipient: generating ephemeral X25519 key pair")
	// Generate a sender-side ephemeral X25519 key pair.
	ephPriv := make([]byte, 32)
	if _, err := rand.Read(ephPriv); err != nil {
		log.Printf("[ERROR] EncryptSessionKeyForRecipient: failed to generate X25519 ephemeral key: %v", err)
		return nil, fmt.Errorf("generate X25519 ephemeral key: %w", err)
	}
	defer zeroBytes(ephPriv)
	log.Printf("[DEBUG] EncryptSessionKeyForRecipient: ephemeral private key generated")

	// Clamp scalar per RFC 7748 §5.
	ephPriv[0] &= 248
	ephPriv[31] &= 127
	ephPriv[31] |= 64

	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		log.Printf("[ERROR] EncryptSessionKeyForRecipient: failed to compute X25519 ephemeral public key: %v", err)
		return nil, fmt.Errorf("compute X25519 ephemeral public key: %w", err)
	}
	log.Printf("[DEBUG] EncryptSessionKeyForRecipient: ephemeral public key computed (size: %d bytes)", len(ephPub))

	x25519Shared, err := curve25519.X25519(ephPriv, pub.X25519Pub)
	if err != nil {
		log.Printf("[ERROR] EncryptSessionKeyForRecipient: X25519 ECDH failed: %v", err)
		return nil, fmt.Errorf("X25519 ECDH: %w", err)
	}
	defer zeroBytes(x25519Shared)
	log.Printf("[DEBUG] EncryptSessionKeyForRecipient: X25519 shared secret computed (size: %d bytes)", len(x25519Shared))

	// ── Kyber768 half ─────────────────────────────────────────────────────────

	var kyberShared, kyberCT []byte

	if len(pub.KyberPub) > 0 {
		log.Printf("[DEBUG] EncryptSessionKeyForRecipient: performing Kyber768 encapsulation")
		scheme := kyber768.Scheme()
		kyberPubKey, err := scheme.UnmarshalBinaryPublicKey(pub.KyberPub)
		if err != nil {
			log.Printf("[ERROR] EncryptSessionKeyForRecipient: failed to unmarshal Kyber768 public key: %v", err)
			return nil, fmt.Errorf("unmarshal Kyber768 public key: %w", err)
		}
		log.Printf("[DEBUG] EncryptSessionKeyForRecipient: Kyber768 public key unmarshaled")

		ct, ss, err := scheme.Encapsulate(kyberPubKey)
		if err != nil {
			log.Printf("[ERROR] EncryptSessionKeyForRecipient: Kyber768 encapsulation failed: %v", err)
			return nil, fmt.Errorf("Kyber768 encapsulate: %w", err)
		}
		kyberCT = ct
		kyberShared = ss
		defer zeroBytes(kyberShared)
		log.Printf("[DEBUG] EncryptSessionKeyForRecipient: Kyber768 encapsulation complete (ciphertext: %d bytes, shared: %d bytes)", len(kyberCT), len(kyberShared))
	} else {
		log.Printf("[DEBUG] EncryptSessionKeyForRecipient: no Kyber768 public key provided, using X25519 only")
	}

	// ── Combine shared secrets → AES-256 key ─────────────────────────────────

	combinedKey := combineSharedSecrets(x25519Shared, kyberShared)
	defer zeroBytes(combinedKey)
	log.Printf("[DEBUG] EncryptSessionKeyForRecipient: combined shared secret (size: %d bytes)", len(combinedKey))

	// ── Encrypt sessionKey ────────────────────────────────────────────────────

	log.Printf("[DEBUG] EncryptSessionKeyForRecipient: encrypting session key with AES-256-GCM")
	block, err := aes.NewCipher(combinedKey)
	if err != nil {
		log.Printf("[ERROR] EncryptSessionKeyForRecipient: failed to create AES cipher: %v", err)
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[ERROR] EncryptSessionKeyForRecipient: failed to create GCM: %v", err)
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	log.Printf("[DEBUG] EncryptSessionKeyForRecipient: GCM nonce size: %d bytes", gcm.NonceSize())

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		log.Printf("[ERROR] EncryptSessionKeyForRecipient: failed to generate nonce: %v", err)
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	log.Printf("[DEBUG] EncryptSessionKeyForRecipient: nonce generated (size: %d bytes)", len(nonce))

	// Fingerprint is authenticated data — a tampered fingerprint breaks decryption.
	encSessionKey := gcm.Seal(nil, nonce, sessionKey, []byte(pub.Fingerprint))
	log.Printf("[DEBUG] EncryptSessionKeyForRecipient: session key encrypted (ciphertext size: %d bytes)", len(encSessionKey))

	// Layout: ephemeralPub (32) || nonce (12) || ciphertext+tag
	x25519CT := make([]byte, 0, 32+len(nonce)+len(encSessionKey))
	x25519CT = append(x25519CT, ephPub...)
	x25519CT = append(x25519CT, nonce...)
	x25519CT = append(x25519CT, encSessionKey...)
	log.Printf("[DEBUG] EncryptSessionKeyForRecipient: X25519 ciphertext size: %d bytes", len(x25519CT))

	entry := &RecipientEntry{
		Fingerprint:      pub.Fingerprint,
		X25519Ciphertext: x25519CT,
		KyberCiphertext:  kyberCT,
	}

	log.Printf("[SUCCESS] EncryptSessionKeyForRecipient: hybrid KEM wrapped session key for recipient %.16s...", pub.Fingerprint)
	return entry, nil
}

// -----------------------------------------------------------------------------
// Hybrid KEM — Decrypt session key (V3 vaults)
// -----------------------------------------------------------------------------

// DecryptSessionKeyWithPrivates recovers the session key from a V3 RecipientEntry
// using the recipient's ephemeral X25519 and Kyber768 private keys.
func DecryptSessionKeyWithPrivates(entry *RecipientEntry, x25519Priv, kyberPriv []byte) ([]byte, error) {
	log.Printf("[INFO] DecryptSessionKeyWithPrivates: starting hybrid KEM decryption for recipient: %.16s...", entry.Fingerprint[:16])
	log.Printf("[DEBUG] DecryptSessionKeyWithPrivates: X25519 ciphertext length: %d bytes", len(entry.X25519Ciphertext))
	log.Printf("[DEBUG] DecryptSessionKeyWithPrivates: Kyber ciphertext length: %d bytes", len(entry.KyberCiphertext))
	log.Printf("[DEBUG] DecryptSessionKeyWithPrivates: X25519 private key length: %d bytes", len(x25519Priv))
	log.Printf("[DEBUG] DecryptSessionKeyWithPrivates: Kyber private key length: %d bytes", len(kyberPriv))

	if entry == nil {
		log.Printf("[ERROR] DecryptSessionKeyWithPrivates: nil entry")
		return nil, errors.New("DecryptSessionKeyWithPrivates: nil entry")
	}
	// Minimum: ephemeralPub(32) + nonce(12) + AES-GCM tag(16) = 60 bytes.
	if len(entry.X25519Ciphertext) < 60 {
		log.Printf("[ERROR] DecryptSessionKeyWithPrivates: X25519Ciphertext too short: %d bytes (minimum 60)", len(entry.X25519Ciphertext))
		return nil, errors.New("DecryptSessionKeyWithPrivates: X25519Ciphertext too short")
	}
	if len(x25519Priv) != 32 {
		log.Printf("[ERROR] DecryptSessionKeyWithPrivates: x25519 private key must be 32 bytes, got %d", len(x25519Priv))
		return nil, fmt.Errorf("DecryptSessionKeyWithPrivates: x25519 private key must be 32 bytes, got %d", len(x25519Priv))
	}

	// ── X25519 half ──────────────────────────────────────────────────────────

	log.Printf("[DEBUG] DecryptSessionKeyWithPrivates: extracting ephemeral public key from ciphertext")
	ephPub := entry.X25519Ciphertext[:32]
	rest := entry.X25519Ciphertext[32:]
	log.Printf("[DEBUG] DecryptSessionKeyWithPrivates: ephemeral public key extracted (size: %d bytes)", len(ephPub))
	log.Printf("[DEBUG] DecryptSessionKeyWithPrivates: remaining ciphertext size: %d bytes", len(rest))

	x25519Shared, err := curve25519.X25519(x25519Priv, ephPub)
	if err != nil {
		log.Printf("[ERROR] DecryptSessionKeyWithPrivates: X25519 ECDH failed: %v", err)
		return nil, fmt.Errorf("X25519 ECDH: %w", err)
	}
	defer zeroBytes(x25519Shared)
	log.Printf("[DEBUG] DecryptSessionKeyWithPrivates: X25519 shared secret computed (size: %d bytes)", len(x25519Shared))

	// ── Kyber768 half ─────────────────────────────────────────────────────────

	var kyberShared []byte

	if len(entry.KyberCiphertext) > 0 && len(kyberPriv) > 0 {
		log.Printf("[DEBUG] DecryptSessionKeyWithPrivates: performing Kyber768 decapsulation")
		scheme := kyber768.Scheme()
		kyberPrivKey, err := scheme.UnmarshalBinaryPrivateKey(kyberPriv)
		if err != nil {
			log.Printf("[ERROR] DecryptSessionKeyWithPrivates: failed to unmarshal Kyber768 private key: %v", err)
			return nil, fmt.Errorf("unmarshal Kyber768 private key: %w", err)
		}
		log.Printf("[DEBUG] DecryptSessionKeyWithPrivates: Kyber768 private key unmarshaled")

		ss, err := scheme.Decapsulate(kyberPrivKey, entry.KyberCiphertext)
		if err != nil {
			log.Printf("[ERROR] DecryptSessionKeyWithPrivates: Kyber768 decapsulation failed: %v", err)
			return nil, fmt.Errorf("Kyber768 decapsulate: %w", err)
		}
		kyberShared = ss
		defer zeroBytes(kyberShared)
		log.Printf("[DEBUG] DecryptSessionKeyWithPrivates: Kyber768 decapsulation complete (shared secret size: %d bytes)", len(kyberShared))
	} else {
		log.Printf("[DEBUG] DecryptSessionKeyWithPrivates: no Kyber768 ciphertext or private key, using X25519 only")
	}

	// ── Combine shared secrets → AES-256 key ─────────────────────────────────

	combinedKey := combineSharedSecrets(x25519Shared, kyberShared)
	defer zeroBytes(combinedKey)
	log.Printf("[DEBUG] DecryptSessionKeyWithPrivates: combined shared secret (size: %d bytes)", len(combinedKey))

	// ── Decrypt session key ───────────────────────────────────────────────────

	log.Printf("[DEBUG] DecryptSessionKeyWithPrivates: decrypting session key with AES-256-GCM")
	block, err := aes.NewCipher(combinedKey)
	if err != nil {
		log.Printf("[ERROR] DecryptSessionKeyWithPrivates: failed to create AES cipher: %v", err)
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[ERROR] DecryptSessionKeyWithPrivates: failed to create GCM: %v", err)
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	log.Printf("[DEBUG] DecryptSessionKeyWithPrivates: GCM nonce size: %d bytes", gcm.NonceSize())

	ns := gcm.NonceSize()
	if len(rest) < ns {
		log.Printf("[ERROR] DecryptSessionKeyWithPrivates: X25519Ciphertext remainder too short for nonce: need %d bytes, have %d", ns, len(rest))
		return nil, errors.New("X25519Ciphertext: remainder too short for nonce")
	}

	sessionKey, err := gcm.Open(nil, rest[:ns], rest[ns:], []byte(entry.Fingerprint))
	if err != nil {
		log.Printf("[ERROR] DecryptSessionKeyWithPrivates: hybrid KEM decryption failed — wrong keys or tampered entry: %v", err)
		return nil, errors.New("hybrid KEM decryption failed — wrong keys or tampered entry")
	}
	log.Printf("[DEBUG] DecryptSessionKeyWithPrivates: session key decrypted (size: %d bytes)", len(sessionKey))

	log.Printf("[SUCCESS] DecryptSessionKeyWithPrivates: hybrid KEM recovered session key for recipient %.16s...", entry.Fingerprint)
	return sessionKey, nil
}

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

// combineSharedSecrets XORs the first 32 bytes of kyberSecret into x25519Secret
// to produce a 32-byte hybrid key.  If kyberSecret is empty, x25519Secret is
// returned unchanged (graceful degradation to plain X25519).
func combineSharedSecrets(x25519Secret, kyberSecret []byte) []byte {
	combined := make([]byte, 32)
	copy(combined, x25519Secret)
	log.Printf("[DEBUG] combineSharedSecrets: X25519 secret (first 8 bytes): %x", x25519Secret[:8])

	for i := 0; i < 32 && i < len(kyberSecret); i++ {
		combined[i] ^= kyberSecret[i]
	}
	if len(kyberSecret) > 0 {
		log.Printf("[DEBUG] combineSharedSecrets: Kyber secret (first 8 bytes): %x", kyberSecret[:8])
		log.Printf("[DEBUG] combineSharedSecrets: combined secret (first 8 bytes): %x", combined[:8])
	} else {
		log.Printf("[DEBUG] combineSharedSecrets: no Kyber secret, using X25519 only")
	}
	return combined
}

// zeroBytes overwrites every byte in b with zero to clear sensitive data.
func zeroBytes(b []byte) {
	log.Printf("[DEBUG] zeroBytes: clearing sensitive data of size %d bytes", len(b))
	for i := range b {
		b[i] = 0
	}
}
