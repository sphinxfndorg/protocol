// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package seed

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"

	"encoding/base32"
	"errors"
	"fmt"
	"unicode/utf8"

	sips3 "github.com/sphinxorg/protocol/src/accounts/mnemonic"
	"github.com/sphinxorg/protocol/src/common"
	key "github.com/sphinxorg/protocol/src/core/sthincs/key/backend"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

// SIPS-0004 https://github.com/sphinx-core/sips/wiki/SIPS0004

// Define constants for the sizes used in the seed generation process
const (
	// EntropySize determines the length of entropy to be generated
	EntropySize = 128 // Set default entropy size to 128 bits for 12-word mnemonic
	SaltSize    = 16  // 128 bits salt size
	PasskeySize = 32  // Set this to 32 bytes for a 256-bit output
	NonceSize   = 16  // 128 bits nonce size, adjustable as needed

	// Argon2 parameters
	// OWASP have published guidance on Argon2 at https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
	// At time of writing (Jan 2023), this says:
	// Argon2id should use one of the following configuration settings as a base minimum which includes the minimum memory size (m), the minimum number of iterations (t) and the degree of parallelism (p).
	// m=37 MiB, t=1, p=1
	// m=15 MiB, t=2, p=1
	// Both of these configuration settings are equivalent in the defense they provide. The only difference is a trade off between CPU and RAM usage.
	memory      = 64 * 1024 // Memory cost set to 64 KiB (64 * 1024 bytes) for demonstration purpose
	iterations  = 2         // Number of iterations for Argon2id set to 2
	parallelism = 1         // Degree of parallelism set to 1

	// REMOVED DEPENDENCY: auth.GenerateChainCode / utils.GenerateMacKey /
	// utils.VerifyBase32Passkey / utils.NewWalletConfig all lived in
	// src/core/wallet/{auth,utils}, which you've deleted. This file no
	// longer imports either package — see the inline notes at each call
	// site below for what replaced what (and what was simply removed).

	// macKeyDomain / chainCodeDomain are HKDF-style domain-separation
	// labels for the local SHAKE256-based replacements below. Using
	// distinct labels for each derived value (instead of one shared
	// label, or none) ensures macKey and chainCode are cryptographically
	// independent even though both derive from the same (passkeyBytes,
	// hashedPasskey) inputs.
	macKeyDomainLabel    = "sphinx-seed-mac-key-v1"
	chainCodeDomainLabel = "sphinx-seed-chain-code-v1"
)

// GenerateSalt generates a cryptographically secure random salt.
func GenerateSalt() ([]byte, error) {
	// Create a byte slice for the salt
	salt := make([]byte, SaltSize)
	// Fill the slice with random bytes
	_, err := rand.Read(salt)
	if err != nil {
		// Return an error if salt generation fails
		return nil, fmt.Errorf("error generating salt: %v", err)
	}
	// Return the generated salt
	return salt, nil
}

// GenerateNonce generates a cryptographically secure random nonce.
func GenerateNonce() ([]byte, error) {
	// Create a byte slice for the nonce
	nonce := make([]byte, NonceSize)
	// Fill the slice with random bytes
	_, err := rand.Read(nonce)
	if err != nil {
		// Return an error if nonce generation fails
		return nil, fmt.Errorf("error generating nonce: %v", err)
	}
	// Return the generated nonce
	return nonce, nil
}

// GenerateEntropy generates secure random entropy for private key generation.
func GenerateEntropy() ([]byte, error) {
	// Create a byte slice for entropy
	entropy := make([]byte, EntropySize/8) // Ensure entropy is in byte units (EntropySize in bits)
	// Fill the slice with random bytes
	_, err := rand.Read(entropy)
	if err != nil {
		// Return an error if entropy generation fails
		return nil, fmt.Errorf("error generating entropy: %v", err)
	}

	// Check if the entropy size is valid
	if EntropySize != 128 && EntropySize != 160 && EntropySize != 192 && EntropySize != 224 && EntropySize != 256 {
		return nil, fmt.Errorf("invalid entropy size: %d, must be one of 128, 160, 192, 224, or 256 bits", EntropySize)
	}

	// Return the raw entropy for sips3
	return entropy, nil
}

// GeneratePassphrase generates a sips0003 passphrase from entropy.
func GeneratePassphrase(entropy []byte) (string, error) {
	// The entropy length is used to determine the mnemonic length
	entropySize := len(entropy) * 8 // Convert bytes to bits

	// Create a new mnemonic (passphrase) from the provided entropy size
	passphrase, _, err := sips3.NewMnemonic(entropySize)
	if err != nil {
		return "", fmt.Errorf("error generating mnemonic: %v", err)
	}

	// Return the generated passphrase
	return passphrase, nil
}

// GeneratePasskey generates a passkey using Argon2 with the given passphrase and an optional public key as input material.
// If no public key (pk) is provided, a new one will be generated.
func GeneratePasskey(passphrase string, pk []byte) ([]byte, error) {
	// Step 1: Validate the passphrase encoding (UTF-8 validation).
	if !utf8.Valid([]byte(passphrase)) {
		return nil, errors.New("invalid UTF-8 encoding in passphrase")
	}

	// Step 2: Check if the public key (pk) is empty, and generate a new one if necessary.
	if len(pk) == 0 {
		// Initialize the KeyManager for key generation.
		keyManager, err := key.NewKeyManager()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize KeyManager: %v", err)
		}

		// Generate a new key pair.
		_, generatedPk, err := keyManager.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate new public key: %v", err)
		}

		// Serialize the generated public key to bytes.
		pk, err = generatedPk.SerializePK()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize new public key: %v", err)
		}
	}

	// Step 3: Convert the passphrase to bytes for processing.
	passphraseBytes := []byte(passphrase)

	// Step 4: Perform double hashing on the public key using a custom Sphinx hash.
	firstHash := common.SpxHash(pk)                // First Sphinx hash of the public key.
	doubleHashedPk := common.SpxHash(firstHash[:]) // Double Sphinx hash of the public key.

	// Step 5: Combine the passphrase and double-hashed public key as input key material (IKM).
	ikmHashInput := bytes.Join([][]byte{passphraseBytes, doubleHashedPk[:]}, []byte{}) // Concatenate passphraseBytes and doubleHashedPk[:]
	ikm := sha3.Sum256(ikmHashInput)                                                   // Derive the initial key material using SHA-256.

	// Step 6: Create a salt string using the double-hashed public key and passphrase.
	salt := "passphrase" + string(doubleHashedPk)

	// Step 7: Convert the salt string to bytes.
	saltBytes := []byte(salt)

	// Step 8: Generate a random nonce to enhance the salt uniqueness.
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("error generating nonce: %v", err)
	}

	// Step 9: Combine the salt and nonce for the final Argon2 salt.
	combinedSaltAndNonce := bytes.Join([][]byte{saltBytes, nonce}, []byte{})

	// Step 10: Use Argon2 to derive the passkey using the IKM and the combined salt.
	passkey := argon2.IDKey(ikm[:], combinedSaltAndNonce, iterations, memory, parallelism, PasskeySize)

	// Return the derived passkey.
	return passkey, nil
}

// HashPasskey hashes the given passkey using SHA3-512.
func HashPasskey(passkey []byte) ([]byte, error) {
	// Initialize the SHA3-512 hasher.
	hash := sha3.New512()

	// Write the passkey to the hasher.
	if _, err := hash.Write(passkey); err != nil {
		return nil, fmt.Errorf("error hashing with SHA3-512: %v", err)
	}

	// Return the final hash as bytes.
	return hash.Sum(nil), nil
}

// EncodeBase32 encodes the input data into Base32 format without padding.
func EncodeBase32(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

// DecodeBase32 decodes a no-padding Base32 string back into bytes. Added
// as the missing counterpart to EncodeBase32 — the original codebase had
// no exported decode function in this package; callers apparently relied
// on the now-deleted utils.VerifyBase32Passkey to do decode-and-verify
// together. This is decode-only, with no verification semantics attached.
func DecodeBase32(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

// deriveLabeledKey is a local, dependency-free replacement for what
// utils.GenerateMacKey used to do. It derives a fixed-length key from
// (passkeyBytes, hashedPasskey) using a domain-separation label, via
// keyed SHAKE256 — the same primitive GenerateKeys() already uses below
// for its own PRF step, so this introduces no new cryptographic
// machinery to the file, just reuses sha3.NewShake256 with a label.
//
// NOT REVIEWED AGAINST THE ORIGINAL: I don't have utils.GenerateMacKey's
// source, so this is a clean re-derivation matching its apparent contract
// (two []byte inputs -> []byte output), not a verified drop-in replica.
// If macKey/chainCode are consumed anywhere that hard-codes assumptions
// about the OLD algorithm (e.g. another package re-deriving the same
// value independently to check equality), that caller needs updating too
// — grep for GenerateMacKey/macKey usage outside this file before
// treating this as done.
func deriveLabeledKey(label string, passkeyBytes, hashedPasskey []byte, outLen int) []byte {
	sh := sha3.NewShake256()
	sh.Write([]byte(label))
	sh.Write(passkeyBytes)
	sh.Write(hashedPasskey)
	out := make([]byte, outLen)
	sh.Read(out)
	return out
}

// GenerateKeys generates a passphrase, a hashed Base32-encoded passkey, and its fingerprint.
// It derives a 6–8 byte output cryptographically from a large intermediate state to ensure
// the output is protected by the state's entropy against brute-force attacks.
func GenerateKeys() (passphrase string, base32Passkey string, hashedPasskey []byte, macKey []byte, chainCode []byte, fingerprint []byte, err error) {
	// Step 1: Generate a secret random value (256-bit) to serve as the PRF key
	secretKey := make([]byte, 32)
	_, err = rand.Read(secretKey)
	if err != nil {
		return "", "", nil, nil, nil, nil, fmt.Errorf("failed to generate secret key: %v", err)
	}

	// Step 2: Generate entropy for the passphrase (optional context)
	entropy, err := GenerateEntropy()
	if err != nil {
		return "", "", nil, nil, nil, nil, fmt.Errorf("failed to generate entropy: %v", err)
	}

	// Step 3: Generate passphrase from entropy
	passphrase, err = GeneratePassphrase(entropy)
	if err != nil {
		return "", "", nil, nil, nil, nil, fmt.Errorf("failed to generate passphrase: %v", err)
	}

	// Step 4: Use secretKey + passphrase as PRF input
	prfInput := append([]byte(passphrase), secretKey...)

	// Step 5: Keyed SHAKE256 PRF
	sh := sha3.NewShake256()
	sh.Write(secretKey)
	sh.Write(prfInput)

	prfOutput := make([]byte, 32)
	sh.Read(prfOutput)

	// Step 6: Derive hashedPasskey (optional: SHA3-512 for extra entropy)
	hashed := sha3.Sum512(prfOutput)
	hashedPasskey = hashed[:]

	// Step 7: Take first 8 bytes (or 6–8 bytes) as passkey material
	outputLength := 8
	if prfOutput[0]&1 == 0 {
		outputLength = 6
	}
	passkeyBytes := hashedPasskey[:outputLength]

	// Step 8: Encode passkey in Base32
	base32Passkey = EncodeBase32(passkeyBytes)

	// Step 9: Generate MAC key and chain code from passkey and hashedPasskey.
	//
	// REMOVED DEPENDENCY: was utils.GenerateMacKey(passkeyBytes, hashedPasskey).
	// Replaced with deriveLabeledKey using domain-separated SHAKE256 — see
	// the warning on that function above. macKey and chainCode use
	// different labels so they're independent outputs despite sharing
	// inputs (chainCode being 32 bytes matches typical BIP-32 chain code
	// size; adjust outLen if your HD-derivation code expects something else).
	macKey = deriveLabeledKey(macKeyDomainLabel, passkeyBytes, hashedPasskey, 32)
	chainCode = deriveLabeledKey(chainCodeDomainLabel, passkeyBytes, hashedPasskey, 32)

	// Step 10: Generate fingerprint linking passphrase and passkey.
	//
	// REMOVED DEPENDENCY: was auth.GenerateChainCode(passphrase, passkeyBytes)
	// (note: despite the name "GenerateChainCode", this populated
	// `fingerprint`, not `chainCode` — that naming mismatch existed in your
	// original code, not introduced here). Replaced with an HMAC-SHA3-512
	// over passkeyBytes, keyed by passphrase: a fingerprint that lets you
	// later verify "does this passphrase correspond to this passkey?"
	// without storing the passphrase itself — see VerifyFingerprint below,
	// which is the matching replacement for auth.VerifyFingerPrint and
	// MUST stay in sync with this construction.
	fingerprint = computeFingerprint(passphrase, passkeyBytes)

	return passphrase, base32Passkey, hashedPasskey, macKey, chainCode, fingerprint, nil
}

// computeFingerprint and VerifyFingerprint are a local, dependency-free
// replacement pair for auth.GenerateChainCode (used as a fingerprint
// generator) / auth.VerifyFingerPrint. They MUST be changed together —
// VerifyFingerprint only works correctly if it recomputes the fingerprint
// exactly the way computeFingerprint built it.
//
// NOT REVIEWED AGAINST THE ORIGINAL: same caveat as deriveLabeledKey above
// — I don't have auth.GenerateChainCode's source, so this satisfies the
// same (passphrase, passkeyBytes) -> fingerprint -> bool contract your
// code already calls, but isn't a verified bit-for-bit replica of the
// deleted implementation. Any previously-generated fingerprints (e.g.
// already persisted to disk under the old auth package) will NOT verify
// against this new construction — this is a breaking change for existing
// data, not just a recompile fix.
func computeFingerprint(passphrase string, passkeyBytes []byte) []byte {
	mac := hmac.New(sha3.New512, []byte(passphrase))
	mac.Write(passkeyBytes)
	return mac.Sum(nil)
}

// VerifyFingerprint recomputes the fingerprint from (passphrase,
// passkeyBytes) and compares it against an expected value using a
// constant-time comparison (hmac.Equal), to avoid leaking timing
// information about how much of the fingerprint matched.
//
// REMOVED DEPENDENCY: replaces auth.VerifyFingerPrint(base32Passkey, passphrase).
// Note the original took base32Passkey (the encoded string) and
// internally must have decoded it before comparing — this version takes
// the raw passkeyBytes and the expected fingerprint directly, which is a
// cleaner contract but DOES change the call signature. Callers (e.g.
// test_key.go) need updating accordingly — see the rewritten test_key.go.
func VerifyFingerprint(passphrase string, passkeyBytes []byte, expectedFingerprint []byte) bool {
	computed := computeFingerprint(passphrase, passkeyBytes)
	return hmac.Equal(computed, expectedFingerprint)
}
