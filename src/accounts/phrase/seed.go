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

	sips3 "github.com/sphinxfndorg/protocol/src/accounts/mnemonic"
	"github.com/sphinxfndorg/protocol/src/common"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

// SIPS-0004 https://github.com/sphinx-core/sips/wiki/SIPS0004

const (
	// EntropySize in bits. 128 bits -> 12-word mnemonic.
	EntropySize = 128
	SaltSize    = 16
	PasskeySize = 32
	NonceSize   = 16

	// Argon2 parameters. NOTE: argon2.IDKey memory is in KiB, so
	// 64*1024 is 64 MiB (the old comment said 64 KiB).
	// OWASP minimum: m=37 MiB,t=1,p=1 or m=15 MiB,t=2,p=1.
	memory      = 64 * 1024
	iterations  = 2
	parallelism = 1

	// Domain-separation labels so macKey and chainCode are independent.
	macKeyDomainLabel    = "sphinx-seed-mac-key-v1"
	chainCodeDomainLabel = "sphinx-seed-chain-code-v1"
)

// wipe overwrites b with zeros.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GenerateSalt generates a cryptographically secure random salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("error generating salt: %w", err)
	}
	return salt, nil
}

// GenerateNonce generates a cryptographically secure random nonce.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("error generating nonce: %w", err)
	}
	return nonce, nil
}

// GenerateEntropy generates secure random entropy (EntropySize bits).
func GenerateEntropy() ([]byte, error) {
	// Validate first, then spend randomness.
	switch EntropySize {
	case 128, 160, 192, 224, 256:
	default:
		return nil, fmt.Errorf("invalid entropy size: %d, must be one of 128, 160, 192, 224, or 256 bits", EntropySize)
	}
	entropy := make([]byte, EntropySize/8)
	if _, err := rand.Read(entropy); err != nil {
		return nil, fmt.Errorf("error generating entropy: %w", err)
	}
	return entropy, nil
}

// GeneratePassphrase encodes the given entropy as a checksummed sips0003
// mnemonic.
//
// FIX: previously only len(entropy) was used and the mnemonic was built from
// a second, unrelated random draw, so the entropy bytes were discarded and
// could never reproduce the phrase. The mnemonic is now a deterministic
// encoding of exactly this entropy (plus checksum).
func GeneratePassphrase(entropy []byte) (string, error) {
	passphrase, err := sips3.NewMnemonicFromEntropy(entropy)
	if err != nil {
		return "", fmt.Errorf("error generating mnemonic: %w", err)
	}
	return passphrase, nil
}

// DerivePasskey is the deterministic core of GeneratePasskey: the same
// (passphrase, pk, nonce) always yields the same passkey, so it can be
// re-derived and verified later.
func DerivePasskey(passphrase string, pk, nonce []byte) ([]byte, error) {
	if !utf8.ValidString(passphrase) {
		return nil, errors.New("invalid UTF-8 encoding in passphrase")
	}
	if len(pk) == 0 {
		return nil, errors.New("public key must not be empty")
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}

	passphraseBytes := []byte(passphrase)

	firstHash := common.SpxHash(pk)
	doubleHashedPk := common.SpxHash(firstHash[:])

	// IKM = SHA3-256(passphrase || doubleHashedPk)  (comment used to say SHA-256).
	ikmHashInput := bytes.Join([][]byte{passphraseBytes, doubleHashedPk[:]}, []byte{})
	ikm := sha3.Sum256(ikmHashInput)
	defer wipe(ikmHashInput)
	defer wipe(ikm[:])

	salt := "passphrase" + string(doubleHashedPk)
	combinedSaltAndNonce := bytes.Join([][]byte{[]byte(salt), nonce}, []byte{})

	return argon2.IDKey(ikm[:], combinedSaltAndNonce, iterations, memory, parallelism, PasskeySize), nil
}

// GeneratePasskeyWithNonce derives a passkey with a fresh random nonce and
// RETURNS the nonce. Store the nonce next to the passkey/public key: without
// it the passkey can never be re-derived.
func GeneratePasskeyWithNonce(passphrase string, pk []byte) (passkey, nonce []byte, err error) {
	if !utf8.ValidString(passphrase) {
		return nil, nil, errors.New("invalid UTF-8 encoding in passphrase")
	}

	if len(pk) == 0 {
		keyManager, err := key.NewKeyManager()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize KeyManager: %w", err)
		}
		_, generatedPk, err := keyManager.GenerateKey()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate new public key: %w", err)
		}
		pk, err = generatedPk.SerializePK()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to serialize new public key: %w", err)
		}
	}

	nonce, err = GenerateNonce()
	if err != nil {
		return nil, nil, err
	}
	passkey, err = DerivePasskey(passphrase, pk, nonce)
	if err != nil {
		return nil, nil, err
	}
	return passkey, nonce, nil
}

// GeneratePasskey keeps the original signature. WARNING: the random nonce is
// not returned, so the result cannot be re-derived later (same as before).
// Prefer GeneratePasskeyWithNonce for anything that must be verified.
func GeneratePasskey(passphrase string, pk []byte) ([]byte, error) {
	passkey, nonce, err := GeneratePasskeyWithNonce(passphrase, pk)
	wipe(nonce)
	return passkey, err
}

// HashPasskey hashes the given passkey using SHA3-512.
func HashPasskey(passkey []byte) ([]byte, error) {
	hash := sha3.New512()
	if _, err := hash.Write(passkey); err != nil {
		return nil, fmt.Errorf("error hashing with SHA3-512: %w", err)
	}
	return hash.Sum(nil), nil
}

// EncodeBase32 encodes the input data into Base32 format without padding.
func EncodeBase32(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

// DecodeBase32 decodes a no-padding Base32 string back into bytes.
func DecodeBase32(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

// deriveLabeledKey derives a fixed-length key from (passkeyBytes,
// hashedPasskey) using a domain-separation label via SHAKE256.
// NOT REVIEWED AGAINST utils.GenerateMacKey (source unavailable); grep for
// other callers that re-derive macKey/chainCode independently.
func deriveLabeledKey(label string, passkeyBytes, hashedPasskey []byte, outLen int) []byte {
	sh := sha3.NewShake256()
	sh.Write([]byte(label))
	sh.Write(passkeyBytes)
	sh.Write(hashedPasskey)
	out := make([]byte, outLen)
	sh.Read(out)
	return out
}

// GenerateKeys generates a 12-word recovery passphrase and every value derived
// from it: the Base32 passkey, the hashed passkey, the MAC key, the chain code
// and the fingerprint. Each derived value is a deterministic function of the
// passphrase alone, so DeriveKeys(phrase) reproduces them all exactly — the
// phrase is therefore the sole root of trust for rebuilding the wallet.
//
// NOTE: the passkey is 6-8 bytes (48-64 bits). That is a short identifier,
// not a secret that resists offline brute force; do not use it as an
// encryption key. The fingerprint (HMAC keyed by the passphrase) is what lets
// you check passphrase <-> passkey later.
func GenerateKeys() (passphrase string, base32Passkey string, hashedPasskey []byte, macKey []byte, chainCode []byte, fingerprint []byte, err error) {
	entropy, err := GenerateEntropy()
	if err != nil {
		return "", "", nil, nil, nil, nil, fmt.Errorf("failed to generate entropy: %w", err)
	}
	defer wipe(entropy)

	passphrase, err = GeneratePassphrase(entropy)
	if err != nil {
		return "", "", nil, nil, nil, nil, fmt.Errorf("failed to generate passphrase: %w", err)
	}

	base32Passkey, hashedPasskey, macKey, chainCode, fingerprint = deriveFromPhrase(passphrase)
	return passphrase, base32Passkey, hashedPasskey, macKey, chainCode, fingerprint, nil
}

// DeriveKeys reconstructs every value GenerateKeys produced, using only the
// recovery phrase. It is the deterministic inverse of GenerateKeys: the same
// words always yield the same Base32 passkey, hashed passkey, MAC key, chain
// code and fingerprint, so a wallet can be rebuilt from the phrase alone (the
// same philosophy derivation.go applies to the master seed). The phrase is
// validated (word list + checksum, in any supported language) before anything
// is derived.
func DeriveKeys(phrase string) (base32Passkey string, hashedPasskey []byte, macKey []byte, chainCode []byte, fingerprint []byte, err error) {
	if err = sips3.ValidateMnemonic(phrase); err != nil {
		return "", nil, nil, nil, nil, fmt.Errorf("invalid mnemonic: %w", err)
	}
	base32Passkey, hashedPasskey, macKey, chainCode, fingerprint = deriveFromPhrase(phrase)
	return base32Passkey, hashedPasskey, macKey, chainCode, fingerprint, nil
}

// deriveFromPhrase is the shared deterministic core of GenerateKeys and
// DeriveKeys: every returned value is a pure function of the passphrase, which
// is what makes the whole key set reproducible from the words alone. Keeping
// it in one place guarantees GenerateKeys and DeriveKeys can never drift apart.
func deriveFromPhrase(passphrase string) (base32Passkey string, hashedPasskey, macKey, chainCode, fingerprint []byte) {
	// 32-byte PRF seed keyed solely by the passphrase (SHAKE256). Previously a
	// random secret was mixed in here and then discarded, which made the
	// derived values unreproducible; keying off the phrase instead is what
	// lets DeriveKeys regenerate them.
	sh := sha3.NewShake256()
	sh.Write([]byte(passphrase))
	prfOutput := make([]byte, 32)
	sh.Read(prfOutput)
	defer wipe(prfOutput)

	hashed := sha3.Sum512(prfOutput)
	hashedPasskey = hashed[:]

	outputLength := 8
	if prfOutput[0]&1 == 0 {
		outputLength = 6
	}
	passkeyBytes := hashedPasskey[:outputLength]

	base32Passkey = EncodeBase32(passkeyBytes)
	macKey = deriveLabeledKey(macKeyDomainLabel, passkeyBytes, hashedPasskey, 32)
	chainCode = deriveLabeledKey(chainCodeDomainLabel, passkeyBytes, hashedPasskey, 32)
	fingerprint = computeFingerprint(passphrase, passkeyBytes)

	return base32Passkey, hashedPasskey, macKey, chainCode, fingerprint
}

// computeFingerprint / VerifyFingerprint must change together.
// Old fingerprints created under the deleted auth package will not verify.
func computeFingerprint(passphrase string, passkeyBytes []byte) []byte {
	mac := hmac.New(sha3.New512, []byte(passphrase))
	mac.Write(passkeyBytes)
	return mac.Sum(nil)
}

// VerifyFingerprint recomputes and compares in constant time.
func VerifyFingerprint(passphrase string, passkeyBytes []byte, expectedFingerprint []byte) bool {
	computed := computeFingerprint(passphrase, passkeyBytes)
	return hmac.Equal(computed, expectedFingerprint)
}
