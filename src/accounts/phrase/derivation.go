// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package seed

import (
	"errors"
	"fmt"
	"strings"

	sips3 "github.com/sphinxfndorg/protocol/src/accounts/mnemonic"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

// Deterministic wallet derivation:
//
//	mnemonic (+ optional passphrase) --Argon2id--> 64-byte master seed
//	master seed --SHAKE256 + labels--> SKseed, SKprf, PKseed   (n bytes each)
//
// The same phrase always yields the same seed, so a wallet can be rebuilt from
// the words alone (like BTC/ETH). The key-generation step that turns
// (SKseed, SKprf, PKseed) into a full SPHINCS+ key pair lives in the sthincs
// package, because only it can compute PKroot.
//
// VERSIONING: every constant below is part of the wallet format. Changing any
// of them changes every derived key and makes existing wallets unrecoverable.
// A new format must use a new version label (v2), never edit v1.
const (
	// MasterSeedSize is the Argon2id output length in bytes.
	MasterSeedSize = 64

	seedKDFTime    = 3
	seedKDFMemory  = 64 * 1024 // KiB -> 64 MiB
	seedKDFThreads = 1

	seedSaltPrefix = "sphinx-mnemonic-seed-v1"

	skSeedLabel = "sphinx-sthincs-skseed-v1"
	skPrfLabel  = "sphinx-sthincs-skprf-v1"
	pkSeedLabel = "sphinx-sthincs-pkseed-v1"
)

// normalizeMnemonic collapses all whitespace to single spaces. The word lists
// are lowercase ASCII-compatible; if they ever contain non-ASCII words, add
// Unicode NFKD normalization here (golang.org/x/text/unicode/norm) BEFORE
// shipping, because it changes the derived seed.
func normalizeMnemonic(m string) string {
	return strings.Join(strings.Fields(m), " ")
}

// DeriveSeed validates the mnemonic (word list + checksum, either language)
// and returns the 64-byte master seed. extraPassphrase is an optional
// "25th word": different passphrase => completely different wallet. Pass ""
// for none. Caller should wipe the result when done.
func DeriveSeed(mnemonic, extraPassphrase string) ([]byte, error) {
	if err := sips3.ValidateMnemonic(mnemonic); err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}
	m := normalizeMnemonic(mnemonic)
	salt := []byte(seedSaltPrefix + extraPassphrase)
	return argon2.IDKey([]byte(m), salt, seedKDFTime, seedKDFMemory, seedKDFThreads, MasterSeedSize), nil
}

func shakeDerive(label string, seed []byte, outLen int) []byte {
	sh := sha3.NewShake256()
	sh.Write([]byte(label))
	sh.Write(seed)
	out := make([]byte, outLen)
	sh.Read(out)
	return out
}

// SplitKeySeed derives the three SPHINCS+ secret/public seeds of n bytes each
// (n is the parameter set's security parameter, e.g. 16 for 128-bit sets).
// Each output uses its own domain label, so they are independent.
func SplitKeySeed(masterSeed []byte, n int) (skSeed, skPrf, pkSeed []byte, err error) {
	if len(masterSeed) != MasterSeedSize {
		return nil, nil, nil, fmt.Errorf("master seed must be %d bytes, got %d", MasterSeedSize, len(masterSeed))
	}
	if n < 16 || n > 32 {
		return nil, nil, nil, errors.New("seed length n must be between 16 and 32 bytes")
	}
	return shakeDerive(skSeedLabel, masterSeed, n),
		shakeDerive(skPrfLabel, masterSeed, n),
		shakeDerive(pkSeedLabel, masterSeed, n),
		nil
}
