// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/sphincs/key/backend/verify.go
package key

import (
	"bytes"
	"errors"
	"log"
)

// VerifyPubKey checks that a decrypted secret-key blob's embedded public-key
// material (PKseed, PKroot) matches an expected serialized public key.
//
// REPLACES the placeholder in crypter.go:
//
//	func VerifyPubKey(secret, pubKey []byte) bool {
//	    return bytes.Equal(secret, pubKey)
//	}
//
// That placeholder compared the ENTIRE decrypted secret blob
// (SKseed||SKprf||PKseed||PKroot, per SerializeSK in key.go) against the
// entire serialized public key. Those are different lengths for any real
// SPHINCS+ parameter set (the secret blob is strictly longer — it embeds
// PKseed/PKroot as a SUFFIX, not the whole thing), so bytes.Equal could
// never return true for real keys. It wasn't just unimplemented, it was
// structurally guaranteed to fail (or, if some future caller passed in
// secret == pubKey directly to make it pass, structurally guaranteed to
// pass without checking anything real).
//
// This implementation does NOT attempt to cryptographically re-derive a
// public key from a secret seed — SPHINCS+ doesn't have a cheap one-way
// function for that, and trying to fake one would be its own bug. Instead
// it uses the fact, visible directly in key.go/types.go, that
// SPHINCS_SK already carries the same PKseed/PKroot that went into the
// paired public key at generation time (GenerateKey() copies them onto
// both structs from the same Spx_keygen() call). So this is a structural
// consistency check — "does this secret's embedded public-key material
// match the public key on file" — using your EXISTING deserialization
// (DeserializeKeyPair/DeserializePublicKey), not invented byte offsets.
//
// This requires a *KeyManager (for parameter-aware deserialization via
// km.Params), which is why it now lives in this package instead of
// crypter — crypter has no concept of SPHINCS+ field structure and
// shouldn't need one.
func (km *KeyManager) VerifyPubKey(secretBytes, pubKeyBytes []byte) (bool, error) {
	if km.Params == nil || km.Params.Params == nil {
		return false, errors.New("missing SPHINCS+ parameters in KeyManager")
	}
	if len(secretBytes) == 0 || len(pubKeyBytes) == 0 {
		return false, errors.New("empty secret or public key bytes")
	}

	// Deserialize the decrypted secret blob using the SAME parameter set
	// and parsing logic as everywhere else in this package — no
	// hardcoded/guessed byte offsets for SKseed/SKprf/PKseed/PKroot
	// lengths. sthincs.DeserializeSK (called internally) knows the real
	// field widths for whatever parameter set km.Params was built with.
	sk, _, err := km.DeserializeKeyPair(secretBytes, pubKeyBytes)
	if err != nil {
		// A deserialize failure here usually means the decrypted secret
		// isn't a validly-shaped SPHINCS_SK at all (wrong passphrase
		// decrypted to garbage that happened to pass GCM auth on a
		// different key, corrupted storage, etc.) — surface it rather
		// than silently reporting "not verified".
		log.Printf("VerifyPubKey: failed to deserialize key pair: %v", err)
		return false, err
	}

	// Independently deserialize the expected public key from its own
	// bytes (not reusing the pk returned above, which came from
	// DeserializeKeyPair's own pkBytes argument — same pubKeyBytes either
	// way, but parsed via the dedicated single-purpose path for clarity).
	expectedPK, err := km.DeserializePublicKey(pubKeyBytes)
	if err != nil {
		log.Printf("VerifyPubKey: failed to deserialize expected public key: %v", err)
		return false, err
	}

	// Compare the secret's embedded public-key material against the
	// expected public key, field by field. Using bytes.Equal per-field
	// (not a single concatenated comparison) so a length mismatch in one
	// field can't accidentally make a comparison "succeed" by shifting
	// bytes across a field boundary.
	seedMatch := bytes.Equal(sk.PKseed, expectedPK.PKseed)
	rootMatch := bytes.Equal(sk.PKroot, expectedPK.PKroot)

	if !seedMatch || !rootMatch {
		log.Printf("VerifyPubKey: mismatch (PKseed match=%t, PKroot match=%t)", seedMatch, rootMatch)
		return false, nil
	}

	return true, nil
}
