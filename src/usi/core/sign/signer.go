// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/sign/signer.go
package sign

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	keys "github.com/sphinxorg/protocol/src/usi/core/key"
)

// Sign creates a SPHINCS+ signature for `msg` using the decrypted private key.
// The passphrase is needed only to decrypt the encrypted SK stored on disk.
// The returned Signature embeds the signer's public key for transport;
// callers must still verify against a trusted key store before accepting.
func Sign(msg []byte, passphrase string) (*Signature, error) {
	startTime := time.Now()
	log.Printf("[INFO] Sign: starting signing process for message length %d bytes", len(msg))
	log.Printf("[DEBUG] Sign: message hash (hex): %s", hex.EncodeToString(msg))

	kp, skBytes, err := keys.LoadKeyFromDisk(passphrase)
	if err != nil {
		log.Printf("[ERROR] Sign: failed to load keypair: %v", err)
		return nil, fmt.Errorf("load key: %w", err)
	}
	// FIX #1: Zero the raw private key bytes immediately after use.
	// Ranging over a nil slice is safe in Go, so no nil check needed.
	defer func() {
		for i := range skBytes {
			skBytes[i] = 0
		}
		log.Printf("[INFO] Sign: private key bytes zeroed")
	}()

	sk, err := sphincs.DeserializeSK(keys.DefaultParams, skBytes)
	if err != nil {
		log.Printf("[ERROR] Sign: failed to deserialize private key: %v", err)
		return nil, fmt.Errorf("deserialize SK: %w", err)
	}
	log.Printf("[INFO] Sign: private key deserialized successfully")

	pk, err := sphincs.DeserializePK(keys.DefaultParams, kp.PublicKey)
	if err != nil {
		log.Printf("[ERROR] Sign: failed to deserialize public key: %v", err)
		return nil, fmt.Errorf("deserialize PK: %w", err)
	}
	log.Printf("[INFO] Sign: public key deserialized successfully")
	log.Printf("[DEBUG] Sign: public key (hex): %s", hex.EncodeToString(kp.PublicKey))

	sigObj := sphincs.Spx_sign(keys.DefaultParams, msg, sk)
	log.Printf("[INFO] Sign: SPHINCS+ signature created")

	sigBytes, err := sigObj.SerializeSignature()
	if err != nil {
		log.Printf("[ERROR] Sign: failed to serialize signature: %v", err)
		return nil, fmt.Errorf("serialize signature: %w", err)
	}
	log.Printf("[INFO] Sign: signature serialized (size: %d bytes)", len(sigBytes))
	log.Printf("[DEBUG] Sign: signature (hex prefix): %s...", hex.EncodeToString(sigBytes)[:min(64, len(sigBytes))])

	pkBytes, err := pk.SerializePK()
	if err != nil {
		log.Printf("[ERROR] Sign: failed to serialize public key: %v", err)
		return nil, fmt.Errorf("serialize PK: %w", err)
	}
	log.Printf("[INFO] Sign: public key serialized (size: %d bytes)", len(pkBytes))

	elapsed := time.Since(startTime)
	log.Printf("[SUCCESS] Sign: signing completed successfully in %v", elapsed)
	return &Signature{
		Signature: sigBytes,
		PublicKey: pkBytes,
	}, nil
}

// Verify checks a SPHINCS+ signature against an explicitly trusted public key.
//
// FIX #2 (Critical): The trusted key MUST come from a local key store or
// an out-of-band trusted source — never from the same untrusted file that
// contains the signature being verified. Passing the embedded public key
// from an untrusted file allows a full signature-bypass attack.
//
// Correct usage:
//
//	registeredKP, _, _ := keys.LoadKeyFromDisk(passphrase)
//	ok, err := Verify(hash, sig, registeredKP.PublicKey)
//
// Incorrect (still vulnerable) usage:
//
//	ok, err := Verify(hash, sig, sig.PublicKey)   // ← DO NOT DO THIS
func Verify(msg []byte, sig *Signature, trustedPKBytes []byte) (bool, error) {
	startTime := time.Now()
	log.Printf("[INFO] Verify: starting verification for message length %d bytes", len(msg))
	log.Printf("[DEBUG] Verify: message hash (hex): %s", hex.EncodeToString(msg))

	if len(trustedPKBytes) == 0 {
		log.Printf("[ERROR] Verify: empty trusted public key")
		return false, fmt.Errorf("trusted public key required: refusing to verify against empty key")
	}
	if sig == nil {
		log.Printf("[ERROR] Verify: nil signature")
		return false, fmt.Errorf("nil signature")
	}
	if len(sig.Signature) == 0 {
		log.Printf("[ERROR] Verify: empty signature bytes")
		return false, fmt.Errorf("empty signature bytes")
	}
	log.Printf("[INFO] Verify: signature size: %d bytes", len(sig.Signature))
	log.Printf("[DEBUG] Verify: signature (hex prefix): %s...", hex.EncodeToString(sig.Signature)[:min(64, len(sig.Signature))])
	log.Printf("[DEBUG] Verify: trusted public key (hex prefix): %s...", hex.EncodeToString(trustedPKBytes)[:min(64, len(trustedPKBytes))])

	pk, err := sphincs.DeserializePK(keys.DefaultParams, trustedPKBytes)
	if err != nil {
		log.Printf("[ERROR] Verify: failed to deserialize trusted public key: %v", err)
		return false, fmt.Errorf("deserialize trusted PK: %w", err)
	}
	log.Printf("[INFO] Verify: trusted public key deserialized successfully")

	sigObj, err := sphincs.DeserializeSignature(keys.DefaultParams, sig.Signature)
	if err != nil {
		log.Printf("[ERROR] Verify: failed to deserialize signature: %v", err)
		return false, fmt.Errorf("deserialize signature: %w", err)
	}
	log.Printf("[INFO] Verify: signature deserialized successfully")

	ok := sphincs.Spx_verify(keys.DefaultParams, msg, sigObj, pk)
	elapsed := time.Since(startTime)
	if ok {
		log.Printf("[SUCCESS] Verify: signature verified successfully against trusted key in %v", elapsed)
	} else {
		log.Printf("[FAILED] Verify: signature verification failed against trusted key in %v", elapsed)
	}
	return ok, nil
}

// VerifyWithRegisteredKey verifies a signature against the key currently
// registered on disk for the given passphrase. This is the preferred
// verification path for all local operations (vault decryption, document
// sign-check) because it closes the embedded-key substitution attack.
func VerifyWithRegisteredKey(msg []byte, sig *Signature, passphrase string) (bool, error) {
	startTime := time.Now()
	log.Printf("[INFO] VerifyWithRegisteredKey: starting verification")
	log.Printf("[DEBUG] VerifyWithRegisteredKey: message hash (hex): %s", hex.EncodeToString(msg))

	if passphrase == "" {
		log.Printf("[ERROR] VerifyWithRegisteredKey: empty passphrase")
		return false, fmt.Errorf("passphrase required to load registered key")
	}

	registeredKP, skBytes, err := keys.LoadKeyFromDisk(passphrase)
	if err != nil {
		log.Printf("[ERROR] VerifyWithRegisteredKey: failed to load registered key: %v", err)
		return false, fmt.Errorf("load registered key: %w", err)
	}
	// Zero the decrypted SK — we only needed the KP to obtain the public key.
	defer func() {
		for i := range skBytes {
			skBytes[i] = 0
		}
		log.Printf("[INFO] VerifyWithRegisteredKey: private key bytes zeroed")
	}()
	log.Printf("[INFO] VerifyWithRegisteredKey: registered key loaded")
	log.Printf("[DEBUG] VerifyWithRegisteredKey: registered public key (hex prefix): %s...", hex.EncodeToString(registeredKP.PublicKey)[:min(64, len(registeredKP.PublicKey))])

	result, err := Verify(msg, sig, registeredKP.PublicKey)
	elapsed := time.Since(startTime)
	log.Printf("[INFO] VerifyWithRegisteredKey: verification completed in %v", elapsed)
	return result, err
}

// VerifyWithEmbeddedKey verifies a signature using the public key embedded
// inside the Signature struct itself.
//
// WARNING — SECURITY CONSTRAINT: This function MUST only be used when the
// caller has already independently confirmed that sig.PublicKey equals the
// registered public key on disk (see BindingCheck). Using this function
// without that prior check is equivalent to trusting attacker-supplied data.
//
// The only legitimate internal caller is verifyManifestSignature in vault.go,
// which calls BindingCheck immediately before calling this function.
func VerifyWithEmbeddedKey(msg []byte, sig *Signature, passphrase string) (bool, error) {
	startTime := time.Now()
	log.Printf("[INFO] VerifyWithEmbeddedKey: starting verification with embedded key")
	log.Printf("[DEBUG] VerifyWithEmbeddedKey: message hash (hex): %s", hex.EncodeToString(msg))

	// First verify key matches registered key
	registeredKP, _, err := keys.LoadKeyFromDisk(passphrase)
	if err != nil {
		log.Printf("[ERROR] VerifyWithEmbeddedKey: failed to load registered key: %v", err)
		return false, err
	}
	if subtle.ConstantTimeCompare(sig.PublicKey, registeredKP.PublicKey) != 1 {
		log.Printf("[ERROR] VerifyWithEmbeddedKey: embedded key does not match registered key")
		log.Printf("[DEBUG] VerifyWithEmbeddedKey: embedded key (hex prefix): %s...", hex.EncodeToString(sig.PublicKey)[:min(64, len(sig.PublicKey))])
		log.Printf("[DEBUG] VerifyWithEmbeddedKey: registered key (hex prefix): %s...", hex.EncodeToString(registeredKP.PublicKey)[:min(64, len(registeredKP.PublicKey))])
		return false, errors.New("embedded key does not match registered key")
	}
	log.Printf("[INFO] VerifyWithEmbeddedKey: key binding verification passed")

	if sig == nil || len(sig.PublicKey) == 0 {
		log.Printf("[ERROR] VerifyWithEmbeddedKey: missing embedded public key")
		return false, fmt.Errorf("embedded public key missing")
	}
	log.Printf("[DEBUG] VerifyWithEmbeddedKey: embedded public key (hex prefix): %s...", hex.EncodeToString(sig.PublicKey)[:min(64, len(sig.PublicKey))])

	pk, err := sphincs.DeserializePK(keys.DefaultParams, sig.PublicKey)
	if err != nil {
		log.Printf("[ERROR] VerifyWithEmbeddedKey: failed to deserialize embedded PK: %v", err)
		return false, fmt.Errorf("deserialize embedded PK: %w", err)
	}
	log.Printf("[INFO] VerifyWithEmbeddedKey: embedded public key deserialized")

	sigObj, err := sphincs.DeserializeSignature(keys.DefaultParams, sig.Signature)
	if err != nil {
		log.Printf("[ERROR] VerifyWithEmbeddedKey: failed to deserialize signature: %v", err)
		return false, fmt.Errorf("deserialize signature: %w", err)
	}
	log.Printf("[INFO] VerifyWithEmbeddedKey: signature deserialized")
	log.Printf("[DEBUG] VerifyWithEmbeddedKey: signature size: %d bytes", len(sig.Signature))

	result := sphincs.Spx_verify(keys.DefaultParams, msg, sigObj, pk)
	elapsed := time.Since(startTime)
	if result {
		log.Printf("[SUCCESS] VerifyWithEmbeddedKey: verification successful in %v", elapsed)
	} else {
		log.Printf("[FAILED] VerifyWithEmbeddedKey: verification failed in %v", elapsed)
	}
	return result, nil
}

// BindingCheck confirms that the public key embedded in a Signature struct
// matches the registered public key for the given passphrase. Call this
// BEFORE calling VerifyWithEmbeddedKey to prevent key-substitution attacks.
//
// Returns the registered KeyPair and any error.
func BindingCheck(sig *Signature, passphrase string) (*keys.KeyPair, error) {
	startTime := time.Now()
	log.Printf("[INFO] BindingCheck: starting key binding check")

	if sig == nil || len(sig.PublicKey) == 0 {
		log.Printf("[ERROR] BindingCheck: signature has no embedded public key")
		return nil, fmt.Errorf("signature has no embedded public key")
	}
	log.Printf("[DEBUG] BindingCheck: embedded public key (hex prefix): %s...", hex.EncodeToString(sig.PublicKey)[:min(64, len(sig.PublicKey))])

	registeredKP, skBytes, err := keys.LoadKeyFromDisk(passphrase)
	if err != nil {
		log.Printf("[ERROR] BindingCheck: failed to load registered key: %v", err)
		return nil, fmt.Errorf("load registered key for binding check: %w", err)
	}

	// Always zero the sensitive key material before returning
	defer func() {
		if skBytes != nil {
			for i := range skBytes {
				skBytes[i] = 0
			}
			_ = skBytes // Prevent compiler optimization
			log.Printf("[INFO] BindingCheck: private key bytes zeroed")
		}
	}()
	log.Printf("[INFO] BindingCheck: registered key loaded")
	log.Printf("[DEBUG] BindingCheck: registered public key (hex prefix): %s...", hex.EncodeToString(registeredKP.PublicKey)[:min(64, len(registeredKP.PublicKey))])

	// Constant-time comparison of public keys
	if subtle.ConstantTimeCompare(sig.PublicKey, registeredKP.PublicKey) != 1 {
		log.Printf("[ERROR] BindingCheck: key binding failed - embedded key does not match registered identity")
		return nil, fmt.Errorf("key binding check failed: embedded key does not match registered identity")
	}

	elapsed := time.Since(startTime)
	log.Printf("[SUCCESS] BindingCheck: key binding verified successfully in %v", elapsed)
	return registeredKP, nil
}

// LoadKeyPairForSigning returns the decrypted SK raw bytes together with the
// public key. The caller MUST zero skBytes immediately after use:
//
//	_, skBytes, err := LoadKeyPairForSigning(passphrase)
//	defer func() { for i := range skBytes { skBytes[i] = 0 } }()
func LoadKeyPairForSigning(passphrase string) (pkBytes, skBytes []byte, err error) {
	log.Printf("[INFO] LoadKeyPairForSigning: loading keypair")

	kp, sk, err := keys.LoadKeyFromDisk(passphrase)
	if err != nil {
		log.Printf("[ERROR] LoadKeyPairForSigning: failed to load keypair: %v", err)
		return nil, nil, err
	}
	log.Printf("[INFO] LoadKeyPairForSigning: keypair loaded - caller MUST zero skBytes after use")
	log.Printf("[DEBUG] LoadKeyPairForSigning: public key (hex prefix): %s...", hex.EncodeToString(kp.PublicKey)[:min(64, len(kp.PublicKey))])
	return kp.PublicKey, sk, nil
}

// VerifyWithPublicKey verifies a SPHINCS+ signature using explicit raw public
// key bytes supplied by the caller. Intended for the key server, which holds
// Bob's SphincsPub bytes directly and has no passphrase to load from disk.
//
// The pubKey parameter is authoritative — sig.PublicKey is ignored entirely.
// This prevents a caller from accidentally passing an untrusted embedded key.
func VerifyWithPublicKey(message []byte, sig *Signature, pubKey []byte) (bool, error) {
	startTime := time.Now()
	log.Printf("[INFO] VerifyWithPublicKey: starting verification with explicit public key (size: %d bytes)", len(pubKey))
	log.Printf("[DEBUG] VerifyWithPublicKey: message hash (hex): %s", hex.EncodeToString(message))
	log.Printf("[DEBUG] VerifyWithPublicKey: public key (hex prefix): %s...", hex.EncodeToString(pubKey)[:min(64, len(pubKey))])

	if len(pubKey) == 0 {
		log.Printf("[ERROR] VerifyWithPublicKey: empty public key")
		return false, fmt.Errorf("VerifyWithPublicKey: empty public key")
	}
	if sig == nil || len(sig.Signature) == 0 {
		log.Printf("[ERROR] VerifyWithPublicKey: nil or empty signature")
		return false, fmt.Errorf("VerifyWithPublicKey: nil or empty signature")
	}
	log.Printf("[INFO] VerifyWithPublicKey: signature size: %d bytes", len(sig.Signature))
	log.Printf("[DEBUG] VerifyWithPublicKey: signature (hex prefix): %s...", hex.EncodeToString(sig.Signature)[:min(64, len(sig.Signature))])

	pk, err := sphincs.DeserializePK(keys.DefaultParams, pubKey)
	if err != nil {
		log.Printf("[ERROR] VerifyWithPublicKey: failed to deserialize public key: %v", err)
		return false, fmt.Errorf("VerifyWithPublicKey: deserialize public key: %w", err)
	}
	log.Printf("[INFO] VerifyWithPublicKey: public key deserialized successfully")

	sigObj, err := sphincs.DeserializeSignature(keys.DefaultParams, sig.Signature)
	if err != nil {
		log.Printf("[ERROR] VerifyWithPublicKey: failed to deserialize signature: %v", err)
		return false, fmt.Errorf("VerifyWithPublicKey: deserialize signature: %w", err)
	}
	log.Printf("[INFO] VerifyWithPublicKey: signature deserialized successfully")

	ok := sphincs.Spx_verify(keys.DefaultParams, message, sigObj, pk)
	elapsed := time.Since(startTime)
	if ok {
		log.Printf("[SUCCESS] VerifyWithPublicKey: signature verified successfully in %v", elapsed)
	} else {
		log.Printf("[FAILED] VerifyWithPublicKey: signature verification failed in %v", elapsed)
	}
	return ok, nil
}
