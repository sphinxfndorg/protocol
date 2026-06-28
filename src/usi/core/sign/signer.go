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

	sthincs "github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
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
	// Zero the raw private key bytes immediately after use.
	defer func() {
		for i := range skBytes {
			skBytes[i] = 0
		}
		log.Printf("[INFO] Sign: private key bytes zeroed")
	}()

	// Get the key manager from the keys package
	keyManager := keys.GetKeyManager()
	if keyManager == nil {
		return nil, fmt.Errorf("key manager not initialized")
	}

	// Get SPHINCS+ parameters from key manager
	params := keyManager.GetSPHINCSParameters()
	if params == nil || params.Params == nil {
		return nil, fmt.Errorf("SPHINCS+ parameters not initialized")
	}

	// Deserialize the private key using the key manager's DeserializeKeyPair
	// We only need the private key, but DeserializeKeyPair needs both
	sk, _, err := keyManager.DeserializeKeyPair(skBytes, kp.PublicKey)
	if err != nil {
		log.Printf("[ERROR] Sign: failed to deserialize key pair: %v", err)
		return nil, fmt.Errorf("deserialize key pair: %w", err)
	}
	log.Printf("[INFO] Sign: private key deserialized successfully")

	// Create a proper SPHINCS_SK struct for signing
	sphincsSK := &sthincs.SPHINCS_SK{
		SKseed: sk.SKseed,
		SKprf:  sk.SKprf,
		PKseed: sk.PKseed,
		PKroot: sk.PKroot,
	}

	// Generate the signature using the SPHINCS+ library
	// Spx_sign returns (signature, error)
	sigObj, err := sthincs.Spx_sign(params.Params, msg, sphincsSK)
	if err != nil {
		log.Printf("[ERROR] Sign: failed to create signature: %v", err)
		return nil, fmt.Errorf("sign: %w", err)
	}
	if sigObj == nil {
		log.Printf("[ERROR] Sign: failed to create signature - nil object")
		return nil, fmt.Errorf("failed to create signature")
	}
	log.Printf("[INFO] Sign: SPHINCS+ signature created")

	sigBytes, err := sigObj.SerializeSignature()
	if err != nil {
		log.Printf("[ERROR] Sign: failed to serialize signature: %v", err)
		return nil, fmt.Errorf("serialize signature: %w", err)
	}
	log.Printf("[INFO] Sign: signature serialized (size: %d bytes)", len(sigBytes))

	// Deserialize public key for serialization
	pk, err := sthincs.DeserializePK(params.Params, kp.PublicKey)
	if err != nil {
		log.Printf("[ERROR] Sign: failed to deserialize public key: %v", err)
		return nil, fmt.Errorf("deserialize PK: %w", err)
	}
	log.Printf("[INFO] Sign: public key deserialized successfully")

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
// The trusted key MUST come from a local key store or an out-of-band trusted
// source — never from the same untrusted file that contains the signature.
func Verify(msg []byte, sig *Signature, trustedPKBytes []byte) (bool, error) {
	startTime := time.Now()
	log.Printf("[INFO] Verify: starting verification for message length %d bytes", len(msg))

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

	// Get the key manager and parameters
	keyManager := keys.GetKeyManager()
	if keyManager == nil {
		return false, fmt.Errorf("key manager not initialized")
	}

	params := keyManager.GetSPHINCSParameters()
	if params == nil || params.Params == nil {
		return false, fmt.Errorf("SPHINCS+ parameters not initialized")
	}

	// Deserialize the trusted public key
	pk, err := sthincs.DeserializePK(params.Params, trustedPKBytes)
	if err != nil {
		log.Printf("[ERROR] Verify: failed to deserialize trusted public key: %v", err)
		return false, fmt.Errorf("deserialize trusted PK: %w", err)
	}
	log.Printf("[INFO] Verify: trusted public key deserialized successfully")

	// Deserialize the signature
	sigObj, err := sthincs.DeserializeSignature(params.Params, sig.Signature)
	if err != nil {
		log.Printf("[ERROR] Verify: failed to deserialize signature: %v", err)
		return false, fmt.Errorf("deserialize signature: %w", err)
	}
	log.Printf("[INFO] Verify: signature deserialized successfully")

	// Verify the signature
	ok := sthincs.Spx_verify(params.Params, msg, sigObj, pk)
	elapsed := time.Since(startTime)
	if ok {
		log.Printf("[SUCCESS] Verify: signature verified successfully against trusted key in %v", elapsed)
	} else {
		log.Printf("[FAILED] Verify: signature verification failed against trusted key in %v", elapsed)
	}
	return ok, nil
}

// VerifyWithRegisteredKey verifies a signature against the key currently
// registered on disk for the given passphrase.
func VerifyWithRegisteredKey(msg []byte, sig *Signature, passphrase string) (bool, error) {
	log.Printf("[INFO] VerifyWithRegisteredKey: starting verification")

	if passphrase == "" {
		log.Printf("[ERROR] VerifyWithRegisteredKey: empty passphrase")
		return false, fmt.Errorf("passphrase required to load registered key")
	}

	registeredKP, skBytes, err := keys.LoadKeyFromDisk(passphrase)
	if err != nil {
		log.Printf("[ERROR] VerifyWithRegisteredKey: failed to load registered key: %v", err)
		return false, fmt.Errorf("load registered key: %w", err)
	}
	defer func() {
		for i := range skBytes {
			skBytes[i] = 0
		}
		log.Printf("[INFO] VerifyWithRegisteredKey: private key bytes zeroed")
	}()

	result, err := Verify(msg, sig, registeredKP.PublicKey)
	if result {
		log.Printf("[SUCCESS] VerifyWithRegisteredKey: verification successful")
	} else {
		log.Printf("[FAILED] VerifyWithRegisteredKey: verification failed")
	}
	return result, err
}

// VerifyWithEmbeddedKey verifies a signature using the public key embedded
// inside the Signature struct itself.
//
// WARNING: This function MUST only be used when the caller has already
// independently confirmed that sig.PublicKey matches the registered key.
func VerifyWithEmbeddedKey(msg []byte, sig *Signature, passphrase string) (bool, error) {
	log.Printf("[INFO] VerifyWithEmbeddedKey: starting verification with embedded key")

	// First verify key matches registered key
	registeredKP, _, err := keys.LoadKeyFromDisk(passphrase)
	if err != nil {
		log.Printf("[ERROR] VerifyWithEmbeddedKey: failed to load registered key: %v", err)
		return false, err
	}
	if subtle.ConstantTimeCompare(sig.PublicKey, registeredKP.PublicKey) != 1 {
		log.Printf("[ERROR] VerifyWithEmbeddedKey: embedded key does not match registered key")
		return false, errors.New("embedded key does not match registered key")
	}
	log.Printf("[INFO] VerifyWithEmbeddedKey: key binding verification passed")

	result, err := Verify(msg, sig, sig.PublicKey)
	if result {
		log.Printf("[SUCCESS] VerifyWithEmbeddedKey: verification successful")
	} else {
		log.Printf("[FAILED] VerifyWithEmbeddedKey: verification failed")
	}
	return result, err
}

// VerifyWithPublicKey verifies a SPHINCS+ signature using explicit raw public
// key bytes supplied by the caller.
func VerifyWithPublicKey(message []byte, sig *Signature, pubKey []byte) (bool, error) {
	log.Printf("[INFO] VerifyWithPublicKey: starting verification with explicit public key (size: %d bytes)", len(pubKey))

	if len(pubKey) == 0 {
		log.Printf("[ERROR] VerifyWithPublicKey: empty public key")
		return false, fmt.Errorf("VerifyWithPublicKey: empty public key")
	}
	if sig == nil || len(sig.Signature) == 0 {
		log.Printf("[ERROR] VerifyWithPublicKey: nil or empty signature")
		return false, fmt.Errorf("VerifyWithPublicKey: nil or empty signature")
	}

	result, err := Verify(message, sig, pubKey)
	if result {
		log.Printf("[SUCCESS] VerifyWithPublicKey: verification successful")
	} else {
		log.Printf("[FAILED] VerifyWithPublicKey: verification failed")
	}
	return result, err
}

// BindingCheck confirms that the public key embedded in a Signature struct
// matches the registered public key for the given passphrase.
func BindingCheck(sig *Signature, passphrase string) (*keys.KeyPair, error) {
	log.Printf("[INFO] BindingCheck: starting key binding check")

	if sig == nil || len(sig.PublicKey) == 0 {
		log.Printf("[ERROR] BindingCheck: signature has no embedded public key")
		return nil, fmt.Errorf("signature has no embedded public key")
	}

	registeredKP, skBytes, err := keys.LoadKeyFromDisk(passphrase)
	if err != nil {
		log.Printf("[ERROR] BindingCheck: failed to load registered key: %v", err)
		return nil, fmt.Errorf("load registered key for binding check: %w", err)
	}
	defer func() {
		if skBytes != nil {
			for i := range skBytes {
				skBytes[i] = 0
			}
			log.Printf("[INFO] BindingCheck: private key bytes zeroed")
		}
	}()

	if subtle.ConstantTimeCompare(sig.PublicKey, registeredKP.PublicKey) != 1 {
		log.Printf("[ERROR] BindingCheck: key binding failed - embedded key does not match registered identity")
		return nil, fmt.Errorf("key binding check failed: embedded key does not match registered identity")
	}

	log.Printf("[SUCCESS] BindingCheck: key binding verified successfully")
	return registeredKP, nil
}

// LoadKeyPairForSigning returns the decrypted SK raw bytes together with the
// public key. The caller MUST zero skBytes immediately after use.
func LoadKeyPairForSigning(passphrase string) (pkBytes, skBytes []byte, err error) {
	log.Printf("[INFO] LoadKeyPairForSigning: loading keypair")

	kp, sk, err := keys.LoadKeyFromDisk(passphrase)
	if err != nil {
		log.Printf("[ERROR] LoadKeyPairForSigning: failed to load keypair: %v", err)
		return nil, nil, err
	}
	log.Printf("[INFO] LoadKeyPairForSigning: keypair loaded - caller MUST zero skBytes after use")
	return kp.PublicKey, sk, nil
}
