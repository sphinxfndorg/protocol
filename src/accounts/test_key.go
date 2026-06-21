// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package main

import (
	"fmt"
	"log"

	seed "github.com/sphinxorg/protocol/src/accounts/phrase"
)

// REMOVED DEPENDENCY: this file used to import
//
//	auth "github.com/sphinxorg/protocol/src/core/wallet/auth"
//	utils "github.com/sphinxorg/protocol/src/core/wallet/utils"
//
// Both packages are deleted. See seed.go for the replacement primitives
// (computeFingerprint / VerifyFingerprint) that this file now calls instead
// of auth.VerifyFingerPrint.
//
// utils.VerifyBase32Passkey has NO replacement here — see the note in
// main() below. I don't know what it actually checked internally (decode
// + recompute + compare against what reference value?), so rather than
// fabricate a function that merely compiles, I removed the call and left
// an explicit TODO. Filling it in correctly requires knowing what
// "valid" was supposed to mean for a passkey in isolation, vs. in the
// fingerprint-paired check this file already does below.
func main() {
	// Step 1: Generate the keys (passphrase, Base32-encoded passkey, fingerprint, chain code, and macKey)
	passphrase, base32Passkey, _, macKey, chainCode, fingerprint, err := seed.GenerateKeys()
	if err != nil {
		// Log the error and terminate the program if key generation fails
		log.Fatalf("Error generating keys: %v", err)
	}

	// Step 2: Display the generated keys for debugging or information purposes
	fmt.Println("Passphrase: ", passphrase) // Display the original mnemonic phrase
	fmt.Println("Passkey: ", base32Passkey) // Display the Base32-encoded passkey
	fmt.Printf("MacKey: %x\n", macKey)
	fmt.Printf("Chain code: %x\n", chainCode)
	fmt.Printf("Fingerprint: %x\n", fingerprint)

	// Step 3: Verify the Base32 passkey.
	//
	// REMOVED, NOT REPLACED: previously called
	//   utils.VerifyBase32Passkey(base32Passkey)
	// which returned (isValid bool, _, _, error) — two extra unnamed
	// values whose purpose I can't infer from this call site alone (the
	// original code discarded them with `_, _`). I don't have a
	// principled way to reconstruct what this checked, since it took only
	// the *encoded* passkey as input — no expected value to compare
	// against was passed in, suggesting it might have re-derived something
	// internally and compared against a value embedded in/alongside the
	// encoding, or checked structural validity (e.g. correct Base32
	// alphabet/length) rather than cryptographic correctness.
	//
	// Decode the raw bytes back out, at minimum, so the rest of this file
	// has something to work with — but this does NOT replace whatever
	// validation utils.VerifyBase32Passkey was actually doing.
	decodedPasskeyBytes, decodeErr := seed.DecodeBase32(base32Passkey)
	if decodeErr != nil {
		fmt.Printf("Base32 decode failed: %v\n", decodeErr)
	} else {
		fmt.Printf("Decoded passkey bytes: %x\n", decodedPasskeyBytes)
	}
	// TODO: replace with real passkey validation once you decide what
	// utils.VerifyBase32Passkey was supposed to guarantee. If it's "does
	// this decode to the expected length / hashedPasskey prefix", that's
	// straightforward to add back — let me know and I'll wire it up
	// against GenerateKeys()'s actual construction (hashedPasskey[:6 or 8]).

	// Step 4: Verify the fingerprint.
	//
	// REMOVED DEPENDENCY: previously
	//   auth.VerifyFingerPrint(base32Passkey, passphrase)
	// Replaced with seed.VerifyFingerprint, which takes the raw
	// passkeyBytes (not the Base32-encoded string) plus the expected
	// fingerprint to check against — a stricter, more explicit contract
	// than the original, which apparently re-derived everything from just
	// (base32Passkey, passphrase) without an explicit expected value.
	if decodeErr == nil {
		isValidFingerprint := seed.VerifyFingerprint(passphrase, decodedPasskeyBytes, fingerprint)
		if isValidFingerprint {
			fmt.Printf("Verification fingerprint result: %t\n", isValidFingerprint)
		} else {
			fmt.Println("Fingerprint did not match!")
		}
	}
}
