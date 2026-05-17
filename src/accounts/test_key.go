// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package main

import (
	"fmt"
	"log"

	seed "github.com/sphinxorg/protocol/src/accounts/phrase"
	auth "github.com/sphinxorg/protocol/src/core/wallet/auth"
	utils "github.com/sphinxorg/protocol/src/core/wallet/utils"
)

func main() {
	// Step 1: Generate the keys (passphrase, Base32-encoded passkey, fingerprint, chain code, and macKey)
	passphrase, base32Passkey, _, macKey, chainCode, fingerprint, err := seed.GenerateKeys()
	if err != nil {
		// Log the error and terminate the program if key generation fails
		log.Fatalf("Error generating keys: %v", err)
	}

	// Step 2: Display the generated keys for debugging or information purposes
	fmt.Println("Passphrase: ", passphrase)            // Display the original mnemonic phrase
	fmt.Println("Passkey: ", base32Passkey)            // Display the Base32-encoded passkey
	fmt.Printf("MacKey: %x\n", macKey)                 // Display the fingerprint in hexadecimal format
	fmt.Printf("Chain code (Mackey): %x\n", chainCode) // Display the Chain code in hexadecimal format
	fmt.Printf("Fingerprint: %x\n", fingerprint)       // Display the hmac key in hexadecimal format

	// Step 3: Verify the Base32 passkey
	// Now using the `VerifyBase32Passkey` function from `utils`, which no longer generates a root hash.
	isValidmacKey, _, _, err := utils.VerifyBase32Passkey(base32Passkey)
	if err != nil {
		// If verification fails, print an error message
		fmt.Printf("Verification failed: %v\n", err)
	} else {
		// If verification succeeds, display the results
		fmt.Printf("Verification macKey result: %t\n", isValidmacKey) // Indicate whether the passkey is valid
	}

	// Step 4: Verify the fingerprint
	isValidFingerprint, err := auth.VerifyFingerPrint(base32Passkey, passphrase)
	if err != nil {
		// If verification fails, print an error message
		fmt.Printf("Fingerprint verification failed: %v\n", err)
	} else if isValidFingerprint {
		// If the fingerprint verification succeeds, display the result
		fmt.Printf("Verification fingerprint result: %t\n", isValidFingerprint)
	} else {
		// If the fingerprint does not match
		fmt.Println("Fingerprint did not match!")
	}
}
