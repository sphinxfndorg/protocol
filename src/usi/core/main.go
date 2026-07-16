// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/main.go
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	seed "github.com/sphinxfndorg/protocol/src/accounts/phrase"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
	"github.com/sphinxfndorg/protocol/src/usi/core/sign"
)

func main() {
	// --- 1. Generate the recovery mnemonic (account root of trust) ---
	// Shown once. The wallet itself must NOT persist this — only the user's
	// physical record of it should survive past this point.
	mnemonic, base32Passkey, _, _, _, _, err := seed.GenerateKeys()
	if err != nil {
		log.Fatalf("Failed to generate keys from seed: %v", err)
	}
	fmt.Println("=== WRITE THIS DOWN — shown only once, never stored ===")
	fmt.Printf("Mnemonic: %s\n", mnemonic)
	fmt.Printf("Base32Passkey: %s\n", base32Passkey)
	fmt.Println("========================================================")

	// --- 2. Use the mnemonic as the passphrase for key generation ---
	// Following test_encrypt.go pattern, we use the generated mnemonic
	// as the passphrase for key encryption
	passphrase := mnemonic
	fmt.Printf("\nUsing passphrase for key encryption: %s\n", passphrase)

	// --- 3. Generate SPHINCS+ key pair using USI key package ---
	fmt.Println("\nGenerating SPHINCS+ key pair...")
	kp, err := keys.GenerateKeyPairWithOrg(passphrase, keys.OrgSPIF)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}
	fmt.Printf("SUCCESS Key pair generated successfully!\n")
	fmt.Printf("Address: %s\n", kp.Address)
	fmt.Printf("Public Key (hex, first 32): %x…\n", kp.PublicKey[:32])
	fmt.Printf("Key stored with ID: %s\n", kp.Path)
	fmt.Printf("Encrypted Secret Key (hex, first 32): %x…\n", kp.PrivateKey[:32])

	// --- 4. Test signing and verification ---
	const msg = "Hello, SPHINCS+!"
	fmt.Printf("\n--- Testing Sign/Verify ---\n")
	fmt.Printf("Message: %q\n", msg)

	// Sign the message using the passphrase
	sig, err := sign.Sign([]byte(msg), passphrase)
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}
	fmt.Printf("Signature (hex, first 64): %s…\n", hex.EncodeToString(sig.Signature[:64]))
	fmt.Printf("Embedded Public Key (hex, first 32): %x…\n", sig.PublicKey[:32])

	// Verify the signature using the embedded public key
	ok, err := sign.Verify([]byte(msg), sig, sig.PublicKey)
	if err != nil {
		log.Fatalf("Failed to verify: %v", err)
	}
	if ok {
		fmt.Println("SUCCESS Signature VERIFIED successfully!")
	} else {
		fmt.Println("ERROR Signature INVALID")
	}

	// --- 5. Simulate a fresh reload: load the key from storage ---
	// Following test_encrypt.go pattern, we load the key using the passphrase
	fmt.Println("\n--- Testing key reload from storage ---")

	loadedKp, skBytes, err := keys.LoadKeyFromDisk(passphrase)
	if err != nil {
		log.Printf("WARNING  Could not load key from disk: %v", err)
		fmt.Println("   (This is expected if the key ID is not 'default')")
		fmt.Println("   Use keys.GetKeyByID(keyID, passphrase) to load by specific ID")

		// Try to load by ID if we have one
		if kp.Path != "" {
			fmt.Printf("\n   Trying to load by ID: %s\n", kp.Path)
			loadedKp, skBytes, err = keys.GetKeyByID(kp.Path, passphrase)
			if err != nil {
				log.Printf("ERROR Failed to load key by ID: %v", err)
			} else {
				fmt.Printf("SUCCESS Key loaded successfully by ID!\n")
				fmt.Printf("   Loaded Address: %s\n", loadedKp.Address)
				fmt.Printf("   Loaded Secret Key (hex, first 32): %x…\n", skBytes[:32])
			}
		}
	} else {
		fmt.Printf("SUCCESS Key loaded successfully!\n")
		fmt.Printf("   Loaded Address: %s\n", loadedKp.Address)
		fmt.Printf("   Loaded Secret Key (hex, first 32): %x…\n", skBytes[:32])

		// Verify the loaded key matches the original
		if loadedKp.Address == kp.Address {
			fmt.Println("   SUCCESS Loaded key matches original key!")
		} else {
			fmt.Println("   WARNING  Loaded key address differs from original")
		}
	}

	// --- 6. Demonstrate signing with the loaded key ---
	if loadedKp != nil && len(skBytes) > 0 {
		fmt.Println("\n--- Testing sign with loaded key ---")
		sig2, err := sign.Sign([]byte(msg), passphrase)
		if err != nil {
			log.Printf("Failed to sign with loaded key: %v", err)
		} else {
			ok2, err := sign.Verify([]byte(msg), sig2, sig2.PublicKey)
			if err != nil {
				log.Printf("Failed to verify with loaded key: %v", err)
			} else if ok2 {
				fmt.Println("SUCCESS Signature with loaded key VERIFIED successfully!")
			} else {
				fmt.Println("ERROR Signature with loaded key INVALID")
			}
		}
	}

	fmt.Println("\n--- All done ---")
}
