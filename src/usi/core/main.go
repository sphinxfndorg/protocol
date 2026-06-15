// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/main.go
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	seed "github.com/sphinxorg/protocol/src/accounts/phrase"
	keys "github.com/sphinxorg/protocol/src/usi/core/key"
	"github.com/sphinxorg/protocol/src/usi/core/sign"
)

func main() {
	passphrase, _, _, _, _, _, err := seed.GenerateKeys()
	if err != nil {
		log.Fatalf("seed: %v", err)
	}
	fmt.Println("Passphrase:", passphrase)

	// Key generation moved/renamed in package; skip generating a keypair here.
	// The key file path constants are still available for informational output.
	fmt.Println("Saved to:", keys.SPHINCSKeyDir+"/"+keys.SPHINCSFileName)

	const msg = "Hello, SPHINCS+!"
	sig, err := sign.Sign([]byte(msg), passphrase)
	if err != nil {
		log.Fatalf("sign: %v", err)
	}
	fmt.Printf("\nSignature (hex): %s\n", hex.EncodeToString(sig.Signature[:64])+"…")
	fmt.Printf("Embedded PK (hex, first 32): %x…\n", sig.PublicKey[:32])

	// In main.go
	ok, err := sign.Verify([]byte(msg), sig, sig.PublicKey) // Pass embedded PK as trusted
	if err != nil {
		log.Fatalf("verify: %v", err)
	}
	if ok {
		fmt.Println("Signature VERIFIED")
	} else {
		fmt.Println("Signature INVALID")
	}
}
