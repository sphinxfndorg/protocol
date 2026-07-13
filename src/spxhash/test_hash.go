// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/test_hash.go
package main

import (
	"fmt"
	"log"

	spxhash "github.com/sphinxfndorg/protocol/src/spxhash/hash"
)

func main() {
	// Define three different messages to hash
	messages := [][]byte{
		[]byte("Hello, SphinxHash!"),
		[]byte("Hello, Sphinxhash!"),
		[]byte("Hash functions are fascinating."),
	}

	// Iterate over the messages and compute their hashes
	for i, data := range messages {
		fmt.Printf("\nMessage %d: %s\n", i+1, data)

		// FIX SALT-DEMO: NewSphinxHash requires a non-empty salt (see FIX DET
		// in spxhash.go) — a deterministic hasher isn't meaningful without a
		// fixed salt to derive from. Passing []byte{} here always returned an
		// error, so this demo never got past message 1 before hitting
		// log.Fatalf. ProtocolSalt is the package's canonical, public salt
		// for exactly this kind of deterministic, reproducible hashing (the
		// same one common.SpxHash uses), so it's the right value for a demo
		// that hashes the same messages the same way on every run.
		sphinx, err := spxhash.NewSphinxHash(256, spxhash.ProtocolSalt)
		if err != nil {
			log.Fatalf("Error creating SphinxHash for message %d: %v", i+1, err)
		}

		// Write data to the SphinxHash instance
		n, err := sphinx.Write(data)
		if err != nil {
			log.Fatalf("Error writing data for message %d: %v", i+1, err)
		}
		fmt.Printf("Wrote %d bytes to the hash.\n", n)

		// Retrieve the computed hash
		hash := sphinx.Sum(nil) // Sum with nil appends the hash to an empty slice
		fmt.Printf("Computed hash: %x\n", hash)

		// Check the length of the computed hash
		if len(hash) != 32 {
			fmt.Printf("Warning: Computed hash for message %d is not 256 bits.\n", i+1)
		} else {
			fmt.Printf("Computed hash for message %d is 256 bits.\n", i+1)
		}

		// Optional: You can check cache usage by trying to get the hash again
		cachedHash := sphinx.GetHash(data)
		if cachedHash != nil {
			fmt.Printf("Cached hash: %x\n", cachedHash)
		} else {
			fmt.Println("No cached hash found.")
		}
	}
}
