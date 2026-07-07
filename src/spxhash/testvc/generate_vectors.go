// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/testvc/generate_vectors.go
//go:build ignore

package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"

	hash "github.com/sphinxfndorg/protocol/src/spxhash/hash"
	"golang.org/x/crypto/hkdf"
)

const (
	testVectorKey     = "whats the Elvish word for friend"
	testVectorContext = "spxHash test vectors context v1"
)

var fixedSalt = []byte("SPXHASH_TEST_VECTOR_SALT_2024")

func generateInput(length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = uint8(i % 251)
	}
	return out
}

func computeKeyedHash(inputLen int) string {
	input := generateInput(inputLen)
	mac := hmac.New(sha512.New512_256, []byte(testVectorKey))
	mac.Write(input)
	return hex.EncodeToString(mac.Sum(nil))
}

func computeDerivedKey(inputLen int) string {
	input := generateInput(inputLen)
	hkdf := hkdf.New(sha512.New512_256, []byte(testVectorKey), input, []byte(testVectorContext))
	output := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, output); err != nil {
		panic(err)
	}
	return hex.EncodeToString(output)
}

func main() {
	// FIX DET (confirming comment, no functional change): this call already
	// passes a non-empty, fixed salt (fixedSalt), so it is unaffected by the
	// split of NewSphinxHash into a deterministic, salt-required constructor
	// plus the separate NewSphinxHashKeyed for randomized instances. Test
	// vectors must be reproducible across runs, so this file deliberately
	// keeps using NewSphinxHash with an explicit salt rather than
	// NewSphinxHashKeyed.
	s, err := hash.NewSphinxHash(256, fixedSalt)
	if err != nil {
		panic(err)
	}

	lengths := []int{0, 1, 1023, 1024, 2048, 4096}

	fmt.Println("// Test vectors for SpxHash with fixed salt")
	fmt.Println("// Salt:", string(fixedSalt))
	fmt.Println()

	for _, length := range lengths {
		input := generateInput(length)
		hashBytes := s.GetHash(input)
		hashHex := hex.EncodeToString(hashBytes)

		fmt.Printf("inputLen: %d\n", length)
		fmt.Printf("hash: %q\n", hashHex)
		fmt.Printf("keyedHash: %q\n", computeKeyedHash(length))
		fmt.Printf("deriveKey: %q\n", computeDerivedKey(length))
		fmt.Println()
	}
}
