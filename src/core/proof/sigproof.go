// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/core/proof/sigproof.go
package sigproof

import (
	"bytes"
	"errors"
	"sync"

	"github.com/sphinxorg/protocol/src/common"
)

// SIPS-0011 https://github.com/sphinxorg/SIPS/wiki/sips0011

var (
	mu          sync.Mutex
	storedProof []byte // Global variable for storing the proof
)

// GenerateSigProof generates a hash of the signature parts, Merkle leaves, and public key as a proof
func GenerateSigProof(sigParts [][]byte, leaves [][]byte, pkBytes []byte) ([]byte, error) {
	mu.Lock()
	defer mu.Unlock()

	if len(sigParts) == 0 {
		return nil, errors.New("no signature parts provided")
	}

	// Include pkBytes in the proof generation
	hash := generateHashFromParts(sigParts, leaves, pkBytes)
	return hash, nil
}

// generateHashFromParts creates a combined hash of the given signature parts, Merkle leaves, and public key
func generateHashFromParts(parts [][]byte, leaves [][]byte, pkBytes []byte) []byte {
	var combined []byte
	for _, part := range parts {
		combined = append(combined, part...)
	}
	for _, leaf := range leaves {
		combined = append(combined, leaf...)
	}
	// Append the public key bytes
	combined = append(combined, pkBytes...)

	return common.SpxHash(combined)
}

// VerifySigProof compares the generated hash with the expected proof hash
func VerifySigProof(proofHash, generatedHash []byte) bool {
	mu.Lock()
	defer mu.Unlock()
	return bytes.Equal(proofHash, generatedHash)
}

// SetStoredProof safely sets the stored proof
func SetStoredProof(proof []byte) {
	mu.Lock()
	defer mu.Unlock()
	storedProof = proof
}

// GetStoredProof safely retrieves the stored proof
func GetStoredProof() []byte {
	mu.Lock()
	defer mu.Unlock()
	return storedProof
}

// VerifyStoredProof re-derives the proof from public inputs and compares
// against the stored proof. Call this after sigBytes has been discarded.
//
// Inputs available permanently after sigBytes is gone:
//
//	storedProof    — the 32-byte proof Charlie stored at verification time
//	message        — the transaction content (always public)
//	timestamp      — 8 bytes, from Charlie's DB
//	nonce          — 16 bytes, from Charlie's DB
//	merkleRootHash — 32 bytes, from Charlie's DB
//	commitment     — 32 bytes, from Charlie's DB
//	pkBytes        — Alice's public key (always public, in registry)
//	signatureHash  — OPTIONAL: 32 bytes, for content-based replay verification
//
// What a PASS means:
//
//	The values you provided are byte-for-byte identical to what Charlie
//	passed to Spx_verify. Charlie's Spx_verify ran on these exact inputs.
//
// What a PASS does NOT mean:
//
//	It does not re-run Spx_verify. sigBytes is gone — that is by design.
//	It proves consistency of the receipt, not validity of the signature.
//	The caller must trust that Charlie ran Spx_verify honestly at tx time.
func VerifyStoredProof(
	storedProof []byte,
	message, timestamp, nonce []byte,
	merkleRootHash, commitment []byte,
	pkBytes []byte,
	signatureHash ...[]byte, // variadic - optional signature hash
) bool {
	// Rebuild the proof message exactly as GenerateSigProof received it.
	proofMsg := make([]byte, 0, len(timestamp)+len(nonce)+len(message))
	proofMsg = append(proofMsg, timestamp...)
	proofMsg = append(proofMsg, nonce...)
	proofMsg = append(proofMsg, message...)

	commitmentLeaf := common.SpxHash(commitment) // CommitmentLeaf inline

	regenerated, err := GenerateSigProof(
		[][]byte{proofMsg},
		[][]byte{merkleRootHash, commitmentLeaf},
		pkBytes,
	)
	if err != nil {
		return false
	}

	// Verify the proof matches
	if !VerifySigProof(storedProof, regenerated) {
		return false
	}

	// If signature hash was provided, verify it's not empty
	if len(signatureHash) > 0 && len(signatureHash[0]) == 32 {
		// Check if signature hash is all zeros (invalid)
		allZero := true
		for i := 0; i < len(signatureHash[0]); i++ {
			if signatureHash[0][i] != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return false
		}
		// Signature hash is valid
	}

	return true
}
