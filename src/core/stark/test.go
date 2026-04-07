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

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	params "github.com/sphinxorg/protocol/src/core/sphincs/config"
	key "github.com/sphinxorg/protocol/src/core/sphincs/key/backend"
	sign "github.com/sphinxorg/protocol/src/core/stark/zk"
)

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	fmt.Println("Initializing STARK proof tests...")

	// Initialize SignManager
	fmt.Println("Creating SignManager...")
	start := time.Now()
	sm, err := sign.NewSignManager()
	if err != nil {
		fmt.Printf("Test failed: Failed to create SignManager: %v\n", err)
		return
	}
	fmt.Printf("SignManager created successfully in %.3f sec.\n", time.Since(start).Seconds())

	// Initialize SPHINCS+ parameters
	fmt.Println("Initializing SPHINCS+ parameters...")
	start = time.Now()
	sphincsParams, err := params.NewSPHINCSParameters()
	if err != nil {
		fmt.Printf("Test failed: Failed to initialize SPHINCS+ parameters: %v\n", err)
		return
	}
	fmt.Printf("SPHINCS+ parameters initialized: N=%d, K=%d, A=%d, H=%d, D=%d, Len=%d, LogT=%d, RANDOMIZE=%v\n",
		sphincsParams.Params.N, sphincsParams.Params.K, sphincsParams.Params.A,
		sphincsParams.Params.H, sphincsParams.Params.D, sphincsParams.Params.Len,
		sphincsParams.Params.LogT, sphincsParams.Params.RANDOMIZE)
	fmt.Printf("Parameters initialization time: %.3f sec\n", time.Since(start).Seconds())

	// Initialize Signer
	signer := sign.NewSigner()

	// Test Case 1: High TPS simulation (100 signatures)
	fmt.Println("\n=== Test Case 1: High TPS simulation (100 signatures) ===")
	start = time.Now()
	const numTxs = 100
	const batchSize = 100
	fmt.Printf("Generating %d signatures...\n", numTxs)
	signatures := make([]sign.Signature, numTxs)
	km, err := key.NewKeyManager()
	if err != nil {
		fmt.Printf("Test Case 1 failed: Failed to create KeyManager: %v\n", err)
		return
	}

	// Parallel signature generation AND verification
	var wg sync.WaitGroup
	sigErrChan := make(chan error, numTxs)

	for i := 0; i < numTxs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			msg := []byte(fmt.Sprintf("message %d", i))

			// Generate key pair
			sk, pk, err := km.GenerateKey()
			if err != nil {
				sigErrChan <- fmt.Errorf("failed to generate key pair for signature %d: %v", i+1, err)
				return
			}

			// Log for first signature only
			if i == 0 {
				skBytes, err := sk.SerializeSK()
				if err != nil {
					sigErrChan <- fmt.Errorf("failed to serialize secret key: %v", err)
					return
				}
				pkBytes, err := pk.SerializePK()
				if err != nil {
					sigErrChan <- fmt.Errorf("failed to serialize public key: %v", err)
					return
				}
				fmt.Printf("    Secret Key (hex, first signature): %s\n", hex.EncodeToString(skBytes))
				fmt.Printf("    Secret Key size: %d bytes\n", len(skBytes))
				fmt.Printf("    Public Key (hex, first signature): %s\n", hex.EncodeToString(pkBytes))
				fmt.Printf("    Public Key size: %d bytes\n", len(pkBytes))
			}

			// Sign message
			signStart := time.Now()
			sig, err := signer.SignMessage(sphincsParams, msg, sk)
			if err != nil {
				sigErrChan <- fmt.Errorf("failed to generate signature %d: %v", i+1, err)
				return
			}
			signDuration := time.Since(signStart).Seconds()

			// Log for first signature
			if i == 0 {
				sigHex, _, err := signer.SerializeSignature(sig)
				if err != nil {
					sigErrChan <- fmt.Errorf("failed to serialize signature %d: %v", i+1, err)
					return
				}
				fmt.Printf("    Signature (hex, first signature): %s\n", sigHex)
				sigBytes, err := hex.DecodeString(sigHex)
				if err != nil {
					sigErrChan <- fmt.Errorf("failed to decode signature hex: %v", err)
					return
				}
				fmt.Printf("    Signature size: %d bytes\n", len(sigBytes))
				fmt.Printf("    Signature generation time (first signature): %.3f sec\n", signDuration)
			}

			// =============================================
			// FIX: VERIFY ALL SIGNATURES (not just the first)
			// =============================================
			verifyStart := time.Now()
			valid, err := signer.VerifySignature(sphincsParams, msg, sig, pk)
			verifyDuration := time.Since(verifyStart).Seconds()

			if err != nil || !valid {
				sigErrChan <- fmt.Errorf("signature verification FAILED for signature %d: %v", i+1, err)
				return
			}

			// Log verification result for first and last signatures
			if i == 0 {
				fmt.Printf("    Signature verification result (first): true\n")
				fmt.Printf("    Signature verification time (first): %.3f sec\n", verifyDuration)
			} else if i == numTxs-1 {
				fmt.Printf("    Signature verification result (last): true\n")
				fmt.Printf("    Signature verification time (last): %.3f sec\n", verifyDuration)
			} else if i < 5 {
				// Log first few verifications to show they're all being checked
				fmt.Printf("    Signature %d verified: true (%.3f sec)\n", i+1, verifyDuration)
			}

			signatures[i] = sign.Signature{
				Message:   msg,
				Signature: sig,
				PublicKey: pk,
			}
		}(i)
	}

	wg.Wait()
	close(sigErrChan)

	// Check if any signature generation or verification failed
	for err := range sigErrChan {
		if err != nil {
			fmt.Printf("Test Case 1 failed: %v\n", err)
			return
		}
	}

	fmt.Printf("All %d signatures generated and VERIFIED successfully.\n", numTxs)

	// Generate STARK proofs in batches
	fmt.Printf("\nGenerating STARK proofs for %d VERIFIED signatures in batches of %d...\n", numTxs, batchSize)
	proofStart := time.Now()
	proofs := make([]*sign.STARKProof, 0, (numTxs+batchSize-1)/batchSize)
	proofChan := make(chan *sign.STARKProof, (numTxs+batchSize-1)/batchSize)
	proofErrChan := make(chan error, (numTxs+batchSize-1)/batchSize)

	for i := 0; i < numTxs; i += batchSize {
		wg.Add(1)
		go func(startIdx int) {
			defer wg.Done()
			endIdx := min(startIdx+batchSize, numTxs)
			proof, err := sm.GenerateSTARKProof(signatures[startIdx:endIdx])
			if err != nil {
				proofErrChan <- fmt.Errorf("failed to generate batch STARK proof: %v", err)
				return
			}
			proofChan <- proof
		}(i)
	}

	wg.Wait()
	close(proofChan)
	close(proofErrChan)

	for proof := range proofChan {
		proofs = append(proofs, proof)
	}
	for err := range proofErrChan {
		if err != nil {
			fmt.Printf("Test Case 1 failed: %v\n", err)
			return
		}
	}
	proofGenDuration := time.Since(proofStart).Seconds()

	// Log proof details for the first proof
	for i, proof := range proofs {
		if i == 0 {
			fmt.Printf("\n  Commitment (hex, first proof): %s\n", hex.EncodeToString(proof.Commitment))
			fmt.Printf("  Evaluation Root (hex, first proof): %s\n", hex.EncodeToString(proof.DomainParams.EvaluationRoot))
			fmt.Printf("  Computation Trace (first 5 elements, hex):")
			for j, elem := range proof.DomainParams.Trace[:min(5, len(proof.DomainParams.Trace))] {
				fmt.Printf(" %s", elem.Big().Text(16))
				if j < min(5, len(proof.DomainParams.Trace))-1 {
					fmt.Print(",")
				}
			}
			fmt.Println()
			fmt.Printf("  Polynomial Evaluations (first 5, hex):")
			for j, eval := range proof.DomainParams.PolynomialEvaluations[:min(5, len(proof.DomainParams.PolynomialEvaluations))] {
				fmt.Printf(" %s", eval.Text(16))
				if j < min(5, len(proof.DomainParams.PolynomialEvaluations))-1 {
					fmt.Print(",")
				}
			}
			fmt.Println()
			proofBytes, err := json.Marshal(proof)
			if err != nil {
				fmt.Printf("Test Case 1 failed: Failed to serialize STARK proof: %v\n", err)
				return
			}
			fmt.Printf("  STARK proof size (first proof): %d bytes\n", len(proofBytes))
		}
	}
	fmt.Printf("\n  STARK proof generation time: %.3f sec\n", proofGenDuration)
	fmt.Println("STARK proofs generated successfully.")

	// Verify STARK proofs
	fmt.Println("\nVerifying STARK proofs...")
	verifyStart := time.Now()
	verifyErrChan := make(chan error, len(proofs))

	for _, proof := range proofs {
		wg.Add(1)
		go func(p *sign.STARKProof) {
			defer wg.Done()
			valid, err := sm.VerifySTARKProof(p)
			if err != nil || !valid {
				verifyErrChan <- fmt.Errorf("STARK proof verification failed: %v", err)
			}
		}(proof)
	}

	wg.Wait()
	close(verifyErrChan)

	for err := range verifyErrChan {
		if err != nil {
			fmt.Printf("Test Case 1 failed: %v\n", err)
			return
		}
	}
	verifyDuration := time.Since(verifyStart).Seconds()
	fmt.Printf("  STARK proof verification time: %.3f sec\n", verifyDuration)
	fmt.Printf("\n✅ Test Case 1 passed: All %d signatures verified, STARK proof valid (total time: %.3f sec)\n",
		numTxs, time.Since(start).Seconds())
}
