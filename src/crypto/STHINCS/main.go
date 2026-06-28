// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/main.go
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
)

func main() {
	// Define test cases - ALL variants including ALL SHA256 and SHAKE256
	testCases := []struct {
		name   string
		params *parameters.Parameters
	}{
		// ========================================================================
		// SHA256 Variants - ALL Security Levels
		// ========================================================================
		// SHA256 - Security Level 5 (N=32, 256-bit)
		{"SHA256-256f (LV 5)", parameters.MakeSthincsPlusSHA256256fRobust(true)},
		{"SHA256-256s (LV 5)", parameters.MakeSthincsPlusSHA256256sRobust(true)},

		// SHA256 - Security Level 3 (N=24, 192-bit)
		{"SHA256-192f (LV 3)", parameters.MakeSthincsPlusSHA256192fRobust(true)},
		{"SHA256-192s (LV 3)", parameters.MakeSthincsPlusSHA256192sRobust(true)},

		// SHA256 - Security Level 1 (N=16, 128-bit)
		{"SHA256-128f (LV 1)", parameters.MakeSthincsPlusSHA256128fRobust(true)},
		{"SHA256-128s (LV 1)", parameters.MakeSthincsPlusSHA256128sRobust(true)},

		// ========================================================================
		// SHAKE256 Variants - ALL Security Levels
		// ========================================================================
		// SHAKE256 - Security Level 5 (N=32, 256-bit)
		{"SHAKE256-256f (LV 5)", parameters.MakeSthincsPlusSHAKE256256fRobust(true)},
		{"SHAKE256-256s (LV 5)", parameters.MakeSthincsPlusSHAKE256256sRobust(true)},

		// SHAKE256 - Security Level 3 (N=24, 192-bit)
		{"SHAKE256-192f (LV 3)", parameters.MakeSthincsPlusSHAKE256192fRobust(true)},
		{"SHAKE256-192s (LV 3)", parameters.MakeSthincsPlusSHAKE256192sRobust(true)},

		// SHAKE256 - Security Level 1 (N=16, 128-bit)
		{"SHAKE256-128f (LV 1)", parameters.MakeSthincsPlusSHAKE256128fRobust(true)},
		{"SHAKE256-128s (LV 1)", parameters.MakeSthincsPlusSHAKE256128sRobust(true)},

		// ========================================================================
		// SPHINXHASH Variants - ALL Security Levels
		// ========================================================================
		// SPHINXHASH - Security Level 5 (N=32, 256-bit)
		{"SPHINXHASH-256f (LV 5)", parameters.MakeSthincsPlusSPHINXHASH256fRobust(true)},
		{"SPHINXHASH-256s (LV 5)", parameters.MakeSthincsPlusSPHINXHASH256sRobust(true)},

		// SPHINXHASH - Security Level 3 (N=24, 192-bit)
		{"SPHINXHASH-192f (LV 3)", parameters.MakeSthincsPlusSPHINXHASH192fRobust(true)},
		{"SPHINXHASH-192s (LV 3)", parameters.MakeSthincsPlusSPHINXHASH192sRobust(true)},

		// SPHINXHASH - Security Level 1 (N=16, 128-bit)
		{"SPHINXHASH-128f (LV 1)", parameters.MakeSthincsPlusSPHINXHASH128fRobust(true)},
		{"SPHINXHASH-128s (LV 1)", parameters.MakeSthincsPlusSPHINXHASH128sRobust(true)},
	}

	// Print expanded table header - REMOVED MaxSigs column (redundant, all H=30)
	fmt.Println("\n" + strings.Repeat("=", 165))
	fmt.Printf("%-35s | %-4s | %-4s | %-4s | %-4s | %-5s | %-5s | %-5s | %-8s | %-8s | %-10s | %-10s | %-10s | %-10s | %-6s\n",
		"Parameter Set", "N", "W", "H", "D", "H'", "K", "LogT", "PKSize(B)", "SKSize(B)", "KeyGen(ms)", "Sign(ms)", "Verify(ms)", "SigSize(B)", "Valid")
	fmt.Println(strings.Repeat("-", 165))

	// Store results for each test
	type Result struct {
		name          string
		params        *parameters.Parameters
		pkSize        int
		skSize        int
		keygenTime    time.Duration
		signTime      time.Duration
		verifyTime    time.Duration
		signatureSize int
		valid         bool
		err           error
	}

	var results []Result

	// Run all tests
	for _, tc := range testCases {
		result := Result{
			name:   tc.name,
			params: tc.params,
		}

		// Print parameters row
		fmt.Printf("%-35s | %-4d | %-4d | %-4d | %-4d | %-5d | %-5d | %-5d | ",
			truncateString(tc.name, 33),
			tc.params.N,
			tc.params.W,
			tc.params.H,
			tc.params.D,
			tc.params.Hprime,
			tc.params.K,
			tc.params.LogT)

		// Generate key pair
		start := time.Now()
		sk, pk, err := sthincs.Spx_keygen(tc.params)
		result.keygenTime = time.Since(start)

		if err != nil {
			result.err = err
			fmt.Printf("%-8s | %-8s | %-10s | %-10s | %-10s | %-10s | %-6s\n",
				"ERROR", "ERROR", "ERROR", "ERROR", "ERROR", "ERROR", "ERROR")
			results = append(results, result)
			continue
		}

		// Get PK and SK sizes using serialization
		serializedPK, err := pk.SerializePK()
		if err != nil {
			result.err = err
			fmt.Printf("%-8s | %-8s | %-10s | %-10s | %-10s | %-10s | %-6s\n",
				"ERROR", "ERROR", "ERROR", "ERROR", "ERROR", "ERROR", "ERROR")
			results = append(results, result)
			continue
		}
		result.pkSize = len(serializedPK)

		serializedSK, err := sk.SerializeSK()
		if err != nil {
			result.err = err
			fmt.Printf("%-8s | %-8s | %-10s | %-10s | %-10s | %-10s | %-6s\n",
				formatSize(result.pkSize), "ERROR", "ERROR", "ERROR", "ERROR", "ERROR", "ERROR")
			results = append(results, result)
			continue
		}
		result.skSize = len(serializedSK)

		// Print PK and SK sizes
		fmt.Printf("%-8s | %-8s | ",
			formatSize(result.pkSize),
			formatSize(result.skSize))

		// Sign a message
		message := []byte("Test message for STHINCS with 2^30 signature limit")
		start = time.Now()
		signature, err := sthincs.Spx_sign(tc.params, message, sk)
		result.signTime = time.Since(start)

		if err != nil {
			result.err = err
			fmt.Printf("%-10s | %-10s | %-10s | %-10s | %-6s\n",
				"ERROR", "ERROR", "ERROR", "ERROR", "ERROR")
			results = append(results, result)
			continue
		}

		// Get signature size using SerializeSignature method
		serializedSig, err := signature.SerializeSignature()
		if err != nil {
			result.err = err
			fmt.Printf("%-10s | %-10s | %-10s | %-10s | %-6s\n",
				formatDuration(result.keygenTime), formatDuration(result.signTime),
				"ERROR", "ERROR", "ERROR")
			results = append(results, result)
			continue
		}
		result.signatureSize = len(serializedSig)

		// Verify signature
		start = time.Now()
		result.valid = sthincs.Spx_verify(tc.params, message, signature, pk)
		result.verifyTime = time.Since(start)

		// Print timing results
		validStr := "✓"
		if !result.valid {
			validStr = "✗"
		}

		fmt.Printf("%-10s | %-10s | %-10s | %-10d | %-6s\n",
			formatDuration(result.keygenTime),
			formatDuration(result.signTime),
			formatDuration(result.verifyTime),
			result.signatureSize,
			validStr)

		results = append(results, result)
	}

	fmt.Println(strings.Repeat("=", 165))

	// Print detailed summary table with all parameters including PK/SK sizes
	fmt.Println("\n" + strings.Repeat("=", 165))
	fmt.Println("DETAILED SUMMARY TABLE")
	fmt.Println(strings.Repeat("-", 165))
	fmt.Printf("%-35s | %-4s | %-4s | %-4s | %-4s | %-5s | %-5s | %-5s | %-8s | %-8s | %-10s | %-10s | %-10s | %-12s | %-10s\n",
		"Parameter Set", "N", "W", "H", "D", "H'", "K", "LogT", "PK(B)", "SK(B)", "KeyGen(ms)", "Sign(ms)", "Verify(ms)", "SigSize(B)", "Status")
	fmt.Println(strings.Repeat("-", 165))

	for _, r := range results {
		status := "✓ OK"
		if r.err != nil {
			status = fmt.Sprintf("✗ %v", r.err)
		} else if !r.valid {
			status = "✗ Invalid"
		}

		fmt.Printf("%-35s | %-4d | %-4d | %-4d | %-4d | %-5d | %-5d | %-5d | %-8s | %-8s | %-10s | %-10s | %-10s | %-12d | %-10s\n",
			truncateString(r.name, 33),
			r.params.N,
			r.params.W,
			r.params.H,
			r.params.D,
			r.params.Hprime,
			r.params.K,
			r.params.LogT,
			formatSize(r.pkSize),
			formatSize(r.skSize),
			formatDuration(r.keygenTime),
			formatDuration(r.signTime),
			formatDuration(r.verifyTime),
			r.signatureSize,
			status)
	}
	fmt.Println(strings.Repeat("=", 165))

	// Print compact comparison table with key sizes
	fmt.Println("\n" + strings.Repeat("=", 165))
	fmt.Println("COMPACT COMPARISON TABLE (Key Sizes & Performance)")
	fmt.Println(strings.Repeat("-", 165))
	fmt.Printf("%-30s | %-6s | %-5s | %-8s | %-8s | %-8s | %-8s | %-8s | %-10s | %-10s\n",
		"Parameter Set", "N", "LogT", "PK(B)", "SK(B)", "Sig(B)", "KeyGen(ms)", "Sign(ms)", "Verify(ms)", "Hash")
	fmt.Println(strings.Repeat("-", 165))

	for _, r := range results {
		if r.err == nil && r.valid {
			hashType := ""
			if strings.Contains(r.name, "SHA256") {
				hashType = "SHA256"
			} else if strings.Contains(r.name, "SHAKE256") {
				hashType = "SHAKE256"
			} else if strings.Contains(r.name, "SPHINXHASH") {
				hashType = "SPHINX"
			}

			fmt.Printf("%-30s | %-6d | %-5d | %-8s | %-8s | %-8d | %-8s | %-8s | %-10s | %-10s\n",
				truncateString(r.name, 28),
				r.params.N,
				r.params.LogT,
				formatSize(r.pkSize),
				formatSize(r.skSize),
				r.signatureSize,
				formatDuration(r.keygenTime),
				formatDuration(r.signTime),
				formatDuration(r.verifyTime),
				hashType)
		}
	}
	fmt.Println(strings.Repeat("=", 165))

	// Calculate actual parameter ranges from test results
	nValues := make(map[int]bool)
	wValues := make(map[int]bool)
	hValues := make(map[int]bool)
	dValues := make(map[int]bool)
	hprimeValues := make(map[int]bool)
	kValues := make(map[int]bool)
	logtValues := make(map[int]bool)

	minK, maxK := int(^uint(0)>>1), 0
	minLogT, maxLogT := int(^uint(0)>>1), 0

	for _, r := range results {
		if r.err == nil && r.valid {
			nValues[r.params.N] = true
			wValues[r.params.W] = true
			hValues[r.params.H] = true
			dValues[r.params.D] = true
			hprimeValues[r.params.Hprime] = true
			kValues[r.params.K] = true
			logtValues[r.params.LogT] = true

			if r.params.K < minK {
				minK = r.params.K
			}
			if r.params.K > maxK {
				maxK = r.params.K
			}
			if r.params.LogT < minLogT {
				minLogT = r.params.LogT
			}
			if r.params.LogT > maxLogT {
				maxLogT = r.params.LogT
			}
		}
	}

	// Convert maps to sorted slices for display
	nList := []int{}
	for n := range nValues {
		nList = append(nList, n)
	}

	wList := []int{}
	for w := range wValues {
		wList = append(wList, w)
	}

	hList := []int{}
	for h := range hValues {
		hList = append(hList, h)
	}

	dList := []int{}
	for d := range dValues {
		dList = append(dList, d)
	}

	hprimeList := []int{}
	for hp := range hprimeValues {
		hprimeList = append(hprimeList, hp)
	}

	// Print key size summary by security level
	fmt.Println("\n" + strings.Repeat("=", 100))
	fmt.Println("KEY SIZE SUMMARY BY SECURITY LEVEL")
	fmt.Println(strings.Repeat("-", 100))
	fmt.Printf("%-20s | %-12s | %-12s | %-12s\n", "Security Level", "PK Size", "SK Size", "Signature Size")
	fmt.Println(strings.Repeat("-", 100))

	// Group by security level (N value)
	level5Results := []Result{}
	level3Results := []Result{}
	level1Results := []Result{}

	for _, r := range results {
		if r.err == nil && r.valid {
			switch r.params.N {
			case 32:
				level5Results = append(level5Results, r)
			case 24:
				level3Results = append(level3Results, r)
			case 16:
				level1Results = append(level1Results, r)
			}
		}
	}

	if len(level5Results) > 0 {
		avgPK := 0
		avgSK := 0
		avgSig := 0
		for _, r := range level5Results {
			avgPK += r.pkSize
			avgSK += r.skSize
			avgSig += r.signatureSize
		}
		avgPK /= len(level5Results)
		avgSK /= len(level5Results)
		avgSig /= len(level5Results)
		fmt.Printf("%-20s | %-12s | %-12s | %-12d\n",
			"Level 5 (N=32, 128-bit)",
			formatSize(avgPK),
			formatSize(avgSK),
			avgSig)
	}

	if len(level3Results) > 0 {
		avgPK := 0
		avgSK := 0
		avgSig := 0
		for _, r := range level3Results {
			avgPK += r.pkSize
			avgSK += r.skSize
			avgSig += r.signatureSize
		}
		avgPK /= len(level3Results)
		avgSK /= len(level3Results)
		avgSig /= len(level3Results)
		fmt.Printf("%-20s | %-12s | %-12s | %-12d\n",
			"Level 3 (N=24, 192-bit)",
			formatSize(avgPK),
			formatSize(avgSK),
			avgSig)
	}

	if len(level1Results) > 0 {
		avgPK := 0
		avgSK := 0
		avgSig := 0
		for _, r := range level1Results {
			avgPK += r.pkSize
			avgSK += r.skSize
			avgSig += r.signatureSize
		}
		avgPK /= len(level1Results)
		avgSK /= len(level1Results)
		avgSig /= len(level1Results)
		fmt.Printf("%-20s | %-12s | %-12s | %-12d\n",
			"Level 1 (N=16, 128-bit legacy)",
			formatSize(avgPK),
			formatSize(avgSK),
			avgSig)
	}
	fmt.Println(strings.Repeat("=", 100))

	// Print count of tested variants
	successfulTests := 0
	for _, r := range results {
		if r.err == nil && r.valid {
			successfulTests++
		}
	}

	fmt.Printf("\n📊 Total parameter sets tested: %d\n", len(results))
	fmt.Printf("   ✅ Successful: %d\n", successfulTests)
	fmt.Printf("   ❌ Failed: %d\n", len(results)-successfulTests)

	// Print actual parameter ranges from test results
	fmt.Printf("\n📈 Parameter ranges tested:\n")
	fmt.Printf("   - N (security): %s bytes\n", joinInts(nList, ", "))
	fmt.Printf("   - W (Winternitz): %s (fixed)\n", joinInts(wList, ", "))
	fmt.Printf("   - H (total height): %s (2^H = 2^30 = 1,073,741,824 signatures)\n", joinInts(hList, ", "))
	fmt.Printf("   - D (layers): %s\n", joinInts(dList, ", "))
	fmt.Printf("   - H' (tree height): %s\n", joinInts(hprimeList, ", "))
	fmt.Printf("   - K (FORS trees): %d-%d depending on security level\n", minK, maxK)
	fmt.Printf("   - LogT (FORS height): %d-%d depending on variant\n", minLogT, maxLogT)

	fmt.Printf("\n📈 Key Size Summary:\n")
	if len(level5Results) > 0 {
		fmt.Printf("   - Level 5 (N=32): PK=%d bytes, SK=%d bytes\n",
			level5Results[0].pkSize, level5Results[0].skSize)
	}
	if len(level3Results) > 0 {
		fmt.Printf("   - Level 3 (N=24): PK=%d bytes, SK=%d bytes\n",
			level3Results[0].pkSize, level3Results[0].skSize)
	}
	if len(level1Results) > 0 {
		fmt.Printf("   - Level 1 (N=16): PK=%d bytes, SK=%d bytes\n",
			level1Results[0].pkSize, level1Results[0].skSize)
	}
	fmt.Printf("   - Signature: Varies by parameter set (see table)\n")

	// Warning about signature limit (2^30 = 1,073,741,824 signatures)
	fmt.Printf("\n⚠ WARNING: All key pairs are limited to 2^30 = 1,073,741,824 signatures!\n")
	fmt.Println("           Signature lifetime analysis:")
	fmt.Println("             - 1 signature/second   → 34 years")
	fmt.Println("             - 10 signatures/second  → 3.4 years")
	fmt.Println("             - 100 signatures/second → 124 days")
	fmt.Println("             - 1,000 signatures/second → 12.4 days")
	fmt.Println()
	fmt.Println("           Track signature counts carefully and rotate keys before limit!")

	// Exit with error code if any test failed
	if successfulTests < len(results) {
		fmt.Println("\n❌ Some tests failed!")
		os.Exit(1)
	}
}

func formatDuration(d time.Duration) string {
	ms := float64(d.Nanoseconds()) / 1000000.0
	return fmt.Sprintf("%.2f", ms)
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func formatSize(size int) string {
	return fmt.Sprintf("%d", size)
}

func joinInts(ints []int, sep string) string {
	if len(ints) == 0 {
		return ""
	}
	result := fmt.Sprintf("%d", ints[0])
	for i := 1; i < len(ints); i++ {
		result += sep + fmt.Sprintf("%d", ints[i])
	}
	return result
}
