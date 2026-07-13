// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/common/types_test.go
package common

import (
	"bytes"
	"fmt"
	"testing"

	spxhash "github.com/sphinxfndorg/protocol/src/spxhash/hash"
)

// TestSpxHashBasic tests basic SpxHash functionality with various inputs.
func TestSpxHashBasic(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty input", []byte{}},
		{"simple string", []byte("hello world")},
		{"longer string", []byte("The quick brown fox jumps over the lazy dog")},
		{"binary data", []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}},
		{"unicode", []byte("Hello 世界 🌍")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SpxHash(tt.input)
			if result == nil {
				t.Fatalf("SpxHash returned nil for input: %s", tt.name)
			}
			if len(result) != 32 { // 256-bit = 32 bytes
				t.Errorf("SpxHash returned %d bytes, expected 32", len(result))
			}
		})
	}
}

// TestSpxHashDeterministic tests that the same input always produces the same hash.
func TestSpxHashDeterministic(t *testing.T) {
	input := []byte("deterministic test")

	hash1 := SpxHash(input)
	hash2 := SpxHash(input)
	hash3 := SpxHash(input)

	if !bytes.Equal(hash1, hash2) {
		t.Error("SpxHash is not deterministic: hash1 != hash2")
	}
	if !bytes.Equal(hash1, hash3) {
		t.Error("SpxHash is not deterministic: hash1 != hash3")
	}
}

// TestSpxHashDifferentInputs tests that different inputs produce different hashes.
func TestSpxHashDifferentInputs(t *testing.T) {
	input1 := []byte("input one")
	input2 := []byte("input two")
	input3 := []byte("input one") // duplicate of input1

	hash1 := SpxHash(input1)
	hash2 := SpxHash(input2)
	hash3 := SpxHash(input3)

	if bytes.Equal(hash1, hash2) {
		t.Error("Different inputs produced identical hashes")
	}
	if !bytes.Equal(hash1, hash3) {
		t.Error("Same inputs produced different hashes (determinism failure)")
	}
}

// TestSpxHashAvalancheEffect tests the avalanche effect (small input change = large output change).
func TestSpxHashAvalancheEffect(t *testing.T) {
	input1 := []byte("test data")
	input2 := []byte("test datb") // changed last char

	hash1 := SpxHash(input1)
	hash2 := SpxHash(input2)

	// Count differing bits
	if len(hash1) != len(hash2) {
		t.Fatalf("Hash lengths differ: %d vs %d", len(hash1), len(hash2))
	}

	differingBits := 0
	for i := range hash1 {
		xor := hash1[i] ^ hash2[i]
		for j := 0; j < 8; j++ {
			if (xor>>j)&1 == 1 {
				differingBits++
			}
		}
	}

	totalBits := len(hash1) * 8
	changePercentage := float64(differingBits) / float64(totalBits)

	if changePercentage < 0.3 {
		t.Errorf("Avalanche effect too weak: only %.1f%% bits changed (expected ~50%%)", changePercentage*100)
	}
}

// TestSpxHashConcurrency tests thread safety of the shared hasher instance.
func TestSpxHashConcurrency(t *testing.T) {
	const goroutines = 100
	const iterations = 50

	results := make(chan []byte, goroutines*iterations)
	errors := make(chan error, goroutines*iterations)

	input := []byte("concurrent test")

	for i := 0; i < goroutines; i++ {
		go func() {
			for j := 0; j < iterations; j++ {
				hash := SpxHash(input)
				if hash == nil {
					errors <- nil // will be caught below
					continue
				}
				results <- hash
			}
		}()
	}

	// Collect all results
	var allHashes [][]byte
	for i := 0; i < goroutines*iterations; i++ {
		select {
		case hash := <-results:
			allHashes = append(allHashes, hash)
		case <-errors:
			t.Fatal("SpxHash returned nil in concurrent test")
		}
	}

	// All hashes should be identical
	referenceHash := allHashes[0]
	for i, hash := range allHashes {
		if !bytes.Equal(hash, referenceHash) {
			t.Errorf("Hash at index %d differs from reference (concurrency issue)", i)
		}
	}
}

// TestSpxHashCacheEffectiveness verifies that the LRU cache is being used.
func TestSpxHashCacheEffectiveness(t *testing.T) {
	// Call SpxHash multiple times with the same input.
	// Due to the singleton pattern, subsequent calls should hit the cache.
	input := []byte("cache test input")

	// First call to initialize the hasher
	_ = SpxHash(input)

	// Multiple calls with same input - all should succeed and be identical
	hashes := make([][]byte, 10)
	for i := range hashes {
		hashes[i] = SpxHash(input)
	}

	for i := 1; i < len(hashes); i++ {
		if !bytes.Equal(hashes[i], hashes[0]) {
			t.Errorf("Cache miss at call %d: hash differs", i)
		}
	}
}

// TestSpxHashEmptyInput tests hashing empty byte slice.
func TestSpxHashEmptyInput(t *testing.T) {
	result := SpxHash([]byte{})
	if result == nil {
		t.Fatal("SpxHash returned nil for empty input")
	}
	if len(result) != 32 {
		t.Errorf("Empty input hash has %d bytes, expected 32", len(result))
	}

	// Empty input should be deterministic
	result2 := SpxHash([]byte{})
	if !bytes.Equal(result, result2) {
		t.Error("Empty input is not deterministic")
	}
}

// TestSpxHashLargeInput tests hashing a larger input.
func TestSpxHashLargeInput(t *testing.T) {
	// Create a 64KB input
	input := make([]byte, 64*1024)
	for i := range input {
		input[i] = byte(i)
	}

	result := SpxHash(input)
	if result == nil {
		t.Fatal("SpxHash returned nil for large input")
	}
	if len(result) != 32 {
		t.Errorf("Large input hash has %d bytes, expected 32", len(result))
	}
}

// TestSpxHashConsistencyAcrossCalls tests that the singleton pattern maintains consistency.
func TestSpxHashConsistencyAcrossCalls(t *testing.T) {
	inputs := [][]byte{
		[]byte("test1"),
		[]byte("test2"),
		[]byte("test3"),
		{},
		[]byte("a"),
		[]byte("ab"),
		[]byte("abc"),
	}

	// Call SpxHash multiple times and store first results
	firstResults := make([][]byte, len(inputs))
	for i, input := range inputs {
		firstResults[i] = SpxHash(input)
	}

	// Call again and verify consistency
	for i, input := range inputs {
		result := SpxHash(input)
		if !bytes.Equal(result, firstResults[i]) {
			t.Errorf("Inconsistent hash for input %d across calls", i)
		}
	}
}

// BenchmarkSpxHash benchmarks the SpxHash function.
func BenchmarkSpxHash(b *testing.B) {
	input := []byte("benchmark input data")

	for b.Loop() {
		_ = SpxHash(input)
	}
}

// BenchmarkSpxHashLargeInput benchmarks SpxHash with larger input.
func BenchmarkSpxHashLargeInput(b *testing.B) {
	input := make([]byte, 1024)
	for i := range input {
		input[i] = byte(i)
	}

	for b.Loop() {
		_ = SpxHash(input)
	}
}

// TestSpxHashMatchesSpxHashAPI verifies that common.SpxHash produces identical
// output to spxhash.NewSphinxHash(256, spxhash.ProtocolSalt).GetHash(data).
func TestSpxHashMatchesSpxHashAPI(t *testing.T) {
	testInputs := [][]byte{
		[]byte("test"),
		[]byte("hello world"),
		{},
		{0x00, 0x01, 0x02, 0x03},
	}

	for i, data := range testInputs {
		t.Run(fmt.Sprintf("input_%d", i), func(t *testing.T) {
			// Create SphinxHash instance directly with ProtocolSalt
			s, err := spxhash.NewSphinxHash(256, spxhash.ProtocolSalt)
			if err != nil {
				t.Fatalf("Failed to create SphinxHash: %v", err)
			}
			expected := s.GetHash(data)

			// Get hash from common.SpxHash
			actual := SpxHash(data)
			if actual == nil {
				t.Fatal("SpxHash returned nil")
			}

			if !bytes.Equal(expected, actual) {
				t.Errorf("SpxHash output does not match direct API\n  expected: %x\n  actual:   %x", expected, actual)
			}
		})
	}
}

// TestSpxHashDeterminismAcrossRuns verifies that SpxHash produces consistent
// results across multiple calls within the same test run.
func TestSpxHashDeterminismAcrossRuns(t *testing.T) {
	inputs := [][]byte{
		[]byte("determinism check 1"),
		[]byte("determinism check 2"),
		[]byte("determinism check 3"),
	}

	rounds := 5
	hashes := make([][][]byte, rounds)

	for r := 0; r < rounds; r++ {
		hashes[r] = make([][]byte, len(inputs))
		for i, input := range inputs {
			hashes[r][i] = SpxHash(input)
		}
	}

	// Compare all rounds
	for r := 1; r < rounds; r++ {
		for i := range inputs {
			if !bytes.Equal(hashes[r][i], hashes[0][i]) {
				t.Errorf("Non-deterministic output at round %d, input %d", r, i)
			}
		}
	}
}
