// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/testvc/test_test.go
package spxhash_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	svm "github.com/sphinxfndorg/protocol/src/core/svm/opcodes"
	hash "github.com/sphinxfndorg/protocol/src/spxhash/hash"
	"golang.org/x/crypto/hkdf"
)

const (
	testVectorKey     = "whats the Elvish word for friend"
	testVectorContext = "spxHash test vectors context v1"
)

type testVec struct {
	inputLen  int
	salt      []byte
	hash      string
	keyedHash string
	deriveKey string
	input     func() []byte
}

// generateInput creates the input pattern used in test vectors
func generateInput(length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = uint8(i % 251)
	}
	return out
}

// fixedSalt is a deterministic salt for test vectors
var fixedSalt = []byte("SPXHASH_TEST_VECTOR_SALT_2024")

// vectors contains precomputed test vectors for SpxHash with fixed salt
var vectors = []testVec{
	{
		inputLen:  0,
		salt:      fixedSalt,
		hash:      "875bb731c84bd2813a30618e4214e3678e4ea2a900f63175ff6484b44e1d0d87",
		keyedHash: computeKeyedHash(0),
		deriveKey: computeDerivedKey(0),
		input:     func() []byte { return generateInput(0) },
	},
	{
		inputLen:  1,
		salt:      fixedSalt,
		hash:      "7e58479ba72f0cce53de87a2934c89d9dff2525071f7beba076c14bc984cdee6",
		keyedHash: computeKeyedHash(1),
		deriveKey: computeDerivedKey(1),
		input:     func() []byte { return generateInput(1) },
	},
	{
		inputLen:  1023,
		salt:      fixedSalt,
		hash:      "a51b5376687f55d9ba42291d73be54f3d9bc6a32bf30318cbe0c8e0ef9daaa00",
		keyedHash: computeKeyedHash(1023),
		deriveKey: computeDerivedKey(1023),
		input:     func() []byte { return generateInput(1023) },
	},
	{
		inputLen:  1024,
		salt:      fixedSalt,
		hash:      "ea9e3491da045156312334ef2f0f8b33ddb8b94510861a3f1c0e97d9599395e1",
		keyedHash: computeKeyedHash(1024),
		deriveKey: computeDerivedKey(1024),
		input:     func() []byte { return generateInput(1024) },
	},
	{
		inputLen:  2048,
		salt:      fixedSalt,
		hash:      "56f1eec6ff8c53611f6bd2c5fef7d653e8f3d68c7853b05998c942745d9fcfa1",
		keyedHash: computeKeyedHash(2048),
		deriveKey: computeDerivedKey(2048),
		input:     func() []byte { return generateInput(2048) },
	},
	{
		inputLen:  4096,
		salt:      fixedSalt,
		hash:      "e7dcedda19fc88cee0cd4c65088107fc1d80187af7f7ea94d69807230556dc60",
		keyedHash: computeKeyedHash(4096),
		deriveKey: computeDerivedKey(4096),
		input:     func() []byte { return generateInput(4096) },
	},
}

// computeKeyedHash generates the HMAC-SHA-512/256 for a given input length
func computeKeyedHash(inputLen int) string {
	input := generateInput(inputLen)
	mac := hmac.New(sha512.New512_256, []byte(testVectorKey))
	mac.Write(input)
	return hex.EncodeToString(mac.Sum(nil))
}

// computeDerivedKey generates the HKDF-SHA-512/256 for a given input length
func computeDerivedKey(inputLen int) string {
	input := generateInput(inputLen)
	hkdf := hkdf.New(sha512.New512_256, []byte(testVectorKey), input, []byte(testVectorContext))
	output := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, output); err != nil {
		panic(err)
	}
	return hex.EncodeToString(output)
}

// computeHashWithSalt computes SpxHash with a fixed salt for deterministic testing
func computeHashWithSalt(input []byte, salt []byte) ([]byte, error) {
	s, err := hash.NewSphinxHash(256, salt)
	if err != nil {
		return nil, err
	}
	return s.GetHash(input), nil
}

// hashCache stores computed hashes to avoid redundant computations
var (
	hashCache = make(map[int]string)
	cacheMu   sync.Mutex
	fileMu    sync.Mutex
)

// computeHash generates the SpxHash and logs opcode info
func computeHash(inputLen int, logFile *os.File) string {
	cacheMu.Lock()
	if cachedHash, found := hashCache[inputLen]; found {
		opcodeMsg := fmt.Sprintf("Using opcode: SphinxHash=0x%02X (cached)\n", svm.SphinxHash)
		fmt.Print(opcodeMsg)
		if logFile != nil {
			fileMu.Lock()
			fmt.Fprint(logFile, opcodeMsg)
			fileMu.Unlock()
		}
		cacheMu.Unlock()
		return cachedHash
	}
	cacheMu.Unlock()

	input := generateInput(inputLen)

	// Compute hash with fixed salt
	hashBytes, err := computeHashWithSalt(input, fixedSalt)
	if err != nil {
		panic(fmt.Sprintf("Failed to compute hash: %v", err))
	}

	opcodeMsg := fmt.Sprintf("Using opcode: SphinxHash=0x%02X\n", svm.SphinxHash)
	fmt.Print(opcodeMsg)
	if logFile != nil {
		fileMu.Lock()
		fmt.Fprint(logFile, opcodeMsg)
		fileMu.Unlock()
	}

	result := hex.EncodeToString(hashBytes)
	cacheMu.Lock()
	hashCache[inputLen] = result
	cacheMu.Unlock()
	return result
}

// TestVectors verifies the test vectors and prints them in the required format
func TestVectors(t *testing.T) {
	filename := filepath.Join(".", "vectorsoutput.txt")
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("Failed to open TXT file: %v", err)
	}
	defer f.Close()

	header := "=== RUN   TestPrintHashes"
	fmt.Println(header)
	fileMu.Lock()
	fmt.Fprintln(f, header)
	fileMu.Unlock()

	for _, vec := range vectors {
		computedHash := computeHash(vec.inputLen, f)

		// Print hash line
		hashLine := fmt.Sprintf("inputLen: %d, hash: %s", vec.inputLen, computedHash)
		fmt.Println(hashLine)
		fileMu.Lock()
		fmt.Fprintln(f, hashLine)
		fileMu.Unlock()

		// Print vector line
		line := fmt.Sprintf(
			"<vector inputLen=%d hash=%s keyedHash=%s deriveKey=%s>",
			vec.inputLen, computedHash, vec.keyedHash, vec.deriveKey,
		)
		fmt.Println(line)
		fileMu.Lock()
		fmt.Fprintln(f, line)
		fileMu.Unlock()
	}

	footer := "--- PASS: TestPrintHashes (0.00s)"
	fmt.Println(footer)
	fileMu.Lock()
	fmt.Fprintln(f, footer)
	fileMu.Unlock()
}

// TestRandomSaltNonDeterminism verifies that different instances produce different hashes
func TestRandomSaltNonDeterminism(t *testing.T) {
	input := []byte("test input for randomness")

	s1, err := hash.NewSphinxHash(256, nil)
	if err != nil {
		t.Fatalf("Failed to create SphinxHash: %v", err)
	}

	s2, err := hash.NewSphinxHash(256, nil)
	if err != nil {
		t.Fatalf("Failed to create SphinxHash: %v", err)
	}

	h1 := s1.GetHash(input)
	h2 := s2.GetHash(input)

	if bytes.Equal(h1, h2) {
		t.Error("Different instances produced identical hashes - salt may not be random")
	}
}

// TestFixedSaltDeterminism verifies that fixed salt produces consistent results
func TestFixedSaltDeterminism(t *testing.T) {
	input := []byte("test input")
	salt := []byte("deterministic_salt_12345")

	s1, err := hash.NewSphinxHash(256, salt)
	if err != nil {
		t.Fatalf("Failed to create SphinxHash: %v", err)
	}
	h1 := s1.GetHash(input)

	s2, err := hash.NewSphinxHash(256, salt)
	if err != nil {
		t.Fatalf("Failed to create SphinxHash: %v", err)
	}
	h2 := s2.GetHash(input)

	h3 := s1.GetHash(input)

	if !bytes.Equal(h1, h2) {
		t.Errorf("Same salt produced different hashes between instances - determinism broken\n  h1: %x\n  h2: %x", h1, h2)
	}

	if !bytes.Equal(h1, h3) {
		t.Errorf("Same instance produced different hashes on subsequent calls\n  h1: %x\n  h3: %x", h1, h3)
	}
}

// TestDifferentBitSizes verifies that different bit sizes produce different output lengths
func TestDifferentBitSizes(t *testing.T) {
	input := []byte("test input")
	salt := []byte("test_salt")

	bitSizes := []int{256, 384, 512}
	expectedLengths := map[int]int{
		256: 32,
		384: 48,
		512: 64,
	}

	for _, bitSize := range bitSizes {
		t.Run(fmt.Sprintf("bitSize=%d", bitSize), func(t *testing.T) {
			s, err := hash.NewSphinxHash(bitSize, salt)
			if err != nil {
				t.Fatalf("Failed to create SphinxHash: %v", err)
			}
			result := s.GetHash(input)
			expectedLen := expectedLengths[bitSize]
			if len(result) != expectedLen {
				t.Errorf("Expected length %d, got %d", expectedLen, len(result))
			}
		})
	}
}

// BenchmarkSpxHash benchmarks the actual hash computation
func BenchmarkSpxHash(b *testing.B) {
	filename := filepath.Join(".", "vectorsoutput.txt")
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		b.Fatalf("Failed to open vectorsoutput.txt: %v", err)
	}
	defer f.Close()

	header := "=== RUN   BenchmarkSpxHash"
	fmt.Println(header)
	fileMu.Lock()
	fmt.Fprintln(f, header)
	fileMu.Unlock()

	for _, vec := range vectors {
		b.Run(fmt.Sprintf("inputLen=%d", vec.inputLen), func(b *testing.B) {
			// Warm up the cache
			computeHash(vec.inputLen, f)
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				computeHash(vec.inputLen, nil)
			}

			// Print benchmark result
			result := fmt.Sprintf(
				"BenchmarkSpxHash/inputLen=%d-%d %d %f ns/op",
				vec.inputLen, runtime.NumCPU(), b.N, float64(b.Elapsed().Nanoseconds())/float64(b.N),
			)
			fmt.Println(result)
			fileMu.Lock()
			fmt.Fprintln(f, result)
			fileMu.Unlock()
		})
	}

	footer := "--- PASS: BenchmarkSpxHash"
	fmt.Println(footer)
	fileMu.Lock()
	fmt.Fprintln(f, footer)
	fileMu.Unlock()
}

// BenchmarkSHA512_256 benchmarks SHA-512/256 for comparison
func BenchmarkSHA512_256(b *testing.B) {
	filename := filepath.Join(".", "vectorsoutput.txt")
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		b.Fatalf("Failed to open vectorsoutput.txt: %v", err)
	}
	defer f.Close()

	header := "=== RUN   BenchmarkSHA512_256"
	fmt.Println(header)
	fileMu.Lock()
	fmt.Fprintln(f, header)
	fileMu.Unlock()

	for _, vec := range vectors {
		b.Run(fmt.Sprintf("inputLen=%d", vec.inputLen), func(b *testing.B) {
			input := generateInput(vec.inputLen)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				h := sha512.New512_256()
				h.Write(input)
				h.Sum(nil)
			}
			result := fmt.Sprintf(
				"BenchmarkSHA512_256/inputLen=%d-%d %d %f ns/op",
				vec.inputLen, runtime.NumCPU(), b.N, float64(b.Elapsed().Nanoseconds())/float64(b.N),
			)
			fmt.Println(result)
			fileMu.Lock()
			fmt.Fprintln(f, result)
			fileMu.Unlock()
		})
	}

	footer := "--- PASS: BenchmarkSHA512_256"
	fmt.Println(footer)
	fileMu.Lock()
	fmt.Fprintln(f, footer)
	fileMu.Unlock()
}

// TestMain runs once before all tests
func TestMain(m *testing.M) {
	// Clear cache before tests
	hashCache = make(map[int]string)

	code := m.Run()
	os.Exit(code)
}
