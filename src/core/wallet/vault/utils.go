// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/wallet/vault/utils.go
package vault

import (
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"unsafe"

	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
	"lukechampine.com/blake3"
)

// ---------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------
// clearBytes securely clears a byte slice from memory
func clearBytes(data []byte) {
	if data == nil {
		return
	}

	// Use compiler intrinsic for efficient memory clearing
	for i := range data {
		data[i] = 0
	}

	// Prevent compiler optimization
	_ = (*[0]byte)(unsafe.Pointer(&data[0]))
}

// NewSecureBuffer creates a new secure buffer with the given data
func NewSecureBuffer(data []byte) *SecureBuffer {
	return &SecureBuffer{data: data}
}

// Bytes returns a copy of the underlying data (use with caution)
func (sb *SecureBuffer) Bytes() []byte {
	if sb.data == nil {
		return nil
	}
	cp := make([]byte, len(sb.data))
	copy(cp, sb.data)
	return cp
}

// Clear securely wipes the buffer from memory
func (sb *SecureBuffer) Clear() {
	if sb.data != nil {
		for i := range sb.data {
			sb.data[i] = 0
		}
		sb.data = nil
	}
	runtime.GC() // Encourage garbage collection
}

// Len returns the length of the data
func (sb *SecureBuffer) Len() int {
	if sb.data == nil {
		return 0
	}
	return len(sb.data)
}

// ---------------------------------------------------------------------
// Key Derivation (matches keys package)
// ---------------------------------------------------------------------
// deriveKey derives a key using the SAME method as keys.DeriveKeyFromPassphrase
// This ensures encryption/decryption works consistently with the keys package
// Note: params parameter is intentionally ignored - we use fixed parameters from keys package
// deriveKey derives a key using the SAME method as keys.DeriveKeyFromPassphrase
func deriveKey(passphrase string, salt []byte, _ KeyDerivationParams) (*SecureBuffer, error) {
	log.Println("Deriving key using keys.DeriveKeyFromPassphrase (matches keypair derivation)")

	// Validate salt length
	if len(salt) < 16 {
		return nil, errors.New("salt must be at least 16 bytes")
	}

	// Use the exact same function from keys package
	key := keys.DeriveKeyFromPassphrase(passphrase, salt)

	if len(key) != 32 {
		return nil, fmt.Errorf("derived key has wrong length: expected 32, got %d", len(key))
	}

	log.Println("Key derived successfully using keys.DeriveKeyFromPassphrase")
	return NewSecureBuffer(key), nil
}

// generateSalt generates a cryptographically secure random salt
func generateSalt(size int) ([]byte, error) {
	if size < 16 {
		return nil, errors.New("salt size must be at least 16 bytes")
	}

	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		log.Printf("Error generating salt: %v", err)
		return nil, err
	}

	log.Printf("Salt generated successfully: %d bytes", size)
	return salt, nil
}

// blake3File computes the BLAKE3 hash of a file
func blake3File(path string) (string, error) {
	log.Println("Computing BLAKE3 hash for file:", path)
	f, err := os.Open(path)
	if err != nil {
		log.Printf("Error opening file for hashing: %v", err)
		return "", err
	}
	defer f.Close()

	hasher := blake3.New(32, nil) // 32 bytes = 256 bits
	if _, err := io.Copy(hasher, f); err != nil {
		log.Printf("Error computing hash: %v", err)
		return "", err
	}
	hash := fmt.Sprintf("%x", hasher.Sum(nil))
	log.Println("File hash computed successfully")
	return hash, nil
}

// computeChecksum computes the SHAKE256 checksum of data
func computeChecksum(data []byte) []byte {
	log.Println("Computing SHAKE256 checksum")

	// Use SHAKE256 with 32-byte output
	shaker := sha3.NewSHAKE256()
	shaker.Write(data)
	checksum := make([]byte, 32) // 256 bits
	shaker.Read(checksum)

	log.Println("Checksum computed successfully")
	return checksum
}

// ConvertToTerminalFormat converts GUI format back to terminal format
func ConvertToTerminalFormat(guiFingerprint string) string {
	return strings.ReplaceAll(guiFingerprint, " ", "")
}
