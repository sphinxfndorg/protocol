// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/hash/params.go
package spxhash

// SIPS-0001 https://github.com/sphinx-core/sips/wiki/SIPS-0001

// Define prime constants for hash calculations.
const (
	// FIX N: prime32 removed — it became unused after fix #9 switched all call
	// sites to prime64. Keeping dead constants misleads future readers.
	prime64 = 0x9e3779b97f4a7c15 // Prime constant for 64-bit hash mixing

	saltSize = 16 // Size of salt in bytes (128 bits)

	// Argon2 parameters
	// Following OWASP guidance: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
	// Minimum configuration: m=19 MiB, t=2, p=1
	// FIX #4: Raised memory from 64 KiB (demonstration value) to 19 MiB to meet
	// OWASP minimum. 64 KiB provided essentially no memory-hardness.
	memory      = 19 * 1024 // Memory cost: 19 MiB (19 * 1024 KiB) — OWASP minimum
	iterations  = 2         // Number of iterations for Argon2id
	parallelism = 1         // Degree of parallelism

	tagSize          = 32  // Tag size: 256 bits (32 bytes)
	DefaultCacheSize = 100 // Default LRU cache size for SphinxHash
)

// Size returns the number of bytes in the hash output based on the configured bit size.
func (s *SphinxHash) Size() int {
	switch s.bitSize {
	case 256:
		return 32 // SHA-512/256: 256 bits = 32 bytes
	case 384:
		return 48 // SHA-384: 384 bits = 48 bytes
	case 512:
		return 64 // SHA-512: 512 bits = 64 bytes
	default:
		return 32 // Default to SHA-512/256 output size
	}
}

// BlockSize returns the hash block size based on the configured bit size.
func (s *SphinxHash) BlockSize() int {
	switch s.bitSize {
	case 256:
		return 128 // SHA-512/256 block size: 128 bytes
	case 384:
		return 128 // SHA-384 block size: 128 bytes
	case 512:
		return 128 // SHA-512 block size: 128 bytes
	default:
		return 136 // SHAKE256 block size: 136 bytes (1088 bits)
	}
}
