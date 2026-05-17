// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/hash/params.go
package spxhash

// SIPS-0001 https://github.com/sphinx-core/sips/wiki/SIPS-0001

// Define prime constants for hash calculations.
const (
	prime32  = 0x9e3779b9         // Example prime constant for 32-bit hash
	prime64  = 0x9e3779b97f4a7c15 // Example prime constant for 64-bit hash
	saltSize = 16                 // Size of salt in bytes (128 bits = 16 bytes)

	// Argon2 parameters
	// OWASP have published guidance on Argon2 at https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
	// At time of writing (Jan 2023), this says:
	// Argon2id should use one of the following configuration settings as a base minimum which includes the minimum memory size (m), the minimum number of iterations (t) and the degree of parallelism (p).
	// m=37 MiB, t=1, p=1
	// m=15 MiB, t=2, p=1
	// Both of these configuration settings are equivalent in the defense they provide. The only difference is a trade off between CPU and RAM usage.
	memory           = 64 * 1024 // Memory cost set to 64 KiB (64 * 1024 bytes) is for demonstration purpose
	iterations       = 2         // Number of iterations for Argon2id set to 2
	parallelism      = 1         // Degree of parallelism set to 1
	tagSize          = 32        // Tag size set to 256 bits (32 bytes)
	DefaultCacheSize = 100       // Default cache size for SphinxHash
)

// Size returns the number of bytes in the hash based on the bit size.
func (s *SphinxHash) Size() int {
	switch s.bitSize {
	case 256:
		// SHA-512/256 produces a 256-bit output, equivalent to 32 bytes.
		return 32 // 256 bits = 32 bytes (SHA-512/256)
	case 384:
		// SHA-384 produces a 384-bit output, equivalent to 48 bytes.
		return 48 // 384 bits = 48 bytes (SHA-384)
	case 512:
		// SHA-512 produces a 512-bit output, equivalent to 64 bytes.
		return 64 // 512 bits = 64 bytes (SHA-512)
	default:
		// Default to 256 bits (SHA-512/256) if bitSize is unspecified
		return 32 // Default to 256 bits (SHA-512/256)
	}
}

// BlockSize returns the hash block size based on the current bit size configuration.
func (s *SphinxHash) BlockSize() int {
	switch s.bitSize {
	case 256:
		return 128 // SHA-512/256 block size is 128 bytes
	case 384:
		return 128 // SHA-384 block size is 128 bytes
	case 512:
		return 128 // SHA-512 block size is 128 bytes
	default:
		return 136 // SHAKE256 block size is 136 bytes (1088 bits)
	}
}
