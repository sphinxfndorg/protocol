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

// ProtocolSalt is the fixed, public salt to use with NewSphinxHash at every
// call site that needs a deterministic, consensus-critical digest —
// transaction hashes, block hashes, Merkle leaves/roots, address derivation,
// or anything else that must be independently reproducible by every node.
//
// FIX DET (determinism/one-way contradiction):
// Before this fix, callers that wanted a "plain hash" had no single agreed
// value to pass as salt, and NewSphinxHash even accepted nil and silently
// substituted random entropy, so two nodes could compute different hashes
// for the same bytes. ProtocolSalt gives every deterministic call site one
// canonical value to pass, so all nodes agree by construction.
//
// This value is NOT a secret — its only purpose is domain separation (so
// SphinxHash output doesn't collide with some other unrelated use of
// Argon2id), not unpredictability. It must never change without a
// coordinated protocol version bump, since changing it changes every
// resulting hash.
var ProtocolSalt = []byte("sphinx-protocol-hash-v1")
