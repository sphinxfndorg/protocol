// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/bloom/hash.go
package bloom

import (
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// This file contains only hash algorithms — deriving deterministic bit
// positions from an input key. It has no knowledge of BloomFilter,
// bitset, or any blockchain type; bloom.go is the only caller.
//
// Approach: double hashing (Kirsch–Mitzenmacher).
//
// A textbook Bloom filter needs k independent hash functions per insertion.
// Computing k full cryptographic hashes per key (as literally implementing
// "3-5 hash functions" might suggest) is unnecessary and wasteful: Kirsch
// and Mitzenmacher (2006) proved that k positions of essentially the same
// quality can be derived from just TWO independent hash values h1, h2 via:
//
//	position_i = (h1 + i*h2) mod m,  for i = 0 .. k-1
//
// This is why the package computes exactly one SHA-256 digest and one
// SHA3-256 digest per key — regardless of k — rather than k separate
// digests. Using two different, cryptographically-independent hash
// families (not the same algorithm called twice) is what makes h1 and h2
// independent enough for the technique to hold, and satisfies the "use
// SHA-256 and SHA3-256" requirement directly rather than decoratively.
//
// Determinism: crypto/sha256 and golang.org/x/crypto/sha3 are both pure
// functions of their input with no salt, seed, or randomness, so the same
// key always produces the same positions — on every node, forever. This
// is what makes Add()/Contains() agreement possible across the network,
// and what serialize.go's cross-node determinism guarantee depends on.

// digestPair computes one SHA-256 digest and one SHA3-256 digest of key,
// then reduces each to a uint64 by reading its first 8 bytes big-endian.
// Reducing to uint64 here (rather than carrying the full 32-byte digests
// through the position loop) keeps the per-position arithmetic in
// positions() to simple integer ops.
func digestPair(key []byte) (h1, h2 uint64) {
	sum256 := sha256.Sum256(key)
	sum3 := sha3.Sum256(key)

	h1 = binary.BigEndian.Uint64(sum256[:8])
	h2 = binary.BigEndian.Uint64(sum3[:8])

	// Kirsch-Mitzenmacher's construction can degenerate if h2 == 0 (every
	// position collapses to h1 mod m, i.e. k effectively becomes 1). This
	// is astronomically unlikely for a real hash function output, but a
	// hash-position generator that is not proactively empty of even
	// theoretical linebreaks is easier to trust — the cost is one branch.
	if h2 == 0 {
		h2 = 1
	}

	return h1, h2
}

// positions returns k deterministic bit indices in the range [0, bits)
// for the given key, using the double-hashing construction above. The
// same key always yields the same k positions for a given (bits, k)
// configuration — this is the "no false negatives" guarantee: if a key
// was Add()-ed, Contains() recomputes the identical positions and will
// always find them set.
//
// k and bits come from a validated Config (see config.go); this function
// does not re-validate them, since bloom.go guarantees a BloomFilter can
// only be constructed from a valid Config.
func positions(key []byte, bits, k int) []int {
	h1, h2 := digestPair(key)

	result := make([]int, k)
	m := uint64(bits)
	for i := 0; i < k; i++ {
		// uint64 addition wraps on overflow (defined behavior in Go),
		// which is harmless here — we immediately reduce mod m and only
		// care about the resulting value's distribution, not its
		// pre-modulo magnitude.
		combined := h1 + uint64(i)*h2
		result[i] = int(combined % m)
	}
	return result
}
