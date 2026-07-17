// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/bloom/config.go
package bloom

import "errors"

// Config-related sentinel errors. Declared here (rather than a separate
// errors.go) because they only ever originate from Config.Validate().
var (
	// ErrInvalidBits is returned when a Config's Bits field is <= 0.
	ErrInvalidBits = errors.New("bloom: bits must be positive")

	// ErrBitsNotByteAligned is returned when Bits is not a multiple of 8.
	// This package stores the filter as a []byte bitset, so partial
	// trailing bytes are not supported.
	ErrBitsNotByteAligned = errors.New("bloom: bits must be a multiple of 8")

	// ErrInvalidHashCount is returned when a Config's K field is < 1.
	ErrInvalidHashCount = errors.New("bloom: hash function count (k) must be at least 1")
)

// Package bloom implements a reusable, Ethereum-`logsBloom`-inspired
// probabilistic membership filter. It has no dependency on any Sphinx
// blockchain type (Block, Transaction, etc.) — it operates purely on
// []byte keys, so it can be embedded in a block header, an index file,
// a cache layer, or any other application that needs fast "definitely
// not present" / "maybe present" membership tests.
//
// Blockchain-specific logic (deciding *which* objects to insert — sender
// addresses, tx IDs, contract addresses, event topics, etc.) intentionally
// does NOT live in this package. It lives in the core/transaction package,
// which imports bloom. Keeping the dependency one-directional (transaction
// -> bloom, never bloom -> transaction) is what allows BlockHeader to hold
// a Bloom filter without creating an import cycle.

const (
	// BloomBits is the size of the filter in bits. 2048 bits (256 bytes)
	// matches Ethereum's logsBloom size, which is a well-studied trade-off
	// between false-positive rate and header size for typical block
	// transaction/address counts.
	BloomBits = 2048

	// BloomBytes is BloomBits expressed in bytes. Kept as a separate
	// constant (rather than computed at init) so callers can use it in
	// other constant expressions (e.g. fixed-size array declarations).
	BloomBytes = BloomBits / 8

	// HashFunctions is the number of independent bit positions set per
	// inserted key (k in standard Bloom filter terminology). 3 is a
	// deliberate choice consistent with Ethereum's logsBloom (which also
	// sets 3 bits per topic/address) and gives a low false-positive rate
	// for the expected number of distinct keys in one block (typically
	// tens to low hundreds of addresses/tx IDs) at this filter size.
	//
	// False-positive rate for n inserted elements, m bits, k hash functions:
	//   p ≈ (1 - e^(-kn/m))^k
	// With m=2048, k=3, n=200: p ≈ 0.017 (~1.7%), which is acceptable for
	// a "may contain, verify against real data" pre-filter — see query.go
	// in the core/transaction package, which never trusts a positive
	// result without loading and checking the actual block.
	HashFunctions = 3
)

// Config allows advanced callers to construct a BloomFilter with
// non-default parameters (e.g. a smaller filter for a light client index,
// or a different k for a workload with far more or fewer expected keys)
// without changing the package-level defaults that the rest of the
// blockchain code relies on.
//
// The zero value is NOT valid — use DefaultConfig() or NewConfig().
type Config struct {
	// Bits is the total filter size in bits. Must be a positive multiple
	// of 8 (whole bytes only — this package does not support partial
	// trailing bytes).
	Bits int

	// K is the number of hash functions (bit positions set per Add).
	// Must be >= 1.
	K int
}

// DefaultConfig returns the standard Sphinx block-header Bloom filter
// configuration (2048 bits, 3 hash functions). All block-header Bloom
// filters across the network MUST use this configuration — changing it
// changes serialization size and hash positions, which would be a
// consensus-breaking change requiring a coordinated upgrade.
func DefaultConfig() Config {
	return Config{
		Bits: BloomBits,
		K:    HashFunctions,
	}
}

// NewConfig builds a custom configuration for non-consensus uses of this
// package (e.g. an explorer-side secondary index). It validates its
// inputs so a caller can fail fast at construction time instead of
// getting confusing behavior later from bitset.go.
func NewConfig(bits, k int) (Config, error) {
	cfg := Config{Bits: bits, K: k}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks that a Config is usable. Bits must be a positive
// multiple of 8, and K must be at least 1.
func (c Config) Validate() error {
	if c.Bits <= 0 {
		return ErrInvalidBits
	}
	if c.Bits%8 != 0 {
		return ErrBitsNotByteAligned
	}
	if c.K <= 0 {
		return ErrInvalidHashCount
	}
	return nil
}

// Bytes returns the number of bytes needed to store a filter of this
// configuration's bit size.
func (c Config) Bytes() int {
	return c.Bits / 8
}
