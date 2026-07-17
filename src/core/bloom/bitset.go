// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/bloom/bitset.go
package bloom

import "math/bits"

// bitset is a fixed-size, byte-backed array of bits. It contains no
// knowledge of hashing or Bloom-filter semantics — it is a general-purpose
// primitive that bloom.go builds on top of. Keeping it separate keeps
// bloom.go free of manual bit-twiddling and makes the bit operations
// independently testable and reusable.
//
// Bit indexing convention: bit i lives in byte i/8, at bit position
// (7 - i%8) within that byte — i.e. bit 0 is the most-significant bit of
// byte 0. This is an arbitrary but fixed convention; what matters for
// correctness is that SetBit/GetBit/ClearBit agree with each other and
// that it's applied consistently across nodes (serialize.go depends on
// this exact layout for deterministic cross-node encoding).
type bitset struct {
	bits []byte
	size int // total number of addressable bits (== len(bits)*8)
}

// newBitset allocates a zeroed bitset large enough to hold numBits bits.
// numBits must be a positive multiple of 8; callers within this package
// only ever pass values already validated by Config.Validate(), so this
// function panics on misuse rather than returning an error — it is not
// part of the public API surface.
func newBitset(numBits int) *bitset {
	if numBits <= 0 || numBits%8 != 0 {
		panic("bloom: newBitset requires a positive multiple of 8")
	}
	return &bitset{
		bits: make([]byte, numBits/8),
		size: numBits,
	}
}

// newBitsetFromBytes wraps an existing byte slice as a bitset without
// copying. The caller must not mutate buf afterward through any other
// reference — ownership transfers to the bitset. Used by serialize.go
// when loading a filter from a byte representation.
func newBitsetFromBytes(buf []byte) *bitset {
	return &bitset{
		bits: buf,
		size: len(buf) * 8,
	}
}

// SetBit sets bit i to 1. It is a no-op if i is out of range, so a
// hash-derived index can never cause a panic — this mirrors how a real
// Bloom filter's insertion path must never fail regardless of input.
func (b *bitset) SetBit(i int) {
	if i < 0 || i >= b.size {
		return
	}
	byteIdx := i / 8
	bitIdx := uint(7 - i%8)
	b.bits[byteIdx] |= 1 << bitIdx
}

// GetBit reports whether bit i is set. Out-of-range indices return false.
func (b *bitset) GetBit(i int) bool {
	if i < 0 || i >= b.size {
		return false
	}
	byteIdx := i / 8
	bitIdx := uint(7 - i%8)
	return b.bits[byteIdx]&(1<<bitIdx) != 0
}

// ClearBit sets bit i to 0. Out-of-range indices are a no-op.
func (b *bitset) ClearBit(i int) {
	if i < 0 || i >= b.size {
		return
	}
	byteIdx := i / 8
	bitIdx := uint(7 - i%8)
	b.bits[byteIdx] &^= 1 << bitIdx
}

// CountBits returns the number of bits currently set to 1 (popcount).
// Used by query.go / callers wanting a cheap fill-ratio / saturation
// estimate (a Bloom filter's false-positive rate rises as more bits get
// set, so this is useful telemetry without needing to know how many
// keys were inserted).
func (b *bitset) CountBits() int {
	count := 0
	for _, byteVal := range b.bits {
		count += bits.OnesCount8(byteVal)
	}
	return count
}

// ResetBits clears every bit back to 0, reusing the existing backing
// array (no allocation). This backs BloomFilter.Reset() in bloom.go.
func (b *bitset) ResetBits() {
	for i := range b.bits {
		b.bits[i] = 0
	}
}

// Size returns the total number of addressable bits in this bitset.
func (b *bitset) Size() int {
	return b.size
}

// Bytes returns the underlying byte slice directly (no copy). Callers
// that need an independent copy (e.g. for Copy() semantics in bloom.go)
// must clone it themselves — this method is intentionally low-level.
func (b *bitset) Bytes() []byte {
	return b.bits
}

// or performs an in-place bitwise OR of other into b (b = b | other),
// which is exactly what merging two Bloom filters means at the bitset
// level. Both bitsets must have the same size; mismatched sizes are a
// no-op, since a merge across incompatible filter configurations is a
// programming error the caller (bloom.go's Merge) is expected to guard
// against with a clearer error message before ever reaching here.
func (b *bitset) or(other *bitset) {
	if other == nil || b.size != other.size {
		return
	}
	for i := range b.bits {
		b.bits[i] |= other.bits[i]
	}
}

// clone returns an independent copy of this bitset, backed by a freshly
// allocated byte slice.
func (b *bitset) clone() *bitset {
	cp := make([]byte, len(b.bits))
	copy(cp, b.bits)
	return &bitset{bits: cp, size: b.size}
}
