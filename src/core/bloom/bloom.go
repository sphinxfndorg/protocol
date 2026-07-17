// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/bloom/bloom.go
package bloom

import "sync"

// BloomFilter is a probabilistic set membership structure. Safe for
// concurrent use: many readers may call Contains while a single writer
// builds the filter via Add.
type BloomFilter struct {
	mu   sync.RWMutex
	bits *bitset
	cfg  Config
}

// New creates an empty BloomFilter using the given Config.
func New(cfg Config) (*BloomFilter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &BloomFilter{
		bits: newBitset(cfg.Bits),
		cfg:  cfg,
	}, nil
}

// NewDefault creates an empty BloomFilter using DefaultConfig().
func NewDefault() *BloomFilter {
	bf, _ := New(DefaultConfig())
	return bf
}

// Add inserts key into the filter, setting its k derived bit positions.
func (bf *BloomFilter) Add(key []byte) {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	for _, pos := range positions(key, bf.cfg.Bits, bf.cfg.K) {
		bf.bits.SetBit(pos)
	}
}

// Contains reports whether key may be in the filter. A false result is
// certain; a true result may be a false positive.
func (bf *BloomFilter) Contains(key []byte) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	for _, pos := range positions(key, bf.cfg.Bits, bf.cfg.K) {
		if !bf.bits.GetBit(pos) {
			return false
		}
	}
	return true
}

// Merge OR-combines other into bf. Both filters must share the same
// Config; a mismatched Config is a no-op, since merging filters built
// with different bit sizes or hash counts is meaningless.
func (bf *BloomFilter) Merge(other *BloomFilter) {
	if other == nil {
		return
	}
	other.mu.RLock()
	defer other.mu.RUnlock()

	bf.mu.Lock()
	defer bf.mu.Unlock()
	if bf.cfg != other.cfg {
		return
	}
	bf.bits.or(other.bits)
}

// Reset clears every bit back to 0, reusing the existing backing array.
func (bf *BloomFilter) Reset() {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	bf.bits.ResetBits()
}

// Copy returns an independent deep copy of bf.
func (bf *BloomFilter) Copy() *BloomFilter {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	return &BloomFilter{
		bits: bf.bits.clone(),
		cfg:  bf.cfg,
	}
}

// Config returns the configuration this filter was built with.
func (bf *BloomFilter) Config() Config {
	return bf.cfg
}

// CountBits returns the number of set bits, useful as a cheap
// fill-ratio / saturation estimate.
func (bf *BloomFilter) CountBits() int {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	return bf.bits.CountBits()
}
