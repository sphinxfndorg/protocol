// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/bloom/fuzz_test.go
package bloom

import "testing"

// FuzzAddContains asserts the one property a Bloom filter can never
// violate: no false negatives. Any key that was Add()-ed must always
// report Contains() == true.
func FuzzAddContains(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("a"))
	f.Add([]byte{0x00, 0x00, 0x00})
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, key []byte) {
		bf := NewDefault()
		bf.Add(key)
		if !bf.Contains(key) {
			t.Fatalf("false negative for key %v", key)
		}
	})
}

// FuzzLoadRoundTrip asserts that any valid-length byte slice loaded into
// a filter comes back out unchanged via Bytes().
func FuzzLoadRoundTrip(f *testing.F) {
	f.Add(make([]byte, BloomBytes))

	f.Fuzz(func(t *testing.T, buf []byte) {
		if len(buf) != BloomBytes {
			t.Skip()
		}
		bf := NewDefault()
		if err := bf.Load(buf); err != nil {
			t.Fatalf("Load failed on valid-length input: %v", err)
		}
		out := bf.Bytes()
		if len(out) != len(buf) {
			t.Fatalf("round-tripped length = %d, want %d", len(out), len(buf))
		}
		for i := range buf {
			if out[i] != buf[i] {
				t.Fatalf("byte %d changed: got %x, want %x", i, out[i], buf[i])
			}
		}
	})
}

// FuzzPositionsInRange asserts positions() never returns an out-of-range
// index regardless of input key.
func FuzzPositionsInRange(f *testing.F) {
	f.Add([]byte("seed"))

	f.Fuzz(func(t *testing.T, key []byte) {
		for _, p := range positions(key, BloomBits, HashFunctions) {
			if p < 0 || p >= BloomBits {
				t.Fatalf("position %d out of range [0, %d)", p, BloomBits)
			}
		}
	})
}
