// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/bloom/bitset_test.go
package bloom

import "testing"

func TestNewBitset(t *testing.T) {
	bs := newBitset(2048)
	if bs.Size() != 2048 {
		t.Fatalf("expected size 2048, got %d", bs.Size())
	}
	if len(bs.Bytes()) != 256 {
		t.Fatalf("expected 256 backing bytes, got %d", len(bs.Bytes()))
	}
	// A freshly allocated bitset must start fully zeroed.
	if bs.CountBits() != 0 {
		t.Fatalf("expected 0 bits set on a fresh bitset, got %d", bs.CountBits())
	}
}

func TestNewBitsetInvalidSize(t *testing.T) {
	cases := []int{0, -8, 7, 15, 1}
	for _, n := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("newBitset(%d): expected panic, got none", n)
				}
			}()
			newBitset(n)
		}()
	}
}

func TestSetGetClearBit(t *testing.T) {
	bs := newBitset(64)

	for _, i := range []int{0, 1, 7, 8, 15, 63} {
		if bs.GetBit(i) {
			t.Fatalf("bit %d should start unset", i)
		}
		bs.SetBit(i)
		if !bs.GetBit(i) {
			t.Fatalf("bit %d should be set after SetBit", i)
		}
		bs.ClearBit(i)
		if bs.GetBit(i) {
			t.Fatalf("bit %d should be unset after ClearBit", i)
		}
	}
}

func TestSetBitDoesNotAffectNeighbors(t *testing.T) {
	bs := newBitset(64)
	bs.SetBit(9)
	for i := 0; i < 64; i++ {
		want := i == 9
		if got := bs.GetBit(i); got != want {
			t.Fatalf("bit %d: got %v, want %v (only bit 9 should be set)", i, got, want)
		}
	}
}

func TestOutOfRangeIsNoOpNotPanic(t *testing.T) {
	bs := newBitset(64)

	// None of these should panic.
	bs.SetBit(-1)
	bs.SetBit(64)
	bs.SetBit(1000)
	bs.ClearBit(-1)
	bs.ClearBit(64)

	if got := bs.GetBit(-1); got != false {
		t.Fatalf("GetBit(-1) = %v, want false", got)
	}
	if got := bs.GetBit(64); got != false {
		t.Fatalf("GetBit(64) = %v, want false", got)
	}
	if bs.CountBits() != 0 {
		t.Fatalf("out-of-range SetBit calls must not affect in-range bits, got %d bits set", bs.CountBits())
	}
}

func TestCountBits(t *testing.T) {
	bs := newBitset(64)
	indices := []int{0, 3, 3, 8, 40, 63} // note: 3 set twice, must still count once
	for _, i := range indices {
		bs.SetBit(i)
	}
	want := 5 // distinct indices: 0, 3, 8, 40, 63
	if got := bs.CountBits(); got != want {
		t.Fatalf("CountBits() = %d, want %d", got, want)
	}
}

func TestResetBits(t *testing.T) {
	bs := newBitset(64)
	for i := 0; i < 64; i += 2 {
		bs.SetBit(i)
	}
	if bs.CountBits() == 0 {
		t.Fatal("setup failed: expected some bits set before Reset")
	}
	bs.ResetBits()
	if got := bs.CountBits(); got != 0 {
		t.Fatalf("after ResetBits, CountBits() = %d, want 0", got)
	}
	// Reuses the same backing array rather than reallocating.
	if len(bs.Bytes()) != 8 {
		t.Fatalf("ResetBits must not change backing size, got %d bytes", len(bs.Bytes()))
	}
}

func TestNewBitsetFromBytes(t *testing.T) {
	raw := make([]byte, 32)
	raw[0] = 0x80  // bit 0 set (MSB-first convention)
	raw[31] = 0x01 // bit 255 set (LSB of last byte)

	bs := newBitsetFromBytes(raw)
	if bs.Size() != 256 {
		t.Fatalf("expected size 256, got %d", bs.Size())
	}
	if !bs.GetBit(0) {
		t.Fatal("expected bit 0 to be set")
	}
	if !bs.GetBit(255) {
		t.Fatal("expected bit 255 to be set")
	}
	if bs.GetBit(1) {
		t.Fatal("expected bit 1 to be unset")
	}
}

func TestBitsetOr(t *testing.T) {
	a := newBitset(64)
	b := newBitset(64)

	a.SetBit(0)
	a.SetBit(10)
	b.SetBit(10)
	b.SetBit(20)

	a.or(b)

	for _, i := range []int{0, 10, 20} {
		if !a.GetBit(i) {
			t.Fatalf("after or(), bit %d should be set", i)
		}
	}
	if got := a.CountBits(); got != 3 {
		t.Fatalf("after or(), CountBits() = %d, want 3 (0, 10, 20)", got)
	}
	// b must be unmodified by a.or(b).
	if got := b.CountBits(); got != 2 {
		t.Fatalf("or() must not mutate its argument, but b now has %d bits set", got)
	}
}

func TestBitsetOrMismatchedSizeIsNoOp(t *testing.T) {
	a := newBitset(64)
	b := newBitset(32)
	a.SetBit(5)

	a.or(b) // must not panic, must not change a

	if got := a.CountBits(); got != 1 {
		t.Fatalf("or() with mismatched size must be a no-op, got %d bits set", got)
	}
}

func TestBitsetOrNilIsNoOp(t *testing.T) {
	a := newBitset(64)
	a.SetBit(5)
	a.or(nil) // must not panic

	if got := a.CountBits(); got != 1 {
		t.Fatalf("or(nil) must be a no-op, got %d bits set", got)
	}
}

func TestBitsetClone(t *testing.T) {
	a := newBitset(64)
	a.SetBit(3)
	a.SetBit(40)

	cp := a.clone()

	if cp.Size() != a.Size() {
		t.Fatalf("clone size mismatch: got %d, want %d", cp.Size(), a.Size())
	}
	if cp.CountBits() != a.CountBits() {
		t.Fatalf("clone bit count mismatch: got %d, want %d", cp.CountBits(), a.CountBits())
	}

	// Mutating the clone must not affect the original (independent backing array).
	cp.SetBit(63)
	if a.GetBit(63) {
		t.Fatal("mutating a clone must not affect the original bitset")
	}
	if !cp.GetBit(63) {
		t.Fatal("clone should reflect its own mutation")
	}
}
