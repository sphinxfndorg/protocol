// hashinto_equiv_test.go proves HashIntoUncached produces byte-identical
// output to GetHashUncached across the input sizes that matter, including the
// boundaries where the large-input prehash path engages.
package spxhash

import (
	"bytes"
	"math/rand"
	"testing"
)

// TestHashIntoMatchesGetHashUncached compares the allocating path against the
// in-place path over a spread of input lengths.
//
// Sizes are chosen to cover: empty, 1 byte, the rate-1/rate/rate+1 boundaries
// (where SHAKE256's sponge absorbs input without block boundaries — a natural
// place for an off-by-one to hide), exact block multiples, and lengths on both
// sides of the 1 MB maxHashInputSize large-input path.
func TestHashIntoMatchesGetHashUncached(t *testing.T) {
	const rate = 136 // SHAKE256 rate in bytes

	sizes := []int{
		0, 1, 2,
		rate - 1, rate, rate + 1,
		2 * rate, 2*rate - 1, 2*rate + 1,
		3 * rate, 64, 65, 127, 128, 136, 137, 200,
		4095, 4096, 4097,
		maxHashInputSize - 1, maxHashInputSize, maxHashInputSize + 1,
		maxHashInputSize + rate, 2*maxHashInputSize + 7,
	}

	for _, bits := range []int{256, 384, 512} {
		s, err := NewSphinxHash(bits, ProtocolSalt)
		if err != nil {
			t.Fatalf("NewSphinxHash(%d): %v", bits, err)
		}
		for _, n := range sizes {
			data := make([]byte, n)
			rng := rand.New(rand.NewSource(int64(n)*31 + int64(bits)))
			rng.Read(data)

			want := s.GetHashUncached(data)

			buf := make([]byte, s.Size())
			got := s.HashIntoUncached(buf, data)

			if len(got) != s.Size() {
				t.Fatalf("bits=%d len=%d: got length %d, want %d", bits, n, len(got), s.Size())
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("bits=%d len=%d: HashIntoUncached != GetHashUncached\n got  %x\n want %x", bits, n, got, want)
			}
			if !bytes.Equal(buf[:s.Size()], want) {
				t.Fatalf("bits=%d len=%d: dst was not written in full", bits, n)
			}
		}
	}
}

// TestHashIntoDoesNotRetainInternally checks the property that actually
// matters for correctness: the hasher keeps no reference to dst, so a later
// hash is unaffected by whatever the caller does to the buffer.
//
// Note the returned slice DOES alias dst — that is the deliberate trade (the
// caller gets the digest with no allocation). What must not happen is the
// hasher holding onto it, which would let a later call return stale bytes.
func TestHashIntoDoesNotRetainInternally(t *testing.T) {
	s, err := NewSphinxHash(256, ProtocolSalt)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("retain-check")
	want := s.GetHashUncached(data)

	buf := make([]byte, s.Size())
	s.HashIntoUncached(buf, data)

	// Scribble over the caller's buffer.
	for i := range buf {
		buf[i] = 0xAA
	}

	// A subsequent hash must be unaffected: nothing internal points at buf.
	if got := s.GetHashUncached(data); !bytes.Equal(got, want) {
		t.Fatalf("digest changed after the caller mutated dst: the hasher retained the buffer\n got  %x\n want %x", got, want)
	}
	// And the in-place path must still be correct into the dirtied buffer.
	got := s.HashIntoUncached(buf, data)
	if !bytes.Equal(got, want) {
		t.Fatalf("HashIntoUncached into a dirtied buffer != GetHashUncached\n got  %x\n want %x", got, want)
	}
}

// TestHashIntoReturnedSliceHasNoSpareCapacity checks the full-slice-expression
// guarantee, so a caller cannot append into the caller's buffer.
func TestHashIntoReturnedSliceHasNoSpareCapacity(t *testing.T) {
	s, err := NewSphinxHash(256, ProtocolSalt)
	if err != nil {
		t.Fatal(err)
	}
	// Oversized dst on purpose: the returned slice must still be capped at
	// Size(), not at cap(dst).
	buf := make([]byte, 256)
	got := s.HashIntoUncached(buf, []byte("cap-check"))
	if cap(got) != s.Size() {
		t.Fatalf("cap(returned) = %d, want %d (full slice expression missing?)", cap(got), s.Size())
	}
}

// TestHashIntoRejectsShortBuffer checks the panic contract.
func TestHashIntoRejectsShortBuffer(t *testing.T) {
	s, err := NewSphinxHash(512, ProtocolSalt)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for an undersized dst")
		}
	}()
	s.HashIntoUncached(make([]byte, 8), []byte("short"))
}
