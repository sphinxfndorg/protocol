package spxhash

import (
	"bytes"
	"crypto/sha512"
	"testing"

	"golang.org/x/crypto/sha3"
)

// A >1 MB input must never hash to the same value as a small input that
// equals its 64-byte prehash. The key is public, so an attacker can compute
// that prehash for any large file.
func TestLargeInputNotAliasedToItsPrehash(t *testing.T) {
	h, err := NewSphinxHash(256, ProtocolSalt)
	if err != nil {
		t.Fatal(err)
	}

	big := bytes.Repeat([]byte{0xAB}, maxHashInputSize+1)

	// Recompute the prehash exactly as hashData does.
	prehash := refPrehash(ProtocolSalt, big)

	if bytes.Equal(h.GetHashUncached(big), h.GetHashUncached(prehash)) {
		t.Fatal("hash(bigInput) == hash(prehash(bigInput)): large path lacks domain separation")
	}
}

// GetHash and GetHashUncached must return identical digests.
func TestUncachedMatchesCached(t *testing.T) {
	h, err := NewSphinxHash(256, ProtocolSalt)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range [][]byte{{}, []byte("a"), bytes.Repeat([]byte{7}, 96), bytes.Repeat([]byte{9}, maxHashInputSize+5)} {
		if !bytes.Equal(h.GetHash(in), h.GetHashUncached(in)) {
			t.Fatalf("cached/uncached mismatch for len=%d", len(in))
		}
	}
}

func refPrehash(key, data []byte) []byte {
	a := sha512.New512_256()
	a.Write(key)
	a.Write(domainPre)
	a.Write(data)
	b := sha3.NewShake256()
	b.Write(key)
	b.Write(domainPreB)
	b.Write(data)
	out := make([]byte, 64)
	a.Sum(out[:0])
	b.Read(out[32:])
	return out
}

func refHash(key, data []byte, size int) []byte {
	tagA, tagB, d := domainH1, domainH2, data
	if len(data) > maxHashInputSize {
		tagA, tagB, d = domainH1Large, domainH2Large, refPrehash(key, data)
	}
	ha := sha512.New512_256()
	ha.Write(key)
	ha.Write(tagA)
	ha.Write(d)
	sb := sha3.NewShake256()
	sb.Write(key)
	sb.Write(tagB)
	sb.Write(d)
	b := make([]byte, 32)
	sb.Read(b)
	f := sha3.NewShake256()
	f.Write(domainFinal)
	f.Write(ha.Sum(nil))
	f.Write(b)
	out := make([]byte, size)
	f.Read(out)
	return out
}

func TestReferenceMatchesAcrossLargeBoundary(t *testing.T) {
	h, err := NewSphinxHash(384, ProtocolSalt)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 4097, maxHashInputSize, maxHashInputSize + 1, 2*maxHashInputSize + 3} {
		in := bytes.Repeat([]byte{0x5A}, n)
		if !bytes.Equal(h.GetHashUncached(in), refHash(ProtocolSalt, in, h.Size())) {
			t.Fatalf("implementation diverges from reference at len=%d", n)
		}
	}
}

// Both halves of the prehash must depend on the data, so a break of either
// primitive alone cannot produce a large-input collision on its own.
func TestPrehashBothHalvesDependOnData(t *testing.T) {
	x := bytes.Repeat([]byte{1}, maxHashInputSize+1)
	y := append([]byte(nil), x...)
	y[len(y)-1] ^= 1
	px, py := refPrehash(ProtocolSalt, x), refPrehash(ProtocolSalt, y)
	if bytes.Equal(px[:32], py[:32]) || bytes.Equal(px[32:], py[32:]) {
		t.Fatal("a prehash half did not change with the input")
	}
}
