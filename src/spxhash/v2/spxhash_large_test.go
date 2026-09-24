package spxhash

import (
	"bytes"
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
	pre := sha3.NewShake256()
	pre.Write(domainPre)
	pre.Write(ProtocolSalt)
	pre.Write(big)
	prehash := make([]byte, 64)
	pre.Read(prehash)

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
