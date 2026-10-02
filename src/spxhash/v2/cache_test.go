package spxhash

import (
	"bytes"
	"testing"
)

func TestCacheCollisionNeverReturnsWrongValue(t *testing.T) {
	c := NewLRUCache(4)
	c.Put(CacheKey(1), []byte("a"), []byte("va"))
	if _, ok := c.Get(CacheKey(1), []byte("b")); ok {
		t.Fatal("same key, different input must miss")
	}
	c.Put(CacheKey(1), []byte("b"), []byte("vb"))
	if _, ok := c.Get(CacheKey(1), []byte("a")); ok {
		t.Fatal("overwritten entry must miss for old input")
	}
	if v, ok := c.Get(CacheKey(1), []byte("b")); !ok || !bytes.Equal(v, []byte("vb")) {
		t.Fatal("expected hit for current input")
	}
}

func TestCachedMatchesUncachedAcrossSizes(t *testing.T) {
	h, _ := NewSphinxHash(256, ProtocolSalt)
	for _, n := range []int{0, 1, 1023, 4096, 4097, 9000} {
		in := bytes.Repeat([]byte{byte(n)}, n)
		u := h.GetHashUncached(in)
		for i := 0; i < 2; i++ {
			if !bytes.Equal(h.GetHash(in), u) {
				t.Fatalf("mismatch len=%d pass=%d", n, i)
			}
		}
	}
}

func BenchmarkCached(b *testing.B) {
	h, _ := NewSphinxHash(256, ProtocolSalt)
	for _, n := range []int{0, 1, 1024, 4096} {
		in := bytes.Repeat([]byte{1}, n)
		h.GetHash(in)
		b.Run(itoa(n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				h.GetHash(in)
			}
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for ; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	return s
}
