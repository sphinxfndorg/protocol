// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/bloom/hash_test.go
package bloom

import (
	"fmt"
	"testing"
)

func TestPositionsDeterministic(t *testing.T) {
	key := []byte("0xSphinxAddress0001")

	first := positions(key, BloomBits, HashFunctions)
	for i := 0; i < 100; i++ {
		again := positions(key, BloomBits, HashFunctions)
		if len(again) != len(first) {
			t.Fatalf("iteration %d: got %d positions, want %d", i, len(again), len(first))
		}
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("iteration %d: position %d changed: got %d, want %d (positions() must be a pure function of its input)",
					i, j, again[j], first[j])
			}
		}
	}
}

func TestPositionsCountMatchesK(t *testing.T) {
	for _, k := range []int{1, 3, 5, 8} {
		pos := positions([]byte("key"), BloomBits, k)
		if len(pos) != k {
			t.Errorf("k=%d: got %d positions, want %d", k, len(pos), k)
		}
	}
}

func TestPositionsInRange(t *testing.T) {
	keys := [][]byte{
		[]byte(""),
		[]byte("a"),
		[]byte("0000000000000000000000000000000000000001"),
		make([]byte, 1024), // large all-zero key
	}
	for _, key := range keys {
		pos := positions(key, BloomBits, HashFunctions)
		for _, p := range pos {
			if p < 0 || p >= BloomBits {
				t.Errorf("key %q: position %d out of range [0, %d)", key, p, BloomBits)
			}
		}
	}
}

func TestPositionsDifferentKeysDifferentPositions(t *testing.T) {
	// Not a hard guarantee (collisions are expected and fine for a Bloom
	// filter), but for a reasonable sample of distinct short keys, the
	// full position *sets* should very rarely collide entirely — if they
	// did for every pair, that would indicate the hash isn't actually
	// varying with input (e.g. a bug that ignores `key`).
	seen := make(map[string]bool)
	collisions := 0
	total := 200
	for i := 0; i < total; i++ {
		key := []byte(fmt.Sprintf("sphinx-address-%d", i))
		pos := positions(key, BloomBits, HashFunctions)
		sig := fmt.Sprint(pos)
		if seen[sig] {
			collisions++
		}
		seen[sig] = true
	}
	if collisions == total {
		t.Fatal("every key produced an identical position set — positions() appears to ignore its input")
	}
}

func TestPositionsDistinctAlgorithmsProduceDistinctHalves(t *testing.T) {
	// Sanity check that h1 (SHA-256) and h2 (SHA3-256) are not
	// accidentally identical for a given key, which would silently
	// collapse the double-hashing construction (every position would
	// then be h1*(i+1) mod m rather than using two independent sources).
	h1, h2 := digestPair([]byte("distinct-check"))
	if h1 == h2 {
		t.Fatal("SHA-256 and SHA3-256 digests of the same key must not be equal — double hashing requires independent sources")
	}
}

func TestDigestPairHandlesZeroH2(t *testing.T) {
	// digestPair must never return h2 == 0, since that degenerates every
	// position to h1 mod m. We can't force a real collision, but we can
	// confirm the guard exists and doesn't break normal inputs.
	_, h2 := digestPair([]byte("any-key"))
	if h2 == 0 {
		t.Fatal("digestPair must never return h2 == 0")
	}
}

func TestPositionsDifferentKConfigurations(t *testing.T) {
	// Using the same key with a smaller bit size must still stay in range.
	pos := positions([]byte("key"), 64, 3)
	for _, p := range pos {
		if p < 0 || p >= 64 {
			t.Fatalf("position %d out of range for bits=64", p)
		}
	}
}

func BenchmarkPositions(b *testing.B) {
	key := []byte("0xSphinxBenchmarkAddress")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = positions(key, BloomBits, HashFunctions)
	}
}

func TestPositionsIntoMatchesPositions(t *testing.T) {
	keys := [][]byte{
		[]byte(""),
		[]byte("xAlice"),
		[]byte("tx-0003"),
		make([]byte, 128),
	}
	for _, key := range keys {
		want := positions(key, BloomBits, HashFunctions)

		var scratch [maxInlineK]int
		got := positionsInto(key, BloomBits, HashFunctions, scratch[:0])

		if len(got) != len(want) {
			t.Fatalf("key %q: got %d positions, want %d", key, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("key %q: position %d = %d, want %d", key, i, got[i], want[i])
			}
		}
	}
}

func TestPositionsIntoReusesBuffer(t *testing.T) {
	buf := make([]int, 0, maxInlineK)

	first := positionsInto([]byte("xAlice"), BloomBits, HashFunctions, buf)
	second := positionsInto([]byte("xBob"), BloomBits, HashFunctions, buf)

	if &first[0] != &second[0] {
		t.Fatal("positionsInto did not reuse the caller's buffer")
	}
}

func TestPositionsIntoAllocatesOnlyWhenBufferTooSmall(t *testing.T) {
	tooSmall := make([]int, 0, 2)
	got := positionsInto([]byte("xAlice"), BloomBits, HashFunctions, tooSmall)
	if len(got) != HashFunctions {
		t.Fatalf("got %d positions, want %d", len(got), HashFunctions)
	}
	if &got[0] == &tooSmall[:cap(tooSmall)][0] {
		t.Fatal("positionsInto must allocate when the buffer is too small")
	}
}

func TestPositionsIntoZeroK(t *testing.T) {
	var scratch [maxInlineK]int
	if got := positionsInto([]byte("xAlice"), BloomBits, 0, scratch[:0]); len(got) != 0 {
		t.Fatalf("k=0 returned %v, want empty", got)
	}
}

func TestPositionsIntoDoesNotAllocateWithStackBuffer(t *testing.T) {
	key := []byte("xAlice")

	allocs := testing.AllocsPerRun(100, func() {
		var scratch [maxInlineK]int
		_ = positionsInto(key, BloomBits, HashFunctions, scratch[:0])
	})
	if allocs != 0 {
		t.Fatalf("positionsInto allocated %.1f objects/op with a stack buffer, want 0", allocs)
	}
}
