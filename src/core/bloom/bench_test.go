// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/bloom/benchmark_test.go
package bloom

import (
	"fmt"
	"testing"
)

func BenchmarkAdd(b *testing.B) {
	bf := NewDefault()
	b.ReportAllocs()
	var i int
	buf := make([]byte, 0, 16) // reused across iterations
	for b.Loop() {
		buf = fmt.Appendf(buf[:0], "addr-%d", i)
		bf.Add(buf)
		i++
	}
}

func BenchmarkContains(b *testing.B) {
	bf := NewDefault()
	// Pre-populate with 200 entries (outside the timed loop)
	for i := 0; i < 200; i++ {
		bf.Add([]byte(fmt.Sprintf("addr-%d", i)))
	}
	b.ReportAllocs()
	b.ResetTimer()

	var i int
	buf := make([]byte, 0, 16)
	for b.Loop() {
		buf = fmt.Appendf(buf[:0], "addr-%d", i%200)
		bf.Contains(buf)
		i++
	}
}

func BenchmarkBuildBlockFilter(b *testing.B) {
	// Pre-build the list of keys once.
	keys := make([][]byte, 200)
	for i := range keys {
		keys[i] = []byte(fmt.Sprintf("sphinx-address-%d", i))
	}
	b.ReportAllocs()
	for b.Loop() {
		bf := NewDefault()
		for _, k := range keys {
			bf.Add(k)
		}
	}
}

func BenchmarkBytes(b *testing.B) {
	bf := NewDefault()
	bf.Add([]byte("k1"))
	b.ReportAllocs()
	for b.Loop() {
		_ = bf.Bytes()
	}
}
