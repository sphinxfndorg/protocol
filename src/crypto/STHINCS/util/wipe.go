// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/util/wipe.go
package util

// Wipe zeroes every byte of b.
//
// It exists instead of a bare clear() for one reason: the Go race detector
// does not instrument clear(), so a wipe written with it is invisible to
// -race. A test that runs a wipe concurrently with a reader of the same bytes
// reports nothing, which makes a real data race indistinguishable from a
// correctly synchronized one. An explicit assignment loop is instrumented
// normally, so the detector can see the conflict.
//
// This was confirmed directly: with an otherwise identical A/B probe, a writer
// using clear() produced zero race reports over millions of concurrent
// iterations, while a writer using the equivalent loop produced a full report
// naming both stacks.
//
// The cost is irrelevant at these sizes — the buffers wiped through Wipe are
// N-byte seeds (16–48 bytes), not bulk data — so production uses the loop
// directly rather than hiding it behind a build tag. That keeps the code the
// tests exercise identical to the code that ships.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
