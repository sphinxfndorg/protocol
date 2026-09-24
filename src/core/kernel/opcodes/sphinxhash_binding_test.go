// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package svm

import "testing"

// TestSphinxHashOpReadsMemory is a regression test for the consensus-critical
// bug where executeSphinxHashOp hashed a zero-filled buffer of the requested
// size instead of the actual bytes at the given memory pointer. With the old
// implementation every message of the same length produced an identical
// digest, so a SphinxHash-derived consensus signature bound to nothing and
// could be replayed across heights, views and phases.
func TestSphinxHashOpReadsMemory(t *testing.T) {
	hashOf := func(data []byte) uint64 {
		t.Helper()
		stack := NewStack()
		mem := make([]byte, len(data)+16)
		copy(mem, data)
		stack.Push(0)                 // ptr
		stack.Push(uint64(len(data))) // size (top of stack)
		if err := executeSphinxHashOp(stack, mem); err != nil {
			t.Fatalf("executeSphinxHashOp: %v", err)
		}
		got, err := stack.Peek()
		if err != nil {
			t.Fatalf("Peek: %v", err)
		}
		return got
	}

	a := hashOf([]byte("AAAA"))
	b := hashOf([]byte("BBBB"))

	if a == b {
		t.Fatalf("SphinxHash must depend on memory contents; got identical %#x for different same-length inputs", a)
	}

	// Deterministic for identical input and pointer.
	if again := hashOf([]byte("AAAA")); again != a {
		t.Fatalf("SphinxHash is not deterministic: first=%#x again=%#x", a, again)
	}

	// The data pointer must actually be honoured: hashing offset 4 ("BBBB" in
	// "AAAABBBB") must equal hashing a standalone "BBBB" buffer.
	offsetStack := NewStack()
	offsetMem := []byte("AAAABBBB")
	offsetStack.Push(4) // ptr -> "BBBB"
	offsetStack.Push(4) // size
	if err := executeSphinxHashOp(offsetStack, offsetMem); err != nil {
		t.Fatalf("executeSphinxHashOp(offset): %v", err)
	}
	offsetHash, _ := offsetStack.Peek()
	if offsetHash != b {
		t.Fatalf("SphinxHash did not read from the given pointer: offset=%#x standalone=%#x", offsetHash, b)
	}
}

// TestSphinxHashOpBoundsCheck verifies malformed bytecode cannot panic the node.
func TestSphinxHashOpBoundsCheck(t *testing.T) {
	stack := NewStack()
	mem := make([]byte, 8)
	stack.Push(4) // ptr
	stack.Push(8) // size -> 4+8 > 8, out of bounds
	if err := executeSphinxHashOp(stack, mem); err == nil {
		t.Fatal("expected an out-of-bounds error, got nil")
	}
}
