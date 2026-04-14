// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/crypto/STHINCS/address/stack.go
package util

// Package util provides common utility functions and data structures for STHINCS implementation
//
// This file implements a stack data structure used in Merkle tree construction.
// The stack is a fundamental component of the treehash algorithm, which builds
// Merkle trees efficiently with O(height) memory instead of O(leaves) memory.

// StackEntry represents a node in the Merkle tree building stack
//
// During treehash algorithm, we maintain a stack of nodes at different heights.
// When two nodes at the same height appear, they are combined into a parent node.
// This stack-based approach processes leaves left-to-right and only keeps
// nodes that cannot yet be combined.
//
// Mathematical invariant:
// The stack always maintains strictly increasing heights from bottom to top.
// Example: [height 2, height 5, height 7] - heights increase as we go up
// This invariant ensures efficient parent-child detection.
type StackEntry struct {
	// Node: The hash value (N bytes) of this Merkle tree node
	// For leaf nodes: Node = F(PRF(SEED, adrs))
	// For internal nodes: Node = H(left_child || right_child)
	Node []byte

	// NodeHeight: Height of this node in the Merkle tree
	// Height 0 = leaf nodes (at the bottom)
	// Height h = node at level h (2^h leaves below it)
	// Height H' = root node (top of tree)
	//
	// Mathematical meaning:
	// A node at height h is the root of a subtree containing 2^h leaves
	// The node's value is the Merkle hash of those 2^h leaves
	NodeHeight int
}

// Stack is a slice of StackEntry pointers implementing a LIFO (Last-In-First-Out) stack
//
// Memory optimization:
// The stack size is bounded by O(height) because we only store nodes that
// cannot yet be combined. For a tree of height H', the maximum stack size
// is H' (when processing leaves in order).
//
// Example: Building a tree of height 3 (8 leaves):
// Process leaf 0: stack = [height0]
// Process leaf 1: combine with leaf 0 -> height1, stack = [height1]
// Process leaf 2: stack = [height1, height0]
// Process leaf 3: combine leaf 2+3 -> height1, then combine with existing height1 -> height2
// Stack size never exceeds height (3 in this case)
type Stack []*StackEntry

// IsEmpty checks if the stack has no elements
// Time complexity: O(1)
// Space complexity: O(1)
func (s *Stack) IsEmpty() bool {
	return len(*s) == 0
}

// Push adds a new node to the top of the stack
//
// Operation: appends to end of slice (top of stack)
// Time complexity: O(1) amortized
// Space complexity: O(1) amortized (may cause slice growth)
//
// Invariant maintained: After push, heights may temporarily violate
// the strictly increasing property. The caller (treehash algorithm)
// is responsible for combining nodes when heights are equal.
func (s *Stack) Push(stackEntry *StackEntry) {
	*s = append(*s, stackEntry)
}

// Pop removes and returns the top element from the stack
//
// Operation: removes last element of slice (top of stack)
// Time complexity: O(1)
// Space complexity: O(1)
//
// Returns nil if stack is empty (should not happen in correct usage)
//
// Mathematical usage:
// In treehash, Pop is called when combining two nodes at same height.
// The left node is popped from stack, then combined with current node
// to form the parent node.
func (s *Stack) Pop() *StackEntry {
	if s.IsEmpty() {
		return nil
	} else {
		// Get the top element (last element in slice)
		element := (*s)[len(*s)-1]

		// Remove top element by slicing (reference remains, but GC will handle)
		// Note: This doesn't free memory immediately, but the slice header
		// is updated to exclude the popped element
		*s = (*s)[:len(*s)-1]
		return element
	}
}

// Peek returns the top element without removing it
//
// Operation: reads last element of slice without modification
// Time complexity: O(1)
// Space complexity: O(1)
//
// # Returns nil if stack is empty
//
// Mathematical usage:
// Peek is used to check the height of the top node without removing it.
// This determines whether we need to combine (if heights equal) or
// just push the new node (if heights are strictly increasing).
func (s *Stack) Peek() *StackEntry {
	if s.IsEmpty() {
		return nil
	} else {
		element := (*s)[len(*s)-1]
		return element
	}
}
