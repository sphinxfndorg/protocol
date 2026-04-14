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

// go/src/crypto/STHINCS/address/xmss.go
package xmss

import (
	"fmt"

	"github.com/sphinxorg/protocol/src/crypto/STHINCS/address"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/util"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/wots"
)

// GetWOTSSig returns the WOTS+ signature component
func (s *XMSSSignature) GetWOTSSig() []byte {
	return s.WotsSignature
}

// GetXMSSAUTH returns the authentication path component
func (s *XMSSSignature) GetXMSSAUTH() []byte {
	return s.AUTH
}

// treehash computes the root of a Merkle subtree using a stack-based algorithm
//
// MATHEMATICAL ALGORITHM:
// For a subtree of height h (2^h leaves):
//
//	root = MerkleTree(leaves[startIndex ... startIndex + 2^h - 1])
//
// The algorithm processes leaves left-to-right using a stack where:
//   - Stack entries have strictly increasing heights
//   - When two nodes at same height exist, they are combined into a parent
//   - Parent = H(left_child || right_child)
//
// In XMSS, leaves are WOTS+ public keys (compressed to N bytes)
//
// Time complexity: O(2^h) hash operations
// Space complexity: O(h) stack entries
//
// Parameters:
//
//	params: STHINCS parameters (N, Hprime, etc.)
//	SKseed: Secret seed for generating WOTS+ keys
//	startIndex: First leaf index (must be multiple of 2^targetNodeHeight)
//	targetNodeHeight: Height of desired subtree root (0 = leaf, Hprime = full tree)
//	PKseed: Public seed for WOTS+ key generation
//	adrs: Base address (will be modified during computation)
//
// Returns: Root node value (N bytes) at height targetNodeHeight
func treehash(params *parameters.Parameters, SKseed []byte, startIndex int, targetNodeHeight int, PKseed []byte, adrs *address.ADRS) ([]byte, error) {
	// Validate startIndex alignment
	// Mathematical requirement: For a subtree of height h, leaves must start
	// at an index that is a multiple of 2^h.
	// Example: height 3 (8 leaves) → valid starts: 0, 8, 16, ...
	// 1 << targetNodeHeight = 2^targetNodeHeight
	if startIndex%(1<<targetNodeHeight) != 0 {
		return nil, fmt.Errorf("startIndex %d not aligned to subtree of height %d", startIndex, targetNodeHeight)
	}

	// Use bit shift instead of math.Pow for performance and precision
	// leafCount = 2^targetNodeHeight
	leafCount := 1 << targetNodeHeight
	if leafCount <= 0 {
		return nil, fmt.Errorf("targetNodeHeight %d too large, would overflow", targetNodeHeight)
	}

	// Initialize empty stack for treehash algorithm
	// Stack stores nodes with their heights, maintaining increasing order
	stack := util.Stack{}

	// Process each leaf in order from left to right
	for i := 0; i < leafCount; i++ {
		// STEP 1: Compute leaf node at position startIndex + i
		// Leaf = WOTS+ public key for this index
		// Each leaf is a compressed WOTS+ public key (N bytes)
		adrs.SetType(address.WOTS_HASH)
		adrs.SetKeyPairAddress(startIndex + i)

		node, err := wots.Wots_PKgen(params, SKseed, PKseed, adrs)
		if err != nil {
			return nil, fmt.Errorf("WOTS_PKgen failed for leaf %d: %w", startIndex+i, err)
		}

		// Prepare for parent computation (start at height 1)
		adrs.SetType(address.TREE)
		adrs.SetTreeHeight(1)
		adrs.SetTreeIndex(startIndex + i)

		// STEP 2: Combine with stack entries at same height
		// This implements the classic Merkle tree algorithm:
		// While stack top has same height as current node, combine them
		// because they are siblings in the binary tree
		for len(stack) > 0 && (stack.Peek().NodeHeight == adrs.GetTreeHeight()) {
			// Parent index calculation:
			// In a binary tree with indices at each level:
			//   Left child index = 2 * parent_index
			//   Right child index = 2 * parent_index + 1
			// Therefore: parent_index = floor(child_index / 2)
			// For right child: (index - 1) / 2 = floor(index/2)
			// Both cases reduce to integer division by 2
			adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2)

			// Parent = H(left_child || right_child)
			// Order matters: left child first (popped from stack), then current node
			leftNode := stack.Pop().Node
			combined := append(leftNode, node...) // left || right
			node = params.Tweak.H(PKseed, adrs, combined)

			// Parent is one level higher in the tree
			adrs.SetTreeHeight(adrs.GetTreeHeight() + 1)
		}

		// Push current node onto stack with its height
		stack.Push(&util.StackEntry{Node: node, NodeHeight: adrs.GetTreeHeight()})
	}

	// After processing all leaves, stack should contain exactly one node: the root
	if stack.IsEmpty() {
		return nil, fmt.Errorf("stack is empty after processing leaves")
	}

	return stack.Pop().Node, nil
}

// Xmss_PKgen generates the public key (root) of an XMSS tree
//
// The public key is simply the root of the full Merkle tree of height Hprime.
// This root authenticates all 2^Hprime leaves (WOTS+ key pairs).
//
// MATHEMATICAL PROCESS:
//
//	root = MerkleTree(WOTS_PK[0], WOTS_PK[1], ..., WOTS_PK[2^Hprime - 1])
//
// Returns: N-byte root value (public key)
func Xmss_PKgen(params *parameters.Parameters, SKseed []byte, PKseed []byte, adrs *address.ADRS) ([]byte, error) {
	// Build full tree of height Hprime starting from leaf 0
	// 2^Hprime leaves total
	return treehash(params, SKseed, 0, params.Hprime, PKseed, adrs)
}

// Xmss_sign generates an XMSS signature for message M using leaf index idx
//
// SIGNING PROCESS:
//  1. Generate authentication path from leaf idx to root
//     For each level i from 0 to Hprime-1:
//     - Determine sibling node at this level
//     - Compute subtree root of sibling using treehash
//     - Store as AUTH[i]
//  2. Sign message using WOTS+ at leaf idx
//  3. Return (WOTS_signature, AUTH)
//
// AUTHENTICATION PATH GENERATION:
// At level i, we need the sibling of the node on the path to root.
//
// Let's understand with an example tree of height 3 (8 leaves):
//
// Level 2 (root):        R
//
//	/ \
//
// Level 1:            N0   N1
//
//	/  \  / \
//
// Level 0 (leaves): L0 L1 L2 L3
//
// For leaf index 1 (L1):
//
//	i=0: sibling of L1 is L0 → index 0
//	i=1: sibling of N0 (parent of L0/L1) is N1 → index 1
//	i=2: sibling of R is none (root has no sibling)
//
// FORMULA: sibling_index = idx XOR (1 << i)
// But for subtree roots, we use: k = (idx >> i) ^ 1
// Then multiply by 2^i to get starting leaf index of sibling subtree
//
// Example with idx=1 (binary 001), i=1:
//
//	(1 >> 1) = 0, 0 ^ 1 = 1, then 1 << 1 = 2
//	Starting leaf index = 2 (L2 and L3 are the sibling subtree)
//
// Parameters:
//
//	M: Message to sign (already hashed by Hmsg)
//	SKseed: Secret seed for generating WOTS+ keys
//	idx: Leaf index to use (0 to 2^Hprime - 1)
//	PKseed: Public seed for randomization
//	adrs: Address (will be modified during signing)
//
// Returns: XMSS signature structure (WOTS signature + authentication path)
func Xmss_sign(params *parameters.Parameters, M []byte, SKseed []byte, idx int, PKseed []byte, adrs *address.ADRS) (*XMSSSignature, error) {
	// Validate idx is within bounds
	// maxLeaves = 2^Hprime
	maxLeaves := 1 << params.Hprime
	if idx < 0 || idx >= maxLeaves {
		return nil, fmt.Errorf("idx %d out of range [0, %d)", idx, maxLeaves)
	}

	// Step 1: Generate authentication path
	// AUTH will contain Hprime nodes, each N bytes
	AUTH := make([]byte, params.Hprime*params.N)

	for i := 0; i < params.Hprime; i++ {
		// Compute sibling index at level i
		// Formula: k = floor(idx / 2^i) XOR 1
		// Using bit shift: (idx >> i) gives floor(idx / 2^i)
		// XOR with 1 flips the least significant bit (0↔1)
		// This gives the sibling's ancestor index at level i
		k := (idx >> i) ^ 1

		// Compute root of sibling subtree of height i
		// Starting leaf index = k * 2^i = k << i
		// Height i subtree contains leaves [k<<i, (k<<i) + 2^i - 1]
		subtreeRoot, err := treehash(params, SKseed, k<<i, i, PKseed, adrs)
		if err != nil {
			return nil, fmt.Errorf("treehash failed for level %d: %w", i, err)
		}
		// Store at position i * N in the AUTH buffer
		copy(AUTH[i*params.N:], subtreeRoot)
	}

	// Step 2: Sign message with WOTS+ at leaf idx
	adrs.SetType(address.WOTS_HASH)
	adrs.SetKeyPairAddress(idx)

	sig, err := wots.Wots_sign(params, M, SKseed, PKseed, adrs)
	if err != nil {
		return nil, fmt.Errorf("WOTS_sign failed: %w", err)
	}

	return &XMSSSignature{WotsSignature: sig, AUTH: AUTH}, nil
}

// Xmss_pkFromSig recovers the XMSS public key from a signature
//
// VERIFICATION PROCESS (Root Reconstruction):
//  1. Recover WOTS+ public key from signature: pk_wots = Wots_pkFromSig(...)
//  2. Combine pk_wots with authentication path to reconstruct root
//     Starting from leaf, move up using auth nodes:
//     - If leaf is left child (bit k = 0): parent = H(pk_wots || AUTH[i])
//     - If leaf is right child (bit k = 1): parent = H(AUTH[i] || pk_wots)
//  3. After Hprime steps, we have the root
//
// MATHEMATICAL PROPERTY:
// For a Merkle tree, the root can be reconstructed from any leaf and
// its authentication path using the formula:
//
//	root = H(... H(H(leaf || auth0) || auth1) ... || auth_{Hprime-1})
//	with appropriate ordering based on whether the leaf is left or right child
//
// This works because the authentication path provides all sibling nodes
// needed to compute parent nodes up to the root.
//
// Returns: Reconstructed N-byte root (should match Xmss_PKgen output)
func Xmss_pkFromSig(params *parameters.Parameters, idx int, SIG_XMSS *XMSSSignature, M []byte, PKseed []byte, adrs *address.ADRS) ([]byte, error) {
	// Validate signature is not nil
	if SIG_XMSS == nil {
		return nil, fmt.Errorf("nil XMSS signature provided")
	}

	// Validate AUTH length
	expectedAuthLen := params.Hprime * params.N
	if len(SIG_XMSS.AUTH) != expectedAuthLen {
		return nil, fmt.Errorf("invalid AUTH length: expected %d, got %d", expectedAuthLen, len(SIG_XMSS.AUTH))
	}

	// Step 1: Recover WOTS+ public key from signature
	// This gives us the leaf value (WOTS+ public key)
	adrs.SetType(address.WOTS_HASH)
	adrs.SetKeyPairAddress(idx)

	node0, err := wots.Wots_pkFromSig(params, SIG_XMSS.WotsSignature, M, PKseed, adrs)
	if err != nil {
		return nil, fmt.Errorf("WOTS_pkFromSig failed: %w", err)
	}

	AUTH := SIG_XMSS.AUTH
	var node1 []byte

	// Step 2: Reconstruct path from leaf to root using authentication nodes
	adrs.SetType(address.TREE)
	adrs.SetTreeIndex(idx)

	// Process each level from leaf (k=0) to root (k=Hprime-1)
	for k := 0; k < params.Hprime; k++ {
		adrs.SetTreeHeight(k + 1)

		// Determine if current node is left or right child
		// Check bit k of the leaf index:
		//   ((idx >> k) & 1) == 0 → left child
		//   ((idx >> k) & 1) == 1 → right child
		if ((idx >> k) & 1) == 0 {
			// LEFT CHILD CASE: current node is left, AUTH[k] is right sibling
			// Parent index = floor(child_index / 2)
			adrs.SetTreeIndex(adrs.GetTreeIndex() / 2)

			// Parent = H(current || AUTH[k])
			// Concatenate: left child (node0) then right sibling (AUTH[k])
			bytesToHash := make([]byte, params.N+params.N)
			copy(bytesToHash, node0)
			copy(bytesToHash[params.N:], AUTH[k*params.N:(k+1)*params.N])

			node1 = params.Tweak.H(PKseed, adrs, bytesToHash)
		} else {
			// RIGHT CHILD CASE: AUTH[k] is left sibling, current is right
			// Parent index = floor((child_index - 1) / 2)
			adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2)

			// Parent = H(AUTH[k] || current)
			// Concatenate: left sibling (AUTH[k]) then right child (node0)
			bytesToHash := make([]byte, params.N+params.N)
			copy(bytesToHash, AUTH[k*params.N:(k+1)*params.N])
			copy(bytesToHash[params.N:], node0)

			node1 = params.Tweak.H(PKseed, adrs, bytesToHash)
		}

		// Move up to next level
		node0 = node1
	}

	// After processing all Hprime levels, node0 is the root
	return node0, nil
}
