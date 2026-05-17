// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/address/fors.go
package fors

import (
	"fmt"

	"github.com/sphinxorg/protocol/src/crypto/STHINCS/address"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/util"
)

// GetSK returns the private key value (leaf) at given index
// Performs bounds checking to prevent out-of-range panics
func (s *FORSSignature) GetSK(index int) []byte {
	if index < 0 || index >= len(s.Forspkauth) {
		return nil
	}
	return s.Forspkauth[index].PrivateKeyValue
}

// GetAUTH returns the authentication path at given index
// Performs bounds checking to prevent out-of-range panics
func (s *FORSSignature) GetAUTH(index int) []byte {
	if index < 0 || index >= len(s.Forspkauth) {
		return nil
	}
	return s.Forspkauth[index].AUTH
}

// Fors_treehash computes the root of a Merkle subtree using a stack-based algorithm
//
// MATHEMATICAL ALGORITHM:
// For a subtree of height h (2^h leaves):
//
//	root = MerkleTree(leaves[startIndex ... startIndex + 2^h - 1])
//
// The algorithm processes leaves left-to-right and uses a stack where:
//   - Stack entries have strictly increasing heights
//   - When two nodes at same height exist, they are combined into a parent
//   - Parent = H(left_child || right_child)
//
// Time complexity: O(2^h) hash operations
// Space complexity: O(h) stack entries
//
// Parameters:
//
//	params: STHINCS parameters (N, etc.)
//	SKseed: Secret seed for generating leaf values
//	startIndex: First leaf index (must be multiple of 2^targetNodeHeight)
//	targetNodeHeight: Height of desired subtree root (0 = leaf, a = full tree)
//	PKseed: Public seed for randomization (domain separation)
//	adrs: Base address (will be modified during computation)
//
// Returns: Root node value (N bytes) at height targetNodeHeight, or error
func Fors_treehash(params *parameters.Parameters, SKseed []byte, startIndex int, targetNodeHeight int, PKseed []byte, adrs *address.ADRS) ([]byte, error) {
	// Validate startIndex alignment
	// Mathematical requirement: For a subtree of height h, leaves must start
	// at an index that is a multiple of 2^h. Example: height 3 (8 leaves)
	// valid starts: 0, 8, 16, ... invalid starts: 1, 2, 3, ...
	// 1 << targetNodeHeight = 2^targetNodeHeight (bit shift is 2^power)
	if startIndex%(1<<targetNodeHeight) != 0 {
		return nil, fmt.Errorf("startIndex %d not aligned to subtree of height %d", startIndex, targetNodeHeight)
	}

	// Use bit shift instead of math.Pow for performance and precision
	// 1 << targetNodeHeight = 2^targetNodeHeight leaves in this subtree
	// Example: targetNodeHeight=3 → 1<<3 = 8 leaves
	leafCount := 1 << targetNodeHeight
	if leafCount <= 0 {
		return nil, fmt.Errorf("targetNodeHeight %d too large, would overflow", targetNodeHeight)
	}

	// Initialize empty stack for the treehash algorithm
	// Stack stores nodes with their heights, maintaining increasing order
	stack := util.Stack{}

	// Process each leaf in order from left to right
	for i := 0; i < leafCount; i++ {
		// STEP 1: Compute leaf node at position startIndex + i
		// Leaf = F(PRF(SKseed, adrs(leaf_index)))
		// This two-step process ensures each leaf is pseudorandom
		// but deterministic given the seed (no randomness needed)
		adrs.SetTreeHeight(0)                    // Height 0 = leaf level
		adrs.SetTreeIndex(startIndex + i)        // Set leaf index
		sk := params.Tweak.PRF(SKseed, adrs)     // Generate secret at this leaf
		node := params.Tweak.F(PKseed, adrs, sk) // Compress to N-byte leaf value

		// Prepare for parent computation (start at height 1)
		adrs.SetTreeHeight(1)
		adrs.SetTreeIndex(startIndex + i)

		// STEP 2: Combine with existing stack entries at same height
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
			// append(stack.Pop().Node, node...) concatenates left + right
			node = params.Tweak.H(PKseed, adrs, append(stack.Pop().Node, node...))

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

// Fors_PKgen generates the FORS public key
//
// MATHEMATICAL PROCESS:
// 1. For each of the k trees (i = 0 to k-1):
//   - Build a Merkle tree of height a (2^a leaves)
//   - Compute root_i = MerkleTree(leaves_{i*2^a} to leaves_{(i+1)*2^a-1})
//
// 2. Concatenate all k roots: roots = root_0 || root_1 || ... || root_{k-1}
// 3. Public key = T_l(PKseed, adrs_fors_roots, roots)
//
// Total leaves = k * 2^a (this is the few-time signature capacity)
// The public key is compressed to N bytes using T_l
func Fors_PKgen(params *parameters.Parameters, SKseed []byte, PKseed []byte, adrs *address.ADRS) ([]byte, error) {
	// Copy address to avoid modifying the original
	forsPKadrs := adrs.Copy()

	// Buffer for concatenated roots: k * N bytes
	// Each root is N bytes, total size = K * N
	root := make([]byte, params.K*params.N)

	// Build each FORS tree and collect its root
	// params.T = number of leaves per tree = 2^LogT
	// params.A = LogT = height of each FORS tree
	for i := 0; i < params.K; i++ {
		// Compute root of tree i
		// i * params.T = starting leaf index for this tree
		// params.A = target height (full tree height)
		treeRoot, err := Fors_treehash(params, SKseed, i*params.T, params.A, PKseed, adrs)
		if err != nil {
			return nil, fmt.Errorf("Fors_treehash failed for tree %d: %w", i, err)
		}
		// Copy root to position i*N in the concatenated buffer
		copy(root[i*params.N:], treeRoot)
	}

	// Set address for final compression
	// Type FORS_ROOTS indicates we're combining the k roots
	forsPKadrs.SetType(address.FORS_ROOTS)
	forsPKadrs.SetKeyPairAddress(adrs.GetKeyPairAddress())

	// Final public key = T_l(PKseed, adrs, root_0 || ... || root_{k-1})
	// This compresses k*N bytes into a single N-byte value
	pk := params.Tweak.T_l(PKseed, forsPKadrs, root)

	return pk, nil
}

// message_to_indices converts a message digest into k indices
//
// MATHEMATICAL PROCESS:
// The message M (length m bytes) is treated as a bit string of length 8m bits
// We extract a bits at a time to form k indices:
//
//	index_i = bits[(i*a) : (i*a + a)] interpreted as integer (0 to 2^a - 1)
//
// BIT EXTRACTION FORMULA:
// For each bit position 'offset' (0-indexed):
//
//	byte_index = offset >> 3 (integer division by 8)
//	bit_in_byte = offset & 0x7 (offset mod 8)
//	bit_value = (M[byte_index] >> bit_in_byte) & 0x1
//
// XOR construction: indices[i] ^= bit_value << j
// This builds the integer by setting bits from LSB to MSB
//
// Parameters:
//
//	M: Message digest (length = m bytes)
//	k: Number of indices to extract (equals number of FORS trees)
//	a: Number of bits per index (a = log2(2^a) = tree height)
//
// Returns: Array of k indices, each in [0, 2^a - 1]
func message_to_indices(M []byte, k int, a int) ([]int, error) {
	// Calculate required bits and validate input length
	// Each index needs a bits, total = k * a bits
	// Convert bits to bytes: ceil(bits / 8) = (bits + 7) / 8
	requiredBits := k * a
	requiredBytes := (requiredBits + 7) / 8

	if len(M) < requiredBytes {
		return nil, fmt.Errorf("message too short: need %d bytes, have %d", requiredBytes, len(M))
	}

	offset := 0 // Current bit position in the message (0-indexed)
	indices := make([]int, k)

	// Extract k indices, each of a bits
	for i := 0; i < k; i++ {
		indices[i] = 0

		// Build index by reading a bits (least significant first)
		// j = bit position within the index (0 = LSB, a-1 = MSB)
		for j := 0; j < a; j++ {
			// Bounds check to prevent out-of-range panic
			if offset/8 >= len(M) {
				return nil, fmt.Errorf("offset %d out of bounds (message length %d)", offset, len(M))
			}

			// Extract single bit at position 'offset'
			// offset>>3 = byte index (integer division by 8)
			// offset&0x7 = bit position within byte (0-7)
			// >> (offset & 0x7) shifts to LSB
			// & 0x1 masks to get single bit
			bit := (int(M[offset>>3]) >> (offset & 0x7)) & 0x1

			// Set the j-th bit of the index
			// bit << j places the bit at correct position
			// XOR (^=) accumulates bits (same as OR since bits don't overlap)
			indices[i] ^= bit << j

			offset++ // Move to next bit position
		}
	}
	return indices, nil
}

// Fors_sign generates a FORS signature for message M
//
// SIGNING PROCESS:
//  1. Convert message to indices: idx_i = message_to_indices(M, k, a)
//  2. For each tree i (0 to k-1):
//     a. Select leaf at position idx_i within tree i
//     b. Compute leaf value: PKElement = PRF(SKseed, adrs(leaf))
//     c. Compute authentication path from leaf to root (height a)
//     - For each level j from 0 to a-1:
//     * Determine sibling index at level j
//     * Compute subtree root of sibling using Fors_treehash
//     * Store in AUTH[j]
//     d. Store (PKElement, AUTH) in signature
//
// SIBLING INDEX CALCULATION:
// At level j, the sibling is the node that is NOT on the path to root
// If bit j of leaf index is 0 (going left), sibling is index+1 (right)
// If bit j of leaf index is 1 (going right), sibling is index-1 (left)
// Formula: sibling_index = leaf_index XOR (1 << j)
// But since we need subtree root, we use s = (leaf_index >> j) ^ 1
// Then multiply by 2^j to get starting leaf index of sibling subtree
func Fors_sign(params *parameters.Parameters, M []byte, SKseed []byte, PKseed []byte, adrs *address.ADRS) (*FORSSignature, error) {
	// Get indices from message (k indices, each a bits)
	indices, err := message_to_indices(M, params.K, params.A)
	if err != nil {
		return nil, fmt.Errorf("message_to_indices failed: %w", err)
	}

	// Initialize signature structure with capacity for k trees
	SIG_FORS := &FORSSignature{
		Forspkauth: make([]*TreePKAUTH, 0, params.K),
	}

	// Process each FORS tree independently
	for i := 0; i < params.K; i++ {
		// STEP 1: Select leaf at position indices[i] within tree i
		// Leaf index = base_index + offset
		// base_index = i * params.T (start of tree i)
		// offset = indices[i] (0 to 2^a - 1)
		adrs.SetTreeHeight(0)
		adrs.SetTreeIndex(i*params.T + indices[i])

		// STEP 2a: Compute leaf value (the actual signature element)
		// Leaf = PRF(SKseed, adrs) - deterministic given the seed
		PKElement := params.Tweak.PRF(SKseed, adrs)

		// STEP 2b: Compute authentication path of length a
		// AUTH will contain a nodes, each N bytes
		AUTH := make([]byte, params.A*params.N)

		// For each level j from 0 to a-1
		for j := 0; j < params.A; j++ {
			// Calculate sibling index at level j
			// (indices[i] >> j) ^ 1:
			//   - Shift right by j to get the ancestor index at this level
			//   - XOR with 1 flips the last bit, giving the sibling ancestor
			// Then multiply by 2^j to get starting leaf index of sibling subtree
			// Using bit shift: s * (1 << j) = s << j
			//
			// Example: leaf index = 5 (binary 101), j=1
			//   (5 >> 1) = 2 (binary 10)
			//   2 ^ 1 = 3 (binary 11)
			//   sibling start = 3 << 1 = 6
			s := (indices[i] >> j) ^ 1

			// Compute root of sibling subtree of height j
			// This node is exactly what we need for the authentication path
			// i*params.T = start of current tree
			// s << j = starting leaf index of sibling subtree
			// j = height of subtree (we want the root at this level)
			test, err := Fors_treehash(params, SKseed, i*params.T+(s<<j), j, PKseed, adrs)
			if err != nil {
				return nil, fmt.Errorf("Fors_treehash failed for tree %d, level %d: %w", i, j, err)
			}
			// Store auth node at position j * N
			copy(AUTH[j*params.N:], test)
		}

		// Store leaf and auth path for this tree
		SIG_FORS.Forspkauth = append(SIG_FORS.Forspkauth, &TreePKAUTH{
			PrivateKeyValue: PKElement,
			AUTH:            AUTH,
		})
	}
	return SIG_FORS, nil
}

// Fors_pkFromSig recovers the FORS public key from a signature
//
// VERIFICATION PROCESS (Root Reconstruction):
// For each tree i (0 to k-1):
//  1. Start with revealed leaf value: node = σ_i
//  2. For each level j from 0 to a-1:
//     - If leaf was left child (bit j = 0):
//     parent = H(node || AUTH[j])
//     - If leaf was right child (bit j = 1):
//     parent = H(AUTH[j] || node)
//     - node = parent
//  3. After a steps, node = root_i
//
// 4. Concatenate all roots: roots = root_0 || ... || root_{k-1}
// 5. Public key = T_l(PKseed, adrs_fors_roots, roots)
//
// This reconstructs the exact same public key that Fors_PKgen would produce
func Fors_pkFromSig(params *parameters.Parameters, SIG_FORS *FORSSignature, M []byte, PKseed []byte, adrs *address.ADRS) ([]byte, error) {
	// Validate signature structure
	if SIG_FORS == nil {
		return nil, fmt.Errorf("nil FORS signature provided")
	}
	if len(SIG_FORS.Forspkauth) != params.K {
		return nil, fmt.Errorf("invalid FORS signature: expected %d trees, got %d", params.K, len(SIG_FORS.Forspkauth))
	}

	// Get indices from message (same as during signing)
	indices, err := message_to_indices(M, params.K, params.A)
	if err != nil {
		return nil, fmt.Errorf("message_to_indices failed: %w", err)
	}

	// Buffer for concatenated roots: k * N bytes
	root := make([]byte, params.K*params.N)

	// Reconstruct each tree's root from the signature
	for i := 0; i < params.K; i++ {
		// Get the revealed leaf value for this tree
		sk := SIG_FORS.GetSK(i)
		if sk == nil {
			return nil, fmt.Errorf("nil private key for tree %d", i)
		}

		// Compute leaf node = F(PKseed, adrs, sk)
		// This is the same computation as during tree building
		adrs.SetTreeHeight(0)
		adrs.SetTreeIndex(i*params.T + indices[i])
		node0 := params.Tweak.F(PKseed, adrs, sk)
		var node1 []byte

		// Get authentication path for this tree
		auth := SIG_FORS.GetAUTH(i)
		if auth == nil {
			return nil, fmt.Errorf("nil AUTH for tree %d", i)
		}
		if len(auth) < params.A*params.N {
			return nil, fmt.Errorf("AUTH too short for tree %d: expected %d, got %d", i, params.A*params.N, len(auth))
		}

		// Reconstruct path from leaf to root using authentication nodes
		// Start at leaf index and move up level by level
		adrs.SetTreeIndex(i*params.T + indices[i])

		for j := 0; j < params.A; j++ {
			adrs.SetTreeHeight(j + 1)

			// Determine if current node is left or right child
			// Check bit j of the leaf index:
			//   If bit j = 0: current node is left child
			//   If bit j = 1: current node is right child
			// Formula: (indices[i] >> j) & 1
			if ((indices[i] >> j) & 1) == 0 {
				// LEFT CHILD CASE: current node is left, AUTH[j] is right sibling
				// Parent index = floor(child_index / 2)
				adrs.SetTreeIndex(adrs.GetTreeIndex() / 2)

				// Parent = H(current || AUTH[j])
				// Concatenate: left child (node0) then right sibling (auth)
				bytesToHash := make([]byte, params.N+params.N)
				copy(bytesToHash, node0)
				copy(bytesToHash[params.N:], auth[j*params.N:(j+1)*params.N])

				node1 = params.Tweak.H(PKseed, adrs, bytesToHash)
			} else {
				// RIGHT CHILD CASE: AUTH[j] is left sibling, current is right
				// Parent index = floor((child_index - 1) / 2)
				adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2)

				// Parent = H(AUTH[j] || current)
				// Concatenate: left sibling (auth) then right child (node0)
				bytesToHash := make([]byte, params.N+params.N)
				copy(bytesToHash, auth[j*params.N:(j+1)*params.N])
				copy(bytesToHash[params.N:], node0)

				node1 = params.Tweak.H(PKseed, adrs, bytesToHash)
			}

			// Move up to next level
			node0 = node1
		}

		// After processing all a levels, node0 is the tree root
		copy(root[i*params.N:], node0)
	}

	// Reconstruct final public key from k roots
	// This is identical to the key generation process
	forsPKadrs := adrs.Copy()
	forsPKadrs.SetType(address.FORS_ROOTS)
	forsPKadrs.SetKeyPairAddress(adrs.GetKeyPairAddress())
	pk := params.Tweak.T_l(PKseed, forsPKadrs, root)

	return pk, nil
}
