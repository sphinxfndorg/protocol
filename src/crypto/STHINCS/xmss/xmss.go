// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/xmss/xmss.go
package xmss

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/address"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/util"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/wots"
)

// parallelThreshold is the smallest number of leaf computations for which
// fanning out across goroutines is worth the scheduling and ADRS-copy cost.
// Below it the plain sequential loop is faster, so small subtrees stay
// sequential. This only affects speed, never the output.
const parallelThreshold = 4

// buildTree computes the root of a full XMSS tree of height Hprime AND the
// authentication path for one leaf, in a single pass.
//
// WHY THIS EXISTS. The original Xmss_sign called treehash once per level
// (2^Hprime - 1 leaves in total, all WOTS+ keygens) and then called
// Xmss_pkFromSig in Ht_sign to recover the root it had just computed. So each
// layer built every leaf twice over. This builds each leaf exactly once and
// returns both the root and the auth path from it.
//
// The root is mathematically identical to treehash's: the same WOTS+ leaves in
// the same order, folded left-to-right by the same H() calls at the same
// absolute TreeHeight/TreeIndex addresses. The ADRS usage is identical to
// treehash's, which is what keeps the bytes identical — see
// TestGoldenSignatures.
//
// Concurrency: the leaves are independent, so they are computed in parallel.
// Every goroutine gets its own ADRS copy (the tree walk mutates the address),
// writes only to its own slot in the level slice, and the fold that follows is
// sequential and single-threaded, so there is no shared mutable state. A
// panic inside a leaf — e.g. the nil-hasher panic in the SPHINXHASH backend —
// is converted to an error, so a fault cannot take down the process from a
// worker goroutine.
func buildTree(params *parameters.Parameters, SKseed []byte, PKseed []byte,
	base *address.ADRS, leafIdx int) (root, auth []byte, err error) {

	n := 1 << params.Hprime
	level := make([][]byte, n)

	// Fan out over leaves. Each goroutine owns level[i] and its own ADRS.
	if n >= parallelThreshold {
		workers := runtime.GOMAXPROCS(0)
		if workers > n {
			workers = n
		}
		var wg sync.WaitGroup
		// Buffer n so a failing worker never blocks on send; only the first
		// error is reported but every error is drained.
		errs := make(chan error, n)
		sem := make(chan struct{}, workers)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				// A panic in a worker would otherwise crash the process; the
				// sequential path below had the same risk, so convert it to an
				// error and keep signing reportable.
				defer func() {
					if r := recover(); r != nil {
						errs <- fmt.Errorf("panic computing leaf %d: %v", i, r)
					}
				}()
				v, lerr := leafNode(params, SKseed, PKseed, base, i)
				if lerr != nil {
					errs <- lerr
					return
				}
				level[i] = v
			}(i)
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			if err == nil {
				err = e
			}
		}
		if err != nil {
			return nil, nil, err
		}
	} else {
		for i := 0; i < n; i++ {
			v, lerr := leafNode(params, SKseed, PKseed, base, i)
			if lerr != nil {
				return nil, nil, lerr
			}
			level[i] = v
		}
	}

	// Fold level by level, recording the sibling on the leaf's path.
	// Sequential on purpose: this is O(2^Hprime) H() calls, and parallelizing
	// it would need a second fan-out for very little gain.
	auth = make([]byte, params.Hprime*params.N)
	for h := 1; h <= params.Hprime; h++ {
		// The sibling on the leaf's path at this height.
		sib := (leafIdx >> (h - 1)) ^ 1
		copy(auth[(h-1)*params.N:], level[sib])

		next := make([][]byte, len(level)/2)
		for j := range next {
			a := base.Copy()
			a.SetType(address.TREE)
			a.SetTreeHeight(h)
			a.SetTreeIndex(j)
			// Fresh buffer per node: append(level[2j], ...) would write into
			// a hash output's spare capacity and can alias memory another
			// node still references.
			combined := make([]byte, 0, 2*params.N)
			combined = append(combined, level[2*j]...)
			combined = append(combined, level[2*j+1]...)
			next[j] = params.Tweak.H(PKseed, a, combined)
		}
		level = next
	}

	return level[0], auth, nil
}

// leafNode computes one WOTS+ public key (a tree leaf) at absolute index i.
// It uses a private copy of base so the caller's address is untouched, which is
// what makes the parallel fan-out above safe.
func leafNode(params *parameters.Parameters, SKseed, PKseed []byte,
	base *address.ADRS, i int) ([]byte, error) {
	a := base.Copy()
	a.SetType(address.WOTS_HASH)
	a.SetKeyPairAddress(i)
	v, err := wots.Wots_PKgen(params, SKseed, PKseed, a)
	if err != nil {
		return nil, fmt.Errorf("WOTS_PKgen failed for leaf %d: %w", i, err)
	}
	return v, nil
}

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
			// Order matters: left child first (popped from stack), then current node.
			//
			// Build the concatenation in a fresh buffer. append(leftNode, node...)
			// would write into leftNode's spare capacity (hash outputs are often
			// sliced from larger arrays, e.g. sha256.Sum(nil)[:N]) and can alias
			// memory that something else still holds.
			leftNode := stack.Pop().Node
			combined := make([]byte, 0, len(leftNode)+len(node))
			combined = append(combined, leftNode...)
			combined = append(combined, node...) // left || right
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

	// One pass: build every leaf once, fold to the root, and keep the sibling
	// on idx's path as the auth path.
	root, AUTH, err := Xmss_treeWithAuth(params, SKseed, PKseed, adrs, idx)
	if err != nil {
		return nil, fmt.Errorf("tree build failed: %w", err)
	}
	_ = root

	// Sign the message with WOTS+ at leaf idx.
	a := adrs.Copy()
	a.SetType(address.WOTS_HASH)
	a.SetKeyPairAddress(idx)

	sig, err := wots.Wots_sign(params, M, SKseed, PKseed, a)
	if err != nil {
		return nil, fmt.Errorf("WOTS_sign failed: %w", err)
	}

	return &XMSSSignature{WotsSignature: sig, AUTH: AUTH}, nil
}

// Xmss_treeCache is a precomputed XMSS layer: all leaves plus the root.
type Xmss_treeCache struct {
	// Leaves holds 2^Hprime WOTS+ public keys, N bytes each. It is
	// unexported-by-convention inside this package: callers get a copy.
	leaves [][]byte
	root   []byte
}

// Root returns a copy of the layer's root.
func (c *Xmss_treeCache) Root() []byte {
	out := make([]byte, len(c.root))
	copy(out, c.root)
	return out
}

// Xmss_cacheLeaves builds the whole tree once and returns its leaves and root,
// so a caller that signs many messages under one key does not rebuild a tree
// whose contents never change.
//
// This is only valid for a tree that does not depend on the message — in
// practice the top hypertree layer, whose tree address is always 0. For a
// per-signature tree use Xmss_treeWithAuth instead.
func Xmss_cacheLeaves(params *parameters.Parameters, SKseed []byte, PKseed []byte,
	adrs *address.ADRS) (*Xmss_treeCache, error) {

	n := 1 << params.Hprime
	leaves := make([][]byte, n)

	if n >= parallelThreshold {
		var wg sync.WaitGroup
		errs := make(chan error, n)
		sem := make(chan struct{}, runtime.GOMAXPROCS(0))
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				defer func() {
					if r := recover(); r != nil {
						errs <- fmt.Errorf("panic computing leaf %d: %v", i, r)
					}
				}()
				v, err := leafNode(params, SKseed, PKseed, adrs, i)
				if err != nil {
					errs <- err
					return
				}
				leaves[i] = v
			}(i)
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			return nil, e
		}
	} else {
		for i := 0; i < n; i++ {
			v, err := leafNode(params, SKseed, PKseed, adrs, i)
			if err != nil {
				return nil, err
			}
			leaves[i] = v
		}
	}

	// Fold to the root, then drop the intermediate levels: only the leaves and
	// the root are kept, which is what the caller needs (an auth path can be
	// derived from the leaves without re-folding).
	level := leaves
	for h := 1; h <= params.Hprime; h++ {
		next := make([][]byte, len(level)/2)
		for j := range next {
			a := adrs.Copy()
			a.SetType(address.TREE)
			a.SetTreeHeight(h)
			a.SetTreeIndex(j)
			combined := make([]byte, 0, 2*params.N)
			combined = append(combined, level[2*j]...)
			combined = append(combined, level[2*j+1]...)
			next[j] = params.Tweak.H(PKseed, a, combined)
		}
		level = next
	}

	return &Xmss_treeCache{leaves: leaves, root: level[0]}, nil
}

// AuthPathFromLeaves folds the cached leaves into the authentication path for
// leafIdx. It is the same walk buildTree performs, so the AUTH bytes are
// identical to the ones a full build would have produced.
func (c *Xmss_treeCache) AuthPathFromLeaves(params *parameters.Parameters,
	PKseed []byte, adrs *address.ADRS, leafIdx int) []byte {

	level := make([][]byte, len(c.leaves))
	copy(level, c.leaves)
	auth := make([]byte, params.Hprime*params.N)
	for h := 1; h <= params.Hprime; h++ {
		sib := (leafIdx >> (h - 1)) ^ 1
		copy(auth[(h-1)*params.N:], level[sib])
		next := make([][]byte, len(level)/2)
		for j := range next {
			a := adrs.Copy()
			a.SetType(address.TREE)
			a.SetTreeHeight(h)
			a.SetTreeIndex(j)
			combined := make([]byte, 0, 2*params.N)
			combined = append(combined, level[2*j]...)
			combined = append(combined, level[2*j+1]...)
			next[j] = params.Tweak.H(PKseed, a, combined)
		}
		level = next
	}
	return auth
}

// Xmss_treeWithAuth builds the full XMSS tree rooted at the given address and
// returns BOTH the root and the authentication path for leaf leafIdx.
//
// The root used to be recovered afterwards by the caller with
// Xmss_pkFromSig, which re-ran the entire WOTS+ chain reconstruction
// (Len chains x W-1 F calls) plus the full auth-path fold — duplicating work
// the tree build had already done. Returning the root the build produced
// removes that second pass entirely.
//
// Neither output changes: this is the same tree, built by the same H() calls
// at the same absolute TreeHeight/TreeIndex addresses as treehash. The
// caller's adrs is not modified (buildTree works from copies), which matters
// because Ht_sign reuses one address struct across layers.
//
// This is the primitive Ht_sign fans out over: a tree depends only on
// (SKseed, PKseed, the ADRS) and the leaf index, never on the message.
func Xmss_treeWithAuth(params *parameters.Parameters, SKseed []byte, PKseed []byte,
	adrs *address.ADRS, leafIdx int) (root, auth []byte, err error) {

	maxLeaves := 1 << params.Hprime
	if leafIdx < 0 || leafIdx >= maxLeaves {
		return nil, nil, fmt.Errorf("leafIdx %d out of range [0, %d)", leafIdx, maxLeaves)
	}
	return buildTree(params, SKseed, PKseed, adrs, leafIdx)
}

// Xmss_signWithAuthPath signs M at leaf idx reusing an auth path that was
// already produced by Xmss_treeWithAuth.
//
// Splitting the tree build from the WOTS+ signing is what lets Ht_sign build
// all D layer trees concurrently and then sign them in order, without
// rebuilding any tree.
func Xmss_signWithAuthPath(params *parameters.Parameters, M []byte, SKseed []byte, idx int,
	PKseed []byte, adrs *address.ADRS, AUTH []byte) (*XMSSSignature, error) {

	maxLeaves := 1 << params.Hprime
	if idx < 0 || idx >= maxLeaves {
		return nil, fmt.Errorf("idx %d out of range [0, %d)", idx, maxLeaves)
	}
	if len(AUTH) != params.Hprime*params.N {
		return nil, fmt.Errorf("invalid AUTH length: expected %d, got %d", params.Hprime*params.N, len(AUTH))
	}

	a := adrs.Copy()
	a.SetType(address.WOTS_HASH)
	a.SetKeyPairAddress(idx)

	sig, err := wots.Wots_sign(params, M, SKseed, PKseed, a)
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
