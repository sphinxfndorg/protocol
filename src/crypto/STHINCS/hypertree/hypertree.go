// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/address/hypertree.go
package hypertree

import (
	"crypto/subtle"
	"fmt"
	"sync"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/address"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/xmss"
)

// Package hypertree implements the hypertree (XMSST) structure for STHINCS
//
// Mathematical concept: A hypertree is a tree of trees
// Instead of one giant Merkle tree of height H (which would be huge),
// we use D layers of smaller XMSS trees, each of height H/D
//
// Structure:
// Layer 0 (bottom): 2^(H*(D-1)/D) XMSS trees, each height H/D
// Layer 1: 2^(H*(D-2)/D) XMSS trees, each height H/D
// ...
// Layer D-1 (top): 1 XMSS tree of height H/D
//
// Each node in layer i is the root of an XMSS tree in layer i-1
// This creates a hypertree of total height H = D * (H/D)
//
// Advantages:
// - Smaller signature size (store only H/D auth paths instead of H)
// - Faster signing/verification (build smaller trees)
// - Supports up to 2^H signatures total (H = 24 for reduced version)

// HTSignature represents a hypertree signature
// Contains D XMSS signatures (one per layer)
//
// Structure:
// - Signature[0]: XMSS signature from bottom layer (authenticates the message)
// - Signature[1]: XMSS signature from layer 1 (authenticates root of layer 0)
// - ...
// - Signature[D-1]: XMSS signature from top layer (authenticates root of layer D-2)
//
// Total signature size: D * (XMSS signature size)
// For D=4-6 and XMSS signature ~1KB, total ~4-6KB
type HTSignature struct {
	XMSSSignatures []*xmss.XMSSSignature
}

// GetXMSSSignature returns the XMSS signature at given index
func (s *HTSignature) GetXMSSSignature(index int) *xmss.XMSSSignature {
	if index < 0 || index >= len(s.XMSSSignatures) {
		return nil
	}
	return s.XMSSSignatures[index]
}

// Ht_PKgen generates the hypertree public key
// The public key is simply the root of the top-layer XMSS tree
//
// Mathematical process:
// 1. Start at top layer (layer D-1)
// 2. Generate XMSS tree with 2^(H/D) leaves
// 3. The root of this tree is the overall public key
//
// Note: Lower layers are generated on-demand during signing
// This is possible because XMSS key generation only needs the seed
// and can deterministically generate any leaf when needed
//
// Fixed: Returns error
func Ht_PKgen(params *parameters.Parameters, SKseed []byte, PKseed []byte) ([]byte, error) {
	// Validate inputs
	if params == nil || SKseed == nil || PKseed == nil {
		return nil, fmt.Errorf("nil parameters provided")
	}

	// Create address for top-layer XMSS tree
	// Layer address = D-1 (top layer)
	// Tree address = 0 (only one tree at top layer)
	adrs := new(address.ADRS)
	adrs.SetLayerAddress(params.D - 1)
	adrs.SetTreeAddress(0)

	// Generate root of top-layer XMSS tree
	// This becomes the public key
	root, err := xmss.Xmss_PKgen(params, SKseed, PKseed, adrs)
	if err != nil {
		return nil, fmt.Errorf("XMSS PKgen failed for top layer: %w", err)
	}
	return root, nil
}

// Ht_sign generates a hypertree signature for message M
//
// Signing process (bottom-up):
//
// Let idx_tree be the tree index (0 to 2^(H - H/D) - 1)
// Let idx_leaf be the leaf index within the bottom tree (0 to 2^(H/D) - 1)
// The signature index = idx_tree * 2^(H/D) + idx_leaf
//
// For layer 0 (bottom):
//   - Sign message M using XMSS at leaf idx_leaf, tree idx_tree
//   - Get signature SIG_0 and compute root_0 = XMSS_pkFromSig(...)
//
// For layer 1:
//   - Sign root_0 (the authenticated root from layer 0)
//   - Use leaf idx_leaf' = idx_tree mod 2^(H/D)
//   - Use tree idx_tree' = idx_tree >> (H/D)
//   - Get signature SIG_1 and compute root_1 = XMSS_pkFromSig(...)
//
// Continue until top layer (D-1)
// Final signature = [SIG_0, SIG_1, ..., SIG_{D-1}]
//
// This creates a chain of authentication:
//
//	SIG_{D-1} authenticates root_{D-2}
//	SIG_{D-2} authenticates root_{D-3}
//	...
//	SIG_0 authenticates the message M
//	All roots are deterministically derived from the seeds
//
// Fixed: Returns error
func Ht_sign(params *parameters.Parameters, M []byte, SKseed []byte, PKseed []byte, idx_tree uint64, idx_leaf int) (*HTSignature, error) {
	return Ht_signCached(params, M, SKseed, PKseed, idx_tree, idx_leaf, nil)
}

// Ht_signCached is Ht_sign with an optional precomputed top layer.
//
// topCache, when non-nil, must be the layer-(D-1), tree-0 tree for this key.
// That layer is the one whose contents never vary per signature, so reusing it
// removes 1/D of the tree-building work (1/3 for the `s` sets, which have D=3).
// Pass nil to build every layer, which is what a caller with no cache does.
//
// The produced signature is byte-identical either way: the cached tree is the
// same tree, and AuthPathFromLeaves performs the same fold a full build does.
func Ht_signCached(params *parameters.Parameters, M []byte, SKseed []byte, PKseed []byte,
	idx_tree uint64, idx_leaf int, topCache *xmss.Xmss_treeCache) (*HTSignature, error) {
	// Validate inputs
	if params == nil || M == nil || SKseed == nil || PKseed == nil {
		return nil, fmt.Errorf("nil parameters provided")
	}

	// Resolve every layer's (tree, leaf) index up front. Each layer signs the
	// root of the layer below it, so the SIGNS are sequential — but the TREES
	// they authenticate are not: layer j's tree is fully determined by
	// (SKseed, PKseed, layer address, tree address), none of which depends on
	// the message or on any other layer. So all D trees can be built in
	// parallel, and only the cheap WOTS+ signing is left sequential.
	//
	// hPrime is the per-layer tree height: H/D. (params.Hprime is the same
	// value; the local name matches the index arithmetic below.)
	hPrime := params.H / params.D
	layers := make([]struct {
		leaf int
		tree uint64
	}, params.D)

	// Layer 0 authenticates the message itself and is the only one whose tree
	// index is not a shifted copy of idx_tree.
	layers[0] = struct {
		leaf int
		tree uint64
	}{idx_leaf, idx_tree}

	curTree := idx_tree
	for j := 1; j < params.D; j++ {
		leaf := int(curTree % (1 << uint64(hPrime)))
		curTree = curTree >> hPrime
		layers[j] = struct {
			leaf int
			tree uint64
		}{leaf, curTree}
	}

	// Pass 1 (parallel): build every layer's tree once, keeping the root and
	// the auth path. This is the expensive part — 2^Hprime WOTS+ keygens per
	// layer — and the layers are mutually independent.
	//
	// The top layer is skipped when a cache was supplied: its leaves and root
	// are already known, and only the auth path (which depends on this
	// signature's leaf index) has to be folded out of the cached leaves.
	top := params.D - 1
	roots := make([][]byte, params.D)
	auths := make([][]byte, params.D)
	if err := buildLayerTrees(params, SKseed, PKseed, layers, roots, auths, top, topCache); err != nil {
		return nil, err
	}

	// Pass 2 (sequential): WOTS+ signing. Layer 0 signs the message; layer j
	// signs the root of layer j-1, so this chain must stay in order.
	//
	// The root of the top layer is never consumed — it is the public key —
	// but it is built anyway, because the top layer's auth path needs the
	// whole tree.
	SIG_HT := make([]*xmss.XMSSSignature, 0, params.D)
	msg := M
	for j := 0; j < params.D; j++ {
		adrs := new(address.ADRS)
		adrs.SetLayerAddress(j)
		adrs.SetTreeAddress(layers[j].tree)

		sig, err := xmss.Xmss_signWithAuthPath(params, msg, SKseed, layers[j].leaf, PKseed, adrs, auths[j])
		if err != nil {
			return nil, fmt.Errorf("XMSS sign failed for layer %d: %w", j, err)
		}
		SIG_HT = append(SIG_HT, sig)
		msg = roots[j]
	}

	return &HTSignature{XMSSSignatures: SIG_HT}, nil
}

// buildLayerTrees builds every hypertree layer's tree in parallel and stores
// the root and auth path for the layer's signing leaf.
//
// The ADRS passed in is per-layer and private, so no layer can observe
// another's address state. Roots and auth paths are only written to their
// slots after that layer's work completes, and the caller waits for all
// workers, so the result is independent of scheduling.
//
// Layer topLayer is served from topCache when one is supplied (see
// Ht_signCached); otherwise it is built like any other layer.
func buildLayerTrees(params *parameters.Parameters, SKseed, PKseed []byte,
	layers []struct {
		leaf int
		tree uint64
	}, roots, auths [][]byte, topLayer int, topCache *xmss.Xmss_treeCache) error {

	var wg sync.WaitGroup
	errs := make(chan error, len(layers))
	for j := range layers {
		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					errs <- fmt.Errorf("panic building layer %d: %v", j, r)
				}
			}()
			adrs := new(address.ADRS)
			adrs.SetLayerAddress(j)
			adrs.SetTreeAddress(layers[j].tree)

			if j == topLayer && topCache != nil {
				// The cached tree was built at this same layer/tree address, so
				// its root and the auth path folded from its leaves are the same
				// values a fresh build would produce.
				roots[j] = topCache.Root()
				auths[j] = topCache.AuthPathFromLeaves(params, PKseed, adrs, layers[j].leaf)
				return
			}

			// A tree depends only on the seeds, the address and the leaf
			// index — never on the message — so this needs nothing from the
			// layer below and the D builds are mutually independent.
			root, auth, err := xmss.Xmss_treeWithAuth(params, SKseed, PKseed, adrs, layers[j].leaf)
			if err != nil {
				errs <- fmt.Errorf("tree build failed for layer %d: %w", j, err)
				return
			}
			roots[j] = root
			auths[j] = auth
		}(j)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		return e
	}
	return nil
}

// Ht_verify verifies a hypertree signature
//
// Verification process (top-down):
// 1. Start with the message M and the bottom-layer signature SIG_0
// 2. Reconstruct root_0 from SIG_0 and M
// 3. For layer 1 to D-1:
//   - Reconstruct root_j from SIG_j and root_{j-1}
//
// 4. After processing all layers, we have root_{D-1}
// 5. Compare root_{D-1} with the public key PK_HT
//
// If all reconstructed roots match, the signature is valid
// This works because:
// - Only the correct leaf values produce the correct roots
// - The authentication paths prove leaf membership in their trees
// - The chaining ensures consistency across all layers
//
// Fixed: Returns error, handles XMSS_pkFromSig errors
func Ht_verify(params *parameters.Parameters, M []byte, SIG_HT *HTSignature, PKseed []byte, idx_tree uint64, idx_leaf int, PK_HT []byte) (bool, error) {
	// Validate inputs
	if params == nil || M == nil || SIG_HT == nil || PKseed == nil || PK_HT == nil {
		return false, fmt.Errorf("nil parameters provided")
	}

	if len(SIG_HT.XMSSSignatures) != params.D {
		return false, fmt.Errorf("invalid signature count: expected %d, got %d", params.D, len(SIG_HT.XMSSSignatures))
	}

	// Initialize address structure
	adrs := new(address.ADRS)

	// Verify layer 0 (bottom) - reconstruct root from message
	SIG_tmp := SIG_HT.GetXMSSSignature(0)
	if SIG_tmp == nil {
		return false, fmt.Errorf("nil XMSS signature at layer 0")
	}

	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idx_tree)

	node, err := xmss.Xmss_pkFromSig(params, idx_leaf, SIG_tmp, M, PKseed, adrs)
	if err != nil {
		return false, fmt.Errorf("XMSS pkFromSig failed for layer 0: %w", err)
	}

	// Verify higher layers (1 to D-1)
	// Each layer verifies that the previous layer's root is authentic
	current_idx_tree := idx_tree
	current_idx_leaf := idx_leaf

	for j := 1; j < params.D; j++ {
		// Extract leaf index for this layer (same as during signing)
		current_idx_leaf = int(current_idx_tree % (1 << uint64(params.H/params.D)))

		// Extract tree index for this layer
		current_idx_tree = current_idx_tree >> (params.H / params.D)

		// Verify signature at this layer
		SIG_tmp = SIG_HT.GetXMSSSignature(j)
		if SIG_tmp == nil {
			return false, fmt.Errorf("nil XMSS signature at layer %d", j)
		}

		adrs.SetLayerAddress(j)
		adrs.SetTreeAddress(current_idx_tree)

		node, err = xmss.Xmss_pkFromSig(params, current_idx_leaf, SIG_tmp, node, PKseed, adrs)
		if err != nil {
			return false, fmt.Errorf("XMSS pkFromSig failed for layer %d: %w", j, err)
		}
	}

	// After verifying all layers, node should be the top root
	// Compare with public key to confirm validity using constant-time comparison
	return subtle.ConstantTimeCompare(node, PK_HT) == 1, nil
}
