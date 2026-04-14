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

// go/src/crypto/STHINCS/address/hypertree.go
package hypertree

import (
	"crypto/subtle"
	"fmt"

	"github.com/sphinxorg/protocol/src/crypto/STHINCS/address"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/xmss"
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
	// Validate inputs
	if params == nil || M == nil || SKseed == nil || PKseed == nil {
		return nil, fmt.Errorf("nil parameters provided")
	}

	// Initialize address structure
	adrs := new(address.ADRS)

	// Layer 0: Sign the actual message
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idx_tree)

	SIG_tmp, err := xmss.Xmss_sign(params, M, SKseed, idx_leaf, PKseed, adrs)
	if err != nil {
		return nil, fmt.Errorf("XMSS sign failed for layer 0: %w", err)
	}

	SIG_HT := make([]*xmss.XMSSSignature, 0)
	SIG_HT = append(SIG_HT, SIG_tmp)

	// Compute root of layer 0 tree from signature
	// This root will be signed by layer 1
	root, err := xmss.Xmss_pkFromSig(params, idx_leaf, SIG_tmp, M, PKseed, adrs)
	if err != nil {
		return nil, fmt.Errorf("XMSS pkFromSig failed for layer 0: %w", err)
	}

	// Process higher layers (1 to D-1)
	current_idx_tree := idx_tree
	current_idx_leaf := idx_leaf

	for j := 1; j < params.D; j++ {
		// Extract leaf index for this layer
		// Leaf index = least significant (H/D) bits of idx_tree
		// This works because each layer compresses the tree index by factor 2^(H/D)
		current_idx_leaf = int(current_idx_tree % (1 << uint64(params.H/params.D)))

		// Extract tree index for this layer
		// Tree index = most significant bits after shifting right by (H/D)
		current_idx_tree = current_idx_tree >> (params.H / params.D)

		// Sign the root from previous layer
		adrs.SetLayerAddress(j)
		adrs.SetTreeAddress(current_idx_tree)

		SIG_tmp, err = xmss.Xmss_sign(params, root, SKseed, current_idx_leaf, PKseed, adrs)
		if err != nil {
			return nil, fmt.Errorf("XMSS sign failed for layer %d: %w", j, err)
		}
		SIG_HT = append(SIG_HT, SIG_tmp)

		// Compute root of this layer (for next layer, except at top)
		if j < params.D-1 {
			root, err = xmss.Xmss_pkFromSig(params, current_idx_leaf, SIG_tmp, root, PKseed, adrs)
			if err != nil {
				return nil, fmt.Errorf("XMSS pkFromSig failed for layer %d: %w", j, err)
			}
		}
	}

	return &HTSignature{XMSSSignatures: SIG_HT}, nil
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
