// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/address/address.go
package address

import (
	"encoding/binary"
	"fmt"

	"github.com/sphinxorg/protocol/src/crypto/STHINCS/util"
)

// Package address implements the ADRS (Address) structure for STHINCS
// STHINCS uses a hierarchical addressing scheme to domain-separate different
// hash function calls. Each hash function invocation receives a unique 32-byte
// address that encodes the context (layer, tree, type, etc.) to prevent
// interactions between different parts of the scheme.

// ADRS type constants defining the context of hash function calls
// These values are placed in bytes 16-19 of the 32-byte address
const (
	// WOTS_HASH = 0: Hashing within WOTS+ chain (iterative hash computations)
	WOTS_HASH = 0

	// WOTS_PK = 1: Computing WOTS+ public key from the chain (L-tuple compression)
	WOTS_PK = 1

	// TREE = 2: Building Merkle tree nodes (internal hash computations)
	TREE = 2

	// FORS_TREE = 3: Building FORS (Forest of Random Subsets) Merkle trees
	// FORS is a few-time signature scheme used as the first layer
	FORS_TREE = 3

	// FORS_ROOTS = 4: Combining FORS tree roots into a single root value
	FORS_ROOTS = 4
)

// ADRS (Address) structure - 32 bytes total
// The addressing scheme ensures each hash function call in STHINCS is unique
//
// Layout (32 bytes total):
// [0-3]   LayerAddress: Which layer in the hypertree (0 = bottom, D-1 = top)
// [4-15]  TreeAddress: Which tree within the layer (supports up to 2^96 trees)
// [16-19] Type: Context of hash call (0-4 as defined above)
// [20-23] KeyPairAddress: Which key pair within the tree (for WOTS+/FORS)
// [24-27] ChainAddress: Which chain within WOTS+ (0 to len-1)
// [28-31] HashAddress: Which step within the WOTS+ chain (0 to w-1)
// Note: Fields beyond byte 19 are reused based on Type (union-like structure)
type ADRS struct {
	// LayerAddress: 0 = bottom layer (signing), D-1 = top layer (root)
	// In a hypertree of height H with D layers, each layer has height H/D
	LayerAddress [4]byte

	// TreeAddress: Identifies which tree at this layer
	// For layer 0: index of the FORS tree being used
	// For layer i: index of the subtree in the hypertree
	TreeAddress [12]byte

	// Type: Determines how the remaining fields are interpreted
	// Acts as a discriminator for the union of fields below
	Type [4]byte

	// KeyPairAddress: Identifies which WOTS+ key pair or FORS tree
	// Within a Merkle tree, each leaf corresponds to a key pair
	KeyPairAddress [4]byte

	// TreeHeight: Current height in Merkle tree (0 = leaf, A = root)
	// Used when building or traversing the authentication path
	TreeHeight [4]byte

	// TreeIndex: Position of node within its level of the Merkle tree
	// Range: 0 to (2^height - 1) for given height level
	TreeIndex [4]byte

	// ChainAddress: Which WOTS+ chain (0 to len1+len2-1)
	// WOTS+ uses multiple independent chains for message encoding
	ChainAddress [4]byte

	// HashAddress: Which step within a WOTS+ chain (0 to w-1)
	// Each chain has w-1 iterations of the hash function
	HashAddress [4]byte
}

// Copy creates a deep copy of the ADRS structure
// Needed because ADRS is frequently modified during tree traversal
// while original addresses must be preserved for later use
func (adrs *ADRS) Copy() *ADRS {
	newADRS := new(ADRS)
	newADRS.LayerAddress = adrs.LayerAddress
	newADRS.TreeAddress = adrs.TreeAddress
	newADRS.Type = adrs.Type
	newADRS.KeyPairAddress = adrs.KeyPairAddress
	newADRS.TreeHeight = adrs.TreeHeight
	newADRS.TreeIndex = adrs.TreeIndex
	newADRS.ChainAddress = adrs.ChainAddress
	newADRS.HashAddress = adrs.HashAddress
	return newADRS
}

// GetBytes serializes the ADRS structure into a 32-byte slice
// This follows the SPHINCS+ specification (Section 2.7.3)
//
// The encoding is as follows:
// - Bytes 0-3:   Layer address (big-endian)
// - Bytes 4-15:  Tree address (big-endian)
// - Bytes 16-19: Type (big-endian)
// - Bytes 20-31: Context-specific fields (based on Type)
//
// Mathematical principle: Domain separation ensures that:
// Pr[Hash(x||ADRS1) = Hash(y||ADRS2)] = Pr[Hash collision] when ADRS1 ≠ ADRS2
// This prevents cross-context attacks where outputs from one part of the scheme
// could be misused in another context.
func (adrs *ADRS) GetBytes() []byte {
	typ := adrs.GetType()
	if typ < 0 || typ > 4 {
		// Return a default or panic
		panic(fmt.Sprintf("invalid ADRS type: %d", typ))
	}
	ADRSc := make([]byte, 32)

	// Copy the fixed header (always present regardless of type)
	copy(ADRSc[0:4], adrs.LayerAddress[:]) // Layer in hypertree
	copy(ADRSc[4:16], adrs.TreeAddress[:]) // Tree identifier
	copy(ADRSc[16:20], adrs.Type[:])       // Context discriminator

	// Based on Type, encode different payloads in bytes 20-31
	// This is a union structure - the same bytes have different meanings
	// depending on the context of the hash call
	switch adrs.GetType() {

	case WOTS_HASH:
		// Type 0: Hashing within WOTS+ chain
		// Bytes 20-23: Which WOTS+ key pair (leaf index in Merkle tree)
		// Bytes 24-27: Which chain within WOTS+ (0 to len-1)
		// Bytes 28-31: Which step in chain (0 to w-1)
		//
		// Math: For WOTS+ with length L and winternitz parameter w,
		// we need L * (w-1) distinct hash calls. This addressing ensures
		// each call gets a unique input domain.
		copy(ADRSc[20:24], adrs.KeyPairAddress[:])
		copy(ADRSc[24:28], adrs.ChainAddress[:])
		copy(ADRSc[28:32], adrs.HashAddress[:])

	case WOTS_PK:
		// Type 1: Computing WOTS+ public key from the chain ends
		// Bytes 20-23: Which WOTS+ key pair (leaf index in Merkle tree)
		//
		// Math: The WOTS+ public key is computed by compressing the L
		// chain ends (each of length N bytes) into a single N-byte value.
		// The address ensures this compression is domain-separated from
		// other hash operations.
		copy(ADRSc[20:24], adrs.KeyPairAddress[:])

	case TREE:
		// Type 2: Building Merkle tree nodes (internal hashes)
		// Bytes 24-27: Height in tree (0 = leaf, H' = root)
		// Bytes 28-31: Index at that height (0 to 2^height - 1)
		//
		// Math: A Merkle tree of height H' has 2^(H'+1)-1 nodes.
		// Each node is computed as: parent = Hash(left_child || right_child)
		// The address encodes (layer, tree, height, index) to uniquely
		// identify each node in the hypertree structure.
		copy(ADRSc[24:28], adrs.TreeHeight[:])
		copy(ADRSc[28:32], adrs.TreeIndex[:])

	case FORS_TREE:
		// Type 3: Building FORS (Forest of Random Subsets) Merkle trees
		// Bytes 20-23: Which FORS tree (0 to k-1, where k is number of trees)
		// Bytes 24-27: Height in FORS tree (0 = leaf, a = root)
		// Bytes 28-31: Index at that height
		//
		// Math: FORS uses k independent Merkle trees, each of height a.
		// Total leaves = k * 2^a. The address ensures each tree's nodes
		// are domain-separated from other trees and from the main hypertree.
		copy(ADRSc[20:24], adrs.KeyPairAddress[:])
		copy(ADRSc[24:28], adrs.TreeHeight[:])
		copy(ADRSc[28:32], adrs.TreeIndex[:])

	case FORS_ROOTS:
		// Type 4: Combining FORS tree roots into a single root
		// Bytes 20-23: Which key pair (identifies the FORS instance)
		//
		// Math: The k tree roots (each N bytes) are concatenated and hashed
		// to produce a single N-byte value that represents the entire FORS
		// structure. This value becomes a leaf in the bottom-layer Merkle tree.
		copy(ADRSc[20:24], adrs.KeyPairAddress[:])
	}

	return ADRSc
}

// SetLayerAddress sets the layer index (0 to D-1)
// Layer 0 = bottom layer (where signatures are generated)
// Layer D-1 = top layer (root of the hypertree)
//
// Mathematical meaning: The hypertree has D layers, each of height H/D.
// Total tree height H = D * (H/D). The layer address selects which
// level of this hierarchy we're operating on.
func (adrs *ADRS) SetLayerAddress(a int) {
	var layerAddress [4]byte
	copy(layerAddress[:], util.ToByte(uint64(a), 4))
	adrs.LayerAddress = layerAddress
}

// SetTreeAddress sets the tree identifier (up to 2^96 possible trees)
// This supports the 2^24 signature limit (reduced from 2^64 in standard STHINCS)
//
// Mathematical principle: Each signature uses a different tree index,
// allowing up to 2^96 signatures before tree address wraps around.
// For 2^24 limit, we only need 24 bits, but the structure supports more.
func (adrs *ADRS) SetTreeAddress(a uint64) {
	var treeAddress [12]byte
	treeAddressBytes := util.ToByte(a, 12)
	copy(treeAddress[:], treeAddressBytes)
	adrs.TreeAddress = treeAddress
}

// SetType sets the ADRS type and zeros out type-specific fields
// This follows the STHINCS specification requirement (Section 2.7.3)
// When type changes, fields that are not applicable must be set to 0
// to prevent accidental reuse of old values from previous types.
func (adrs *ADRS) SetType(a int) {
	var typ [4]byte
	copy(typ[:], util.ToByte(uint64(a), 4))
	adrs.Type = typ

	// Reset fields to 0 as required by specification
	// This is crucial for security: fields from previous type
	// must not "leak" into the new type's context
	adrs.SetKeyPairAddress(0)
	adrs.SetChainAddress(0)
	adrs.SetHashAddress(0)
	adrs.SetTreeHeight(0)
	adrs.SetTreeIndex(0)
}

// SetKeyPairAddress sets the key pair identifier
// For WOTS+: Which leaf in the Merkle tree (0 to 2^(H/D)-1)
// For FORS: Which FORS tree (0 to k-1)
//
// Mathematical: In a Merkle tree of height H', there are 2^H' leaves.
// Each leaf corresponds to a WOTS+ key pair or a FORS instance.
func (adrs *ADRS) SetKeyPairAddress(a int) {
	var keyPairAddress [4]byte
	copy(keyPairAddress[:], util.ToByte(uint64(a), 4))
	adrs.KeyPairAddress = keyPairAddress
}

// SetTreeHeight sets the height in the Merkle tree
// Height 0 = leaf node (the actual WOTS+ public key or FORS leaf)
// Height H' = root node (where H' is tree height)
//
// Mathematical: In a binary tree of height H', there are H'+1 levels.
// Level h (0-indexed from bottom) has 2^(H'-h) nodes.
// The height field identifies which level we're working on.
func (adrs *ADRS) SetTreeHeight(a int) {
	var treeHeight [4]byte
	copy(treeHeight[:], util.ToByte(uint64(a), 4))
	adrs.TreeHeight = treeHeight
}

// SetTreeIndex sets the node index at the current height
// At height h, indices range from 0 to 2^(H'-h)-1
//
// Mathematical: The tree is built such that:
// Node at (height h, index i) has children:
// - Left child: (height h-1, index 2*i)
// - Right child: (height h-1, index 2*i+1)
// This binary tree indexing is standard and efficient.
func (adrs *ADRS) SetTreeIndex(a int) {
	var treeIndex [4]byte
	copy(treeIndex[:], util.ToByte(uint64(a), 4))
	adrs.TreeIndex = treeIndex
}

// SetChainAddress sets which WOTS+ chain (0 to len-1)
// WOTS+ uses multiple chains to encode the message digest
//
// Mathematical: For WOTS+ with length L = len1 + len2:
// - len1 = ceil(8n / log2(w)) chains encode the message
// - len2 = floor(log2(len1*(w-1))/log2(w)) + 1 chains encode the checksum
// Total L independent chains, each producing one N-byte output.
func (adrs *ADRS) SetChainAddress(a int) {
	var chainAddress [4]byte
	copy(chainAddress[:], util.ToByte(uint64(a), 4))
	adrs.ChainAddress = chainAddress
}

// SetHashAddress sets which step within a WOTS+ chain (0 to w-1)
// Each chain has w-1 hash iterations to go from secret to public value
//
// Mathematical: For a chain starting at secret key sk, we compute:
// chain[0] = sk
// chain[i] = F(chain[i-1]) for i = 1 to w-1
// Public key = chain[w-1]
// The hash address distinguishes each iteration.
func (adrs *ADRS) SetHashAddress(a int) {
	var hashAddress [4]byte
	copy(hashAddress[:], util.ToByte(uint64(a), 4))
	adrs.HashAddress = hashAddress
}

// GetKeyPairAddress returns the key pair address as integer
func (adrs *ADRS) GetKeyPairAddress() int {
	keyPairAddressBytes := adrs.KeyPairAddress[:]
	keyPairAddressUint32 := binary.BigEndian.Uint32(keyPairAddressBytes)
	return int(keyPairAddressUint32)
}

// GetTreeIndex returns the tree index as integer
func (adrs *ADRS) GetTreeIndex() int {
	treeIndexBytes := adrs.TreeIndex[:]
	treeIndexUint32 := binary.BigEndian.Uint32(treeIndexBytes)
	return int(treeIndexUint32)
}

// GetTreeHeight returns the tree height as integer
func (adrs *ADRS) GetTreeHeight() int {
	treeHeightBytes := adrs.TreeHeight[:]
	treeHeightUint32 := binary.BigEndian.Uint32(treeHeightBytes)
	return int(treeHeightUint32)
}

// GetType returns the ADRS type as integer
func (adrs *ADRS) GetType() int {
	typeBytes := adrs.Type[:]
	typeUint32 := binary.BigEndian.Uint32(typeBytes)
	return int(typeUint32)
}

// GetTreeAddress returns the tree address as integer
func (adrs *ADRS) GetTreeAddress() int {
	treeAddressBytes := adrs.TreeAddress[:]
	treeAddressUint64 := binary.BigEndian.Uint64(treeAddressBytes)
	return int(treeAddressUint64)
}
