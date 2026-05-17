// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/address/types.go
package fors

// FORSSignature represents a FORS (Forest of Random Subsets) signature
// FORS is a few-time signature scheme that forms the first layer of SPHINCS+
// Each signature contains k authentication paths (one per tree)
type FORSSignature struct {
	// Forspkauth: Array of k TreePKAUTH structures, one for each FORS tree
	// Each element contains a leaf value and its authentication path
	Forspkauth []*TreePKAUTH
}

// TreePKAUTH represents one tree's authentication path in FORS
// For a tree of height a (2^a leaves), we need a authentication nodes
// plus the leaf value itself to prove membership
type TreePKAUTH struct {
	// PrivateKeyValue: The actual leaf value (N bytes)
	// This is the secret that proves knowledge of the leaf
	PrivateKeyValue []byte

	// AUTH: Authentication path of length a * N bytes
	// Contains the sibling nodes needed to reconstruct the root
	AUTH []byte
}
