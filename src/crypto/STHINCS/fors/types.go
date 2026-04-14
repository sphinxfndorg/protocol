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
