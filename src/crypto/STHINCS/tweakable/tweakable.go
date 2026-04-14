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

// go/src/crypto/STHINCS/address/tweakable.go
package tweakable

import "github.com/sphinxorg/protocol/src/crypto/STHINCS/address"

// Package tweakable defines the tweakable hash function interface for SPHINCS+
//
// Tweakable hash functions are a key innovation in SPHINCS+ that provide
// domain separation without needing separate hash functions for each purpose.
//
// Mathematical concept:
// A tweakable hash function H_tweak(t, x) behaves like a family of hash functions
// indexed by a tweak t. In SPHINCS+, the tweak is the ADRS (32-byte address)
// which encodes the context (layer, tree, type, etc.).
//
// Benefits:
// 1. Domain separation: Different contexts use different "tweaks"
// 2. Security reduction: Can prove security using indifferentiability
// 3. Efficiency: Single hash function with context parameter
//
// The interface provides 6 specific tweakable functions required by SPHINCS+:
// - Hmsg:  Message hashing (with randomization)
// - PRF:   Pseudorandom function (keyed)
// - PRFmsg: Message-specific pseudorandom function
// - F:     Tweakable hash for compression (WOTS+ chains, FORS leaves)
// - H:     Tweakable hash for Merkle tree internal nodes
// - T_l:   Tweakable hash for final compression (last layer)

// Variant constants determine the security/performance trade-off
const (
	// Simple variant: Direct hashing without XOR masking
	// - Faster (no bitmask generation)
	// - Simpler implementation
	// - Still considered secure (used in many implementations)
	Simple = "simple"

	// Robust variant: XOR with pseudorandom bitmask before hashing
	// - Provably secure in the standard model
	// - Slower (needs bitmask generation)
	// - Recommended for maximum security guarantees
	Robust = "robust"
)

// TweakableHashFunction defines the interface for all hash function variants
//
// Each method takes an ADRS (address) as a tweak to ensure domain separation.
// The address is serialized to bytes and included in the hash input (or used
// to generate a bitmask in robust mode).
//
// Security property: For any two distinct (function, address) pairs,
// the outputs should be indistinguishable from random independent functions.
type TweakableHashFunction interface {
	// Hmsg generates a message digest for signing
	//
	// Inputs:
	//   R:     Randomizer (optional, for randomized signing)
	//   PKseed: Public seed (part of public key)
	//   PKroot: Root of hypertree (public key)
	//   M:      Original message to sign
	//
	// Output: Message digest of length MessageDigestLength bytes
	//
	// Mathematical definition:
	//   Hmsg(R, PKseed, PKroot, M) = Hash(R || PKseed || PKroot || M)
	// Or for robust variant: includes additional randomization
	//
	// Usage: Called once per signature to create message digest
	Hmsg(R []byte, PKseed []byte, PKroot, M []byte) []byte

	// PRF generates pseudorandom values from a seed and address
	// Used to derive secret keys for WOTS+ and FORS leaves
	//
	// Inputs:
	//   SEED: Secret seed (from private key)
	//   adrs: Address identifying the specific leaf/key
	//
	// Output: N-byte pseudorandom value
	//
	// Mathematical definition:
	//   PRF(SEED, adrs) = Hash(SEED || ADRS_bytes)
	//
	// Security: Should be a pseudorandom function family
	// Usage: Called 2^H times total over lifetime (but computed on-demand)
	PRF(SEED []byte, adrs *address.ADRS) []byte

	// PRFmsg generates message-specific pseudorandom values
	// Used to derive randomization for each signature
	//
	// Inputs:
	//   SKprf:   Secret key for PRF (part of private key)
	//   OptRand: Optional randomizer (if RANDOMIZE=true)
	//   M:       Message to sign
	//
	// Output: N-byte pseudorandom value
	//
	// Mathematical definition:
	//   If RANDOMIZE: PRFmsg(SKprf, OptRand, M) = HMAC(SKprf, OptRand || M)
	//   Else: PRFmsg(SKprf, M) = HMAC(SKprf, M)
	//
	// Usage: Called once per signature
	PRFmsg(SKprf []byte, OptRand []byte, M []byte) []byte

	// F is a tweakable hash function for compression
	// Used in:
	// - WOTS+ chain compression (F)
	// - FORS leaf computation
	// - XMSS leaf compression
	//
	// Inputs:
	//   PKseed: Public seed (from public key)
	//   adrs:   Address tweak
	//   tmp:    Input to compress (typically N bytes, sometimes more)
	//
	// Output: N-byte compressed value
	//
	// Mathematical definition:
	//   Simple variant: F(PKseed, adrs, tmp) = Hash(PKseed || ADRS || tmp)
	//   Robust variant: F(PKseed, adrs, tmp) = Hash(PKseed || ADRS || (tmp XOR bitmask))
	//   where bitmask = Hash(PKseed || ADRS || 0x00...)
	//
	// Security: Must be collision-resistant and one-way
	// Usage: Called many times (O(2^H) total over lifetime)
	F(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte

	// H is a tweakable hash function for Merkle tree internal nodes
	// Similar to F but used specifically for combining two child nodes
	//
	// Inputs:
	//   PKseed: Public seed (from public key)
	//   adrs:   Address tweak
	//   tmp:    Concatenation of two N-byte child nodes (2N bytes)
	//
	// Output: N-byte parent node value
	//
	// Mathematical definition:
	//   Simple: H(PKseed, adrs, left||right) = Hash(PKseed || ADRS || left || right)
	//   Robust: H(PKseed, adrs, left||right) = Hash(PKseed || ADRS || (left||right XOR bitmask))
	//
	// Usage: Called O(2^H) times during tree building
	H(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte

	// T_l is the final tweakable hash (last layer compression)
	// Used to compress the concatenation of k FORS roots into a single N-byte value
	// Also used in other final compression steps
	//
	// Inputs:
	//   PKseed: Public seed (from public key)
	//   adrs:   Address tweak
	//   tmp:    Concatenation of multiple N-byte values (k*N bytes for FORS)
	//
	// Output: N-byte compressed value
	//
	// Mathematical definition:
	//   Same as H but for arbitrary-length input (not just 2N bytes)
	//   T_l(PKseed, adrs, X) = Hash(PKseed || ADRS || X)
	//
	// Security: Must be collision-resistant and preimage-resistant
	// Usage: Called O(D + k) times per signature
	T_l(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte
}
