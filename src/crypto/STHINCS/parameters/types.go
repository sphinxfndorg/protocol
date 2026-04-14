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
package parameters

import "github.com/sphinxorg/protocol/src/crypto/STHINCS/tweakable"

// Parameters contains all SPHINCS+ configuration parameters for a specific security level
type Parameters struct {
	// N: Length of hash outputs in bytes (16, 24, or 32)
	// Security level (post-quantum) = N*4 bits, but limited to N*2 due to Grover's algorithm
	// N=32 -> 128-bit post-quantum, N=24 -> 192-bit post-quantum, N=16 -> 64-bit post-quantum
	N int

	// W: Winternitz parameter for WOTS+ signatures
	// Must be power of 2: 4, 16, 256, etc.
	// Trade-off: Larger W = shorter signatures but more computation
	// W=16 is standard (4 bits per chain step)
	W int

	// Hprime: Height of each XMSS tree in the hypertree
	// Hprime = H / D (must be integer)
	// Each tree has 2^Hprime leaves (WOTS+ key pairs)
	Hprime int

	// H: Total height of hypertree (2^H = maximum signatures)
	// H=30 for these sets (2^30 ≈ 1.07 billion signatures)
	H int

	// D: Number of layers in hypertree (must divide H evenly)
	// Fast variant: D=6 (H'=5), Slow variant: D=3 (H'=10)
	D int

	// K: Number of FORS trees (Forest of Random Subsets)
	// Each signature reveals K leaf nodes (one per tree)
	// Larger K = more security but larger signatures
	K int

	// T: Number of leaves per FORS tree (T = 2^LogT)
	T int

	// LogT: Base-2 logarithm of T (FORS tree height)
	// Each FORS tree has 2^LogT leaves
	LogT int

	// A: Alias for LogT (FORS tree height) - maintained for backward compatibility
	A int

	// RANDOMIZE: Enable randomized signing
	// Randomized: Uses OptRand for PRFmsg (stronger security proof)
	// Deterministic: Simpler, still secure (standard SPHINCS+)
	RANDOMIZE bool

	// Tweak: Tweakable hash function implementation
	// Provides domain-separated hash functions (F, H, T_l, PRF, etc.)
	// Security relies on this hash function's properties
	Tweak tweakable.TweakableHashFunction

	// Len1: Number of WOTS+ chains for message encoding
	// Formula: ceil(8*N / log2(W))
	// Each chain encodes log2(W) bits of message digest
	Len1 int

	// Len2: Number of WOTS+ chains for checksum
	// Formula: floor(log2(Len1*(W-1))/log2(W)) + 1
	// Checksum prevents forgery by message modification
	Len2 int

	// Len: Total WOTS+ chain length (Len = Len1 + Len2)
	// WOTS+ signature size contribution: Len * N bytes
	Len int
}
