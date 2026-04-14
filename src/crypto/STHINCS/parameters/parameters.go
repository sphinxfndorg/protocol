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

// go/src/crypto/STHINCS/address/parameters.go
package parameters

import (
	"fmt"
	"math"

	"github.com/sphinxorg/protocol/src/crypto/STHINCS/tweakable"
)

// ============================================================================
// Package parameters implements STHINCS parameter set management
// ============================================================================
//
// STHINCSS is a stateless hash-based signature scheme that provides post-quantum security.
// Unlike stateful schemes (XMSS, LMS), STHINCS does not require tracking which signatures
// have been issued - the message digest itself determines which leaf index to use.

// ============================================================================
// SECURITY FOUNDATION
// ============================================================================
// The security of STHINCS ultimately relies on the UNDERLYING HASH FUNCTION,
// not on the parameter N alone. Even with N=32 (256-bit output), the security
// level is NOT 256 bits - it's limited by the best known attacks:
//
//   - Classical security: ~min(128, n/2) bits for collision resistance
//   - Post-quantum security: ~n/2 bits due to Grover's algorithm
//
// For SHA256 with N=32:
//   - Pre-quantum security: 128 bits (2^128 operations)
//   - Post-quantum security: 128 bits (Grover reduces to 2^128)
//
// Therefore, N=32 provides ~128-bit post-quantum security, not 256-bit.

// ============================================================================
// SIGNATURE CAPACITY: 2^30 (1,073,741,824 SIGNATURES)
// ============================================================================
//
// Standard STHINCS supports 2^64 signatures (overkill for most applications).
// This implementation uses H=30 for 2^30 signatures - a practical balance.
//
// SIGNATURE LIFETIME ANALYSIS:
//   At 1 signature/second   → 34 years
//   At 10 signatures/second  → 3.4 years
//   At 100 signatures/second → 124 days
//
// For blockchain nodes signing every 5 minutes:
//   105,120 signatures/year → 2^30 lasts ~10,220 years
//
// WARNING: These sets MUST NOT exceed 2^30 signatures per key!

// ============================================================================
// Security Level 1 (N=32 bytes, 128-bit post-quantum) - 2^30 variants
// ============================================================================

// MakeSthincsPlusSHA256256fRobust creates SHA256-robust, N=32, Fast variant (2^30 signatures)
// Fast variant: D=6 layers, Hprime=5 (32 leaves per XMSS tree)
// Optimization: More layers = smaller trees = faster signing
// Result: Larger signatures but faster operations
func MakeSthincsPlusSHA256256fRobust(RANDOMIZE bool) *Parameters {
	// H=30 (2^30 signatures), D=6, Hprime=30/6=5
	// K=35, logT=9 unchanged for security level 1
	return MakeSthincsPlus(32, 16, 30, 6, 35, 9, "SHA256-robust", RANDOMIZE)
}

// MakeSthincsPlusSHA256256sRobust creates SHA256-robust, N=32, Slow variant (2^30 signatures)
// Slow variant: D=3 layers, Hprime=10 (1024 leaves per XMSS tree)
// Optimization: Fewer layers = fewer auth paths = smaller signatures
// Result: Smaller signatures but slower signing
func MakeSthincsPlusSHA256256sRobust(RANDOMIZE bool) *Parameters {
	// H=30 (2^30 signatures), D=3, Hprime=30/3=10
	// K=20, logT=13 adjusted for slow variant
	return MakeSthincsPlus(32, 16, 30, 3, 20, 13, "SHA256-robust", RANDOMIZE)
}

// MakeSthincsPlusSHA256256fSimple creates SHA256-simple, N=32, Fast variant (2^30 signatures)
// Simple variant: No XOR bitmask - faster but weaker security proof
func MakeSthincsPlusSHA256256fSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(32, 16, 30, 6, 35, 9, "SHA256-simple", RANDOMIZE)
}

// MakeSthincsPlusSHA256256sSimple creates SHA256-simple, N=32, Slow variant (2^30 signatures)
func MakeSthincsPlusSHA256256sSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(32, 16, 30, 3, 20, 13, "SHA256-simple", RANDOMIZE)
}

// ============================================================================
// Security Level 3 (N=24 bytes, 192-bit post-quantum) - 2^30 variants
// ============================================================================

// MakeSthincsPlusSHA256192fRobust creates SHA256-robust, N=24, Fast variant (2^30 signatures)
func MakeSthincsPlusSHA256192fRobust(RANDOMIZE bool) *Parameters {
	// H=30, D=6, Hprime=5, K=33, logT=8
	return MakeSthincsPlus(24, 16, 30, 6, 33, 8, "SHA256-robust", RANDOMIZE)
}

// MakeSthincsPlusSHA256192sRobust creates SHA256-robust, N=24, Slow variant (2^30 signatures)
func MakeSthincsPlusSHA256192sRobust(RANDOMIZE bool) *Parameters {
	// H=30, D=3, Hprime=10, K=18, logT=12
	return MakeSthincsPlus(24, 16, 30, 3, 18, 12, "SHA256-robust", RANDOMIZE)
}

// MakeSthincsPlusSHA256192fSimple creates SHA256-simple, N=24, Fast variant (2^30 signatures)
func MakeSthincsPlusSHA256192fSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(24, 16, 30, 6, 33, 8, "SHA256-simple", RANDOMIZE)
}

// MakeSthincsPlusSHA256192sSimple creates SHA256-simple, N=24, Slow variant (2^30 signatures)
func MakeSthincsPlusSHA256192sSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(24, 16, 30, 3, 18, 12, "SHA256-simple", RANDOMIZE)
}

// ============================================================================
// Security Level 5 (N=16 bytes, LEGACY - 64-bit post-quantum) - 2^30 variants
// ============================================================================

// MakeSthincsPlusSHA256128fRobust creates SHA256-robust, N=16, Fast variant (2^30 signatures)
func MakeSthincsPlusSHA256128fRobust(RANDOMIZE bool) *Parameters {
	// H=30, D=6, Hprime=5, K=30, logT=6
	return MakeSthincsPlus(16, 16, 30, 6, 30, 6, "SHA256-robust", RANDOMIZE)
}

// MakeSthincsPlusSHA256128sRobust creates SHA256-robust, N=16, Slow variant (2^30 signatures)
func MakeSthincsPlusSHA256128sRobust(RANDOMIZE bool) *Parameters {
	// H=30, D=3, Hprime=10, K=14, logT=11
	return MakeSthincsPlus(16, 16, 30, 3, 14, 11, "SHA256-robust", RANDOMIZE)
}

// MakeSthincsPlusSHA256128fSimple creates SHA256-simple, N=16, Fast variant (2^30 signatures)
func MakeSthincsPlusSHA256128fSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(16, 16, 30, 6, 30, 6, "SHA256-simple", RANDOMIZE)
}

// MakeSthincsPlusSHA256128sSimple creates SHA256-simple, N=16, Slow variant (2^30 signatures)
func MakeSthincsPlusSHA256128sSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(16, 16, 30, 3, 14, 11, "SHA256-simple", RANDOMIZE)
}

// ============================================================================
// SHAKE256 Variants - 2^30 signatures (SHA-3 based, post-quantum secure)
// ============================================================================

// Security Level 1 (N=32)
func MakeSthincsPlusSHAKE256256fRobust(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(32, 16, 30, 6, 35, 9, "SHAKE256-robust", RANDOMIZE)
}
func MakeSthincsPlusSHAKE256256sRobust(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(32, 16, 30, 3, 20, 13, "SHAKE256-robust", RANDOMIZE)
}
func MakeSthincsPlusSHAKE256256fSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(32, 16, 30, 6, 35, 9, "SHAKE256-simple", RANDOMIZE)
}
func MakeSthincsPlusSHAKE256256sSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(32, 16, 30, 3, 20, 13, "SHAKE256-simple", RANDOMIZE)
}

// Security Level 3 (N=24)
func MakeSthincsPlusSHAKE256192fRobust(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(24, 16, 30, 6, 33, 8, "SHAKE256-robust", RANDOMIZE)
}
func MakeSthincsPlusSHAKE256192sRobust(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(24, 16, 30, 3, 18, 12, "SHAKE256-robust", RANDOMIZE)
}
func MakeSthincsPlusSHAKE256192fSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(24, 16, 30, 6, 33, 8, "SHAKE256-simple", RANDOMIZE)
}
func MakeSthincsPlusSHAKE256192sSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(24, 16, 30, 3, 18, 12, "SHAKE256-simple", RANDOMIZE)
}

// Security Level 5 (N=16)
func MakeSthincsPlusSHAKE256128fRobust(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(16, 16, 30, 6, 30, 6, "SHAKE256-robust", RANDOMIZE)
}
func MakeSthincsPlusSHAKE256128sRobust(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(16, 16, 30, 3, 14, 11, "SHAKE256-robust", RANDOMIZE)
}
func MakeSthincsPlusSHAKE256128fSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(16, 16, 30, 6, 30, 6, "SHAKE256-simple", RANDOMIZE)
}
func MakeSthincsPlusSHAKE256128sSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(16, 16, 30, 3, 14, 11, "SHAKE256-simple", RANDOMIZE)
}

// ============================================================================
// SPHINXHASH Variants - Custom hash function optimized for SPHINCS+
// ============================================================================

// Security Level 1 (N=32)
func MakeSthincsPlusSPHINXHASH256fRobust(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(32, 16, 30, 6, 35, 9, "SPHINXHASH-robust", RANDOMIZE)
}
func MakeSthincsPlusSPHINXHASH256sRobust(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(32, 16, 30, 3, 20, 13, "SPHINXHASH-robust", RANDOMIZE)
}
func MakeSthincsPlusSPHINXHASH256fSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(32, 16, 30, 6, 35, 9, "SPHINXHASH-simple", RANDOMIZE)
}
func MakeSthincsPlusSPHINXHASH256sSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(32, 16, 30, 3, 20, 13, "SPHINXHASH-simple", RANDOMIZE)
}

// Security Level 3 (N=24)
func MakeSthincsPlusSPHINXHASH192fRobust(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(24, 16, 30, 6, 33, 8, "SPHINXHASH-robust", RANDOMIZE)
}
func MakeSthincsPlusSPHINXHASH192sRobust(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(24, 16, 30, 3, 18, 12, "SPHINXHASH-robust", RANDOMIZE)
}
func MakeSthincsPlusSPHINXHASH192fSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(24, 16, 30, 6, 33, 8, "SPHINXHASH-simple", RANDOMIZE)
}
func MakeSthincsPlusSPHINXHASH192sSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(24, 16, 30, 3, 18, 12, "SPHINXHASH-simple", RANDOMIZE)
}

// Security Level 5 (N=16)
func MakeSthincsPlusSPHINXHASH128fRobust(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(16, 16, 30, 6, 30, 6, "SPHINXHASH-robust", RANDOMIZE)
}
func MakeSthincsPlusSPHINXHASH128sRobust(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(16, 16, 30, 3, 14, 11, "SPHINXHASH-robust", RANDOMIZE)
}
func MakeSthincsPlusSPHINXHASH128fSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(16, 16, 30, 6, 30, 6, "SPHINXHASH-simple", RANDOMIZE)
}
func MakeSthincsPlusSPHINXHASH128sSimple(RANDOMIZE bool) *Parameters {
	return MakeSthincsPlus(16, 16, 30, 3, 14, 11, "SPHINXHASH-simple", RANDOMIZE)
}

// ============================================================================
// Helper functions and generic constructor
// ============================================================================

// isPowerOfTwo checks if x is a power of two
// Used to validate Winternitz parameter W
func isPowerOfTwo(x int) bool {
	return x > 0 && (x&(x-1)) == 0
}

// MakeSthincsPlus creates a parameter set with the specified parameters
//
// PARAMETER VALIDATION:
//   - H must be divisible by D (ensures integer tree heights)
//   - W must be a power of 2 (required for base-w conversion)
//   - logt must be < 62 (prevents 1<<logt overflow)
//   - Message digest length m must be >= 16 bytes (minimum security)
//
// MATHEMATICAL DERIVATIONS:
//
//	Len1 = ceil(8N / log2(W)) - number of WOTS+ chains for message encoding
//	Len2 = floor(log2(Len1*(W-1))/log2(W)) + 1 - number of checksum chains
//	m = ceil(K*logT/8) + ceil((H - H/D)/8) + ceil((H/D)/8) - message digest length
func MakeSthincsPlus(n int, w int, h int, d int, k int, logt int, hashFunc string, RANDOMIZE bool) *Parameters {
	params := new(Parameters)

	// Set basic security parameters
	params.N = n       // Hash output length in bytes
	params.W = w       // Winternitz parameter (base for WOTS+)
	params.H = h       // Total hypertree height (2^H signatures max)
	params.D = d       // Number of hypertree layers
	params.K = k       // Number of FORS trees
	params.LogT = logt // Log2 of FORS leaves per tree

	// Validate H divisible by D (ensures integer tree heights)
	if h%d != 0 {
		panic(fmt.Sprintf("H (%d) must be divisible by D (%d)", h, d))
	}
	params.Hprime = params.H / params.D // Height of each XMSS tree

	// Validate logt to prevent 1<<logt overflow (safe for 64-bit systems)
	if logt >= 62 {
		panic(fmt.Sprintf("logt too large: %d (max 61)", logt))
	}
	params.T = 1 << logt // T = 2^logt, number of leaves per FORS tree
	params.A = logt      // Alias for FORS tree height
	params.RANDOMIZE = RANDOMIZE

	// WOTS+ parameter calculations
	// Len1: Number of message encoding chains (each encodes log2(W) bits)
	params.Len1 = int(math.Ceil(8 * float64(n) / math.Log2(float64(w))))

	// Len2: Number of checksum chains (prevents forgery by message modification)
	params.Len2 = int(math.Floor(math.Log2(float64(params.Len1*(w-1)))/math.Log2(float64(w))) + 1)

	// Len: Total WOTS+ chain length
	params.Len = params.Len1 + params.Len2

	// Validate W is power of 2 (required for base-w conversion)
	if !isPowerOfTwo(w) {
		panic(fmt.Sprintf("Winternitz parameter W=%d must be power of 2", w))
	}

	// Message digest length for Hmsg function
	// md_len: Bytes for FORS indices (K*logT bits)
	md_len := int(math.Floor((float64(params.K)*float64(logt) + 7) / 8))
	// idx_tree_len: Bytes for tree index (H - H/D bits)
	idx_tree_len := int(math.Floor((float64(h - h/d + 7)) / 8))
	// idx_leaf_len: Bytes for leaf index (H/D bits)
	idx_leaf_len := int(math.Floor(float64(h/d+7) / 8))
	m := md_len + idx_tree_len + idx_leaf_len

	// Ensure minimum digest length for security
	if m < 16 {
		panic(fmt.Sprintf("message digest length too small: %d bytes (minimum 16)", m))
	}

	// Initialize the appropriate tweakable hash function
	// Robust variant: XOR with bitmask (provably secure)
	// Simple variant: Direct hashing (faster, still considered secure)
	switch hashFunc {
	case "SHA256-robust":
		params.Tweak = &tweakable.Sha256Tweak{
			Variant:             tweakable.Robust,
			MessageDigestLength: m,
			N:                   n,
		}
	case "SHA256-simple":
		params.Tweak = &tweakable.Sha256Tweak{
			Variant:             tweakable.Simple,
			MessageDigestLength: m,
			N:                   n,
		}
	case "SHAKE256-robust":
		params.Tweak = &tweakable.Shake256Tweak{
			Variant:             tweakable.Robust,
			MessageDigestLength: m,
			N:                   n,
		}
	case "SHAKE256-simple":
		params.Tweak = &tweakable.Shake256Tweak{
			Variant:             tweakable.Simple,
			MessageDigestLength: m,
			N:                   n,
		}
	case "SPHINXHASH-robust":
		params.Tweak = &tweakable.SphinxHashTweak{
			Variant:             tweakable.Robust,
			MessageDigestLength: m,
			N:                   n,
		}
	case "SPHINXHASH-simple":
		params.Tweak = &tweakable.SphinxHashTweak{
			Variant:             tweakable.Simple,
			MessageDigestLength: m,
			N:                   n,
		}
	default:
		// Default to SHA256-robust for safety
		params.Tweak = &tweakable.Sha256Tweak{
			Variant:             tweakable.Robust,
			MessageDigestLength: m,
			N:                   n,
		}
	}
	return params
}
