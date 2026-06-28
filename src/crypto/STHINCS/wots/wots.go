// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/address/wots.go
package wots

import (
	"fmt"
	"math"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/address"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/util"
)

// chain computes the value of F iterated 'steps' times starting from X
//
// MATHEMATICAL DEFINITION:
//
//	chain(X, start, 0) = X
//	chain(X, start, s) = F(chain(X, start, s-1)) for s > 0
//
// However, each step uses a different address (HashAddress = start + step - 1)
// to ensure domain separation between different chain positions.
//
// The chain represents the WOTS+ hash chain:
//
//	sk (secret key) → F(sk) → F(F(sk)) → ... → pk (public key)
//	where pk = F^(W-1)(sk) (apply F W-1 times)
//
// For signing, we apply F d times where d is the base-w digit (0 to W-1)
// For verification, we apply F (W-1-d) times to reach the public key
//
// Parameters:
//
//	X: Starting value (N bytes) - secret key or intermediate value
//	startIndex: Starting position in chain (0 to W-1)
//	steps: Number of iterations to apply (0 to W-1-startIndex)
//	PKseed: Public seed for randomization (domain separation)
//	adrs: Base address (ChainAddress and HashAddress will be modified)
//
// Returns: Value after applying F 'steps' times, or error if steps would exceed W-1
func chain(params *parameters.Parameters, X []byte, startIndex int, steps int, PKseed []byte, adrs *address.ADRS) ([]byte, error) {
	// Validate steps is non-negative
	if steps < 0 {
		return nil, fmt.Errorf("steps cannot be negative: %d", steps)
	}

	// Base case: No steps to apply
	if steps == 0 {
		return X, nil
	}

	// Security check: Ensure we don't exceed the chain length
	// Maximum chain length is W-1 (0 to W-1 inclusive = W positions)
	// Example: W=16, valid chain positions: 0..15, maximum steps = 15
	if (startIndex + steps) > (params.W - 1) {
		return nil, fmt.Errorf("chain steps exceed maximum: startIndex=%d, steps=%d, W=%d",
			startIndex, steps, params.W)
	}

	// Iterative implementation to avoid stack overflow
	// Starting from X, apply F repeatedly 'steps' times
	// Each iteration uses a unique HashAddress = startIndex + i
	result := make([]byte, params.N)
	copy(result, X)

	for i := 0; i < steps; i++ {
		// Set address to current chain position (startIndex + i)
		// This ensures each step in the chain gets a unique hash input
		adrs.SetHashAddress(startIndex + i)
		// Apply F: result = F(PKseed, adrs, result)
		result = params.Tweak.F(PKseed, adrs, result)
	}

	return result, nil
}

// Wots_PKgen generates a WOTS+ public key from a secret seed
//
// MATHEMATICAL PROCESS:
// For a WOTS+ key pair with L chains (L = Len1 + Len2):
//  1. For each chain i (0 to L-1):
//     a. Generate secret key: sk_i = PRF(SKseed, adrs(chain=i, hash=0))
//     b. Compute public key: pk_i = chain(sk_i, 0, W-1)
//     This applies F (W-1) times to the secret key
//  2. Concatenate all pk_i: tmp = pk_0 || pk_1 || ... || pk_{L-1}
//  3. Compress using T_l: PK = T_l(PKseed, adrs(WOTS_PK), tmp)
//
// WHY COMPRESS? The raw public key would be L*N bytes (e.g., 67*32=2144 bytes)
// Compression reduces it to N bytes (32 bytes), making it suitable for Merkle trees
//
// Returns: N-byte compressed public key
func Wots_PKgen(params *parameters.Parameters, SKseed []byte, PKseed []byte, adrs *address.ADRS) ([]byte, error) {
	// Validate inputs to prevent nil pointer dereference
	if SKseed == nil || PKseed == nil || adrs == nil {
		return nil, fmt.Errorf("nil parameters provided")
	}

	// Copy address to avoid modifying the original
	wotspkADRS := adrs.Copy()

	// Buffer for concatenated chain public keys (L * N bytes)
	tmp := make([]byte, params.Len*params.N)

	// Generate each chain's public key
	for i := 0; i < params.Len; i++ {
		// Set address to point to chain i, position 0 (secret key)
		adrs.SetChainAddress(i)
		adrs.SetHashAddress(0)

		// Generate secret key at this chain using PRF
		// PRF ensures deterministic but pseudorandom output from seed
		sk := params.Tweak.PRF(SKseed, adrs)

		// Validate PRF output
		if sk == nil || len(sk) != params.N {
			return nil, fmt.Errorf("PRF returned invalid key for chain %d", i)
		}

		// Apply F (W-1) times to get public key
		// This is the value at the end of the chain (position W-1)
		// chain(sk, 0, W-1) = F^(W-1)(sk)
		chainResult, err := chain(params, sk, 0, params.W-1, PKseed, adrs)
		if err != nil {
			return nil, fmt.Errorf("chain failed for chain %d: %w", i, err)
		}
		// Store at position i * N in the concatenated buffer
		copy(tmp[i*params.N:], chainResult)
	}

	// Set address type to WOTS_PK for final compression
	wotspkADRS.SetType(address.WOTS_PK)
	wotspkADRS.SetKeyPairAddress(adrs.GetKeyPairAddress())

	// Compress all chain public keys into a single N-byte value using T_l
	// T_l is a tweakable hash function that takes arbitrary-length input
	pk := params.Tweak.T_l(PKseed, wotspkADRS, tmp)
	return pk, nil
}

// Wots_sign signs a message using WOTS+
//
// SIGNING PROCESS:
//  1. Convert message to base-w digits (Len1 digits)
//     message (m bytes) → base-w digits d[0..Len1-1], each in [0, W-1]
//  2. Compute checksum: csum = Σ (W-1 - d[i]) for i=0..Len1-1
//  3. Convert checksum to base-w digits (Len2 digits)
//  4. Concatenate: digits = msg_basew || csum_basew (total Len digits)
//  5. For each digit d_i (0 to Len-1):
//     a. Generate secret key: sk_i = PRF(SKseed, adrs(chain=i))
//     b. Signature component = chain(sk_i, 0, d_i)
//     This applies F d_i times (NOT W-1-d_i!)
//
// WHY CHECKSUM?
// The checksum prevents forgery by message modification.
// If an attacker increases one digit, they must decrease another to keep
// the checksum valid, which is hard because decreasing requires inverting F.
// Property: Σ d_i + Σ csum_i = Len1*(W-1) (constant for all messages)
//
// BASE-W CONVERSION:
// For w = 16 (log2(16)=4 bits per digit), message of 32 bytes (256 bits)
// produces Len1 = ceil(256/4) = 64 digits.
//
// Returns: Signature of Len*N bytes
func Wots_sign(params *parameters.Parameters, message []byte, SKseed []byte, PKseed []byte, adrs *address.ADRS) ([]byte, error) {
	// Validate message is not empty
	if len(message) == 0 {
		return nil, fmt.Errorf("empty message")
	}

	// Step 1: Convert message to base-w digits
	// message is already hashed to m bytes by Hmsg
	// Base_w extracts log2(W) bits at a time from the message
	msg, err := util.Base_w(message, params.W, params.Len1)
	if err != nil {
		return nil, fmt.Errorf("base-w conversion failed: %w", err)
	}

	// Step 2: Compute checksum using uint64 to prevent overflow
	// Checksum = sum of (W-1 - each digit)
	// This ensures that Σ digits + Σ checksum_digits = Len1*(W-1)
	// Thus the total sum is constant regardless of message
	var csum64 uint64 = 0
	for i := 0; i < params.Len1; i++ {
		csum64 += uint64(params.W - 1 - msg[i])
	}

	// Step 3: Prepare checksum for base-w conversion
	// If log2(W) doesn't divide 8, we need to align bits to byte boundaries
	// Example: W=16 (log2=4 bits), totalBits = Len2 * 4
	// If totalBits % 8 != 0, we need to pad with zeros at LSB
	bitsPerDigit := int(math.Log2(float64(params.W))) // log2(W) bits per digit
	totalBits := params.Len2 * bitsPerDigit           // Total bits needed for checksum
	bitsToPad := (8 - (totalBits % 8)) % 8            // Bits to pad to reach byte boundary (0-7)
	if bitsToPad > 0 {
		csum64 = csum64 << bitsToPad // Shift left to add padding zeros at LSB
	}

	// Convert checksum to bytes (big-endian)
	// (totalBits + 7) / 8 = ceil(totalBits / 8) bytes needed
	len2_bytes := (totalBits + 7) / 8
	csumBytes := util.ToByte(csum64, len2_bytes)

	// Convert checksum bytes to base-w digits and append to msg
	csumDigits, err := util.Base_w(csumBytes, params.W, params.Len2)
	if err != nil {
		return nil, fmt.Errorf("checksum base-w conversion failed: %w", err)
	}
	msg = append(msg, csumDigits...)

	// Step 4: Generate signature
	// Signature size = Len * N bytes
	sig := make([]byte, params.Len*params.N)

	for i := 0; i < params.Len; i++ {
		// Set address to chain i, position 0 (secret key)
		adrs.SetChainAddress(i)
		adrs.SetHashAddress(0)

		// Generate secret key for this chain
		sk := params.Tweak.PRF(SKseed, adrs)

		// Apply F msg[i] times (NOT W-1-msg[i]!)
		// This is different from public key generation:
		//   Public key: W-1 steps from secret
		//   Signature: msg[i] steps from secret
		chainResult, err := chain(params, sk, 0, msg[i], PKseed, adrs)
		if err != nil {
			return nil, fmt.Errorf("chain failed for chain %d: %w", i, err)
		}
		// Store signature component at position i * N
		copy(sig[i*params.N:], chainResult)
	}

	return sig, nil
}

// Wots_pkFromSig recovers the WOTS+ public key from a signature
//
// VERIFICATION PROCESS:
// Given signature component σ_i = chain(sk_i, 0, d_i)
// We want to compute pk_i = chain(sk_i, 0, W-1)
//
// CHAIN PROPERTY:
//
//	chain(sk, 0, W-1) = chain(chain(sk, 0, d), d, W-1-d)
//	                  = chain(σ_i, d_i, W-1-d_i)
//
// So we can compute pk_i by starting from the signature component
// and applying F (W-1-d_i) more times.
//
// Steps:
//  1. Convert message to base-w digits (same as during signing)
//  2. Recompute checksum (same as during signing)
//  3. For each chain i:
//     a. Take signature component σ_i
//     b. Apply F (W-1-msg[i]) times to reach public key
//     c. Store reconstructed public key component
//  4. Compress all reconstructed components to get final public key
//
// Returns: Reconstructed N-byte public key (same as Wots_PKgen would produce)
func Wots_pkFromSig(params *parameters.Parameters, signature []byte, message []byte, PKseed []byte, adrs *address.ADRS) ([]byte, error) {
	// Validate input signature length
	expectedSigLen := params.Len * params.N
	if len(signature) != expectedSigLen {
		return nil, fmt.Errorf("invalid signature length: expected %d, got %d", expectedSigLen, len(signature))
	}

	// Copy address to avoid modifying original
	wotspkADRS := adrs.Copy()

	// Step 1: Convert message to base-w digits (same as during signing)
	msg, err := util.Base_w(message, params.W, params.Len1)
	if err != nil {
		return nil, fmt.Errorf("base-w conversion failed: %w", err)
	}

	// Step 2: Recompute checksum using uint64 (same as during signing)
	var csum64 uint64 = 0
	for i := 0; i < params.Len1; i++ {
		csum64 += uint64(params.W - 1 - msg[i])
	}

	// Prepare checksum for base-w conversion
	bitsPerDigit := int(math.Log2(float64(params.W)))
	totalBits := params.Len2 * bitsPerDigit
	bitsToPad := (8 - (totalBits % 8)) % 8
	if bitsToPad > 0 {
		csum64 = csum64 << bitsToPad
	}

	len2_bytes := (totalBits + 7) / 8
	csumBytes := util.ToByte(csum64, len2_bytes)

	csumDigits, err := util.Base_w(csumBytes, params.W, params.Len2)
	if err != nil {
		return nil, fmt.Errorf("checksum base-w conversion failed: %w", err)
	}
	msg = append(msg, csumDigits...)

	// Step 3: Reconstruct each chain's public key from signature
	// Buffer for reconstructed chain public keys (L * N bytes)
	tmp := make([]byte, params.Len*params.N)

	for i := 0; i < params.Len; i++ {
		// Set address to chain i
		adrs.SetChainAddress(i)

		// Validate signature slice bounds
		start := i * params.N
		end := (i + 1) * params.N
		if end > len(signature) {
			return nil, fmt.Errorf("signature slice out of bounds: %d >= %d", end, len(signature))
		}

		// Reconstruct public key component using chain property:
		// pk_i = chain(σ_i, msg[i], W-1-msg[i])
		// This starts from the signature value and applies F (W-1-msg[i]) more times
		chainResult, err := chain(params,
			signature[start:end], // σ_i - the signature component
			msg[i],               // starting position = msg[i]
			params.W-1-msg[i],    // steps = W-1-msg[i]
			PKseed,
			adrs)
		if err != nil {
			return nil, fmt.Errorf("chain reconstruction failed for chain %d: %w", i, err)
		}
		// Store reconstructed public key component
		copy(tmp[i*params.N:], chainResult)
	}

	// Step 4: Compress reconstructed chain public keys (same as key generation)
	wotspkADRS.SetType(address.WOTS_PK)
	wotspkADRS.SetKeyPairAddress(adrs.GetKeyPairAddress())
	pk_sig := params.Tweak.T_l(PKseed, wotspkADRS, tmp)
	return pk_sig, nil
}
