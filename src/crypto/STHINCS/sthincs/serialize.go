// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/sthincs/serialize.go
package sthincs

import (
	"errors"
	"fmt"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/fors"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/hypertree"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/xmss"
)

// ============================================================================
// SERIALIZATION FORMAT
// ============================================================================
//
// SPHINCS+ Signature Binary Format:
// ┌─────────────────────────────────────────────────────────────────────┐
// │ R (N bytes)                                                         │
// ├─────────────────────────────────────────────────────────────────────┤
// │ FORS Signature (K * (N + A*N) bytes)                                │
// │   For each tree i = 0..K-1:                                         │
// │     ├─ PrivateKeyValue (N bytes)                                    │
// │     └─ AUTH (A * N bytes)                                           │
// ├─────────────────────────────────────────────────────────────────────┤
// │ Hypertree Signature (D * (Len*N + Hprime*N) bytes)                  │
// │   For each layer j = 0..D-1:                                        │
// │     ├─ WOTS Signature (Len * N bytes)                               │
// │     └─ XMSS AUTH (Hprime * N bytes)                                 │
// └─────────────────────────────────────────────────────────────────────┘
//
// Total Size = N + K*(N + A*N) + D*(Len*N + Hprime*N) bytes
//
// Public Key Binary Format:
// ┌─────────────────────────────────────────────────────────────────────┐
// │ PKseed (N bytes) - Public seed for randomization                    │
// │ PKroot (N bytes) - Root of hypertree (actual public key)            │
// └─────────────────────────────────────────────────────────────────────┘
// Total Size = 2*N bytes
//
// Secret Key Binary Format:
// ┌─────────────────────────────────────────────────────────────────────┐
// │ SKseed (N bytes) - Secret seed for generating WOTS+/FORS keys       │
// │ SKprf (N bytes)  - Secret key for PRFmsg (message randomization)    │
// │ PKseed (N bytes) - Public seed (copied from public key)             │
// │ PKroot (N bytes) - Public root (copied from public key)             │
// └─────────────────────────────────────────────────────────────────────┘
// Total Size = 4*N bytes
// ============================================================================

// SerializeSignature converts a SPHINCS+ signature to bytes
//
// SERIALIZATION ORDER:
//  1. R component (N bytes) - randomizer for message hashing
//  2. FORS signature components (K trees):
//     For each FORS tree i from 0 to K-1:
//     a. PrivateKeyValue (N bytes) - the revealed leaf value
//     b. AUTH (A * N bytes) - authentication path of length A
//  3. Hypertree signature components (D layers):
//     For each layer j from 0 to D-1:
//     a. WOTS signature (Len * N bytes)
//     b. XMSS AUTH (Hprime * N bytes) - authentication path
//
// This order matches the signing process:
//   - First the message randomizer R
//   - Then the FORS signature (bottom layer)
//   - Then the hypertree signatures (upper layers)
//
// Returns: Serialized byte slice or error if any component is nil
func (s *SPHINCS_SIG) SerializeSignature() ([]byte, error) {
	// Validate all components are present
	if s == nil {
		return nil, errors.New("cannot serialize nil signature")
	}
	if s.R == nil {
		return nil, errors.New("signature has nil R component")
	}
	if s.SIG_FORS == nil {
		return nil, errors.New("signature has nil FORS component")
	}
	if s.SIG_HT == nil {
		return nil, errors.New("signature has nil hypertree component")
	}

	var sig_as_bytes []byte

	// Step 1: Add R component (N bytes)
	// R is the randomizer used in Hmsg for message hashing
	// Size: N bytes
	sig_as_bytes = append(sig_as_bytes, s.R...)

	// Step 2: Add FORS signature components
	// FORS has K trees, each contributing (N + A*N) bytes
	for i := range s.SIG_FORS.Forspkauth {
		// Get private key value (leaf) for this tree
		sk := s.SIG_FORS.GetSK(i)
		if sk == nil {
			return nil, fmt.Errorf("FORS signature has nil private key at index %d", i)
		}
		// Get authentication path for this tree
		auth := s.SIG_FORS.GetAUTH(i)
		if auth == nil {
			return nil, fmt.Errorf("FORS signature has nil AUTH at index %d", i)
		}
		// Append: PrivateKeyValue (N bytes) then AUTH (A*N bytes)
		sig_as_bytes = append(sig_as_bytes, sk...)
		sig_as_bytes = append(sig_as_bytes, auth...)
	}

	// Step 3: Add hypertree XMSS signatures (D layers)
	// Each layer contributes (Len*N + Hprime*N) bytes
	for idx, xmssSig := range s.SIG_HT.XMSSSignatures {
		if xmssSig == nil {
			return nil, fmt.Errorf("hypertree signature has nil XMSS signature at index %d", idx)
		}
		// Get WOTS signature component
		wotsSig := xmssSig.GetWOTSSig()
		if wotsSig == nil {
			return nil, fmt.Errorf("XMSS signature %d has nil WOTS signature", idx)
		}
		// Get XMSS authentication path
		auth := xmssSig.GetXMSSAUTH()
		if auth == nil {
			return nil, fmt.Errorf("XMSS signature %d has nil AUTH", idx)
		}
		// Append: WOTS signature (Len*N bytes) then AUTH (Hprime*N bytes)
		sig_as_bytes = append(sig_as_bytes, wotsSig...)
		sig_as_bytes = append(sig_as_bytes, auth...)
	}

	return sig_as_bytes, nil
}

// DeserializeSignature reconstructs a SPHINCS+ signature from bytes
//
// DESERIALIZATION PROCESS:
//  1. Verify total length matches expected size
//  2. Extract R component (first N bytes)
//  3. Extract FORS signature (next K*(N + A*N) bytes)
//     - For each tree: read N bytes (PrivateKeyValue) then A*N bytes (AUTH)
//  4. Extract hypertree signature (remaining D*(Len*N + Hprime*N) bytes)
//     - For each layer: read Len*N bytes (WOTS sig) then Hprime*N bytes (AUTH)
//
// This is the inverse of SerializeSignature()
//
// Parameters:
//
//	params: SPHINCS+ parameters (N, K, A, D, Len, Hprime)
//	signature: Raw signature bytes
//
// Returns: Reconstructed SPHINCS_SIG structure or error
func DeserializeSignature(params *parameters.Parameters, signature []byte) (*SPHINCS_SIG, error) {
	// Validate inputs
	if params == nil {
		return nil, errors.New("nil parameters provided")
	}
	if signature == nil {
		return nil, errors.New("nil signature bytes provided")
	}

	// Calculate expected signature length based on parameters
	// Formula: N + K*(N + A*N) + D*(Len*N + Hprime*N)
	//
	// Mathematical breakdown:
	//   - N bytes: R component
	//   - K*(N + A*N): FORS signature (K trees, each with leaf + AUTH)
	//   - D*(Len*N + Hprime*N): Hypertree signature (D layers, each with WOTS + AUTH)
	expectedLen := params.N + // R component
		params.K*(params.N+params.A*params.N) + // FORS: K * (sk + AUTH)
		params.D*(params.Len*params.N+params.Hprime*params.N) // HT: D * (WOTS sig + AUTH)

	// Verify signature length matches expected size
	if len(signature) != expectedLen {
		return nil, fmt.Errorf("signature has incorrect length: expected %d bytes, got %d bytes",
			expectedLen, len(signature))
	}

	SIG := &SPHINCS_SIG{}
	bytes_processed := 0

	// Step 1: Extract R component (first N bytes)
	// R is the randomizer used in Hmsg
	SIG.R = make([]byte, params.N)
	copy(SIG.R, signature[bytes_processed:bytes_processed+params.N])
	bytes_processed += params.N

	// Step 2: Extract FORS signature
	// FORS has K trees, each contributing (N + A*N) bytes
	fors_signature := &fors.FORSSignature{
		Forspkauth: make([]*fors.TreePKAUTH, 0, params.K),
	}

	for i := 0; i < params.K; i++ {
		// Calculate size for this tree: N bytes (leaf) + A*N bytes (AUTH)
		treeSize := params.N + params.A*params.N

		// Bounds check to prevent out-of-range panic
		if bytes_processed+treeSize > len(signature) {
			return nil, fmt.Errorf("signature too short while reading FORS tree %d", i)
		}

		pkauth := &fors.TreePKAUTH{}
		pkauth_bytes := signature[bytes_processed : bytes_processed+treeSize]

		// Extract PrivateKeyValue (first N bytes)
		pkauth.PrivateKeyValue = make([]byte, params.N)
		copy(pkauth.PrivateKeyValue, pkauth_bytes[:params.N])

		// Extract AUTH path (remaining A*N bytes)
		pkauth.AUTH = make([]byte, params.A*params.N)
		copy(pkauth.AUTH, pkauth_bytes[params.N:])

		fors_signature.Forspkauth = append(fors_signature.Forspkauth, pkauth)
		bytes_processed += treeSize
	}
	SIG.SIG_FORS = fors_signature

	// Step 3: Extract hypertree signature
	// Hypertree has D layers, each contributing (Len*N + Hprime*N) bytes
	hypertree_signature := &hypertree.HTSignature{
		XMSSSignatures: make([]*xmss.XMSSSignature, 0, params.D),
	}

	for i := 0; i < params.D; i++ {
		// Calculate size for this XMSS signature: Len*N (WOTS) + Hprime*N (AUTH)
		xmssSize := (params.Len + params.Hprime) * params.N

		// Bounds check to prevent out-of-range panic
		if bytes_processed+xmssSize > len(signature) {
			return nil, fmt.Errorf("signature too short while reading XMSS signature %d", i)
		}

		xmss_sig := &xmss.XMSSSignature{}
		xmss_sig_bytes := signature[bytes_processed : bytes_processed+xmssSize]

		// Extract WOTS signature (first Len*N bytes)
		xmss_sig.WotsSignature = make([]byte, params.Len*params.N)
		copy(xmss_sig.WotsSignature, xmss_sig_bytes[:params.Len*params.N])

		// Extract XMSS AUTH path (remaining Hprime*N bytes)
		xmss_sig.AUTH = make([]byte, params.Hprime*params.N)
		copy(xmss_sig.AUTH, xmss_sig_bytes[params.Len*params.N:])

		hypertree_signature.XMSSSignatures = append(hypertree_signature.XMSSSignatures, xmss_sig)
		bytes_processed += xmssSize
	}
	SIG.SIG_HT = hypertree_signature

	return SIG, nil
}

// SerializePK converts a SPHINCS+ public key to bytes
//
// PUBLIC KEY FORMAT:
//
//	┌────────────────────────────────────┐
//	│ PKseed (N bytes)                   │
//	├────────────────────────────────────┤
//	│ PKroot (N bytes)                   │
//	└────────────────────────────────────┘
//
// Total size: 2 * N bytes
//
// The public key consists of:
//   - PKseed: Public seed used for randomization in all hash functions
//   - PKroot: Root of the hypertree (the actual public key value)
//
// Returns: Serialized byte slice or error if any component is nil
func (pk *SPHINCS_PK) SerializePK() ([]byte, error) {
	// Validate public key components
	if pk == nil {
		return nil, errors.New("cannot serialize nil public key")
	}
	if pk.PKseed == nil {
		return nil, errors.New("public key has nil PKseed")
	}
	if pk.PKroot == nil {
		return nil, errors.New("public key has nil PKroot")
	}

	// Concatenate: PKseed (N bytes) then PKroot (N bytes)
	var pk_as_bytes []byte
	pk_as_bytes = append(pk_as_bytes, pk.PKseed...)
	pk_as_bytes = append(pk_as_bytes, pk.PKroot...)

	return pk_as_bytes, nil
}

// DeserializePK reconstructs a SPHINCS+ public key from bytes
//
// This is the inverse of SerializePK()
//
// Parameters:
//
//	params: SPHINCS+ parameters (provides N)
//	pk: Raw public key bytes (must be exactly 2*N bytes)
//
// Returns: Reconstructed SPHINCS_PK structure or error
func DeserializePK(params *parameters.Parameters, pk []byte) (*SPHINCS_PK, error) {
	// Validate inputs
	if params == nil {
		return nil, errors.New("nil parameters provided")
	}
	if pk == nil {
		return nil, errors.New("nil public key bytes provided")
	}

	// Verify length: Public key is exactly 2*N bytes
	expectedLen := 2 * params.N
	if len(pk) != expectedLen {
		return nil, fmt.Errorf("public key has incorrect length: expected %d bytes, got %d bytes",
			expectedLen, len(pk))
	}

	// Extract components
	serialized_pk := &SPHINCS_PK{}
	serialized_pk.PKseed = make([]byte, params.N)
	serialized_pk.PKroot = make([]byte, params.N)

	// First N bytes: PKseed
	copy(serialized_pk.PKseed, pk[:params.N])
	// Last N bytes: PKroot
	copy(serialized_pk.PKroot, pk[params.N:])

	return serialized_pk, nil
}

// SerializeSK converts a SPHINCS+ secret key to bytes
//
// SECRET KEY FORMAT:
//
//	┌────────────────────────────────────┐
//	│ SKseed (N bytes)                   │
//	├────────────────────────────────────┤
//	│ SKprf (N bytes)                    │
//	├────────────────────────────────────┤
//	│ PKseed (N bytes)                   │
//	├────────────────────────────────────┤
//	│ PKroot (N bytes)                   │
//	└────────────────────────────────────┘
//
// Total size: 4 * N bytes
//
// The secret key consists of:
//   - SKseed: Secret seed for generating WOTS+ and FORS keys
//   - SKprf:  Secret key for PRFmsg (message randomization)
//   - PKseed: Public seed (copied from public key for convenience)
//   - PKroot: Public root (copied from public key for convenience)
//
// Returns: Serialized byte slice or error if any component is nil
func (sk *SPHINCS_SK) SerializeSK() ([]byte, error) {
	// Validate secret key components
	if sk == nil {
		return nil, errors.New("cannot serialize nil secret key")
	}
	if sk.SKseed == nil {
		return nil, errors.New("secret key has nil SKseed")
	}
	if sk.SKprf == nil {
		return nil, errors.New("secret key has nil SKprf")
	}
	if sk.PKseed == nil {
		return nil, errors.New("secret key has nil PKseed")
	}
	if sk.PKroot == nil {
		return nil, errors.New("secret key has nil PKroot")
	}

	// Concatenate all components in order
	var sk_as_bytes []byte
	sk_as_bytes = append(sk_as_bytes, sk.SKseed...) // First N bytes: SKseed
	sk_as_bytes = append(sk_as_bytes, sk.SKprf...)  // Next N bytes: SKprf
	sk_as_bytes = append(sk_as_bytes, sk.PKseed...) // Next N bytes: PKseed
	sk_as_bytes = append(sk_as_bytes, sk.PKroot...) // Last N bytes: PKroot

	return sk_as_bytes, nil
}

// DeserializeSK reconstructs a SPHINCS+ secret key from bytes
//
// This is the inverse of SerializeSK()
//
// Parameters:
//
//	params: SPHINCS+ parameters (provides N)
//	sk: Raw secret key bytes (must be exactly 4*N bytes)
//
// Returns: Reconstructed SPHINCS_SK structure or error
func DeserializeSK(params *parameters.Parameters, sk []byte) (*SPHINCS_SK, error) {
	// Validate inputs
	if params == nil {
		return nil, errors.New("nil parameters provided")
	}
	if sk == nil {
		return nil, errors.New("nil secret key bytes provided")
	}

	// Verify length: Secret key is exactly 4*N bytes
	expectedLen := 4 * params.N
	if len(sk) != expectedLen {
		return nil, fmt.Errorf("secret key has incorrect length: expected %d bytes, got %d bytes",
			expectedLen, len(sk))
	}

	// Extract components in order
	serialized_sk := &SPHINCS_SK{}
	serialized_sk.SKseed = make([]byte, params.N)
	serialized_sk.SKprf = make([]byte, params.N)
	serialized_sk.PKseed = make([]byte, params.N)
	serialized_sk.PKroot = make([]byte, params.N)

	// Bytes 0..N-1: SKseed
	copy(serialized_sk.SKseed, sk[:params.N])
	// Bytes N..2N-1: SKprf
	copy(serialized_sk.SKprf, sk[params.N:2*params.N])
	// Bytes 2N..3N-1: PKseed
	copy(serialized_sk.PKseed, sk[2*params.N:3*params.N])
	// Bytes 3N..4N-1: PKroot
	copy(serialized_sk.PKroot, sk[3*params.N:])

	return serialized_sk, nil
}
