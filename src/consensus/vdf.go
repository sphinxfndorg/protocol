// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/consensus/vdf.go
package consensus

import (
	"fmt"
	"math/big"
	"sync"

	logger "github.com/sphinxfndorg/protocol/src/log"
	"golang.org/x/crypto/sha3"
)

// vdfParamsCache holds the canonical VDF parameters after they have been
// derived from the genesis block on first call to LoadCanonicalVDFParams.
// Using sync.Once guarantees the derivation runs exactly once per process,
// even when multiple goroutines call LoadCanonicalVDFParams concurrently.
var (
	vdfParamsOnce   sync.Once // Ensures derivation runs exactly once
	vdfParamsCached VDFParams // Cached result after first derivation
	vdfParamsErr    error     // Cached error after first derivation
)

// canonicalT is the sequential-squaring delay parameter.
//
// At ~10^8 squarings/second on modern hardware, T=2^20 (~1M) takes roughly
// 10ms — fast enough to fit in a 10-second slot and slow enough to prevent
// look-ahead grinding. Increase T for longer slots or faster hardware.
const canonicalT = uint64(1 << 20) // 1,048,576 squarings

// canonicalLambda is the security parameter in bits.
// 256 provides 128-bit post-quantum security margin.
const canonicalLambda = uint64(256)

// canonicalHashBytes is the output size for SHAKE-256 expansion.
// 128 bytes = 1024 bits — the target discriminant size.
// The actual prime found will be 1022–1024 bits depending on leading bytes,
// which is normal and provides the same security margin as exactly 1024 bits.
const canonicalHashBytes = 128

// genesisHashProvider is a function variable that returns the genesis block
// hash string. It is set by InitVDFFromGenesis and called by
// LoadCanonicalVDFParams on first use.
//
// This indirection allows the blockchain layer to inject the real genesis hash
// at startup without creating an import cycle between the consensus and core
// packages.
var genesisHashProvider func() (string, error)

// InitVDFFromGenesis registers the genesis hash provider function that
// LoadCanonicalVDFParams will call to derive the discriminant.
//
// This MUST be called once during node startup, before any call to
// NewConsensus, so that the VDF parameters can be derived from the real
// genesis block stored on disk.
//
// Usage (in blockchain or node initialization code):
//
//	consensus.InitVDFFromGenesis(func() (string, error) {
//	    block := blockchain.GetGenesisBlock()
//	    if block == nil {
//	        return "", fmt.Errorf("genesis block not found")
//	    }
//	    return block.GetHash(), nil
//	})
func InitVDFFromGenesis(provider func() (string, error)) {
	genesisHashProvider = provider
}

// Global variable to hold pre-derived VDF parameters
var (
	preDerivedVDFParams     *VDFParams
	preDerivedVDFParamsOnce sync.Once
)

// SetCanonicalVDFParameters sets pre-derived VDF parameters from the caller
// (typically setup.go after deriving from genesis block once).
// This should be called BEFORE NewConsensus.
func SetCanonicalVDFParameters(params *VDFParams) error {
	if params == nil {
		return fmt.Errorf("VDF parameters cannot be nil")
	}
	if params.Discriminant == nil || params.Discriminant.BitLen() == 0 {
		return fmt.Errorf("invalid discriminant in VDF parameters")
	}
	if params.T == 0 {
		return fmt.Errorf("invalid T value in VDF parameters")
	}

	preDerivedVDFParamsOnce.Do(func() {
		preDerivedVDFParams = params
		logger.Info("✅ Pre-derived VDF parameters set: D=%d bits, T=%d",
			params.Discriminant.BitLen(), params.T)
	})
	return nil
}

// LoadCanonicalVDFParams returns the network-wide VDF parameters that every
// node must use. If pre-derived parameters were set via SetCanonicalVDFParameters,
// they are returned immediately. Otherwise, parameters are derived from the
// genesis block hash on first call.
func LoadCanonicalVDFParams() (VDFParams, error) {
	// First, check if pre-derived parameters are available
	if preDerivedVDFParams != nil {
		logger.Info("Using pre-derived VDF parameters (D=%d bits, T=%d)",
			preDerivedVDFParams.Discriminant.BitLen(), preDerivedVDFParams.T)
		return *preDerivedVDFParams, nil
	}

	// Fall back to deriving from genesis hash
	vdfParamsOnce.Do(func() {
		vdfParamsCached, vdfParamsErr = deriveVDFParams()
	})
	return vdfParamsCached, vdfParamsErr
}

// ResetVDFParamsCache clears the cached VDF parameters so they will be
// re-derived on the next call to LoadCanonicalVDFParams.
//
// This is intended for use in tests only — production nodes must never
// reset the cache after startup, as doing so could cause parameter
// divergence between nodes.
func ResetVDFParamsCache() {
	vdfParamsOnce = sync.Once{}
	vdfParamsCached = VDFParams{}
	vdfParamsErr = nil
}

// deriveVDFParams performs the actual derivation. It is called exactly once
// by the sync.Once inside LoadCanonicalVDFParams.
func deriveVDFParams() (VDFParams, error) {
	// Step 1: obtain the genesis block hash from the registered provider.
	if genesisHashProvider == nil {
		return VDFParams{}, fmt.Errorf(
			"VDF genesis hash provider not registered — call consensus.InitVDFFromGenesis() " +
				"before NewConsensus()")
	}

	genesisHash, err := genesisHashProvider()
	if err != nil {
		return VDFParams{}, fmt.Errorf("failed to obtain genesis hash for VDF derivation: %w", err)
	}
	if genesisHash == "" {
		return VDFParams{}, fmt.Errorf("genesis hash is empty — genesis block may not be stored yet")
	}

	logger.Info("Deriving canonical VDF parameters from genesis hash: %s", genesisHash)

	// Step 2: expand the genesis hash to 1024 bits using SHAKE-256.
	// SHAKE-256 is an extendable-output function (XOF) — unlike SHA-256 which
	// is fixed at 256 bits, SHAKE-256 can produce any number of output bytes.
	// This is the same function used in GetSeed and HashToClassGroup, keeping
	// the entire VDF stack consistent on a single hash primitive.
	shake := sha3.NewShake256()
	shake.Write([]byte(genesisHash))
	hashBytes := make([]byte, canonicalHashBytes) // 128 bytes = 1024 bits
	shake.Read(hashBytes)

	// Step 3: build a candidate integer and force it to satisfy p ≡ 3 mod 4.
	// Setting bit 0 makes the number odd (eliminates ≡ 0 and ≡ 2 mod 4).
	// Setting bit 1 combined with bit 0 gives exactly ≡ 3 mod 4.
	// This is identical to what GenerateClassGroupParameters does for random
	// primes, but here we start from a deterministic seed instead of rand.Reader.
	p := new(big.Int).SetBytes(hashBytes)
	p.SetBit(p, 0, 1) // force odd
	p.SetBit(p, 1, 1) // force ≡ 3 mod 4

	// Step 4: find the next prime from this starting point.
	// We increment by 4 to preserve the ≡ 3 mod 4 property:
	//   (3 mod 4) + 4 = 7 mod 4 = 3 mod 4  ✓
	// Using +1 or +2 would destroy the property we just established.
	// ProbablyPrime(20) gives a false-prime probability below 4^-20 ≈ 10^-12,
	// which is acceptable for a public parameter derived from a public hash.
	iterations := 0
	for !p.ProbablyPrime(20) {
		p.Add(p, big.NewInt(4)) // preserve ≡ 3 mod 4
		iterations++
		// Safety guard: if we iterate more than 10,000 times something is
		// wrong with the input. In practice this loop runs < 1000 iterations.
		if iterations > 10_000 {
			return VDFParams{}, fmt.Errorf(
				"prime search exceeded 10,000 iterations — genesis hash may be malformed")
		}
	}

	// Step 5: negate to form the discriminant D = -p.
	// Class group VDF requires D < 0 (imaginary quadratic field ℚ(√D)).
	D := new(big.Int).Neg(p)

	// ── Sanity checks ────────────────────────────────────────────────────────
	// These verify the derivation produced a mathematically valid discriminant.
	// They catch bugs in the derivation code, not network parameter mismatches.

	// The prime p must be at least 512 bits for meaningful security.
	// In practice it will be ~1022 bits given canonicalHashBytes=128.
	if p.BitLen() < 512 {
		return VDFParams{}, fmt.Errorf(
			"derived prime too short: %d bits (need ≥ 512) — increase canonicalHashBytes",
			p.BitLen())
	}

	// Verify p ≡ 3 mod 4 on the absolute value (p, not D).
	// Using p instead of D avoids ambiguity from Go's signed mod behavior.
	mod4 := new(big.Int).Mod(p, big.NewInt(4))
	if mod4.Int64() != 3 {
		return VDFParams{}, fmt.Errorf(
			"derived prime ≡ %d mod 4, need ≡ 3 — derivation logic error", mod4.Int64())
	}

	// Verify p is actually prime (redundant with ProbablyPrime above, but
	// running it here with higher rounds catches any edge cases).
	if !p.ProbablyPrime(40) {
		return VDFParams{}, fmt.Errorf("derived value failed primality check — derivation error")
	}
	// ─────────────────────────────────────────────────────────────────────────

	logger.Info("✅ Canonical VDF parameters derived successfully:")
	logger.Info("   Genesis hash  : %s", genesisHash)
	logger.Info("   Prime p       : %d bits", p.BitLen())
	logger.Info("   p mod 4       : %d (must be 3)", mod4.Int64())
	logger.Info("   Discriminant D: %d bits (negative)", D.BitLen())
	logger.Info("   T             : %d squarings", canonicalT)
	logger.Info("   Search iters  : %d", iterations)

	return VDFParams{
		Discriminant: D,
		T:            canonicalT,
		Lambda:       uint(canonicalLambda),
	}, nil
}

// GetRawGenesisHash returns the raw genesis hash without any prefix.
// This is used to ensure consistent VDF parameter derivation.
func GetRawGenesisHash(displayHash string) string {
	// Remove "GENESIS_" prefix if present
	if len(displayHash) > 8 && displayHash[:8] == "GENESIS_" {
		return displayHash[8:]
	}
	return displayHash
}
