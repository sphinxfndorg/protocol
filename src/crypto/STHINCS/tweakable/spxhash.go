// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/tweakable/spxhash.go
package tweakable

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/address"
	"golang.org/x/crypto/sha3"
)

// SphinxHashTweak is the tweakable hash used by the SPHINXHASH-* parameter
// sets (see parameters.MakeSthincsPlusSPHINXHASH...).
//
// SECURITY HISTORY: this type used to be a placeholder stub that "hashed" by
// XORing the first N bytes of a concatenated input buffer with a byte
// counter. Because PKseed/SEED/R was always written first into that buffer
// and N <= len(PKseed), only that first field ever survived the truncation —
// the message, the ADRS, and the actual compression input (tmp) were
// silently ignored. That made every tweak function's output depend only on
// PKseed/SEED/R, which made SPHINCS+ verification message- and
// address-independent: Spx_verify accepted a signature made under one key
// as valid under a completely different key (see
// TestChallengeProofRoundTripAndBinding, step 3). Every function below
// absorbs every one of its arguments — none of this input-independence can
// come back.
//
// SPLIT DESIGN (call-frequency driven):
//
//   - Hmsg, PRFmsg — called exactly ONCE per signature. These use
//     common.SpxHash: the project's real SphinxHash (Argon2id, 19 MiB,
//     t=2, ProtocolSalt) expanded via SHAKE256 to the exact output length
//     needed. Cost here is bounded (one call per sign/verify), so the
//     Argon2id hardening is affordable and gives these two functions a
//     genuinely SphinxHash-branded, memory-hard construction.
//
//   - F, H, PRF, T_l — called on the order of 1.8 MILLION times per
//     signature (WOTS+ chains x XMSS trees x FORS leaves), each with a
//     DISTINCT ADRS. Measured on this machine, common.SpxHash costs ~38ms
//     per call on a genuine cache miss — and because every call here uses a
//     different ADRS, the shared instance's LRU cache almost never hits in
//     real signing/verification. At that volume Argon2id-backed hashing
//     projects to roughly 19 HOURS per signature. These four functions
//     therefore use a fast core (SHA-512/256 bind + SHAKE256 squeeze,
//     domain-separated per function) instead — no SHA-256, no Argon2id,
//     but still fully input-dependent and collision-resistant.
//
// If you're tempted to move F/H/PRF/T_l onto common.SpxHash because a
// benchmark looked fast: check whether that benchmark reused inputs across
// calls. A cache hit on the shared spxHasher instance is sub-microsecond;
// a genuine miss (the normal case here, since ADRS differs every call) is
// ~38ms. Re-run TestTmpCountAndCost end-to-end through Spx_sign before
// changing this split.
type SphinxHashTweak struct {
	Variant             string
	MessageDigestLength int
	N                   int
}

// Domain separation tags for the fast-core functions, so F/H/T_l/PRF/mask
// can never collide with one another on the same raw input.
const (
	domainPRF  byte = 0x02
	domainF    byte = 0x04
	domainH    byte = 0x05
	domainTl   byte = 0x06
	domainMask byte = 0x07
)

// fastCorePrefix binds every fast-core call to this specific
// construction/version so it can't collide with an unrelated use of
// SHA-512/256+SHAKE256 elsewhere in the codebase.
var fastCorePrefix = []byte("STHINCS-SPHINXHASH-fastcore-v1")

// Domain separation tags for the once-per-signature, SpxHash-backed
// functions.
const (
	domainHmsgSlow   byte = 0x11
	domainPRFmsgSlow byte = 0x12
)

// writeLP writes a 4-byte big-endian length prefix followed by b into h.
// Length-prefixing every field makes the encoding unambiguous: without it,
// Hash("ab"||"c") and Hash("a"||"bc") would collide.
func writeLP(h interface{ Write([]byte) (int, error) }, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	h.Write(l[:])
	h.Write(b)
}

// ---- fast core (F, H, PRF, T_l) ----

// sphinxFastCore is the shared two-stage construction backing the hot-loop
// tweak functions: a fixed-size, fully-mixing binding stage (SHA-512/256)
// feeding an arbitrary-length squeeze stage (SHAKE256). No memory-hard step
// — this must stay cheap, since it runs up to ~1.8M times per signature.
func sphinxFastCore(domain byte, outLen int, parts ...[]byte) []byte {
	bind := sha512.New512_256()
	bind.Write(fastCorePrefix)
	bind.Write([]byte{domain})
	for _, p := range parts {
		writeLP(bind, p)
	}
	stage1 := bind.Sum(nil) // 32 bytes, depends on every byte of every part

	squeeze := sha3.NewShake256()
	squeeze.Write(stage1)
	out := make([]byte, outLen)
	squeeze.Read(out)
	return out
}

// sphinxMask derives an XOR bitmask for the Robust variant, domain-separated
// from every other fast-core use so the mask can't be mistaken for (or
// collide with) an actual F/H/T_l output.
func sphinxMask(PKseed []byte, adrs *address.ADRS, length int) []byte {
	return sphinxFastCore(domainMask, length, PKseed, adrs.GetBytes())
}

// PRF derives an N-byte pseudorandom value from a secret seed and an ADRS.
// Called hundreds of thousands of times per signature — must stay cheap.
func (s *SphinxHashTweak) PRF(SEED []byte, adrs *address.ADRS) []byte {
	return sphinxFastCore(domainPRF, s.N, SEED, adrs.GetBytes())
}

// F is the tweakable compression hash used inside WOTS+ chains and FORS
// leaves — the hottest path in the whole scheme. Every byte of PKseed,
// adrs AND tmp affects the output.
func (s *SphinxHashTweak) F(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	M1 := applyMask(s.Variant, PKseed, adrs, tmp)
	return sphinxFastCore(domainF, s.N, PKseed, adrs.GetBytes(), M1)
}

// H is the tweakable hash for Merkle tree internal nodes (combining two
// N-byte children into their parent). Domain-separated from F so a leaf
// value can never be replayed as an internal-node output.
func (s *SphinxHashTweak) H(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	M1 := applyMask(s.Variant, PKseed, adrs, tmp)
	return sphinxFastCore(domainH, s.N, PKseed, adrs.GetBytes(), M1)
}

// T_l is the final compression hash (FORS root concatenation, WOTS+ public
// key compression) — arbitrary-length input, N-byte output.
func (s *SphinxHashTweak) T_l(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	M1 := applyMask(s.Variant, PKseed, adrs, tmp)
	return sphinxFastCore(domainTl, s.N, PKseed, adrs.GetBytes(), M1)
}

// applyMask implements the Robust/Simple variant switch shared by F, H, T_l.
func applyMask(variant string, PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	if variant != Robust {
		return tmp // Simple: no masking
	}
	mask := sphinxMask(PKseed, adrs, len(tmp))
	out := make([]byte, len(tmp))
	_ = subtle.XORBytes(out, tmp, mask)
	return out
}

// ---- once-per-signature, SpxHash-backed (Hmsg, PRFmsg) ----

// spxHashExpand hashes domain||parts with the real, Argon2id-backed
// common.SpxHash (32-byte fixed output), then expands that via SHAKE256 to
// exactly outLen bytes. This is what lets Hmsg return an arbitrary
// MessageDigestLength (which can exceed 32 bytes for larger parameter
// sets) instead of being capped at SpxHash's fixed width or falling back to
// a non-message-dependent zero-pad.
func spxHashExpand(domain byte, outLen int, parts ...[]byte) []byte {
	seed := make([]byte, 0, 1+len(parts)*4)
	seed = append(seed, domain)
	for _, p := range parts {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		seed = append(seed, l[:]...)
		seed = append(seed, p...)
	}

	base := common.SpxHash(seed) // 32 bytes, Argon2id-backed, deterministic (ProtocolSalt)
	if base == nil {
		// common.SpxHash only returns nil on internal hasher construction
		// failure (see getSpxHasher); that's an unrecoverable environment
		// error, not a per-call condition, so fail loudly rather than
		// silently degrade signature security.
		panic("tweakable: common.SpxHash returned nil — SphinxHash instance unavailable")
	}
	if outLen <= len(base) {
		out := make([]byte, outLen)
		copy(out, base)
		return out
	}

	// Expand past 32 bytes via SHAKE256 rather than pad — every output byte
	// stays input-dependent instead of falling back to a fixed pattern.
	out := make([]byte, outLen)
	sq := sha3.NewShake256()
	sq.Write(base)
	sq.Read(out)
	return out
}

// Hmsg generates the message digest used to derive the FORS/tree/leaf
// indices. Called once per signature — the Argon2id cost of common.SpxHash
// is affordable here.
func (s *SphinxHashTweak) Hmsg(R []byte, PKseed []byte, PKroot, M []byte) []byte {
	return spxHashExpand(domainHmsgSlow, s.MessageDigestLength, R, PKseed, PKroot, M)
}

// PRFmsg derives the per-signature randomizer R. Called once per signature.
func (s *SphinxHashTweak) PRFmsg(SKprf []byte, OptRand []byte, M []byte) []byte {
	return spxHashExpand(domainPRFmsgSlow, s.N, SKprf, OptRand, M)
}
