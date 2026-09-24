// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/tweakable/spxhash.go
package tweakable

import (
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
// as valid under a completely different key. Every function below absorbs
// every one of its arguments — none of this input-independence can come
// back.
//
// UNIFIED DESIGN (v2 supersedes the old call-frequency split):
//
// This type used to split its six functions across two different backends:
// Hmsg/PRFmsg (called once per signature) went through common.SpxHash,
// while F/H/PRF/T_l (called ~1.8 MILLION times per signature, across WOTS+
// chains, XMSS trees, and FORS leaves) used a separate, hand-rolled
// SHA-512/256 + SHAKE256 "fast core" instead — because common.SpxHash was,
// at the time, backed by v1's Argon2id-based SphinxHash (19 MiB, t=2),
// measured at ~38ms per call. At 1.8M calls with no cache reuse (every call
// here uses a distinct ADRS, so the shared instance's LRU cache almost never
// hit), that projected to ~19 HOURS per signature — using common.SpxHash for
// the hot loop was simply not viable.
//
// common.SpxHash is now backed by spxhash/hash's v2 construction (double
// SHA-256 + SHAKE256, see spxhash/hash/spxhash.go) — no Argon2id, no KDF, ~3
// fast hash calls per digest instead of a memory-hard derivation. Measured
// on this machine that's low-microsecond, not tens of milliseconds: at 1.8M
// calls, roughly 3 SECONDS per signature (see the benchmark comparison
// above this file's history), not 19 hours. The reason for the two-backend
// split is gone, so every function below now goes through the same
// common.SpxHash-backed helper, spxHashExpand. This means every tweak
// function — Hmsg, PRF, PRFmsg, F, H, T_l — is now genuinely
// SphinxHash-branded (SIPS-0001), not just the two that used to be called
// once per signature.
//
// If you're tempted to reintroduce a separate fast path because a benchmark
// looked slow: check whether spxhash/hash's own construction changed under
// you (a future v3 that reintroduces a KDF, say) before assuming this file
// needs to change — the split existed because of Argon2id specifically, not
// because of hot-loop call volume in the abstract.
type SphinxHashTweak struct {
	Variant             string
	MessageDigestLength int
	N                   int
}

// Domain separation tags, one per tweakable function, so no two of them can
// ever produce a colliding transcript into common.SpxHash for the same raw
// arguments.
const (
	domainHmsg   byte = 0x01
	domainPRF    byte = 0x02
	domainPRFmsg byte = 0x03
	domainF      byte = 0x04
	domainH      byte = 0x05
	domainTl     byte = 0x06
	domainMask   byte = 0x07
)

// spxHashExpand hashes domain||length-prefixed(parts) with common.SpxHash
// (v2-backed: SHA-256 double-hash + SHAKE256, see spxhash/hash/spxhash.go),
// then expands that 32-byte result via SHAKE256 to exactly outLen bytes.
// Length-prefixing every field makes the encoding unambiguous — without it,
// spxHashExpand(d, n, "ab", "c") and spxHashExpand(d, n, "a", "bc") would
// collide.
func spxHashExpand(domain byte, outLen int, parts ...[]byte) []byte {
	seed := make([]byte, 0, 1+len(parts)*4)
	seed = append(seed, domain)
	for _, p := range parts {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		seed = append(seed, l[:]...)
		seed = append(seed, p...)
	}

	base := common.SpxHash(seed) // 32 bytes, v2-backed, deterministic (ProtocolSalt)
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
// indices. Called once per signature.
func (s *SphinxHashTweak) Hmsg(R []byte, PKseed []byte, PKroot, M []byte) []byte {
	return spxHashExpand(domainHmsg, s.MessageDigestLength, R, PKseed, PKroot, M)
}

// PRF derives an N-byte pseudorandom value from a secret seed and an ADRS.
// Called on the order of hundreds of thousands of times per signature.
func (s *SphinxHashTweak) PRF(SEED []byte, adrs *address.ADRS) []byte {
	return spxHashExpand(domainPRF, s.N, SEED, adrs.GetBytes())
}

// PRFmsg derives the per-signature randomizer R. Called once per signature.
func (s *SphinxHashTweak) PRFmsg(SKprf []byte, OptRand []byte, M []byte) []byte {
	return spxHashExpand(domainPRFmsg, s.N, SKprf, OptRand, M)
}

// F is the tweakable compression hash used inside WOTS+ chains and FORS
// leaves — the hottest path in the whole scheme. Every byte of PKseed, adrs
// AND tmp affects the output.
func (s *SphinxHashTweak) F(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	M1 := applyMask(s.Variant, PKseed, adrs, tmp)
	return spxHashExpand(domainF, s.N, PKseed, adrs.GetBytes(), M1)
}

// H is the tweakable hash for Merkle tree internal nodes (combining two
// N-byte children into their parent). Domain-separated from F so a leaf
// value can never be replayed as an internal-node output.
func (s *SphinxHashTweak) H(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	M1 := applyMask(s.Variant, PKseed, adrs, tmp)
	return spxHashExpand(domainH, s.N, PKseed, adrs.GetBytes(), M1)
}

// T_l is the final compression hash (FORS root concatenation, WOTS+ public
// key compression) — arbitrary-length input, N-byte output.
func (s *SphinxHashTweak) T_l(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	M1 := applyMask(s.Variant, PKseed, adrs, tmp)
	return spxHashExpand(domainTl, s.N, PKseed, adrs.GetBytes(), M1)
}

// applyMask implements the Robust/Simple variant switch shared by F, H, T_l.
// The bitmask itself is now also common.SpxHash-backed (via spxHashExpand),
// under its own domain tag so it can never be mistaken for an actual F/H/T_l
// output even when PKseed, adrs, and length happen to match.
func applyMask(variant string, PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	if variant != Robust {
		return tmp // Simple: no masking
	}
	mask := spxHashExpand(domainMask, len(tmp), PKseed, adrs.GetBytes())
	out := make([]byte, len(tmp))
	_ = subtle.XORBytes(out, tmp, mask)
	return out
}
