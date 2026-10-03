// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/tweakable/spxhash.go
package tweakable

import (
	"crypto/subtle"
	"encoding/binary"
	"runtime"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/address"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/util"
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
// back. (tweakable_test.go checks this for every backend, and
// sthincs_test.go checks cross-message and cross-key verification.)
//
// UNIFIED DESIGN (v2 supersedes the old call-frequency split):
//
// This type used to split its six functions across two different backends:
// Hmsg/PRFmsg (called once per signature) went through common.SpxHash,
// while F/H/PRF/T_l (on the order of a million calls per signature, across
// WOTS+ chains, XMSS trees, and FORS leaves) used a separate, hand-rolled
// SHA-512/256 + SHAKE256 "fast core" instead — because common.SpxHash was,
// at the time, backed by v1's Argon2id-based SphinxHash (19 MiB, t=2),
// measured at ~38ms per call. With no cache reuse (every call here uses a
// distinct ADRS, so the shared instance's LRU cache almost never hit), that
// projected to ~19 HOURS per signature — using common.SpxHash for the hot
// loop was simply not viable.
//
// The hash package's v2 construction (SHA-512/256 + SHAKE256, see
// spxhash/hash/spxhash.go) has no Argon2id and no KDF: ~3 fast hash calls
// per digest, low-microsecond instead of tens of milliseconds. The reason
// for the two-backend split is gone, so every function below now goes
// through the same helper, spxHashExpand, which calls
// common.SpxHashUncached. Every tweak function — Hmsg, PRF, PRFmsg, F, H,
// T_l — is therefore genuinely SphinxHash-branded (SIPS-0001).
//
// MEASURED COST: the per-signature cost is NOT a flat "calls x per-call
// cost": the call count scales with N, K, D, and logT, and the Robust
// variants make two hash calls (mask + hash) per F/H/T_l. Measured with
// BenchmarkSpxSignConstructors before the GetHashUncached change, the
// SPHINXHASH sets ranged from ~355 ms (128f-simple) to ~24.5 s
// (256s-robust) per signature. Re-run the benchmark rather than
// extrapolating from this comment.
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
// ever produce a colliding transcript into common.SpxHashUncached for the
// same raw arguments.
const (
	domainHmsg   byte = 0x01
	domainPRF    byte = 0x02
	domainPRFmsg byte = 0x03
	domainF      byte = 0x04
	domainH      byte = 0x05
	domainTl     byte = 0x06
	domainMask   byte = 0x07
)

// seedStackBound is the stack-allocated size of the hash-input scratch buffer.
//
// CHOSEN FROM MEASUREMENT, not guesswork. `seeder_max_total_test.go`
// (TestReportSeedTotals) computes the exact `total` that spxHashExpand derives
// for every call type across all 36 parameter sets:
//
//	PRF(SEED=N, adrs=32)          57 .. 73
//	F(PKseed, adrs, tmp=N)        77 .. 109
//	H(PKseed, adrs, tmp=2N)       93 .. 141     <- largest hot case
//	T_l(PKseed, adrs, Len*N)    621 .. 2221     <- WOTS+ pk compression
//	T_l(PKseed, adrs, K*N)      285 .. 1197     <- FORS roots
//	Hmsg(R, PKseed, PKroot, M)  129 .. 177     (M is the caller's, unbounded)
//
// So 256 covers every HOT call type (PRF/F/H) on the stack across all 36 sets,
// while T_l — whose input is genuinely Len*N or K*N bytes — falls back to the
// heap. That is the right split: T_l runs O(K + D) times per signature, while
// F/H/PRF run on the order of 10^6 times, so the hot paths are exactly the
// ones worth keeping allocation-free.
//
// 256 bytes is also cheap to zero relative to what it saves: the fallback it
// replaces is a heap allocation of the same size, and the hash it feeds is
// ~1500 ns, so a 256-byte stack clear is noise next to it.
const seedStackBound = 256

// digestStackBound is the stack-allocated size of the intermediate digest
// buffer in spxHashExpand.
//
// 64 covers every digest this hasher can produce at its supported sizes
// (256/384/512-bit -> 32/48/64 bytes). Anything larger falls back to the heap,
// so a future size cannot silently overflow the stack buffer.
const digestStackBound = 64

// spxHashExpand hashes domain||length-prefixed(parts) with
// common.SpxHashUncached (v2-backed: SHA-512/256 + SHAKE256, see
// spxhash/hash/spxhash.go), then expands that 32-byte result via SHAKE256 to
// exactly outLen bytes. Length-prefixing every field makes the encoding
// unambiguous — without it, spxHashExpand(d, n, "ab", "c") and
// spxHashExpand(d, n, "a", "bc") would collide.
//
// THE ENCODING IS UNCHANGED. Two buffers live here rather than three:
// `seed` (the input, stack-resident when small) and `base` (the digest, stack
// -resident). `out` is heap-allocated because it is returned and becomes a tree
// node, an auth path or signature bytes — it is allocated with its exact length
// and returned as out[:outLen:outLen] so no caller can append into spare
// capacity.
func spxHashExpand(domain byte, outLen int, parts ...[]byte) []byte {
	// Exact capacity: one append chain, no regrowth in the hot loop.
	total := 1
	for _, p := range parts {
		total += 4 + len(p)
	}

	// Hot path (PRF/F/H): the compiler proves `stack` never escapes, so this
	// is a stack write, not a heap allocation. Escape analysis
	// (`go build -gcflags=-m=1`) reports the makes as non-escaping.
	var stack [seedStackBound]byte
	var seed []byte
	if total <= seedStackBound {
		seed = stack[:0]
	} else {
		seed = make([]byte, 0, total)
	}

	seed = append(seed, domain)
	for _, p := range parts {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		seed = append(seed, l[:]...)
		seed = append(seed, p...)
	}

	// The digest buffer: written by HashIntoUncached, read below, never
	// retained. common.SpxHashUncachedInto is a direct concrete call (not an
	// interface method), so these arrays provably stay on the stack.
	var dstack [digestStackBound]byte
	var dbuf []byte
	if digest := common.SpxHashDigestSize(); digest <= digestStackBound {
		dbuf = dstack[:digest]
	} else {
		dbuf = make([]byte, digest)
	}

	// SpxHashUncachedInto never returns nil: an unavailable shared hasher
	// panics inside common, so there is no per-call failure to handle here.
	base := common.SpxHashUncachedInto(dbuf, seed)
	// The seed holds WOTS+ chain values and PRF output — derived secret
	// material. On the heap path the allocator may retain those bytes; on the
	// stack path the frame is reused and overwritten. Wiping here is what
	// makes the heap fallback safe; measured cost is under 1% (see the README).
	util.Wipe(seed)

	// Wipe the whole backing array as well, not just len(seed) bytes.
	//
	// On the stack path seed aliases stack, and len(seed) is only the bytes
	// this call appended. stack[total:seedStackBound] was not written here,
	// but a reused frame can still hold a previous call's seed there: an
	// earlier invocation with a larger total would have written further into
	// the same array. util.Wipe(seed) cannot reach those bytes, so without
	// this the function leaves part of an older seed in the frame.
	//
	// On the heap path seed does not alias stack and this wipes an array that
	// was never written; it is cheap (seedStackBound bytes) and keeps the
	// handling uniform across both branches.
	util.Wipe(stack[:])

	// KeepAlive is a compiler barrier, not a memory operation: it costs nothing
	// at runtime. It is required because nothing reads seed or stack again on
	// any path out of this function, which makes the writes in the Wipe calls
	// look like dead stores that the optimizer is free to delete. KeepAlive
	// marks both as reachable at this point, so the stores must actually
	// happen.
	//
	// Do not remove this on the grounds that seed is stack-resident. On the
	// stack path a reused frame can still hold the previous call's seed bytes,
	// and on the heap path the allocator may retain them; the wipe is what
	// clears both, and it only counts if the compiler is forced to emit it.
	runtime.KeepAlive(seed)
	runtime.KeepAlive(&stack)

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
// The bitmask itself is also SpxHashUncached-backed (via spxHashExpand),
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
