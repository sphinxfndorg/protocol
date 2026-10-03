// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/hash/spxhash.go
package spxhash

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash/maphash"
	"io"

	"golang.org/x/crypto/sha3"
)

// SIPS-0001 https://github.com/sphinx-core/sips/wiki/SIPS-0001

// =============================================================================
// SpxHash v2 — narrowed threat model, speed/weight reduction
// =============================================================================
//
// This is still SpxHash v2. Branch A is a single SHA-512/256 call (an earlier
// v2 draft used a double SHA-256); everything else is unchanged.
//
// SCOPE: this construction is designed to resist exactly two attack classes:
//
//  1. Length-extension attacks of the kind classical Merkle-Damgard hashes
//     like raw SHA-256 are vulnerable to (H(key||msg) lets an attacker who
//     only knows H(key||msg) and len(msg) compute H(key||msg||pad||extra)
//     without knowing key).
//  2. Collision attacks against SHA-512/256 and against SHAKE256 — i.e. an
//     attacker must break BOTH primitives, not just the weaker one, to
//     produce two distinct inputs with the same SphinxHash output.
//
// Pre-image resistance is not a DESIGN GOAL of this version. That is a
// statement about what the construction is argued to provide, not a claim
// that it is weak: it still ends in 256-bit primitives, and callers such as
// STHINCS (whose WOTS+ chains rely on one-wayness) should not read "out of
// scope" as "safe to break". Do not use it to hash passwords or other
// low-entropy secrets; use Argon2id/scrypt/PBKDF2 for that.
//
// DESIGN
//
//	A   = SHA512/256(key || 0x01 || data)         // 32 bytes
//	B   = SHAKE256(key || 0x02 || data), 32 bytes // independent of A
//	out = SHAKE256(0x03 || A || B), Size() bytes  // concatenate, then squeeze
//
// Inputs larger than 1 MB are first compressed to a 64-byte prehash,
// SHA512/256(key || 0x10 || data) || SHAKE256(key || 0x13 || data) (32 bytes
// each), so the prehash keeps the two-primitive collision property, and then
// run through the same construction under DIFFERENT domain tags (0x11/0x12)
// so a large input can never collide with a small input that happens to equal
// its prehash. See prepare.
//
// Why this gets both properties:
//
//   - Length-extension: SHA-512/256 is SHA-512 with its output truncated to
//     256 bits. The 512-bit internal state is never fully exposed — an
//     attacker who sees A learns only 256 of the 512 state bits and would
//     have to guess the other 256 to continue the compression. That is why
//     the truncated SHA-2 variants are the standard answer to length
//     extension, and why no outer SHA-256 call is needed.
//     B needs no such trick: SHAKE256 is a sponge, and a sponge's capacity is
//     never exposed in its squeezed output, so it has no length-extension
//     weakness to begin with, keyed or not. The final SHAKE256 compression
//     step is immune for the same reason.
//
//   - Collision resistance that survives either primitive alone breaking: A
//     and B are computed INDEPENDENTLY over domain-separated encodings of
//     the same (key, data) — B does not take A as input, and vice versa —
//     then concatenated before the final compression. This is the classical
//     "concatenation combiner": a collision in `out` requires a matching
//     pair in A's 32 bytes AND B's 32 bytes at once, so the construction
//     stays collision-resistant if EITHER SHA-512/256 or SHAKE256 remains
//     sound, even if the other is later broken outright.
//
//     What this does NOT give you is amplified bit-strength. A and B are
//     both 32 bytes (~128-bit birthday bound each), and Joux showed
//     ("Multicollisions in Iterated Hash Functions", CRYPTO 2004) that for
//     Merkle-Damgard hashes, concatenation's real collision-resistance floor
//     is close to max(strength of A, strength of B), not their sum. So this
//     is ~128-bit collision resistance overall, not ~256-bit.
//
//     This is deliberately NOT a chain/cascade (out = SHAKE256(SHA512/256(x))
//     with no concatenation). A chain G(F(x)) only inherits the collision
//     resistance of F, the function applied first. See Boneh & Boyen, "On the
//     Impossibility of Efficiently Combining Collision-Resistant Hash
//     Functions" (CRYPTO 2006): concatenation is the only combiner proven
//     robust for collision resistance in the black-box model. The domain
//     tags (0x01/0x02/0x03) stop the three hash calls from being trivially
//     related transcripts of one another.
//
// SPEED: 3 hash calls per digest. Branch A is one SHA-512/256 pass instead
// of a double SHA-256 (two or three compressions plus an outer one). Measured
// against the earlier double-SHA-256 draft with HashIntoUncached on one core:
// ~23% faster at 77 B, ~20% at 109 B, ~13% at 141 B, ~9% at 600 B, ~20% at
// 2221 B. The gain is noisy and hardware-dependent: CPUs with SHA-NI favour
// SHA-256, so re-measure on your target machines.
//
// Every digest differs from the earlier double-SHA-256 draft for the same
// input, and ProtocolSalt is unchanged, so the two can no longer be told
// apart by salt. Any pinned vector, golden signature or stored hash produced
// by that draft must be regenerated.
// =============================================================================

// Domain-separation tags. Distinct, fixed single-byte prefixes make the two
// branches and the final compression independent functions of (key, data)
// even though all three are ultimately built from the same inputs. Without
// these, an attacker could try to relate the branches to each other; with
// them, each branch is a differently-labeled instance of its primitive.
//
// The key is fixed per instance, so "key || tag || ..." is unambiguous: the
// tag always sits at the same offset, and inputs under different tags can
// never produce the same transcript.
var (
	domainH1    = []byte{0x01} // branch A tag: SHA-512/256
	domainH2    = []byte{0x02} // branch B tag: SHAKE256
	domainFinal = []byte{0x03} // final compress/expand step

	// Large-input path (> maxHashInputSize). The 64-byte prehash that
	// replaces the data must NOT be indistinguishable from a genuine 64-byte
	// input: the key is public, so anyone can compute the prehash of a big
	// file, and without separate tags hash(bigFile) == hash(prehash(bigFile))
	// — a trivial second preimage. Separate tags make the two transcripts
	// differ at the tag byte.
	domainPre     = []byte{0x10} // prehash tag, SHA-512/256 half
	domainPreB    = []byte{0x13} // prehash tag, SHAKE256 half
	domainH1Large = []byte{0x11} // branch A tag for prehashed input
	domainH2Large = []byte{0x12} // branch B tag for prehashed input
)

// maxHashInputSize is the largest input hashed directly; anything bigger is
// prehashed with a streaming SHAKE256 pass so memory stays bounded.
const maxHashInputSize = 1 << 20 // 1 MB

// protocolSaltV2 is the immutable source of truth for ProtocolSalt. The exported
// ProtocolSalt slice can be mutated by any package; NewProtocolHash ignores it.
const protocolSaltV2 = "sphinx-protocol-hash-v2"

// NewProtocolHash returns a deterministic SphinxHash keyed with the v2 protocol
// salt, immune to later mutation of the exported ProtocolSalt slice. Prefer it
// for every consensus-critical call site.
func NewProtocolHash(bitSize int) (*SphinxHash, error) {
	return NewSphinxHash(bitSize, []byte(protocolSaltV2))
}

// NewSphinxHash creates a new, DETERMINISTIC SphinxHash with a specific bit
// size for the hash.
//
// This is the constructor to use anywhere the output must be independently
// reproducible by another process, another node, or another call — for
// example transaction hashes, block hashes, Merkle leaves/roots, or address
// derivation from a public key. Given the same bitSize and the same key,
// GetHash(data) always returns the same bytes, no matter which instance or
// process computed it.
//
// key is used directly as the prefix key for the SHA-512/256 and SHAKE256
// branches — there is no KDF step (v1 ran this through Argon2id). A
// nil/empty key is still rejected: a deterministic hasher is meaningless
// without a fixed key, and callers that actually want per-instance
// randomness should call NewSphinxHashKeyed.
func NewSphinxHash(bitSize int, key []byte) (*SphinxHash, error) {
	if bitSize != 256 && bitSize != 384 && bitSize != 512 {
		return nil, fmt.Errorf("spxhash: unsupported bitSize %d (must be 256, 384, or 512)", bitSize)
	}
	if len(key) == 0 {
		return nil, errors.New("spxhash: NewSphinxHash requires a non-empty key for deterministic hashing; use NewSphinxHashKeyed for randomized, per-instance hashing")
	}

	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	return &SphinxHash{
		bitSize: bitSize,
		key:     keyCopy,
		cache:   NewLRUCache(DefaultCacheSize),
		seed:    maphash.MakeSeed(),
	}, nil
}

// NewSphinxHashKeyed creates a new, RANDOMIZED SphinxHash with a specific bit
// size for the hash.
//
// Each call produces an instance with its own fresh, cryptographically
// random key, so two instances created by NewSphinxHashKeyed will (with
// overwhelming probability) produce different output for the same input.
//
// Do not use this constructor anywhere the resulting hash must be
// independently reproduced by another process or node.
func NewSphinxHashKeyed(bitSize int) (*SphinxHash, error) {
	if bitSize != 256 && bitSize != 384 && bitSize != 512 {
		return nil, fmt.Errorf("spxhash: unsupported bitSize %d (must be 256, 384, or 512)", bitSize)
	}

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, errors.New("spxhash: failed to read random key: " + err.Error())
	}

	return &SphinxHash{
		bitSize: bitSize,
		key:     key,
		cache:   NewLRUCache(DefaultCacheSize),
		seed:    maphash.MakeSeed(),
	}, nil
}

// Size returns the output length in bytes for this instance's configured
// bitSize: 256 -> 32, 384 -> 48, 512 -> 64.
func (s *SphinxHash) Size() int {
	return s.bitSize / 8
}

// EncodedSalt returns the key bytes used by this instance.
//
// For instances created with NewSphinxHash, this returns the caller's own
// fixed key (echoed back), which is already known and shared. For instances
// created with NewSphinxHashKeyed, this is the only way to recover the
// random key that made the instance unique, and it must be persisted if the
// hash needs to be reproduced later.
func (s *SphinxHash) EncodedSalt() []byte {
	out := make([]byte, len(s.key))
	copy(out, s.key)
	return out
}

// Clone returns a deep copy of s with the same key and bitSize but an empty
// accumulated data buffer and a fresh cache.
func (s *SphinxHash) Clone() *SphinxHash {
	keyCopy := make([]byte, len(s.key))
	copy(keyCopy, s.key)
	return &SphinxHash{
		bitSize: s.bitSize,
		key:     keyCopy,
		cache:   NewLRUCache(DefaultCacheSize),
		seed:    maphash.MakeSeed(),
	}
}

// GetHash retrieves or calculates the hash of the given data.
// Inputs larger than MaxCachedInputSize bypass the cache.
func (s *SphinxHash) GetHash(data []byte) []byte {
	if len(data) > MaxCachedInputSize {
		return s.hashData(data)
	}
	key := CacheKey(maphash.Bytes(s.seed, data))
	if v, ok := s.cache.Get(key, data); ok {
		return v
	}
	out := s.hashData(data)
	s.cache.Put(key, data, out)
	return out
}

// GetHashUncached computes the hash of data directly, skipping the LRU
// cache entirely: no cache-key derivation, no Get, no Put.
//
// Use this instead of GetHash when the caller already knows the lookup
// cannot hit: STHINCS's tweakable-hash hot loop (F/H/PRF/T_l) is the
// motivating case. Every call there carries a distinct ADRS, so the
// cache's hit rate is ~0%, and GetHash would still pay for a maphash pass,
// a lock, a map probe and a Put (a copy of the input) on every call for a
// lookup that will never find anything.
//
// GetHashUncached(data) and GetHash(data) return byte-identical output;
// this just never looks anything up or stores anything.
//
// Safe for concurrent use: it only reads s.key and s.bitSize.
//
// Do not use this for call sites that DO see repeated inputs (e.g. a
// Merkle tree with reused leaf values, or SpxHash's own package-level
// singleton serving arbitrary callers) — those want GetHash's cache.
func (s *SphinxHash) GetHashUncached(data []byte) []byte {
	return s.hashData(data)
}

// HashIntoUncached computes the digest of data directly (no cache lookup, no
// key derivation, no store) and writes it into dst, returning dst[:Size()].
//
// CONTRACT:
//   - len(dst) must be >= Size(), or this panics. It is a caller-owned buffer,
//     so the caller must size it.
//   - Exactly Size() bytes are written. Nothing beyond that is touched.
//   - The hasher does NOT retain dst: it is not stored on the receiver and is
//     not referenced after this call returns, so the caller may reuse or wipe
//     the buffer immediately.
//   - The RETURNED SLICE IS dst[:Size():Size()] — i.e. it deliberately aliases
//     the caller's buffer. That is the point: the caller gets the digest
//     without an allocation. The full slice expression caps it at Size() so an
//     append by the caller cannot write into the caller's spare capacity. A
//     caller who needs the digest to outlive (or survive mutation of) the
//     buffer must copy it — use GetHashUncached for that.
//
// This exists because the digest is almost always consumed immediately by the
// caller (copied out, or fed as input to another hash) rather than retained.
// Allocating a fresh 32-byte slice per call and then throwing it away is pure
// waste, and profiling a STHINCS signature showed finish()'s output was the
// single largest source of allocations by object count — one per hash call,
// for a buffer whose lifetime is a few instructions.
//
// Byte-for-byte identical to GetHashUncached(data); see
// TestHashIntoMatchesGetHashUncached and TestHashIntoDoesNotRetainInternally.
func (s *SphinxHash) HashIntoUncached(dst, data []byte) []byte {
	if len(dst) < s.Size() {
		panic(fmt.Sprintf("spxhash: HashIntoUncached destination too small: have %d bytes, need %d", len(dst), s.Size()))
	}
	out := s.hashDataInto(data, dst[:s.Size()])
	return out[:s.Size():s.Size()]
}

// Read reads from the hash data into p.
func (s *SphinxHash) Read(p []byte) (n int, err error) {
	s.dmu.Lock()
	defer s.dmu.Unlock()
	hash := s.GetHash(s.data)
	n = copy(p, hash)
	if n < len(hash) {
		return n, io.ErrShortBuffer
	}
	return n, nil
}

// Write adds data to the hash.
func (s *SphinxHash) Write(p []byte) (n int, err error) {
	s.dmu.Lock()
	defer s.dmu.Unlock()
	s.data = append(s.data, p...)
	return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice.
func (s *SphinxHash) Sum(b []byte) []byte {
	s.dmu.Lock()
	defer s.dmu.Unlock()
	hash := s.GetHash(s.data)
	return append(b, hash...)
}

// Reset clears the accumulated data so the instance can be reused.
func (s *SphinxHash) Reset() {
	s.dmu.Lock()
	defer s.dmu.Unlock()
	if cap(s.data) > maxHashInputSize {
		s.data = nil
		return
	}
	s.data = s.data[:0]
}

// hashData computes the SpxHash v2 digest of data, allocating the result.
// Callers that already own a buffer should use HashIntoUncached instead, which
// writes into it and skips this allocation.
func (s *SphinxHash) hashData(data []byte) []byte {
	return s.hashDataInto(data, make([]byte, s.Size()))
}

// hashDataInto is hashData writing into a caller-supplied buffer. dst must be
// at least Size() bytes (HashIntoUncached checks); it is written in full and
// never retained.
func (s *SphinxHash) hashDataInto(data, dst []byte) []byte {
	if len(s.key) == 0 || s.bitSize == 0 {
		panic("spxhash: uninitialized SphinxHash; use NewSphinxHash, NewProtocolHash or NewSphinxHashKeyed")
	}
	tagB, d, a := s.prepare(data)
	return s.finish(tagB, d, a, dst)
}

// finish completes the construction from branch A's digest, writing the result
// into dst and returning it. Callers own dst; finish does not retain it.
func (s *SphinxHash) finish(tagB, d []byte, a [32]byte, dst []byte) []byte {
	shakeB := sha3.NewShake256()
	shakeB.Write(s.key)
	shakeB.Write(tagB)
	shakeB.Write(d)
	var b [32]byte
	if _, err := shakeB.Read(b[:]); err != nil {
		panic(fmt.Sprintf("spxhash: failed to read B: %v", err))
	}

	var combined [1 + 32 + 32]byte
	combined[0] = domainFinal[0]
	copy(combined[1:], a[:])
	copy(combined[33:], b[:])

	final := sha3.NewShake256()
	final.Write(combined[:])
	if _, err := final.Read(dst); err != nil {
		panic(fmt.Sprintf("spxhash: failed to read final digest: %v", err))
	}
	return dst
}

// prepare applies the large-input prehash if needed and returns the branch-B
// tag, the effective data, and branch A's digest SHA512/256(key || tagA || d).
func (s *SphinxHash) prepare(data []byte) (tagB, d []byte, a [32]byte) {
	tagA := domainH1
	tagB = domainH2
	d = data

	if len(data) > maxHashInputSize {
		preA := sha512.New512_256()
		preA.Write(s.key)
		preA.Write(domainPre)
		preB := sha3.NewShake256()
		preB.Write(s.key)
		preB.Write(domainPreB)
		const writeChunk = 1 << 18
		for off := 0; off < len(data); off += writeChunk {
			end := off + writeChunk
			if end > len(data) {
				end = len(data)
			}
			preA.Write(data[off:end])
			preB.Write(data[off:end])
		}
		digest := make([]byte, 64)
		preA.Sum(digest[:0])
		if _, err := preB.Read(digest[32:]); err != nil {
			panic(fmt.Sprintf("spxhash: failed to read large-input prehash: %v", err))
		}
		d = digest
		tagA, tagB = domainH1Large, domainH2Large
	}

	h := sha512.New512_256()
	h.Write(s.key)
	h.Write(tagA)
	h.Write(d)
	h.Sum(a[:0])
	return
}
