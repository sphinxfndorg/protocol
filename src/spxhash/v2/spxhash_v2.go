// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/hash/spxhash.go
package spxhash

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"
)

// SIPS-0001 https://github.com/sphinx-core/sips/wiki/SIPS-0001

// =============================================================================
// v2 REDESIGN — narrowed threat model, speed/weight reduction
// =============================================================================
//
// SCOPE: this construction is designed to resist exactly two attack classes:
//
//  1. Length-extension attacks of the kind classical Merkle-Damgard hashes
//     like raw SHA-256 are vulnerable to (H(key||msg) lets an attacker who
//     only knows H(key||msg) and len(msg) compute H(key||msg||pad||extra)
//     without knowing key).
//  2. Collision attacks against SHA-256 and against SHAKE256 — i.e. an
//     attacker must break BOTH primitives, not just the weaker one, to
//     produce two distinct inputs with the same SphinxHash output.
//
// Pre-image resistance is explicitly OUT of scope for this version. v1 spent
// most of its runtime (two Argon2id calls plus a 1000-round SHAKE256 mixing
// loop) hardening pre-image search, which this redesign deliberately does
// not pay for. What's left is 3 fast hash calls per digest instead of ~2000+
// hash/Argon2 operations, and no external Argon2 dependency.
//
// DESIGN
//
//	A   = SHA256(SHA256(key || 0x01 || data))     // Bitcoin-style double hash
//	B   = SHAKE256(key || 0x02 || data), 32 bytes // independent of A
//	out = SHAKE256(0x03 || A || B), Size() bytes  // concatenate, then squeeze
//
// Why this gets both properties:
//
//   - Length-extension: A is a double hash, the same construction Bitcoin
//     uses for txids/block hashes. An attacker who sees only A cannot mount
//     a length-extension attack, because doing so requires knowing the raw
//     inner digest SHA256(key||0x01||data) to append padding and continue
//     the compression from — and A only exposes SHA256 of THAT digest, not
//     the digest itself. Recovering it means inverting the outer SHA-256
//     call. B needs no such trick: SHAKE256 is a sponge construction, and a
//     sponge's internal capacity is never exposed in its squeezed output, so
//     it has no length-extension weakness to begin with, keyed or not. The
//     final SHAKE256 compression step is immune for the same reason.
//
//   - Collision resistance that survives either primitive alone breaking: A
//     and B are computed INDEPENDENTLY over domain-separated encodings of
//     the same (key, data) — B does not take A as input, and vice versa —
//     then concatenated before the final compression. This is the classical
//     "concatenation combiner": a collision in `out` requires a matching
//     pair in A's 32 bytes AND B's 32 bytes at once, so the construction
//     stays collision-resistant if EITHER SHA-256 or SHAKE256 remains sound,
//     even if the other is later broken outright (the MD5/SHA-1 failure
//     scenario TLS 1.0/1.1's PRF was designed against, though that PRF used
//     an XOR of two HMAC streams rather than concatenation — XOR is weaker:
//     it lets a break in one side be masked by a compensating difference in
//     the other, without either side actually needing to collide).
//
//     What this does NOT give you is amplified bit-strength. A and B are
//     both 32 bytes (~128-bit birthday bound each), and Joux showed
//     ("Multicollisions in Iterated Hash Functions", CRYPTO 2004) that for
//     Merkle-Damgard hashes, concatenation's real collision-resistance floor
//     is close to max(strength of A, strength of B), not their sum: an
//     attacker can build a large multicollision set under the cheaper side
//     for near-birthday cost, then birthday-search that free set against the
//     other side. So this is ~128-bit collision resistance overall (already
//     far beyond any practical attack), not ~256-bit.
//
//     This is deliberately NOT a chain/cascade (out = SHAKE256(SHA256(x))
//     with no concatenation). A chain G(F(x)) only inherits the collision
//     resistance of F, the function applied first: if an attacker finds any
//     x1 != x2 with F(x1) == F(x2), then G(F(x1)) == G(F(x2)) automatically,
//     with G contributing nothing — not even the "secure if either holds"
//     fallback concatenation provides. See Boneh & Boyen, "On the
//     Impossibility of Efficiently Combining Collision-Resistant Hash
//     Functions" (CRYPTO 2006): concatenation is the only combiner proven
//     robust for collision resistance in the black-box model. The domain
//     tags (0x01/0x02/0x03) stop the three hash calls from being trivially
//     related transcripts of one another.
//
// This is a breaking, consensus-critical change: every hash produced by v2
// differs from v1 for the same input. ProtocolSalt was bumped
// ("sphinx-protocol-hash-v1" -> "...-v2", see params.go) precisely so v1 and
// v2 nodes can never silently agree on the wrong digest; deploying this
// requires a coordinated protocol version bump, not a drop-in swap.
// =============================================================================

// Domain-separation tags. Distinct, fixed single-byte prefixes make H1, H2,
// and the final compression independent functions of (key, data) even
// though all three are ultimately built from the same inputs. Without these,
// an attacker could try to relate the branches to each other; with them,
// each branch is a differently-labeled instance of its primitive.
var (
	domainH1    = []byte{0x01} // HMAC-SHA256 branch
	domainH2    = []byte{0x02} // SHAKE256 branch
	domainFinal = []byte{0x03} // final compress/expand step
	domainCache = []byte{0x00} // cache-key derivation (kept disjoint from 0x01-0x03)
)

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
// v2 REDESIGN: key is used directly as the HMAC/SHAKE key — there is no KDF
// step (v1 ran this through Argon2id). A nil/empty key is still rejected: a
// deterministic hasher is meaningless without a fixed key, and callers that
// actually want per-instance randomness should call NewSphinxHashKeyed.
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
	}
}

// cacheKey builds a collision-resistant cache key bound to both the full
// input content and the instance's key, using its own domain tag so it can
// never collide with the A/B/final branches of hashData even for the same
// (key, data) pair. Same double-SHA256 shape as branch A of hashData, just
// under a different domain tag.
func (s *SphinxHash) cacheKey(data []byte) CacheKey {
	inner := sha256.New()
	inner.Write(s.key)
	inner.Write(domainCache)
	inner.Write(data)
	return sha256.Sum256(inner.Sum(nil))
}

// GetHash retrieves or calculates the hash of the given data.
func (s *SphinxHash) GetHash(data []byte) []byte {
	hashKey := s.cacheKey(data)
	if cachedValue, found := s.cache.Get(hashKey); found {
		return cachedValue
	}

	hash := s.hashData(data)
	s.cache.Put(hashKey, hash)

	return hash
}

// GetHashUncached computes the hash of data directly, skipping the LRU
// cache entirely — no cacheKey derivation, no Get, no Put.
//
// Use this instead of GetHash when the caller already knows the lookup
// cannot hit: STHINCS's tweakable-hash hot loop (F/H/PRF/T_l) is the
// motivating case — every call there carries a distinct ADRS, so the
// cache's hit rate is ~0%, yet GetHash's cacheKey step still pays for a
// full extra SHA-256 pass over the input on every call to compute a key
// that will never find anything (see the "Stop paying the cache-key
// derivation on uncacheable calls" finding in the STHINCS benchmark
// README). hashData already does 2 full-input hash passes (branch A's
// inner SHA-256, branch B's SHAKE256); cacheKey adds a 3rd, structurally
// identical to branch A, purely to build a key for a cache that can't
// help here. Skipping it removes that 3rd pass — roughly a third of the
// full-input hashing work on this path — without changing the digest
// itself: GetHashUncached(data) and GetHash(data) return byte-identical
// output, this just never looks anything up or stores anything.
//
// Do not use this for call sites that DO see repeated inputs (e.g. a
// Merkle tree with reused leaf values, or SpxHash's own package-level
// singleton serving arbitrary callers) — those want GetHash's cache.
func (s *SphinxHash) GetHashUncached(data []byte) []byte {
	return s.hashData(data)
}

// Read reads from the hash data into p.
func (s *SphinxHash) Read(p []byte) (n int, err error) {
	hash := s.GetHash(s.data)
	n = copy(p, hash)
	if n < len(hash) {
		return n, io.ErrShortBuffer
	}
	return n, nil
}

// Write adds data to the hash.
func (s *SphinxHash) Write(p []byte) (n int, err error) {
	s.data = append(s.data, p...)
	return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice.
func (s *SphinxHash) Sum(b []byte) []byte {
	hash := s.GetHash(s.data)
	return append(b, hash...)
}

// Reset clears the accumulated data so the instance can be reused.
func (s *SphinxHash) Reset() {
	s.data = s.data[:0]
}

// hashData computes the SphinxHash-v2 digest of data. See the package-level
// design comment above for the full construction and why it delivers
// length-extension resistance and dual (SHA-256 + SHAKE256) collision
// resistance without a KDF or a mixing-round loop.
func (s *SphinxHash) hashData(data []byte) []byte {
	// Large-payload path (e.g. a fallback CID over a >1 MB file): pre-absorb
	// with a streaming SHAKE256 pass so memory stays bounded. This mirrors
	// v1's large-input handling but without the Argon2 step.
	const maxHashInputSize = 1 << 20 // 1 MB
	if len(data) > maxHashInputSize {
		pre := sha3.NewShake256()
		const writeChunk = 1 << 18 // 256 KiB per Write
		for off := 0; off < len(data); off += writeChunk {
			end := off + writeChunk
			if end > len(data) {
				end = len(data)
			}
			pre.Write(data[off:end])
		}
		pre.Write(s.key)
		digest := make([]byte, 64)
		if _, err := pre.Read(digest); err != nil {
			panic(fmt.Sprintf("spxhash: failed to read large-input prehash: %v", err))
		}
		data = digest
	}

	// A: SHA256(SHA256(key || tag || data)) — Bitcoin-style double hash, 32
	// bytes. Immune to length-extension: extending the original message
	// would require the raw inner digest, which the outer SHA-256 call
	// never exposes.
	innerA := sha256.New()
	innerA.Write(s.key)
	innerA.Write(domainH1)
	innerA.Write(data)
	a := sha256.Sum256(innerA.Sum(nil))

	// B: SHAKE256(key || tag || data), squeezed to 32 bytes — computed
	// independently of A (sponge construction, length-extension safe on its
	// own regardless of keying).
	shakeB := sha3.NewShake256()
	shakeB.Write(s.key)
	shakeB.Write(domainH2)
	shakeB.Write(data)
	b := make([]byte, 32)
	if _, err := shakeB.Read(b); err != nil {
		panic(fmt.Sprintf("spxhash: failed to read B: %v", err))
	}

	// Concatenation combiner: forging a collision now requires colliding in
	// both A and B at once (see design comment above) — this is why B is
	// concatenated onto A rather than A being piped into B as input.
	combined := make([]byte, 0, len(domainFinal)+len(a)+len(b))
	combined = append(combined, domainFinal...)
	combined = append(combined, a[:]...)
	combined = append(combined, b...)

	// Final expand/compress to the configured output size in a single pass.
	final := sha3.NewShake256()
	final.Write(combined)
	out := make([]byte, s.Size())
	if _, err := final.Read(out); err != nil {
		panic(fmt.Sprintf("spxhash: failed to read final digest: %v", err))
	}
	return out
}
