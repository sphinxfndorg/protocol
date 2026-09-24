// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/hash/params.go
package spxhash

// SIPS-0001 https://github.com/sphinx-core/sips/wiki/SIPS-0001

// v2 REDESIGN (speed/weight reduction, narrowed threat model):
//
// The v1 parameter set (prime64 mixing constant, and Argon2id's memory/
// iterations/parallelism) existed to serve two goals this redesign no
// longer targets:
//   - Argon2id's memory-hardness slows down brute-force PRE-IMAGE search.
//     Pre-image resistance is not a design goal of this version — the
//     properties argued for are length-extension resistance and collision
//     resistance (see spxhash.go). Argon2id and its OWASP-tuned
//     memory/iteration/parallelism knobs are therefore removed entirely,
//     along with the golang.org/x/crypto/argon2 dependency.
//   - prime64 fed a 1000-round avalanche-mixing loop that added no
//     collision- or length-extension-resistance guarantee beyond what the
//     concatenation combiner already provides on its own (see hashData /
//     the A||B combine step in spxhash.go); it only added latency.
//
// What remains below is the minimal parameter set the v2 construction
// actually needs.
const (
	// keySize is the size, in bytes, of the randomly generated key used by
	// NewSphinxHashKeyed. 32 bytes matches SHA-256's output size and gives a
	// 256-bit search space for per-instance keys.
	keySize = 32

	DefaultCacheSize = 100 // Default LRU cache size for SphinxHash
)

// ProtocolSalt is the fixed, public key to use with NewSphinxHash at every
// call site that needs a deterministic, consensus-critical digest —
// transaction hashes, block hashes, Merkle leaves/roots, address derivation,
// or anything else that must be independently reproducible by every node.
//
// This value is NOT a secret — its only purpose is domain separation (so
// SphinxHash output doesn't collide with some other unrelated use of
// SHA-256/SHAKE256), not unpredictability. Writing it as raw bytes instead
// of a string changes nothing about that: it is public either way, and it
// adds no security.
//
// It is written out byte-by-byte on purpose — these are exactly the ASCII
// bytes of "sphinx-protocol-hash-v2" (23 bytes), so every hash is identical
// to the string form. The version tag ("v2") is the last two bytes:
// 0x76 0x32. If you ever change this value, bump that version marker in the
// same commit; TestProtocolSaltUnchanged (params_test.go) pins the exact
// bytes so an accidental edit is caught before it silently forks consensus.
//
// It must never change without a coordinated protocol version bump, since
// changing it changes every resulting hash.
//
// v2 REDESIGN: the value and its role are unchanged from v1 — it is still
// used as the fixed instance key — but it is no longer run through Argon2id
// first. It is used directly as the prefix key for the SHA-256 and SHAKE256
// branches, which is what makes the v2 construction fast: there is no
// per-call KDF cost to pay.
//
// Treat it as read-only: it is an exported slice, so any package can mutate
// it. NewSphinxHash copies the key at construction, so later mutation cannot
// change an existing instance, but mutating it BEFORE the shared hasher is
// first built would silently change every hash on that node.
var ProtocolSalt = []byte{
	0x73, 0x70, 0x68, 0x69, 0x6e, 0x78, 0x2d,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x2d,
	0x68, 0x61, 0x73, 0x68, 0x2d,
	0x76, 0x32,
}
