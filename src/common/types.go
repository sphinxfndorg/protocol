// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/common/types.go
package common

import (
	"sync"

	spxhash "github.com/sphinxfndorg/protocol/src/spxhash/v2"
)

// Params represents the configuration for SphinxHash.
type Params struct {
	BitSize int
}

// Predefined Params for 256-bit hashing
var spxParams = Params{
	BitSize: 256,
}

// spxHasher is a single, package-level SphinxHash instance shared by every
// call to SpxHash, built lazily on first use and cached thereafter.
//
// FIX SALT (data-derived / hardcoded fallback salt):
// The previous implementation passed the input data itself as the salt
// argument to NewSphinxHash, falling back to a hardcoded literal
// "sphinx-default-salt" only when data was empty. Using data as its own salt
// is not a harmless default — under the original (v1) Argon2id-based
// construction it reduced to argon2.IDKey(data, data, ...), i.e. data used
// as both password and salt, the same anti-pattern spxhash.go's FIX #2
// already eliminated one layer down. It also meant a brand-new SphinxHash
// instance was built on every single call, since no two distinct inputs
// ever shared a salt to reuse, making the per-instance LRU cache useless.
//
// Fix: use spxhash.ProtocolSalt, the fixed, public, non-secret key
// spxhash/hash already defines for exactly this purpose (see params.go) —
// every node derives it independently, so hashes stay reproducible across
// the network without needing data-dependent or ad hoc keys. The instance is
// constructed once and reused, so repeated calls with the same data now
// actually hit the LRU cache instead of recomputing.
//
// v2 REDESIGN NOTE: spxhash/hash dropped Argon2id entirely (see spxhash.go)
// — hashData is now three fast hash calls, no per-call KDF — so reusing this
// instance is no longer about avoiding an expensive Argon2id re-derivation.
// It still matters for two cheaper reasons: (1) it keeps the LRU cache warm
// across calls instead of starting a fresh, empty one every time, and (2) it
// avoids re-copying/re-validating the key on each call. GetHash only reads
// s.key (fixed at construction, a single field in v2 — v1's separate
// s.salt/s.saltEntropy pair no longer exists) and uses its own
// mutex-guarded LRU cache, so sharing this single instance across concurrent
// callers is safe as long as callers only ever invoke SpxHash (never
// Write/Read/Sum/Reset, which would mutate the shared instance's
// accumulated data buffer).
var (
	spxHasher     *spxhash.SphinxHash
	spxHasherOnce sync.Once
	spxHasherErr  error
)

func getSpxHasher() (*spxhash.SphinxHash, error) {
	spxHasherOnce.Do(func() {
		spxHasher, spxHasherErr = spxhash.NewSphinxHash(spxParams.BitSize, spxhash.ProtocolSalt)
	})
	return spxHasher, spxHasherErr
}

// SpxHash hashes the given data using the SphinxHash algorithm with the
// predefined parameters and the protocol's canonical, deterministic salt.
//
// SECURITY: do NOT pass secret material (private keys, seeds, PRF inputs)
// through SpxHash. It goes through a shared LRU cache, so
//   - a cache hit returns measurably faster than a miss, which leaks whether
//     that exact input was hashed recently (a timing side channel), and
//   - the cache retains outputs derived from the input in process memory.
//
// Use SpxHashUncached for secret or one-off inputs (STHINCS's tweakable
// hashes do).
func SpxHash(data []byte) []byte {
	hasher, err := getSpxHasher()
	if err != nil {
		return nil
	}
	return hasher.GetHash(data)
}

// SpxHashUncached is SpxHash without the LRU cache lookup/store. Same
// instance, same key, byte-identical output — it just skips the cache-key
// derivation and cache Get/Put, which cost a full extra hash pass over data
// for no benefit when the caller already knows this exact input won't repeat
// (see SphinxHash.GetHashUncached's doc comment for why that matters).
//
// It is also the right choice for secret inputs: with no cache lookup, its
// timing does not depend on whether the input was seen before, and nothing
// derived from the input is retained in the shared cache.
//
// The shared spxHasher singleton's cache stays reserved for callers that
// DO see repeated inputs; routing one-off callers through this method
// instead of SpxHash also avoids evicting that singleton's genuinely
// reusable entries with cache lines that were never going to hit again.
func SpxHashUncached(data []byte) []byte {
	hasher, err := getSpxHasher()
	if err != nil {
		return nil
	}
	return hasher.GetHashUncached(data)
}
