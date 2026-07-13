// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/common/types.go
package common

import (
	"sync"

	spxhash "github.com/sphinxfndorg/protocol/src/spxhash/hash"
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
// is not a harmless default — tracing it through generateSalt shows it
// reduces to argon2.IDKey(data, data, ...), i.e. data used as both password
// and salt. That is exactly the anti-pattern spxhash.go's FIX #2 already
// eliminated one layer down; routing it back in through NewSphinxHash's salt
// parameter reintroduces it. It also meant a brand-new SphinxHash instance —
// and therefore a full 19 MiB / 2-iteration Argon2id salt derivation — was
// built on every single call, since no two distinct inputs ever shared a
// salt to reuse, making the per-instance LRU cache useless.
//
// Fix: use spxhash.ProtocolSalt, the fixed, public, non-secret salt
// spxhash/hash already defines for exactly this purpose (see params.go) —
// every node derives it independently, so hashes stay reproducible across
// the network without needing data-dependent or ad hoc salts. The instance
// is constructed once and reused, so repeated calls with the same data now
// actually hit the LRU cache instead of re-deriving Argon2id from scratch.
//
// GetHash only reads s.salt/s.saltEntropy (fixed at construction) and uses
// its own mutex-guarded LRU cache, so sharing this single instance across
// concurrent callers is safe as long as callers only ever invoke SpxHash
// (never Write/Read/Sum/Reset, which would mutate the shared instance's
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
func SpxHash(data []byte) []byte {
	hasher, err := getSpxHasher()
	if err != nil {
		return nil
	}
	return hasher.GetHash(data)
}
