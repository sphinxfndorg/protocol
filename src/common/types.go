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

var spxParams = Params{
	BitSize: 256,
}

// spxHasher is the shared SphinxHash instance used by SpxHash and
// SpxHashUncached, keyed with spxhash.ProtocolSalt and built once on first
// use. Sharing it keeps the LRU cache warm across calls. It is safe for
// concurrent use as long as callers only invoke GetHash/GetHashUncached
// (never Write/Read/Sum/Reset, which mutate the accumulated data buffer).
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

// SpxHash hashes data with SphinxHash under the protocol's canonical salt.
// Inputs up to spxhash.MaxCachedInputSize go through the shared LRU cache;
// larger inputs bypass it.
//
// SECURITY: do NOT pass secret material (private keys, seeds, PRF inputs).
//   - A cache hit is measurably faster than a miss, leaking whether that exact
//     input was hashed recently.
//   - The cache keeps a verbatim copy of each cached input, plus its digest,
//     in process memory.
//
// Use SpxHashUncached for secret or one-off inputs.
func SpxHash(data []byte) []byte {
	hasher, err := getSpxHasher()
	if err != nil {
		return nil
	}
	return hasher.GetHash(data)
}

// SpxHashUncached is SpxHash without the cache: same instance, same key,
// byte-identical output. It stores nothing and its timing does not depend on
// prior calls, so use it for secret inputs and for inputs that won't repeat
// (it also avoids evicting entries that will). A miss through SpxHash costs
// an extra allocation and copy in Put that this path skips.
func SpxHashUncached(data []byte) []byte {
	hasher, err := getSpxHasher()
	if err != nil {
		return nil
	}
	return hasher.GetHashUncached(data)
}

// SpxHashUncachedInto is SpxHashUncached writing into a caller-supplied
// buffer instead of allocating. dst must be at least SpxHashDigestSize() bytes;
// exactly that many bytes are written, dst is never retained, and the return
// value is dst[:size:size].
//
// Callers that immediately consume the digest (copy it out, or feed it to
// another hash) should prefer this: profiling a STHINCS signature showed the
// per-call digest allocation was the largest single source of allocated
// objects, for a buffer whose lifetime is a few instructions.
//
// On hasher-construction failure it returns nil, matching SpxHashUncached.
func SpxHashUncachedInto(dst, data []byte) []byte {
	hasher, err := getSpxHasher()
	if err != nil {
		return nil
	}
	return hasher.HashIntoUncached(dst, data)
}

// SpxHashDigestSize returns the digest length in bytes for the shared
// instance's configured bit size, so a caller can size a buffer for
// SpxHashUncachedInto. Returns 0 if the shared hasher cannot be built.
func SpxHashDigestSize() int {
	hasher, err := getSpxHasher()
	if err != nil {
		return 0
	}
	return hasher.Size()
}
