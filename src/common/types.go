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
// SpxHashUncached, keyed with the immutable v2 protocol salt (not the mutable
// spxhash.ProtocolSalt slice) and built once on first use. Sharing it keeps the
// LRU cache warm across calls. Construction failure is fatal: returning a nil
// digest would let every input collide at call sites that do not check it.
var (
	spxHasher     *spxhash.SphinxHash
	spxHasherOnce sync.Once
)

func getSpxHasher() *spxhash.SphinxHash {
	spxHasherOnce.Do(func() {
		h, err := spxhash.NewProtocolHash(spxParams.BitSize)
		if err != nil {
			panic("common: cannot build protocol hasher: " + err.Error())
		}
		spxHasher = h
	})
	return spxHasher
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
	return getSpxHasher().GetHash(data)
}

// SpxHashUncached is SpxHash without the cache: same instance, same key,
// byte-identical output. It stores nothing and its timing does not depend on
// prior calls, so use it for secret inputs and for inputs that won't repeat
// (it also avoids evicting entries that will). A miss through SpxHash costs
// an extra allocation and copy in Put that this path skips.
func SpxHashUncached(data []byte) []byte {
	return getSpxHasher().GetHashUncached(data)
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
// It panics if dst is shorter than SpxHashDigestSize().
func SpxHashUncachedInto(dst, data []byte) []byte {
	return getSpxHasher().HashIntoUncached(dst, data)
}

// SpxHashDigestSize returns the digest length in bytes for the shared
// instance's configured bit size, so a caller can size a buffer for
// SpxHashUncachedInto.
func SpxHashDigestSize() int {
	return getSpxHasher().Size()
}
