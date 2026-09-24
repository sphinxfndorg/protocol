// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/hash/types.go
package spxhash

import "sync"

// SIPS-0001 https://github.com/sphinx-core/sips/wiki/SIPS-0001

// CacheKey indexes entries in LRUCache.
//
// FIX WIDE (birthday-bound cache-key collisions):
// Previously the cache key was a uint64 — the truncated first 8 bytes of a
// cryptographic digest. A uint64 key space has only a ~2^32 birthday bound:
// given a fast enough hash, an attacker who knows the (public) instance
// salt can search for two distinct inputs whose keys collide in well under
// a day on commodity hardware. Since spxhash.go's cacheKey previously
// compensated for this with Argon2id (memory-hard, ~1ms/op) rather than a
// wider key, every cache lookup — hit or miss — paid Argon2id's cost just
// to stay ahead of a collision search on a key space that was too small to
// begin with.
//
// CacheKey is now the full 32-byte output of a fast keyed hash (see
// cacheKey in spxhash.go), giving a ~2^128 birthday bound. That is strong
// enough to use a fast hash instead of a memory-hard KDF: the defense comes
// from key-space width, not from making each guess expensive.
type CacheKey [32]byte

// LRUCache is a thread-safe LRU cache backed by a doubly-linked list and a map.
type LRUCache struct {
	capacity int                // Maximum number of entries the cache can hold
	mu       sync.Mutex         // Mutex guarding all cache operations
	cache    map[CacheKey]*Node // Maps cache keys to linked-list nodes
	head     *Node              // Most-recently-used node
	tail     *Node              // Least-recently-used node
}

// Node is a doubly-linked list node used internally by LRUCache.
type Node struct {
	key   CacheKey // Cache key
	value []byte   // Cached hash value
	prev  *Node    // Previous (more-recently-used) node
	next  *Node    // Next (less-recently-used) node
}

// SphinxHash implements hashing based on SIPS-0001.
//
// FIX K: maxCacheSize removed — it was set in NewSphinxHash but never read
// anywhere; enforcement is handled entirely by LRUCache.capacity. Keeping dead
// fields in the struct wastes memory and misleads maintainers.
type SphinxHash struct {
	bitSize     int    // Output bit size: 256, 384, or 512
	data        []byte // Accumulated input data (written via Write)
	salt        []byte // Per-instance derived salt for Argon2 key derivation
	saltEntropy []byte // Random entropy used when deriving the salt; included
	// in the cache key (FIX F) and available for MarshalBinary (FIX E) so that
	// the salt can be reconstructed for cross-process verification.
	cache *LRUCache // LRU cache of previously computed hashes
}
