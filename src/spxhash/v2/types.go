// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/hash/types.go
package spxhash

import (
	"hash/maphash"
	"sync"
)

// SIPS-0001 https://github.com/sphinx-core/sips/wiki/SIPS-0001

// CacheKey is a seeded non-cryptographic hash of the input. It only selects
// a bucket; hits are confirmed by comparing the stored input, so a collision
// can never return a wrong digest.
type CacheKey uint64

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
	input []byte   // Copy of the hashed input, compared on every hit
	value []byte   // Cached hash value
	prev  *Node    // Previous (more-recently-used) node
	next  *Node    // Next (less-recently-used) node
}

// SphinxHash implements hashing based on SIPS-0001.
//
// v2 REDESIGN: saltEntropy is removed. In v1 it existed because
// NewSphinxHash separated a caller-supplied "salt" from Argon2-generated
// "entropy" and mixed both into the Argon2id call. v2 has no KDF step — key
// is used directly as the HMAC/SHAKE key (see hashData in spxhash.go) — so
// there is only one key value to track, not two.
type SphinxHash struct {
	bitSize int    // Output bit size: 256, 384, or 512
	data    []byte // Accumulated input data (written via Write)
	key     []byte // Per-instance key: either the caller's fixed value
	// (NewSphinxHash) or freshly random (NewSphinxHashKeyed)
	cache *LRUCache    // LRU cache of previously computed hashes
	seed  maphash.Seed // Per-instance seed for cache-key hashing
}
