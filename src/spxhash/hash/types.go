// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/hash/types.go
package spxhash

import "sync"

// SIPS-0001 https://github.com/sphinx-core/sips/wiki/SIPS-0001

// LRUCache is a thread-safe LRU cache backed by a doubly-linked list and a map.
type LRUCache struct {
	capacity int              // Maximum number of entries the cache can hold
	mu       sync.Mutex       // Mutex guarding all cache operations
	cache    map[uint64]*Node // Maps cache keys to linked-list nodes
	head     *Node            // Most-recently-used node
	tail     *Node            // Least-recently-used node
}

// Node is a doubly-linked list node used internally by LRUCache.
type Node struct {
	key   uint64 // Cache key
	value []byte // Cached hash value
	prev  *Node  // Previous (more-recently-used) node
	next  *Node  // Next (less-recently-used) node
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
