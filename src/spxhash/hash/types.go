// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/hash/types.go
package spxhash

import "sync"

// LRUCache is a struct for the LRU cache implementation.
type LRUCache struct {
	capacity int              // Maximum capacity of the cache
	mu       sync.Mutex       // Mutex for concurrent access
	cache    map[uint64]*Node // Maps keys to their corresponding nodes in the cache
	head     *Node            // Pointer to the most recently used node
	tail     *Node            // Pointer to the least recently used node
}

// Node is a doubly linked list node for the LRU cache.
type Node struct {
	key   uint64 // Unique key for the node
	value []byte // Value associated with the key
	prev  *Node  // Pointer to the previous node in the list
	next  *Node  // Pointer to the next node in the list
}

// SphinxHash implements hashing based on SIP-0001 draft.
type SphinxHash struct {
	bitSize      int       // Specifies the bit size of the hash (128, 256, 384, 512)
	data         []byte    // Holds the input data to be hashed
	salt         []byte    // Salt for hashing
	cache        *LRUCache // Cache to store previously computed hashes
	maxCacheSize int       // Maximum cache size
}
