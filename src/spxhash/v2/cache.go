// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/hash/cache.go
package spxhash

import "bytes"

// SIPS-0001 https://github.com/sphinx-core/sips/wiki/SIPS-0001

// NewLRUCache initializes a new LRU cache with the given capacity.
// Capacity must be >= 1; a capacity of 0 would evict every entry immediately.
func NewLRUCache(capacity int) *LRUCache {
	if capacity < 1 {
		capacity = 1
	}
	return &LRUCache{
		capacity: capacity,
		cache:    make(map[CacheKey]*Node),
	}
}

// Get returns a copy of the cached value for key if the stored input equals input.
func (l *LRUCache) Get(key CacheKey, input []byte) ([]byte, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	node, found := l.cache[key]
	if !found || !bytes.Equal(node.input, input) {
		return nil, false
	}
	l.moveToFront(node)
	result := make([]byte, len(node.value))
	copy(result, node.value)
	return result, true
}

// Put stores copies of input and value under key, replacing any entry with the same key.
func (l *LRUCache) Put(key CacheKey, input, value []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()

	buf := make([]byte, len(input)+len(value))
	copy(buf, input)
	copy(buf[len(input):], value)
	in, val := buf[:len(input):len(input)], buf[len(input):]

	if node, found := l.cache[key]; found {
		node.input = in
		node.value = val
		l.moveToFront(node)
		return
	}

	node := &Node{key: key, input: in, value: val}
	l.cache[key] = node

	if l.head == nil {
		l.head = node
		l.tail = node
	} else {
		node.next = l.head
		l.head.prev = node
		l.head = node
	}

	if len(l.cache) > l.capacity {
		l.evict()
	}
}

// evict removes the least-recently-used (tail) node from the cache.
func (l *LRUCache) evict() {
	if l.tail == nil {
		return
	}

	delete(l.cache, l.tail.key)

	if l.head == l.tail {
		l.head = nil
		l.tail = nil
		return
	}

	l.tail = l.tail.prev
	l.tail.next = nil
}

// moveToFront moves node to the head of the list (marks it most-recently used).
// The caller must hold l.mu.
func (l *LRUCache) moveToFront(node *Node) {
	if node == l.head {
		return
	}

	if node.prev != nil {
		node.prev.next = node.next
	}
	if node.next != nil {
		node.next.prev = node.prev
	}

	if node == l.tail {
		l.tail = node.prev
		if l.tail != nil {
			l.tail.next = nil
		}
	}

	node.prev = nil
	node.next = l.head
	if l.head != nil {
		l.head.prev = node
	}
	l.head = node
}
