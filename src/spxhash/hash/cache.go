// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/hash/cache.go
package spxhash

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

// Get retrieves the cached value for key.
// Returns a defensive copy of the value and true on a hit, nil and false on a miss.
//
// FIX G: The original implementation returned the cached slice directly.
// A caller that modified the returned slice would silently corrupt the cached
// value, causing subsequent hits to return wrong data. Get now returns a copy
// so the caller owns the bytes it receives.
func (l *LRUCache) Get(key CacheKey) ([]byte, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if node, found := l.cache[key]; found {
		l.moveToFront(node)
		// FIX G: return a copy, not a reference into the cache's own storage.
		result := make([]byte, len(node.value))
		copy(result, node.value)
		return result, true
	}
	return nil, false
}

// Put inserts or updates a key-value pair in the cache.
// A defensive copy of value is stored so the caller retains ownership of its slice.
//
// FIX G: Store a copy of value so that later mutations by the caller do not
// corrupt the cached entry.
func (l *LRUCache) Put(key CacheKey, value []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// FIX G: take a copy before storing.
	stored := make([]byte, len(value))
	copy(stored, value)

	if node, found := l.cache[key]; found {
		node.value = stored
		l.moveToFront(node)
		return
	}

	node := &Node{key: key, value: stored}
	l.cache[key] = node

	if l.head == nil {
		// Cache is empty: this node is both head and tail.
		l.head = node
		l.tail = node
	} else {
		// Prepend to the front of the list.
		node.next = l.head
		l.head.prev = node
		l.head = node
	}

	if len(l.cache) > l.capacity {
		l.evict()
	}
}

// evict removes the least-recently-used (tail) node from the cache.
//
// FIX #6: The original implementation did not update l.head when the cache
// held exactly one node (head == tail). After eviction l.tail was set to nil
// but l.head still pointed to the freed node, corrupting the list on the next
// Put call. The fix resets both l.head and l.tail to nil when the last node
// is removed.
func (l *LRUCache) evict() {
	if l.tail == nil {
		return // Cache is already empty; nothing to do.
	}

	delete(l.cache, l.tail.key)

	if l.head == l.tail {
		// FIX #6: Only one node existed. Reset both sentinels so the list is
		// left in a clean empty state rather than leaving l.head dangling.
		l.head = nil
		l.tail = nil
		return
	}

	// General case: unlink the tail and move the sentinel back one step.
	l.tail = l.tail.prev
	l.tail.next = nil
}

// moveToFront moves node to the head of the list (marks it most-recently used).
// The caller must hold l.mu.
func (l *LRUCache) moveToFront(node *Node) {
	if node == l.head {
		return // Already at the front.
	}

	// Unlink node from its current position.
	if node.prev != nil {
		node.prev.next = node.next
	}
	if node.next != nil {
		node.next.prev = node.prev
	}

	// If node was the tail, promote its predecessor.
	if node == l.tail {
		l.tail = node.prev
		if l.tail != nil {
			l.tail.next = nil
		}
	}

	// Splice node in at the front.
	node.prev = nil
	node.next = l.head
	if l.head != nil {
		l.head.prev = node
	}
	l.head = node
}
