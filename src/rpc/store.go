// Copyright 2024 Lei Ni (nilei81@gmail.com)
//
// This library follows a dual licensing model -
//
// - it is licensed under the 2-clause BSD license if you have written evidence showing that you are a licensee of github.com/lni/pothos
// - otherwise, it is licensed under the GPL-2 license
//
// See the LICENSE file for details
// https://github.com/lni/dht/tree/main
//
// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/rpc/store.go
package rpc

import (
	"encoding/binary"
	"time"

	"lukechampine.com/blake3"
)

// NewKVStore creates a new in-memory key-value store.
// BLAKE3 is stateless so no keying material or pre-initialisation is required.
func NewKVStore() *KVStore {
	return &KVStore{
		data: make(map[Key]*stored),
	}
}

// To4KBatches splits a slice of byte slices into batches whose cumulative size
// stays below 3 KB, suitable for fitting inside a 4 KB UDP payload alongside
// framing overhead.
func To4KBatches(values [][]byte) [][][]byte {
	results := make([][][]byte, 0)
	total := 0
	current := make([][]byte, 0)

	for _, value := range values {
		if total+len(value) >= 3*1024 {
			results = append(results, current)
			current = make([][]byte, 0)
			total = 0
		}
		current = append(current, value)
		total += len(value)
	}

	if len(current) > 0 {
		results = append(results, current)
	}

	return results
}

// Put stores a value under k with the specified TTL (in seconds).
//
// Deduplication is performed via a BLAKE3 content checksum so that the same
// value is never stored twice under the same key.  The checksum is computed
// outside the mutex because blake3.Sum256 is a pure, allocation-free function
// with no shared state — calling it concurrently is safe and avoids holding
// the lock longer than necessary.
func (s *KVStore) Put(k Key, v []byte, ttlInSeconds uint16) {
	// Compute checksum before acquiring the lock — blake3.Sum256 is stateless
	// and goroutine-safe, so this is safe to do without any synchronisation.
	cs := s.getChecksum(v)

	s.mu.Lock()
	defer s.mu.Unlock()

	ttl := time.Now().Add(time.Duration(ttlInSeconds) * time.Second)

	rec, ok := s.data[k]
	if !ok {
		rec = &stored{
			values:   make([][]byte, 0),
			included: make(map[checksum]struct{}),
		}
		s.data[k] = rec
	}

	// Skip duplicate values — O(1) map lookup on the checksum struct.
	if _, exists := rec.included[cs]; exists {
		return
	}

	rec.ttl = ttl
	rec.values = append(rec.values, v)
	rec.included[cs] = struct{}{}
}

// Get returns all values stored under k and whether the key was found.
// The returned slice is a direct reference to internal storage; callers must
// not mutate it.
func (s *KVStore) Get(k Key) ([][]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.data[k]
	if !ok {
		return nil, false
	}

	return rec.values, true
}

// GC removes all records whose TTL has elapsed.  It should be called
// periodically (e.g. from a background goroutine) to prevent unbounded memory
// growth.
func (s *KVStore) GC() {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	for key, rec := range s.data {
		if rec.ttl.Before(now) {
			delete(s.data, key)
		}
	}
}

// getChecksum returns a collision-resistant BLAKE3-256 checksum for v.
//
// blake3.Sum256 is a pure function: it creates no shared state and is safe to
// call from multiple goroutines simultaneously without any locking.  This
// replaces the previous HighwayHash-based approach, which:
//
//   - used a non-cryptographic hash (susceptible to collision crafting by
//     adversarial peers in a P2P network), and
//   - required a shared, stateful hash.Hash object protected by the store
//     mutex, serialising all checksum computations.
func (s *KVStore) getChecksum(v []byte) checksum {
	digest := blake3.Sum256(v) // [32]byte — stack-allocated, no heap pressure

	codec := binary.BigEndian
	return checksum{
		v1: codec.Uint64(digest[0:8]),
		v2: codec.Uint64(digest[8:16]),
		v3: codec.Uint64(digest[16:24]),
		v4: codec.Uint64(digest[24:32]),
	}
}
