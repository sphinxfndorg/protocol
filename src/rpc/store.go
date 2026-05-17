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
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/minio/highwayhash"
)

// To4KBatches splits values into batches of approximately 3KB.
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

// NewKVStore creates a new in-memory key-value store with HighwayHash.
func NewKVStore() *KVStore {
	highwayKey := make([]byte, 32)
	if _, err := rand.Read(highwayKey); err != nil {
		panic(err)
	}
	h, err := highwayhash.New(highwayKey)
	if err != nil {
		panic(err)
	}
	return &KVStore{
		hash: h,
		data: make(map[Key]*stored),
	}
}

// Put stores a value under a key with a specified TTL.
func (s *KVStore) Put(k Key, v []byte, ttlInSeconds uint16) {
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
	// Deduplicate
	cs := s.getChecksum(v)
	if _, ok := rec.included[cs]; ok {
		return
	}
	rec.ttl = ttl
	rec.values = append(rec.values, v)
	rec.included[cs] = struct{}{}
}

// Get retrieves values associated with a key.
func (s *KVStore) Get(k Key) ([][]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.data[k]
	if !ok {
		return nil, false
	}
	return rec.values, true
}

// GC performs garbage collection on expired key-value entries.
func (s *KVStore) GC() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, stored := range s.data {
		if stored.ttl.Before(now) {
			delete(s.data, key)
		}
	}
}

// getChecksum computes a checksum for a value using HighwayHash.
func (s *KVStore) getChecksum(v []byte) checksum {
	s.hash.Reset()
	if _, err := s.hash.Write(v); err != nil {
		panic(err)
	}
	c := s.hash.Sum(nil)
	if len(c) != 32 {
		panic("unexpected checksum length")
	}
	codec := binary.BigEndian
	return checksum{
		v1: codec.Uint64(c),
		v2: codec.Uint64(c[8:]),
		v3: codec.Uint64(c[16:]),
		v4: codec.Uint64(c[24:]),
	}
}
