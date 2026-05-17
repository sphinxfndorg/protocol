// Copyright 2024 Lei Ni (nilei81@gmail.com)
//
// This library follows a dual licensing model -
//
// - it is licensed under the 2-clause BSD license if you have written evidence showing that you are a licensee of github.com/lni/pothos
// - otherwise, it is licensed under the GPL-2 license
//
// See the LICENSE file for details
//
// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/network/key.go
package network

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"lukechampine.com/blake3"
)

// IsEmpty checks if the key is zero.
// Iterates through all bytes to verify none have non-zero values
func (k Key) IsEmpty() bool {
	// Iterate through each byte in the key
	for _, b := range k {
		// If any byte is non-zero, the key is not empty
		if b != 0 {
			return false
		}
	}
	// All bytes were zero, key is empty
	return true
}

// Short returns a shortened hexadecimal string of the last 16 bits.
// Useful for logging and display where full keys would be too long
func (k Key) Short() string {
	// Extract last 2 bytes (16 bits) from the key
	// k[30] is the 31st byte, k[31] is the 32nd byte
	// Combine them into a 16-bit unsigned integer
	// Format as 4-character hex string with leading zeros
	return fmt.Sprintf("%04x", uint16(k[30])<<8|uint16(k[31]))
}

// String returns a full hexadecimal string of the key.
// Converts the entire 32-byte key to a 64-character hex string
func (k Key) String() string {
	// Encode all bytes of the key as a hex string
	return hex.EncodeToString(k[:])
}

// Equal compares two keys for equality.
// Parameters:
//   - other: Key to compare against
//
// Returns: true if keys are identical
func (k Key) Equal(other Key) bool {
	// Direct comparison of key arrays
	return k == other
}

// Less compares two keys lexicographically.
// Parameters:
//   - other: Key to compare against
//
// Returns: true if k is lexicographically less than other
func (k Key) Less(other Key) bool {
	// Compare byte by byte lexicographically
	for i := 0; i < 32; i++ {
		if k[i] < other[i] {
			// Current byte is less, key is less
			return true
		} else if k[i] > other[i] {
			// Current byte is greater, key is greater
			return false
		}
		// If equal, continue to next byte
	}
	// All bytes equal, keys are equal (not less)
	return false
}

// leadingZeroBits counts the number of leading zero bits in the key.
// Used in Kademlia for bucket selection and distance calculations
func (k Key) leadingZeroBits() int {
	count := 0
	// Iterate through each byte
	for _, b := range k {
		if b == 0 {
			// Byte is all zeros, count all 8 bits
			count += 8
			continue
		}
		// Count leading zero bits in the current byte
		for i := 7; i >= 0; i-- {
			// Check each bit from most significant to least
			if b&(1<<i) == 0 {
				// Bit is zero, increment count
				count++
			} else {
				// Found first 1 bit, stop counting
				break
			}
		}
		// Stop after finding first non-zero byte with mixed bits
		break
	}
	return count
}

// CommonPrefixLength computes the number of leading bits shared with another key.
// Parameters:
//   - other: Key to compare against
//
// Returns: Number of leading bits that are the same
func (k Key) CommonPrefixLength(other Key) int {
	var r Key
	// Calculate XOR distance between keys
	r.Distance(k, other)
	// Count leading zero bits in the XOR result
	// Leading zero bits indicate matching bits
	return r.leadingZeroBits()
}

// Distance sets k as the XOR result of a and b.
// XOR distance is the standard metric in Kademlia DHT
// Parameters:
//   - a: First key
//   - b: Second key
func (k *Key) Distance(a, b Key) {
	// XOR each byte of the two keys
	for i := 0; i < 32; i++ {
		k[i] = a[i] ^ b[i]
	}
}

// FromNodeID copies a nodeID into the key.
// Parameters:
//   - other: NodeID to copy from
func (k *Key) FromNodeID(other nodeID) {
	// Direct assignment of the entire array
	*k = other
}

// FromString generates a 256-bit key by hashing the input string with BLAKE3.
// Returns an error instead of panicking.
// Parameters:
//   - v: Input string to hash
//
// Returns: Error if key size is insufficient
func (k *Key) FromString(v string) error {
	// Generate BLAKE3 hash of the input string
	// BLAKE3 produces 256-bit (32-by) hashes by default
	hash := blake3.Sum256([]byte(v))

	// Verify the key has enough capacity for the hash
	if len(k) < len(hash) {
		return fmt.Errorf("key size too small: need %d bytes, have %d", len(hash), len(k))
	}

	// Copy the hash into the key
	copy(k[:], hash[:])
	return nil
}

// GenerateKademliaID generates a 256-bit Kademlia ID by hashing the input string.
// Parameters:
//   - input: String to generate ID from
//
// Returns: NodeID derived from the input
func GenerateKademliaID(input string) NodeID {
	var k Key
	// Convert string to key via hashing
	k.FromString(input)
	// Cast Key to NodeID type
	return NodeID(k)
}

// GetRandomNodeID generates a random 256-bit nodeID.
// Uses cryptographically secure random number generator
// Returns: Random NodeID
func GetRandomNodeID() NodeID {
	var k Key
	// Read 32 random bytes into the key
	_, err := rand.Read(k[:])
	if err != nil {
		// Panic on random number generation failure
		// This is critical because secure random is essential for node identity
		panic(err)
	}
	// Cast Key to NodeID type
	return NodeID(k)
}
