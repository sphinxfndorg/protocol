// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/address/util.go
package util

import (
	"fmt"
	"math"
)

// Package util provides common utility functions for STHINCS implementation
//
// This file contains low-level helper functions for:
// - Integer to byte array conversion (big-endian encoding)
// - Byte array to integer conversion
// - Base-w representation conversion (used in WOTS+)
//
// All functions follow the STHINCS specification requirements for
// endianness and encoding formats.

// ToByte converts an unsigned integer to a big-endian byte array of specified length
//
// Mathematical operation:
// For input x (uint64) and output length L, produces bytes b[0..L-1] such that:
//
//	x = sum_{i=0}^{L-1} b[i] * 256^{L-1-i}
//
// This is the standard big-endian (network byte order) representation.
//
// Parameters:
//
//	in: Non-negative integer to convert (0 to 2^64-1)
//	outlen: Desired output length in bytes (1 to 8 typically, but can be larger)
//	        For values >8 bytes, the higher bytes will be zero-padded.
//
// Returns: outlen-byte slice containing big-endian representation
//
// Implementation details:
// - Processes bytes from least significant to most (right to left)
// - Extracts 8 bits at a time using bitmask 0xff
// - Shifts right by 8 bits after each byte extraction
// - Fills output from rightmost position (big-endian order)
//
// Examples:
//
//	ToByte(0x1234, 4) -> [0x00, 0x00, 0x12, 0x34]
//	ToByte(0x12345678, 4) -> [0x12, 0x34, 0x56, 0x78]
//	ToByte(0x01, 8) -> [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
//
// STHINCS usage:
// Used extensively for encoding addresses and indices into ADRS structures.
// All multi-byte integers in STHINCS use big-endian encoding as per spec.
func ToByte(in uint64, outlen int) []byte {
	out := make([]byte, outlen)

	// Fill from rightmost byte to leftmost (big-endian)
	// i = outlen-1 (last byte) down to 0 (first byte)
	for i := outlen - 1; i >= 0; i-- {
		// Extract least significant 8 bits
		out[i] = byte(in & 0xff)

		// Shift right by 8 bits for next iteration
		// This processes the next more significant byte
		in = in >> 8
	}
	return out
}

// BytesToUint64 converts a big-endian byte slice to uint64
//
// Mathematical operation:
// For input bytes b[0..L-1] (L <= 8), computes:
//
//	result = sum_{i=0}^{L-1} b[i] * 256^{L-1-i}
//
// This is the inverse of ToByte for L <= 8.
//
// Parameters:
//
//	in: Big-endian encoded byte slice (length 1-8 bytes)
//
// Returns: Decoded uint64 value
//
// Implementation details:
// - Iterates from leftmost byte (most significant) to rightmost
// - For each byte, shifts existing result left by 8 bits (multiply by 256)
// - Adds the current byte value
// - Handles variable input lengths gracefully
//
// Example:
//
//	BytesToUint64([0x12, 0x34, 0x56, 0x78]) = 0x12345678
//
// Security note: No overflow checking since input limited to 8 bytes
func BytesToUint64(in []byte) uint64 {
	res := uint64(0)

	// Process bytes from left (most significant) to right (least significant)
	for i := 0; i < len(in); i++ {
		// Shift existing result left by 8 bits (make room for next byte)
		// Then OR with current byte value
		res = res | (uint64(in[i]) << (8 * (len(in) - 1 - i)))
	}
	return res
}

// BytesToUint32 converts a big-endian byte slice to uint32
//
// Similar to BytesToUint64 but for 32-bit values.
// Input length should be <= 4 bytes, but function works for any length
// by only using the least significant 32 bits of the result.
//
// Mathematical operation:
// For input bytes b[0..L-1] (L <= 4), computes:
//
//	result = sum_{i=0}^{L-1} b[i] * 256^{L-1-i}
//
// Parameters:
//
//	in: Big-endian encoded byte slice (length 1-4 bytes typically)
//
// Returns: Decoded uint32 value (truncated to 32 bits)
//
// Implementation: Same as BytesToUint64 but with uint32 arithmetic
//
// STHINCS usage:
// Used for extracting ADRS fields (KeyPairAddress, TreeIndex, etc.)
// which are 32-bit values in the specification.
func BytesToUint32(in []byte) uint32 {
	res := uint32(0)

	for i := 0; i < len(in); i++ {
		res = res | (uint32(in[i]) << (8 * (len(in) - 1 - i)))
	}
	return res
}

// Base_w converts a byte slice to base-w representation
//
// Mathematical concept:
// Base-w representation expresses a number using digits in [0, w-1]
// where w is typically a power of 2 (Winternitz parameter).
//
// In WOTS+, we need to convert the message digest (and checksum) into
// base-w digits. Each base-w digit determines how many times to iterate
// the hash function in each WOTS+ chain.
//
// Algorithm:
// The input byte slice X is treated as a big-endian integer of length len(X) bytes.
// We extract digits by reading bits from this integer:
//  1. Read w bits at a time (where w = log2(W) bits)
//  2. Each group of w bits forms one base-w digit
//  3. Output out_len digits (padded with zeros if needed)
//
// Parameters:
//
//	X: Input byte slice (treated as big-endian integer)
//	w: Base value (must be power of 2, e.g., 16, 256)
//	out_len: Number of base-w digits to output
//
// Returns: Slice of out_len integers, each in [0, w-1]
//
// Implementation details:
// This is a streaming bit reader that processes the input byte by byte:
// - Maintains 'total' buffer that holds pending bits
// - 'bits' tracks how many valid bits are in the buffer
// - When bits < log2(w), read another byte
// - Extract log2(w) bits from the buffer to form next digit
// - Shift buffer to remove consumed bits
//
// Example with w=16 (4 bits per digit):
//
//	Input: X = [0x12, 0x34] = 0x1234 (binary: 0001 0010 0011 0100)
//	Output digits: 1, 2, 3, 4 (4 bits each)
//
// STHINCS usage:
// This is critical for WOTS+ signature generation and verification.
// The message digest is converted to base-w digits, then each digit
// determines how many hash iterations to apply to each WOTS+ chain.
// util.go - Updated Base_w function
func Base_w(X []byte, w int, out_len int) ([]int, error) {
	// Validate w is power of 2
	if w&(w-1) != 0 || w < 2 {
		return nil, fmt.Errorf("w must be power of 2 >= 2, got %d", w)
	}

	bitsPerDigit := int(math.Log2(float64(w)))
	totalBitsNeeded := out_len * bitsPerDigit
	bytesNeeded := (totalBitsNeeded + 7) / 8

	if len(X) < bytesNeeded {
		return nil, fmt.Errorf("input too short: need at least %d bytes, have %d", bytesNeeded, len(X))
	}

	in := 0
	out := 0
	total := 0
	bits := 0
	basew := make([]int, out_len)

	for consumed := 0; consumed < out_len; consumed++ {
		if bits == 0 {
			total = int(X[in])
			in++
			bits += 8
		}
		bits -= bitsPerDigit
		basew[out] = (total >> bits) & (w - 1)
		out++
	}
	return basew, nil
}
