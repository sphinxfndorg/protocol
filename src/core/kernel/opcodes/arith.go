// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/svm/opcodes/arith.go
package svm

import "fmt"

// ========== BITWISE OPERATIONS ==========

// XorOp - Bitwise XOR (exclusive OR)
func XorOp(a, b uint64) uint64 {
	return a ^ b
}

// OrOp - Bitwise OR (inclusive OR)
func OrOp(a, b uint64) uint64 {
	return a | b
}

// AndOp - Bitwise AND
func AndOp(a, b uint64) uint64 {
	return a & b
}

// NotOp - Bitwise NOT (inverts all bits)
func NotOp(a uint64) uint64 {
	return ^a
}

// ShrOp - Bitwise right shift (logical shift)
func ShrOp(a uint64, n uint) uint64 {
	return a >> n
}

// ShlOp - Bitwise left shift (logical shift)
func ShlOp(a uint64, n uint) uint64 {
	return a << n
}

// SarOp - Arithmetic right shift (preserves sign bit)
func SarOp(a uint64, n uint) uint64 {
	// Convert to int64 for arithmetic shift, then back to uint64
	return uint64(int64(a) >> n)
}

// ByteOp - Get Nth byte from word (0 = most significant)
func ByteOp(a uint64, n uint) uint64 {
	if n >= 8 {
		return 0
	}
	// Extract byte at position n (0 = most significant)
	return (a >> (56 - 8*n)) & 0xFF
}

// ========== ARITHMETIC OPERATIONS ==========

// AddOp - Addition (mod 2^64, wraps on overflow)
func AddOp(a, b uint64) uint64 {
	return a + b // Go will naturally overflow here
}

// AddOp32 - Addition modulo 2^32 (for 32-bit compatibility)
func AddOp32(a, b uint64) uint64 {
	return (a + b) % (1 << 32)
}

// SubOp - Subtraction (mod 2^64, wraps on underflow)
func SubOp(a, b uint64) uint64 {
	return a - b // Go will naturally underflow
}

// MulOp - Multiplication (mod 2^64, wraps on overflow)
func MulOp(a, b uint64) uint64 {
	return a * b
}

// DivOp - Unsigned integer division
func DivOp(a, b uint64) (uint64, error) {
	if b == 0 {
		return 0, fmt.Errorf("division by zero")
	}
	return a / b, nil
}

// SDivOp - Signed integer division
func SDivOp(a, b int64) (int64, error) {
	if b == 0 {
		return 0, fmt.Errorf("division by zero")
	}
	return a / b, nil
}

// ModOp - Unsigned modulo operation
func ModOp(a, b uint64) (uint64, error) {
	if b == 0 {
		return 0, fmt.Errorf("modulo by zero")
	}
	return a % b, nil
}

// SModOp - Signed modulo operation (result has sign of divisor)
func SModOp(a, b int64) (int64, error) {
	if b == 0 {
		return 0, fmt.Errorf("modulo by zero")
	}
	return a % b, nil
}

// ExpOp - Exponentiation (a ^ b)
func ExpOp(a, b uint64) uint64 {
	if b == 0 {
		return 1
	}
	if a == 0 {
		return 0
	}
	result := uint64(1)
	for i := uint64(0); i < b; i++ {
		result *= a
	}
	return result
}

// SignExtendOp - Sign extend from b bits to 256 bits (simplified for uint64)
func SignExtendOp(a uint64, b uint64) uint64 {
	if b >= 7 {
		return a
	}
	// Check if the sign bit is set
	signBit := (a >> (8*b + 7)) & 1
	if signBit == 1 {
		// Extend with ones
		mask := (uint64(1) << (8*b + 8)) - 1
		return a | ^mask
	}
	return a
}

// ========== COMPARISON OPERATIONS ==========

// LtOp - Less than comparison
func LtOp(a, b uint64) uint64 {
	if a < b {
		return 1
	}
	return 0
}

// GtOp - Greater than comparison
func GtOp(a, b uint64) uint64 {
	if a > b {
		return 1
	}
	return 0
}

// SlTOp - Signed less than comparison
func SlTOp(a, b int64) uint64 {
	if a < b {
		return 1
	}
	return 0
}

// SgTOp - Signed greater than comparison
func SgTOp(a, b int64) uint64 {
	if a > b {
		return 1
	}
	return 0
}

// EqOp - Equality comparison
func EqOp(a, b uint64) uint64 {
	if a == b {
		return 1
	}
	return 0
}

// IsZeroOp - Check if value is zero
func IsZeroOp(a uint64) uint64 {
	if a == 0 {
		return 1
	}
	return 0
}

// ========== BITCOIN SCRIPT OPERATIONS ==========

// CatOp - Concatenate two byte slices (OP_CAT)
// Note: This is the classic Bitcoin opcode that was disabled
func CatOp(a, b []byte) ([]byte, error) {
	const maxConcatSize = 520 // Bitcoin's maximum stack element size
	if len(a)+len(b) > maxConcatSize {
		return nil, fmt.Errorf("concatenated size exceeds %d bytes", maxConcatSize)
	}
	result := make([]byte, 0, len(a)+len(b))
	result = append(result, a...)
	result = append(result, b...)
	return result, nil
}

// SubStrOp - Extract substring from byte slice (OP_SUBSTR)
func SubStrOp(data []byte, start, length uint64) ([]byte, error) {
	if start >= uint64(len(data)) {
		return []byte{}, nil
	}
	end := start + length
	if end > uint64(len(data)) {
		end = uint64(len(data))
	}
	return data[start:end], nil
}

// LeftOp - Take leftmost bytes (OP_LEFT)
func LeftOp(data []byte, length uint64) ([]byte, error) {
	if length >= uint64(len(data)) {
		return data, nil
	}
	return data[:length], nil
}

// RightOp - Take rightmost bytes (OP_RIGHT)
func RightOp(data []byte, length uint64) ([]byte, error) {
	if length >= uint64(len(data)) {
		return data, nil
	}
	return data[uint64(len(data))-length:], nil
}

// SizeOp - Get size of data (OP_SIZE)
func SizeOp(data []byte) uint64 {
	return uint64(len(data))
}

// SplitOp - Split data at position (OP_SPLIT)
func SplitOp(data []byte, position uint64) ([]byte, []byte, error) {
	if position > uint64(len(data)) {
		return nil, nil, fmt.Errorf("split position exceeds data length")
	}
	return data[:position], data[position:], nil
}

// ========== UTILITY OPERATIONS ==========

// MinOp - Minimum of two values
func MinOp(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// MaxOp - Maximum of two values
func MaxOp(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// AbsOp - Absolute value (for signed integers)
func AbsOp(a int64) uint64 {
	if a < 0 {
		return uint64(-a)
	}
	return uint64(a)
}

// ClampOp - Clamp value between min and max
func ClampOp(a, minVal, maxVal uint64) uint64 {
	if a < minVal {
		return minVal
	}
	if a > maxVal {
		return maxVal
	}
	return a
}

// ========== ADDITIONAL BITCOIN STACK OPERATIONS ==========

// DepthOp - Get stack depth
func DepthOp(stackSize int) uint64 {
	return uint64(stackSize)
}

// NipOp - Remove second item from stack
func NipOp(stack []uint64) ([]uint64, error) {
	if len(stack) < 2 {
		return nil, fmt.Errorf("stack underflow")
	}
	top := stack[len(stack)-1]
	return append(stack[:len(stack)-2], top), nil
}

// OverOp - Copy second item to top
func OverOp(stack []uint64) ([]uint64, error) {
	if len(stack) < 2 {
		return nil, fmt.Errorf("stack underflow")
	}
	second := stack[len(stack)-2]
	return append(stack, second), nil
}

// PickOp - Pick item from depth n
func PickOp(stack []uint64, n uint64) ([]uint64, error) {
	if uint64(len(stack)) <= n {
		return nil, fmt.Errorf("stack underflow")
	}
	idx := len(stack) - 1 - int(n)
	val := stack[idx]
	return append(stack, val), nil
}

// RollOp - Move item at depth n to top
func RollOp(stack []uint64, n uint64) ([]uint64, error) {
	if uint64(len(stack)) <= n {
		return nil, fmt.Errorf("stack underflow")
	}
	idx := len(stack) - 1 - int(n)
	val := stack[idx]
	// Remove element at idx
	stack = append(stack[:idx], stack[idx+1:]...)
	return append(stack, val), nil
}

// RotOp - Rotate top three items
func RotOp(stack []uint64) ([]uint64, error) {
	if len(stack) < 3 {
		return nil, fmt.Errorf("stack underflow")
	}
	a := stack[len(stack)-1]
	b := stack[len(stack)-2]
	c := stack[len(stack)-3]
	stack = stack[:len(stack)-3]
	stack = append(stack, b)
	stack = append(stack, a)
	stack = append(stack, c)
	return stack, nil
}

// TuckOp - Copy top item to third position
func TuckOp(stack []uint64) ([]uint64, error) {
	if len(stack) < 2 {
		return nil, fmt.Errorf("stack underflow")
	}
	top := stack[len(stack)-1]
	second := stack[len(stack)-2]
	stack = stack[:len(stack)-2]
	stack = append(stack, top)
	stack = append(stack, second)
	stack = append(stack, top)
	return stack, nil
}
