// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/svm/test/main.go
package main

import (
	"encoding/binary"
	"fmt"

	svm "github.com/sphinxfndorg/protocol/src/core/kernel/opcodes"
	vmachine "github.com/sphinxfndorg/protocol/src/core/kernel/vm"
)

func main() {
	// Test arithmetic operations using stack machine
	fmt.Println("=== Testing Arithmetic Operations ===")

	tests := []struct {
		name     string
		code     []byte
		expected uint64
	}{
		{
			name:     "Xor",
			code:     buildBinaryOpCode(svm.PUSH8, 5, svm.PUSH8, 3, svm.Xor),
			expected: 5 ^ 3,
		},
		{
			name:     "Or",
			code:     buildBinaryOpCode(svm.PUSH8, 5, svm.PUSH8, 3, svm.Or),
			expected: 5 | 3,
		},
		{
			name:     "And",
			code:     buildBinaryOpCode(svm.PUSH8, 5, svm.PUSH8, 3, svm.And),
			expected: 5 & 3,
		},
		{
			name:     "Add",
			code:     buildBinaryOpCode(svm.PUSH8, 10, svm.PUSH8, 15, svm.Add),
			expected: 10 + 15,
		},
		{
			name:     "Not",
			code:     buildUnaryOpCode(svm.PUSH8, 5, svm.Not),
			expected: ^uint64(5),
		},
	}

	for _, test := range tests {
		result, err := vmachine.RunProgram(test.code)
		if err != nil {
			fmt.Printf("%s: Error: %v\n", test.name, err)
			continue
		}

		fmt.Printf("%s(0x%x) = 0x%x (%d) - %v\n",
			test.name,
			getTestValue(test.code),
			result,
			int64(result),
			result == test.expected)
	}

	fmt.Println("\n=== Testing Stack Operations ===")

	// Test DUP
	dupCode := buildUnaryOpCode(svm.PUSH8, 42, svm.DUP)
	result, _ := vmachine.RunProgram(dupCode)
	fmt.Printf("DUP: PUSH 42, DUP -> stack top = %d (expected 42) - %v\n", result, result == 42)

	// Test SWAP
	swapCode := []byte{}
	swapCode = append(swapCode, byte(svm.PUSH8))
	swapCode = append(swapCode, uint64ToBytes(10)...)
	swapCode = append(swapCode, byte(svm.PUSH8))
	swapCode = append(swapCode, uint64ToBytes(20)...)
	swapCode = append(swapCode, byte(svm.SWAP))
	swapCode = append(swapCode, byte(svm.POP)) // pop the swapped value
	result, _ = vmachine.RunProgram(swapCode)
	fmt.Printf("SWAP: PUSH 10, PUSH 20, SWAP, POP -> stack top = %d (expected 10) - %v\n", result, result == 10)
}

func buildBinaryOpCode(op1 svm.OpCode, val1 uint64, op2 svm.OpCode, val2 uint64, resultOp svm.OpCode) []byte {
	code := []byte{}
	code = append(code, byte(op1))
	code = append(code, uint64ToBytes(val1)...)
	code = append(code, byte(op2))
	code = append(code, uint64ToBytes(val2)...)
	code = append(code, byte(resultOp))
	return code
}

func buildUnaryOpCode(pushOp svm.OpCode, val uint64, op svm.OpCode) []byte {
	code := []byte{}
	code = append(code, byte(pushOp))
	code = append(code, uint64ToBytes(val)...)
	code = append(code, byte(op))
	return code
}

func uint64ToBytes(val uint64) []byte {
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, val)
	return bytes
}

func getTestValue(code []byte) uint64 {
	// Find the PUSH8 instruction and extract its value
	for i := 0; i < len(code); i++ {
		if svm.OpCode(code[i]) == svm.PUSH8 && i+8 < len(code) {
			return binary.BigEndian.Uint64(code[i+1 : i+9])
		}
	}
	return 0
}
