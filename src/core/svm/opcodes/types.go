// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/svm/test/types.go
package svm

// OpCode represents an instruction in the SVM
// Each opcode is a single byte (0x00 to 0xFF) that tells the VM what operation to perform
// The VM fetches this byte from the code, then executes the corresponding logic
type OpCode byte

// Stack represents the execution stack for the SVM
// The stack is a LIFO (Last-In-First-Out) data structure that holds operands
// All operations pop values from the stack and push results back
type Stack struct {
	data []uint64 // Stack data stored as 64-bit unsigned integers (uint64)
	// Using uint64 allows the stack to hold addresses, lengths, and hash fragments
}
