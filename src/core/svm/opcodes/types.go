// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
