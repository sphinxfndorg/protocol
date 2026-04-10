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

// go/src/core/svm/vm/vm.go
package vm

import (
	"fmt"

	svm "github.com/sphinxorg/protocol/src/core/svm/opcodes"
)

// NewVM initializes a new VM instance with the given bytecode
// Creates a stack, allocates 1MB memory, sets program counter to 0
func NewVM(code []byte) *VM {
	return &VM{
		stack:  svm.NewStack(),
		memory: make([]byte, 1024*1024), // 1 MB of memory for data storage
		pc:     0,
		code:   code,
	}
}

// Run executes the bytecode loaded in the VM
// Fetches opcodes one by one and executes them using ExecuteOp
// PUSH operations will advance the PC by the number of bytes pushed
func (vm *VM) Run() error {
	for vm.pc < uint64(len(vm.code)) {
		op := svm.OpCode(vm.code[vm.pc]) // Fetch opcode at current PC
		vm.pc++                          // Advance PC to next instruction

		// Execute opcode with access to stack, memory, code, and PC
		// Pass vm.code for PUSH operations to read immediate values
		if err := svm.ExecuteOp(op, vm.stack, vm.memory, vm.code, &vm.pc); err != nil {
			return fmt.Errorf("error executing opcode 0x%x at pc=%d: %v", op, vm.pc-1, err)
		}
	}
	return nil
}

// GetResult retrieves the top value from the stack after execution
// Used to get the return value of the program (e.g., verification result)
func (vm *VM) GetResult() (uint64, error) {
	if vm.stack.Size() == 0 {
		return 0, fmt.Errorf("no result on stack")
	}
	return vm.stack.Peek()
}

// GetMemory returns a slice of the VM's memory
// Allows external access to memory contents (e.g., for debugging)
func (vm *VM) GetMemory() []byte {
	return vm.memory
}

// SetMemoryBytes copies data into VM memory at the specified offset
// Used to load transaction data, signatures, public keys into memory
func (vm *VM) SetMemoryBytes(offset int, data []byte) error {
	if offset+len(data) > len(vm.memory) {
		return fmt.Errorf("memory offset out of bounds: %d + %d > %d", offset, len(data), len(vm.memory))
	}
	copy(vm.memory[offset:], data)
	return nil
}

// GetMemoryBytes retrieves data from VM memory
// Used to read results or debug memory contents
func (vm *VM) GetMemoryBytes(offset, length int) ([]byte, error) {
	if offset+length > len(vm.memory) {
		return nil, fmt.Errorf("memory offset out of bounds: %d + %d > %d", offset, length, len(vm.memory))
	}
	result := make([]byte, length)
	copy(result, vm.memory[offset:offset+length])
	return result, nil
}

// RunProgram is a helper function to execute a bytecode program and return the result
// Simplifies VM execution for simple programs without custom memory
func RunProgram(code []byte) (uint64, error) {
	vm := NewVM(code)
	if err := vm.Run(); err != nil {
		return 0, err
	}
	return vm.GetResult()
}

// RunProgramWithMemory is a helper function to execute a bytecode program with custom memory
// Used for transaction verification where signature, public key, message are pre-loaded
func RunProgramWithMemory(code []byte, memory []byte) (uint64, error) {
	vm := &VM{
		stack:  svm.NewStack(),
		memory: make([]byte, len(memory)),
		pc:     0,
		code:   code,
	}
	copy(vm.memory, memory)
	if err := vm.Run(); err != nil {
		return 0, err
	}
	return vm.GetResult()
}
