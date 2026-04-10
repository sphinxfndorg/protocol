package vm

import svm "github.com/sphinxorg/protocol/src/core/svm/opcodes"

// VM represents the virtual machine for executing SVM bytecode
// The VM executes opcodes sequentially, managing a stack and memory
type VM struct {
	stack  *svm.Stack // Stack for operand storage (holds uint64 values)
	memory []byte     // Linear memory for data storage (1MB default)
	pc     uint64     // Program counter - points to current instruction in code
	code   []byte     // Bytecode program being executed
}
