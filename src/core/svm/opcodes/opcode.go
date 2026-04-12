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

// go/src/core/svm/opcodes/opcode.go
package svm

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/sphinxorg/protocol/src/common"
	logger "github.com/sphinxorg/protocol/src/log"
	"golang.org/x/crypto/sha3"
)

// NewStack creates and initializes a new empty stack
// Pre-allocates capacity for 1024 items to reduce reallocations
func NewStack() *Stack {
	return &Stack{data: make([]uint64, 0, 1024)}
}

// Push adds a uint64 value to the top of the stack
// The value can be a length, pointer, hash fragment, or boolean (0/1)
func (s *Stack) Push(value uint64) {
	s.data = append(s.data, value) // Append to the end (top of stack)
}

// Pop removes and returns the top value from the stack
// Returns error "stack underflow" if the stack is empty
func (s *Stack) Pop() (uint64, error) {
	if len(s.data) == 0 {
		return 0, fmt.Errorf("stack underflow") // No items to pop
	}
	value := s.data[len(s.data)-1]  // Get the last element (top)
	s.data = s.data[:len(s.data)-1] // Remove it by slicing
	return value, nil               // Return the popped value
}

// Peek returns the top value from the stack without removing it
// Useful for DUP operation where we need to see the top value
func (s *Stack) Peek() (uint64, error) {
	if len(s.data) == 0 {
		return 0, fmt.Errorf("stack underflow") // No items to peek
	}
	return s.data[len(s.data)-1], nil // Return top without removing
}

// Size returns the current number of items on the stack
func (s *Stack) Size() int {
	return len(s.data) // Length of the data slice
}

// IsPush specifies if an opcode is a PUSH opcode
// PUSH opcodes load immediate values from the bytecode onto the stack
func (op OpCode) IsPush() bool {
	switch op {
	case PUSH1, PUSH2, PUSH4, PUSH8: // These are the only PUSH opcodes
		return true
	default:
		return false
	}
}

// GetPushBytes returns number of bytes to push for PUSH opcodes
// PUSH1 pushes 1 byte (value 0-255)
// PUSH2 pushes 2 bytes (value 0-65535)
// PUSH4 pushes 4 bytes (value 0-4294967295)
// PUSH8 pushes 8 bytes (value 0-18446744073709551615)
func (op OpCode) GetPushBytes() int {
	switch op {
	case PUSH1:
		return 1 // Single byte value
	case PUSH2:
		return 2 // Two-byte (uint16) value
	case PUSH4:
		return 4 // Four-byte (uint32) value
	case PUSH8:
		return 8 // Eight-byte (uint64) value
	default:
		return 0 // Not a PUSH opcode
	}
}

// ========== HASH FUNCTION IMPLEMENTATIONS ==========
// These are the cryptographic hash functions available to the VM
// They use the golang.org/x/crypto/sha3 package for post-quantum security

// sha3_256 computes SHA3-256 hash (32 bytes output)
// Used for: commitment verification, Merkle root calculations
// Security: 256-bit post-quantum security
func sha3_256(data []byte) []byte {
	h := sha3.New256() // Create a new SHA3-256 hash object
	h.Write(data)      // Write the input data into the hash
	return h.Sum(nil)  // Finalize and return the 32-byte hash
}

// sha512_224 computes SHA3-512 truncated to 224 bits (28 bytes output)
// Used for: alternative hash requirements, compatibility
// Security: 224-bit post-quantum security (from 512-bit internal state)
func sha512_224(data []byte) []byte {
	h := sha3.New512() // Create SHA3-512 hash (64 byte output)
	h.Write(data)      // Write input data
	hash := h.Sum(nil) // Get 64-byte hash
	return hash[:28]   // Truncate to first 28 bytes (224 bits)
}

// sha512_256 computes SHA3-512 truncated to 256 bits (32 bytes output)
// Used for: Merkle root calculations, alternative to SHA3-256
// Security: 256-bit post-quantum security (from 512-bit internal state)
func sha512_256(data []byte) []byte {
	h := sha3.New512() // Create SHA3-512 hash
	h.Write(data)      // Write input data
	hash := h.Sum(nil) // Get 64-byte hash
	return hash[:32]   // Truncate to first 32 bytes (256 bits)
}

// sha3_shake256 computes SHAKE256 extendable-output function
// Can produce variable length output (specified by length parameter)
// Used for: variable-length hash requirements, key derivation
func sha3_shake256(data []byte, length int) []byte {
	h := sha3.NewShake256()     // Create SHAKE256 XOF (Extendable-Output Function)
	h.Write(data)               // Write input data
	out := make([]byte, length) // Allocate output buffer of requested length
	h.Read(out)                 // Read/ squeeze the output bytes
	return out                  // Return the variable-length output
}

// Global SPHINCS+ verification function (to be set by the application)
// This is a function pointer that allows the VM to call back into the application
// The application registers its SPHINCS+ verification implementation here
var verifySphincsPlusFunc func(signature, publicKey, message []byte) bool

// sphincsVerifyFunc holds the real deserialization+crypto implementation.
// Populated by SetSphincsVerifier at node startup.
// Kept separate from verifySphincsPlusFunc so the two registration paths
// are explicit and cannot be confused.
// SetVerifySphincsPlusFunc remains available for tests that need a simple override.
var sphincsVerifyFunc func(signature, publicKey, message []byte) bool

// Global storage for signature hashes (content-based replay prevention)
// This stores hashes of SPHINCS+ signatures that have been seen
// Key: signature hash (32 bytes as string), Value: used flag
var signatureHashStore = make(map[string]bool)

// SetVerifySphincsPlusFunc sets the verification function for SPHINCS+ signatures
// Called by the application once during initialization to register its crypto
// Example: svm.SetVerifySphincsPlusFunc(myApp.VerifySPHINCS)
// NOTE: For real SPHINCS+ verification, prefer SetSphincsVerifier which wires in
// actual deserialization and Spx_verify. This function is retained for tests
// that need a lightweight override without real crypto.
func SetVerifySphincsPlusFunc(verifyFunc func([]byte, []byte, []byte) bool) {
	verifySphincsPlusFunc = verifyFunc // Store the function pointer
}

// SetSphincsVerifier registers the real SPHINCS+ verification implementation.
// Must be called once at node startup, before any VM execution.
//
// Parameters:
//
//	deserializePK  — converts raw public key bytes → opaque PK handle (interface{})
//	deserializeSig — converts raw signature bytes  → opaque SIG handle (interface{})
//	verify         — calls the real Spx_verify(msg, sig, pk) using the handles above
//
// Using interface{} parameters keeps opcode.go free of a direct import of the
// sphincs package, which avoids import cycles, while still performing real crypto.
//
// The registered function handles TWO execution paths distinguished by pkLen:
//
//	pkLen == 0 → light-client sig-hash lookup path (Dave's convention).
//	             Rejected in full-node context — return false explicitly.
//
//	pkLen >  0 → full-node SPHINCS+ verification path (Charlie's path).
//	             Deserializes pk and sig then calls real Spx_verify.
//
// This replaces the devnet placeholder that returned true unconditionally.
// Call this instead of SetVerifySphincsPlusFunc for production/mainnet nodes.
func SetSphincsVerifier(
	deserializePK func([]byte) (interface{}, error),
	deserializeSig func([]byte) (interface{}, error),
	verify func(msg []byte, sig interface{}, pk interface{}) bool,
) {
	sphincsVerifyFunc = func(signature, publicKey, message []byte) bool {
		if len(publicKey) == 0 {
			// Light-client path (Dave): signature = daveSigHash (32 bytes).
			// Do LevelDB lookup: "sig-hash:" + sigHash → "used".
			// In the consensus/helper context there is no Dave DB —
			// this path is unused here. Return false to be explicit and safe.
			logger.Warn("OP_CHECK_SPHINCS: light-client path rejected in full-node context")
			return false
		}

		// Full-node path (Charlie): real SPHINCS+ verification.
		// Deserialize the public key from raw bytes.
		pk, err := deserializePK(publicKey)
		if err != nil {
			logger.Warn("OP_CHECK_SPHINCS: pk deserialization failed: %v", err)
			return false
		}

		// Deserialize the signature from raw bytes.
		sig, err := deserializeSig(signature)
		if err != nil {
			logger.Warn("OP_CHECK_SPHINCS: sig deserialization failed: %v", err)
			return false
		}

		// Call the real Spx_verify provided by the caller.
		// This is the actual post-quantum cryptographic verification.
		valid := verify(message, sig, pk)
		logger.Debug("OP_CHECK_SPHINCS: sig=%d pk=%d msg=%d valid=%v",
			len(signature), len(publicKey), len(message), valid)
		return valid
	}

	// Wire into the existing dispatch path so executeCheckSphincs and
	// executeVerifySphincs both benefit from the real verifier automatically.
	verifySphincsPlusFunc = sphincsVerifyFunc
	logger.Info("✅ OP_CHECK_SPHINCS: real SPHINCS+ verifier registered")
}

// verifySphincsPlus calls the registered verification function
// Used by OP_CHECK_SPHINCS and OP_VERIFY_SPHINCS opcodes
// Returns true if the signature is valid, false otherwise
// Fails closed — returns false and logs a warning if no verifier has been registered.
// Previously fell back to a non-empty check (fail-open); that has been removed
// because an unregistered verifier on a blockchain node must hard-reject, not silently pass.
func verifySphincsPlus(signature, publicKey, message []byte) bool {
	if verifySphincsPlusFunc == nil {
		// No verifier registered — fail closed.
		// This prevents silent pass-through if node startup skipped registration.
		logger.Warn("OP_CHECK_SPHINCS: no verifier registered — rejecting (fail-closed)")
		return false
	}
	return verifySphincsPlusFunc(signature, publicKey, message) // Call registered function
}

// Global storage for nonce and receipt
// nonceStore: prevents replay attacks by tracking used timestamp+nonce pairs
// receiptStore: stores commitment → merkleRootHash mappings for dispute resolution
var nonceStore = make(map[string]bool)     // Key: timestamp+nonce string, Value: used flag
var receiptStore = make(map[string][]byte) // Key: commitment hex, Value: merkle root hash

// ExecuteOp processes an operation using stack machine semantics
// This is the main dispatch function that routes opcodes to their implementations
// Parameters:
//
//	op: the opcode byte to execute
//	stack: the execution stack (holds operands and results)
//	memory: linear memory for data storage (signatures, keys, messages)
//	code: the bytecode program (needed for PUSH to read immediate values)
//	pc: program counter pointer (can be modified by jumps in future)
func ExecuteOp(op OpCode, stack *Stack, memory []byte, code []byte, pc *uint64) error {
	switch op {
	// ========== PUSH OPERATIONS (0x60-0x67) ==========
	// PUSH1, PUSH2, PUSH4, PUSH8 - Load immediate values from bytecode onto stack
	// Used to load constants, lengths, pointers, and addresses
	// Example: PUSH4 0x00 0x00 0x1E 0xB0 pushes 7856 onto stack (signature length)
	// The values are read from the code (bytecode) not from memory
	// NOTE: PUSH4 remapped to 0xB0, PUSH8 remapped to 0xB1 to avoid collision
	//       with OP_IF (0x63) and OP_ELSE (0x67)
	case PUSH1, PUSH2, PUSH4, PUSH8:
		n := op.GetPushBytes() // Get number of bytes to push (1,2,4,8)
		// Check bounds: current PC + n must not exceed code length
		if *pc+uint64(n) > uint64(len(code)) {
			return fmt.Errorf("push operation out of bounds: pc=%d, n=%d, code_len=%d", *pc, n, len(code))
		}
		var value uint64 // Will hold the value to push
		switch n {
		case 1:
			value = uint64(code[*pc]) // Read 1 byte, convert to uint64
		case 2:
			value = uint64(binary.BigEndian.Uint16(code[*pc : *pc+2])) // Read 2 bytes as uint16
		case 4:
			value = uint64(binary.BigEndian.Uint32(code[*pc : *pc+4])) // Read 4 bytes as uint32
		case 8:
			value = binary.BigEndian.Uint64(code[*pc : *pc+8]) // Read 8 bytes as uint64
		}
		stack.Push(value) // Push the value onto the stack
		*pc += uint64(n)  // Advance PC past the pushed data
		return nil

	// ========== HASHING OPERATIONS (0x10-0x14) ==========
	// SphinxHash (0x10) - Custom hash function for Sphinx protocol
	// Used for commitment generation and Merkle tree operations
	// This implementation uses the spxhash package for the custom Sphinx hash
	// The hash is computed on the input data from the stack
	case SphinxHash:
		return executeSphinxHashOp(stack)

	// SHA3_256 (0x11) - SHA3-256 hash function
	// Used for commitment verification: commitment = SHA3_256(sigBytes || pkBytes || timestamp || nonce || message)
	// Pops size, creates dummy data, hashes with SHA3-256, pushes first 8 bytes of result
	case SHA3_256:
		return executeHashOp(stack, sha3_256)

	// SHA512_224 (0x12) - SHA3-512 truncated to 224 bits
	// Used for alternative hash requirements where 224-bit output is needed
	// Pops size, creates dummy data, hashes with SHA3-512, truncates to 28 bytes, pushes first 8 bytes
	case SHA512_224:
		return executeHashOp(stack, sha512_224)

	// SHA512_256 (0x13) - SHA3-512 truncated to 256 bits
	// Used for Merkle root calculations and alternative to SHA3-256
	// Pops size, creates dummy data, hashes with SHA3-512, truncates to 32 bytes, pushes first 8 bytes
	case SHA512_256:
		return executeHashOp(stack, sha512_256)

	// SHA3_Shake256 (0x14) - SHAKE256 extendable-output function
	// Used for variable-length hash outputs and key derivation
	// Pops output length and size, creates dummy data, generates hash, pushes first 8 bytes
	case SHA3_Shake256:
		return executeShakeOp(stack)

	// ========== BITWISE ARITHMETIC OPERATIONS (0x20-0x2E) ==========
	// Xor (0x20) - Bitwise XOR (exclusive OR)
	// Used for combining values, cryptographic operations, and masking
	// Pops two values, XORs them, pushes result
	case Xor, Or, And, Rot, Not, Shr, Add:
		return executeArithmeticOp(op, stack)
	// ========== NEW ARITHMETIC OPERATIONS ==========
	case SUB, MUL, DIV, SDIV, MOD, SMOD, EXP, SIGNEXTEND:
		return executeArithmeticOp(op, stack)

	// ========== COMPARISON OPERATIONS (0x31-0x36) ==========
	// LT, GT, SLT, SGT, EQ, ISZERO - Comparison operations
	case LT, GT, SLT, SGT, EQ, ISZERO:
		return executeComparisonOp(op, stack)

	// ========== BITWISE OPERATIONS (0x3A-0x3C) ==========
	case BYTE, SHL, SAR:
		return executeBitwiseOp(op, stack)

	// ========== ETHEREUM CONTEXT OPERATIONS ==========
	// NOTE: ORIGIN, CALLER, CALLVALUE, CALLDATALOAD, CALLDATASIZE remapped to 0xA0-0xA4
	//       to avoid collision with GT(0x32), SLT(0x33), SGT(0x34), EQ(0x35), ISZERO(0x36)
	// NOTE: EXTCODESIZE, EXTCODECOPY remapped to 0xA5-0xA6
	//       to avoid collision with SHL(0x3B), SAR(0x3C)
	// ADDRESS (0x30) - no conflict, kept as-is
	// CALLDATACOPY (0x37), CODESIZE (0x38), CODECOPY (0x39) - no conflict, kept as-is
	// RETURNDATASIZE (0x3D), RETURNDATACOPY (0x3E), GASPRICE (0x3F) - no conflict, kept as-is
	case ADDRESS, ORIGIN, CALLER, CALLVALUE, CALLDATALOAD, CALLDATASIZE, CALLDATACOPY,
		CODESIZE, CODECOPY, EXTCODESIZE, EXTCODECOPY, RETURNDATASIZE, RETURNDATACOPY, GASPRICE:
		return executeEthereumContextOp(op, stack, memory)

	// ========== ETHEREUM BLOCK CONTEXT (0x40-0x47) ==========
	case BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, DIFFICULTY, GASLIMIT, CHAINID, SELFBALANCE:
		return executeBlockContextOp(op, stack)

	// ========== CONTROL FLOW OPERATIONS (0x56-0x5B) ==========
	case JUMP, JUMPI, PC, JUMPDEST:
		return executeControlFlowOp(op, stack, code, pc)

	// ========== BITCOIN SCRIPT STACK OPS ==========
	// OP_IF (0x63), OP_ELSE (0x67), OP_ENDIF (0x68), OP_VERIFY (0x69)
	// OP_DEPTH (0x74), OP_NIP (0x77), OP_OVER (0x78), OP_PICK (0x79), OP_ROLL (0x7A), OP_ROT (0x7B), OP_TUCK (0x7D)
	// OP_EQUAL (0x87), OP_EQUALVERIFY (0x88)
	// NOTE: OP_IF (0x63) and OP_ELSE (0x67) no longer conflict because PUSH4 was remapped
	//       to 0xB0 and PUSH8 was remapped to 0xB1
	case OP_IF, OP_ELSE, OP_ENDIF, OP_VERIFY, OP_EQUAL, OP_EQUALVERIFY, OP_DEPTH, OP_NIP,
		OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_TUCK:
		return executeBitcoinScriptStackOp(op, stack)

	// ========== BITCOIN SCRIPT OPERATIONS (0x7E-0x7F,0x8A-0x8D) ==========
	case OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_SIZE, OP_SPLIT:
		return executeBitcoinScriptOp(op, stack, memory)

	// ========== SPHINCS+ PROTOCOL OPERATIONS (0xD0-0xDA) ==========
	// OP_CHECK_SPHINCS (0xD0) - Verify SPHINCS+ signature, push 1/0 on stack
	// Used for transaction signature verification without consuming stack items
	// Expected stack: msg_len, msg_ptr, pk_len, pk_ptr, sig_len, sig_ptr
	// Pushes 1 for valid signature, 0 for invalid (does not halt on invalid)
	case OP_CHECK_SPHINCS:
		return executeCheckSphincs(stack, memory)

	// OP_VERIFY_SPHINCS (0xD1) - Verify SPHINCS+ signature, fail if invalid
	// Used for mandatory signature verification (consumes stack items)
	// Same stack layout as OP_CHECK_SPHINCS but returns error if signature is invalid
	// This halts execution on invalid signatures (unlike CHECK which continues)
	case OP_VERIFY_SPHINCS:
		return executeVerifySphincs(stack, memory)

	// OP_DUP_SPHINCS (0xD2) - Duplicate top 6 SPHINCS+ items on stack
	// Used for preparing multiple SPHINCS+ parameters for verification
	// Copies the top 6 stack items so they can be used multiple times
	case OP_DUP_SPHINCS:
		return executeDupSphincs(stack)

	// OP_CHECK_TIMESTAMP (0xD3) - Verify timestamp freshness (within 5 minutes)
	// Used for replay attack prevention - ensures transaction isn't too old
	// Pops: timestamp length, timestamp pointer from memory
	// Pushes 1 if timestamp is within 5 minutes of current time, 0 if too old
	case OP_CHECK_TIMESTAMP:
		return executeCheckTimestamp(stack, memory)

	// OP_CHECK_NONCE (0xD4) - Verify nonce hasn't been used before
	// Used for replay attack prevention - checks if timestamp+nonce pair exists
	// Pops: nonce length, nonce pointer, timestamp length, timestamp pointer
	// Pushes 1 if nonce is new (not seen before), 0 if already used
	case OP_CHECK_NONCE:
		return executeCheckNonce(stack, memory)

	// OP_STORE_NONCE (0xD5) - Store timestamp+nonce pair after verification
	// Called after successful transaction verification to prevent future replays
	// Pops: nonce length, nonce pointer, timestamp length, timestamp pointer
	// Stores the pair in nonceStore and pushes 1 on success
	case OP_STORE_NONCE:
		return executeStoreNonce(stack, memory)

	// OP_VERIFY_MERKLE_ROOT (0xD6) - Rebuild Merkle tree and verify root
	// Used to verify that the Merkle root was honestly derived from signature
	// Pops: root length, root pointer, commitment length, pointer, sig length, pointer
	// Rebuilds tree from signature chunks and commitment, compares with expected root
	// Pushes 1 if roots match, 0 otherwise
	case OP_VERIFY_MERKLE_ROOT:
		return executeVerifyMerkleRoot(stack, memory)

	// OP_VERIFY_COMMITMENT (0xD7) - Verify the commitment hash matches
	// Used to verify that commitment = SHA3_256(sigBytes || pk || ts || nonce || msg)
	// Pops: expected commitment length, pointer, message length, pointer, nonce length, pointer, timestamp length, pointer, public key length, pointer, signature length, pointer
	// Recomputes commitment from signature, public key, timestamp, nonce, message
	// Pushes 1 if recomputed matches expected, 0 otherwise
	case OP_VERIFY_COMMITMENT:
		return executeVerifyCommitment(stack, memory)

	// OP_BUILD_MERKLE_TREE (0xD8) - Build Merkle tree from signature parts
	// Used to reconstruct the Merkle root from signature chunks
	// Pops: commitment length, pointer, signature length, pointer
	// Builds 5-leaf Merkle tree, computes root hash
	// Pushes root hash pointer and length onto stack (simplified - placeholder for root pointer)
	case OP_BUILD_MERKLE_TREE:
		return executeBuildMerkleTree(stack, memory)

	// OP_STORE_RECEIPT (0xD9) - Store commitment → merkleRootHash mapping
	// Used to persist transaction receipts for dispute resolution
	// Pops: root length, root pointer, commitment length, commitment pointer
	// Stores mapping in receiptStore and pushes 1 on success
	case OP_STORE_RECEIPT:
		return executeStoreReceipt(stack, memory)

	// OP_VERIFY_PROOF (0xDA) - Verify light client proof
	// Used by light clients to verify transactions without full SPHINCS+ verification
	// Pops: proof length, proof pointer
	// Simplified: pushes 1 if proof is non-empty, 0 otherwise
	// In production: would verify Merkle inclusion proofs
	case OP_VERIFY_PROOF:
		return executeVerifyProof(stack, memory)

	// ========== LEGACY SPHINCS+ MULTISIG OPERATIONS (0xE0-0xE3) ==========
	// These are placeholders for future multisignature functionality
	// Currently simplified: each pushes 1 onto the stack
	case OP_SPHINCS_MULTISIG_INIT, OP_SPHINCS_MULTISIG_SIGN,
		OP_SPHINCS_MULTISIG_VERIFY, OP_SPHINCS_MULTISIG_PROOF:
		return executeMultisigOp(op, stack)

	// ========== STACK MANIPULATION OPERATIONS (0x50,0x80,0x90) ==========
	// DUP (0x80) - Duplicate top stack item
	// Used to copy values for multiple operations without consuming the original
	case DUP, SWAP, POP:
		return executeStackOp(op, stack)

	// ========== DATA EMBEDDING OPERATION (0xFD) ==========
	// OP_RETURN (0xFD) - Embed arbitrary data (memos, proofs, metadata)
	// Similar to Bitcoin's OP_RETURN - stores data without affecting state
	// Used for: attaching memos to transactions, embedding SPHINCS+ proofs,
	//           storing metadata, anchoring commitments, light client proofs
	// Stack layout: data_len, data_ptr
	// Pushes 1 on success, 0 on failure
	case OP_RETURN:
		return executeReturn(stack, memory)

	case OP_CHECK_SIGNATURE_HASH:
		return executeCheckSignatureHash(stack, memory)

	case OP_VERIFY_SIGNATURE_HASH:
		return executeVerifySignatureHash(stack, memory)

	case OP_STORE_SIGNATURE_HASH:
		return executeStoreSignatureHash(stack, memory)

	default:
		return fmt.Errorf("unknown opcode: 0x%x", op) // Invalid opcode
	}
}

// ========== SPHINX HASH OPERATION ==========
// executeSphinxHashOp - Custom Sphinx hash operation using common.SpxHash
// This implements the SphinxHash opcode (0x10) using the protocol's SpxHash function
// SphinxHash is a combination of SHA2-256 and SHAKE256, optimized for large data sizes (>1MB)
// It is faster than standard hash functions for processing large amounts of data
//
// The function pops a size parameter from the stack, creates a zero-filled buffer of that size,
// computes the Sphinx hash using common.SpxHash, and pushes the first 8 bytes of the result
//
// Performance note: For large data sizes (>1MB), SphinxHash is designed to be efficient
// and faster than SHA3-256 or SHAKE256 alone due to its internal optimization.
//
// Stack operation:
//
//	Before: ... [size]
//	After:  ... [hash_prefix] (first 8 bytes of hash as uint64)
func executeSphinxHashOp(stack *Stack) error {
	// Pop the size parameter from the stack (number of bytes to hash)
	size, err := stack.Pop()
	if err != nil {
		return err // Stack underflow - no size parameter
	}

	// Create a byte slice of the specified size filled with zeros
	// This is the input data for the Sphinx hash function
	// For large sizes (>1MB), SphinxHash internally processes this efficiently
	data := make([]byte, size)

	// Compute the Sphinx hash using common.SpxHash
	// SpxHash combines SHA2-256 and SHAKE256 for optimal performance
	// It is specifically optimized for large data sizes (>1MB)
	hash := common.SpxHash(data)

	// Push the first 8 bytes of the hash as a uint64 value onto the stack
	// Using BigEndian for consistency with other hash operations
	if len(hash) >= 8 {
		// Convert first 8 bytes to uint64 (big-endian)
		stack.Push(binary.BigEndian.Uint64(hash[:8]))
	} else {
		// Hash is shorter than 8 bytes (should not happen for 32-byte output)
		stack.Push(0)
	}

	return nil
}

// OP_CHECK_SPHINCS - Checks SPHINCS+ signature without consuming stack items
// Expected stack layout (top to bottom):
//
//	msg_len, msg_ptr, pk_len, pk_ptr, sig_len, sig_ptr
//
// Pushes 1 if signature is valid, 0 otherwise
// Used for non-destructive signature verification (does not halt on invalid)
func executeCheckSphincs(stack *Stack, memory []byte) error {
	// Pop message length from stack (number of bytes in the message)
	msgLen, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing message length: %v", err)
	}
	// Pop message pointer from stack (offset in memory where message starts)
	msgPtr, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing message pointer: %v", err)
	}

	// Pop public key length from stack
	pubkeyLen, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing public key length: %v", err)
	}
	// Pop public key pointer from stack
	pubkeyPtr, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing public key pointer: %v", err)
	}

	// Pop signature length from stack
	sigLen, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing signature length: %v", err)
	}
	// Pop signature pointer from stack
	sigPtr, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing signature pointer: %v", err)
	}

	// Validate signature bounds: pointer + length must not exceed memory size
	if sigPtr+sigLen > uint64(len(memory)) {
		return fmt.Errorf("signature out of bounds: ptr=%d, len=%d, mem=%d", sigPtr, sigLen, len(memory))
	}
	// Validate public key bounds
	if pubkeyPtr+pubkeyLen > uint64(len(memory)) {
		return fmt.Errorf("public key out of bounds")
	}
	// Validate message bounds
	if msgPtr+msgLen > uint64(len(memory)) {
		return fmt.Errorf("message out of bounds")
	}

	// Extract the actual byte slices from memory using the pointers and lengths
	signature := memory[sigPtr : sigPtr+sigLen]          // Slice of signature bytes
	publicKey := memory[pubkeyPtr : pubkeyPtr+pubkeyLen] // Slice of public key bytes
	message := memory[msgPtr : msgPtr+msgLen]            // Slice of message bytes

	// Call the registered SPHINCS+ verification function
	valid := verifySphincsPlus(signature, publicKey, message)

	// Push result onto stack (1 = valid, 0 = invalid)
	if valid {
		stack.Push(1) // Valid signature
	} else {
		stack.Push(0) // Invalid signature
	}

	return nil
}

// OP_VERIFY_SPHINCS - Verifies SPHINCS+ signature and consumes stack items
// Same stack layout as OP_CHECK_SPHINCS but returns error on failure
// Used for mandatory signature verification where invalid signature halts execution
func executeVerifySphincs(stack *Stack, memory []byte) error {
	// Pop all parameters (same order as executeCheckSphincs)
	msgLen, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing message length: %v", err)
	}
	msgPtr, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing message pointer: %v", err)
	}

	pubkeyLen, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing public key length: %v", err)
	}
	pubkeyPtr, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing public key pointer: %v", err)
	}

	sigLen, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing signature length: %v", err)
	}
	sigPtr, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing signature pointer: %v", err)
	}

	// Validate all memory bounds
	if sigPtr+sigLen > uint64(len(memory)) {
		return fmt.Errorf("signature out of bounds: ptr=%d, len=%d, mem=%d", sigPtr, sigLen, len(memory))
	}
	if pubkeyPtr+pubkeyLen > uint64(len(memory)) {
		return fmt.Errorf("public key out of bounds")
	}
	if msgPtr+msgLen > uint64(len(memory)) {
		return fmt.Errorf("message out of bounds")
	}

	// Extract byte slices from memory
	signature := memory[sigPtr : sigPtr+sigLen]
	publicKey := memory[pubkeyPtr : pubkeyPtr+pubkeyLen]
	message := memory[msgPtr : msgPtr+msgLen]

	// Verify signature - this version RETURNS ERROR on failure (doesn't push 0)
	valid := verifySphincsPlus(signature, publicKey, message)

	if !valid {
		return fmt.Errorf("SPHINCS+ signature verification failed") // Halt execution
	}

	return nil // Success - no value pushed to stack
}

// OP_DUP_SPHINCS - Duplicates the top 6 SPHINCS+ items on the stack
// Used to prepare multiple SPHINCS+ verification calls with the same parameters
// This is useful when you need to verify multiple signatures with same parameters
func executeDupSphincs(stack *Stack) error {
	// Check we have at least 6 items on the stack
	if stack.Size() < 6 {
		return fmt.Errorf("stack underflow: need 6 items for OP_DUP_SPHINCS, have %d", stack.Size())
	}

	// Pop 6 items and store them in reverse order
	items := make([]uint64, 6)
	for i := 0; i < 6; i++ {
		val, err := stack.Pop()
		if err != nil {
			return fmt.Errorf("failed to read stack item %d: %v", i, err)
		}
		items[5-i] = val // Store in reverse to maintain original order
	}

	// Push the original 6 items back (first copy)
	for i := 0; i < 6; i++ {
		stack.Push(items[i])
	}
	// Push the duplicate 6 items (second copy)
	for i := 0; i < 6; i++ {
		stack.Push(items[i])
	}

	return nil
}

// OP_CHECK_TIMESTAMP - Verifies timestamp freshness (within 5 minutes)
// Used for replay attack prevention - ensures transaction isn't too old
// Pushes 1 if timestamp is within 5 minutes of current time, 0 otherwise
func executeCheckTimestamp(stack *Stack, memory []byte) error {
	// Pop timestamp length (should be 8 bytes for Unix timestamp)
	tsLen, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing timestamp length: %v", err)
	}
	// Pop timestamp pointer (where timestamp bytes are stored in memory)
	tsPtr, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing timestamp pointer: %v", err)
	}

	// Validate bounds: pointer + length must be within memory
	if tsPtr+tsLen > uint64(len(memory)) {
		return fmt.Errorf("timestamp out of bounds")
	}

	// Convert timestamp bytes to uint64 (assuming 8-byte Unix timestamp)
	var timestampInt uint64
	if tsLen == 8 { // Standard Unix timestamp is 8 bytes
		timestampInt = binary.BigEndian.Uint64(memory[tsPtr : tsPtr+8])
	}

	// Get current Unix time
	currentTime := uint64(time.Now().Unix())
	// Calculate age (how old the timestamp is)
	age := currentTime - timestampInt

	// Check if timestamp is within 5 minutes (300 seconds)
	if age > 300 { // 5 minutes = 300 seconds
		stack.Push(0) // Too old - reject
	} else {
		stack.Push(1) // Fresh - accept
	}

	return nil
}

// OP_CHECK_NONCE - Verifies nonce hasn't been used before
// Used for replay attack prevention - checks if timestamp+nonce pair exists in storage
// Pushes 1 if nonce is new (not seen before), 0 if already used
func executeCheckNonce(stack *Stack, memory []byte) error {
	// Pop nonce length (should be 16 bytes for random nonce)
	nonceLen, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing nonce length: %v", err)
	}
	// Pop nonce pointer
	noncePtr, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing nonce pointer: %v", err)
	}

	// Pop timestamp length (8 bytes)
	tsLen, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing timestamp length: %v", err)
	}
	// Pop timestamp pointer
	tsPtr, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing timestamp pointer: %v", err)
	}

	// Validate bounds
	if tsPtr+tsLen > uint64(len(memory)) || noncePtr+nonceLen > uint64(len(memory)) {
		return fmt.Errorf("timestamp or nonce out of bounds")
	}

	// Extract timestamp and nonce bytes from memory
	timestamp := memory[tsPtr : tsPtr+tsLen]
	nonce := memory[noncePtr : noncePtr+nonceLen]

	// Create composite key by concatenating timestamp and nonce
	key := string(timestamp) + string(nonce)
	// Check if this key exists in the nonceStore (used for replay detection)
	exists := nonceStore[key]

	// Push result: 0 = already used (replay), 1 = new (safe)
	if exists {
		stack.Push(0) // Already used - replay attack detected
	} else {
		stack.Push(1) // New - safe to process
	}

	return nil
}

// OP_STORE_NONCE - Stores timestamp+nonce pair after verification
// Called after successful transaction verification to prevent future replays
// Pushes 1 on successful storage
func executeStoreNonce(stack *Stack, memory []byte) error {
	// Pop nonce length and pointer
	nonceLen, err := stack.Pop()
	if err != nil {
		return err
	}
	noncePtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Pop timestamp length and pointer
	tsLen, err := stack.Pop()
	if err != nil {
		return err
	}
	tsPtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Validate bounds
	if tsPtr+tsLen > uint64(len(memory)) || noncePtr+nonceLen > uint64(len(memory)) {
		return fmt.Errorf("timestamp or nonce out of bounds")
	}

	// Extract timestamp and nonce bytes
	timestamp := memory[tsPtr : tsPtr+tsLen]
	nonce := memory[noncePtr : noncePtr+nonceLen]

	// Create composite key and store in nonceStore (mark as used)
	key := string(timestamp) + string(nonce)
	nonceStore[key] = true // Store the pair to prevent future replays

	stack.Push(1) // Success
	return nil
}

// OP_VERIFY_MERKLE_ROOT - Rebuilds Merkle tree and verifies root
// Used to verify that the Merkle root was honestly derived from the signature
// Rebuilds tree from signature chunks and commitment, compares with expected root
// Pushes 1 if roots match, 0 otherwise
func executeVerifyMerkleRoot(stack *Stack, memory []byte) error {
	// Pop expected root length and pointer
	rootLen, err := stack.Pop()
	if err != nil {
		return err
	}
	rootPtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Pop commitment length and pointer
	commitLen, err := stack.Pop()
	if err != nil {
		return err
	}
	commitPtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Pop signature length and pointer
	sigLen, err := stack.Pop()
	if err != nil {
		return err
	}
	sigPtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Validate all memory bounds
	if sigPtr+sigLen > uint64(len(memory)) ||
		commitPtr+commitLen > uint64(len(memory)) ||
		rootPtr+rootLen > uint64(len(memory)) {
		return fmt.Errorf("memory bounds exceeded")
	}

	// Extract signature, commitment, and expected root from memory
	signature := memory[sigPtr : sigPtr+sigLen]
	commitment := memory[commitPtr : commitPtr+commitLen]
	expectedRoot := memory[rootPtr : rootPtr+rootLen]

	// Split signature into 4 chunks (Merkle leaves 1-4)
	// Each chunk is approximately 1/4 of the signature size
	chunkSize := len(signature) / 4
	parts := make([][]byte, 5) // 5 leaves total (0-4)

	// Create 4 chunks from the signature
	for i := 0; i < 4; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if i == 3 { // Last chunk takes any remaining bytes
			end = len(signature)
		}
		chunk := make([]byte, end-start)  // Create new slice for this chunk
		copy(chunk, signature[start:end]) // Copy chunk bytes
		parts[i] = chunk
	}

	// Leaf 0: commitment prepended to first signature chunk
	// This binds the commitment to the Merkle root
	leaf0 := make([]byte, 0, len(commitment)+len(parts[0]))
	leaf0 = append(leaf0, commitment...) // Add commitment first
	leaf0 = append(leaf0, parts[0]...)   // Add first signature chunk
	parts[0] = leaf0

	// Leaf 4: hash of commitment (independently verifiable)
	// This prevents commitment substitution attacks
	commitHash := sha3_256(commitment)
	parts[4] = commitHash

	// Build Merkle tree by concatenating and hashing all leaves
	// Simplified: concatenate all leaves and hash once (not a proper tree)
	var allData []byte
	for _, part := range parts {
		allData = append(allData, part...) // Concatenate all parts
	}
	computedRoot := sha3_256(allData) // Hash the concatenation

	// Compare computed root with expected root
	if len(computedRoot) == len(expectedRoot) {
		// Byte-by-byte comparison
		for i := range computedRoot {
			if computedRoot[i] != expectedRoot[i] {
				stack.Push(0) // Root mismatch - tampering detected
				return nil
			}
		}
		stack.Push(1) // Root matches - receipt is valid
	} else {
		stack.Push(0) // Length mismatch - invalid
	}

	return nil
}

// OP_VERIFY_COMMITMENT - Verifies the commitment hash
// Recomputes commitment = SHA3_256(sigBytes || pkBytes || timestamp || nonce || message)
// Pushes 1 if recomputed commitment matches expected, 0 otherwise
func executeVerifyCommitment(stack *Stack, memory []byte) error {
	// Pop expected commitment length and pointer
	expectedCommitLen, err := stack.Pop()
	if err != nil {
		return err
	}
	expectedCommitPtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Pop message length and pointer
	msgLen, err := stack.Pop()
	if err != nil {
		return err
	}
	msgPtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Pop nonce length and pointer
	nonceLen, err := stack.Pop()
	if err != nil {
		return err
	}
	noncePtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Pop timestamp length and pointer
	tsLen, err := stack.Pop()
	if err != nil {
		return err
	}
	tsPtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Pop public key length and pointer
	pkLen, err := stack.Pop()
	if err != nil {
		return err
	}
	pkPtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Pop signature length and pointer
	sigLen, err := stack.Pop()
	if err != nil {
		return err
	}
	sigPtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Validate all memory accesses are within bounds
	if sigPtr+sigLen > uint64(len(memory)) ||
		pkPtr+pkLen > uint64(len(memory)) ||
		tsPtr+tsLen > uint64(len(memory)) ||
		noncePtr+nonceLen > uint64(len(memory)) ||
		msgPtr+msgLen > uint64(len(memory)) ||
		expectedCommitPtr+expectedCommitLen > uint64(len(memory)) {
		return fmt.Errorf("memory bounds exceeded")
	}

	// Extract all components from memory
	signature := memory[sigPtr : sigPtr+sigLen]
	publicKey := memory[pkPtr : pkPtr+pkLen]
	timestamp := memory[tsPtr : tsPtr+tsLen]
	nonce := memory[noncePtr : noncePtr+nonceLen]
	message := memory[msgPtr : msgPtr+msgLen]
	expectedCommitment := memory[expectedCommitPtr : expectedCommitPtr+expectedCommitLen]

	// Recompute commitment with length-prefixed fields
	// Length prefix prevents concatenation ambiguity (e.g., "ab"+"c" vs "a"+"bc")
	var input []byte
	writeWithLength := func(b []byte) {
		// Write 4-byte length prefix (big-endian)
		length := make([]byte, 4)
		binary.BigEndian.PutUint32(length, uint32(len(b)))
		input = append(input, length...) // Add length prefix
		input = append(input, b...)      // Add the actual data
	}

	// Add each field with its length prefix
	writeWithLength(signature) // Signature bytes
	writeWithLength(publicKey) // Public key bytes
	writeWithLength(timestamp) // Timestamp bytes
	writeWithLength(nonce)     // Nonce bytes
	writeWithLength(message)   // Message bytes

	// Hash the concatenated length-prefixed fields
	computedCommitment := sha3_256(input)

	// Compare computed commitment with expected
	if len(computedCommitment) == len(expectedCommitment) {
		// Byte-by-byte comparison
		for i := range computedCommitment {
			if computedCommitment[i] != expectedCommitment[i] {
				stack.Push(0) // Commitment mismatch - tampering detected
				return nil
			}
		}
		stack.Push(1) // Commitment matches - valid
	} else {
		stack.Push(0) // Length mismatch
	}

	return nil
}

// OP_BUILD_MERKLE_TREE - Builds Merkle tree and pushes root
// Reconstructs Merkle tree from signature chunks and commitment
// Pushes root hash pointer and length onto stack (simplified - placeholder for root pointer)
func executeBuildMerkleTree(stack *Stack, memory []byte) error {
	// Pop commitment length and pointer
	commitLen, err := stack.Pop()
	if err != nil {
		return err
	}
	commitPtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Pop signature length and pointer
	sigLen, err := stack.Pop()
	if err != nil {
		return err
	}
	sigPtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Validate bounds
	if sigPtr+sigLen > uint64(len(memory)) || commitPtr+commitLen > uint64(len(memory)) {
		return fmt.Errorf("memory bounds exceeded")
	}

	// Extract signature and commitment from memory
	signature := memory[sigPtr : sigPtr+sigLen]
	commitment := memory[commitPtr : commitPtr+commitLen]

	// Split signature into 4 chunks for Merkle leaves
	chunkSize := len(signature) / 4
	var allData []byte // Will hold all leaf data concatenated

	// Process each of the 4 signature chunks
	for i := 0; i < 4; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if i == 3 { // Last chunk takes remaining bytes
			end = len(signature)
		}
		if i == 0 {
			// Leaf 0: commitment + first signature chunk
			allData = append(allData, commitment...)
		}
		allData = append(allData, signature[start:end]...)
	}

	// Leaf 4: hash of commitment (independently verifiable)
	commitHash := sha3_256(commitment)
	allData = append(allData, commitHash...)

	// Final root hash (SHA3-256 of all concatenated leaves)
	rootHash := sha3_256(allData)

	// Placeholder for root pointer (would need memory allocation in production)
	stack.Push(0)                     // Placeholder for root pointer
	stack.Push(uint64(len(rootHash))) // Push root hash length

	return nil
}

// OP_STORE_RECEIPT - Stores commitment → merkleRootHash mapping
// Used to persist transaction receipts for dispute resolution
// Pushes 1 on success
func executeStoreReceipt(stack *Stack, memory []byte) error {
	// Pop root length and pointer
	rootLen, err := stack.Pop()
	if err != nil {
		return err
	}
	rootPtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Pop commitment length and pointer
	commitLen, err := stack.Pop()
	if err != nil {
		return err
	}
	commitPtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Validate bounds
	if commitPtr+commitLen > uint64(len(memory)) || rootPtr+rootLen > uint64(len(memory)) {
		return fmt.Errorf("memory bounds exceeded")
	}

	// Extract commitment and merkle root from memory
	commitment := memory[commitPtr : commitPtr+commitLen]
	merkleRoot := memory[rootPtr : rootPtr+rootLen]

	// Store mapping in receiptStore (keyed by commitment string)
	receiptStore[string(commitment)] = merkleRoot

	stack.Push(1) // Success
	return nil
}

// OP_VERIFY_PROOF - Verifies light client proof
// Simplified proof verification - in production would verify Merkle inclusion proofs
// Pushes 1 if proof is non-empty, 0 otherwise
func executeVerifyProof(stack *Stack, memory []byte) error {
	// Pop proof length and pointer
	proofLen, err := stack.Pop()
	if err != nil {
		return err
	}
	proofPtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Validate bounds
	if proofPtr+proofLen > uint64(len(memory)) {
		return fmt.Errorf("proof out of bounds")
	}

	// Extract proof bytes
	proof := memory[proofPtr : proofPtr+proofLen]

	// Simplified: non-empty proof is considered valid
	if len(proof) > 0 {
		stack.Push(1) // Valid proof
	} else {
		stack.Push(0) // Invalid/empty proof
	}

	return nil
}

// ========== OP_RETURN OPERATION ==========
// executeReturn - Embeds arbitrary data (memos, proofs, metadata) on-chain
// This is similar to Bitcoin's OP_RETURN - stores data without affecting state
// The data is prunable - full nodes can discard it to save space
// Light clients can still access the data if needed
//
// Stack layout:
//
//	Before: ... [data_len] [data_ptr]
//	After:  ... [1] (success) or [0] (failure)
//
// Use cases:
//   - Attaching memos to transactions
//   - Embedding SPHINCS+ proofs for light clients
//   - Storing metadata or JSON data
//   - Anchoring commitments
//   - Recording transaction notes
func executeReturn(stack *Stack, memory []byte) error {
	// Pop data length from stack (number of bytes to embed)
	dataLen, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing data length: %v", err)
	}

	// Pop data pointer from stack (offset in memory where data starts)
	dataPtr, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing data pointer: %v", err)
	}

	// Validate bounds: pointer + length must not exceed memory size
	if dataPtr+dataLen > uint64(len(memory)) {
		return fmt.Errorf("data out of bounds: ptr=%d, len=%d, mem=%d", dataPtr, dataLen, len(memory))
	}

	// Extract the data (memo, proof, or metadata) from memory
	data := memory[dataPtr : dataPtr+dataLen]

	// Maximum size limit for OP_RETURN data (like Bitcoin's 80 bytes)
	// This prevents abuse and keeps the data prunable
	// Can be adjusted based on network needs
	const maxReturnSize = 80
	if dataLen > maxReturnSize {
		return fmt.Errorf("OP_RETURN data exceeds maximum size of %d bytes (got %d)", maxReturnSize, dataLen)
	}

	// Generate a hash of the data as a key for retrieval
	// This allows light clients to reference the data by hash
	dataHash := sha3_256(data)
	key := fmt.Sprintf("%x", dataHash[:8]) // Use first 8 bytes as short key

	// Store the data in receiptStore (already defined in your code)
	// This data is prunable - full nodes can discard it to save space
	receiptStore[key] = data

	// Also store in a dedicated "memos" or "proofs" store for easy retrieval
	// This is where SPHINCS+ proofs, commitments, and memos are anchored
	memoKey := fmt.Sprintf("memo:%x", dataHash[:8])
	receiptStore[memoKey] = data

	// Log the embedded memo if it's readable text
	// Check if data contains only printable ASCII characters
	// Log the embedded memo if it's readable text
	// Check if data contains only printable ASCII characters
	isText := true
	for i, b := range data {
		if b < 32 || b > 126 {
			logger.Debug("OP_RETURN: Non-printable char at position %d: %d (hex: %x)", i, b, b)
			isText = false
			break
		}
	}

	if isText && len(data) > 0 {
		logger.Info("📝 OP_RETURN: Embedded %d bytes of text: %s", len(data), string(data))
	} else {
		// Log first few bytes as hex for debugging
		hexPreview := ""
		if len(data) > 16 {
			hexPreview = hex.EncodeToString(data[:16]) + "..."
		} else {
			hexPreview = hex.EncodeToString(data)
		}
		logger.Info("📝 OP_RETURN: Embedded %d bytes of data (hex preview: %s)", len(data), hexPreview)
	}
	// Push success onto stack
	stack.Push(1)
	return nil
}

// ========== HELPER FUNCTION IMPLEMENTATIONS ==========

// executeHashOp - Generic hash operation
// Pops size, creates dummy data, applies hash function, pushes first 8 bytes of result
// Used by SHA3_256, SHA512_224, SHA512_256 opcodes
func executeHashOp(stack *Stack, hashFunc func([]byte) []byte) error {
	// Pop the size parameter
	size, err := stack.Pop()
	if err != nil {
		return err
	}
	// Create dummy data of the specified size
	data := make([]byte, size)
	// Apply the specified hash function
	hash := hashFunc(data)
	// Push first 8 bytes of hash as uint64
	if len(hash) >= 8 {
		result := binary.BigEndian.Uint64(hash[:8])
		stack.Push(result)
	} else {
		stack.Push(0)
	}
	return nil
}

// executeShakeOp - SHAKE256 extendable-output function
// Pops output length and size, creates dummy data, generates hash, pushes first 8 bytes
func executeShakeOp(stack *Stack) error {
	// Pop output length (how many bytes to generate)
	outputLen, err := stack.Pop()
	if err != nil {
		return err
	}
	// Pop input size (dummy data length)
	size, err := stack.Pop()
	if err != nil {
		return err
	}
	// Create dummy data
	data := make([]byte, size)
	// Generate SHAKE256 hash of requested length
	hash := sha3_shake256(data, int(outputLen))
	// Push first 8 bytes of output
	if len(hash) >= 8 {
		stack.Push(binary.BigEndian.Uint64(hash[:8]))
	} else {
		stack.Push(0)
	}
	return nil
}

// executeArithmeticOp - Handles all arithmetic and bitwise operations
// Supported ops: Xor (0x20), Or (0x21), And (0x22), Rot (0x23), Not (0x24), Shr (0x25), Add (0x26)
// Also supports: SUB, MUL, DIV, SDIV, MOD, SMOD, EXP, SIGNEXTEND
func executeArithmeticOp(op OpCode, stack *Stack) error {
	switch op {
	case Not:
		// Unary operation: pop one value, push its bitwise NOT
		a, err := stack.Pop()
		if err != nil {
			return err
		}
		stack.Push(^a) // Bitwise NOT (ones complement - flips all bits)

	case Rot:
		// Rotate left operation: (a << n) | (a >> (64-n))
		a, err := stack.Pop() // Value to rotate
		if err != nil {
			return err
		}
		n, err := stack.Pop() // Number of bits to rotate
		if err != nil {
			return err
		}
		n = n % 64                           // Modulo 64 for uint64 rotation
		result := (a << n) | (a >> (64 - n)) // Rotate left
		stack.Push(result)

	case Shr:
		b, err := stack.Pop()
		if err != nil {
			return err
		}
		a, err := stack.Pop()
		if err != nil {
			return err
		}
		stack.Push(ShrOp(a, uint(b)))

	case Add:
		b, err := stack.Pop()
		if err != nil {
			return err
		}
		a, err := stack.Pop()
		if err != nil {
			return err
		}
		stack.Push(AddOp(a, b))

	case SUB:
		b, err := stack.Pop()
		if err != nil {
			return err
		}
		a, err := stack.Pop()
		if err != nil {
			return err
		}
		stack.Push(SubOp(a, b))

	case MUL:
		b, err := stack.Pop()
		if err != nil {
			return err
		}
		a, err := stack.Pop()
		if err != nil {
			return err
		}
		stack.Push(MulOp(a, b))

	case DIV:
		b, err := stack.Pop()
		if err != nil {
			return err
		}
		a, err := stack.Pop()
		if err != nil {
			return err
		}
		result, err := DivOp(a, b)
		if err != nil {
			return err
		}
		stack.Push(result)

	case SDIV:
		b, err := stack.Pop()
		if err != nil {
			return err
		}
		a, err := stack.Pop()
		if err != nil {
			return err
		}
		result, err := SDivOp(int64(a), int64(b))
		if err != nil {
			return err
		}
		stack.Push(uint64(result))

	case MOD:
		b, err := stack.Pop()
		if err != nil {
			return err
		}
		a, err := stack.Pop()
		if err != nil {
			return err
		}
		result, err := ModOp(a, b)
		if err != nil {
			return err
		}
		stack.Push(result)

	case SMOD:
		b, err := stack.Pop()
		if err != nil {
			return err
		}
		a, err := stack.Pop()
		if err != nil {
			return err
		}
		result, err := SModOp(int64(a), int64(b))
		if err != nil {
			return err
		}
		stack.Push(uint64(result))

	case EXP:
		b, err := stack.Pop()
		if err != nil {
			return err
		}
		a, err := stack.Pop()
		if err != nil {
			return err
		}
		stack.Push(ExpOp(a, b))

	case SIGNEXTEND:
		b, err := stack.Pop()
		if err != nil {
			return err
		}
		a, err := stack.Pop()
		if err != nil {
			return err
		}
		stack.Push(SignExtendOp(a, b))

	default:
		// Binary operations: pop two values, apply operation, push result
		b, err := stack.Pop() // Second operand (right)
		if err != nil {
			return err
		}
		a, err := stack.Pop() // First operand (left)
		if err != nil {
			return err
		}
		var result uint64
		switch op {
		case Xor:
			result = a ^ b // Bitwise XOR (exclusive OR)
		case Or:
			result = a | b // Bitwise OR (inclusive OR)
		case And:
			result = a & b // Bitwise AND
		}
		stack.Push(result)
	}
	return nil
}

// executeStackOp - Handles stack manipulation operations
// DUP (0x80) - Duplicate top item
// SWAP (0x90) - Swap top two items
// POP (0x50) - Remove top item
func executeStackOp(op OpCode, stack *Stack) error {
	switch op {
	case DUP:
		// Duplicate the top stack item
		val, err := stack.Peek() // Get top without popping
		if err != nil {
			return err
		}
		stack.Push(val) // Push a copy

	case SWAP:
		// Swap the top two stack items
		if stack.Size() < 2 {
			return fmt.Errorf("stack underflow for SWAP")
		}
		a, _ := stack.Pop() // Pop top
		b, _ := stack.Pop() // Pop second
		stack.Push(a)       // Push top back
		stack.Push(b)       // Push second back (now on top)

	case POP:
		// Remove the top stack item (discard it)
		_, err := stack.Pop()
		return err
	}
	return nil
}

// executeMultisigOp - Placeholder for SPHINCS+ multisignature operations
// Currently pushes 1 for all multisig operations (simplified)
// Future implementation will support multisignature aggregation and verification
func executeMultisigOp(op OpCode, stack *Stack) error {
	switch op {
	case OP_SPHINCS_MULTISIG_INIT:
		stack.Push(1) // Initialize multisig context
	case OP_SPHINCS_MULTISIG_SIGN:
		stack.Push(1) // Add signature to multisig
	case OP_SPHINCS_MULTISIG_VERIFY:
		stack.Push(1) // Verify multisig
	case OP_SPHINCS_MULTISIG_PROOF:
		stack.Push(1) // Generate multisig proof
	}
	return nil
}

// ========== NEW HELPER FUNCTIONS ==========

// executeComparisonOp - Handles comparison operations
func executeComparisonOp(op OpCode, stack *Stack) error {
	b, err := stack.Pop()
	if err != nil {
		return err
	}
	a, err := stack.Pop()
	if err != nil {
		return err
	}
	var result uint64
	switch op {
	case LT:
		result = LtOp(a, b)
	case GT:
		result = GtOp(a, b)
	case SLT:
		result = SlTOp(int64(a), int64(b))
	case SGT:
		result = SgTOp(int64(a), int64(b))
	case EQ:
		result = EqOp(a, b)
	case ISZERO:
		stack.Push(IsZeroOp(a))
		return nil
	}
	stack.Push(result)
	return nil
}

// executeBitwiseOp - Handles bitwise operations
func executeBitwiseOp(op OpCode, stack *Stack) error {
	switch op {
	case BYTE:
		b, err := stack.Pop()
		if err != nil {
			return err
		}
		a, err := stack.Pop()
		if err != nil {
			return err
		}
		stack.Push(ByteOp(a, uint(b)))
	case SHL:
		b, err := stack.Pop()
		if err != nil {
			return err
		}
		a, err := stack.Pop()
		if err != nil {
			return err
		}
		stack.Push(ShlOp(a, uint(b)))
	case SAR:
		b, err := stack.Pop()
		if err != nil {
			return err
		}
		a, err := stack.Pop()
		if err != nil {
			return err
		}
		stack.Push(SarOp(a, uint(b)))
	}
	return nil
}

// executeBitcoinScriptOp - Handles Bitcoin script operations
func executeBitcoinScriptOp(op OpCode, stack *Stack, memory []byte) error {
	switch op {
	case OP_CAT:
		// Get second data (length and pointer)
		len2, err := stack.Pop()
		if err != nil {
			return err
		}
		ptr2, err := stack.Pop()
		if err != nil {
			return err
		}
		// Get first data (length and pointer)
		len1, err := stack.Pop()
		if err != nil {
			return err
		}
		ptr1, err := stack.Pop()
		if err != nil {
			return err
		}
		// Validate bounds
		if ptr1+len1 > uint64(len(memory)) || ptr2+len2 > uint64(len(memory)) {
			return fmt.Errorf("data out of bounds")
		}
		data1 := memory[ptr1 : ptr1+len1]
		data2 := memory[ptr2 : ptr2+len2]
		result, err := CatOp(data1, data2)
		if err != nil {
			return err
		}
		// Push result (simplified - would need memory allocation)
		stack.Push(uint64(len(result)))
		stack.Push(0) // Placeholder pointer
	case OP_SIZE:
		len1, err := stack.Pop()
		if err != nil {
			return err
		}
		ptr1, err := stack.Pop()
		if err != nil {
			return err
		}
		if ptr1+len1 > uint64(len(memory)) {
			return fmt.Errorf("data out of bounds")
		}
		data := memory[ptr1 : ptr1+len1]
		stack.Push(SizeOp(data))
	case OP_SUBSTR:
		length, err := stack.Pop()
		if err != nil {
			return err
		}
		start, err := stack.Pop()
		if err != nil {
			return err
		}
		len1, err := stack.Pop()
		if err != nil {
			return err
		}
		ptr1, err := stack.Pop()
		if err != nil {
			return err
		}
		if ptr1+len1 > uint64(len(memory)) {
			return fmt.Errorf("data out of bounds")
		}
		data := memory[ptr1 : ptr1+len1]
		result, err := SubStrOp(data, start, length)
		if err != nil {
			return err
		}
		stack.Push(uint64(len(result)))
		stack.Push(0)
	case OP_LEFT:
		length, err := stack.Pop()
		if err != nil {
			return err
		}
		len1, err := stack.Pop()
		if err != nil {
			return err
		}
		ptr1, err := stack.Pop()
		if err != nil {
			return err
		}
		if ptr1+len1 > uint64(len(memory)) {
			return fmt.Errorf("data out of bounds")
		}
		data := memory[ptr1 : ptr1+len1]
		result, err := LeftOp(data, length)
		if err != nil {
			return err
		}
		stack.Push(uint64(len(result)))
		stack.Push(0)
	case OP_RIGHT:
		length, err := stack.Pop()
		if err != nil {
			return err
		}
		len1, err := stack.Pop()
		if err != nil {
			return err
		}
		ptr1, err := stack.Pop()
		if err != nil {
			return err
		}
		if ptr1+len1 > uint64(len(memory)) {
			return fmt.Errorf("data out of bounds")
		}
		data := memory[ptr1 : ptr1+len1]
		result, err := RightOp(data, length)
		if err != nil {
			return err
		}
		stack.Push(uint64(len(result)))
		stack.Push(0)
	case OP_SPLIT:
		position, err := stack.Pop()
		if err != nil {
			return err
		}
		len1, err := stack.Pop()
		if err != nil {
			return err
		}
		ptr1, err := stack.Pop()
		if err != nil {
			return err
		}
		if ptr1+len1 > uint64(len(memory)) {
			return fmt.Errorf("data out of bounds")
		}
		data := memory[ptr1 : ptr1+len1]
		left, right, err := SplitOp(data, position)
		if err != nil {
			return err
		}
		// Push right then left (stack order)
		stack.Push(uint64(len(right)))
		stack.Push(0)
		stack.Push(uint64(len(left)))
		stack.Push(0)
	}
	return nil
}

// executeControlFlowOp - Handles control flow operations
func executeControlFlowOp(op OpCode, stack *Stack, code []byte, pc *uint64) error {
	switch op {
	case PC:
		stack.Push(*pc)
	case JUMPDEST:
		// No operation, just a marker
		return nil
	case JUMP:
		dest, err := stack.Pop()
		if err != nil {
			return err
		}
		if dest >= uint64(len(code)) {
			return fmt.Errorf("invalid jump destination")
		}
		*pc = dest
		return nil // Skip the automatic pc increment
	case JUMPI:
		cond, err := stack.Pop()
		if err != nil {
			return err
		}
		dest, err := stack.Pop()
		if err != nil {
			return err
		}
		if cond != 0 {
			if dest >= uint64(len(code)) {
				return fmt.Errorf("invalid jump destination")
			}
			*pc = dest
			return nil // Skip the automatic pc increment
		}
	}
	return nil
}

// executeEthereumContextOp - Handles Ethereum context operations
func executeEthereumContextOp(op OpCode, stack *Stack, memory []byte) error {
	// These are placeholder implementations
	switch op {
	case ADDRESS, ORIGIN, CALLER, COINBASE:
		// Push a placeholder address (20 bytes as uint64 is too small)
		// In production, these would push 160-bit addresses
		stack.Push(0)
	case CALLVALUE, GASPRICE, SELFBALANCE:
		stack.Push(0)
	case CALLDATALOAD:
		stack.Push(0)
	case CALLDATASIZE, CODESIZE, EXTCODESIZE, RETURNDATASIZE:
		stack.Push(0)
	case CALLDATACOPY, CODECOPY, EXTCODECOPY, RETURNDATACOPY:
		// Pop parameters and do nothing (placeholder)
		for i := 0; i < 3; i++ {
			stack.Pop()
		}
	}
	return nil
}

// executeBlockContextOp - Handles block context operations
func executeBlockContextOp(op OpCode, stack *Stack) error {
	switch op {
	case BLOCKHASH:
		stack.Push(0)
	case TIMESTAMP:
		stack.Push(uint64(time.Now().Unix()))
	case NUMBER:
		stack.Push(0)
	case DIFFICULTY:
		stack.Push(0)
	case GASLIMIT:
		stack.Push(0)
	case CHAINID:
		stack.Push(1)
	}
	return nil
}

// executeBitcoinScriptStackOp - Handles Bitcoin script stack operations
func executeBitcoinScriptStackOp(op OpCode, stack *Stack) error {
	switch op {
	case OP_VERIFY:
		val, err := stack.Pop()
		if err != nil {
			return err
		}
		if val == 0 {
			return fmt.Errorf("VERIFY failed")
		}
	case OP_EQUAL:
		b, err := stack.Pop()
		if err != nil {
			return err
		}
		a, err := stack.Pop()
		if err != nil {
			return err
		}
		if a == b {
			stack.Push(1)
		} else {
			stack.Push(0)
		}
	case OP_EQUALVERIFY:
		b, err := stack.Pop()
		if err != nil {
			return err
		}
		a, err := stack.Pop()
		if err != nil {
			return err
		}
		if a != b {
			return fmt.Errorf("EQUALVERIFY failed")
		}
	case OP_DEPTH:
		stack.Push(uint64(stack.Size()))
	case OP_NIP:
		if stack.Size() < 2 {
			return fmt.Errorf("stack underflow")
		}
		top, _ := stack.Pop()
		stack.Pop() // Remove second
		stack.Push(top)
	case OP_OVER:
		if stack.Size() < 2 {
			return fmt.Errorf("stack underflow")
		}
		// Get second item without popping
		second := stack.data[stack.Size()-2]
		stack.Push(second)
	case OP_PICK:
		n, err := stack.Pop()
		if err != nil {
			return err
		}
		if uint64(stack.Size()) <= n {
			return fmt.Errorf("stack underflow")
		}
		val := stack.data[stack.Size()-1-int(n)]
		stack.Push(val)
	case OP_ROLL:
		n, err := stack.Pop()
		if err != nil {
			return err
		}
		if uint64(stack.Size()) <= n {
			return fmt.Errorf("stack underflow")
		}
		idx := stack.Size() - 1 - int(n)
		val := stack.data[idx]
		// Remove and shift
		stack.data = append(stack.data[:idx], stack.data[idx+1:]...)
		stack.Push(val)
	case OP_ROT:
		if stack.Size() < 3 {
			return fmt.Errorf("stack underflow")
		}
		a, _ := stack.Pop()
		b, _ := stack.Pop()
		c, _ := stack.Pop()
		stack.Push(b)
		stack.Push(a)
		stack.Push(c)
	case OP_TUCK:
		if stack.Size() < 2 {
			return fmt.Errorf("stack underflow")
		}
		top, _ := stack.Pop()
		second, _ := stack.Pop()
		stack.Push(top)
		stack.Push(second)
		stack.Push(top)
	}
	return nil
}

// OP_CHECK_SIGNATURE_HASH - Verifies signature hash and checks for replay
// Expected stack layout (top to bottom):
//
//	sigHash_len, sigHash_ptr, sig_len, sig_ptr
//
// This opcode:
//  1. Recomputes signature hash from signature bytes in memory
//  2. Compares with expected signature hash from stack
//  3. Checks if this signature hash has been seen before (replay detection)
//  4. Pushes 1 if hash matches AND not seen before, 0 otherwise
func executeCheckSignatureHash(stack *Stack, memory []byte) error {
	// Pop expected signature hash length (should be 32 bytes)
	expectedHashLen, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing expected signature hash length: %v", err)
	}

	// Pop expected signature hash pointer
	expectedHashPtr, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing expected signature hash pointer: %v", err)
	}

	// Pop signature length
	sigLen, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing signature length: %v", err)
	}

	// Pop signature pointer
	sigPtr, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing signature pointer: %v", err)
	}

	// Validate memory bounds
	if sigPtr+sigLen > uint64(len(memory)) {
		return fmt.Errorf("signature out of bounds: ptr=%d, len=%d, mem=%d", sigPtr, sigLen, len(memory))
	}
	if expectedHashPtr+expectedHashLen > uint64(len(memory)) {
		return fmt.Errorf("expected hash out of bounds")
	}

	// Extract signature bytes from memory
	signature := memory[sigPtr : sigPtr+sigLen]

	// Extract expected signature hash from memory
	expectedHash := memory[expectedHashPtr : expectedHashPtr+expectedHashLen]

	// Step 1: Recompute signature hash from signature bytes
	recomputedHash := sha3_256(signature) // Use SHA3-256 for hash

	// Step 2: Verify hash matches
	if len(recomputedHash) != len(expectedHash) {
		stack.Push(0) // Length mismatch
		return nil
	}

	for i := range recomputedHash {
		if recomputedHash[i] != expectedHash[i] {
			stack.Push(0) // Hash mismatch - Alice lying or data corruption
			return nil
		}
	}

	// Step 3: Check if this signature hash has been seen before (replay detection)
	hashKey := string(recomputedHash)
	exists := signatureHashStore[hashKey]

	if exists {
		stack.Push(0) // Signature already used - replay attack
	} else {
		stack.Push(1) // Hash matches and is fresh
	}

	return nil
}

// OP_VERIFY_SIGNATURE_HASH - Same as CHECK but fails on invalid or replay
// This opcode halts execution if the signature hash is invalid or already used
func executeVerifySignatureHash(stack *Stack, memory []byte) error {
	// Same parameter popping as executeCheckSignatureHash
	expectedHashLen, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing expected signature hash length: %v", err)
	}

	expectedHashPtr, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing expected signature hash pointer: %v", err)
	}

	sigLen, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing signature length: %v", err)
	}

	sigPtr, err := stack.Pop()
	if err != nil {
		return fmt.Errorf("missing signature pointer: %v", err)
	}

	// Validate bounds
	if sigPtr+sigLen > uint64(len(memory)) {
		return fmt.Errorf("signature out of bounds")
	}
	if expectedHashPtr+expectedHashLen > uint64(len(memory)) {
		return fmt.Errorf("expected hash out of bounds")
	}

	// Extract data
	signature := memory[sigPtr : sigPtr+sigLen]
	expectedHash := memory[expectedHashPtr : expectedHashPtr+expectedHashLen]

	// Recompute and verify hash
	recomputedHash := sha3_256(signature)

	if len(recomputedHash) != len(expectedHash) {
		return fmt.Errorf("signature hash verification failed: length mismatch")
	}

	for i := range recomputedHash {
		if recomputedHash[i] != expectedHash[i] {
			return fmt.Errorf("signature hash verification failed: hash mismatch")
		}
	}

	// Check for replay
	hashKey := string(recomputedHash)
	if signatureHashStore[hashKey] {
		return fmt.Errorf("signature hash replay detected: this signature has been used before")
	}

	// All checks passed
	return nil
}

// OP_STORE_SIGNATURE_HASH - Stores signature hash after successful verification
// This should be called after OP_VERIFY_SIGNATURE_HASH passes
// Pushes 1 on success
func executeStoreSignatureHash(stack *Stack, memory []byte) error {
	// Pop signature hash length and pointer
	hashLen, err := stack.Pop()
	if err != nil {
		return err
	}
	hashPtr, err := stack.Pop()
	if err != nil {
		return err
	}

	// Validate bounds
	if hashPtr+hashLen > uint64(len(memory)) {
		return fmt.Errorf("signature hash out of bounds")
	}

	// Extract signature hash
	signatureHash := memory[hashPtr : hashPtr+hashLen]

	// Store in signatureHashStore to prevent future replays
	hashKey := string(signatureHash)
	signatureHashStore[hashKey] = true

	stack.Push(1) // Success
	return nil
}

// ========== OPCODE CONSTANTS ==========
// All opcodes are single-byte values that the VM interprets
// Opcodes are grouped by functionality with gaps for future expansion

const (
	// Push operations - Load immediate values from bytecode onto stack
	// PUSH1 (0x60) and PUSH2 (0x61) are unchanged - no conflicts
	// PUSH4 remapped from 0x63 → 0xB0 to avoid collision with OP_IF (0x63)
	// PUSH8 remapped from 0x67 → 0xB1 to avoid collision with OP_ELSE (0x67)
	PUSH1 OpCode = 0x60 // Push next 1 byte as uint64 value
	PUSH2 OpCode = 0x61 // Push next 2 bytes as uint64 value
	PUSH4 OpCode = 0xB0 // Push next 4 bytes as uint64 value (remapped from 0x63)
	PUSH8 OpCode = 0xB1 // Push next 8 bytes as uint64 value (remapped from 0x67)

	// Stack operations (0x50,0x80,0x90) - Manipulate stack without changing values
	DUP  OpCode = 0x80 // Duplicate top stack item
	SWAP OpCode = 0x90 // Swap top two stack items
	POP  OpCode = 0x50 // Remove top stack item

	// Hash operations (0x10-0x14) - Cryptographic hash functions
	SphinxHash    OpCode = 0x10 // Custom Sphinx hash function using spxhash package
	SHA3_256      OpCode = 0x11 // SHA3-256 hash (32 bytes output)
	SHA512_224    OpCode = 0x12 // SHA3-512 truncated to 224 bits (28 bytes)
	SHA512_256    OpCode = 0x13 // SHA3-512 truncated to 256 bits (32 bytes)
	SHA3_Shake256 OpCode = 0x14 // SHAKE256 extendable-output function

	// Bitwise operations (0x20-0x26) - Arithmetic and logical operations
	Xor OpCode = 0x20 // Bitwise XOR (exclusive OR)
	Or  OpCode = 0x21 // Bitwise OR (inclusive OR)
	And OpCode = 0x22 // Bitwise AND
	Rot OpCode = 0x23 // Rotate left (circular shift)
	Not OpCode = 0x24 // Bitwise NOT (ones complement)
	Shr OpCode = 0x25 // Shift right (logical shift)
	Add OpCode = 0x26 // Addition (mod 2^64, wraps on overflow)

	// ========== NEW ARITHMETIC OPERATIONS (0x27-0x2E) ==========
	SUB        OpCode = 0x27 // Subtraction (a - b)
	MUL        OpCode = 0x28 // Multiplication (a * b)
	DIV        OpCode = 0x29 // Unsigned integer division (a / b)
	SDIV       OpCode = 0x2A // Signed integer division
	MOD        OpCode = 0x2B // Unsigned modulo (a % b)
	SMOD       OpCode = 0x2C // Signed modulo
	EXP        OpCode = 0x2D // Exponentiation (a ^ b)
	SIGNEXTEND OpCode = 0x2E // Sign extend from b bits

	// ========== COMPARISON OPERATIONS (0x31-0x36) ==========
	LT     OpCode = 0x31 // Less than
	GT     OpCode = 0x32 // Greater than
	SLT    OpCode = 0x33 // Signed less than
	SGT    OpCode = 0x34 // Signed greater than
	EQ     OpCode = 0x35 // Equality
	ISZERO OpCode = 0x36 // Check if zero

	// ========== BITWISE OPERATIONS (0x3A-0x3C) ==========
	BYTE OpCode = 0x3A // Get Nth byte from word
	SHL  OpCode = 0x3B // Shift left
	SAR  OpCode = 0x3C // Arithmetic shift right

	// ========== ETHEREUM CONTEXT OPERATIONS ==========
	// ADDRESS (0x30) - unchanged, no conflict
	// ORIGIN remapped from 0x32 → 0xA0 to avoid collision with GT (0x32)
	// CALLER remapped from 0x33 → 0xA1 to avoid collision with SLT (0x33)
	// CALLVALUE remapped from 0x34 → 0xA2 to avoid collision with SGT (0x34)
	// CALLDATALOAD remapped from 0x35 → 0xA3 to avoid collision with EQ (0x35)
	// CALLDATASIZE remapped from 0x36 → 0xA4 to avoid collision with ISZERO (0x36)
	// CALLDATACOPY (0x37), CODESIZE (0x38), CODECOPY (0x39) - unchanged, no conflict
	// EXTCODESIZE remapped from 0x3B → 0xA5 to avoid collision with SHL (0x3B)
	// EXTCODECOPY remapped from 0x3C → 0xA6 to avoid collision with SAR (0x3C)
	// RETURNDATASIZE (0x3D), RETURNDATACOPY (0x3E), GASPRICE (0x3F) - unchanged, no conflict
	ADDRESS        OpCode = 0x30 // Get address of executing account
	ORIGIN         OpCode = 0xA0 // Get transaction origin (remapped from 0x32)
	CALLER         OpCode = 0xA1 // Get caller address (remapped from 0x33)
	CALLVALUE      OpCode = 0xA2 // Get value sent with call (remapped from 0x34)
	CALLDATALOAD   OpCode = 0xA3 // Load input data (remapped from 0x35)
	CALLDATASIZE   OpCode = 0xA4 // Get input data size (remapped from 0x36)
	CALLDATACOPY   OpCode = 0x37 // Copy input data
	CODESIZE       OpCode = 0x38 // Get code size
	CODECOPY       OpCode = 0x39 // Copy code
	EXTCODESIZE    OpCode = 0xA5 // Get external code size (remapped from 0x3B)
	EXTCODECOPY    OpCode = 0xA6 // Copy external code (remapped from 0x3C)
	RETURNDATASIZE OpCode = 0x3D // Get return data size
	RETURNDATACOPY OpCode = 0x3E // Copy return data
	GASPRICE       OpCode = 0x3F // Get gas price

	// ========== ETHEREUM BLOCK CONTEXT (0x40-0x47) ==========
	BLOCKHASH   OpCode = 0x40 // Get block hash
	COINBASE    OpCode = 0x41 // Get block miner address
	TIMESTAMP   OpCode = 0x42 // Get block timestamp
	NUMBER      OpCode = 0x43 // Get block number
	DIFFICULTY  OpCode = 0x44 // Get block difficulty
	GASLIMIT    OpCode = 0x45 // Get block gas limit
	CHAINID     OpCode = 0x46 // Get chain ID
	SELFBALANCE OpCode = 0x47 // Get balance of current account

	// ========== CONTROL FLOW OPERATIONS (0x56-0x5B) ==========
	JUMP     OpCode = 0x56 // Unconditional jump
	JUMPI    OpCode = 0x57 // Conditional jump
	PC       OpCode = 0x58 // Program counter
	JUMPDEST OpCode = 0x5B // Jump destination marker

	// ========== BITCOIN SCRIPT OPS (0x63-0x68,0x69,0x74,0x77-0x7B,0x7D,0x87-0x88) ==========
	// OP_IF (0x63) and OP_ELSE (0x67) are now conflict-free because PUSH4 and PUSH8
	// have been remapped to 0xB0 and 0xB1 respectively
	OP_IF          OpCode = 0x63 // Conditional if
	OP_ELSE        OpCode = 0x67 // Conditional else
	OP_ENDIF       OpCode = 0x68 // End conditional
	OP_VERIFY      OpCode = 0x69 // Verify condition
	OP_DEPTH       OpCode = 0x74 // Stack depth
	OP_NIP         OpCode = 0x77 // Remove second item
	OP_OVER        OpCode = 0x78 // Copy second item to top
	OP_PICK        OpCode = 0x79 // Pick item from depth
	OP_ROLL        OpCode = 0x7A // Move item to top
	OP_ROT         OpCode = 0x7B // Rotate top three items
	OP_TUCK        OpCode = 0x7D // Copy top to third position
	OP_EQUAL       OpCode = 0x87 // Check equality
	OP_EQUALVERIFY OpCode = 0x88 // Equal then verify

	// ========== BITCOIN SCRIPT OPERATIONS (0x7E-0x7F,0x8A-0x8D) ==========
	OP_CAT    OpCode = 0x7E // Concatenate two strings
	OP_SUBSTR OpCode = 0x7F // Extract substring
	OP_LEFT   OpCode = 0x8A // Take leftmost bytes
	OP_RIGHT  OpCode = 0x8B // Take rightmost bytes
	OP_SIZE   OpCode = 0x8C // Get size of data
	OP_SPLIT  OpCode = 0x8D // Split at position

	// SPHINCS+ protocol opcodes (0xD0-0xDA) - Post-quantum signature operations
	OP_CHECK_SPHINCS        OpCode = 0xD0 // Verify signature, push 1/0 on stack
	OP_VERIFY_SPHINCS       OpCode = 0xD1 // Verify signature, fail if invalid
	OP_DUP_SPHINCS          OpCode = 0xD2 // Duplicate top 6 SPHINCS stack items
	OP_CHECK_TIMESTAMP      OpCode = 0xD3 // Verify timestamp freshness (5 min window)
	OP_CHECK_NONCE          OpCode = 0xD4 // Verify nonce uniqueness (replay protection)
	OP_STORE_NONCE          OpCode = 0xD5 // Store nonce for replay protection
	OP_VERIFY_MERKLE_ROOT   OpCode = 0xD6 // Verify Merkle root matches signature
	OP_VERIFY_COMMITMENT    OpCode = 0xD7 // Verify commitment hash matches
	OP_BUILD_MERKLE_TREE    OpCode = 0xD8 // Build Merkle tree from signature
	OP_STORE_RECEIPT        OpCode = 0xD9 // Store transaction receipt (commitment->root)
	OP_VERIFY_PROOF         OpCode = 0xDA // Verify light client proof
	OP_STORE_SIGNATURE_HASH OpCode = 0xDD // Store signature hash after verification

	// Legacy SPHINCS+ Multisig operations (0xE0-0xE3) - Placeholder for multisignatures
	OP_SPHINCS_MULTISIG_INIT   OpCode = 0xE0 // Initialize multisignature context
	OP_SPHINCS_MULTISIG_SIGN   OpCode = 0xE1 // Add signature to multisignature
	OP_SPHINCS_MULTISIG_VERIFY OpCode = 0xE2 // Verify multisignature
	OP_SPHINCS_MULTISIG_PROOF  OpCode = 0xE3 // Generate multisignature proof

	// OP_RETURN (0xFD) - Embed arbitrary data (memos, proofs, metadata)
	// Similar to Bitcoin's OP_RETURN - stores data without affecting state
	// Maximum size is configurable (default 80 bytes like Bitcoin)
	OP_RETURN OpCode = 0xFD

	// Add this with the other SPHINCS+ protocol opcodes (0xD0-0xDA)
	OP_CHECK_SIGNATURE_HASH  OpCode = 0xDB // Verify signature hash and check replay
	OP_VERIFY_SIGNATURE_HASH OpCode = 0xDC // Verify signature hash, fail if invalid or replay
)

// ========== STRING TO OPCODE MAPPING ==========
// stringToOp maps string representations to OpCode values
// Used for parsing human-readable opcode names from configuration or scripts
var stringToOp = map[string]OpCode{
	"SphinxHash":              SphinxHash,
	"SHA3_256":                SHA3_256,
	"SHA512_224":              SHA512_224,
	"SHA512_256":              SHA512_256,
	"SHA3_Shake256":           SHA3_Shake256,
	"Xor":                     Xor,
	"Or":                      Or,
	"And":                     And,
	"Rot":                     Rot,
	"Not":                     Not,
	"Shr":                     Shr,
	"Add":                     Add,
	"SUB":                     SUB,
	"MUL":                     MUL,
	"DIV":                     DIV,
	"SDIV":                    SDIV,
	"MOD":                     MOD,
	"SMOD":                    SMOD,
	"EXP":                     EXP,
	"SIGNEXTEND":              SIGNEXTEND,
	"LT":                      LT,
	"GT":                      GT,
	"SLT":                     SLT,
	"SGT":                     SGT,
	"EQ":                      EQ,
	"ISZERO":                  ISZERO,
	"BYTE":                    BYTE,
	"SHL":                     SHL,
	"SAR":                     SAR,
	"ADDRESS":                 ADDRESS,
	"ORIGIN":                  ORIGIN,       // now 0xA0
	"CALLER":                  CALLER,       // now 0xA1
	"CALLVALUE":               CALLVALUE,    // now 0xA2
	"CALLDATALOAD":            CALLDATALOAD, // now 0xA3
	"CALLDATASIZE":            CALLDATASIZE, // now 0xA4
	"CALLDATACOPY":            CALLDATACOPY,
	"CODESIZE":                CODESIZE,
	"CODECOPY":                CODECOPY,
	"EXTCODESIZE":             EXTCODESIZE, // now 0xA5
	"EXTCODECOPY":             EXTCODECOPY, // now 0xA6
	"RETURNDATASIZE":          RETURNDATASIZE,
	"RETURNDATACOPY":          RETURNDATACOPY,
	"GASPRICE":                GASPRICE,
	"BLOCKHASH":               BLOCKHASH,
	"COINBASE":                COINBASE,
	"TIMESTAMP":               TIMESTAMP,
	"NUMBER":                  NUMBER,
	"DIFFICULTY":              DIFFICULTY,
	"GASLIMIT":                GASLIMIT,
	"CHAINID":                 CHAINID,
	"SELFBALANCE":             SELFBALANCE,
	"JUMP":                    JUMP,
	"JUMPI":                   JUMPI,
	"PC":                      PC,
	"JUMPDEST":                JUMPDEST,
	"OP_IF":                   OP_IF,
	"OP_ELSE":                 OP_ELSE,
	"OP_ENDIF":                OP_ENDIF,
	"OP_VERIFY":               OP_VERIFY,
	"OP_DEPTH":                OP_DEPTH,
	"OP_NIP":                  OP_NIP,
	"OP_OVER":                 OP_OVER,
	"OP_PICK":                 OP_PICK,
	"OP_ROLL":                 OP_ROLL,
	"OP_ROT":                  OP_ROT,
	"OP_TUCK":                 OP_TUCK,
	"OP_EQUAL":                OP_EQUAL,
	"OP_EQUALVERIFY":          OP_EQUALVERIFY,
	"OP_CAT":                  OP_CAT,
	"OP_SUBSTR":               OP_SUBSTR,
	"OP_LEFT":                 OP_LEFT,
	"OP_RIGHT":                OP_RIGHT,
	"OP_SIZE":                 OP_SIZE,
	"OP_SPLIT":                OP_SPLIT,
	"PUSH1":                   PUSH1,
	"PUSH2":                   PUSH2,
	"PUSH4":                   PUSH4, // now 0xB0
	"PUSH8":                   PUSH8, // now 0xB1
	"DUP":                     DUP,
	"SWAP":                    SWAP,
	"POP":                     POP,
	"CHECK_SPHINCS":           OP_CHECK_SPHINCS,
	"VERIFY_SPHINCS":          OP_VERIFY_SPHINCS,
	"DUP_SPHINCS":             OP_DUP_SPHINCS,
	"CHECK_TIMESTAMP":         OP_CHECK_TIMESTAMP,
	"CHECK_NONCE":             OP_CHECK_NONCE,
	"STORE_NONCE":             OP_STORE_NONCE,
	"VERIFY_MERKLE_ROOT":      OP_VERIFY_MERKLE_ROOT,
	"VERIFY_COMMITMENT":       OP_VERIFY_COMMITMENT,
	"BUILD_MERKLE_TREE":       OP_BUILD_MERKLE_TREE,
	"STORE_RECEIPT":           OP_STORE_RECEIPT,
	"VERIFY_PROOF":            OP_VERIFY_PROOF,
	"SPHINCS_MULTISIG_INIT":   OP_SPHINCS_MULTISIG_INIT,
	"SPHINCS_MULTISIG_SIGN":   OP_SPHINCS_MULTISIG_SIGN,
	"SPHINCS_MULTISIG_VERIFY": OP_SPHINCS_MULTISIG_VERIFY,
	"SPHINCS_MULTISIG_PROOF":  OP_SPHINCS_MULTISIG_PROOF,
	"RETURN":                  OP_RETURN, // Alias for OP_RETURN
	"OP_RETURN":               OP_RETURN,
	"CHECK_SIGNATURE_HASH":    OP_CHECK_SIGNATURE_HASH,
	"VERIFY_SIGNATURE_HASH":   OP_VERIFY_SIGNATURE_HASH,
	"STORE_SIGNATURE_HASH":    OP_STORE_SIGNATURE_HASH,
}

// OpCodeFromString returns the OpCode corresponding to a given string
// Used for converting human-readable opcode names to byte values
// Example: op, err := OpCodeFromString("SHA3_256") returns 0x11, nil
func OpCodeFromString(name string) (OpCode, error) {
	if op, exists := stringToOp[name]; exists {
		return op, nil
	}
	return 0, fmt.Errorf("unknown opcode: %s", name)
}
