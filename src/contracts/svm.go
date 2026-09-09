// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"fmt"

	svm "github.com/sphinxfndorg/protocol/src/core/kernel/opcodes"
	kv "github.com/sphinxfndorg/protocol/src/core/kernel/vm"
)

// SVM1 magic and opcode bytes are defined centrally in the kernel opcode
// package. They are re-exported here so the contracts layer and its callers
// keep this identical public API while the authoritative definitions live
// next to the rest of the kernel opcode set.
var SVM1Magic = svm.SVM1Magic

const (
	SVMStop  = svm.SVMStop
	SVMPush8 = svm.SVMPush8
	SVMAdd   = svm.SVMAdd
	SVMSub   = svm.SVMSub
	SVMMul   = svm.SVMMul
	SVMDiv   = svm.SVMDiv
	SVMStore = svm.SVMStore
	SVMLoad  = svm.SVMLoad
	// SVMCallDataWord pops a byte offset and pushes an eight-byte big-endian
	// word from transaction call data (zero-padded past its end).
	SVMCallDataWord = svm.SVMCallDataWord
	SVMReturn       = svm.SVMReturn
)

// AnalyzeSVM validates an SVM1 program without executing it and returns its
// exact operation count. SVM1 has no branches, so this is deterministic and
// lets mempool admission enforce the same policy gas floor as block execution.
func AnalyzeSVM(code []byte) (uint64, error) {
	return svm.AnalyzeSVM(code)
}

// ExecuteSVM runs SVM1 code. Storage keys and values are uint64, encoded in
// deterministic big-endian form. It returns consumed operation count.
func ExecuteSVM(store Store, address string, code []byte, maxOperations uint64) (*ExecutionResult, uint64, error) {
	return ExecuteSVMWithCallData(store, address, code, nil, maxOperations)
}

// ExecuteSVMWithCallData executes SVM1 with immutable transaction input. The
// Store satisfies the kernel engine's SVM1Store interface (it only needs the
// storage get/set methods), so execution itself lives in src/core/kernel/vm.
func ExecuteSVMWithCallData(store Store, address string, code, callData []byte, maxOperations uint64) (*ExecutionResult, uint64, error) {
	result, ops, err := kv.ExecuteSVM1(store, address, code, callData, maxOperations)
	if err != nil {
		return nil, ops, err
	}
	return &ExecutionResult{
		ContractAddress: address,
		Status:          "ok",
		Return:          map[string]string{"result": fmt.Sprintf("%d", result)},
	}, ops, nil
}
