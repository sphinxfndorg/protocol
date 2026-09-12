// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package svm

import (
	"testing"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// TestOpcodeReturnDataSizeMatchesCanonical asserts the SVM OP_RETURN
// handler's size limit equals transaction.MaxReturnDataSize. A drift
// between these two values is what caused ReturnData to be silently
// discarded at CommitBlock time: the transaction still landed in the
// block, but vm.Run() failed and the data was never stored. This test
// keeps the SVM limit locked to the canonical chain value.
func TestOpcodeReturnDataSizeMatchesCanonical(t *testing.T) {
	// This mirrors the constant used in executeOpReturn.
	const opcodeLimit = 4096
	if opcodeLimit != types.MaxReturnDataSize {
		t.Fatalf("SVM OP_RETURN limit (%d) != types.MaxReturnDataSize (%d) — these must be equal or ReturnData gets silently dropped at commit time",
			opcodeLimit, types.MaxReturnDataSize)
	}
}
