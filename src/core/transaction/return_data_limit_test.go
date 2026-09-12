// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package types

import (
	"testing"
)

// TestMaxReturnDataSizeCanonical confirms the constant matches the documented
// chain limit and hasn't been silently edited to a value the other layers
// (mempool validation, SVM opcode execution) no longer agree with.
func TestMaxReturnDataSizeCanonical(t *testing.T) {
	// NFT anchor payloads are ~480 bytes today; this limit must stay above that
	// with headroom for richer metadata. If you lower it below ~1024, re-mint
	// the test in pool/validation_test.go and opcode/op_return_size_test.go —
	// they assert against this exact value.
	if MaxReturnDataSize != 4096 {
		t.Fatalf("MaxReturnDataSize = %d, want 4096 — this is the canonical chain limit; mempool validation and SVM OP_RETURN must match", MaxReturnDataSize)
	}
}
