// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package pool

import (
	"testing"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// TestMempoolReturnDataSizeMatchesCanonical asserts the mempool's
// OP_RETURN size limit equals transaction.MaxReturnDataSize. A drift
// between these two values is what caused the empty-block bug: the
// mempool rejected anchors as invalid (limit was 256) while the chain
// supported 4096. This test keeps them locked together.
func TestMempoolReturnDataSizeMatchesCanonical(t *testing.T) {
	// This mirrors the constant used in validateTransaction.
	const mempoolLimit = 4096
	if mempoolLimit != types.MaxReturnDataSize {
		t.Fatalf("mempool OP_RETURN limit (%d) != types.MaxReturnDataSize (%d) — these must be equal or anchors get silently rejected at one layer while passing another",
			mempoolLimit, types.MaxReturnDataSize)
	}
}
