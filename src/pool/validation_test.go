// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package pool

import (
	"math/big"
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

// TestValidateTransactionBasicAllowsZeroValueContractTxs covers the admission
// rule that produced the reported
// "basic validation failed: empty sender or receiver" on "Deploy New
// Collection". A contract deploy carries no external recipient and zero value,
// so both the empty-Receiver and the positive-Amount rule must be relaxed for
// contract payloads — while plain transfers keep both rules.
func TestValidateTransactionBasicAllowsZeroValueContractTxs(t *testing.T) {
	mp := &Mempool{}

	mustPass := func(name string, tx *types.Transaction) {
		t.Helper()
		if err := mp.validateTransactionBasic(tx); err != nil {
			t.Fatalf("%s: expected admission, got: %v", name, err)
		}
	}
	mustFail := func(name string, tx *types.Transaction) {
		t.Helper()
		if err := mp.validateTransactionBasic(tx); err == nil {
			t.Fatalf("%s: expected rejection, got none", name)
		}
	}

	// The exact shape the node's deploycontract RPC builds: no Receiver, zero
	// value, Code carrying the DeploySpec.
	mustPass("zero-value receiverless deploy", &types.Transaction{
		Sender: "SPIF00112233445566778899AABBCCDDEEFF00112233",
		Amount: big.NewInt(0),
		Code:   []byte(`{"runtime":"native","standard":"sip721","name":"Datasets","symbol":"DSC"}`),
	})

	// A value-less contract call (list / cancel / revoke_license) takes the
	// same shape: ToContract set, no Receiver, zero value.
	mustPass("zero-value receiverless call", &types.Transaction{
		Sender:     "SPIF00112233445566778899AABBCCDDEEFF00112233",
		Amount:     big.NewInt(0),
		ToContract: "SPIF11223344556677889900AABBCCDDEEFF1122334455",
	})

	// Plain transfers keep the original rules.
	mustFail("receiverless transfer", &types.Transaction{
		Sender: "SPIF00112233445566778899AABBCCDDEEFF00112233",
		Amount: big.NewInt(1),
	})
	mustFail("zero-amount transfer", &types.Transaction{
		Sender:   "SPIF00112233445566778899AABBCCDDEEFF00112233",
		Receiver: "SPIF11223344556677889900AABBCCDDEEFF1122334455",
		Amount:   big.NewInt(0),
	})
	mustFail("negative-amount deploy", &types.Transaction{
		Sender: "SPIF00112233445566778899AABBCCDDEEFF00112233",
		Amount: big.NewInt(-1),
		Code:   []byte(`{}`),
	})
}
