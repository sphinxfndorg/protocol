// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package types

import (
	"math/big"
	"testing"
	"time"
)

// TestSanityCheckAllowsReceiverlessContractTxs locks in the fix for the
// reported "deploy failed: ... empty sender or receiver".
//
// A contract deployment has no external recipient: its destination is the
// address the chain derives from (Sender, Nonce, Code) at execution time. A
// contract call names its destination in ToContract. Demanding a non-empty
// Receiver rejected every contract transaction at mempool admission, block
// validation, and consensus alike — which made contract deployment impossible.
func TestSanityCheckAllowsReceiverlessContractTxs(t *testing.T) {
	base := func() *Transaction {
		return &Transaction{
			Sender:    "SPIF00112233445566778899AABBCCDDEEFF00112233",
			Amount:    big.NewInt(0),
			GasLimit:  big.NewInt(21000),
			GasPrice:  big.NewInt(1000000000),
			Timestamp: time.Now().Unix(),
		}
	}

	deploy := base()
	deploy.Code = []byte(`{"runtime":"native","standard":"sip721","name":"Datasets","symbol":"DSC"}`)
	if !deploy.IsContractDeployment() || !deploy.HasContractPayload() {
		t.Fatal("a tx with Code set must classify as a contract deployment")
	}
	if err := deploy.SanityCheck(); err != nil {
		t.Fatalf("receiverless deploy must pass SanityCheck, got: %v", err)
	}

	call := base()
	call.ToContract = "SPIF11223344556677889900AABBCCDDEEFF1122334455"
	if !call.IsContractCall() || !call.HasContractPayload() {
		t.Fatal("a tx with ToContract set must classify as a contract call")
	}
	if err := call.SanityCheck(); err != nil {
		t.Fatalf("receiverless contract call must pass SanityCheck, got: %v", err)
	}

	// A transaction with neither Code nor ToContract is still a plain transfer
	// and must still require a destination.
	bare := base()
	if bare.HasContractPayload() {
		t.Fatal("a tx with neither Code nor ToContract must not be a contract payload")
	}
	if err := bare.SanityCheck(); err == nil {
		t.Fatal("a receiverless plain transfer must still be rejected")
	}

	// An ordinary transfer is unaffected.
	plain := base()
	plain.Receiver = "SPIF11223344556677889900AABBCCDDEEFF1122334455"
	plain.Amount = big.NewInt(1)
	if err := plain.SanityCheck(); err != nil {
		t.Fatalf("ordinary transfer must pass SanityCheck, got: %v", err)
	}
}
