// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"math/big"
	"testing"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// genesisBlockWith wraps one transaction in a block-0 body for block-level
// auth validation.
func genesisBlockWith(tx *types.Transaction) *types.Block {
	return &types.Block{
		Header: &types.BlockHeader{Block: 0, Height: 0},
		Body:   types.BlockBody{TxsList: []*types.Transaction{tx}},
	}
}

// genesisFundingTxs returns the canonical genesis allocation transactions,
// exactly as GenesisState.buildBlock emits them.
func genesisFundingTxs(t *testing.T) []*types.Transaction {
	t.Helper()
	gs := DefaultGenesisState()
	txs := gs.allocationsToTxList()
	if len(txs) == 0 {
		t.Fatal("genesis produced no funding transactions")
	}
	return txs
}

// TestGenesisFundingTxsMatchTheSharedIDFormula pins the single definition of
// the genesis funding ID: the transaction carried in block 0 must satisfy the
// very formula IsSystemTransaction re-derives.
func TestGenesisFundingTxsMatchTheSharedIDFormula(t *testing.T) {
	for i, tx := range genesisFundingTxs(t) {
		want := types.GenesisAllocationTxID(tx.Receiver, tx.Amount, tx.Nonce)
		if tx.ID != want {
			t.Fatalf("tx[%d] id = %s, want %s (formula drift)", i, tx.ID, want)
		}
	}
}

// TestGenesisFundingIsSystemOnlyAtHeightZero is the core scoping guarantee:
// the unsigned exemption holds for the genesis allocation set inside block 0
// and for nothing else — least of all for a vault spend after genesis.
func TestGenesisFundingIsSystemOnlyAtHeightZero(t *testing.T) {
	bc := &Blockchain{} // no sphincsManager: the height-0 bypass must not need one

	for i, tx := range genesisFundingTxs(t) {
		if !tx.IsSystemTransaction() {
			t.Fatalf("tx[%d] (%s) is not recognized as a genesis funding tx", i, tx.ID)
		}
		if !tx.IsSystemTransactionAt(0) {
			t.Fatalf("tx[%d] must be a system transaction inside block 0", i)
		}
		if tx.IsSystemTransactionAt(1) {
			t.Fatalf("tx[%d] must NOT be a system transaction above block 0", i)
		}
		if err := bc.validateTransactionAuth(tx, 0, 0, false); err != nil {
			t.Fatalf("tx[%d] must be exempt from auth inside block 0: %v", i, err)
		}
		if err := bc.validateTransactionAuth(tx, 1, 0, false); err == nil {
			t.Fatalf("tx[%d] must require full auth above block 0", i)
		}
		if err := bc.validateBlockTransactionAuth(genesisBlockWith(tx), false); err != nil {
			t.Fatalf("tx[%d] must pass block-0 auth validation: %v", i, err)
		}
	}
}

// TestVaultSenderAloneIsNotASystemTransaction proves sender identity is no
// longer the bypass: only the canonical genesis funding shape is, and only at
// height 0.
func TestVaultSenderAloneIsNotASystemTransaction(t *testing.T) {
	bc := &Blockchain{}

	spend := &types.Transaction{
		ID:        "vault-spend-after-genesis",
		Sender:    GenesisVaultAddress,
		Receiver:  "SPIF0000000000000000000000000000000000000000",
		Amount:    big.NewInt(1_000),
		Nonce:     999,
		Timestamp: CanonicalGenesisTimestamp,
	}
	if spend.IsSystemTransaction() {
		t.Fatal("an ordinary vault spend must not be a system transaction")
	}
	if spend.IsSystemTransactionAt(0) {
		t.Fatal("an ordinary vault spend must not be a system transaction even at height 0")
	}
	if err := bc.validateTransactionAuth(spend, 0, 0, false); err == nil {
		t.Fatal("a vault spend must not be exempt from auth at height 0 either")
	}
	if err := bc.validateTransactionAuth(spend, 1, 0, false); err == nil {
		t.Fatal("a vault spend above genesis must not be exempt from auth")
	}

	// Same sender and the same ID formula, but the ID was fabricated rather
	// than derived: still not a genesis funding transaction.
	fabricated := &types.Transaction{
		ID:        "deadbeef",
		Sender:    GenesisVaultAddress,
		Receiver:  GenesisVaultAddress,
		Amount:    big.NewInt(1),
		GasLimit:  big.NewInt(0),
		GasPrice:  big.NewInt(0),
		Timestamp: CanonicalGenesisTimestamp,
	}
	if fabricated.IsSystemTransaction() {
		t.Fatal("a fabricated ID must not be accepted as a genesis funding transaction")
	}

	// The legacy literal sender used by the old bypass is not special either.
	legacy := &types.Transaction{
		ID:       "legacy-literal",
		Sender:   "genesis",
		Receiver: "SPIF0000000000000000000000000000000000000000",
		Amount:   big.NewInt(1),
	}
	if legacy.IsSystemTransaction() || legacy.IsSystemTransactionAt(0) {
		t.Fatal(`sender == "genesis" must not be a system transaction on its own`)
	}

	// A genesis-shaped vault transaction that carries authorization material is
	// a real (authorized) transaction, not a protocol distribution.
	authorized := &types.Transaction{
		Sender:        GenesisVaultAddress,
		Receiver:      "SPIF0000000000000000000000000000000000000000",
		Amount:        big.NewInt(1),
		GasLimit:      big.NewInt(0),
		GasPrice:      big.NewInt(0),
		Signature:     []byte{0x01},
		SignatureHash: make([]byte, 32),
		PublicKey:     []byte{0x02},
	}
	authorized.ID = types.GenesisAllocationTxID(authorized.Receiver, authorized.Amount, authorized.Nonce)
	if authorized.IsSystemTransaction() {
		t.Fatal("a vault tx carrying auth material must not be a system transaction")
	}
}

// TestValidateTransactionPolicyScopesGenesisExemption covers the policy gate
// that CommitBlock and block selection use.
func TestValidateTransactionPolicyScopesGenesisExemption(t *testing.T) {
	bc := &Blockchain{}
	txs := genesisFundingTxs(t)

	if err := bc.ValidateTransactionPolicyAt(txs[0], 0); err != nil {
		t.Fatalf("genesis funding tx must be policy-exempt inside block 0: %v", err)
	}
	if err := bc.ValidateTransactionPolicyAt(txs[0], 1); err == nil {
		t.Fatal("genesis funding tx must not be policy-exempt above block 0")
	}
	if err := bc.ValidateTransactionPolicy(txs[0]); err == nil {
		t.Fatal("the height-free (ingress) form must not exempt a genesis funding tx")
	}
}
