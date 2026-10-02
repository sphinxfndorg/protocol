// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"math/big"
	"testing"

	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
)

func TestValidateTransactionPolicyEnforcesPolicyGasQuote(t *testing.T) {
	bc := &Blockchain{}
	tx := &types.Transaction{
		Sender:     "sender",
		Receiver:   "receiver",
		Amount:     big.NewInt(1),
		GasLimit:   big.NewInt(21000),
		GasPrice:   big.NewInt(1000000000),
		ReturnData: []byte("anchor"),
	}

	if err := bc.ValidateTransactionPolicy(tx); err == nil {
		t.Fatal("expected data transaction with transfer-only gas limit to be rejected")
	}

	quote := policy.GetDefaultPolicyParams().QuoteTransactionGas(uint64(len(tx.ReturnData)))
	tx.GasLimit = quote.GasLimit
	tx.GasPrice = quote.GasPrice
	if err := bc.ValidateTransactionPolicy(tx); err != nil {
		t.Fatalf("expected policy gas quote to be accepted: %v", err)
	}
}

func TestApplyTransactionsAccumulatesRequiredGasNotGasLimit(t *testing.T) {
	db, err := database.NewLevelDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	stateDB := NewStateDB(db)
	stateDB.SetBalance("sender", big.NewInt(10))
	policyParams := policy.GetDefaultPolicyParams()
	txs := make([]*types.Transaction, 0, 2)
	var expectedGas big.Int
	for i, returnData := range [][]byte{[]byte("a"), []byte("abc")} {
		quote := policyParams.QuoteTransactionGas(uint64(len(returnData)))
		expectedGas.Add(&expectedGas, quote.GasLimit)
		limit := new(big.Int).Add(new(big.Int).Set(quote.GasLimit), big.NewInt(1000))
		txs = append(txs, &types.Transaction{
			ID:         string(rune('a' + i)),
			Sender:     "sender",
			Receiver:   "receiver",
			Amount:     big.NewInt(1),
			GasLimit:   limit,
			GasPrice:   big.NewInt(0),
			Nonce:      uint64(i),
			ReturnData: returnData,
		})
	}
	block := &types.Block{
		Header: &types.BlockHeader{Block: 1, Height: 1},
		Body:   types.BlockBody{TxsList: txs},
	}
	if err := (&Blockchain{}).applyTransactions(block, stateDB); err != nil {
		t.Fatalf("applyTransactions: %v", err)
	}
	if block.Header.GasUsed.Cmp(&expectedGas) != 0 {
		t.Fatalf("block gas used = %s; want required usage %s (not supplied gas limits)",
			block.Header.GasUsed, &expectedGas)
	}
}
