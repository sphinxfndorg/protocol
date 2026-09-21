// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"math/big"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/contracts"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	txtypes "github.com/sphinxfndorg/protocol/src/core/transaction"
	storage "github.com/sphinxfndorg/protocol/src/state"
)

const (
	ibAdmin = "ib-admin"
	ibAlice = "ib-alice"
	ibBob   = "ib-bob"
)

func fundIB(t *testing.T, state *StateDB, addr string) {
	t.Helper()
	state.SetBalance(addr, big.NewInt(1e18))
	if _, err := state.Commit(); err != nil {
		t.Fatalf("fund %s: %v", addr, err)
	}
}

func priceIB(t *testing.T, bc *Blockchain, tx *txtypes.Transaction) {
	t.Helper()
	q, err := bc.RequiredTransactionGas(tx)
	if err != nil {
		t.Fatalf("RequiredTransactionGas: %v", err)
	}
	tx.GasLimit = new(big.Int).Set(q.GasLimit)
	tx.GasPrice = new(big.Int).Set(q.GasPrice)
	if tx.Amount == nil {
		tx.Amount = big.NewInt(0)
	}
	if err := bc.ValidateTransactionPolicy(tx); err != nil {
		t.Fatalf("ValidateTransactionPolicy: %v", err)
	}
}

func blockWith(t *testing.T, height uint64, txs ...*txtypes.Transaction) *txtypes.Block {
	t.Helper()
	body := txtypes.NewBlockBody(txs, nil, height)
	tmp := txtypes.NewBlock(&txtypes.BlockHeader{Height: height}, body)
	hdr := txtypes.NewBlockHeader(height, make([]byte, 32), big.NewInt(1), tmp.CalculateTxsRoot(),
		common.SpxHash([]byte("ib-state")), big.NewInt(10000000), big.NewInt(0), nil, make([]byte, 20),
		common.GetCurrentTimestamp(), nil)
	hdr.ProposerID = ""
	return txtypes.NewBlock(hdr, body)
}

func ibBalance(t *testing.T, bc *Blockchain, addr, owner string) string {
	t.Helper()
	state, err := bc.newStateDB()
	if err != nil {
		t.Fatalf("newStateDB: %v", err)
	}
	v, err := newContractStore(state).GetContractStorage(addr, "sip20:balance:"+owner)
	if err != nil {
		return "0"
	}
	return string(v)
}

func ibTotal(t *testing.T, bc *Blockchain, addr string) string {
	t.Helper()
	state, err := bc.newStateDB()
	if err != nil {
		t.Fatalf("newStateDB: %v", err)
	}
	v, err := newContractStore(state).GetContractStorage(addr, "sip20:total_supply")
	if err != nil {
		t.Fatalf("total_supply missing: %v", err)
	}
	return string(v)
}

func ibNonce(t *testing.T, bc *Blockchain, addr string) uint64 {
	t.Helper()
	state, err := bc.newStateDB()
	if err != nil {
		t.Fatalf("newStateDB: %v", err)
	}
	n, err := state.GetNonce(addr)
	if err != nil {
		t.Fatalf("GetNonce: %v", err)
	}
	return n
}

func callIB(t *testing.T, method string, args map[string]string) []byte {
	t.Helper()
	cd, err := contracts.BuildCallData(&contracts.CallSpec{Method: method, Args: args})
	if err != nil {
		t.Fatalf("BuildCallData %s: %v", method, err)
	}
	return cd
}

// mkIB builds the minimum *Blockchain the in-block executor needs: a real
// storage layer with the shared LevelDB handles attached to it.
//
// bc.SetStorageDB / bc.SetStateDB forward to bc.storage, so a zero-value
// Blockchain (where bc.storage is nil) panics inside Storage.SetDB before any
// block can be executed. NewBlockchain always creates the storage layer first;
// this helper mirrors that ordering, then attaches the handles through the
// same public setters a real node uses.
func mkIB(t *testing.T, dir string, db *database.DB) *Blockchain {
	t.Helper()
	store, err := storage.NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	bc := &Blockchain{storage: store}
	bc.SetStorageDB(db)
	bc.SetStateDB(db)
	return bc
}

func execIB(t *testing.T, bc *Blockchain, height uint64, txs ...*txtypes.Transaction) []byte {
	t.Helper()
	root, err := bc.ExecuteBlock(blockWith(t, height, txs...))
	if err != nil {
		t.Fatalf("ExecuteBlock(%d): %v", height, err)
	}
	return root
}
func TestStablecoinInBlockLifecycle(t *testing.T) {
	dir := t.TempDir()
	db, err := database.NewLevelDB(dir + "/ib-state")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	bc := mkIB(t, dir, db)

	fundIB(t, NewStateDB(db), ibAdmin)
	fundIB(t, NewStateDB(db), ibAlice)
	fundIB(t, NewStateDB(db), ibBob)

	code, err := contracts.BuildDeployCode(&contracts.DeploySpec{
		Standard: contracts.StandardSIP20, Name: "Sphinx USD", Symbol: "SUSD", Owner: ibAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}
	deploy := &txtypes.Transaction{ID: "ib-deploy", Sender: ibAdmin, Nonce: 0,
		Amount: big.NewInt(0), Timestamp: common.GetCurrentTimestamp(), Code: code}
	priceIB(t, bc, deploy)
	r0 := execIB(t, bc, 1, deploy)
	if len(r0) == 0 {
		t.Fatal("empty state root after deploy block")
	}
	addr := contracts.ContractAddress(ibAdmin, 0, code)
	if got := ibTotal(t, bc, addr); got != "0" {
		t.Fatalf("total after deploy: got %s want 0", got)
	}

	mint := &txtypes.Transaction{ID: "ib-mint", Sender: ibAdmin, Nonce: 1,
		Amount: big.NewInt(0), Timestamp: common.GetCurrentTimestamp(),
		ToContract: addr, CallData: callIB(t, "mint", map[string]string{"to": ibAlice, "amount": "1000"})}
	priceIB(t, bc, mint)
	r1 := execIB(t, bc, 2, mint)
	if string(r1) == string(r0) {
		t.Fatal("state root unchanged after mint block")
	}
	if got := ibBalance(t, bc, addr, ibAlice); got != "1000" {
		t.Fatalf("alice after mint: got %s want 1000", got)
	}
	if got := ibTotal(t, bc, addr); got != "1000" {
		t.Fatalf("total after mint: got %s want 1000", got)
	}
	if n := ibNonce(t, bc, ibAdmin); n != 2 {
		t.Fatalf("admin nonce after 2 blocks: got %d want 2", n)
	}

	xfer := &txtypes.Transaction{ID: "ib-xfer", Sender: ibAlice, Nonce: 0,
		Amount: big.NewInt(0), Timestamp: common.GetCurrentTimestamp(),
		ToContract: addr, CallData: callIB(t, "transfer", map[string]string{"to": ibBob, "amount": "300"})}
	priceIB(t, bc, xfer)
	execIB(t, bc, 3, xfer)
	if got := ibBalance(t, bc, addr, ibAlice); got != "700" {
		t.Fatalf("alice after transfer: got %s want 700", got)
	}
	if got := ibBalance(t, bc, addr, ibBob); got != "300" {
		t.Fatalf("bob after transfer: got %s want 300", got)
	}
	if got := ibTotal(t, bc, addr); got != "1000" {
		t.Fatalf("total after transfer: got %s want 1000", got)
	}

	burn := &txtypes.Transaction{ID: "ib-burn", Sender: ibAdmin, Nonce: 2,
		Amount: big.NewInt(0), Timestamp: common.GetCurrentTimestamp(),
		ToContract: addr, CallData: callIB(t, "burn", map[string]string{"from": ibAlice, "amount": "200"})}
	priceIB(t, bc, burn)
	execIB(t, bc, 4, burn)
	if got := ibBalance(t, bc, addr, ibAlice); got != "500" {
		t.Fatalf("alice after burn: got %s want 500", got)
	}
	if got := ibTotal(t, bc, addr); got != "800" {
		t.Fatalf("total after burn: got %s want 800", got)
	}

	// Bob's first OUTGOING transaction: receiving 300 in block 3 does not bump
	// his nonce (applyTransactions increments the sender's nonce only), so the
	// self-burn must be signed with nonce 0.
	selfBurn := &txtypes.Transaction{ID: "ib-self", Sender: ibBob, Nonce: 0,
		Amount: big.NewInt(0), Timestamp: common.GetCurrentTimestamp(),
		ToContract: addr, CallData: callIB(t, "burn_self", map[string]string{"amount": "100"})}
	priceIB(t, bc, selfBurn)
	execIB(t, bc, 5, selfBurn)
	if got := ibBalance(t, bc, addr, ibBob); got != "200" {
		t.Fatalf("bob after self-burn: got %s want 200", got)
	}
	if got := ibTotal(t, bc, addr); got != "700" {
		t.Fatalf("total after self-burn: got %s want 700", got)
	}

	state, err := bc.newStateDB()
	if err != nil {
		t.Fatal(err)
	}
	sum := big.NewInt(0)
	for _, h := range []string{ibAdmin, ibAlice, ibBob} {
		v, err := newContractStore(state).GetContractStorage(addr, "sip20:balance:"+h)
		if err != nil || len(v) == 0 {
			continue
		}
		n, ok := new(big.Int).SetString(string(v), 10)
		if !ok {
			t.Fatalf("bad balance %s: %q", h, v)
		}
		sum.Add(sum, n)
	}
	tot, err := newContractStore(state).GetContractStorage(addr, "sip20:total_supply")
	if err != nil {
		t.Fatal(err)
	}
	if sum.String() != string(tot) {
		t.Fatalf("supply invariant in block state: total=%s sum=%s", tot, sum.String())
	}
}
