// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"math/big"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/contracts"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

func contractGas(bc *Blockchain, deploy bool, code, callData []byte) *big.Int {
	base := bc.ActivePolicy().QuoteTransactionGas(0).GasLimit
	return base.Add(base, bc.ActivePolicy().QuoteContractGas(deploy, uint64(len(code)), uint64(len(callData)), 0).GasLimit)
}

func TestNativeSIP20ContractExecutionUsesStateDB(t *testing.T) {
	db, err := database.NewLevelDB(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	state := NewStateDB(db)
	bc := &Blockchain{}

	code, err := contracts.BuildDeployCode(&contracts.DeploySpec{Standard: contracts.StandardSIP20, Name: "Token", Symbol: "TOK", InitialSupply: "100"})
	if err != nil {
		t.Fatal(err)
	}
	deploy := &types.Transaction{Sender: "owner", Amount: big.NewInt(0), Nonce: 1, Timestamp: 100, Code: code, GasLimit: contractGas(bc, true, code, nil), GasPrice: big.NewInt(1000000000)}
	if err := bc.ValidateTransactionPolicy(deploy); err != nil {
		t.Fatalf("policy rejected correctly priced deploy: %v", err)
	}
	if err := bc.executeContractTransaction(deploy, state); err != nil {
		t.Fatal(err)
	}
	address := contracts.ContractAddress(deploy.Sender, deploy.Nonce, deploy.Code)

	callData, err := contracts.BuildCallData(&contracts.CallSpec{Method: "transfer", Args: map[string]string{"to": "alice", "amount": "25"}})
	if err != nil {
		t.Fatal(err)
	}
	call := &types.Transaction{Sender: "owner", Amount: big.NewInt(0), ToContract: address, CallData: callData, GasLimit: contractGas(bc, false, nil, callData), GasPrice: big.NewInt(1000000000)}
	if err := bc.executeContractTransaction(call, state); err != nil {
		t.Fatal(err)
	}

	value, err := state.GetContractValue(contractKey(address, "storage", "sip20:balance:alice"))
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "25" {
		t.Fatalf("alice balance: want 25, got %s", value)
	}
	if _, err := state.Commit(); err != nil {
		t.Fatalf("commit contract state: %v", err)
	}
	reloaded := NewStateDB(db)
	value, err = reloaded.GetContractValue(contractKey(address, "storage", "sip20:balance:alice"))
	if err != nil || string(value) != "25" {
		t.Fatalf("persisted alice balance: %q, err=%v", value, err)
	}
}

func TestSVMDeployGasIncludesDeterministicOperationCount(t *testing.T) {
	bc := &Blockchain{}
	code := append([]byte{}, contracts.SVM1Magic...)
	code = append(code, contracts.SVMStop)
	tx := &types.Transaction{Code: code}
	quote, err := bc.RequiredTransactionGas(tx)
	if err != nil {
		t.Fatal(err)
	}
	base := bc.ActivePolicy().QuoteTransactionGas(0).GasLimit
	contractQuote := bc.ActivePolicy().QuoteContractGas(true, uint64(len(code)), 0, 1).GasLimit
	want := new(big.Int).Add(base, contractQuote)
	if quote.GasLimit.Cmp(want) != 0 {
		t.Fatalf("gas limit: want %s, got %s", want, quote.GasLimit)
	}
}

// TestContractAddressFormatsResolveToSameContract locks in the address-format
// normalisation: a contract stored under the canonical grouped form must be
// reachable whether the caller phrases the address as the grouped display form
// ("SPIF E1FE 1F5D …"), bare raw hex, or differently cased/spaced. Previously
// only a byte-for-byte echo of the deployed string resolved, which produced
// spurious "contract does not exist" rejections and empty getcontractstorage
// reads.
func TestContractAddressFormatsResolveToSameContract(t *testing.T) {
	db, err := database.NewLevelDB(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	raw := "E1FE1F5DF63C4B2A9C7E0D8F1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D"
	canonical, err := common.FormatSPIFAddress(raw)
	if err != nil {
		t.Fatal(err)
	}
	const meta = `{"standard":"sip721"}`

	// Write via the store using the raw hex form; the key must land on the
	// canonical grouped form so every other rendering resolves to it.
	state := NewStateDB(db)
	store := newContractStore(state)
	store.SetContractMeta(raw, []byte(meta))
	store.SetContractStorage(raw, "sip721:token:1", []byte("listed"))
	store.commit()
	if _, err := state.Commit(); err != nil {
		t.Fatalf("commit contract state: %v", err)
	}

	reloaded := NewStateDB(db)
	forms := map[string]string{
		"canonical grouped": canonical,
		"raw hex":           raw,
		"lowercase":         strings.ToLower(raw),
		"spaced lowercase":  strings.ToLower(canonical),
	}
	for name, form := range forms {
		if !reloaded.ContractExists(form) {
			t.Errorf("ContractExists(%s %q) = false, want true", name, form)
		}
		got, err := newContractStore(reloaded).GetContractMeta(form)
		if err != nil {
			t.Errorf("GetContractMeta(%s %q): %v", name, form, err)
			continue
		}
		if string(got) != meta {
			t.Errorf("GetContractMeta(%s %q) = %s, want %s", name, form, got, meta)
		}
		value, err := newContractStore(reloaded).GetContractStorage(form, "sip721:token:1")
		if err != nil {
			t.Errorf("GetContractStorage(%s %q): %v", name, form, err)
			continue
		}
		if string(value) != "listed" {
			t.Errorf("GetContractStorage(%s %q) = %s, want listed", name, form, value)
		}
	}
}

// TestLegacyContractAddressFallback keeps contracts written by earlier nodes —
// which keyed storage off the un-normalised legacy "SPIF"+40-lowercase-hex
// address — readable through the raw-form fallback.
func TestLegacyContractAddressFallback(t *testing.T) {
	db, err := database.NewLevelDB(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	raw := "C5AFE73E094471D6BB49FEF65457E279FF47E46F"
	legacy := "SPIF" + strings.ToLower(raw)
	canonical, err := common.FormatSPIFAddress(raw)
	if err != nil {
		t.Fatal(err)
	}

	state := NewStateDB(db)
	// Write directly under the legacy raw key, exactly as an older node would.
	state.SetContractValue(legacy+":meta:", []byte(`{"standard":"sip721"}`))
	if _, err := state.Commit(); err != nil {
		t.Fatalf("commit legacy state: %v", err)
	}

	reloaded := NewStateDB(db)
	if !reloaded.ContractExists(legacy) {
		t.Errorf("legacy contract %q not found via rendering fallback", legacy)
	}
	if !reloaded.ContractExists(raw) {
		t.Errorf("legacy contract %q not found when addressed by its bare raw hex", raw)
	}
	if !reloaded.ContractExists(canonical) {
		t.Errorf("legacy contract %q not found when addressed by its canonical form", canonical)
	}

	// A call against a legacy-keyed contract must write back to the legacy key.
	// Canonicalising writes unconditionally would move the contract's state
	// mid-transaction and make block replay diverge from older nodes.
	store := newContractStore(reloaded)
	if _, err := store.GetContractMeta(legacy); err != nil {
		t.Fatalf("load legacy contract meta: %v", err)
	}
	store.SetContractStorage(legacy, "sip721:token:1", []byte("legacy-owner"))
	store.commit()
	if _, err := reloaded.Commit(); err != nil {
		t.Fatalf("commit legacy call: %v", err)
	}

	after := NewStateDB(db)
	if value, err := after.GetContractValue(legacy + ":storage:sip721:token:1"); err != nil || string(value) != "legacy-owner" {
		t.Errorf("write did not stay on the legacy key: value=%q err=%v", value, err)
	}
	if value, err := after.GetContractValue(contractKey(canonical, "storage", "sip721:token:1")); err == nil {
		t.Errorf("write leaked onto the canonical key %q: %q", canonical, value)
	}
}
