// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	txtypes "github.com/sphinxfndorg/protocol/src/core/transaction"
)

func TestGenesisVaultAddressFromPolicy(t *testing.T) {
	prevAddr := GenesisVaultAddress
	prevTxAddr := txtypes.GenesisVaultAddress
	prevLoaded := genesisMultisigAddr
	prevPolicy := genesisMultisigPolicy
	t.Cleanup(func() {
		genesisMultisigMu.Lock()
		GenesisVaultAddress = prevAddr
		txtypes.GenesisVaultAddress = prevTxAddr
		genesisMultisigAddr = prevLoaded
		genesisMultisigPolicy = prevPolicy
		genesisMultisigMu.Unlock()
	})
	km, err := key.NewKeyManager()
	if err != nil {
		t.Fatal(err)
	}
	pks := make([][]byte, 0, 3)
	for i := 0; i < 3; i++ {
		sk, pk, err := km.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		_, pkb, err := km.SerializeKeyPair(sk, pk)
		if err != nil {
			t.Fatal(err)
		}
		pks = append(pks, pkb)
	}
	p := &multisig.MultiPartyPolicy{PubKeys: pks, Threshold: 2, Domain: "sphinx-vault-v1"}
	want, err := p.Address()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "genesis_multisig.json")
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadGenesisVaultPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("derived vault = %s, want %s", got, want)
	}
	if GenesisVaultAddress != want || GetGenesisVaultAddress() != want {
		t.Fatalf("active vault not updated: %s / %s", GenesisVaultAddress, GetGenesisVaultAddress())
	}
	gs := minimalGenesisState()
	block := gs.BuildBlock()
	for _, tx := range block.Body.TxsList {
		if tx.Sender != want && tx.Sender != legacyGenesisVaultAddress {
			t.Fatalf("genesis tx sender = %q, want derived vault %q", tx.Sender, want)
		}
	}
}
