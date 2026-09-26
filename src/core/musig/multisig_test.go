// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package multisig

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
)

func testKeys(t *testing.T, n int) ([][]byte, [][]byte) {
	t.Helper()
	km, err := key.NewKeyManager()
	if err != nil {
		t.Fatal(err)
	}
	sks := make([][]byte, n)
	pks := make([][]byte, n)
	for i := 0; i < n; i++ {
		sk, pk, err := km.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		skb, pkb, err := km.SerializeKeyPair(sk, pk)
		if err != nil {
			t.Fatal(err)
		}
		sks[i] = skb
		pks[i] = pkb
	}
	return sks, pks
}

func TestAddressDeterministicRegardlessOfOrder(t *testing.T) {
	_, pks := testKeys(t, 3)
	a := &MultiPartyPolicy{PubKeys: [][]byte{pks[0], pks[1], pks[2]}, Threshold: 2, Domain: "sphinx-vault-v1"}
	b := &MultiPartyPolicy{PubKeys: [][]byte{pks[2], pks[0], pks[1]}, Threshold: 2, Domain: "sphinx-vault-v1"}
	aa, err := a.Address()
	if err != nil {
		t.Fatal(err)
	}
	bb, err := b.Address()
	if err != nil {
		t.Fatal(err)
	}
	if aa != bb {
		t.Fatalf("order changed address: %s vs %s", aa, bb)
	}
	if len(aa) != 40 {
		t.Fatalf("address len = %d, want 40", len(aa))
	}
	raw := filepath.Join(t.TempDir(), "policy.json")
	data, _ := json.Marshal(a)
	if err := os.WriteFile(raw, data, 0644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	la, err := loaded.Address()
	if err != nil {
		t.Fatal(err)
	}
	if la != aa {
		t.Fatalf("json round-trip changed address: %s vs %s", la, aa)
	}
}

func TestThresholdEnforcement(t *testing.T) {
	sks, pks := testKeys(t, 3)
	p := &MultiPartyPolicy{PubKeys: pks, Threshold: 2, Domain: "sphinx-vault-v1"}
	msg := []byte("vault-release:1")
	sig0, err := SignCustodyMessage(msg, sks[0], pks[0])
	if err != nil {
		t.Fatal(err)
	}
	sig1, err := SignCustodyMessage(msg, sks[1], pks[1])
	if err != nil {
		t.Fatal(err)
	}
	if VerifyThreshold(msg, MultiSigWitness{Policy: *p, Sigs: map[int][]byte{0: sig0}, Expiry: 100}, 50) {
		t.Fatal("M-1 sigs must fail")
	}
	if !VerifyThreshold(msg, MultiSigWitness{Policy: *p, Sigs: map[int][]byte{0: sig0, 1: sig1}, Expiry: 100}, 50) {
		t.Fatal("M valid sigs must pass")
	}
	osk, opk := testKeys(t, 1)
	outsider, err := SignCustodyMessage(msg, osk[0], opk[0])
	if err != nil {
		t.Fatal(err)
	}
	if VerifyThreshold(msg, MultiSigWitness{Policy: *p, Sigs: map[int][]byte{0: sig0, 99: outsider}, Expiry: 100}, 50) {
		t.Fatal("outsider sig must not count")
	}
	_ = hex.EncodeToString
}

func TestExpiryHorizonSanity(t *testing.T) {
	ref := uint64(1_800_000_000)
	if err := ValidateWitnessExpiry(0, ref); err == nil {
		t.Fatal("unset expiry must be rejected")
	}
	if err := ValidateWitnessExpiry(ref+MinWitnessValiditySeconds-1, ref); err == nil {
		t.Fatal("expiry inside the minimum horizon must be rejected as unspendable-too-soon")
	}
	if err := ValidateWitnessExpiry(ref+MaxWitnessValiditySeconds+1, ref); err == nil {
		t.Fatal("expiry beyond the maximum horizon must be rejected as a replay window too wide")
	}
	if err := ValidateWitnessExpiry(ref+30*24*3600, ref); err != nil {
		t.Fatalf("one-month horizon must be accepted: %v", err)
	}
	if err := ValidateWitnessExpiry(ref+48*30*24*3600, ref); err != nil {
		t.Fatalf("four-year vesting horizon must be accepted: %v", err)
	}
	if err := ValidateWitnessExpiry(ref+30*24*3600, 0); err != nil {
		t.Fatalf("offline signing (unknown reference time) must accept a non-zero expiry: %v", err)
	}
}

func TestExpiryEnforcement(t *testing.T) {
	sks, pks := testKeys(t, 2)
	p := &MultiPartyPolicy{PubKeys: pks, Threshold: 2, Domain: "sphinx-vault-v1"}
	msg := []byte("vault-release:2")
	sig0, err := SignCustodyMessage(msg, sks[0], pks[0])
	if err != nil {
		t.Fatal(err)
	}
	sig1, err := SignCustodyMessage(msg, sks[1], pks[1])
	if err != nil {
		t.Fatal(err)
	}
	w := MultiSigWitness{Policy: *p, Sigs: map[int][]byte{0: sig0, 1: sig1}, Expiry: 100}
	if VerifyThreshold(msg, w, 101) {
		t.Fatal("expired witness must fail")
	}
	if !VerifyThreshold(msg, w, 100) {
		t.Fatal("witness at expiry must pass")
	}
}
