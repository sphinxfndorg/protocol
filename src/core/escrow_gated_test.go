// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"encoding/json"
	"testing"

	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	"github.com/sphinxfndorg/protocol/src/policy"
)

func escrowTestKeys(t *testing.T, n int) ([][]byte, [][]byte) {
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

func setupEscrowPolicy(t *testing.T, pks [][]byte, threshold uint8) multisig.MultiPartyPolicy {
	t.Helper()
	prevPolicy := escrowMultisigPolicy
	prevAddr := escrowMultisigAddr
	prevEnforced := escrowMultisigEnforced
	t.Cleanup(func() {
		escrowMultisigMu.Lock()
		escrowMultisigPolicy = prevPolicy
		escrowMultisigAddr = prevAddr
		escrowMultisigEnforced = prevEnforced
		escrowMultisigMu.Unlock()
	})
	p := multisig.MultiPartyPolicy{PubKeys: pks, Threshold: threshold, Domain: escrowMultisigDomain}
	addr, err := p.Address()
	if err != nil {
		t.Fatal(err)
	}
	escrowMultisigMu.Lock()
	cp := p
	escrowMultisigPolicy = &cp
	escrowMultisigAddr = addr
	escrowMultisigEnforced = true
	escrowMultisigMu.Unlock()
	return p
}

func signWitness(t *testing.T, bc *Blockchain, p multisig.MultiPartyPolicy, sks, pks [][]byte, idxs []int, msg []byte, expiry uint64) multisig.MultiSigWitness {
	t.Helper()
	sigs := map[int][]byte{}
	for _, i := range idxs {
		sig, err := multisig.SignCustodyMessage(msg, sks[i], pks[i])
		if err != nil {
			t.Fatal(err)
		}
		sigs[i] = sig
	}
	return multisig.MultiSigWitness{Policy: p, Sigs: sigs, Expiry: expiry}
}

func TestEscrowGatedReleaseEndToEnd(t *testing.T) {
	sks, pks := escrowTestKeys(t, 3)
	p := setupEscrowPolicy(t, pks, 2)
	s := newCGEStateDB(t)
	s.SetBalance(GetCGEEscrowAddress(), nspx(425_000_000))
	genesisTS := CanonicalGenesisTimestamp
	applyCGEReleases(cgeTestBlock(0, genesisTS), s)
	height := uint64(2)
	headerTS := uint64(genesisTS) + uint64(12*policy.CGEMonthSeconds)
	founder := allocByLabel(t, "Founder")
	sched := policy.CGEScheduleForLabel(founder.Label)
	elapsed := int64(headerTS) - genesisTS
	target := sched.UnlockedAt(elapsed, founder.BalanceNSPX)
	msg := cgeReleaseMessage(nil, founder.Address, target, height, headerTS+uint64(12*policy.CGEMonthSeconds))
	w := signWitness(t, nil, p, sks, pks, []int{0, 1}, msg, headerTS+uint64(12*policy.CGEMonthSeconds))
	refs := map[string]multisigWitnessRef{founder.Address: witnessRefFor(w)}
	block := cgeTestBlock(height, int64(headerTS))
	applyCGEReleasesWithWitness(nil, block, s, refs)
	bal, err := s.GetBalance(founder.Address)
	if err != nil {
		t.Fatal(err)
	}
	if bal.Cmp(target) != 0 {
		t.Fatalf("founder gated release: want %s, got %s", target.String(), bal.String())
	}
	raw, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	var decoded multisig.MultiSigWitness
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !multisig.VerifyThreshold(msg, decoded, height) {
		t.Fatal("witness must verify through JSON transport")
	}
}

func TestEscrowGatedReleaseRejects(t *testing.T) {
	sks, pks := escrowTestKeys(t, 3)
	p := setupEscrowPolicy(t, pks, 2)
	newState := func(t *testing.T) *StateDB {
		s := newCGEStateDB(t)
		applyCGEReleases(cgeTestBlock(0, CanonicalGenesisTimestamp), s)
		return s
	}
	height := uint64(2)
	headerTS := uint64(CanonicalGenesisTimestamp) + uint64(12*policy.CGEMonthSeconds)
	founder := allocByLabel(t, "Founder")
	elapsed := int64(headerTS) - CanonicalGenesisTimestamp
	target := policy.CGEScheduleForLabel(founder.Label).UnlockedAt(elapsed, founder.BalanceNSPX)
	msg := cgeReleaseMessage(nil, founder.Address, target, height, headerTS+uint64(12*policy.CGEMonthSeconds))
	weak := signWitness(t, nil, p, sks, pks, []int{0}, msg, headerTS+uint64(12*policy.CGEMonthSeconds))
	s1 := newState(t)
	applyCGEReleasesWithWitness(nil, cgeTestBlock(height, int64(headerTS)), s1, map[string]multisigWitnessRef{founder.Address: witnessRefFor(weak)})
	if bal, _ := s1.GetBalance(founder.Address); bal.Sign() != 0 {
		t.Fatalf("below-threshold witness must not mutate state, got %s", bal.String())
	}
	expiredMsg := cgeReleaseMessage(nil, founder.Address, target, height, headerTS-1)
	expired := signWitness(t, nil, p, sks, pks, []int{0, 1}, expiredMsg, headerTS-1)
	s2 := newState(t)
	applyCGEReleasesWithWitness(nil, cgeTestBlock(height, int64(headerTS)), s2, map[string]multisigWitnessRef{founder.Address: witnessRefFor(expired)})
	if bal, _ := s2.GetBalance(founder.Address); bal.Sign() != 0 {
		t.Fatalf("expired witness must not mutate state, got %s", bal.String())
	}
}

func TestEscrowDevModuleGated(t *testing.T) {
	sks, pks := escrowTestKeys(t, 3)
	p := setupEscrowPolicy(t, pks, 2)
	s := newCGEStateDB(t)
	s.SetBalance(GetCGEEscrowAddress(), nspx(425_000_000))
	dev := allocByLabel(t, "Development")
	height := uint64(5)
	headerTS := uint64(CanonicalGenesisTimestamp) + uint64(13*policy.CGEMonthSeconds)
	msg := devModuleReleaseMessage(nil, dev.Address, 1, headerTS+uint64(12*policy.CGEMonthSeconds))
	w := signWitness(t, nil, p, sks, pks, []int{0, 1}, msg, headerTS+uint64(12*policy.CGEMonthSeconds))
	if err := ReleaseDevModuleWithWitness(nil, s, dev.Address, 1, w, height, headerTS); err != nil {
		t.Fatalf("gated dev release: %v", err)
	}
	weak := signWitness(t, nil, p, sks, pks, []int{0}, msg, headerTS+uint64(12*policy.CGEMonthSeconds))
	if err := ReleaseDevModuleWithWitness(nil, s, dev.Address, 2, weak, height, headerTS); err == nil {
		t.Fatal("below-threshold dev witness must fail")
	}
	expiredMsg := devModuleReleaseMessage(nil, dev.Address, 2, headerTS-1)
	expired := signWitness(t, nil, p, sks, pks, []int{0, 1}, expiredMsg, headerTS-1)
	if err := ReleaseDevModuleWithWitness(nil, s, dev.Address, 2, expired, height, headerTS); err == nil {
		t.Fatal("expired dev witness must fail")
	}
}
