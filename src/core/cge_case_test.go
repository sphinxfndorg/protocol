// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	"github.com/sphinxfndorg/protocol/src/policy"
)

// writeTempEscrowPolicy writes a threshold-1 escrow policy for pkb and returns
// its path. LoadEscrowPolicy registers + publishes it as the live escrow.
func writeTempEscrowPolicy(t *testing.T, pkb []byte) string {
	t.Helper()
	p := multisig.MultiPartyPolicy{
		PubKeys:   [][]byte{pkb},
		Threshold: 1,
		Domain:    "sphinx-escrow-v1",
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatalf("marshal escrow policy: %v", err)
	}
	path := filepath.Join(t.TempDir(), "escrow_multisig.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write escrow policy: %v", err)
	}
	return path
}

// TestSubmitCGEWitness_NormalizesRecipientCase is the regression test for the
// intake/matching case-sensitivity gap: an operator-typed lower/mixed-case
// rendering of a canonical allocation address must still attach to the block
// AND authorize the release — not just stage without error.
//
// Discipline: assert actual state changed (escrow balance moved), not just
// "no error", so a lookup miss that silently skips the release fails loudly.
func TestSubmitCGEWitness_NormalizesRecipientCase(t *testing.T) {
	// ── 1. Real escrow policy (threshold 1) + real custodian key ──
	km, err := key.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	sk, pk, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	skb, pkb, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		t.Fatalf("SerializeKeyPair: %v", err)
	}
	policyPath := writeTempEscrowPolicy(t, pkb)

	// Save/restore the global escrow custody state (same package).
	escrowMultisigMu.Lock()
	prevPolicy, prevAddr, prevEnforced := escrowMultisigPolicy, escrowMultisigAddr, escrowMultisigEnforced
	escrowMultisigMu.Unlock()
	t.Cleanup(func() {
		escrowMultisigMu.Lock()
		escrowMultisigPolicy, escrowMultisigAddr, escrowMultisigEnforced = prevPolicy, prevAddr, prevEnforced
		escrowMultisigMu.Unlock()
	})

	escrowAddr, err := LoadEscrowPolicy(policyPath)
	if err != nil {
		t.Fatalf("LoadEscrowPolicy: %v", err)
	}
	t.Cleanup(func() { multisig.UnregisterPolicy(escrowAddr) })
	SetEscrowMultisigEnforced(true)

	// ── 2. Canonical recipient, operator-typed in lower case ──
	founder := allocByLabel(t, "Founder")
	canonical := founder.Address
	lower := strings.ToLower(canonical)
	if lower == canonical {
		t.Fatalf("canonical founder address %q has no lower-case variant to test with", canonical)
	}

	// ── 3. Sign the exact milestone the chain will verify ──
	genesisTS := CanonicalGenesisTimestamp
	releaseTS := genesisTS + 12*policy.CGEMonthSeconds
	sched := policy.CGEScheduleForLabel(founder.Label)
	target := sched.UnlockedAt(releaseTS-genesisTS, founder.BalanceNSPX) // 25% tranche
	delta := new(big.Int).Set(target)                                    // nothing released yet
	expiry := uint64(releaseTS) + 30*24*3600

	// Ceremony signs with the operator-typed (lower-case) rendering — with the
	// message-level canonicalization this must bind the same bytes as canonical.
	msg := multisig.CGEVestingReleaseMessage("sphinx-escrow-v1", 7331, escrowAddr, lower, delta.Bytes(), target.Bytes(), expiry)
	sig, err := multisig.SignCustodyMessage(msg, skb, pkb)
	if err != nil {
		t.Fatalf("SignCustodyMessage: %v", err)
	}
	p, err := multisig.LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	w := WitnessForRelease(*p, map[int][]byte{0: sig}, expiry)

	// ── 4. Stage via the lower-case rendering ──
	bc := &Blockchain{}
	if err := bc.SubmitCGEWitness(lower, 1, w, uint64(genesisTS)); err != nil {
		t.Fatalf("SubmitCGEWitness(lower-case): %v", err)
	}
	staged := bc.stagedWitnessList()
	if len(staged) != 1 {
		t.Fatalf("staged witnesses = %d, want 1", len(staged))
	}
	if staged[0].Recipient != canonical {
		t.Fatalf("staged recipient = %q, want canonical %q", staged[0].Recipient, canonical)
	}

	// ── 5. Execute the gated release and assert STATE CHANGED ──
	s := newCGEStateDB(t)
	s.SetBalance(escrowAddr, nspx(425_000_000)) // escrow lives at the derived address
	applyCGEReleases(cgeTestBlock(0, genesisTS), s)

	block := cgeTestBlock(1, releaseTS)
	block.Body.CGEWitnesses = staged
	applyCGEReleasesWithWitness(bc, block, s, witnessRefsFromBlock(block))

	got, err := s.GetBalance(canonical)
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if got.Cmp(nspx(6_250_000)) != 0 {
		t.Fatalf("founder balance after gated release = %s nSPX, want 6,250,000 SPX — witness did not authorize", got.String())
	}
}

// TestSubmitCGEWitness_RejectsUnknownRecipient pins the fail-loud intake
// discipline: a recipient that matches no time-based allocation, even
// case-insensitively, must be rejected at SubmitCGEWitness — staging it
// would be a silent no-op because the gated path iterates time-based
// allocations only.
func TestSubmitCGEWitness_RejectsUnknownRecipient(t *testing.T) {
	p := multisig.MultiPartyPolicy{Threshold: 1, Domain: "sphinx-escrow-v1"}
	w := WitnessForRelease(p, map[int][]byte{0: {0x01}}, uint64(CanonicalGenesisTimestamp)+30*24*3600)
	bc := &Blockchain{}

	// Unknown hex address: must fail.
	if err := bc.SubmitCGEWitness("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 1, w, uint64(CanonicalGenesisTimestamp)); err == nil {
		t.Fatal("unknown recipient must be rejected at intake")
	} else if !strings.Contains(err.Error(), "matches no time-based CGE allocation") {
		t.Fatalf("rejection must name the cause, got: %v", err)
	}

	// Known allocation, wrong schedule class (liquid Foundation): must fail.
	foundation := allocByLabel(t, "Foundation")
	if err := bc.SubmitCGEWitness(foundation.Address, 1, w, uint64(CanonicalGenesisTimestamp)); err == nil {
		t.Fatal("liquid (non-time-based) recipient must be rejected at intake")
	}

	// Nothing staged for either rejection.
	if staged := bc.stagedWitnessList(); len(staged) != 0 {
		t.Fatalf("rejected witnesses must not stage, got %d", len(staged))
	}
}

// TestCheckCGEWitnessCoverage_MismatchedCaseIsCovered pins the pre-flight side
// of the intake fix: a witness file whose recipient rendering differs in case
// from canonical must still report COVERED for the canonical recipient —
// because intake canonicalization means the staged entry (and the block body)
// carries the canonical string, so the pre-flight's match is
// canonical-to-canonical, not leniency papering over a real mismatch.
func TestCheckCGEWitnessCoverage_MismatchedCaseIsCovered(t *testing.T) {
	km, err := key.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	sk, pk, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	skb, pkb, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		t.Fatalf("SerializeKeyPair: %v", err)
	}
	_ = skb // signature bytes are slot-counted only by the pre-flight, not verified
	policyPath := writeTempEscrowPolicy(t, pkb)

	escrowMultisigMu.Lock()
	prevPolicy, prevAddr, prevEnforced := escrowMultisigPolicy, escrowMultisigAddr, escrowMultisigEnforced
	escrowMultisigMu.Unlock()
	t.Cleanup(func() {
		escrowMultisigMu.Lock()
		escrowMultisigPolicy, escrowMultisigAddr, escrowMultisigEnforced = prevPolicy, prevAddr, prevEnforced
		escrowMultisigMu.Unlock()
	})
	escrowAddr, err := LoadEscrowPolicy(policyPath)
	if err != nil {
		t.Fatalf("LoadEscrowPolicy: %v", err)
	}
	t.Cleanup(func() { multisig.UnregisterPolicy(escrowAddr) })

	founder := allocByLabel(t, "Founder")
	lower := strings.ToLower(founder.Address)

	nowTS := uint64(CanonicalGenesisTimestamp)
	horizonTS := nowTS + uint64(13*policy.CGEMonthSeconds)
	expiry := horizonTS + uint64(12*policy.CGEMonthSeconds)
	p, err := multisig.LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	w := WitnessForRelease(*p, map[int][]byte{0: {0x01}}, expiry)

	dir := t.TempDir()
	body, err := json.Marshal(map[string]interface{}{
		"recipient":     lower, // operator-typed case, deliberately non-canonical
		"target_height": 2,
		"witness":       w,
	})
	if err != nil {
		t.Fatalf("marshal witness file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "founder.json"), body, 0644); err != nil {
		t.Fatalf("write witness file: %v", err)
	}

	cov, err := CheckCGEWitnessCoverage(dir, nowTS, horizonTS)
	if err != nil {
		t.Fatalf("CheckCGEWitnessCoverage: %v", err)
	}
	for _, c := range cov {
		if c.Label != "Founder" {
			continue
		}
		if !c.Covered {
			t.Fatalf("mismatched-case file must report COVERED (intake canonicalizes), got: %+v", c)
		}
		if c.Recipient != founder.Address {
			t.Fatalf("coverage recipient = %q, want canonical %q", c.Recipient, founder.Address)
		}
		return
	}
	t.Fatal("no Founder row in coverage output")
}
