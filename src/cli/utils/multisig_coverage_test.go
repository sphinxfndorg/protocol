// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/core"
	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	"github.com/sphinxfndorg/protocol/src/policy"
)

// coverageSetup provisions a real escrow policy + custodian keys with
// `multisig devnet` (the same artifact the node auto-loads) and returns the
// policy path, that policy, and a fresh witness directory.
func coverageSetup(t *testing.T) (string, *multisig.MultiPartyPolicy, string) {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "escrow_multisig.json")
	if err := runMultisigDevnet([]string{
		"--role", "escrow",
		"--out", policyPath,
		"--keys-dir", filepath.Join(dir, "keys"),
		"--custodians", "3",
		"--threshold", "2",
	}); err != nil {
		t.Fatalf("multisig devnet: %v", err)
	}
	p, err := multisig.LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("load generated policy: %v", err)
	}
	witnessDir := filepath.Join(dir, "witnesses")
	if err := os.MkdirAll(witnessDir, 0755); err != nil {
		t.Fatal(err)
	}
	return policyPath, p, witnessDir
}

// writeCoverageWitness drops one staged witness file in the format the node
// stages from disk: the witness carries the policy a real ceremony artifact
// would, because musig.MultiPartyPolicy.UnmarshalJSON validates on the way
// back in (a witness with an empty policy does not parse).
func writeCoverageWitness(t *testing.T, dir string, p *multisig.MultiPartyPolicy, recipient string, height, expiry uint64, slots int) {
	t.Helper()
	sigs := map[int][]byte{}
	for i := 0; i < slots; i++ {
		sigs[i] = []byte{byte(i + 1)}
	}
	body, err := json.Marshal(map[string]interface{}{
		"recipient":     recipient,
		"target_height": height,
		"witness":       multisig.MultiSigWitness{Policy: *p, Sigs: sigs, Expiry: expiry},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, recipient+".json"), body, 0644); err != nil {
		t.Fatal(err)
	}
}

// timeBasedRecipients returns label -> address for every time-based CGE
// allocation (the set a pre-flight must cover).
func timeBasedRecipients(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, alloc := range core.DefaultGenesisAllocations() {
		if alloc == nil || !policy.CGEScheduleForLabel(alloc.Label).IsTimeBased() {
			continue
		}
		out[alloc.Label] = alloc.Address
	}
	if len(out) == 0 {
		t.Fatal("no time-based CGE recipients found")
	}
	return out
}

// TestMultisigCoverageGateIsTheExitCode pins the rollout-gate contract:
// incomplete coverage MUST return an error (non-zero exit) naming the
// enforcement flip, and full coverage must pass. This is what turns "confirm
// the rollout plan" from a promise into something a script can check.
func TestMultisigCoverageGateIsTheExitCode(t *testing.T) {
	policyPath, p, witnessDir := coverageSetup(t)
	nowTS := uint64(core.CanonicalGenesisTimestamp)
	horizonTS := nowTS + uint64(13*policy.CGEMonthSeconds)
	expiry := horizonTS + uint64(12*policy.CGEMonthSeconds)
	recipients := timeBasedRecipients(t)

	// Only one recipient staged: the gate must fail.
	writeCoverageWitness(t, witnessDir, p, recipients["Founder"], 2, expiry, 2)
	err := runMultisigCoverage([]string{
		"--policy", policyPath,
		"--dir", witnessDir,
		"--now", itoa(nowTS),
		"--horizon", itoa(horizonTS),
	})
	if err == nil {
		t.Fatal("incomplete coverage must return an error so the gate exits non-zero")
	}
	if !strings.Contains(err.Error(), "do NOT enable enforcement") {
		t.Fatalf("the gate error must name the enforcement flip, got: %v", err)
	}

	// Every time-based recipient staged: the gate must pass.
	for _, addr := range recipients {
		writeCoverageWitness(t, witnessDir, p, addr, 3, expiry, 2)
	}
	if err := runMultisigCoverage([]string{
		"--policy", policyPath,
		"--dir", witnessDir,
		"--now", itoa(nowTS),
		"--horizon", itoa(horizonTS),
	}); err != nil {
		t.Fatalf("full coverage must pass the gate: %v", err)
	}
}

// TestMultisigCoverageReportsUnusableFilesNotMissingOnes pins the distinction
// the operator actually needs: a file that exists for a recipient but cannot
// authorize anything must NOT be reported as "no staged witness", or the
// operator goes hunting for a missing ceremony that already ran.
func TestMultisigCoverageReportsUnusableFilesNotMissingOnes(t *testing.T) {
	policyPath, p, witnessDir := coverageSetup(t)
	nowTS := uint64(core.CanonicalGenesisTimestamp)
	horizonTS := nowTS + uint64(13*policy.CGEMonthSeconds)
	recipients := timeBasedRecipients(t)

	// A structurally truncated file that name-drops a real recipient.
	founder := recipients["Founder"]
	broken := filepath.Join(witnessDir, founder+".json")
	if err := os.WriteFile(broken, []byte(`{"recipient":"`+founder+`","target_height":2,"witness":{}}`), 0644); err != nil {
		t.Fatal(err)
	}
	// And nothing at all for the others.
	if err := runMultisigCoverage([]string{
		"--policy", policyPath,
		"--dir", witnessDir,
		"--now", itoa(nowTS),
		"--horizon", itoa(horizonTS),
		"--json",
	}); err == nil {
		t.Fatal("a broken file must not satisfy the gate")
	}

	if _, err := core.LoadEscrowPolicy(policyPath); err != nil {
		t.Fatal(err)
	}
	cov, err := core.CheckCGEWitnessCoverage(witnessDir, nowTS, horizonTS)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cov {
		if c.Label != "Founder" {
			continue
		}
		if c.FilesPresent != 1 {
			t.Fatalf("Founder files_present = %d, want 1 (the file exists)", c.FilesPresent)
		}
		if !c.Unusable {
			t.Fatalf("Founder must be flagged Unusable, not silently MISSING: %+v", c)
		}
		if c.Reason == "" {
			t.Fatal("an unusable row must explain why")
		}
	}
	out := core.FormatCGEWitnessCoverage(cov, horizonTS)
	if !strings.Contains(out, "UNUSABLE") {
		t.Fatalf("the rendered pre-flight must distinguish UNUSABLE from MISSING:\n%s", out)
	}
	if !strings.Contains(out, "MISSING") {
		t.Fatalf("recipients with no file at all must still read MISSING:\n%s", out)
	}
	_ = p
}

// TestMultisigCoverageRefusesWallClock: with no --now and no reachable node,
// the check must refuse rather than silently fall back to time.Now(). A
// witness that validates against the operator's laptop clock but expires
// before the chain reaches the cliff is exactly the failure this catches.
func TestMultisigCoverageRefusesWallClock(t *testing.T) {
	policyPath, _, witnessDir := coverageSetup(t)
	err := runMultisigCoverage([]string{
		"--policy", policyPath,
		"--dir", witnessDir,
		"--rpc", "127.0.0.1:1",
	})
	if err == nil {
		t.Fatal("no --now and no reachable node must be an error, never a wall-clock fallback")
	}
	if !strings.Contains(err.Error(), "--now") {
		t.Fatalf("the error must point at --now, got: %v", err)
	}
}
