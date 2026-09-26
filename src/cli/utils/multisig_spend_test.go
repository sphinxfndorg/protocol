// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package utils

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	logger "github.com/sphinxfndorg/protocol/src/console"
	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// devnetPolicy runs `multisig devnet` into a temp dir and returns the loaded
// policy, its derived custodial address, and the key directory.
func devnetPolicy(t *testing.T, custodians, threshold int) (*multisig.MultiPartyPolicy, string, string) {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	keysDir := filepath.Join(dir, "keys")
	if err := runMultisigDevnet([]string{
		"--role", "escrow",
		"--out", policyPath,
		"--keys-dir", keysDir,
		"--custodians", itoa(uint64(custodians)),
		"--threshold", itoa(uint64(threshold)),
	}); err != nil {
		t.Fatalf("multisig devnet: %v", err)
	}
	p, err := multisig.LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("load generated policy: %v", err)
	}
	if p.Domain != custodyRoles["escrow"].Domain {
		t.Fatalf("domain = %q, want the escrow domain %q", p.Domain, custodyRoles["escrow"].Domain)
	}
	if len(p.PubKeys) != custodians {
		t.Fatalf("policy holds %d pubkeys, want %d", len(p.PubKeys), custodians)
	}
	addr, err := p.Address()
	if err != nil {
		t.Fatalf("derive address: %v", err)
	}
	return p, addr, keysDir
}

// TestMultisigDevnetWritesUsablePolicyAndKeys locks in the contract that makes
// the live flow possible: the generated policy parses through the same loader
// the node uses, and every custodian key file loads through the same
// loadSigningKeyFile the signer uses, mapping to a policy index.
func TestMultisigDevnetWritesUsablePolicyAndKeys(t *testing.T) {
	p, addr, keysDir := devnetPolicy(t, 3, 2)

	keys, err := custodyKeyFiles(keysDir, nil)
	if err != nil {
		t.Fatalf("custody key files: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("found %d key files, want 3", len(keys))
	}
	seen := map[int]bool{}
	for _, f := range keys {
		_, pkBytes, err := loadSigningKeyFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		idx := -1
		for i, pk := range p.PubKeys {
			if hex.EncodeToString(pk) == hex.EncodeToString(pkBytes) {
				idx = i
				break
			}
		}
		if idx < 0 {
			t.Fatalf("%s: pubkey is not in the generated policy", f)
		}
		if seen[idx] {
			t.Fatalf("policy index %d has two key files", idx)
		}
		seen[idx] = true

		info, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Fatalf("%s mode = %o, want 600 (custodian keys are secret)", f, perm)
		}
	}
	if len(addr) != 40 {
		t.Fatalf("custodial address %q is not a 20-byte hex address", addr)
	}
}

// TestMultisigDevnetRefusesToClobberCustodians: regenerating into a populated
// key directory would silently orphan the old custodians (their policy is
// replaced), so it must require --force.
func TestMultisigDevnetRefusesToClobberCustodians(t *testing.T) {
	dir := t.TempDir()
	base := []string{
		"--role", "escrow",
		"--out", filepath.Join(dir, "policy.json"),
		"--keys-dir", filepath.Join(dir, "keys"),
		"--custodians", "2", "--threshold", "2",
	}
	if err := runMultisigDevnet(base); err != nil {
		t.Fatalf("first devnet: %v", err)
	}
	if err := runMultisigDevnet(base); err == nil {
		t.Fatal("second devnet into a populated key dir must fail without --force")
	}
	if err := runMultisigDevnet(append(base, "--force")); err != nil {
		t.Fatalf("devnet --force: %v", err)
	}
}

// TestLiveSpendWitnessAuthorizesExactlyTheSpend is the signer↔verifier
// agreement test for the live path: it signs with the CLI's own
// signCustodyWitness and verifies with musig.CheckSpendWitness, the function
// every node admission and commit path calls. A pass means the bytes the CLI
// signs are the bytes the network checks.
func TestLiveSpendWitnessAuthorizesExactlyTheSpend(t *testing.T) {
	p, vault, keysDir := devnetPolicy(t, 3, 2)
	keys, err := custodyKeyFiles(keysDir, nil)
	if err != nil {
		t.Fatal(err)
	}

	receiver := "00000000000000000000000000000000000000AA"
	amount := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	const chainID = uint64(7331)
	const nonce = uint64(0)
	refTime := uint64(time.Now().Unix())
	expiry := uint64(time.Now().Add(30 * 24 * time.Hour).Unix())

	msg := multisig.SpendMessage(p, chainID, vault, receiver, amount, nonce, expiry)
	sigs, err := signCustodyWitness(p, msg, keys[:2])
	if err != nil {
		t.Fatalf("sign custody witness: %v", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("witness carries %d signatures, want 2", len(sigs))
	}

	// CheckSpendWitness resolves the sender through the registry, so publish
	// the policy and this chain exactly as the node does.
	addr, err := multisig.RegisterPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	defer multisig.UnregisterPolicy(addr)
	prev := multisig.RequireActiveChainID(chainID)
	defer multisig.SetActiveChainID(prev)

	witness := &multisig.MultiSigWitness{Policy: *p, Sigs: sigs, Expiry: expiry}
	ok, err := multisig.CheckSpendWitness(vault, receiver, chainID, amount, nonce, witness, refTime)
	if !ok || err != nil {
		t.Fatalf("threshold witness must authorize the spend: ok=%v err=%v", ok, err)
	}

	// Any change to the authorized spend must break it — this is what makes the
	// witness non-replayable.
	other := new(big.Int).Mul(big.NewInt(1001), big.NewInt(1e18))
	if _, err := multisig.CheckSpendWitness(vault, receiver, chainID, other, nonce, witness, refTime); err == nil {
		t.Fatal("witness must not authorize a different amount")
	}
	if _, err := multisig.CheckSpendWitness(vault, receiver, chainID+1, amount, nonce, witness, refTime); err == nil {
		t.Fatal("witness must not authorize a spend on another chain")
	}
	if _, err := multisig.CheckSpendWitness(vault, receiver, chainID, amount, nonce+1, witness, refTime); err == nil {
		t.Fatal("witness must not authorize a different nonce")
	}
	expired := *witness
	expired.Expiry = refTime
	if _, err := multisig.CheckSpendWitness(vault, receiver, chainID, amount, nonce, &expired, refTime+1); err == nil {
		t.Fatal("expired witness must be rejected")
	}
}

// TestLiveSpendRefusesBelowThresholdUnlessPartial: an operator who supplies too
// few custodian keys gets a local error naming the threshold, rather than a
// broadcast the network will reject. --allow-partial exists to prove the node
// rejects it, so it must bypass only that local guard.
func TestLiveSpendRefusesBelowThresholdUnlessPartial(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	keysDir := filepath.Join(dir, "keys")
	if err := runMultisigDevnet([]string{
		"--role", "escrow", "--out", policyPath, "--keys-dir", keysDir,
		"--custodians", "3", "--threshold", "3",
	}); err != nil {
		t.Fatalf("devnet: %v", err)
	}
	common := []string{
		"--policy", policyPath,
		"--to", "00000000000000000000000000000000000000BB",
		"--amount-spx", "10",
		"--nonce", "7",
		"--key", filepath.Join(keysDir, "custodian-0.json"),
		"--dry-run",
	}
	if err := runMultisigSpend(common); err == nil {
		t.Fatal("one signature against a 3-of-3 policy must fail locally")
	}
	if err := runMultisigSpend(append(append([]string(nil), common...), "--allow-partial")); err != nil {
		t.Fatalf("--allow-partial must build the transaction for a negative network test: %v", err)
	}
}

// TestWatchSpendLoopRunsCyclesUntilStopped pins the pacing contract behind
// --watch: the first cycle runs immediately (a watcher reacts as soon as it
// starts), every later cycle waits --interval, and a closed stop channel ends
// the loop with nil — that is exactly the SIGINT/SIGTERM path.
func TestWatchSpendLoopRunsCyclesUntilStopped(t *testing.T) {
	const interval = 20 * time.Millisecond
	stop := make(chan struct{})
	cycles := 0
	start := time.Now()
	err := watchSpendLoop(interval, stop, func() error {
		cycles++
		if cycles == 3 {
			close(stop)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("watchSpendLoop: %v", err)
	}
	if cycles != 3 {
		t.Fatalf("cycles = %d, want 3", cycles)
	}
	// Two full interval waits elapse (cycle 1→2 and 2→3); the wait after the
	// final cycle is cut short by the closed stop. Timers never fire early,
	// so the lower bound is guaranteed.
	if elapsed := time.Since(start); elapsed < 2*interval {
		t.Fatalf("loop returned after %s, want at least %s: it must wait --interval between cycles", elapsed, 2*interval)
	}
}

// TestWatchSpendLoopAbortsOnCycleError: a fatal cycle error (a rejected
// witness, an expired horizon) must surface immediately instead of being
// retried forever — the huge interval proves the abort never waits for a tick.
func TestWatchSpendLoopAbortsOnCycleError(t *testing.T) {
	boom := errors.New("cycle failed")
	cycles := 0
	err := watchSpendLoop(time.Hour, make(chan struct{}), func() error {
		cycles++
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the cycle error", err)
	}
	if cycles != 1 {
		t.Fatalf("cycles = %d, want 1: a fatal error must abort before the next tick", cycles)
	}
}

// TestWatchSpendLoopRejectsNonPositiveInterval: a zero or negative interval
// would spin the watcher at full speed against the node; it must be refused
// before any cycle runs.
func TestWatchSpendLoopRejectsNonPositiveInterval(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		err := watchSpendLoop(interval, make(chan struct{}), func() error {
			t.Fatal("cycle must not run when the interval is invalid")
			return nil
		})
		if err == nil {
			t.Fatalf("interval %s must be rejected", interval)
		}
	}
}

// TestMultisigSpendWatchRejectsUnsafeFlagCombinations: --watch reuses the
// one-shot flags in a loop, and two of them are unsafe there — a pinned nonce
// would be reused after the first spend, and --allow-partial would rebroadcast
// a below-threshold spend every interval. All of these must fail before the
// policy file is even opened.
func TestMultisigSpendWatchRejectsUnsafeFlagCombinations(t *testing.T) {
	base := []string{
		"--policy", "policy.json",
		"--to", "00000000000000000000000000000000000000BB",
		"--amount-spx", "1",
	}
	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"fixed nonce", append([]string{"--watch", "--nonce", "7"}, base...), "--nonce"},
		{"zero interval", append([]string{"--watch", "--interval", "0s"}, base...), "--interval"},
		{"negative interval", append([]string{"--interval", "-1s"}, base...), "--interval"},
		{"allow-partial", append([]string{"--watch", "--allow-partial"}, base...), "--allow-partial"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runMultisigSpend(tc.args)
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestMultisigSpendWatchStopsOnSigint drives the real --watch path end to
// end: monitor mode (--dry-run) polls an RPC endpoint where nothing listens,
// so every balance read fails — a failure the loop must survive — until
// SIGINT arrives, after which the command must return nil (a graceful stop,
// not an error and not a hang).
func TestMultisigSpendWatchStopsOnSigint(t *testing.T) {
	// Disable the console renderer's process-wide handler up front: it would
	// otherwise os.Exit(130) the test binary if a SIGINT lands before the
	// watcher registers its own handler (the production watch path disables it
	// too, but only once it is running).
	logger.DisableSignalHandler()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	keysDir := filepath.Join(dir, "keys")
	if err := runMultisigDevnet([]string{
		"--role", "escrow", "--out", policyPath, "--keys-dir", keysDir,
		"--custodians", "1", "--threshold", "1",
	}); err != nil {
		t.Fatalf("devnet: %v", err)
	}

	// Register a guard handler first so the process can never die on SIGINT,
	// even if the signal lands before runMultisigSpend registers its own
	// handler: signal.Notify broadcasts to every registered channel.
	guard := make(chan os.Signal, 1)
	signal.Notify(guard, syscall.SIGINT)
	t.Cleanup(func() { signal.Stop(guard) })

	done := make(chan error, 1)
	go func() {
		done <- runMultisigSpend([]string{
			"--policy", policyPath,
			"--to", "00000000000000000000000000000000000000BB",
			"--amount-spx", "1",
			"--keys-dir", keysDir,
			"--rpc", "127.0.0.1:1", // nothing listens: every balance read fails
			"--watch", "--dry-run", "--interval", "50ms",
		})
	}()

	// Re-sending until the watcher answers covers the window before its
	// handler is registered; once registered, the next SIGINT stops it.
	deadline := time.After(10 * time.Second)
	for {
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
			t.Fatalf("kill(self, SIGINT): %v", err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("--watch must stop with nil on SIGINT, got %v", err)
			}
			return
		case <-time.After(500 * time.Millisecond):
			// Not registered yet — signal again.
		case <-deadline:
			t.Fatal("--watch did not stop after SIGINT")
		}
	}
}

// TestAutoWatchArgsSelfDirected pins the always-on watcher contract: the node
// is never told a destination or amount, so the argv it receives must enable
// --watch without --to/--amount and point at the proposal directory. Startup is
// gated ONLY on the custody policy being present and parseable — a broadcaster
// is not a custodian, so it must start with no custodian keys on disk at all.
func TestAutoWatchArgsSelfDirected(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	keysDir := filepath.Join(dir, "keys")
	if err := runMultisigDevnet([]string{
		"--role", "escrow", "--out", policyPath, "--keys-dir", keysDir,
		"--custodians", "3", "--threshold", "2",
	}); err != nil {
		t.Fatalf("devnet: %v", err)
	}

	// Missing / empty policy → the devnet prerequisite is named.
	if _, err := autoWatchArgs(filepath.Join(dir, "missing.json"), "127.0.0.1:8700", "config/spend_proposals"); err == nil || !strings.Contains(err.Error(), "multisig devnet") {
		t.Fatalf("missing policy: err = %v, want it to point at `multisig devnet`", err)
	}
	if _, err := autoWatchArgs("", "127.0.0.1:8700", "config/spend_proposals"); err == nil || !strings.Contains(err.Error(), "multisig devnet") {
		t.Fatalf("empty policy path: err = %v, want it to point at `multisig devnet`", err)
	}

	// Broadcaster ≠ custodian: delete EVERY custodian key and the watcher must
	// still start — it never signs, so it must not require signing authority.
	if err := os.RemoveAll(keysDir); err != nil {
		t.Fatal(err)
	}
	got, err := autoWatchArgs(policyPath, "127.0.0.1:8700", "config/spend_proposals")
	if err != nil {
		t.Fatalf("happy path with no custodian keys: %v", err)
	}
	want := []string{
		"--policy", policyPath,
		"--rpc", "127.0.0.1:8700",
		"--proposals-dir", "config/spend_proposals",
		"--watch",
		"--interval", defaultCustodyWatchInterval.String(),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
}

// The reachable-threshold and argv-shape coverage now lives in
// TestAutoWatchArgsSelfDirected above: the watcher is self-directed (no --to,
// no --amount), so the old `node --spend` argv assertions no longer apply.

// writeCustodyProposal signs one custody spend with keyFiles and writes the
// exact artifact the always-on watcher consumes: the assembled transaction JSON
// that `multisig spend --dry-run --out` produces, including the M-of-N witness.
func writeCustodyProposal(t *testing.T, path string, p *multisig.MultiPartyPolicy, sender, to string, amount *big.Int, nonce, chainID, expiry uint64, keyFiles []string) *types.Transaction {
	t.Helper()
	msg := multisig.SpendMessage(p, chainID, sender, to, amount, nonce, expiry)
	sigs, err := signCustodyWitness(p, msg, keyFiles)
	if err != nil {
		t.Fatalf("sign custody witness: %v", err)
	}
	tx := &types.Transaction{
		Sender: sender, Receiver: to, Amount: new(big.Int).Set(amount),
		GasLimit: big.NewInt(100_000), GasPrice: big.NewInt(1),
		Nonce: nonce, Timestamp: time.Now().Unix(), ChainID: chainID,
		MultiSigWitness: &multisig.MultiSigWitness{Policy: *p, Sigs: sigs, Expiry: expiry},
	}
	tx.ID = tx.Hash() // exactly how broadcastCustodySpend mints it (ID empty)
	data, err := json.MarshalIndent(tx, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	return tx
}

// TestLoadCustodyProposalVerifiesAgainstLivePolicy is the watcher's admission
// gate: a proposal is broadcast only when it is signed for EXACTLY this spend
// under the CURRENT policy. Every tamper must be refused, and the happy path
// must yield the canonical txid without mutating it.
func TestLoadCustodyProposalVerifiesAgainstLivePolicy(t *testing.T) {
	p, sender, keysDir := devnetPolicy(t, 3, 2)
	keys, err := custodyKeyFiles(keysDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	const chainID = uint64(7331)
	now := uint64(time.Now().Unix())
	expiry := uint64(time.Now().Add(30 * 24 * time.Hour).Unix())
	receiver := "00000000000000000000000000000000000000AA"
	amount := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	dir := t.TempDir()
	path := filepath.Join(dir, "proposal.json")

	tx := writeCustodyProposal(t, path, p, sender, receiver, amount, 0, chainID, expiry, keys[:2])
	got, err := loadCustodyProposal(path, p, sender, chainID, now)
	if err != nil {
		t.Fatalf("valid proposal must load: %v", err)
	}
	if id := custodyProposalTxID(got); id != got.ID || id != tx.ID {
		t.Fatalf("canonical txid mismatch: recomputed=%s field=%s want=%s", id, got.ID, tx.ID)
	}
	if custodyProposalTxID(got) != got.ID { // idempotent under repeated use
		t.Fatal("custodyProposalTxID must be idempotent")
	}

	tamper := func(name string, mutate func(*types.Transaction)) {
		t.Helper()
		clone := *tx
		clone.MultiSigWitness = &multisig.MultiSigWitness{
			Policy: tx.MultiSigWitness.Policy, Sigs: tx.MultiSigWitness.Sigs, Expiry: tx.MultiSigWitness.Expiry,
		}
		mutate(&clone)
		data, err := json.MarshalIndent(&clone, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		badPath := filepath.Join(dir, name+".json")
		if err := os.WriteFile(badPath, data, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadCustodyProposal(badPath, p, sender, chainID, now); err == nil {
			t.Fatalf("%s: tampered proposal must be refused", name)
		}
	}
	tamper("amount", func(x *types.Transaction) { x.Amount = new(big.Int).Mul(big.NewInt(1001), big.NewInt(1e18)) })
	tamper("nonce", func(x *types.Transaction) { x.Nonce++ })
	tamper("receiver", func(x *types.Transaction) { x.Receiver = "00000000000000000000000000000000000000BB" })
	tamper("chain", func(x *types.Transaction) { x.ChainID = chainID + 1 })
	tamper("sender", func(x *types.Transaction) { x.Sender = "00000000000000000000000000000000000000CC" })

	// Below-threshold signatures must not load even though every field is intact.
	oneKeyPath := filepath.Join(dir, "one.json")
	writeCustodyProposal(t, oneKeyPath, p, sender, receiver, amount, 0, chainID, expiry, keys[:1])
	if _, err := loadCustodyProposal(oneKeyPath, p, sender, chainID, now); err == nil {
		t.Fatal("below-threshold proposal must be refused")
	}
}

// TestIsNodeRPCRejection pins the classification the self-directed watcher uses
// to decide "settle forever" vs "retry next cycle": a node-side RPC refusal is
// permanent for these exact bytes, but a dial/handshake failure is transient.
func TestIsNodeRPCRejection(t *testing.T) {
	if !isNodeRPCRejection(fmt.Errorf(
		"sendrawtransaction via 127.0.0.1:1: RPC error (-32000): custody witness verification failed")) {
		t.Fatal("a node-side RPC error must settle the proposal")
	}
	if isNodeRPCRejection(fmt.Errorf(
		"sendrawtransaction via 127.0.0.1:1: dial tcp 127.0.0.1:1: connect: connection refused")) {
		t.Fatal("a transport failure must be retried, not settled")
	}
	if isNodeRPCRejection(nil) {
		t.Fatal("nil error must not be a rejection")
	}
}

// TestListCustodyProposalsFiltersAndSorts pins the directory contract: only
// *.json files count, dotfiles/subdirs/other extensions are ignored, and the
// order is deterministic so the first eligible broadcast is reproducible.
func TestListCustodyProposalsFiltersAndSorts(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"b.json", "a.json", ".hidden.json", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub.json"), 0700); err != nil {
		t.Fatal(err)
	}
	got, err := listCustodyProposals(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.json", "b.json"}
	if !slices.Equal(got, want) {
		t.Fatalf("proposals = %q, want %q", got, want)
	}
	if _, err := listCustodyProposals(filepath.Join(dir, "missing")); !os.IsNotExist(err) {
		t.Fatalf("missing dir: err = %v, want os.IsNotExist", err)
	}
}
