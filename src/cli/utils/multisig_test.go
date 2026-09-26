// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package utils

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
)

func itoa(v uint64) string { return strconv.FormatUint(v, 10) }

type testCustodian struct {
	sk, pk  []byte
	keyPath string
	pubPath string
}

// writeCustodianKeys materialises one custodian's key file and pubkey file in
// exactly the formats the CLI reads.
func writeCustodianKeys(t *testing.T, dir string, i int, km *key.KeyManager) testCustodian {
	t.Helper()
	sk, pk, err := km.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		t.Fatal(err)
	}
	name := "custodian" + strconv.Itoa(i)
	keyPath := filepath.Join(dir, name+".key.json")
	body, err := json.Marshal(map[string]string{
		"sk": hex.EncodeToString(skBytes),
		"pk": hex.EncodeToString(pkBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, body, 0600); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, name+".pub.hex")
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pkBytes)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return testCustodian{sk: skBytes, pk: pkBytes, keyPath: keyPath, pubPath: pubPath}
}

func TestMultisigMessageMatchesVerifierEncoding(t *testing.T) {
	dir := t.TempDir()
	km, err := key.NewKeyManager()
	if err != nil {
		t.Fatal(err)
	}
	custodians := make([]testCustodian, 3)
	for i := range custodians {
		custodians[i] = writeCustodianKeys(t, dir, i, km)
	}

	policyPath := filepath.Join(dir, "policy.json")
	create := []string{"--threshold", "2", "--domain", "sphinx-vault-v1", "--out", policyPath}
	for _, c := range custodians {
		create = append(create, "--pubkey", c.pubPath)
	}
	if err := runMultisigCreate(create); err != nil {
		t.Fatalf("multisig create: %v", err)
	}
	p, err := multisig.LoadPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	vault, err := p.Address()
	if err != nil {
		t.Fatal(err)
	}

	receiver := "00000000000000000000000000000000000000AA"
	amount := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	const nonce = uint64(0)
	const chainID = uint64(7331)
	refTS := uint64(1800000000)
	expiry := refTS + 30*24*3600

	// Raw-bytes form: the file must contain exactly SpendMessage, the same
	// function the verifier calls.
	msgPath := filepath.Join(dir, "spend.msg")
	if err := runMultisigMessage([]string{
		"--policy", policyPath, "--kind", "spend",
		"--receiver", receiver, "--amount-spx", "1000",
		"--nonce", "0", "--expiry", itoa(expiry),
		"--chain-id", "7331", "--release-time", itoa(refTS),
		"--out", msgPath,
	}); err != nil {
		t.Fatalf("multisig message: %v", err)
	}
	written, err := os.ReadFile(msgPath)
	if err != nil {
		t.Fatal(err)
	}
	want := multisig.SpendMessage(p, chainID, vault, receiver, amount, nonce, expiry)
	if hex.EncodeToString(written) != hex.EncodeToString(want) {
		t.Fatalf("message file = %x, verifier builds %x", written, want)
	}

	// Hex-text form for cross-machine transfer: the signer must decode it back
	// to the very same bytes.
	hexPath := filepath.Join(dir, "spend.msg.hex")
	if err := runMultisigMessage([]string{
		"--policy", policyPath, "--kind", "spend",
		"--receiver", receiver, "--amount-nspx", amount.String(),
		"--nonce", "0", "--expiry", itoa(expiry),
		"--chain-id", "7331", "--release-time", itoa(refTS),
		"--out", hexPath, "--hex",
	}); err != nil {
		t.Fatalf("multisig message --hex: %v", err)
	}
	hexWritten, err := os.ReadFile(hexPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(hexWritten) != hex.EncodeToString(want) {
		t.Fatalf("hex message file = %q, want %s", hexWritten, hex.EncodeToString(want))
	}

	// Sign with two custodians over the hex form, combine, and verify the
	// assembled witness with the core verifier.
	sigPaths := make([]string, 0, 2)
	for _, i := range []int{0, 1} {
		sigPath := filepath.Join(dir, "sig"+strconv.Itoa(i)+".json")
		if err := runMultisigSign([]string{
			"--policy", policyPath, "--tx", hexPath, "--hex",
			"--key", custodians[i].keyPath, "--out", sigPath,
		}); err != nil {
			t.Fatalf("multisig sign[%d]: %v", i, err)
		}
		sigPaths = append(sigPaths, sigPath)
	}
	witnessPath := filepath.Join(dir, "witness.json")
	combine := []string{
		"--policy", policyPath, "--expiry", itoa(expiry),
		"--release-time", itoa(refTS), "--out", witnessPath,
	}
	for _, s := range sigPaths {
		combine = append(combine, "--sig", s)
	}
	if err := runMultisigCombine(combine); err != nil {
		t.Fatalf("multisig combine: %v", err)
	}
	raw, err := os.ReadFile(witnessPath)
	if err != nil {
		t.Fatal(err)
	}
	var w multisig.MultiSigWitness
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	if len(w.Sigs) != 2 || !w.MeetsThreshold() {
		t.Fatalf("combined witness has %d sigs, threshold %d", len(w.Sigs), w.Policy.Threshold)
	}
	if !multisig.VerifyThreshold(want, w, refTS) {
		t.Fatal("the CLI-built message must verify against the CLI-built witness")
	}

	// And the whole ceremony must satisfy the real custody spend path. The
	// production node publishes its chain before every custody decision; the
	// test does the same explicitly because it calls the checker directly.
	prev := multisig.RequireActiveChainID(chainID)
	defer multisig.SetActiveChainID(prev)
	if _, err := multisig.RegisterPolicy(p); err != nil {
		t.Fatal(err)
	}
	defer multisig.UnregisterPolicy(vault)
	if ok, err := multisig.CheckSpendWitness(vault, receiver, chainID, amount, nonce, &w, refTS); !ok || err != nil {
		t.Fatalf("CLI ceremony must authorize the spend: ok=%v err=%v", ok, err)
	}

	// A witness collected for another chain must not authorize this one.
	foreign := multisig.RequireActiveChainID(73310)
	defer multisig.SetActiveChainID(foreign)
	if ok, err := multisig.CheckSpendWitness(vault, receiver, chainID, amount, nonce, &w, refTS); !ok || err == nil {
		t.Fatalf("witness bound to chain %d must be rejected on chain 73310 (ok=%v err=%v)", chainID, ok, err)
	}
}

// TestMultisigMessageCGEKindsMatchVerifier covers the two protocol-triggered
// message kinds, which share the canonical encoder with the CGE verifier.
func TestMultisigMessageCGEKindsMatchVerifier(t *testing.T) {
	dir := t.TempDir()
	km, err := key.NewKeyManager()
	if err != nil {
		t.Fatal(err)
	}
	c := writeCustodianKeys(t, dir, 0, km)
	policyPath := filepath.Join(dir, "escrow.json")
	if err := runMultisigCreate([]string{
		"--threshold", "1", "--domain", "sphinx-escrow-v1",
		"--pubkey", c.pubPath, "--out", policyPath,
	}); err != nil {
		t.Fatal(err)
	}
	p, err := multisig.LoadPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	escrow, err := p.Address()
	if err != nil {
		t.Fatal(err)
	}
	receiver := "00000000000000000000000000000000000000BB"
	amount := new(big.Int).Mul(big.NewInt(6250000), big.NewInt(1e18))
	refTS := uint64(1800000000)
	expiry := refTS + 30*24*3600

	out := filepath.Join(dir, "cge.msg")
	if err := runMultisigMessage([]string{
		"--policy", policyPath, "--kind", "cge-release",
		"--receiver", receiver, "--amount-nspx", amount.String(),
		"--nonce", "2", "--expiry", itoa(expiry), "--chain-id", "7331", "--out", out,
	}); err != nil {
		t.Fatalf("cge-release message: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	wantRelease := multisig.CustodyReleaseMessage(p.Domain, 7331, escrow, receiver, amount.Bytes(), 2, expiry)
	if hex.EncodeToString(got) != hex.EncodeToString(wantRelease) {
		t.Fatalf("cge-release message = %x, want %x", got, wantRelease)
	}

	out = filepath.Join(dir, "module.msg")
	if err := runMultisigMessage([]string{
		"--policy", policyPath, "--kind", "dev-module",
		"--receiver", receiver, "--nonce", "7", "--expiry", itoa(expiry),
		"--chain-id", "7331", "--out", out,
	}); err != nil {
		t.Fatalf("dev-module message: %v", err)
	}
	got, err = os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	wantModule := multisig.DevModuleReleaseMessage(p.Domain, 7331, escrow, receiver, 7, expiry)
	if hex.EncodeToString(got) != hex.EncodeToString(wantModule) {
		t.Fatalf("dev-module message = %x, want %x", got, wantModule)
	}
}
