// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"math/big"
	"strings"
	"testing"

	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
)

// genesisVaultChainID matches the chain a bare &Blockchain{} publishes.
const genesisVaultChainID uint64 = 7331

// TestGenesisDistributionUsesCustodyAgreement proves block-0 distributions can
// be authorized by M-of-N agreement: with a vault custody policy loaded, every
// distribution transaction carries a threshold witness bound to the chain and
// the exact (vault, receiver, amount, nonce), and block-0 auth accepts it.
func TestGenesisDistributionUsesCustodyAgreement(t *testing.T) {
	sks, pks := escrowTestKeys(t, 3)
	p := setupVaultCustodyPolicy(t, pks, 2, "sphinx-vault-v1")
	vault, err := p.Address()
	if err != nil {
		t.Fatal(err)
	}

	expiry := uint64(CanonicalGenesisTimestamp) + uint64(30*24*3600)
	auth := func(receiver string, amount *big.Int, nonce uint64) *multisig.MultiSigWitness {
		msg := multisig.SpendMessage(&p, genesisVaultChainID, vault, receiver, amount, nonce, expiry)
		return ptrWitness(signWitness(t, nil, p, sks, pks, []int{0, 2}, msg, expiry))
	}

	block := minimalGenesisState().BuildBlockWithCustody(auth, genesisVaultChainID)
	if len(block.Body.TxsList) == 0 {
		t.Fatal("genesis produced no distribution transactions")
	}
	for i, tx := range block.Body.TxsList {
		if tx.Sender != vault {
			t.Fatalf("tx[%d] sender = %s, want custody vault %s", i, tx.Sender, vault)
		}
		if tx.MultiSigWitness == nil {
			t.Fatalf("tx[%d] is missing its M-of-N custody witness", i)
		}
		if tx.ChainID != genesisVaultChainID {
			t.Fatalf("tx[%d] chain id = %d, want %d", i, tx.ChainID, genesisVaultChainID)
		}
	}

	bc := &Blockchain{} // publishes chain 7331, no sphincsManager needed
	if err := bc.validateBlockTransactionAuth(block, false); err != nil {
		t.Fatalf("custody-authorized genesis distributions must pass block-0 auth: %v", err)
	}
}

// TestGenesisDistributionCustodyFailsClosed proves the fix: once the vault is a
// registered custody policy, an UNSIGNED block-0 distribution — the legacy
// system-transaction shape — can no longer be minted. This is the hole that let
// a custody vault bypass M-of-N on the one block that matters most.
func TestGenesisDistributionCustodyFailsClosed(t *testing.T) {
	_, pks := escrowTestKeys(t, 3)
	setupVaultCustodyPolicy(t, pks, 2, "sphinx-vault-v1")

	// Legacy unsigned build: no witness on any transaction.
	block := minimalGenesisState().BuildBlock()

	bc := &Blockchain{}
	err := bc.validateBlockTransactionAuth(block, false)
	if err == nil {
		t.Fatal("an unsigned distribution from a custody vault must fail block-0 auth (fail-closed)")
	}
}

// TestGenesisDistributionCustodyRejectsBelowThreshold proves a partial witness
// is not enough: fewer than M signatures must fail exactly like no witness.
func TestGenesisDistributionCustodyRejectsBelowThreshold(t *testing.T) {
	sks, pks := escrowTestKeys(t, 3)
	p := setupVaultCustodyPolicy(t, pks, 2, "sphinx-vault-v1")
	vault, err := p.Address()
	if err != nil {
		t.Fatal(err)
	}

	expiry := uint64(CanonicalGenesisTimestamp) + uint64(30*24*3600)
	auth := func(receiver string, amount *big.Int, nonce uint64) *multisig.MultiSigWitness {
		msg := multisig.SpendMessage(&p, genesisVaultChainID, vault, receiver, amount, nonce, expiry)
		return ptrWitness(signWitness(t, nil, p, sks, pks, []int{0}, msg, expiry))
	}

	block := minimalGenesisState().BuildBlockWithCustody(auth, genesisVaultChainID)
	bc := &Blockchain{}
	if err := bc.validateBlockTransactionAuth(block, false); err == nil {
		t.Fatal("a below-threshold witness must not authorize genesis distributions")
	}
}

// TestGenesisDistributionLegacyExemptionUnchanged pins backward compatibility:
// with no custody policy registered, the unsigned genesis distributions keep the
// legacy block-0 exemption (and therefore byte-identical genesis).
func TestGenesisDistributionLegacyExemptionUnchanged(t *testing.T) {
	bc := &Blockchain{}
	for i, tx := range genesisFundingTxs(t) {
		if custodyPolicyOwns(tx.Sender) {
			t.Fatalf("tx[%d]: unexpected custody policy for legacy vault %s", i, tx.Sender)
		}
		if err := bc.validateBlockTransactionAuth(genesisBlockWith(tx), false); err != nil {
			t.Fatalf("legacy genesis funding tx[%d] must stay exempt inside block 0: %v", i, err)
		}
	}
}

func ptrWitness(w multisig.MultiSigWitness) *multisig.MultiSigWitness { return &w }

// TestGenesisStartupGateIntegration is the integration pin for the scenario that
// was previously uncovered: a genesis vault custody policy + block-0 validation,
// driven through the SAME gate createGenesisBlock uses at startup.
//
// The unsigned half documents the trap (a policy-owned vault with an unsigned
// distribution must be REFUSED, not silently stored and executed). The witnessed
// half proves the fix, signing against the ENVIRONMENT chain id (devnet 73310)
// rather than the hardcoded 7331 the genesis cache uses — the chain-id plumbing
// that must land before any witness ceremony is attempted, or every custodian
// signature would fail the cross-chain check.
func TestGenesisStartupGateIntegration(t *testing.T) {
	sks, pks := escrowTestKeys(t, 3)
	p := setupVaultCustodyPolicy(t, pks, 2, "sphinx-vault-v1")
	vault, err := p.Address()
	if err != nil {
		t.Fatal(err)
	}

	bc := &Blockchain{}
	bc.chainParams = GetDevnetChainParams()
	envChainID := uint64(bc.chainParams.ChainID)
	if envChainID == 0 {
		t.Fatal("devnet chain id is zero")
	}
	if envChainID == genesisVaultChainID {
		t.Fatal("devnet chain id must differ from the hardcoded genesis-cache chain id")
	}

	// (a) THE TRAP: node-style unsigned genesis from a custody vault must be
	// refused at startup — the failure mode that used to build, store, execute,
	// and only diverge when a peer later validated the same block.
	err = bc.guardGenesisAuthorization(minimalGenesisState().BuildBlock())
	if err == nil {
		t.Fatal("a custody vault with an unsigned genesis must be refused at startup")
	}
	if !strings.Contains(err.Error(), "refusing to start") {
		t.Fatalf("the refusal must be explicit at startup, got: %v", err)
	}

	// (b) THE FIX: a distribution witnessed for THIS chain is accepted.
	expiry := uint64(CanonicalGenesisTimestamp) + uint64(30*24*3600)
	auth := func(receiver string, amount *big.Int, nonce uint64) *multisig.MultiSigWitness {
		msg := multisig.SpendMessage(&p, envChainID, vault, receiver, amount, nonce, expiry)
		return ptrWitness(signWitness(t, nil, p, sks, pks, []int{0, 1}, msg, expiry))
	}
	witnessed := minimalGenesisState().BuildBlockWithCustody(auth, envChainID)
	if err := bc.guardGenesisAuthorization(witnessed); err != nil {
		t.Fatalf("a genesis witnessed for chain %d must pass the startup gate: %v", envChainID, err)
	}

	// And the SAME witnessed block, when built for the wrong chain, must fail:
	// this is the chain-id mismatch that would otherwise burn a ceremony round.
	wrongChain := minimalGenesisState().BuildBlockWithCustody(
		func(receiver string, amount *big.Int, nonce uint64) *multisig.MultiSigWitness {
			msg := multisig.SpendMessage(&p, genesisVaultChainID, vault, receiver, amount, nonce, expiry)
			return ptrWitness(signWitness(t, nil, p, sks, pks, []int{0, 1}, msg, expiry))
		}, genesisVaultChainID)
	if err := bc.guardGenesisAuthorization(wrongChain); err == nil {
		t.Fatal("a genesis witnessed for the wrong chain must fail the startup gate")
	}
}
