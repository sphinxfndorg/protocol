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
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
)

const custodySpendChainID uint64 = 7331

func custodyBlock(height uint64, ts int64, txs ...*types.Transaction) *types.Block {
	return &types.Block{
		Header: &types.BlockHeader{Block: height, Height: height, Timestamp: ts},
		Body:   types.BlockBody{TxsList: txs},
	}
}

// setupVaultCustodyPolicy loads a real genesis_multisig.json through the same
// loader the node uses, so the policy is registered exactly as it would be in
// production, and restores every global it touches.
func setupVaultCustodyPolicy(t *testing.T, pks [][]byte, threshold uint8, domain string) multisig.MultiPartyPolicy {
	t.Helper()
	p := multisig.MultiPartyPolicy{PubKeys: pks, Threshold: threshold, Domain: domain}
	addr, err := p.Address()
	if err != nil {
		t.Fatal(err)
	}

	prevAddr := GenesisVaultAddress
	prevTxAddr := types.GenesisVaultAddress
	prevLoaded := genesisMultisigAddr
	prevPolicy := genesisMultisigPolicy
	t.Cleanup(func() {
		genesisMultisigMu.Lock()
		GenesisVaultAddress = prevAddr
		types.GenesisVaultAddress = prevTxAddr
		genesisMultisigAddr = prevLoaded
		genesisMultisigPolicy = prevPolicy
		genesisMultisigMu.Unlock()
		multisig.UnregisterPolicy(addr)
	})

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
	if got != addr {
		t.Fatalf("loaded vault %s, want %s", got, addr)
	}
	return p
}

func custodySpendTx(sender, receiver string, amount *big.Int, nonce uint64) *types.Transaction {
	return &types.Transaction{
		ID:       "custody-spend-0",
		ChainID:  custodySpendChainID,
		Sender:   sender,
		Receiver: receiver,
		Amount:   amount,
		Nonce:    nonce,
		GasLimit: big.NewInt(21000),
		GasPrice: big.NewInt(1),
	}
}

// TestCustodyVaultSpendThroughAuthPath drives a vault spend through the real
// block-level tx_auth choke point (validateBlockTransactionAuth, the same call
// CommitBlock makes) with an M-of-N witness instead of a single-key bundle.
func TestCustodyVaultSpendThroughAuthPath(t *testing.T) {
	sks, pks := escrowTestKeys(t, 3)
	p := setupVaultCustodyPolicy(t, pks, 2, "sphinx-vault-v1")
	vault, err := p.Address()
	if err != nil {
		t.Fatal(err)
	}

	headerTS := CanonicalGenesisTimestamp + 40*24*3600
	expiry := uint64(headerTS) + uint64(12*policy.CGEMonthSeconds)
	amount := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	receiver := "00000000000000000000000000000000000000AA"
	tx := custodySpendTx(vault, receiver, amount, 1)

	msg := multisig.SpendMessage(&p, tx.ChainID, vault, receiver, amount, tx.Nonce, expiry)
	sigs := map[int][]byte{}
	for _, i := range []int{0, 2} {
		sig, err := multisig.SignCustodyMessage(msg, sks[i], pks[i])
		if err != nil {
			t.Fatal(err)
		}
		sigs[i] = sig
	}
	tx.MultiSigWitness = &multisig.MultiSigWitness{Policy: p, Sigs: sigs, Expiry: expiry}

	bc := &Blockchain{} // no sphincsManager: custody auth must not need one
	if err := bc.validateTransactionAuth(tx, 1, uint64(headerTS), false); err != nil {
		t.Fatalf("vault spend with a 2-of-3 witness must be authorized: %v", err)
	}
	if err := bc.validateBlockTransactionAuth(custodyBlock(1, headerTS, tx), false); err != nil {
		t.Fatalf("vault spend must pass block-level tx auth: %v", err)
	}

	// The witness survives the wire format the node actually persists and
	// gossips, and still authorizes the same spend.
	raw, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var decodedTx types.Transaction
	if err := json.Unmarshal(raw, &decodedTx); err != nil {
		t.Fatal(err)
	}
	if decodedTx.MultiSigWitness == nil {
		t.Fatal("multisig witness lost in JSON transport")
	}
	if err := bc.validateBlockTransactionAuth(custodyBlock(2, headerTS, &decodedTx), false); err != nil {
		t.Fatalf("transported vault spend must still pass block-level tx auth: %v", err)
	}
}

// TestCustodyVaultSpendRejections covers every way a vault spend must fail.
// TestCustodyVaultSpendRejections covers every way a vault spend must fail.
// A bare &Blockchain{} publishes 7331 as its chain ID, so every subcase
// except the explicit unset one runs with cross-chain protection armed.
func TestCustodyVaultSpendRejections(t *testing.T) {
	sks, pks := escrowTestKeys(t, 3)
	sksOut, pksOut := escrowTestKeys(t, 1)
	p := setupVaultCustodyPolicy(t, pks, 2, "sphinx-vault-v1")
	vault, err := p.Address()
	if err != nil {
		t.Fatal(err)
	}

	headerTS := CanonicalGenesisTimestamp + 40*24*3600
	expiry := uint64(headerTS) + uint64(12*policy.CGEMonthSeconds)
	amount := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	receiver := "00000000000000000000000000000000000000AA"
	bc := &Blockchain{}

	sign := func(t *testing.T, idxs []int, e uint64, amt *big.Int) map[int][]byte {
		t.Helper()
		msg := multisig.SpendMessage(&p, custodySpendChainID, vault, receiver, amt, 1, e)
		out := map[int][]byte{}
		for _, i := range idxs {
			sig, err := multisig.SignCustodyMessage(msg, sks[i], pks[i])
			if err != nil {
				t.Fatal(err)
			}
			out[i] = sig
		}
		return out
	}

	cases := []struct {
		name       string
		txChainID  uint64 // non-zero: the tx declares this chain
		witness    func(t *testing.T) *multisig.MultiSigWitness
		witnessFor uint64 // chain the witness was collected on (defaults to the tx's own chain)
		wantErr    string
	}{
		{
			name:       "witness bound to a different chain",
			txChainID:  custodySpendChainID + 1,
			witnessFor: custodySpendChainID + 1,
			witness: func(t *testing.T) *multisig.MultiSigWitness {
				fmsg := multisig.SpendMessage(&p, custodySpendChainID+1, vault, receiver, amount, 1, expiry)
				fsigs := map[int][]byte{}
				for _, i := range []int{0, 1} {
					sig, err := multisig.SignCustodyMessage(fmsg, sks[i], pks[i])
					if err != nil {
						t.Fatal(err)
					}
					fsigs[i] = sig
				}
				return &multisig.MultiSigWitness{Policy: p, Sigs: fsigs, Expiry: expiry}
			},
			wantErr: "bound to chain",
		},
		{
			name: "below threshold",
			witness: func(t *testing.T) *multisig.MultiSigWitness {
				return &multisig.MultiSigWitness{Policy: p, Sigs: sign(t, []int{0}, expiry, amount), Expiry: expiry}
			},
			wantErr: "below threshold",
		},
		{
			name: "signature from a non-custodian key",
			witness: func(t *testing.T) *multisig.MultiSigWitness {
				sigs := sign(t, []int{0}, expiry, amount)
				msg := multisig.SpendMessage(&p, custodySpendChainID, vault, receiver, amount, 1, expiry)
				outsider, err := multisig.SignCustodyMessage(msg, sksOut[0], pksOut[0])
				if err != nil {
					t.Fatal(err)
				}
				sigs[1] = outsider
				return &multisig.MultiSigWitness{Policy: p, Sigs: sigs, Expiry: expiry}
			},
			wantErr: "below threshold",
		},
		{
			name: "expired witness",
			witness: func(t *testing.T) *multisig.MultiSigWitness {
				e := uint64(headerTS) // no remaining validity horizon
				return &multisig.MultiSigWitness{Policy: p, Sigs: sign(t, []int{0, 1}, e, amount), Expiry: e}
			},
			wantErr: "unspendable too soon",
		},
		{
			name: "witness collected for a different amount",
			witness: func(t *testing.T) *multisig.MultiSigWitness {
				other := new(big.Int).Add(amount, big.NewInt(1))
				return &multisig.MultiSigWitness{Policy: p, Sigs: sign(t, []int{0, 1}, expiry, other), Expiry: expiry}
			},
			wantErr: "below threshold",
		},

		{
			name:    "no witness at all",
			witness: func(t *testing.T) *multisig.MultiSigWitness { return nil },
			wantErr: "requires an M-of-N witness",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx := custodySpendTx(vault, receiver, amount, 1)
			if tc.txChainID != 0 {
				tx.ChainID = tc.txChainID
				// The witness is collected for whatever chain the subcase's
				// signing inputs require; by default the tx's own chain.
				if tc.witnessFor != 0 && tc.witnessFor != tc.txChainID {
					t.Fatalf("witnessFor (%d) must match the tx chain (%d) in this harness", tc.witnessFor, tc.txChainID)
				}
			}
			tx.MultiSigWitness = tc.witness(t)
			err := bc.validateTransactionAuth(tx, 1, uint64(headerTS), false)
			if err == nil {
				t.Fatal("spend must be rejected")
			}
			if !strings.Contains(err.Error(), "M-of-N custody auth failed") {
				t.Fatalf("must fail inside the custody branch, got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q must mention %q", err.Error(), tc.wantErr)
			}
			if err := bc.validateBlockTransactionAuth(custodyBlock(1, headerTS, tx), false); err == nil {
				t.Fatal("block-level tx auth must reject the same spend")
			}
		})
	}
}

// TestCustodySpendFailsClosedOnUnsetChainID pins the tripwire added in the
// cross-chain follow-up: when no chain ID was ever published, the custody path
// must refuse custody authorization outright rather than skip the check.
// Production code can never reach this branch — AddTransaction and
// validateTransactionAuth publish first — so this drives CheckSpendWitness
// directly with a published value of zero.
func TestCustodySpendFailsClosedOnUnsetChainID(t *testing.T) {
	sks, pks := escrowTestKeys(t, 3)
	p := setupVaultCustodyPolicy(t, pks, 2, "sphinx-vault-v1")
	vault, err := p.Address()
	if err != nil {
		t.Fatal(err)
	}

	headerTS := CanonicalGenesisTimestamp + 40*24*3600
	expiry := uint64(headerTS) + uint64(12*policy.CGEMonthSeconds)
	amount := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	receiver := "00000000000000000000000000000000000000AA"

	msg := multisig.SpendMessage(&p, custodySpendChainID, vault, receiver, amount, 1, expiry)
	sigs := map[int][]byte{}
	for _, i := range []int{0, 1} {
		sig, err := multisig.SignCustodyMessage(msg, sks[i], pks[i])
		if err != nil {
			t.Fatal(err)
		}
		sigs[i] = sig
	}

	prev := multisig.RequireActiveChainID(0)
	defer multisig.SetActiveChainID(prev)
	ok, err := multisig.CheckSpendWitness(
		vault, receiver, custodySpendChainID, amount, 1,
		&multisig.MultiSigWitness{Policy: p, Sigs: sigs, Expiry: expiry},
		uint64(headerTS),
	)
	if !ok {
		t.Fatal("the spend must resolve to the custody branch to trip the assertion")
	}
	if err == nil || !strings.Contains(err.Error(), "not published") {
		t.Fatalf("an unset chain ID must refuse custody authorization, got: %v", err)
	}
}

// TestCustodyBranchDoesNotAffectSingleKeyTransactions pins the fail-closed
// boundary: the custody branch is entered only when the sender resolves to a
// registered policy address.
func TestCustodyBranchDoesNotAffectSingleKeyTransactions(t *testing.T) {
	sks, pks := escrowTestKeys(t, 3)
	p := setupVaultCustodyPolicy(t, pks, 2, "sphinx-vault-v1")
	bc := &Blockchain{} // nil sphincsManager: the single-key branch reports that

	user := "00000000000000000000000000000000000000BB"
	dest := "00000000000000000000000000000000000000CC"

	// No bundle, no witness: the ordinary single-key requirement.
	plain := custodySpendTx(user, dest, big.NewInt(10), 1)
	if err := bc.validateTransactionAuth(plain, 1, 0, false); err == nil ||
		!strings.Contains(err.Error(), "missing full SPHINCS auth bundle") {
		t.Fatalf("ordinary spend must still require a bundle, got: %v", err)
	}

	// Attaching a witness to a NON-custody sender must not create a bypass: the
	// witness is ignored and the bundle is still mandatory.
	msg := multisig.SpendMessage(&p, plain.ChainID, user, dest, plain.Amount, plain.Nonce, 1)
	sig, err := multisig.SignCustodyMessage(msg, sks[0], pks[0])
	if err != nil {
		t.Fatal(err)
	}
	optIn := custodySpendTx(user, dest, big.NewInt(10), 1)
	optIn.MultiSigWitness = &multisig.MultiSigWitness{Policy: p, Sigs: map[int][]byte{0: sig}, Expiry: 1}
	if err := bc.validateTransactionAuth(optIn, 1, 0, false); err == nil ||
		!strings.Contains(err.Error(), "missing full SPHINCS auth bundle") {
		t.Fatalf("a witness on a non-custody sender must not bypass the bundle requirement, got: %v", err)
	}

	// A structurally complete bundle takes the single-key branch and reaches the
	// SPHINCS manager, proving the custody branch was not entered.
	bundled := custodySpendTx(user, dest, big.NewInt(10), 1)
	bundled.Signature = []byte{0x01}
	bundled.SignatureHash = make([]byte, 32)
	bundled.PublicKey = []byte{0x02}
	bundled.AuthTimestamp = make([]byte, 8)
	bundled.AuthNonce = make([]byte, 16)
	bundled.MerkleRootHash = make([]byte, 32)
	bundled.Commitment = make([]byte, 32)
	bundled.Proof = make([]byte, 32)
	if !bundled.HasFullAuthBundle() {
		t.Fatal("test bundle must be structurally complete")
	}
	if err := bc.validateTransactionAuth(bundled, 1, 0, false); err == nil ||
		!strings.Contains(err.Error(), "STHINCS manager is not configured") {
		t.Fatalf("single-key spend must reach the SPHINCS manager, got: %v", err)
	}
}
