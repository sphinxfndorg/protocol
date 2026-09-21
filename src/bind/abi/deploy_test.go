// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/sphinxfndorg/protocol/src/contracts"
)

const (
	stubDeployFrom = "SPIF 5555 5555 5555 5555 5555 5555 5555 5555 5555 5555 5555 5555 5555 5555 5555 5555"
)

func deployOpts(client *stubClient, nonce uint64) *TransactOpts {
	return &TransactOpts{Client: client, Signer: &stubSigner{}, NodeAddr: stubNodeAddr, ChainID: 7331, Nonce: &nonce}
}

func sip721Spec() contracts.DeploySpec {
	return contracts.DeploySpec{Name: "Collection", Symbol: "COLL", Owner: stubDeployFrom}
}

func sip20Spec() contracts.DeploySpec {
	return contracts.DeploySpec{Name: "Token", Symbol: "TOK", Decimals: 18, InitialSupply: "1000"}
}

func hexOf(s string) string { return hex.EncodeToString([]byte(s)) }

// The handle's address is not a guess: it must equal the address the node
// derives at commit — contracts.ContractAddress(sender, nonce, code) over the
// nonce Transact actually signed, which is the nonce carried by the broadcast
// payload, not the one the caller passed in.
func TestDeploySIP721BindsTheDerivedAddress(t *testing.T) {
	client := &stubClient{txid: "tx-deploy-721"}
	contract, txid, err := DeploySIP721(deployOpts(client, 3), stubDeployFrom, sip721Spec())
	if err != nil {
		t.Fatalf("DeploySIP721: %v", err)
	}
	if txid != "tx-deploy-721" {
		t.Fatalf("txid = %q", txid)
	}
	broadcast := client.broadcast(t)
	if len(broadcast.Code) == 0 || broadcast.ToContract != "" {
		t.Fatalf("broadcast = %#v, want a code-only deploy", broadcast)
	}
	if broadcast.Nonce != 3 {
		t.Fatalf("broadcast nonce = %d, want the opts nonce 3", broadcast.Nonce)
	}
	if want := contracts.ContractAddress(broadcast.Sender, broadcast.Nonce, broadcast.Code); contract.Address != want {
		t.Fatalf("handle address = %q, want the derived %q", contract.Address, want)
	}
}

func TestDeploySIP20BindsTheDerivedAddress(t *testing.T) {
	client := &stubClient{txid: "tx-deploy-20"}
	contract, txid, err := DeploySIP20(deployOpts(client, 8), stubDeployFrom, sip20Spec())
	if err != nil {
		t.Fatalf("DeploySIP20: %v", err)
	}
	if txid != "tx-deploy-20" {
		t.Fatalf("txid = %q", txid)
	}
	broadcast := client.broadcast(t)
	if len(broadcast.Code) == 0 || broadcast.ToContract != "" {
		t.Fatalf("broadcast = %#v, want a code-only deploy", broadcast)
	}
	if want := contracts.ContractAddress(broadcast.Sender, broadcast.Nonce, broadcast.Code); contract.Address != want {
		t.Fatalf("handle address = %q, want the derived %q", contract.Address, want)
	}
	if contract.Address == "" {
		t.Fatal("handle address is empty")
	}
}

// DeploySIP20 with no sender is rejected before any RPC call, like every other
// typed entry point.
func TestDeployRequiresSenderAndValidatedOpts(t *testing.T) {
	client := &stubClient{txid: "tx-none"}
	if _, _, err := DeploySIP721(deployOpts(client, 1), "  ", sip721Spec()); err == nil {
		t.Fatal("DeploySIP721 with a blank sender = no error")
	}
	if _, _, err := DeploySIP20(&TransactOpts{Client: client, NodeAddr: stubNodeAddr}, stubDeployFrom, sip20Spec()); err == nil {
		t.Fatal("DeploySIP20 without a signer = no error")
	}
	if len(client.calls) != 0 {
		t.Fatalf("calls = %#v, want none", client.calls)
	}
}

// AndWait hands back the handle only once the node reports the deploy
// committed AND its registry answers for the derived address.
func TestDeployAndWaitReturnsTheConfirmedReceipt(t *testing.T) {
	client := &stubClient{
		txid:     "tx-deploy-wait",
		standard: SIP721,
		receipts: []string{`{"txid":"tx-deploy-wait","confirmed":true,"height":12,"blockhash":"0xfeed"}`},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	contract, receipt, err := DeploySIP721AndWait(ctx, deployOpts(client, 1), stubDeployFrom, sip721Spec(), time.Millisecond)
	if err != nil {
		t.Fatalf("DeploySIP721AndWait: %v", err)
	}
	if receipt == nil || !receipt.Confirmed || receipt.Height != 12 {
		t.Fatalf("receipt = %#v", receipt)
	}
	if contract == nil || contract.Address == "" {
		t.Fatalf("contract = %#v", contract)
	}
	methods := client.methods()
	want := []string{"sendrawtransaction", "gettransactionreceipt", "getcontract"}
	if len(methods) != len(want) {
		t.Fatalf("calls = %v, want %v", methods, want)
	}
	for i, method := range want {
		if methods[i] != method {
			t.Fatalf("calls = %v, want %v", methods, want)
		}
	}
	if queried := client.calls[2].params[0].(string); queried != contract.Address {
		t.Fatalf("getcontract queried %q, want the derived %q", queried, contract.Address)
	}
}

// A confirmed receipt only proves the transaction was included. If the node's
// registry has nothing at the derived address, AndWait must not hand the handle
// back as if the contract existed — but the receipt still goes to the caller, so
// a failed deploy is distinguishable from a lost transaction.
func TestDeployAndWaitRequiresTheRegistryToAnswer(t *testing.T) {
	for _, tc := range []struct {
		label  string
		client *stubClient
	}{
		{label: "registry errors", client: &stubClient{txid: "tx-unregistered"}},
		{label: "registry answers null", client: &stubClient{txid: "tx-unregistered", nullContract: true}},
	} {
		t.Run(tc.label, func(t *testing.T) {
			tc.client.receipts = []string{`{"txid":"tx-unregistered","confirmed":true,"height":9,"blockhash":"0xbeef"}`}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			contract, receipt, err := DeploySIP20AndWait(ctx, deployOpts(tc.client, 5), stubDeployFrom, sip20Spec(), time.Millisecond)
			if err == nil {
				t.Fatal("err = nil, want a registry mismatch error")
			}
			for _, want := range []string{"tx-unregistered", "height 9", "no contract is registered at predicted address"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %v, want it to mention %q", err, want)
				}
			}
			if contract != nil {
				t.Fatalf("contract = %#v, want nil when the registry has nothing there", contract)
			}
			if receipt == nil || !receipt.Confirmed || receipt.Height != 9 {
				t.Fatalf("receipt = %#v, want the confirmed receipt for the included tx", receipt)
			}
		})
	}
}

// A deploy the node rejects never creates the contract, so the derived address
// must not be handed back as if it existed.
func TestDeployAndWaitFailsOnRejectedDeploy(t *testing.T) {
	client := &stubClient{
		txid:     "tx-deploy-bad",
		receipts: []string{`{"txid":"tx-deploy-bad","confirmed":false,"invalid_reason":"insufficient balance for deploy fee"}`},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	contract, receipt, err := DeploySIP20AndWait(ctx, deployOpts(client, 2), stubDeployFrom, sip20Spec(), time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "insufficient balance for deploy fee") {
		t.Fatalf("err = %v, want the node's rejection reason", err)
	}
	if contract != nil {
		t.Fatalf("contract = %#v, want nil for a rejected deploy", contract)
	}
	if receipt == nil || receipt.InvalidReason == "" {
		t.Fatalf("receipt = %#v, want the rejected receipt", receipt)
	}
}

// Pinned derived addresses for the fixed inputs above (stubDeployFrom, nonce 3,
// sip721Spec / nonce 8, sip20Spec).
//
// These literals are a DRIFT DETECTOR, not proof of correctness: they were
// generated once from contracts.ContractAddress — the same function the node
// calls in contracts.Deploy — so they prove the formula has not changed under
// the binding, and that the nonce it hashes is the signed one. They cannot prove
// the formula itself is right, because both sides share it. That proof is
// DeploySIP721AndWait's registry query-back (confirmDeployed/getcontract), which
// fails if the node registers the contract anywhere but at this address.
const (
	goldenSIP721Address = "SPIF AB08 1D24 1D7F A946 B69A 31CE 476E A092 795D 7FA2 BA6E 67DA 1AAD 23FA FB50 E5AF"
	goldenSIP20Address  = "SPIF 4367 4289 438E 8058 7F84 5ECE 23EE BD88 CA15 F791 8D1A 168F F03B B270 C2DE 95BA"
)

func TestDeployDerivedAddressMatchesThePinnedFormula(t *testing.T) {
	c721, _, err := DeploySIP721(deployOpts(&stubClient{txid: "t"}, 3), stubDeployFrom, sip721Spec())
	if err != nil {
		t.Fatalf("DeploySIP721: %v", err)
	}
	if c721.Address != goldenSIP721Address {
		t.Fatalf("SIP-721 address = %q, want the pinned %q", c721.Address, goldenSIP721Address)
	}
	c20, _, err := DeploySIP20(deployOpts(&stubClient{txid: "t"}, 8), stubDeployFrom, sip20Spec())
	if err != nil {
		t.Fatalf("DeploySIP20: %v", err)
	}
	if c20.Address != goldenSIP20Address {
		t.Fatalf("SIP-20 address = %q, want the pinned %q", c20.Address, goldenSIP20Address)
	}
}

// DecodeRawTransaction must reverse EncodeRawTransaction, which is what lets a
// caller inspect its own payload or one fetched from the node.
func TestDecodeRawTransactionRoundTrip(t *testing.T) {
	original, err := NewSIP721CallTx(TxOptions{ChainID: 7331, Sender: stubDeployFrom, Nonce: 9}, stubCollection, "list",
		map[string]string{"token_id": "4", "price": "1200"})
	if err != nil {
		t.Fatalf("NewSIP721CallTx: %v", err)
	}
	encoded, err := EncodeRawTransaction(original)
	if err != nil {
		t.Fatalf("EncodeRawTransaction: %v", err)
	}

	decoded, err := DecodeRawTransaction(encoded)
	if err != nil {
		t.Fatalf("DecodeRawTransaction: %v", err)
	}
	if decoded.ID != original.ID || decoded.Sender != original.Sender || decoded.Nonce != original.Nonce ||
		decoded.ToContract != original.ToContract || decoded.Amount.String() != original.Amount.String() {
		t.Fatalf("decoded = %#v, want %#v", decoded, original)
	}
	call, err := DecodeCall(SIP721ABI, decoded.CallData)
	if err != nil || call.Method != "list" || call.Args["price"] != "1200" {
		t.Fatalf("decoded call = %#v (err %v)", call, err)
	}
	// A 0x prefix is how explorers and RPC responses render the same bytes.
	if prefixed, err := DecodeRawTransaction("0x" + encoded); err != nil || prefixed.ID != original.ID {
		t.Fatalf("prefixed decode = %#v (err %v)", prefixed, err)
	}
}

func TestDecodeRawTransactionRejectsGarbage(t *testing.T) {
	if _, err := DecodeRawTransaction("   "); err == nil || !strings.Contains(err.Error(), "empty raw transaction") {
		t.Fatalf("err = %v, want an empty-payload error", err)
	}
	if _, err := DecodeRawTransaction("zzz"); err == nil || !strings.Contains(err.Error(), "decode raw transaction hex") {
		t.Fatalf("err = %v, want a hex error", err)
	}
	if _, err := DecodeRawTransaction(hexOf("not json")); err == nil || !strings.Contains(err.Error(), "decode raw transaction") {
		t.Fatalf("err = %v, want a JSON error", err)
	}
}
