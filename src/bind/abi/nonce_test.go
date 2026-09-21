// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const stubSecondNodeAddr = "127.0.0.1:32308"

// Reserve must never hand out a nonce the account has already used on chain,
// and must advance past its own uncommitted claims — that is the whole point of
// the table (two broadcasts before the first block commits).
func TestNonceReserverClaimsSequentialNonces(t *testing.T) {
	client := &stubClient{nonce: 7}
	reserver := NewNonceReserver()

	for want := uint64(7); want <= 9; want++ {
		got, err := reserver.Reserve(client, stubNodeAddr, stubDeployFrom)
		if err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		if got != want {
			t.Fatalf("Reserve = %d, want %d", got, want)
		}
	}
	if next, ok := reserver.Peek(stubNodeAddr, stubDeployFrom); !ok || next != 10 {
		t.Fatalf("Peek = (%d, %v), want (10, true)", next, ok)
	}
	if methods := client.methods(); len(methods) != 3 {
		t.Fatalf("calls = %v, want one getnonce per claim", methods)
	}
}

// The key is (node, sender): a reservation held against one node must not leak
// into another node the same process also talks to.
func TestNonceReserverIsScopedPerNode(t *testing.T) {
	client := &stubClient{nonce: 5}
	reserver := NewNonceReserver()
	if got, _ := reserver.Reserve(client, stubNodeAddr, stubDeployFrom); got != 5 {
		t.Fatalf("first node nonce = %d, want 5", got)
	}
	if got, _ := reserver.Reserve(client, stubSecondNodeAddr, stubDeployFrom); got != 5 {
		t.Fatalf("second node nonce = %d, want the same committed 5", got)
	}
}

// Advance raises the floor for a caller that claimed a nonce through another
// path, and Release only rewinds while that claim is still the latest — it must
// never rewind past a nonce a later claim already owns.
func TestNonceReserverAdvanceAndRelease(t *testing.T) {
	client := &stubClient{nonce: 2}
	reserver := NewNonceReserver()

	reserver.Advance(stubNodeAddr, stubDeployFrom, 40)
	if got, _ := reserver.Reserve(client, stubNodeAddr, stubDeployFrom); got != 40 {
		t.Fatalf("Reserve after Advance = %d, want 40", got)
	}

	reserver.Release(stubNodeAddr, stubDeployFrom, 40)
	if next, ok := reserver.Peek(stubNodeAddr, stubDeployFrom); !ok || next != 40 {
		t.Fatalf("Peek after Release = (%d, %v), want (40, true)", next, ok)
	}

	// Two live claims: the first cannot be released out from under the second.
	first, _ := reserver.Reserve(client, stubNodeAddr, stubDeployFrom)
	second, _ := reserver.Reserve(client, stubNodeAddr, stubDeployFrom)
	if second != first+1 {
		t.Fatalf("nonces = %d, %d, want consecutive", first, second)
	}
	reserver.Release(stubNodeAddr, stubDeployFrom, first)
	if next, _ := reserver.Peek(stubNodeAddr, stubDeployFrom); next != second+1 {
		t.Fatalf("Peek = %d, want %d — Release rewound a nonce a later claim owns", next, second+1)
	}
}

func TestNonceReserverRejectsMissingInputs(t *testing.T) {
	reserver := NewNonceReserver()
	client := &stubClient{nonce: 1}
	if _, err := reserver.Reserve(nil, stubNodeAddr, stubDeployFrom); err == nil {
		t.Fatal("Reserve(nil client) = no error")
	}
	if _, err := reserver.Reserve(client, "  ", stubDeployFrom); err == nil {
		t.Fatal("Reserve(blank node) = no error")
	}
	if _, err := reserver.Reserve(client, stubNodeAddr, "   "); err == nil {
		t.Fatal("Reserve(blank sender) = no error")
	}
	if len(client.calls) != 0 {
		t.Fatalf("calls = %#v, want none", client.calls)
	}
}

// A getnonce failure must surface as an error rather than a silent nonce 0,
// which the mempool would reject as an exact-match violation.
func TestNonceReserverSurfacesGetNonceErrors(t *testing.T) {
	_, err := NewNonceReserver().Reserve(unreachableClient{}, stubNodeAddr, stubDeployFrom)
	if err == nil || !strings.Contains(err.Error(), "getnonce") {
		t.Fatalf("err = %v, want a getnonce error", err)
	}
}

// Transact must take its nonce from the Reserver when one is set: that is what
// makes two broadcasts from one account in one process sign consecutive nonces
// instead of both re-reading the committed one.
func TestTransactSignsWithTheReservedNonce(t *testing.T) {
	client := &stubClient{nonce: 4, txid: "tx-reserved"}
	opts := &TransactOpts{Client: client, Signer: &stubSigner{}, NodeAddr: stubNodeAddr, ChainID: 7331, Reserver: NewNonceReserver()}

	first, _, err := DeploySIP721(opts, stubDeployFrom, sip721Spec())
	if err != nil {
		t.Fatalf("DeploySIP721: %v", err)
	}
	if broadcast := client.broadcast(t); broadcast.Nonce != 4 {
		t.Fatalf("first broadcast nonce = %d, want the reserved 4", broadcast.Nonce)
	}
	second, _, err := DeploySIP721(opts, stubDeployFrom, sip721Spec())
	if err != nil {
		t.Fatalf("second DeploySIP721: %v", err)
	}
	if broadcast := client.broadcast(t); broadcast.Nonce != 5 {
		t.Fatalf("second broadcast nonce = %d, want the next reserved 5", broadcast.Nonce)
	}
	if first.Address == second.Address {
		t.Fatalf("both deploys derived %q — the reservation did not advance the nonce", first.Address)
	}
}

type unreachableClient struct{}

func (unreachableClient) CallRPC(string, string, interface{}, uint16) (json.RawMessage, error) {
	return nil, errors.New("node unreachable")
}

// clientRefusingBroadcast fails only sendrawtransaction, so a nonce is claimed
// and the broadcast then fails: the reservation must come back, or the account
// would skip that nonce and stall against the exact-match mempool rule.
type clientRefusingBroadcast struct{ *stubClient }

func (c clientRefusingBroadcast) CallRPC(nodeAddr, method string, params interface{}, ttlSeconds uint16) (json.RawMessage, error) {
	if method == "sendrawtransaction" {
		return nil, errors.New("stub: node refused the broadcast")
	}
	return c.stubClient.CallRPC(nodeAddr, method, params, ttlSeconds)
}

func TestTransactReleasesTheReservedNonceWhenTheBroadcastFails(t *testing.T) {
	client := clientRefusingBroadcast{&stubClient{nonce: 6, txid: "tx-never"}}
	reserver := NewNonceReserver()
	opts := &TransactOpts{Client: client, Signer: &stubSigner{}, NodeAddr: stubNodeAddr, ChainID: 7331, Reserver: reserver}

	if _, _, err := DeploySIP721(opts, stubDeployFrom, sip721Spec()); err == nil {
		t.Fatal("DeploySIP721 against a node refusing the broadcast = no error")
	}
	next, ok := reserver.Peek(stubNodeAddr, stubDeployFrom)
	if !ok || next != 6 {
		t.Fatalf("Peek after a failed broadcast = (%d, %v), want (6, true) — the reservation was not released", next, ok)
	}
	if got, err := reserver.Reserve(client, stubNodeAddr, stubDeployFrom); err != nil || got != 6 {
		t.Fatalf("re-Reserve = (%d, %v), want (6, nil) — the retry must reuse the failed nonce", got, err)
	}
}
