// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"encoding/json"
	"fmt"
	"testing"
)

// stubNonceRPC answers getnonce with a fixed committed value, modelling a
// chain whose account nonce never moves (every broadcast from it was rejected
// before it could commit — the exact situation behind the reported
// "invalid nonce: 5 must equal 2" deploy failure).
type stubNonceRPC struct{ nonce uint64 }

func (s stubNonceRPC) CallRPC(nodeAddr, method string, params interface{}, ttlSeconds uint16) (json.RawMessage, error) {
	if method != "getnonce" {
		return nil, fmt.Errorf("stub: unexpected method %s", method)
	}
	return json.RawMessage(fmt.Sprintf("%d", s.nonce)), nil
}

// TestReleaseRejectedNonceGivesTheReservationBack locks in the fix for the
// nonce drift: a transaction that the node TERMINALLY rejected never consumes
// its nonce on chain, so its process-local reservation must be rewound —
// otherwise every retry permanently pushes the wallet's next nonce above the
// chain's, which the exact-match mempool rule surfaces on the NEXT unrelated
// broadcast (the deploy) as "invalid nonce: 5 must equal 2".
//
// Non-terminal states (still in flight, committed, unaskable) must NOT rewind:
// an in-flight transaction still owns its nonce.
func TestReleaseRejectedNonceGivesTheReservationBack(t *testing.T) {
	// Distinct node/sender key so this test never touches another test's
	// entries in the process-wide Nonces table.
	const node = "127.0.0.1:39911"
	const sender = "NONCERELEASETESTSENDER0000000000000000000000000000000000"
	client := stubNonceRPC{nonce: 5}

	first, err := Nonces.Reserve(client, node, sender)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if first != 5 {
		t.Fatalf("first reservation = %d, want the chain nonce 5", first)
	}
	if next, ok := Nonces.Peek(node, sender); !ok || next != 6 {
		t.Fatalf("Peek after first claim = (%d, %v), want (6, true)", next, ok)
	}

	// A non-rejection state must leave the claim alone: the tx may still be
	// about to commit, and rewinding would hand its nonce to a second tx.
	for _, state := range []string{
		"uncommitted (broadcast=1 validating=0 pending=0 invalid=0 total=1)",
		"committed at height 42",
		"", // node could not be asked
	} {
		if releaseRejectedNonce(node, sender, first, state) {
			t.Fatalf("state %q must NOT release the reservation (tx not proven rejected)", state)
		}
		if next, ok := Nonces.Peek(node, sender); !ok || next != 6 {
			t.Fatalf("Peek after non-rejection %q = (%d, %v), want (6, true)", state, next, ok)
		}
	}

	// The exact rejection the reported bug produced — a mempool-invalid gas
	// failure — must rewind so the retry re-uses nonce 5 instead of claiming
	// 6, 7, … forever.
	rejected := "node rejected it: contract gas validation failed: gas limit 60925 below required 68475"
	if !releaseRejectedNonce(node, sender, first, rejected) {
		t.Fatalf("state %q must release the reservation", rejected)
	}
	if next, ok := Nonces.Peek(node, sender); !ok || next != 5 {
		t.Fatalf("Peek after rejection = (%d, %v), want the reservation rewound to (5, true)", next, ok)
	}

	again, err := Nonces.Reserve(client, node, sender)
	if err != nil {
		t.Fatalf("re-Reserve: %v", err)
	}
	if again != 5 {
		t.Fatalf("retry reservation = %d, want 5 — the rejected nonce must be reusable, not skipped", again)
	}
}
