// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sphinxfndorg/protocol/src/bind/abi"
)

// mintWaitResult decides whether a wait that ended without confirmation lets
// the nonce reservation go: only the node's own rejection is terminal.
func TestMintWaitResultClassifiesRejectionAndInFlight(t *testing.T) {
	rejected := &abi.TxReceipt{TxID: "tx-1", InvalidReason: "invalid nonce: 3 must equal 4"}
	terminal, message := mintWaitResult("tx-1", rejected, errors.New("transaction tx-1 failed: invalid nonce"))
	if !terminal {
		t.Fatalf("terminal = false for a rejected tx (%s)", message)
	}
	if !strings.Contains(message, "invalid nonce: 3 must equal 4") {
		t.Fatalf("message = %q, want the node's reason", message)
	}

	pending := &abi.TxReceipt{TxID: "tx-2"}
	terminal, message = mintWaitResult("tx-2", pending, errors.New("waitmined: context deadline exceeded"))
	if terminal {
		t.Fatalf("terminal = true for an unconfirmed tx (%s)", message)
	}
	if !strings.Contains(message, "still in flight") {
		t.Fatalf("message = %q, want the in-flight wording", message)
	}
	if terminal, message = mintWaitResult("tx-3", nil, errors.New("rpc: connection refused")); terminal || !strings.Contains(message, "still in flight") {
		t.Fatalf("terminal/message = %v/%q for a never-answered wait", terminal, message)
	}
	if terminal, message = mintWaitResult("tx-4", &abi.TxReceipt{TxID: "tx-4"}, nil); terminal || message != "" {
		t.Fatalf("terminal/message = %v/%q for a confirmed wait", terminal, message)
	}
}

// A disabled wait must not touch the node at all.
func TestWaitForMinedDisabledIsNoOp(t *testing.T) {
	for _, wait := range []*MintWaitOpts{nil, {Wait: false, Timeout: time.Nanosecond}} {
		receipt, err := waitForMined("127.0.0.1:1", "tx-1", wait)
		if err != nil || receipt != nil {
			t.Fatalf("waitForMined(%#v) = %#v, %v; want nil, nil", wait, receipt, err)
		}
	}
}
