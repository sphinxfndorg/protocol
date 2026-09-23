// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/helper_test.go
package gui

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestFormatGUIErrorLogLineMirrorsPopupMessageVerbatim locks in the contract
// behind "every GUI error also lands on the terminal": the terminal line must
// carry the SAME message the pop-up shows, neither truncated nor reworded —
// otherwise support cannot diff a user's report against the log.
//
// The one intentional difference is the "[USI-GUI][ERROR]" tag: it lets the
// popup lines be grepped out of a terminal session that also carries node
// output, RPC round-trips, and the [USI-GUI] startup beacons.
func TestFormatGUIErrorLogLineMirrorsPopupMessageVerbatim(t *testing.T) {
	// Nil is inert — showErrorDialog returns before logging, so the
	// formatter must produce nothing to log.
	if got := formatGUIErrorLogLine(nil); got != "" {
		t.Fatalf("nil error must format to empty, got %q", got)
	}

	msg := "please enter a recipient address"
	line := formatGUIErrorLogLine(errors.New(msg))
	if !strings.HasPrefix(line, "[USI-GUI][ERROR] ") {
		t.Fatalf("terminal line must carry the greppable tag, got %q", line)
	}
	if !strings.HasSuffix(line, msg) {
		t.Fatalf("terminal line must end with the popup message verbatim, got %q", line)
	}

	// Wrapped errors keep the whole chain — an RPC error whose cause lives
	// three wraps deep is useless if only the outer layer is printed.
	inner := fmt.Errorf("handshake: %w", fmt.Errorf("dial 127.0.0.1:8700: %w", errors.New("connection refused")))
	line = formatGUIErrorLogLine(fmt.Errorf("gettransaction rpc: %w", inner))
	for _, want := range []string{"gettransaction rpc", "handshake", "connection refused"} {
		if !strings.Contains(line, want) {
			t.Fatalf("terminal line must preserve the full error chain, missing %q in %q", want, line)
		}
	}
}

// TestFormatGUIErrorLogLineNeverTruncates guards the reason the popup and the
// terminal are allowed to differ in shape but not in content: the popup
// wraps into a fixed-size scroll area, while the terminal has no width to
// protect — so long unbroken strings (tx hashes, CIDs, node payloads) must
// reach the log whole.
func TestFormatGUIErrorLogLineNeverTruncates(t *testing.T) {
	longMsg := "deploy tx " + strings.Repeat("ab12", 64) + " was REJECTED by the node and can never confirm: invalid nonce: 5 must equal 2"
	line := formatGUIErrorLogLine(errors.New(longMsg))
	if !strings.Contains(line, longMsg) {
		t.Fatalf("terminal line must carry the full message, got %q", line)
	}
	if strings.Contains(line, "…") || strings.Contains(line, "...") {
		t.Fatalf("terminal line must not elide anything, got %q", line)
	}

	// Multiline messages (fmt.Errorf with \n) survive intact too.
	multi := "vault was encrypted, but peer delivery failed: dial tcp\ncaused by: connection reset"
	if got := formatGUIErrorLogLine(errors.New(multi)); !strings.Contains(got, multi) {
		t.Fatalf("multiline errors must survive intact, got %q", got)
	}
}
