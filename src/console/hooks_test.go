// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/console/hooks_test.go
package logger

import (
	"bytes"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeRenderable stands in for a dashboard component (spinner, progress bar,
// status line): it reports one line that must never reach the output once the
// live region is disabled.
type fakeRenderable struct{}

func (fakeRenderable) Lines() []string { return []string{"live-region-should-not-appear"} }

// TestSignalHandlerDisabledFlagLocksInTheDecision pins the default: the
// process-wide handler is ACTIVE unless a host explicitly disables it, so the
// CLI keeps its "restore terminal and exit(130)" behaviour.
func TestSignalHandlerDisabledFlagLocksInTheDecision(t *testing.T) {
	previous := signalHandlerDisabled.Load()
	t.Cleanup(func() { signalHandlerDisabled.Store(previous) })

	if signalHandlerDisabled.Load() {
		t.Fatal("handler must be enabled by default")
	}
	if signalHandlerDisabledNow() {
		t.Fatal("handler must be enabled by default (signalHandlerDisabledNow)")
	}

	DisableSignalHandler()

	if !signalHandlerDisabled.Load() || !signalHandlerDisabledNow() {
		t.Fatal("DisableSignalHandler must be sticky")
	}
}

// TestDisableSignalHandlerKeepsTheProcessAlive is the behavioural half of the
// hook: with the switch flipped, a real SIGINT must reach the host's own
// registration and must NOT terminate this process — the console handler would
// otherwise call os.Exit(130).
//
// If the disable path ever breaks, the test binary exits 130 here, which is
// precisely the failure this guards against (and what a GUI embedding the node
// would suffer on the first Ctrl-C).
func TestDisableSignalHandlerKeepsTheProcessAlive(t *testing.T) {
	// Note: the flag is deliberately left set (no restore). It is one-way BY
	// DESIGN (there is no public re-enable), and restoring it here would be
	// racy: although this test has already received its own copy of the signal,
	// the console handler's goroutine may not have consumed ITS queued copy yet
	// — if it woke up after a restore it would call os.Exit(130) and kill the
	// test binary. Leaving the flag set is also exactly the production state,
	// and no other test in this package sends signals.
	DisableSignalHandler()

	// Stands in for bind's own signal.Notify: the console handler must not
	// consume the signal on its behalf, and must not exit.
	host := make(chan os.Signal, 1)
	signal.Notify(host, syscall.SIGINT)
	defer signal.Stop(host)

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("kill(self, SIGINT): %v", err)
	}

	select {
	case sig := <-host:
		if sig != syscall.SIGINT {
			t.Fatalf("host handler received %v, want SIGINT", sig)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("host handler never received SIGINT — the console handler swallowed it")
	}
}

// TestSetDefaultWriterCapturesLogLines verifies the host-facing log capture:
// after rebinding, package-level log calls (the path every non-console package
// uses) land in the host's writer rather than os.Stdout.
func TestSetDefaultWriterCapturesLogLines(t *testing.T) {
	var buf bytes.Buffer
	SetDefaultWriter(&buf)
	t.Cleanup(func() { SetDefaultWriter(os.Stdout) })

	Info("host captured line %d", 42)

	if out := buf.String(); !strings.Contains(out, "host captured line 42") {
		t.Fatalf("log line did not reach the host writer, got %q", out)
	}
}

// TestSetDefaultWriterNilRestoresStdout pins the documented restore path.
func TestSetDefaultWriterNilRestoresStdout(t *testing.T) {
	var buf bytes.Buffer
	SetDefaultWriter(&buf)
	SetDefaultWriter(nil)
	t.Cleanup(func() { SetDefaultWriter(os.Stdout) })

	Info("after restore")

	if strings.Contains(buf.String(), "after restore") {
		t.Fatalf("nil must rebind to os.Stdout, but the old buffer still captured %q", buf.String())
	}
}

// TestDisableLiveRegionSuppressesTheLiveRegion proves the dashboard can be
// switched off for a host while permanent log lines keep flowing: Attach
// becomes a no-op, a forced redraw paints nothing, and Log still writes.
func TestDisableLiveRegionSuppressesTheLiveRegion(t *testing.T) {
	previous := liveRegionDisabled.Load()
	t.Cleanup(func() { liveRegionDisabled.Store(previous) })
	DisableLiveRegion()

	var buf bytes.Buffer
	r := NewRenderer(&buf)
	detach := r.Attach(fakeRenderable{}) // must be the documented no-op
	defer detach()

	r.Log("a permanent line")
	if !strings.Contains(buf.String(), "a permanent line") {
		t.Fatalf("permanent log lines must survive DisableLiveRegion, got %q", buf.String())
	}

	r.ForceRedraw()
	r.Log("another permanent line")

	if out := buf.String(); strings.Contains(out, "live-region-should-not-appear") {
		t.Fatalf("live-region content leaked into host output: %q", out)
	}
	if !strings.Contains(buf.String(), "another permanent line") {
		t.Fatalf("second log line missing, got %q", buf.String())
	}
}
