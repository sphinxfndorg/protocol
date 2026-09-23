// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/node_options.go
package bind

import "io"

// NodeOptions is how a host process — the src/gui desktop wallet — embeds a
// node instead of handing it a terminal.
//
// THE ZERO VALUE IS THE CLI. StartNode is nothing more than
// StartNodeWithOptions(..., NodeOptions{}), and every host-specific branch in
// StartNodeWithOptions is false for the zero value, so the wrapper path is
// byte-for-byte the behaviour the CLI has always had.
//
// Network-behaviour switches (silent-reader mode: SyncPeers, DisableInboundP2P,
// DisableDHT, DisableHTTP, DisableBlockProduction, MinPeerAgreement, …) are
// deliberately NOT here yet — they land in the silent-reader change set with
// their own tests. This type currently covers only host integration: who owns
// the shutdown decision and who owns the log stream.
type NodeOptions struct {
	// Stop requests a graceful shutdown. The host closes it from its own quit
	// path (window close, Cmd+Q) and StartNodeWithOptions then runs the ordered
	// teardown and returns. nil = wait for SIGINT/SIGTERM only, i.e. exactly
	// the CLI's behaviour.
	//
	// Only ever received from. Closing it twice, closing it after the node has
	// stopped, or closing it from any goroutine are all harmless.
	Stop <-chan struct{}

	// LogWriter receives every byte the console renderer writes — log lines and,
	// in non-TTY plain mode, the throttled dashboard snapshots. nil = the
	// process-wide default renderer, i.e. os.Stdout, i.e. the CLI.
	//
	// The renderer treats a non-*os.File writer as non-interactive, so ANSI
	// animation is off automatically: pass a bounded ring buffer and the GUI can
	// display it verbatim.
	LogWriter io.Writer

	// DisableDashboard suppresses the live terminal dashboard: no startup
	// spinner, no core-driven block animation, no live region at all (see
	// logger.DisableLiveRegion). Permanent log lines still flow to LogWriter.
	//
	// false = today's CLI dashboard.
	DisableDashboard bool
}

// isZero reports whether o asks for nothing host-specific — i.e. whether a
// StartNodeWithOptions call must behave exactly like StartNode. Used by
// lifecycle_test.go to pin the wrapper contract, and by StartNodeWithOptions to
// decide whether it may log that a host owns the node.
func (o NodeOptions) isZero() bool {
	return o.Stop == nil && o.LogWriter == nil && !o.DisableDashboard
}
