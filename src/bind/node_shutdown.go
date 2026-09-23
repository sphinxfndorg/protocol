// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/node_shutdown.go
//
// Ordered shutdown for the node started by StartNodeWithOptions. (The legacy
// same-box harness has its own Shutdown([]NodeResources) in shutdown.go —
// different path, untouched.)
//
// Before this file existed, StartNode's teardown was
// `cons.Stop(); cancelCtx(); wg.Wait(); flushNodeState()` and nothing else: the
// P2P listener was closed only from inside its own accept goroutine (which only
// notices cancellation after an Accept error, so it could linger and keep the
// port bound), and the wallet/JSON-RPC listener, the HTTP server, the DHT and
// the databases were never closed at all. A node could therefore be started
// once per process and never again.
//
// Everything here is nil-safe: StartNodeWithOptions fills the resource list as
// it creates each resource, so the same teardown is valid on early error paths.
package bind

import (
	"context"
	"io"
	"net"
	"os"
	"sync"

	"github.com/sphinxfndorg/protocol/src/consensus"
	logger "github.com/sphinxfndorg/protocol/src/console"
	"github.com/sphinxfndorg/protocol/src/dht"
	"github.com/sphinxfndorg/protocol/src/http"
	"github.com/sphinxfndorg/protocol/src/transport"
)

// shutdownSource names whichever input asked the node to stop. It is reported
// in the shutdown log line so an operator can tell a Ctrl-C from a host-driven
// stop after the fact.
type shutdownSource string

const (
	// shutdownBySignal is SIGINT/SIGTERM — the CLI's only source.
	shutdownBySignal shutdownSource = "signal"
	// shutdownByHost is NodeOptions.Stop being closed by an embedding process.
	shutdownByHost shutdownSource = "host stop request"
	// shutdownByContext is the node's own context being cancelled.
	shutdownByContext shutdownSource = "context cancellation"
)

// String keeps the log line readable.
func (s shutdownSource) String() string { return string(s) }

// waitForShutdown blocks until a shutdown is requested and reports by whom.
//
// The sources are deliberately equivalent, and a nil channel in a select simply
// never fires — so the CLI path (NodeOptions{} ⇒ stop == nil) reduces to today's
// `<-sigCh`. That is the point: the wrapper's behaviour does not change, it only
// gains alternatives.
//
// ctx is the node's lifecycle context (created in SECTION 11 from
// context.Background() today), so in practice the signal or host branch fires;
// the ctx branch exists so a future parent context can cancel a node without a
// signal.
func waitForShutdown(ctx context.Context, stop <-chan struct{}, sigCh <-chan os.Signal) shutdownSource {
	select {
	case <-stop:
		return shutdownByHost
	case <-sigCh:
		return shutdownBySignal
	case <-ctx.Done():
		return shutdownByContext
	}
}

// nodeShutdown carries every resource the ordered teardown must release. Fields
// are set by StartNodeWithOptions as each resource is created; a nil field means
// "this node never created it" and is skipped.
type nodeShutdown struct {
	consensus   *consensus.Consensus
	cancelCtx   context.CancelFunc
	p2pListener net.Listener
	walletRPC   *transport.TCPServer
	httpSrv     *http.Server
	dht         *dht.DHT
	wait        *sync.WaitGroup
	flush       func()
	databases   []io.Closer
}

// run performs the ordered teardown. The ordering is the point:
//
//  1. cancel the node context, so every loop's select observes Done();
//  2. stop the consensus engine, so no new proposals/votes/gossip are emitted
//     while the listeners are still up;
//  3. close the inbound transports (P2P listener, wallet/JSON-RPC listener,
//     HTTP server). Closing the P2P listener from HERE — rather than relying on
//     the accept goroutine to notice cancellation after an Accept error — is
//     what actually unblocks Accept and releases the port;
//  4. close the DHT (stops its workers, releases the UDP socket);
//  5. wait for the WaitGroup. Safe only now: every member's blocking I/O has
//     been unblocked by step 3;
//  6. flush node state, then close the databases so a later in-process start can
//     re-open the same paths (LevelDB holds a file lock per path; the raw
//     leveldb.DB handles opened alongside state.DB are released by their own
//     existing defers as StartNodeWithOptions returns).
//
// Steps 3-6 are exactly what make StartNodeWithOptions re-runnable in one
// process. Close failures are logged, never fatal, so one stuck resource cannot
// block the release of the others.
func (s *nodeShutdown) run() {
	if s.cancelCtx != nil {
		s.cancelCtx()
	}
	if s.consensus != nil {
		if err := s.consensus.Stop(); err != nil {
			logger.Warn("Consensus shutdown error: %v", err)
		}
	}
	if s.p2pListener != nil {
		if err := s.p2pListener.Close(); err != nil {
			// Already-closed is the normal case when the accept goroutine won
			// the race to notice a connection error first.
			logger.Debug("P2P listener close returned %v (already closed is fine)", err)
		} else {
			logger.Info("P2P listener closed")
		}
	}
	if s.walletRPC != nil {
		if err := s.walletRPC.Stop(); err != nil {
			logger.Warn("Wallet/JSON-RPC listener shutdown error: %v", err)
		}
	}
	if s.httpSrv != nil {
		if err := s.httpSrv.Stop(); err != nil {
			logger.Warn("HTTP server shutdown error: %v", err)
		}
	}
	if s.dht != nil {
		if err := s.dht.Close(); err != nil {
			logger.Warn("DHT shutdown error: %v", err)
		}
	}
	if s.wait != nil {
		s.wait.Wait()
	}
	if s.flush != nil {
		s.flush()
	}
	for _, c := range s.databases {
		if c == nil {
			continue
		}
		if err := c.Close(); err != nil {
			logger.Warn("Database close error during shutdown: %v", err)
		}
	}
}
