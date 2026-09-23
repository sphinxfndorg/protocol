// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/lifecycle_test.go
//
// Tests for the host-integration layer added by Phase 2a: the StartNode →
// StartNodeWithOptions wrapper contract, the shutdown-source selection, the
// ordered teardown, and the in-process start → stop → restart contract that the
// explicit closes exist to provide.
package bind

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sphinxfndorg/protocol/src/consensus"
	logger "github.com/sphinxfndorg/protocol/src/console"
	"github.com/sphinxfndorg/protocol/src/network"
)

// TestStartNodeForwardsZeroNodeOptions is the CLI-identical gate for the
// wrapper: StartNode must delegate to StartNodeWithOptions with the ZERO
// NodeOptions — the value for which every host-specific branch is false — and
// forward every argument verbatim.
//
// The startNodeFn seam exists solely for this test; no node is booted.
func TestStartNodeForwardsZeroNodeOptions(t *testing.T) {
	original := startNodeFn
	t.Cleanup(func() { startNodeFn = original })

	var (
		called    bool
		gotDir    string
		gotCfg    network.NodePortConfig
		gotNodes  int
		gotIndex  int
		gotVDF    *consensus.VDFParams
		gotNet    string
		gotSeeds  string
		gotReward string
		gotOpts   NodeOptions
	)
	startNodeFn = func(dataDir string, cfg network.NodePortConfig, totalNodes, nodeIndex int,
		vdfParams *consensus.VDFParams, networkType, seeds, rewardAddress string, opts NodeOptions) error {
		called = true
		gotDir, gotCfg, gotNodes, gotIndex = dataDir, cfg, totalNodes, nodeIndex
		gotVDF, gotNet, gotSeeds, gotReward, gotOpts = vdfParams, networkType, seeds, rewardAddress, opts
		return nil
	}

	cfg := network.NodePortConfig{
		TCPAddr:  "127.0.0.1:30303",
		UDPPort:  "30308",
		WSPort:   "127.0.0.1:8700",
		HTTPPort: "127.0.0.1:8545",
		Role:     network.RoleValidator,
	}
	if err := StartNode("/tmp/cli-datadir", cfg, 3, 1, nil, "devnet", "seed-a,seed-b", "SPIF sender"); err != nil {
		t.Fatalf("StartNode must not fail on the wrapper path: %v", err)
	}

	if !called {
		t.Fatal("StartNode must delegate to StartNodeWithOptions")
	}
	if gotDir != "/tmp/cli-datadir" || !reflect.DeepEqual(gotCfg, cfg) ||
		gotNodes != 3 || gotIndex != 1 || gotVDF != nil ||
		gotNet != "devnet" || gotSeeds != "seed-a,seed-b" || gotReward != "SPIF sender" {
		t.Fatalf("StartNode must forward every argument verbatim, got dir=%q cfg=%+v nodes=%d index=%d vdf=%v net=%q seeds=%q reward=%q",
			gotDir, gotCfg, gotNodes, gotIndex, gotVDF, gotNet, gotSeeds, gotReward)
	}
	if !gotOpts.isZero() {
		t.Fatalf("StartNode must pass the ZERO NodeOptions (CLI behaviour), got %+v", gotOpts)
	}
}

// TestWaitForShutdownSources pins the selection logic that keeps the CLI path
// unchanged while giving a host a programmatic stop.
func TestWaitForShutdownSources(t *testing.T) {
	t.Run("nil stop channel waits for the signal (CLI path)", func(t *testing.T) {
		sigCh := make(chan os.Signal, 1)
		go func() {
			time.Sleep(30 * time.Millisecond)
			sigCh <- syscall.SIGTERM
		}()
		if got := waitForShutdown(context.Background(), nil, sigCh); got != shutdownBySignal {
			t.Fatalf("got %q, want %q", got, shutdownBySignal)
		}
	})

	t.Run("nil stop channel alone never returns", func(t *testing.T) {
		// A nil stop channel contributes nothing to the select, so with a silent
		// signal channel and a live context this must block — exactly like the
		// old bare `<-sigCh`.
		returned := make(chan shutdownSource, 1)
		go func() {
			returned <- waitForShutdown(context.Background(), nil, make(chan os.Signal, 1))
		}()
		select {
		case got := <-returned:
			t.Fatalf("must block without a signal, returned %q", got)
		case <-time.After(200 * time.Millisecond):
		}
	})

	t.Run("host stop channel", func(t *testing.T) {
		stop := make(chan struct{})
		close(stop)
		if got := waitForShutdown(context.Background(), stop, make(chan os.Signal, 1)); got != shutdownByHost {
			t.Fatalf("got %q, want %q", got, shutdownByHost)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if got := waitForShutdown(ctx, nil, make(chan os.Signal, 1)); got != shutdownByContext {
			t.Fatalf("got %q, want %q", got, shutdownByContext)
		}
	})

	t.Run("both sources ready returns one of them", func(t *testing.T) {
		stop := make(chan struct{})
		close(stop)
		sigCh := make(chan os.Signal, 1)
		sigCh <- syscall.SIGINT
		switch got := waitForShutdown(context.Background(), stop, sigCh); got {
		case shutdownByHost, shutdownBySignal:
		default:
			t.Fatalf("got %q, want host or signal", got)
		}
	})
}

// recordingCloser records the order in which resources were closed.
type recordingCloser struct {
	name  string
	order *[]string
}

func (c recordingCloser) Close() error {
	*c.order = append(*c.order, c.name)
	return nil
}

// failingCloser always errors, to prove one bad resource cannot abort the rest
// of the teardown.
type failingCloser struct{}

func (failingCloser) Close() error { return errors.New("deliberate close failure") }

// TestNodeShutdownIsNilSafe covers the early-error path: StartNodeWithOptions
// fills the resource list incrementally, so a run with nothing filled in must be
// a no-op rather than a nil-pointer panic.
func TestNodeShutdownIsNilSafe(t *testing.T) {
	(&nodeShutdown{}).run()
}

// TestNodeShutdownOrdersFlushBeforeDatabases pins step 6 of the ordered
// teardown: node state is flushed while the databases are still open, and only
// then are they closed. Closing first would lose the flush.
func TestNodeShutdownOrdersFlushBeforeDatabases(t *testing.T) {
	var order []string
	sh := &nodeShutdown{
		wait:  &sync.WaitGroup{},
		flush: func() { order = append(order, "flush") },
		databases: []io.Closer{
			recordingCloser{"mainDatabase", &order},
			recordingCloser{"stateDatabase", &order},
		},
	}
	sh.run()

	want := []string{"flush", "mainDatabase", "stateDatabase"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("teardown order = %v, want %v", order, want)
	}
}

// TestNodeShutdownContinuesAfterACloseFailure: a failing resource must not
// prevent the release of the others — that is what makes a restart possible even
// after a messy shutdown.
func TestNodeShutdownContinuesAfterACloseFailure(t *testing.T) {
	var order []string
	sh := &nodeShutdown{
		databases: []io.Closer{failingCloser{}, recordingCloser{"after", &order}},
	}
	sh.run()

	if !reflect.DeepEqual(order, []string{"after"}) {
		t.Fatalf("a failing close must not stop the sequence, got %v", order)
	}
}

// TestNodeShutdownWaitsBeforeFlushing proves the WaitGroup join happens before
// the flush and the database closes: flushing while a loop is still running
// would persist a half-written state.
func TestNodeShutdownWaitsBeforeFlushing(t *testing.T) {
	var (
		mu              sync.Mutex
		workerFinished  bool
		flushSawWorker  bool
		closeSawWorker  bool
		release         = make(chan struct{})
		flushAndCloseOK = true
	)
	sh := &nodeShutdown{
		wait: &sync.WaitGroup{},
		flush: func() {
			mu.Lock()
			defer mu.Unlock()
			flushSawWorker = workerFinished
			if !workerFinished {
				flushAndCloseOK = false
			}
		},
		databases: []io.Closer{closerFunc(func() error {
			mu.Lock()
			defer mu.Unlock()
			closeSawWorker = workerFinished
			return nil
		})},
	}
	sh.wait.Add(1)
	go func() {
		defer sh.wait.Done()
		<-release
		mu.Lock()
		workerFinished = true
		mu.Unlock()
	}()

	// Let the teardown run; release the worker shortly after.
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(release)
	}()
	sh.run()

	mu.Lock()
	defer mu.Unlock()
	if !flushAndCloseOK || !flushSawWorker || !closeSawWorker {
		t.Fatalf("flush/database close ran before the WaitGroup drained (flush saw worker=%t, close saw worker=%t)",
			flushSawWorker, closeSawWorker)
	}
}

// closerFunc adapts a function to io.Closer for the ordering tests.
type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// TestStartStopRestartInProcess is the contract Phase 2a exists for: the node
// must be startable, stoppable via NodeOptions.Stop, and startable AGAIN in the
// same process on the SAME ports and data directory — which only works if the
// listeners, the DHT and the databases were actually released.
//
// It also measures goroutines across the two cycles: a per-start leak shows up as
// a growing resident count even when a constant library baseline remains.
func TestStartStopRestartInProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real node twice")
	}

	// The console package installs a process-wide SIGINT handler at import time
	// that calls os.Exit(130). Nothing here signals the process, but disabling it
	// keeps a stray signal from hiding the real result, and disabling the live
	// region keeps the test log readable.
	logger.DisableSignalHandler()
	logger.DisableLiveRegion()

	dir := t.TempDir()
	cfg := lifecycleNodeConfig(t)

	baseline := runtime.NumGoroutine()
	afterFirst := 0

	for cycle := 1; cycle <= 2; cycle++ {
		stop := make(chan struct{})
		done := make(chan error, 1)

		go func() {
			done <- StartNodeWithOptions(dir, cfg, 1, 0, nil, "devnet", "", "",
				NodeOptions{Stop: stop, LogWriter: io.Discard, DisableDashboard: true})
		}()

		waitForListener(t, cfg.TCPAddr, 120*time.Second, fmt.Sprintf("cycle %d: P2P listener", cycle))
		waitForListener(t, cfg.WSPort, 120*time.Second, fmt.Sprintf("cycle %d: wallet RPC listener", cycle))

		close(stop)

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("cycle %d: StartNodeWithOptions returned an error: %v", cycle, err)
			}
		case <-time.After(180 * time.Second):
			t.Fatalf("cycle %d: node did not stop after the host stop channel was closed", cycle)
		}

		// Every listener must be released immediately: re-binding the identical
		// addresses below is the proof (and why the ports can be reused at all).
		assertPortFree(t, cfg.TCPAddr, fmt.Sprintf("cycle %d: P2P", cycle))
		assertPortFree(t, cfg.WSPort, fmt.Sprintf("cycle %d: wallet RPC", cycle))
		assertPortFree(t, cfg.HTTPPort, fmt.Sprintf("cycle %d: HTTP", cycle))

		settled := settleGoroutines(t, baseline+40, 60*time.Second)
		t.Logf("cycle %d: %d goroutines resident (test baseline %d)", cycle, settled, baseline)
		if cycle == 1 {
			afterFirst = settled
			continue
		}
		if settled > afterFirst+10 {
			t.Fatalf("goroutines grew across restarts: after cycle 1 = %d, after cycle 2 = %d — a per-start leak",
				afterFirst, settled)
		}
	}
}

// lifecycleNodeConfig picks four currently-free loopback ports so the test never
// collides with a real node, and reuses the identical addresses for both cycles.
func lifecycleNodeConfig(t *testing.T) network.NodePortConfig {
	t.Helper()
	return network.NodePortConfig{
		TCPAddr:  "127.0.0.1:" + freeTCPPort(t),
		UDPPort:  freeUDPPort(t),
		WSPort:   "127.0.0.1:" + freeTCPPort(t),
		HTTPPort: "127.0.0.1:" + freeTCPPort(t),
		Role:     network.RoleValidator,
	}
}

func freeTCPPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate a free TCP port: %v", err)
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split listener address %q: %v", l.Addr(), err)
	}
	return port
}

func freeUDPPort(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate a free UDP port: %v", err)
	}
	defer c.Close()
	_, port, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		t.Fatalf("split UDP address %q: %v", c.LocalAddr(), err)
	}
	return port
}

// waitForListener blocks until addr accepts a TCP connection, i.e. until the
// node has passed the section that binds it.
func waitForListener(t *testing.T, addr string, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s at %s never became reachable within %v (last error: %v)", what, addr, timeout, lastErr)
}

// assertPortFree fails if addr is still bound, i.e. if shutdown leaked the
// listener.
func assertPortFree(t *testing.T, addr, label string) {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("%s address %s was NOT released by shutdown (still bound): %v", label, addr, err)
	}
	l.Close()
}

// settleGoroutines waits for the resident goroutine count to drop to want,
// returning the settled count. On timeout it dumps goroutine headers so the leak
// is diagnosable from the failure alone.
func settleGoroutines(t *testing.T, want int, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	got := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		got = runtime.NumGoroutine()
		if got <= want {
			return got
		}
		time.Sleep(100 * time.Millisecond)
	}
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	t.Fatalf("goroutines did not settle: %d resident, want <= %d after %v\n%s",
		got, want, timeout, firstLines(string(buf[:n]), 120))
	return got
}

// firstLines keeps a goroutine dump readable in a failure message.
func firstLines(s string, max int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > max {
		lines = lines[:max]
	}
	return strings.Join(lines, "\n")
}
