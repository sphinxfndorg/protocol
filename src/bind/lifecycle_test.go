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
	"sort"
	"strconv"
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

// lifecycleCycles is the number of start → stop passes TestStartStopRestartInProcess
// runs (F1): two cycles prove a restart works; four prove the residual set is a
// constant baseline rather than a slow leak that two cycles happen to hide.
const lifecycleCycles = 4

// TestStartStopRestartInProcess is the contract Phase 2a exists for: the node
// must be startable, stoppable via NodeOptions.Stop, and startable AGAIN in the
// same process on the SAME ports and data directory — which only works if the
// listeners, the DHT and the databases were actually released.
//
// F1 adds goroutine forensics on top of the count checks:
//   - the resident count must be CONSTANT across cycles 2..lifecycleCycles
//     (cycle 1 is the warm-up: libraries keep one-time workers that legitimately
//     survive the first stop), and
//   - after the final stop, every goroutine NOT in the pre-start baseline set is
//     dumped and grouped by its top frame; no group-(a) frame (any frame in
//     bind/consensus/network/dht/transport/core/rpc/handshake) may remain —
//     those are ours and would be a leak. Group-(b) third-party workers
//     (leveldb, gin, net/http, prometheus, …) are listed for justification.
func TestStartStopRestartInProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real node repeatedly")
	}

	// The console package installs a process-wide SIGINT handler at import time
	// that calls os.Exit(130). Nothing here signals the process, but disabling it
	// keeps a stray signal from hiding the real result, and disabling the live
	// region keeps the test log readable.
	logger.DisableSignalHandler()
	logger.DisableLiveRegion()

	dir := t.TempDir()
	cfg := lifecycleNodeConfig(t)

	baselineIDs := goroutineIDSet(t, goroutineDump(t))
	baseline := len(baselineIDs)
	settledByCycle := make([]int, 0, lifecycleCycles)

	for cycle := 1; cycle <= lifecycleCycles; cycle++ {
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
		settledByCycle = append(settledByCycle, settled)
		t.Logf("cycle %d: %d goroutines resident (pre-start baseline %d)", cycle, settled, baseline)
	}

	// Constant residual across cycles 2..N (cycle 1 may keep one-time library
	// warm-up workers; from cycle 2 on, a restart must leave the same set).
	for i := 2; i < len(settledByCycle); i++ {
		if settledByCycle[i] != settledByCycle[1] {
			t.Errorf("residual goroutines not constant: cycles 2..%d = %v",
				lifecycleCycles, settledByCycle[1:])
			break
		}
	}

	// Forensics: classify every goroutine that survived the final stop and is not
	// part of the pre-start baseline.
	report := classifyResidualGoroutines(t, baselineIDs)
	t.Logf("residual goroutine groups after cycle %d (baseline %d):\n%s",
		lifecycleCycles, baseline, report.table())

	if len(report.ours) > 0 {
		t.Errorf("group (a): %d of OUR goroutines survived shutdown — these are leaks and must be fixed or explained:\n%s",
			len(report.ours), strings.Join(report.ours, "\n"))
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

// goroutineDump returns the full all-goroutine stack dump.
func goroutineDump(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 8<<20)
	n := runtime.Stack(buf, true)
	return string(buf[:n])
}

// goroutineIDSet parses every "goroutine <id> [...]" header in a dump.
func goroutineIDSet(t *testing.T, dump string) map[uint64]struct{} {
	t.Helper()
	ids := make(map[uint64]struct{})
	for _, block := range strings.Split(dump, "\n\n") {
		if id, ok := parseGoroutineID(block); ok {
			ids[id] = struct{}{}
		}
	}
	return ids
}

// parseGoroutineID extracts the numeric id from a single goroutine's stack block.
func parseGoroutineID(block string) (uint64, bool) {
	first, _, _ := strings.Cut(block, "\n")
	if !strings.HasPrefix(first, "goroutine ") {
		return 0, false
	}
	rest := strings.TrimPrefix(first, "goroutine ")
	num, _, _ := strings.Cut(rest, " ")
	id, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

// firstLines keeps a goroutine dump readable in a failure message.
func firstLines(s string, max int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > max {
		lines = lines[:max]
	}
	return strings.Join(lines, "\n")
}

// indent prefixes every line of s with pad.
func indent(s, pad string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}

// ourFrameMarkers name the packages whose surviving goroutines are OUR leaks
// (F1 group (a)): anything under src/ that the node itself spawns.
var ourFrameMarkers = []string{
	"/src/bind",
	"/src/consensus",
	"/src/network",
	"/src/dht",
	"/src/transport",
	"/src/core",
	"/src/rpc",
	"/src/handshake",
}

// thirdPartyMarkers name libraries that keep their own background workers (F1
// group (b)): acceptable to survive, but must be listed and justified.
var thirdPartyMarkers = []string{
	"goleveldb", // sydtr: compaction goroutines owned by the DB handle
	"gin-gonic",
	"net/http", // Transport idlers persist until CloseIdleConnections
	"prometheus",
	"go.uber.org/zap",
	"gorilla/websocket",
	"libp2p",
	"hashicorp",
}

// residualReport groups surviving goroutines by classification and top frame.
type residualReport struct {
	ours        []string // group (a) — must be empty after shutdown
	thirdParty  []string // group (b) — listed with counts for justification
	testHarness []string // the running test itself + testing framework
	other       []string // runtime/stdlib one-offs, listed for completeness
}

// table renders the grouped-by-top-frame count table for the test log.
func (r residualReport) table() string {
	section := func(title string, rows []string) []string {
		out := []string{"  " + title}
		if len(rows) == 0 {
			return append(out, "    (none)")
		}
		return append(out, rows...)
	}
	lines := section("group (a) OURS (must be 0):", r.ours)
	lines = append(lines, section("group (b) third-party (justify):", r.thirdParty)...)
	lines = append(lines, section("test harness:", r.testHarness)...)
	lines = append(lines, section("other (runtime/stdlib):", r.other)...)
	return strings.Join(lines, "\n")
}

// classifyResidualGoroutines dumps every goroutine whose id is NOT in baseline
// and buckets each by its top frame:
//
//	harness     — any testing.* frame (the running test goroutine itself)
//	group (a)   — any frame in our src/ packages: a leak, test must fail
//	group (b)   — third-party worker: listed for justification
//	other       — runtime/stdlib one-offs: listed for completeness
//
// Samples keep the first full stack seen per bucket so a group-(a) failure is
// diagnosable from the test log alone.
func classifyResidualGoroutines(t *testing.T, baseline map[uint64]struct{}) residualReport {
	t.Helper()
	dump := goroutineDump(t)

	counts := map[string]int{}     // "class\ttopframe" → count
	samples := map[string]string{} // key → first full stack seen

	for _, block := range strings.Split(dump, "\n\n") {
		id, ok := parseGoroutineID(block)
		if !ok {
			continue
		}
		if _, isBaseline := baseline[id]; isBaseline {
			continue
		}
		frames := stackFrames(block)
		if len(frames) == 0 {
			continue
		}
		key := classifyStack(frames) + "\t" + frames[0]
		counts[key]++
		if _, seen := samples[key]; !seen {
			samples[key] = block
		}
	}

	var rep residualReport
	for key, n := range counts {
		class, frame, _ := strings.Cut(key, "\t")
		line := fmt.Sprintf("%3d × %s", n, frame)
		switch class {
		case "ours":
			rep.ours = append(rep.ours, line+"\n"+indent(firstLines(samples[key], 25), "      "))
		case "third-party":
			rep.thirdParty = append(rep.thirdParty, line)
		case "harness":
			rep.testHarness = append(rep.testHarness, line)
		default:
			rep.other = append(rep.other, line)
		}
	}
	sort.Strings(rep.ours)
	sort.Strings(rep.thirdParty)
	sort.Strings(rep.testHarness)
	sort.Strings(rep.other)
	return rep
}

// classifyStack buckets one goroutine's frames by the rules above.
func classifyStack(frames []string) string {
	hasOurs, hasThird, hasTesting := false, false, false
	for _, f := range frames {
		if strings.Contains(f, "testing.") {
			hasTesting = true
		}
		for _, m := range ourFrameMarkers {
			if strings.Contains(f, m) {
				hasOurs = true
			}
		}
		for _, m := range thirdPartyMarkers {
			if strings.Contains(f, m) {
				hasThird = true
			}
		}
	}
	// The test's own goroutine reaches src/bind helpers, so testing.* frames
	// take precedence over everything else.
	if hasTesting {
		return "harness"
	}
	if hasOurs {
		return "ours"
	}
	if hasThird {
		return "third-party"
	}
	return "other"
}

// stackFrames extracts the trimmed frame lines of one goroutine block, skipping
// the "goroutine N [...]" header and "created by" lines.
func stackFrames(block string) []string {
	var frames []string
	for _, ln := range strings.Split(block, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "goroutine ") {
			continue
		}
		if strings.HasPrefix(ln, "created by ") {
			continue
		}
		frames = append(frames, ln)
	}
	return frames
}
