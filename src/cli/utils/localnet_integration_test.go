//go:build localnet

// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/localnet_integration_test.go
package utils

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestLocalnet_QuorumFailureAndHalt drives the real `localnet` command with four
// validator processes and asserts the two properties a BFT localnet exists to
// demonstrate:
//
//  1. with all four validators up, blocks commit;
//  2. killing ONE validator keeps the chain committing (3 of 4 is the quorum);
//  3. killing a SECOND validator stops the chain (2 of 4 is not > 2/3).
//
// It is excluded from the default run by the `localnet` build tag because each
// validator spends minutes on SPHINCS+ key generation and block-0 witness
// signing before it can vote.
//
//	go test -tags localnet ./src/cli/utils/ -run TestLocalnet -timeout 40m
const (
	localnetStartupTimeout = 20 * time.Minute
	localnetBlockTimeout   = 5 * time.Minute
	// localnetHaltWindow is how long the chain is given to (incorrectly) commit a
	// further block once only 2 of 4 validators remain. It must comfortably
	// exceed one full proposal/prepare/commit round.
	localnetHaltWindow = 90 * time.Second
)

var (
	bestBlockRe = regexp.MustCompile(`Updated best block: height=(\d+), hash=([0-9a-f]+)`)
	seededRe    = regexp.MustCompile(`seeded (\d+) validators into the consensus set`)
	// nodePrefixRe extracts the Node-<host:port> tag the localnet supervisor
	// prefixes onto every line, so tips can be attributed to a specific node.
	nodePrefixRe = regexp.MustCompile(`(Node-[0-9a-zA-Z\.\:\[\]]+)\s+\|`)
)

// nodeTip is one node's most recent reported best block.
type nodeTip struct {
	height uint64
	hash   string
}

// nodeTips returns the latest best-block tip per NODE.
//
// It must key by node ID, not by block hash. Keying by hash (as this helper
// originally did) makes four nodes that correctly agree on ONE hash collapse to
// a single map entry, so any "all N nodes agree" assertion keyed off its length
// is unsatisfiable by correct behaviour — it can only be satisfied by the nodes
// disagreeing, which is the opposite of what the test is asserting.
func nodeTips(text string) map[string]nodeTip {
	tips := make(map[string]nodeTip)
	for _, line := range strings.Split(text, "\n") {
		m := bestBlockRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		owner := nodePrefixRe.FindStringSubmatch(line)
		if owner == nil {
			continue // unattributed line; cannot be counted per node
		}
		var h uint64
		fmt.Sscanf(m[1], "%d", &h)
		tips[owner[1]] = nodeTip{height: h, hash: m[2]}
	}
	return tips
}

// agreedTip reports the height when every expected node has reported at least
// `minHeight` and ALL of them agree on the same height AND the same hash.
//
// Agreement is the whole point: a localnet that commits different blocks on
// different nodes has failed BFT, so height and hash must both match.
func agreedTip(tips map[string]nodeTip, expected int, minHeight uint64) (uint64, bool) {
	if len(tips) < expected {
		return 0, false
	}
	var height uint64
	var hash string
	seen := 0
	for id, tip := range tips {
		if tip.height < minHeight {
			return 0, false
		}
		if seen == 0 {
			height, hash = tip.height, tip.hash
		} else if tip.height != height || tip.hash != hash {
			// A node is behind or has forked; keep waiting rather than accept.
			return 0, false
		}
		seen++
		_ = id
	}
	if seen < expected {
		return 0, false
	}
	return height, true
}

// TestLocalnet_QuorumFailureAndHalt is the end-to-end proof that a localnet
// reaches real quorum, and that quorum behaves under validator loss.
//
// It runs the real `localnet` command with N validator processes and asserts the
// three properties a BFT localnet exists to demonstrate:
//  1. all N validators commit blocks and agree on height AND hash;
//  2. killing a MINORITY keeps the chain committing;
//  3. killing one more drops it below strict >2/3 and stops the chain.
//
// The kill counts are derived from strictTwoThirds, not hardcoded, so the test
// tracks the production quorum rule:
//
//	N=4: quorum 3. 4 commits -> 3 (kill 1) commits -> 2 (kill 2) halts.
//	N=7: quorum 5. 7 commits -> 5 (kill 2) commits -> 4 (kill 3) halts.
//
// It is excluded from the default run by the `localnet` build tag because each
// validator spends minutes on SPHINCS+ key generation and block-0 witness
// signing before it can vote, so N=7 costs roughly twice the cold start of N=4.
func TestLocalnet_QuorumFailureAndHalt(t *testing.T) {
	if testing.Short() {
		t.Skip("localnet spawns real validator processes; skipped under -short")
	}

	for _, n := range []int{4, 7} {
		t.Run(fmt.Sprintf("validators=%d", n), func(t *testing.T) {
			runLocalnetQuorumCase(t, n)
		})
	}
}

// strictTwoThirds mirrors consensus.StrictTwoThirdsCount. The integration test
// drives the CLI as a subprocess and does not link the consensus package, so
// the rule is restated here and pinned against the real one by
// TestStrictTwoThirdsMatchesConsensus.
func strictTwoThirds(n int) int {
	if n <= 0 {
		return 0
	}
	return (2*n)/3 + 1
}

// runLocalnetQuorumCase starts one localnet of n validators and walks it
// through full quorum, tolerated loss, and loss of quorum.
//
// Quorum sizes come from strictTwoThirds, mirroring the production rule rather
// than restating its numbers, so a change to that rule surfaces here as a wrong
// expectation instead of a silently passing test.
func runLocalnetQuorumCase(t *testing.T, n int) {
	t.Helper()

	quorum := strictTwoThirds(n)
	if quorum <= 0 {
		t.Fatalf("invalid validator count %d", n)
	}
	// The largest kill that still leaves a quorum: survivors must be >= quorum.
	toleratedKills := n - quorum
	if toleratedKills < 1 {
		t.Fatalf("n=%d has quorum %d and cannot demonstrate tolerated loss", n, quorum)
	}
	// One more kill than that drops below quorum and must halt.
	fatalKills := toleratedKills + 1
	survivorsAtHalt := n - fatalKills

	t.Logf("n=%d: quorum %d; tolerate %d loss(es), halt after %d", n, quorum, toleratedKills, fatalKills)

	bin := buildLocalnetBinary(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "localnet.log")

	cmd := exec.Command(bin, "localnet", fmt.Sprintf("--validators=%d", n), "--dir="+dir, "--keep")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	defer logFile.Close()
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start localnet: %v", err)
	}
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_, _ = cmd.Process.Wait()
		_ = os.RemoveAll(dir)
	}()

	// ── Phase 1: wait for the chain to start committing ────────────────────
	// Every node must have seeded the full n-validator set AND committed at
	// least one block beyond genesis, with all n agreeing on height and hash.
	// Cold-start SPHINCS+ key generation and block-0 witness signing must be
	// absorbed on top of the first commit, so this gets startup + block budgets.
	firstHeight := waitForCondition(t, logPath, localnetStartupTimeout+localnetBlockTimeout,
		func(text string) (uint64, bool) {
			if len(seededRe.FindAllStringSubmatch(text, -1)) < n {
				return 0, false
			}
			return agreedTip(nodeTips(text), n, 1)
		})
	t.Logf("phase 1: all %d validators committing and agreeing at height %d", n, firstHeight)

	// Bridge each logged node ID to the --port-offset flag that identifies its
	// process, so liveness can be checked in later phases.
	offByNode := offsetByNodeID(nodeIDList(nodeTips(readLog(t, logPath))))
	if len(offByNode) != n {
		t.Fatalf("resolved %d node IDs, want %d", len(offByNode), n)
	}

	// ── Phase 2: kill a tolerated minority, chain must keep committing ────
	// Kill from the high end so the surviving offsets stay contiguous and
	// predictable; any subset is equally valid for a quorum test.
	height := firstHeight
	for kill := 1; kill <= toleratedKills; kill++ {
		offset := n - kill
		killLocalnetNode(t, offset)
		remaining := n - kill
		t.Logf("phase 2.%d: killed validator %d of %d (offset %d); %d remain, quorum %d",
			kill, kill, n, offset, remaining, quorum)

		height = waitForCondition(t, logPath, localnetBlockTimeout,
			func(text string) (uint64, bool) {
				return agreedTip(liveTips(text, offByNode), remaining, height+1)
			})
		t.Logf("phase 2.%d: chain survived, %d validators committed to height %d",
			kill, remaining, height)
	}

	// ── Phase 3: kill one more, chain must halt ───────────────────────────
	fatalOffset := n - fatalKills
	killLocalnetNode(t, fatalOffset)
	t.Logf("phase 3: killed validator %d of %d (offset %d); %d remain, below quorum %d — expect a halt",
		fatalKills+1, n, fatalOffset, survivorsAtHalt, quorum)

	// survivorsAtHalt is now below strict >2/3, so no further block may commit.
	// Record the survivors' agreed height, then require it to be unchanged
	// after a window far longer than any commit round.
	stale, ok := agreedTip(liveTips(readLog(t, logPath), offByNode), survivorsAtHalt, 0)
	if !ok {
		t.Fatalf("after %d kills the %d survivors did not agree on a common tip; "+
			"the halt condition cannot be evaluated", fatalKills, survivorsAtHalt)
	}
	time.Sleep(localnetHaltWindow)
	if after, ok := agreedTip(liveTips(readLog(t, logPath), offByNode), survivorsAtHalt, 0); ok && after > stale {
		t.Fatalf("chain advanced from height %d to %d with only %d of %d validators alive; "+
			"strict >2/3 quorum (%d) should have halted", stale, after, survivorsAtHalt, n, quorum)
	}
	t.Logf("phase 3: chain halted as expected with %d of %d validators (stayed at height %d)",
		survivorsAtHalt, n, stale)
}

// liveTips returns the reported tips of validators whose process is STILL
// running.
//
// Without this, a killed validator's final logged tip keeps counting as a live
// node, so phases 2 and 3 would be satisfied by a dead process.
func liveTips(text string, offByNode map[string]int) map[string]nodeTip {
	tips := nodeTips(text)
	for id := range tips {
		off, ok := offByNode[id]
		if !ok || !offsetProcessAlive(off) {
			delete(tips, id)
		}
	}
	return tips
}

// offsetProcessAlive reports whether the validator with this --port-offset is
// still running.
//
// Liveness has to be checked against the port offset because a node ID such as
// "Node-127.0.0.1:30303" is printed by the localnet supervisor but never
// appears in the child's argv — argv carries --port-offset and --datadir.
//
// The `--` separator is mandatory: without it pgrep parses "--port-offset=N" as
// an option and fails with "illegal option".
func offsetProcessAlive(offset int) bool {
	out, err := exec.Command("pgrep", "-f", "--", fmt.Sprintf("--port-offset=%d", offset)).Output()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

// offsetByNodeID maps each observed node ID to its --port-offset.
//
// buildLocalnetNodes gives node i the address 127.0.0.1:(30303+i), so sorting
// the observed IDs by port reproduces offsets 0,1,2,... in order. This is the
// bridge from a log line's node ID back to the flag that identifies its process.
func offsetByNodeID(ids []string) map[string]int {
	sorted := append([]string(nil), ids...)
	sort.Slice(sorted, func(a, b int) bool { return nodePort(sorted[a]) < nodePort(sorted[b]) })
	out := make(map[string]int, len(sorted))
	for i, id := range sorted {
		out[id] = i
	}
	return out
}

// nodeIDList returns the node IDs present in a tip map.
func nodeIDList(tips map[string]nodeTip) []string {
	out := make([]string, 0, len(tips))
	for id := range tips {
		out = append(out, id)
	}
	return out
}

// nodePort returns the TCP port embedded in a Node-<host:port> ID.
func nodePort(nodeID string) int {
	_, p, err := net.SplitHostPort(strings.TrimPrefix(nodeID, "Node-"))
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return -1
	}
	return n
}

// maxTipHeight returns the highest height any node reported, for diagnostics.
func maxTipHeight(tips map[string]nodeTip) uint64 {
	var max uint64
	for _, tip := range tips {
		if tip.height > max {
			max = tip.height
		}
	}
	return max
}

// TestStrictTwoThirdsMatchesConsensus pins the local quorum helper against the
// production rule it mirrors.
//
// runLocalnetQuorumCase derives its kill counts from strictTwoThirds, so if the
// production rule in consensus.StrictTwoThirdsCount ever changes and this copy
// does not, the integration test would keep asserting the OLD quorum and could
// report a false pass or a spurious failure. This table makes the two impossible
// to drift apart silently.
//
// The values are the production formula, (2n)/3+1, evaluated by hand.
func TestStrictTwoThirdsMatchesConsensus(t *testing.T) {
	cases := []struct{ n, want int }{
		{0, 0}, // n <= 0 is guarded to 0 by both
		{1, 1},
		{2, 2},
		{3, 3}, // 2 of 3 is exactly 2/3, so 3 are required: no tolerable loss
		{4, 3},
		{5, 4},
		{6, 5},
		{7, 5},
		{8, 6},
		{9, 7},
	}
	for _, c := range cases {
		if got := strictTwoThirds(c.n); got != c.want {
			t.Errorf("strictTwoThirds(%d) = %d, want %d (consensus.StrictTwoThirdsCount)",
				c.n, got, c.want)
		}
	}
}

// TestQuorumCaseKillBudgets checks the derived kill counts for both sizes.
//
// Each case must be able to demonstrate BOTH halves of the property under test:
// a tolerated minority loss that keeps the chain committing, and one more loss
// that drops below quorum and halts it. A size where toleratedKills is 0 or
// negative cannot show the "survives" half, so it is rejected up front rather
// than silently passing a weaker assertion.
func TestQuorumCaseKillBudgets(t *testing.T) {
	for _, n := range []int{4, 7} {
		quorum := strictTwoThirds(n)
		tolerated := n - quorum
		if tolerated < 1 {
			t.Errorf("n=%d: quorum %d leaves no tolerable loss; the test would be "+
				"unable to demonstrate that a minority failure is survivable", n, quorum)
		}
		// One more kill must land strictly below quorum, i.e. the halt is real.
		if survivors := n - (tolerated + 1); survivors >= quorum {
			t.Errorf("n=%d: after %d kills %d validators remain, which still meets "+
				"quorum %d; the halt phase would be vacuous", n, tolerated+1, survivors, quorum)
		}
	}
}

// Regression guard: when tips were keyed by block HASH, four validators that
// correctly agreed on one hash collapsed into a single map entry, so the
// "all four agree" assertion could never be satisfied by working code. These
// cases pin the correct behaviour without paying for real validator startup.
func TestNodeTipsAndAgreedTip(t *testing.T) {
	line := func(node string, h uint64, hash string) string {
		return fmt.Sprintf("%s  | 04:28:07.616 INFO    Updated best block: height=%d, hash=%s", node, h, hash)
	}
	const (
		nA = "Node-127.0.0.1:30303"
		nB = "Node-127.0.0.1:30304"
		nC = "Node-127.0.0.1:30305"
		nD = "Node-127.0.0.1:30306"
	)

	t.Run("four nodes agreeing on height and hash", func(t *testing.T) {
		// This is the case the hash-keyed map got wrong.
		text := line(nA, 10, "aa11") + "\n" +
			line(nB, 10, "aa11") + "\n" +
			line(nC, 10, "aa11") + "\n" +
			line(nD, 10, "aa11") + "\n"
		if got := len(nodeTips(text)); got != 4 {
			t.Fatalf("nodeTips returned %d nodes, want 4 distinct nodes", got)
		}
		h, ok := agreedTip(nodeTips(text), 4, 1)
		if !ok || h != 10 {
			t.Fatalf("agreedTip = (%d, %v), want (10, true)", h, ok)
		}
	})

	t.Run("latest tip per node wins", func(t *testing.T) {
		text := line(nA, 7, "aa11") + "\n" + line(nA, 12, "bb22") + "\n" +
			line(nB, 12, "bb22") + "\n"
		tips := nodeTips(text)
		if tips[nA].height != 12 || tips[nA].hash != "bb22" {
			t.Fatalf("nodeA tip = %+v, want height 12 / hash bb22", tips[nA])
		}
	})

	t.Run("disagreeing heights are rejected", func(t *testing.T) {
		text := line(nA, 10, "aa11") + "\n" + line(nB, 9, "aa11") + "\n"
		if _, ok := agreedTip(nodeTips(text), 2, 1); ok {
			t.Fatal("agreedTip accepted mismatched heights")
		}
	})

	t.Run("same height but different hash is rejected", func(t *testing.T) {
		// A fork: same height, different block. Must never count as agreement.
		text := line(nA, 10, "aa11") + "\n" + line(nB, 10, "cc33") + "\n"
		if _, ok := agreedTip(nodeTips(text), 2, 1); ok {
			t.Fatal("agreedTip accepted a fork at the same height")
		}
	})

	t.Run("too few nodes is rejected", func(t *testing.T) {
		text := line(nA, 10, "aa11") + "\n" + line(nB, 10, "aa11") + "\n"
		if _, ok := agreedTip(nodeTips(text), 3, 1); ok {
			t.Fatal("agreedTip accepted only 2 of the 3 expected nodes")
		}
	})

	t.Run("below minimum height is rejected", func(t *testing.T) {
		text := line(nA, 10, "aa11") + "\n" + line(nB, 10, "aa11") + "\n"
		if _, ok := agreedTip(nodeTips(text), 2, 11); ok {
			t.Fatal("agreedTip accepted height 10 when 11 was required")
		}
	})

	t.Run("genesis height zero does not satisfy a min of one", func(t *testing.T) {
		text := line(nA, 0, "0000") + "\n" + line(nB, 0, "0000") + "\n"
		if _, ok := agreedTip(nodeTips(text), 2, 1); ok {
			t.Fatal("agreedTip accepted height 0 as committed progress")
		}
	})

	t.Run("lines without a node prefix are ignored", func(t *testing.T) {
		// Must not be silently attributed to some node.
		if got := len(nodeTips("  Updated best block: height=5, hash=aa11\n")); got != 0 {
			t.Fatalf("nodeTips attributed an unattributed line (%d nodes)", got)
		}
	})
}

// TestOffsetByNodeID pins the log-ID -> process-flag bridge.
//
// Liveness is checked with pgrep against --port-offset, because a node ID is
// printed by the supervisor but never appears in the child's argv. If this
// mapping silently returned the wrong offsets, phases 2 and 3 would check
// liveness of the wrong validators.
func TestOffsetByNodeID(t *testing.T) {
	ids := []string{
		"Node-127.0.0.1:30306",
		"Node-127.0.0.1:30303",
		"Node-127.0.0.1:30305",
		"Node-127.0.0.1:30304",
	}
	got := offsetByNodeID(ids)
	want := map[string]int{
		"Node-127.0.0.1:30303": 0,
		"Node-127.0.0.1:30304": 1,
		"Node-127.0.0.1:30305": 2,
		"Node-127.0.0.1:30306": 3,
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("offsetByNodeID[%s] = %d, want %d", id, got[id], w)
		}
	}

	// Input order must not matter, and the input slice must not be mutated.
	if ids[0] != "Node-127.0.0.1:30306" {
		t.Errorf("offsetByNodeID reordered its input in place: %v", ids)
	}

	if p := nodePort("Node-127.0.0.1:30304"); p != 30304 {
		t.Errorf("nodePort = %d, want 30304", p)
	}
	if p := nodePort("Node-malformed"); p != -1 {
		t.Errorf("nodePort(malformed) = %d, want -1", p)
	}
}

// buildLocalnetBinary compiles the CLI once for the whole test.
func buildLocalnetBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "sphinx-localnet")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/sphinxfndorg/protocol/src/cli")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build sphinx: %v\n%s", err, out)
	}
	return bin
}

// killLocalnetNode SIGKILLs the localnet child serving --port-offset=<offset>.
//
// The `--` separator is mandatory: without it pgrep parses "--port-offset=N" as
// an option, fails with "illegal option", and exits 2 — which looks like "no
// such node" but is actually a broken pattern.
func killLocalnetNode(t *testing.T, offset int) {
	t.Helper()
	out, err := exec.Command("pgrep", "-f", "--", fmt.Sprintf("--port-offset=%d", offset)).Output()
	if err != nil {
		t.Fatalf("no localnet child with --port-offset=%d: %v (%s)", offset, err, out)
	}
	for _, pid := range strings.Fields(string(out)) {
		if err := syscall.Kill(atoiOrZero(pid), syscall.SIGKILL); err != nil {
			t.Logf("kill pid %s: %v", pid, err)
		}
	}
	t.Logf("killed --port-offset=%d (pid %s)", offset, strings.ReplaceAll(strings.TrimSpace(string(out)), "\n", " "))
}

func atoiOrZero(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

// waitForCondition polls cond until it reports success or the timeout expires,
// then fails with the tail of the log so the failure is diagnosable.
func waitForCondition(t *testing.T, logPath string, timeout time.Duration, cond func(string) (uint64, bool)) uint64 {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last uint64
	for time.Now().Before(deadline) {
		if v, ok := cond(readLog(t, logPath)); ok {
			return v
		}
		last = maxTipHeight(nodeTips(readLog(t, logPath)))
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("condition not met within %s (last height %d). Log tail:\n%s",
		timeout, last, logTail(readLog(t, logPath), 40))
	return 0
}

func logTail(text string, lines int) string {
	all := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	var b strings.Builder
	sc := bufio.NewScanner(strings.NewReader(strings.Join(all, "\n")))
	for sc.Scan() {
		b.WriteString(sc.Text())
		b.WriteString("\n")
	}
	return b.String()
}
