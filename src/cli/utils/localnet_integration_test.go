//go:build localnet

// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/localnet_integration_test.go
package utils

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
)

var (
	bestBlockRe = regexp.MustCompile(`Updated best block: height=(\d+), hash=([0-9a-f]+)`)
	seededRe    = regexp.MustCompile(`seeded (\d+) validators into the consensus set`)
)

// TestLocalnet_QuorumFailureAndHalt is the end-to-end proof that a localnet
// reaches real quorum.
//
// HONEST STATUS: this test currently FAILS at step 1. A four-validator localnet
// starts correctly — every node seeds the same 4-validator set, they agree on
// the genesis hash, they discover each other, and the leader broadcasts a
// proposal to its peers — but NO node ever records a prepare or commit vote, so
// the chain stays at height 0 and the leader logs "Timeout waiting for block
// commitment at height 1". The failure is in vote collection over the existing
// P2P path, not in this command: the same code commits fine when it is not
// waiting on peers.
//
// The assertions below are deliberately NOT weakened to accommodate that. They
// encode the behaviour the command is supposed to enable, so the test fails
// loudly until the engine can collect votes from a multi-process peer set.
func TestLocalnet_QuorumFailureAndHalt(t *testing.T) {
	if testing.Short() {
		t.Skip("localnet spawns real validator processes; skipped under -short")
	}

	bin := buildLocalnetBinary(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "localnet.log")

	cmd := exec.Command(bin, "localnet", "--validators=4", "--dir="+dir, "--keep")
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
	// Requires every node to have seeded the full 4-validator set AND to have
	// committed at least one block beyond genesis, with all four agreeing.
	firstHeight := waitForCondition(t, logPath, localnetBlockTimeout,
		func(text string) (uint64, bool) {
			if len(seededRe.FindAllStringSubmatch(text, -1)) < 4 {
				return 0, false
			}
			heights := allBestHeights(text)
			if len(heights) < 4 {
				return 0, false
			}
			min := heights[0]
			for _, h := range heights[1:] {
				if h < min {
					min = h
				}
			}
			if min < 1 {
				return 0, false
			}
			for _, h := range heights {
				if h != min {
					return 0, false
				}
			}
			return min, true
		})
	t.Logf("phase 1: all 4 validators committing at height %d", firstHeight)

	// ── Phase 2: kill one validator, chain must keep committing ────────────
	killLocalnetNode(t, 2)
	t.Log("phase 2: killed validator 3 of 4 (offset 2); expect progress")

	afterKill := waitForCondition(t, logPath, localnetBlockTimeout,
		func(text string) (uint64, bool) {
			heights := allBestHeights(text)
			// The three survivors (offsets 0,1,3) must all advance.
			var min uint64 = ^uint64(0)
			live := 0
			for _, h := range heights {
				if h > firstHeight {
					live++
				}
				if h < min {
					min = h
				}
			}
			if live < 3 || min <= firstHeight {
				return 0, false
			}
			return min, true
		})
	t.Logf("phase 2: chain survived one failure, height %d", afterKill)

	// ── Phase 3: kill a second validator, chain must halt ──────────────────
	killLocalnetNode(t, 3)
	t.Log("phase 3: killed validator 4 of 4 (offset 3); expect a halt")

	stale := currentHeight(t, logPath)
	time.Sleep(localnetBlockTimeout)
	if after := currentHeight(t, logPath); after > stale {
		t.Fatalf("chain advanced from height %d to %d with only 2 of 4 validators alive; "+
			"strict >2/3 quorum should have halted", stale, after)
	}
	t.Log("phase 3: chain halted as expected with 2 of 4 validators")
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
func killLocalnetNode(t *testing.T, offset int) {
	t.Helper()
	out, err := exec.Command("pgrep", "-f", fmt.Sprintf("--port-offset=%d", offset)).Output()
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

// currentHeight returns the highest height any node has reported.
func currentHeight(t *testing.T, logPath string) uint64 {
	t.Helper()
	heights := allBestHeights(readLog(t, logPath))
	var max uint64
	for _, h := range heights {
		if h > max {
			max = h
		}
	}
	return max
}

// allBestHeights returns one best height per node, in the order the nodes log.
func allBestHeights(text string) []uint64 {
	latest := map[string]uint64{}
	for _, m := range bestBlockRe.FindAllStringSubmatch(text, -1) {
		var h uint64
		fmt.Sscanf(m[1], "%d", &h)
		latest[m[2]] = h
	}
	out := make([]uint64, 0, len(latest))
	for _, h := range latest {
		out = append(out, h)
	}
	return out
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
		last = currentHeight(t, logPath)
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
