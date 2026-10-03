// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/localnet.go
package utils

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/core"
	spxKey "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
)

// minLocalnetValidators is the smallest set that tolerates one offline
// validator. Under strict >2/3, N=3 halts when any single validator stops, so a
// smaller localnet could never exercise the failure behaviour it exists for.
const minLocalnetValidators = 4

// localnetNode is one planned validator process.
type localnetNode struct {
	index      int
	datadir    string
	tcpAddr    string
	nodeID     string
	portOffset int
	reward     string
	pubKey     string
}

// buildLocalnetNodes generates one identity keypair per validator and derives
// the addresses, datadirs and NodeIDs the processes will use.
//
// Keys are written to the same files bind.StartNode loads (network.NodeIdentityKeys
// -> common.KeysExist), so each child adopts its pre-generated identity on first
// start instead of minting a new one. That is what allows the genesis document
// to name all N public keys before any node starts.
func buildLocalnetNodes(root string, n, baseOffset int) ([]localnetNode, error) {
	nodes := make([]localnetNode, 0, n)
	for i := 0; i < n; i++ {
		offset := baseOffset + i
		datadir := filepath.Join(root, fmt.Sprintf("node-%d", i))
		tcpAddr := fmt.Sprintf("127.0.0.1:%d", 30303+offset)

		// Node storage is keyed off the global data dir plus the node
		// identifier, so point it at this node's datadir while writing its keys.
		common.SetDataDir(datadir)
		if err := common.EnsureNodeDirs(tcpAddr); err != nil {
			return nil, fmt.Errorf("prepare dirs for node-%d: %w", i, err)
		}
		pk, err := generateLocalnetIdentityKey(tcpAddr)
		if err != nil {
			return nil, fmt.Errorf("generate identity key for node-%d: %w", i, err)
		}
		nodes = append(nodes, localnetNode{
			index:      i,
			datadir:    datadir,
			tcpAddr:    tcpAddr,
			nodeID:     "Node-" + tcpAddr,
			portOffset: offset,
			reward:     localnetRewardAddress(i, offset),
			pubKey:     pk,
		})
	}
	return nodes, nil
}

// generateLocalnetIdentityKey mints a validator identity keypair and persists it
// exactly as network.generateIdentityKeysFileOnly does, so the on-disk format
// and permissions match what a node expects to load on startup.
func generateLocalnetIdentityKey(address string) (string, error) {
	km, err := spxKey.NewKeyManager()
	if err != nil {
		return "", fmt.Errorf("key manager: %w", err)
	}
	sk, pk, err := km.GenerateKey()
	if err != nil {
		return "", fmt.Errorf("generate: %w", err)
	}
	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		return "", fmt.Errorf("serialize: %w", err)
	}
	if len(skBytes) != 2*len(pkBytes) {
		return "", fmt.Errorf("size invariant violated: sk=%d pk=%d (expected sk=2*pk)", len(skBytes), len(pkBytes))
	}
	if err := common.WriteKeysToFile(address, skBytes, pkBytes); err != nil {
		return "", fmt.Errorf("persist: %w", err)
	}
	return hex.EncodeToString(pkBytes), nil
}

// localnetRewardAddress returns the genesis reward address for validator i.
//
// Genesis requires a reward address per validator but nothing requires it to be
// a key this process holds, so a deterministic per-node address is used. It is
// funded below minimum stake on purpose: validators get their weight from the
// genesis Validators section, not from an account balance.
func localnetRewardAddress(i, offset int) string {
	return fmt.Sprintf("%064x", uint64(0x10c0ffee00000000)+uint64(offset))
}

// It generates N validator identity keypairs, writes ONE genesis document that
// names all N, and starts N node processes with distinct --port-offset values.
// Unlike the hand-run devnet flow, where the first node is the only validator
// and the rest are unstaked peers, every process here is a genesis validator —
// so the network actually exercises quorum.
//
// A validator process that exits is reported and tolerated: the survivors keep
// running, which is what makes quorum loss observable rather than an instant
// teardown. The command returns only when every node has exited, or on a
// termination signal.
//
// This is a development/test tool. The genesis it writes is ordinary devnet
// genesis: membership still comes from the document, never from a flag or a
// node count, and every node derives the same set by reading the same file.
func runLocalnetCmd(args []string) error {
	fs := flag.NewFlagSet("localnet", flag.ExitOnError)
	validators := fs.Int("validators", minLocalnetValidators, "number of validator processes (minimum 4)")
	baseOffset := fs.Int("base-port-offset", 0, "port offset of the first node; node i uses base+i")
	dir := fs.String("dir", "", "directory for the per-node datadirs (default: a temp dir, removed on exit)")
	keep := fs.Bool("keep", false, "keep the data directory on exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *validators < minLocalnetValidators {
		return fmt.Errorf("--validators must be at least %d: under strict >2/3 a smaller set halts when any single validator stops, so it cannot exercise quorum failure",
			minLocalnetValidators)
	}
	if *baseOffset < 0 {
		return fmt.Errorf("--base-port-offset must not be negative")
	}

	root := *dir
	if root == "" {
		tmp, err := os.MkdirTemp("", "sphinx-localnet-")
		if err != nil {
			return fmt.Errorf("create temp dir: %w", err)
		}
		root = tmp
	} else {
		abs, err := filepath.Abs(root)
		if err != nil {
			return fmt.Errorf("resolve --dir: %w", err)
		}
		root = abs
		if err := os.MkdirAll(root, 0o700); err != nil {
			return fmt.Errorf("create --dir: %w", err)
		}
	}

	cleanup := func() {
		if !*keep && *dir == "" {
			os.RemoveAll(root)
		}
	}

	nodes, err := buildLocalnetNodes(root, *validators, *baseOffset)
	if err != nil {
		cleanup()
		return err
	}
	if err := writeLocalnetGenesis(nodes); err != nil {
		cleanup()
		return err
	}

	fmt.Printf("localnet: %d validators under %s\n", len(nodes), root)
	for _, n := range nodes {
		fmt.Printf("  %-22s %-18s offset=%d datadir=%s\n", n.nodeID, n.tcpAddr, n.portOffset, n.datadir)
	}
	fmt.Println("localnet: press Ctrl-C to stop")

	if err := superviseLocalnet(nodes); err != nil {
		cleanup()
		return err
	}
	cleanup()
	return nil
}

// superviseLocalnet starts every node as a child process, prefixes its output,
// shuts the whole set down on SIGINT/SIGTERM, and returns an error if any child
// dies on its own.
func superviseLocalnet(nodes []localnetNode) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own executable: %w", err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)

	var mu sync.Mutex
	started := make([]*exec.Cmd, 0, len(nodes))
	exited := make(chan string, len(nodes))

	stopAll := func() {
		mu.Lock()
		cmds := append([]*exec.Cmd(nil), started...)
		mu.Unlock()
		for _, c := range cmds {
			if c.Process != nil {
				_ = c.Process.Signal(syscall.SIGTERM)
			}
		}
	}

	for _, n := range nodes {
		// Node 0 authors genesis; every other node is given it as a seed so it
		// fetches the identical document instead of authoring its own.
		args := []string{
			"node",
			"--pbft",
			"--network=devnet",
			fmt.Sprintf("--port-offset=%d", n.portOffset),
			fmt.Sprintf("--datadir=%s", n.datadir),
		}
		if n.index > 0 {
			args = append(args, fmt.Sprintf("--seeds=%s", nodes[0].tcpAddr))
		}
		tag := fmt.Sprintf("%-22s| ", n.nodeID)
		cmd := exec.Command(self, args...)
		cmd.Stdout = &prefixWriter{w: os.Stdout, prefix: tag}
		cmd.Stderr = &prefixWriter{w: os.Stderr, prefix: tag}
		if err := cmd.Start(); err != nil {
			stopAll()
			return fmt.Errorf("start %s: %w", n.nodeID, err)
		}
		mu.Lock()
		started = append(started, cmd)
		mu.Unlock()

		go func(name string, c *exec.Cmd) {
			if err := c.Wait(); err != nil {
				exited <- fmt.Sprintf("%s exited: %v", name, err)
				return
			}
			exited <- fmt.Sprintf("%s exited unexpectedly", name)
		}(n.nodeID, cmd)
	}

	// A validator going down is the behaviour this command exists to exercise:
	// the network must keep committing on a minority loss, and must visibly stop
	// committing once quorum is gone. Tearing the survivors down the moment one
	// child exits would make both behaviours impossible to observe, so an
	// individual exit is reported and tolerated.
	remaining := len(started)
	for {
		select {
		case sig := <-sigs:
			fmt.Printf("\nlocalnet: %v received, stopping %d node(s)\n", sig, remaining)
			stopAll()
			drain(exited, remaining)
			return nil
		case msg := <-exited:
			remaining--
			if remaining <= 0 {
				return fmt.Errorf("localnet aborted: every node exited (last: %s)", msg)
			}
			fmt.Fprintf(os.Stderr, "\nlocalnet: %s\n", msg)
			fmt.Fprintf(os.Stderr, "localnet: %d validator(s) still running — the chain keeps "+
				"committing only while a strict >2/3 quorum of them remains\n\n", remaining)
		}
	}
}

// drain waits for n children to exit, giving up after a grace period so a stuck
// child cannot block shutdown forever.
func drain(exited <-chan string, n int) {
	for i := 0; i < n; i++ {
		select {
		case <-exited:
		case <-time.After(20 * time.Second):
			return
		}
	}
}

// prefixWriter prefixes every line with a node tag so N concurrent processes stay
// readable in one terminal.
type prefixWriter struct {
	w      *os.File
	prefix string
	mu     sync.Mutex
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	body := strings.TrimSuffix(string(b), "\n")
	if strings.TrimSpace(body) == "" {
		return len(b), nil
	}
	for _, line := range strings.Split(body, "\n") {
		fmt.Fprintf(p.w, "%s%s\n", p.prefix, line)
	}
	return len(b), nil
}

// writeLocalnetGenesis writes one genesis document naming every validator, into
// every node's datadir. All nodes read the identical document, so they derive
// the identical validator set, epoch-0 snapshot and quorum denominator.
//
// The document is produced with core.CreateGenesisForSelf for node 0 (which
// fixes the chain parameters and bootstrap flag) and then extended with the
// remaining validators through the same MutateGenesisFile writer, so the
// localnet document stays byte-compatible with a normally authored one.
func writeLocalnetGenesis(nodes []localnetNode) error {
	first := nodes[0]
	common.SetDataDir(first.datadir)

	// Node 0 must generate the devnet custody policies BEFORE the document is
	// copied out. Every joiner refuses to start when its genesis lacks the
	// multisig / escrow_multisig sections, because minting its own would be a
	// competing block 0 — this is the same material an ordinarily authored
	// devnet genesis carries.
	if _, err := core.AutoProvisionDevnetCustody(core.DevnetCustodyOptions{
		NetworkType:   "devnet",
		BootstrapNode: true,
		DataDir:       first.datadir,
	}); err != nil {
		return fmt.Errorf("provision localnet custody: %w", err)
	}

	if err := core.CreateGenesisForSelf(first.datadir, "devnet", first.nodeID, first.pubKey, first.reward, ""); err != nil {
		return fmt.Errorf("author localnet genesis: %w", err)
	}

	err := core.MutateGenesisFile(first.datadir, func(gf *core.GenesisStateFile) {
		for _, n := range nodes[1:] {
			gf.Validators = append(gf.Validators, core.GenesisStakedValidator{
				NodeID:        n.nodeID,
				PublicKey:     n.pubKey,
				StakeNSPX:     core.SelfGenesisStakeNSPX(),
				OwnerAddress:  n.reward,
				RewardAddress: n.reward,
			})
		}
		// Genesis validator documents are read sorted by NodeID; keep on-disk
		// order identical on every machine.
		sort.Slice(gf.Validators, func(i, j int) bool {
			return gf.Validators[i].NodeID < gf.Validators[j].NodeID
		})
		funded := map[string]bool{}
		for _, a := range gf.FundedAccounts {
			funded[common.CanonicalSPIFAddress(a.Address)] = true
		}
		for _, n := range nodes {
			addr := common.CanonicalSPIFAddress(n.reward)
			if funded[addr] {
				continue
			}
			funded[addr] = true
			gf.FundedAccounts = append(gf.FundedAccounts, core.GenesisFundedAccount{
				Address:     addr,
				BalanceNSPX: core.SelfGenesisStakeNSPX(),
				Label:       "localnet-stake",
			})
		}
	})
	if err != nil {
		return fmt.Errorf("extend localnet genesis validators: %w", err)
	}

	// Node 0's document is NOT copied into the other datadirs. It still gains
	// sections during startup — most importantly the block-0 witness book that
	// node 0 itself signs — so any copy taken now would be stale and the
	// joiners would refuse the peer's genesis on a document-digest mismatch.
	// Joiners start with an empty datadir and fetch the finished document over
	// the devnet bundle instead (bind.ensureDevnetBundleFromSeeds), which is the
	// same path an ordinarily-started devnet joiner uses.
	return nil
}
