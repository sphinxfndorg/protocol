// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/genesis.go
//
// `genesis create` — the DEVNET helper that authors the genesis file.
//
// This tool is the ONLY place that knows the number of validators K. The node
// never learns K from anywhere: it reads the file this tool writes (from its
// own <datadir>/config/, or over the devnet bundle path) and derives its
// validator set from it.
//
// What it writes, for each of the K validators:
//   - <root>/node<i>/config/genesis_state.json  the SAME genesis document for
//     every node (chain params, validators, funded accounts; the multisig and
//     witnesses sections are merged in later by devnet custody provisioning)
//   - <root>/node<i>/Node-<tcp-addr>/keys  that node's identity keypair, so the
//     Node-<addr> ID the node derives from --tcp-addr always exists
//
// It also generates and funds K + M devnet staking keys under
// <root>/custody/devnet-rewards/, so a validator added later can send a Stake
// transaction from a funded reward address.
package utils

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"strings"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/core"
	spxKey "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	"github.com/sphinxfndorg/protocol/src/network"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
	usiKey "github.com/sphinxfndorg/protocol/src/usi/core/key"
)

// runGenesisCmd dispatches the "genesis" subcommand family.
func runGenesisCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("genesis requires a subcommand: create")
	}
	switch args[0] {
	case "create":
		return runGenesisCreate(args[1:])
	default:
		return fmt.Errorf("unknown genesis subcommand %q", args[0])
	}
}

// devnetRewardKeyFile is the on-disk shape of a devnet staking key. It matches
// the format the custody signers read ({"private_key", "public_key"} as hex),
// so an operator can feed it straight to a future Stake transaction command.
type devnetRewardKeyFile struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// flagWasSet reports whether name was explicitly given on the command line.
// flag.FlagSet.Visit only walks the flags that were actually set, which is how we
// tell "the operator chose a number" from "we are about to use the zero value".
func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// promptValidatorCount is gone: `genesis create` no longer asks. Omitting
// --validators uses the BFT floor, so the common case is a bare command.

func runGenesisCreate(args []string) error {
	fs := flag.NewFlagSet("genesis create", flag.ContinueOnError)
	k := fs.Int("validators", 0, "number of genesis validators; omit for the BFT floor (consensus.MinValidators). Pass a larger value to tolerate offline validators")
	m := fs.Int("funded-accounts", 0, "extra devnet reward addresses to fund with stake-sized balances, so validators added later can send Stake txs")
	root := fs.String("root", "data", "root directory holding node<N> datadirs for the validators")
	host := fs.String("host", "127.0.0.1", "host used to derive each node's Node-<host:port> identity")
	tcpBase := fs.Int("tcp-base", 30303, "P2P TCP port of the first validator (validator i gets tcp-base+i)")
	stakeSPX := fs.Int64("stake-spx", int64(denom.MinValidatorStakeSPX), "initial stake per validator, in whole SPX")
	epochBlocks := fs.Uint64("epoch-blocks", core.DevnetEpochBlocks, "EpochBlocks chain parameter written into the genesis file")
	networkName := fs.String("network", "devnet", "network label written into the genesis file")
	chainID := fs.Uint64("chain-id", core.DevnetChainID, "chain id written into the genesis file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// The validator count is required input to this authoring step — a document
	// listing validators has to be told how many to list. When it is omitted we
	// use the BFT floor (consensus.MinValidators), so the common case — "open
	// three terminals and run" — needs no number, no flag and no prompt at all.
	//
	// The floor is a floor, not a verdict on how many you SHOULD run: it is the
	// smallest set that can produce blocks at all, and it has NO fault
	// tolerance — under strict >2/3 stake, a 3-validator set needs all 3 to vote
	// (2 of 3 is exactly 2/3, not strictly more). Anyone who wants to survive
	// an offline validator passes a larger number explicitly, and that choice
	// is theirs, never inferred.
	//
	// Either way the count lives here and nowhere else: it is written into the
	// document and from then on is just data. No node flag carries it, and no
	// node derives it from a peer count.
	if !flagWasSet(fs, "validators") {
		*k = consensus.MinValidators
	}

	if *k < consensus.MinValidators {
		return fmt.Errorf("--validators=%d is below the BFT minimum (consensus.MinValidators=%d): a genesis file listing fewer can never be safe",
			*k, consensus.MinValidators)
	}
	if *m < 0 {
		return fmt.Errorf("--funded-accounts must not be negative")
	}
	if *stakeSPX < int64(denom.MinValidatorStakeSPX) {
		return fmt.Errorf("--stake-spx=%d is below the minimum validator stake (%d SPX)", *stakeSPX, denom.MinValidatorStakeSPX)
	}
	if *tcpBase <= 0 || *tcpBase+*k-1 > 65535 {
		return fmt.Errorf("--tcp-base %d with %d validators does not fit in the port range", *tcpBase, *k)
	}
	if *epochBlocks == 0 {
		return fmt.Errorf("--epoch-blocks must be positive")
	}

	stakeNSPX := new(big.Int).Mul(big.NewInt(*stakeSPX), big.NewInt(denom.SPX))
	stakeStr := stakeNSPX.String()

	gf := &core.GenesisStateFile{
		Version: 2,
		Chain: core.GenesisChainParams{
			ChainID:      *chainID,
			Network:      *networkName,
			EpochBlocks:  *epochBlocks,
			MinStakeNSPX: stakeStr,
		},
	}

	// Identity keys must be written relative to the NODE's own datadir, which
	// is what --datadir sets at run time. SetDataDir is process-global; restore
	// it on the way out so an embedded caller is unaffected.
	prevDataDir := common.GetDataDir()
	defer common.SetDataDir(prevDataDir)

	rewardKeys, err := prepareRewardKeyWriter(*root)
	if err != nil {
		return err
	}

	plans := make([]nodePlan, 0, *k)

	for i := 0; i < *k; i++ {
		tcpAddr := fmt.Sprintf("%s:%d", *host, *tcpBase+i)
		nodeID := "Node-" + tcpAddr
		nodeDir := filepath.Join(*root, fmt.Sprintf("node%d", i))
		if err := os.MkdirAll(nodeDir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", nodeDir, err)
		}

		common.SetDataDir(nodeDir)
		if err := common.EnsureNodeDirs(tcpAddr); err != nil {
			return fmt.Errorf("node %d dirs: %w", i, err)
		}
		_, pk, _, err := network.NodeIdentityKeys(nil, tcpAddr)
		if err != nil {
			return fmt.Errorf("node %d identity keys (%s): %w", i, tcpAddr, err)
		}

		rewardAddr, err := rewardKeys.writeOrLoad(i, "validator")
		if err != nil {
			return err
		}

		gf.Validators = append(gf.Validators, core.GenesisStakedValidator{
			NodeID:        nodeID,
			PublicKey:     hex.EncodeToString(pk),
			StakeNSPX:     stakeStr,
			RewardAddress: rewardAddr,
		})
		gf.FundedAccounts = append(gf.FundedAccounts, core.GenesisFundedAccount{
			Address:     rewardAddr,
			BalanceNSPX: stakeStr,
			Label:       "genesis-validator-stake",
		})
		plans = append(plans, nodePlan{index: i, nodeID: nodeID, tcpAddr: tcpAddr, datadir: nodeDir})
	}

	for j := 0; j < *m; j++ {
		rewardAddr, err := rewardKeys.writeOrLoad(*k+j, "funded")
		if err != nil {
			return err
		}
		gf.FundedAccounts = append(gf.FundedAccounts, core.GenesisFundedAccount{
			Address:     rewardAddr,
			BalanceNSPX: stakeStr,
			Label:       "devnet-funded-stake",
		})
	}

	// Every node reads the IDENTICAL file; write it into each node's own
	// config/ directory (the same per-node layout the devnet bundle uses).
	//
	// The node ID is derived from --tcp-addr ALONE. --port-offset only shifts a
	// node's own default listen/RPC ports, so it can never change the identity
	// this file already recorded — and the guard below fails loudly rather than
	// silently rewriting an identity a running chain is already signed against.
	for _, p := range plans {
		if err := assertExistingIdentityUnchanged(p, gf); err != nil {
			return err
		}
		if err := core.WriteGenesisFile(p.datadir, gf); err != nil {
			return fmt.Errorf("write genesis file for %s: %w", p.nodeID, err)
		}
	}

	stakeWholeSPX := new(big.Int).Div(new(big.Int).Set(stakeNSPX), big.NewInt(denom.SPX))
	fmt.Printf("genesis file written for %d validator(s); epoch_blocks=%d chain_id=%d network=%s\n",
		*k, *epochBlocks, *chainID, *networkName)
	fmt.Printf("stake per validator: %s SPX (minimum %d SPX)\n", stakeWholeSPX.String(), denom.MinValidatorStakeSPX)
	fmt.Println()
	fmt.Printf("%-4s %-28s %-24s %s\n", "#", "node id", "datadir", "genesis file")
	for _, p := range plans {
		fmt.Printf("%-4d %-28s %-24s %s\n", p.index, p.nodeID, p.datadir, core.GenesisStateFilePathForDataDir(p.datadir))
	}
	fmt.Println()
	fmt.Printf("funded devnet staking keys: %d genesis validator(s) + %d spare(s), in %s\n", *k, *m, rewardKeys.dir)
	fmt.Println()
	fmt.Printf("Next: open %d terminals, one per validator, and run in each:\n\n", *k)
	fmt.Printf("  terminal 1:  ./sphinx node --role=validator --tcp-addr %s --http-port 127.0.0.1:8545 --datadir %s --pbft\n",
		plans[0].tcpAddr, plans[0].datadir)
	for _, p := range plans[1:] {
		fmt.Printf("  terminal %d:  ./sphinx node --role=validator --port-offset=%d --seeds=%s --pbft\n",
			p.index+1, p.index, plans[0].tcpAddr)
	}
	fmt.Println()
	// ★ FAULT-TOLERANCE TABLE, derived from the one rule that decides it:
	// strict `voted*3 > total*2` with equal stakes. K validators at stake s
	// need a strict majority of 2/3, so the number that must vote is
	// floor(2K/3)+1 — NOT "two thirds of K", which for K=3 is 2 and fails.
	fmt.Printf("Fault tolerance for a set of %d validators at %d SPX each (strict >2/3 stake):\n", *k, denom.MinValidatorStakeSPX)
	fmt.Printf("  votes needed to commit a block: %d of %d\n", offlineTolerantVotes(*k), *k)
	fmt.Printf("  offline validators tolerated:   %d\n", (*k-1)/3)
	if *k < 4 {
		fmt.Printf("\n  ⚠ A set of %d has NO fault tolerance: if any ONE validator stops, the chain halts.\n", *k)
		fmt.Printf("    The smallest set that survives one offline validator is 4 (3 of 4 still clear 2/3).\n")
	} else {
		fmt.Printf("\n  This set continues with up to %d validator(s) offline.\n", (*k-1)/3)
	}
	return nil
}

// offlineTolerantVotes is how many validators must vote for a block to commit
// under the strict `voted*3 > total*2` rule, for a set of K equal-stake
// validators. It is floor(2K/3)+1.
//
//	 K=1 -> 1        K=2 -> 2        K=3 -> 3        K=4 -> 3
//	 K=5 -> 4        K=6 -> 5        K=7 -> 5
//
// K=3 needing all 3 is the counter-intuitive case: 2 of 3 is exactly 2/3, and
// the rule is STRICTLY more than 2/3, so 2 of 3 does not commit.
func offlineTolerantVotes(k int) int {
	if k <= 0 {
		return 0
	}
	return (2*k)/3 + 1
}

// nodePlan is one validator's identity and datadir, derived purely from --tcp-addr.
type nodePlan struct {
	index   int
	nodeID  string
	tcpAddr string
	datadir string
}

// assertExistingIdentityUnchanged re-reads any genesis document already present in
// p's datadir and refuses to overwrite it when this run would change an identity
// the document already binds.
//
// Rationale: a node ID is the consensus-layer identity of a validator and is
// derived from --tcp-addr ALONE. --port-offset is deliberately NOT an input here —
// it only shifts a node's own default listen/RPC ports and its datadir — so it can
// never rename a validator. Two things must therefore hold on a re-run:
//
//  1. every node ID the document already binds is still in the plan (a rewrite that
//     drops an existing validator would silently shrink or fork the set); and
//  2. any node ID common to both keeps its public key.
//
// Failing loudly is the only safe response: a chain that is already running has
// signed blocks for these identities, and an operator who really does want a new
// set can delete the old document deliberately.
func assertExistingIdentityUnchanged(p nodePlan, gf *core.GenesisStateFile) error {
	existing, err := core.LoadGenesisFile(p.datadir)
	if err != nil {
		return fmt.Errorf("read existing genesis document for %s: %w", p.nodeID, err)
	}
	if existing == nil || len(existing.Validators) == 0 {
		return nil // nothing written yet: nothing to contradict
	}
	planned := make(map[string]string, len(gf.Validators))
	for _, v := range gf.Validators {
		planned[v.NodeID] = normalizeHexKey(v.PublicKey)
	}
	for _, v := range existing.Validators {
		got, kept := planned[v.NodeID]
		if !kept {
			return fmt.Errorf("refusing to rewrite %s: it already binds validator %s, but this run does not include it (it would rename or drop a validator identity). A node ID comes from --tcp-addr alone and --port-offset does not affect it. Re-run with the same --host/--tcp-base, or delete the old document deliberately.",
				core.GenesisStateFilePathForDataDir(p.datadir), v.NodeID)
		}
		if v.PublicKey != "" && got != normalizeHexKey(v.PublicKey) {
			return fmt.Errorf("refusing to rewrite %s: it already binds %s to public key %s, but this run derives %s. A node ID comes from --tcp-addr alone and --port-offset does not affect it. Re-run with the same --host/--tcp-base, or delete the old document deliberately.",
				core.GenesisStateFilePathForDataDir(p.datadir), v.NodeID, v.PublicKey, got)
		}
	}
	return nil
}

// normalizeHexKey strips an optional 0x/0X prefix and lowercases, so two
// spellings of the same key compare equal.
func normalizeHexKey(s string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"))
}

// devnetRewardKeyWriter owns the <root>/custody/devnet-rewards directory and
// the load-or-create logic for its key files. Re-running `genesis create` must
// yield the SAME addresses, so an existing key file is loaded, never replaced.
type devnetRewardKeyWriter struct {
	dir string
	km  *spxKey.KeyManager
}

func prepareRewardKeyWriter(root string) (*devnetRewardKeyWriter, error) {
	dir := filepath.Join(root, "custody", "devnet-rewards")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create reward key dir %s: %w", dir, err)
	}
	km, err := spxKey.NewKeyManager()
	if err != nil {
		return nil, fmt.Errorf("key manager: %w", err)
	}
	return &devnetRewardKeyWriter{dir: dir, km: km}, nil
}

// writeOrLoad returns the canonical SPIF address for one devnet staking key,
// generating and persisting it on first use.
func (w *devnetRewardKeyWriter) writeOrLoad(index int, kind string) (string, error) {
	path := filepath.Join(w.dir, fmt.Sprintf("%s-%d.key.json", kind, index))
	if rec, err := readRewardKeyFile(path); err == nil {
		return addressForKey(rec.PublicKey)
	}

	sk, pk, err := w.km.GenerateKey()
	if err != nil {
		return "", fmt.Errorf("generate %s reward key %d: %w", kind, index, err)
	}
	skBytes, pkBytes, err := w.km.SerializeKeyPair(sk, pk)
	if err != nil {
		return "", fmt.Errorf("serialize %s reward key %d: %w", kind, index, err)
	}
	body, err := json.MarshalIndent(devnetRewardKeyFile{
		PrivateKey: hex.EncodeToString(skBytes),
		PublicKey:  hex.EncodeToString(pkBytes),
	}, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return addressForKey(hex.EncodeToString(pkBytes))
}

func readRewardKeyFile(path string) (devnetRewardKeyFile, error) {
	var rec devnetRewardKeyFile
	data, err := os.ReadFile(path)
	if err != nil {
		return rec, err
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return rec, err
	}
	if strings.TrimSpace(rec.PublicKey) == "" {
		return rec, fmt.Errorf("%s holds no public_key", path)
	}
	return rec, nil
}

// addressForKey renders a public key as the canonical raw-hex SPIF address
// (the form state keys and the node's balance lookups use).
func addressForKey(publicKeyHex string) (string, error) {
	pkBytes, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(publicKeyHex, "0x"), "0X"))
	if err != nil {
		return "", fmt.Errorf("bad public key hex: %w", err)
	}
	formatted := usiKey.GetPublicKeyFingerprintFromBytes(pkBytes, usiKey.OrgSPIF)
	canonical := common.CanonicalSPIFAddress(formatted)
	if !common.ValidateSPIFAddress(canonical) {
		return "", fmt.Errorf("derived address %q is not a valid SPIF address", formatted)
	}
	return canonical, nil
}
