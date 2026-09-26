// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/multisig_spend.go
//
// Live M-of-N custody flows: `multisig devnet` provisions a local policy plus
// its custodian keys, and `multisig spend` builds, signs, broadcasts and
// verifies a real custody spend against a running node.
//
// ★ WHY THIS EXISTS: create/message/sign/combine build and sign custody
// payloads, but nothing submitted one to a node — so an operator could not
// tell whether the node's admission path (pool.verifyTransactionSignature,
// rpc.sendRawTransaction, core.validateTransactionAuth) accepted a witness or
// silently fell back to single-key auth. These two commands close that loop:
// the witness is produced with the SAME policy file the node auto-loads
// (config/escrow_multisig.json or config/genesis_multisig.json), so a passing
// run proves signer and verifier agree byte-for-byte.
package utils

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/sphinxfndorg/protocol/src/bind/abi"
	logger "github.com/sphinxfndorg/protocol/src/console"
	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
	"github.com/sphinxfndorg/protocol/src/rpc"
)

// defaultCustodyValidity is the witness horizon the live spend signs with. It
// is deliberately inside musig's [24h, 5y] window: long enough that a spend
// broadcast today still validates against the sealed header of the block that
// finally includes it, short enough that a leaked custodian key cannot
// authorize releases years from now.
const defaultCustodyValidity = 30 * 24 * time.Hour

// defaultCustodyWatchInterval is the `multisig spend --watch` poll period:
// fast enough to react within a block or two of the custodial address being
// funded, slow enough that a watcher left running all day does not hammer the
// node with getbalance.
const defaultCustodyWatchInterval = 10 * time.Second

// custodyRoles maps a custody role to the node-side loader it must agree with.
// The escrow domain is not cosmetic: core.escrowMultisigDomain is the string
// bound into every CGE release message, and the vault domain separates the
// genesis vault's spend namespace from the escrow's.
var custodyRoles = map[string]struct {
	Domain   string
	OutPath  string
	KeysDir  string
	Label    string
	AutoLoad string
}{
	"escrow": {
		Domain:   "sphinx-escrow-v1",
		OutPath:  "config/escrow_multisig.json",
		KeysDir:  "data/custody/escrow",
		Label:    "CGE escrow",
		AutoLoad: "core.InitEscrowAddress",
	},
	"vault": {
		Domain:   "sphinx-vault-v1",
		OutPath:  "config/genesis_multisig.json",
		KeysDir:  "data/custody/vault",
		Label:    "genesis vault",
		AutoLoad: "core.InitGenesisVaultAddress",
	},
}

// runMultisigDevnet provisions a complete local custody set: N SPHINCS+
// custodian key files plus the policy JSON that both the node and the CLI
// resolve the custodial address from.
//
//	multisig devnet --role escrow --custodians 3 --threshold 2
//
// Writes:
//
//	config/escrow_multisig.json              policy (public keys only — shareable)
//	data/custody/escrow/custodian-<i>.json   secret keys (chmod 0600)
//
// The policy file must exist BEFORE the nodes start: the address it derives
// replaces policy.CGEEscrowAddress in block 0, so every node's genesis funding
// must be built from the same policy.
func runMultisigDevnet(args []string) error {
	fs := flag.NewFlagSet("multisig devnet", flag.ContinueOnError)
	role := fs.String("role", "escrow", "custody role: escrow | vault (selects the domain and the default paths)")
	domain := fs.String("domain", "", "override the domain separation string")
	out := fs.String("out", "", "policy output path (default: the role's auto-loaded config path)")
	keysDir := fs.String("keys-dir", "", "custodian key output directory (default: the role's data dir)")
	custodians := fs.Int("custodians", 3, "number of custodian keys to generate (N)")
	threshold := fs.Int("threshold", 2, "signatures required to authorize a spend (M)")
	force := fs.Bool("force", false, "overwrite an existing key directory (destroys the current custodians)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	spec, ok := custodyRoles[strings.ToLower(*role)]
	if !ok {
		return fmt.Errorf("unknown --role %q: expected escrow or vault", *role)
	}
	if *threshold < 1 || *threshold > *custodians {
		return fmt.Errorf("--threshold must be between 1 and --custodians (%d)", *custodians)
	}
	if *domain == "" {
		*domain = spec.Domain
	}
	if *out == "" {
		*out = spec.OutPath
	}
	if *keysDir == "" {
		*keysDir = spec.KeysDir
	}

	if entries, err := os.ReadDir(*keysDir); err == nil && len(entries) > 0 && !*force {
		return fmt.Errorf("%s already holds %d entries: pass --force to replace the custodian set", *keysDir, len(entries))
	}
	if err := os.MkdirAll(*keysDir, 0700); err != nil {
		return fmt.Errorf("create keys dir: %w", err)
	}

	km, err := key.NewKeyManager()
	if err != nil {
		return fmt.Errorf("key manager: %w", err)
	}

	p := &multisig.MultiPartyPolicy{Threshold: uint8(*threshold), Domain: *domain}
	for i := 0; i < *custodians; i++ {
		sk, pk, err := km.GenerateKey()
		if err != nil {
			return fmt.Errorf("custodian %d keygen: %w", i, err)
		}
		skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
		if err != nil {
			return fmt.Errorf("custodian %d serialize: %w", i, err)
		}
		p.PubKeys = append(p.PubKeys, pkBytes)

		record, err := json.MarshalIndent(map[string]string{
			"private_key": hex.EncodeToString(skBytes),
			"public_key":  hex.EncodeToString(pkBytes),
		}, "", "  ")
		if err != nil {
			return err
		}
		keyPath := filepath.Join(*keysDir, fmt.Sprintf("custodian-%d.json", i))
		if err := os.WriteFile(keyPath, append(record, '\n'), 0600); err != nil {
			return fmt.Errorf("write %s: %w", keyPath, err)
		}
		logger.Info("custodian %d key written: %s", i, keyPath)
	}

	if err := p.Validate(); err != nil {
		return err
	}
	addr, err := p.Address()
	if err != nil {
		return err
	}
	if dir := filepath.Dir(*out); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create policy dir: %w", err)
		}
	}
	if err := p.Save(*out); err != nil {
		return fmt.Errorf("write policy: %w", err)
	}

	fmt.Printf("role=%s label=%s\naddress=%s\nthreshold=%d-of-%d domain=%s\npolicy=%s\nkeys=%s\n",
		strings.ToLower(*role), spec.Label, addr, *threshold, *custodians, *domain, *out, *keysDir)
	fmt.Printf("The node auto-loads this policy via %s at process start;\n"+
		"start (or restart) every node AFTER writing it so all nodes derive the same address.\n", spec.AutoLoad)
	return nil
}

// runMultisigSpend is the live path: it fetches the custodial account's nonce
// from the node, builds the canonical spend message, signs it with the
// supplied custodian keys, assembles the transaction, broadcasts it through
// the node's own sendrawtransaction, waits for it to be confirmed in a block,
// and (optionally) prints the recipient's confirmed balance from every node in
// the network so cross-node agreement is observable, not assumed.
//
// --watch turns the same command into a loop: every --interval it re-reads
// the custodial balance and, when that balance covers --amount, runs one
// complete sign/broadcast cycle with a freshly fetched nonce and a freshly
// minted witness expiry. An accepted-but-unconfirmed transaction is tracked
// by txid and blocks further cycles until its receipt resolves, so the loop
// can never double-spend; SIGINT/SIGTERM stops it after the current cycle.
// With --dry-run, --watch only prints the balance (monitor mode) and never
// signs or broadcasts.
//
//	multisig spend --policy config/escrow_multisig.json \
//	    --to <recipient> --amount-spx 1000 \
//	    --keys-dir data/custody/escrow \
//	    --rpc 127.0.0.1:8700 --verify-rpc 127.0.0.1:8701
//
//	multisig spend --policy config/escrow_multisig.json \
//	    --to <recipient> --amount-spx 1000 \
//	    --keys-dir data/custody/escrow \
//	    --rpc 127.0.0.1:8700 --watch --interval 10s
func runMultisigSpend(args []string) error {
	fs := flag.NewFlagSet("multisig spend", flag.ContinueOnError)
	var keys stringSliceFlag
	var verifyRPCs stringSliceFlag
	policyPath := fs.String("policy", "", "policy JSON file the custodial address derives from (required)")
	from := fs.String("from", "", "custodial source address (default: the policy's derived address)")
	to := fs.String("to", "", "destination address (required)")
	amountSPX := fs.String("amount-spx", "", "amount in whole SPX (decimal)")
	amountNSPX := fs.String("amount-nspx", "", "exact amount in nSPX (decimal)")
	rpcAddr := fs.String("rpc", "127.0.0.1:8700", "node JSON-RPC host:port used to fetch the nonce and broadcast")
	chainID := fs.Uint64("chain-id", defaultCustodyChainID, "chain id bound into the signed message")
	nonce := fs.Uint64("nonce", 0, "account nonce (0 = fetch the live nonce from --rpc)")
	expiry := fs.Uint64("expiry", 0, "witness expiry as a unix timestamp (0 = now + --validity)")
	validity := fs.Duration("validity", defaultCustodyValidity, "how long the witness stays valid when --expiry is not given")
	gasLimit := fs.Uint64("gas-limit", 0, "gas limit (0 = the policy's transaction quote)")
	gasPrice := fs.Uint64("gas-price", 0, "gas price in nSPX per gas (0 = the policy minimum)")
	keysDir := fs.String("keys-dir", "", "directory of custodian-*.json key files to sign with")
	proposalsDir := fs.String("proposals-dir", custodyProposalsDir, "(self-directed --watch only: --watch with no --to/--amount) directory of threshold-signed custody transaction *.json files to broadcast")
	out := fs.String("out", "", "write the assembled transaction JSON here")
	dryRun := fs.Bool("dry-run", false, "build, sign and print the transaction without broadcasting it")
	allowPartial := fs.Bool("allow-partial", false, "broadcast even when fewer than M signatures were collected (negative test: the network must reject it)")
	wait := fs.Bool("wait", true, "wait until the transaction is confirmed in a block")
	timeout := fs.Int("timeout", 180, "seconds to wait for confirmation")
	watch := fs.Bool("watch", false, "keep polling the custodial balance and spend --amount every time the balance covers it (stops on SIGINT/SIGTERM; with --dry-run it only prints the balance)")
	interval := fs.Duration("interval", defaultCustodyWatchInterval, "poll period between cycles when --watch is set")
	fs.Var(&keys, "key", "custodian key file to sign with (repeatable)")
	fs.Var(&verifyRPCs, "verify-rpc", "node JSON-RPC host:port to print the recipient's confirmed balance from (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	keys = append(keys, fs.Args()...)
	// Self-directed mode: `--watch` with neither --to nor an amount means the
	// node was never told what to spend. Instead of building a brand-new spend
	// from a balance trigger (which would need a destination and amount), the
	// loop broadcasts threshold-signed proposals from --proposals-dir. Those
	// carry their own destination/amount/nonce inside the signed payload, so
	// nothing differs between nodes. See autoWatchArgs / custodyProposalsDir.
	if *watch && *to == "" && *amountNSPX == "" && *amountSPX == "" {
		return runSelfDirectedCustodyWatch(selfDirectedWatchState{
			policyPath:   *policyPath,
			proposalsDir: *proposalsDir,
			rpcAddr:      *rpcAddr,
			chainID:      *chainID,
			interval:     *interval,
			dryRun:       *dryRun,
			timeout:      *timeout,
			verifyRPCs:   verifyRPCs,
		})
	}
	if *policyPath == "" || *to == "" {
		return fmt.Errorf("--policy and --to are required (with --watch, omit --to and both amount flags to run the self-directed proposal watcher)")
	}
	amount, err := parseAmount(*amountNSPX, *amountSPX)
	if err != nil {
		return err
	}
	if amount == nil || amount.Sign() <= 0 {
		return fmt.Errorf("--amount-spx or --amount-nspx is required and must be positive")
	}
	if *interval <= 0 {
		return fmt.Errorf("--interval must be positive, got %s", *interval)
	}
	if *watch {
		if *nonce != 0 {
			return fmt.Errorf("--nonce cannot be combined with --watch: each watch cycle fetches the live nonce so consecutive spends cannot reuse one")
		}
		if *allowPartial {
			return fmt.Errorf("--allow-partial is a negative-test flag and cannot be combined with --watch: it would rebroadcast a below-threshold spend every interval")
		}
	}

	p, err := multisig.LoadPolicy(*policyPath)
	if err != nil {
		return err
	}
	sender := *from
	if sender == "" {
		if sender, err = p.Address(); err != nil {
			return err
		}
	}

	now := time.Now()
	exp := *expiry
	if exp == 0 {
		exp = uint64(now.Add(*validity).Unix())
	}
	// The same horizon check the node applies against a sealed block header;
	// doing it here turns "unspendable too soon / replay window too wide" at
	// admission into an immediate local error.
	if err := multisig.ValidateWitnessExpiry(exp, uint64(now.Unix())); err != nil {
		return err
	}

	keyFiles, err := custodyKeyFiles(*keysDir, keys)
	if err != nil {
		return err
	}
	if len(keyFiles) == 0 {
		return fmt.Errorf("no custodian keys: pass --keys-dir or one or more --key files")
	}

	// One sign+broadcast cycle, shared by the one-shot path and every --watch
	// iteration: same message bytes, same threshold guard, same broadcast.
	// It returns the txid the node accepted (empty when the transaction never
	// reached the network, e.g. a dry run) so the watch loop can track an
	// unconfirmed spend instead of building the next one.
	signAndBroadcast := func(n, exp uint64, ts int64) (string, error) {
		msg := multisig.SpendMessage(p, *chainID, sender, *to, amount, n, exp)
		sigs, err := signCustodyWitness(p, msg, keyFiles)
		if err != nil {
			return "", err
		}
		if len(sigs) < int(p.Threshold) && !*allowPartial {
			return "", fmt.Errorf("collected %d valid signature(s), threshold is %d: supply more custodian keys, or use --allow-partial to prove the network rejects it",
				len(sigs), p.Threshold)
		}
		return broadcastCustodySpend(spendParams{
			policy: p, sender: sender, to: *to, amount: amount, nonce: n,
			expiry: exp, chainID: *chainID, msg: msg, sigs: sigs,
			gasLimit: *gasLimit, gasPrice: *gasPrice, timestamp: ts,
			rpcAddr: *rpcAddr, verifyRPCs: verifyRPCs, out: *out,
			dryRun: *dryRun, wait: *wait, timeout: *timeout,
		})
	}

	if *watch {
		return runWatchedCustodySpend(watchSpendState{
			sender: sender, amount: amount, rpcAddr: *rpcAddr,
			expiry: *expiry, validity: *validity, interval: *interval,
			dryRun: *dryRun, wait: *wait, timeout: *timeout,
			signAndBroadcast: signAndBroadcast,
		})
	}

	n := *nonce
	if n == 0 {
		raw, err := rpc.CallRPC(*rpcAddr, "getnonce", []interface{}{sender}, 30)
		if err != nil {
			return fmt.Errorf("getnonce from %s: %w", *rpcAddr, err)
		}
		if err := json.Unmarshal(raw, &n); err != nil {
			return fmt.Errorf("parse getnonce response: %w", err)
		}
	}
	_, err = signAndBroadcast(n, exp, now.Unix())
	return err
}

// watchSpendState carries everything one `multisig spend --watch` cycle needs
// that the shared signAndBroadcast closure does not already capture: the
// balance gate, the pacing, and the per-cycle witness horizon.
type watchSpendState struct {
	sender           string
	amount           *big.Int
	rpcAddr          string
	expiry           uint64 // explicit --expiry (0 = mint a fresh horizon each cycle)
	validity         time.Duration
	interval         time.Duration
	dryRun           bool
	wait             bool
	timeout          int
	signAndBroadcast func(n, exp uint64, ts int64) (string, error)
}

// runWatchedCustodySpend implements the --watch loop. Each cycle:
//
//  1. resolves any transaction the previous cycle left unconfirmed — while one
//     is outstanding no new spend is built, so the loop can never double-spend;
//  2. reads the custodial balance (a failed read is transient: logged, retried
//     next interval, never fatal);
//  3. with --dry-run, prints the balance and stops there (monitor mode);
//  4. otherwise spends --amount when the balance covers it, with a freshly
//     fetched nonce and a freshly minted witness expiry.
//
// SIGINT/SIGTERM stops the loop after the current cycle. A cycle error that
// happens BEFORE the node accepts a transaction (signing, threshold, nonce,
// broadcast refusal) is fatal — retrying it automatically would either spam
// the node or hide a configuration mistake. An error AFTER acceptance
// (confirmation timeout) is not: the txid is recorded and cycle 1 decides
// when the next spend may go out.
func runWatchedCustodySpend(ws watchSpendState) error {
	// This command, unlike every other CLI subcommand, owns its shutdown: the
	// console renderer's process-wide handler would otherwise os.Exit(130) the
	// moment the signal arrives, mid-broadcast, before the loop can finish its
	// current cycle. Disabling it leaves our handler below as the only actor,
	// and (per DisableSignalHandler) keeps a registration alive so the signal
	// is still delivered to us rather than to the runtime's default action.
	logger.DisableSignalHandler()

	stop := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case sig := <-sigCh:
			logger.Info("multisig spend --watch: %v received; stopping after the current cycle", sig)
			close(stop)
		case <-done:
		}
	}()

	pendingTx := ""
	var pendingSince time.Time
	iter := 0
	cycle := func() error {
		iter++
		if pendingTx != "" {
			rcpt, err := readCustodyTxReceipt(ws.rpcAddr, pendingTx)
			switch {
			case err != nil:
				// State unknown: skip the cycle rather than risk a duplicate.
				fmt.Printf("watch iter=%d pending_tx=%s receipt_unavailable=%v; not spending until it resolves\n", iter, pendingTx, err)
				return nil
			case rcpt.InvalidReason != "":
				return fmt.Errorf("node rejected the custody spend %s: %s", pendingTx, rcpt.InvalidReason)
			case !rcpt.Confirmed:
				if age := time.Since(pendingSince); age > time.Duration(ws.timeout)*2*time.Second {
					return fmt.Errorf("watch: transaction %s is still unconfirmed after %s; inspect it with gettransactionreceipt, then restart multisig spend", pendingTx, age.Truncate(time.Second))
				}
				fmt.Printf("watch iter=%d pending_tx=%s confirmed=false; skipping this cycle\n", iter, pendingTx)
				return nil
			}
			fmt.Printf("watch iter=%d pending_tx=%s confirmed=true\n", iter, pendingTx)
			pendingTx = ""
		}

		bal, err := custodyBalance(ws.rpcAddr, ws.sender)
		if err != nil {
			fmt.Printf("watch iter=%d sender_balance_unavailable=%v; retrying in %s\n", iter, err, ws.interval)
			return nil
		}
		if ws.dryRun {
			// Monitor mode: report the live balance, never sign or broadcast.
			fmt.Printf("watch iter=%d sender=%s sender_balance=%s nSPX amount=%s nSPX rpc=%s\n",
				iter, ws.sender, bal.String(), ws.amount.String(), ws.rpcAddr)
			return nil
		}
		if bal.Cmp(ws.amount) < 0 {
			fmt.Printf("watch iter=%d sender_balance=%s nSPX < amount=%s nSPX; waiting %s\n",
				iter, bal.String(), ws.amount.String(), ws.interval)
			return nil
		}

		// Fresh horizon and live nonce per cycle: a long-running watch must
		// never re-sign yesterday's expiry or a nonce a confirmed spend
		// already consumed.
		now := time.Now()
		exp := ws.expiry
		if exp == 0 {
			exp = uint64(now.Add(ws.validity).Unix())
		}
		if err := multisig.ValidateWitnessExpiry(exp, uint64(now.Unix())); err != nil {
			return err
		}
		var n uint64
		raw, err := rpc.CallRPC(ws.rpcAddr, "getnonce", []interface{}{ws.sender}, 30)
		if err != nil {
			return fmt.Errorf("getnonce from %s: %w", ws.rpcAddr, err)
		}
		if err := json.Unmarshal(raw, &n); err != nil {
			return fmt.Errorf("parse getnonce response: %w", err)
		}

		txid, err := ws.signAndBroadcast(n, exp, now.Unix())
		if txid != "" {
			pendingTx = txid
			pendingSince = time.Now()
		}
		if err != nil {
			if txid != "" {
				// The node accepted it; only confirmation failed. The pending
				// guard above decides when the next spend may go out.
				logger.Warn("multisig spend --watch: %s accepted but not confirmed yet: %v", txid, err)
				return nil
			}
			return err
		}
		if ws.wait {
			pendingTx = "" // the inline wait confirmed it
		}
		return nil
	}

	logger.Info("multisig spend --watch: polling %s every %s until it covers %s nSPX (Ctrl-C to stop)",
		ws.sender, ws.interval, ws.amount.String())
	err := watchSpendLoop(ws.interval, stop, cycle)
	fmt.Printf("watch stopped=true cycles=%d\n", iter)
	return err
}

// watchSpendLoop runs cycle immediately, then once every interval until stop
// is closed. A cycle error aborts the loop and is returned as-is; a closed
// stop ends it with nil — that is how SIGINT/SIGTERM becomes a graceful
// shutdown of `multisig spend --watch`.
func watchSpendLoop(interval time.Duration, stop <-chan struct{}, cycle func() error) error {
	if interval <= 0 {
		return fmt.Errorf("watch interval must be positive, got %s", interval)
	}
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		if err := cycle(); err != nil {
			return err
		}
		timer := time.NewTimer(interval)
		select {
		case <-stop:
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// custodyProposalsDir is where the node's always-on, self-directed custody
// watcher looks for threshold-signed spends. Each *.json file is a complete
// custody transaction as written by `multisig spend --dry-run --out <file>`:
// the destination, amount and nonce live INSIDE the signed payload, so no node
// needs to be told what to spend and no second source of truth can disagree
// with what the custodian quorum actually signed.
//
// ★ TRUST BOUNDARY: anything that can write here can force a broadcast ATTEMPT
// of a payment the quorum already authorized. Treat this directory with the
// same access controls as the custodian keys themselves — it is not a public
// inbox. A malformed or invalid file is logged and skipped, never fatal, so one
// bad drop cannot stop the others from being broadcast.
const custodyProposalsDir = "config/spend_proposals"

// autoWatchArgs validates the custody prerequisites a node needs before it
// starts the always-on, self-directed custody watcher, and returns the argv for
// the in-process `multisig spend --watch` loop.
//
// ★ WHY THIS EXISTS: an operator should only ever run the README's node command
// — no second terminal and no per-node spend configuration. The watcher is
// never told a destination or amount: it scans proposalDir for spends the
// M-of-N custodian quorum already signed, re-verifies each against the live
// policy, and broadcasts only those. Returning `--watch` with no --to/--amount
// is what puts runMultisigSpend into that self-directed proposal mode.
//
// ★ BROADCASTER ≠ CUSTODIAN: this node only broadcasts what the quorum already
// signed, so it needs NO custodian keys and this gate deliberately does not
// demand them. Custodian key files belong only on the machines that sign
// proposals; copying M of N of them onto every broadcasting node would widen
// the key-distribution surface for a signing authority this path never
// exercises. The only hard requirement is that the custody policy is present
// and parses — it is the address block 0 funds and the address the loop
// re-verifies every proposal against.
//
// RPC reachability is intentionally NOT checked here: the watcher starts before
// this node's own RPC listener is up, and the loop already treats an unreachable
// node as transient (log and retry), so gating startup on it would be wrong.
func autoWatchArgs(policyPath, rpcAddr, proposalDir string) ([]string, error) {
	if policyPath == "" {
		return nil, fmt.Errorf("custody policy path is empty (run `multisig devnet --role escrow` BEFORE starting the nodes)")
	}
	if _, err := multisig.LoadPolicy(policyPath); err != nil {
		return nil, fmt.Errorf("custody policy %s: %w (run `multisig devnet --role escrow` BEFORE starting the nodes)", policyPath, err)
	}
	if proposalDir == "" {
		proposalDir = custodyProposalsDir
	}
	return []string{
		"--policy", policyPath,
		"--rpc", rpcAddr,
		"--proposals-dir", proposalDir,
		"--watch",
		"--interval", defaultCustodyWatchInterval.String(),
	}, nil
}

// selfDirectedWatchState is everything one self-directed custody watcher needs.
// It owns no signing keys: the custodian quorum signs off-chain (`multisig
// message` / `sign` / `combine`, assembled into a transaction with `multisig
// spend --dry-run --out`), and this loop only decides which already-signed
// spends are safe to broadcast.
type selfDirectedWatchState struct {
	policyPath   string
	proposalsDir string
	rpcAddr      string
	chainID      uint64
	interval     time.Duration
	dryRun       bool
	timeout      int
	verifyRPCs   []string
}

// listCustodyProposals returns the proposal filenames in dir in deterministic
// order, ignoring subdirectories, dotfiles and anything that is not *.json.
func listCustodyProposals(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// custodyProposalTxID is the transaction ID exactly as broadcastCustodySpend
// mints it: SpxHash over the transaction JSON with the self-referential ID
// field empty. Clearing first is what makes it idempotent — hashing a tx whose
// ID is already populated would fold the old ID into the new one.
func custodyProposalTxID(tx *types.Transaction) string {
	prior := tx.ID
	tx.ID = ""
	id := tx.Hash()
	tx.ID = prior
	return id
}

// broadcastCustodyProposal submits an already-threshold-signed proposal through
// the same broadcast path a hand-run `multisig spend` uses, with the CURRENT
// policy attached to the witness. The proposal's own destination, amount,
// nonce, gas and timestamp are preserved, so the txid it produces is exactly
// the one the proposal file already carries.
func broadcastCustodyProposal(p *multisig.MultiPartyPolicy, tx *types.Transaction, rpcAddr string, timeout int, verifyRPCs []string) (string, error) {
	if tx.GasLimit == nil || !tx.GasLimit.IsUint64() || tx.GasPrice == nil || !tx.GasPrice.IsUint64() {
		return "", fmt.Errorf("gas limit/price is missing or out of range")
	}
	w := tx.MultiSigWitness
	msg := multisig.SpendMessage(p, tx.ChainID, tx.Sender, tx.Receiver, tx.Amount, tx.Nonce, w.Expiry)
	return broadcastCustodySpend(spendParams{
		policy: p, sender: tx.Sender, to: tx.Receiver, amount: tx.Amount,
		nonce: tx.Nonce, expiry: w.Expiry, chainID: tx.ChainID,
		msg: msg, sigs: w.Sigs,
		gasLimit: tx.GasLimit.Uint64(), gasPrice: tx.GasPrice.Uint64(),
		timestamp: tx.Timestamp, rpcAddr: rpcAddr, verifyRPCs: verifyRPCs,
		dryRun: false, wait: false, timeout: timeout,
	})
}

// isNodeRPCRejection reports whether err is a JSON-RPC error the NODE returned
// (it ran the request and refused it) rather than a transport/handshake
// failure. rpc.CallRPC prefixes node-side errors with "RPC error (", so a
// proposal the node permanently refuses is settled instead of resubmitted every
// interval, while a transient dial failure is still retried.
func isNodeRPCRejection(err error) bool {
	return err != nil && strings.Contains(err.Error(), "RPC error (")
}

// loadCustodyProposal reads one *.json spend proposal and re-verifies it from
// scratch against the live policy p. It returns the transaction only when every
// field the node will check is sound, so the watcher can never be tricked into
// broadcasting a payment the quorum did not authorize:
//
//   - sender is exactly p's derived custody address (current policy, not the
//     one embedded in the file);
//   - receiver/amount/nonce are present and the tx is bound to chainID;
//   - the witness's embedded policy resolves to the same address (a stale or
//     superseded custodian set cannot be replayed through the live one);
//   - the witness expiry is inside the musig horizon;
//   - a real threshold signature check over the exact spend, using the CURRENT
//     policy's custodian set.
func loadCustodyProposal(path string, p *multisig.MultiPartyPolicy, sender string, chainID, now uint64) (*types.Transaction, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tx types.Transaction
	if err := json.Unmarshal(data, &tx); err != nil {
		return nil, fmt.Errorf("not a custody transaction JSON: %w", err)
	}
	if tx.Sender == "" || tx.Receiver == "" || tx.Amount == nil || tx.Amount.Sign() <= 0 {
		return nil, fmt.Errorf("incomplete transaction (need sender, receiver and a positive amount)")
	}
	if !strings.EqualFold(tx.Sender, sender) {
		return nil, fmt.Errorf("sender %s is not this policy's custody address %s", tx.Sender, sender)
	}
	if tx.ChainID != chainID {
		return nil, fmt.Errorf("transaction is bound to chain %d, this watcher to %d", tx.ChainID, chainID)
	}
	if tx.GasLimit == nil || !tx.GasLimit.IsUint64() || tx.GasPrice == nil || !tx.GasPrice.IsUint64() {
		return nil, fmt.Errorf("gas limit/price is missing or out of range")
	}
	w := tx.MultiSigWitness
	if w == nil || len(w.Sigs) == 0 {
		return nil, fmt.Errorf("no M-of-N witness")
	}
	if len(w.Policy.PubKeys) > 0 {
		addr, err := w.Policy.Address()
		if err != nil {
			return nil, fmt.Errorf("witness policy invalid: %w", err)
		}
		if !strings.EqualFold(addr, sender) {
			return nil, fmt.Errorf("witness policy resolves to %s, not custody address %s", addr, sender)
		}
	} else if w.Policy.Domain != "" && w.Policy.Domain != p.Domain {
		return nil, fmt.Errorf("witness domain %q does not match policy domain %q", w.Policy.Domain, p.Domain)
	}
	if err := multisig.ValidateWitnessExpiry(w.Expiry, now); err != nil {
		return nil, err
	}
	msg := multisig.SpendMessage(p, chainID, sender, tx.Receiver, tx.Amount, tx.Nonce, w.Expiry)
	witness := *w
	witness.Policy = *p // verify against the live custodian set, never the file's
	if !multisig.VerifyThreshold(msg, witness, now) {
		return nil, fmt.Errorf("signatures do not meet policy threshold %d for this exact spend", p.Threshold)
	}
	tx.ID = custodyProposalTxID(&tx)
	return &tx, nil
}

// runSelfDirectedCustodyWatch is the always-on, no-flags custody watcher. Each
// cycle it:
//
//  1. resolves a proposal it broadcast earlier (while one is outstanding no new
//     proposal goes out, so the loop never races itself);
//  2. lists st.proposalsDir and loads every *.json proposal;
//  3. re-verifies each proposal against the CURRENT policy — sender address,
//     chain id, expiry window, the witness's embedded policy, and a real
//     threshold signature check over the exact spend (loadCustodyProposal);
//  4. skips any proposal whose txid is already settled (broadcast by an earlier
//     cycle, or already known to the node) and any malformed/invalid file,
//     which is logged and skipped so one bad drop cannot block the others;
//  5. broadcasts the first still-unsent proposal through the node's own
//     sendrawtransaction, then resolves its receipt on the next cycle.
//
// SIGINT/SIGTERM stops it after the current cycle.
func runSelfDirectedCustodyWatch(st selfDirectedWatchState) error {
	if st.policyPath == "" {
		return fmt.Errorf("--policy is required")
	}
	if st.interval <= 0 {
		return fmt.Errorf("--interval must be positive, got %s", st.interval)
	}
	p, err := multisig.LoadPolicy(st.policyPath)
	if err != nil {
		return fmt.Errorf("custody policy %s: %w", st.policyPath, err)
	}
	sender, err := p.Address()
	if err != nil {
		return fmt.Errorf("derive custody address: %w", err)
	}

	// Like runWatchedCustodySpend, this command owns its shutdown: the console
	// renderer's process-wide handler would otherwise os.Exit() the process the
	// moment a signal arrives, mid-broadcast.
	logger.DisableSignalHandler()
	stop := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case sig := <-sigCh:
			logger.Info("multisig spend --watch: %v received; stopping after the current cycle", sig)
			close(stop)
		case <-done:
		}
	}()

	// settled is the replay guard, keyed by txid (never by filename, so
	// renaming or re-dropping a proposal cannot resubmit it). A txid enters it
	// when the node accepts the broadcast, or the first time the node reports
	// it confirmed/rejected — the latter is also what makes the guard survive a
	// watcher restart.
	settled := map[string]bool{}
	pendingTx := ""
	var pendingSince time.Time
	iter := 0

	cycle := func() error {
		iter++
		if pendingTx != "" {
			rcpt, err := readCustodyTxReceipt(st.rpcAddr, pendingTx)
			switch {
			case err != nil:
				fmt.Printf("watch iter=%d pending_tx=%s receipt_unavailable=%v; not broadcasting until it resolves\n", iter, pendingTx, err)
				return nil
			case rcpt.InvalidReason != "":
				logger.Warn("self-directed custody watcher: %s was rejected by the node: %s", pendingTx, rcpt.InvalidReason)
				settled[pendingTx] = true
				pendingTx = ""
			case !rcpt.Confirmed:
				if age := time.Since(pendingSince); age > time.Duration(st.timeout)*2*time.Second {
					return fmt.Errorf("watch: proposal %s is still unconfirmed after %s; inspect it with gettransactionreceipt, then restart the watcher", pendingTx, age.Truncate(time.Second))
				}
				fmt.Printf("watch iter=%d pending_tx=%s confirmed=false; waiting\n", iter, pendingTx)
				return nil
			default:
				fmt.Printf("watch iter=%d pending_tx=%s confirmed=true\n", iter, pendingTx)
				settled[pendingTx] = true
				pendingTx = ""
			}
		}

		names, err := listCustodyProposals(st.proposalsDir)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("watch iter=%d proposals_dir=%s missing; nothing to broadcast\n", iter, st.proposalsDir)
				return nil
			}
			return err
		}

		now := uint64(time.Now().Unix())
		for _, name := range names {
			path := filepath.Join(st.proposalsDir, name)
			tx, err := loadCustodyProposal(path, p, sender, st.chainID, now)
			if err != nil {
				// One malformed/invalid drop must never stop the others.
				logger.Warn("self-directed custody watcher: skipping %s: %v", path, err)
				continue
			}
			txid := custodyProposalTxID(tx)
			if settled[txid] {
				continue
			}
			// Restart-safe dedupe: the node already knows this txid (confirmed
			// or rejected) even though this process may never have broadcast it.
			if rcpt, err := readCustodyTxReceipt(st.rpcAddr, txid); err == nil && (rcpt.Confirmed || rcpt.InvalidReason != "") {
				settled[txid] = true
				continue
			}
			if st.dryRun {
				fmt.Printf("proposal %s would broadcast txid=%s %s -> %s amount=%s nSPX nonce=%d\n",
					path, txid, tx.Sender, tx.Receiver, tx.Amount.String(), tx.Nonce)
				continue
			}
			accepted, err := broadcastCustodyProposal(p, tx, st.rpcAddr, st.timeout, st.verifyRPCs)
			if err != nil {
				if isNodeRPCRejection(err) {
					// The node ran the spend and refused it (bad witness, wrong
					// nonce, below the gas floor...). Resubmitting the same bytes
					// every interval would just spam it, so settle the txid:
					// correcting the proposal changes its txid and re-arms it.
					logger.Warn("self-directed custody watcher: node rejected %s (settled, fix and re-drop to retry): %v", path, err)
					settled[txid] = true
					continue
				}
				// Transient transport failure (node's RPC not listening yet):
				// leave the proposal unsettled and retry next cycle.
				logger.Warn("self-directed custody watcher: broadcast %s failed, will retry: %v", path, err)
				continue
			}
			settled[accepted] = true
			pendingTx = accepted
			pendingSince = time.Now()
			return nil // one broadcast per cycle; let its receipt resolve first
		}
		return nil
	}

	logger.Info("self-directed custody watcher: scanning %s every %s for threshold-signed spends from %s (Ctrl-C to stop)",
		st.proposalsDir, st.interval, sender)
	err = watchSpendLoop(st.interval, stop, cycle)
	fmt.Printf("watch stopped=true cycles=%d\n", iter)
	return err
}

// spendParams carries one assembled custody spend from the argument-parsing
// path to the broadcast path, so runMultisigSpend stays a flag/validation
// function and the network I/O stays separately testable.
type spendParams struct {
	policy     *multisig.MultiPartyPolicy
	sender     string
	to         string
	amount     *big.Int
	nonce      uint64
	expiry     uint64
	chainID    uint64
	msg        []byte
	sigs       map[int][]byte
	gasLimit   uint64
	gasPrice   uint64
	timestamp  int64
	rpcAddr    string
	verifyRPCs []string
	out        string
	dryRun     bool
	wait       bool
	timeout    int
}

// broadcastCustodySpend assembles, encodes and submits the custody
// transaction, then waits for confirmation and reports the recipient's balance
// from every requested node. The first return value is the txid the node
// accepted — empty when the transaction never reached the network (a build
// error or a dry run) — so a caller that loops (`--watch`) can keep tracking
// an accepted-but-unconfirmed spend instead of broadcasting another one.
func broadcastCustodySpend(sp spendParams) (string, error) {
	// Gas: the node's admission floor is the policy's own quote, so default to
	// it exactly instead of a hand-picked constant. A below-floor limit is
	// rejected by pool.verifyTransactionGas before the witness is ever
	// considered, which would look like an auth failure but isn't one.
	quote := policy.GetDefaultPolicyParams().QuoteTransactionGas(0)
	limit := quote.GasLimit
	price := quote.GasPrice
	if sp.gasLimit != 0 {
		limit = new(big.Int).SetUint64(sp.gasLimit)
	}
	if sp.gasPrice != 0 {
		price = new(big.Int).SetUint64(sp.gasPrice)
	}

	witness := &multisig.MultiSigWitness{Policy: *sp.policy, Sigs: sp.sigs, Expiry: sp.expiry}
	tx := &types.Transaction{
		Sender:          sp.sender,
		Receiver:        sp.to,
		Amount:          new(big.Int).Set(sp.amount),
		GasLimit:        limit,
		GasPrice:        price,
		Nonce:           sp.nonce,
		Timestamp:       sp.timestamp,
		ChainID:         sp.chainID,
		MultiSigWitness: witness,
	}
	tx.ID = tx.Hash()

	logger.Info("custody spend: %s → %s amount=%s nSPX nonce=%d chain=%d expiry=%d sigs=%d/%d",
		sp.sender, sp.to, sp.amount.String(), sp.nonce, sp.chainID, sp.expiry, len(sp.sigs), sp.policy.Threshold)
	fmt.Printf("message_hex=%s\ntxid=%s\n", hex.EncodeToString(sp.msg), tx.ID)

	if payload, err := json.MarshalIndent(tx, "", "  "); err == nil && sp.out != "" {
		if err := os.WriteFile(sp.out, append(payload, '\n'), 0644); err != nil {
			return "", fmt.Errorf("write transaction file: %w", err)
		}
		logger.Info("assembled transaction written to %s", sp.out)
	}

	raw, err := abi.EncodeRawTransaction(tx)
	if err != nil {
		return "", err
	}
	if sp.dryRun {
		fmt.Printf("dry_run=true raw_tx=%s\n", raw)
		return "", nil
	}

	var before *big.Int
	if bal, err := custodyBalance(sp.rpcAddr, sp.to); err == nil {
		before = bal
		fmt.Printf("recipient_balance_before=%s nSPX (via %s)\n", bal.String(), sp.rpcAddr)
	} else {
		logger.Warn("could not read the recipient's balance before the spend: %v", err)
	}

	resp, err := rpc.CallRPC(sp.rpcAddr, "sendrawtransaction", []interface{}{raw}, 120)
	if err != nil {
		return "", fmt.Errorf("sendrawtransaction via %s: %w", sp.rpcAddr, err)
	}
	var result struct {
		TxID string `json:"txid"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", fmt.Errorf("parse sendrawtransaction response: %w", err)
	}
	logger.Info("accepted by %s: txid=%s", sp.rpcAddr, result.TxID)

	if sp.wait {
		if err := waitForCustodyTx(sp.rpcAddr, result.TxID, sp.timeout); err != nil {
			return result.TxID, err
		}
		fmt.Printf("confirmed=true txid=%s\n", result.TxID)
	}

	targets := append([]string{sp.rpcAddr}, sp.verifyRPCs...)
	seen := map[string]bool{}
	for _, addr := range targets {
		if seen[addr] {
			continue
		}
		seen[addr] = true
		bal, err := custodyBalance(addr, sp.to)
		if err != nil {
			fmt.Printf("verify rpc=%s error=%v\n", addr, err)
			continue
		}
		delta := ""
		if before != nil {
			delta = formatSignedSPX(new(big.Int).Sub(bal, before))
		}
		fmt.Printf("verify rpc=%s recipient_balance=%s nSPX delta=%s\n", addr, bal.String(), delta)
	}
	return result.TxID, nil
}

// custodyKeyFiles expands
// custodyKeyFiles expands --keys-dir (every custodian-*.json, sorted) and the
// repeated --key flags into one ordered key-file list.
func custodyKeyFiles(keysDir string, explicit []string) ([]string, error) {
	files := append([]string(nil), explicit...)
	if keysDir == "" {
		return files, nil
	}
	matches, err := filepath.Glob(filepath.Join(keysDir, "custodian-*.json"))
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", keysDir, err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no custodian-*.json key files in %s", keysDir)
	}
	sort.Strings(matches)
	return append(matches, files...), nil
}

// signCustodyWitness signs msg with every supplied custodian key and returns
// the witness. A key that is not a custodian in p is a hard error: a signature
// that cannot be mapped to a policy index is worthless, and silently dropping
// it would make an under-threshold broadcast look like a node-side rejection.
func signCustodyWitness(p *multisig.MultiPartyPolicy, msg []byte, keyFiles []string) (map[int][]byte, error) {
	sigs := make(map[int][]byte, len(keyFiles))
	for _, f := range keyFiles {
		skBytes, pkBytes, err := loadSigningKeyFile(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		idx := -1
		for i, pk := range p.PubKeys {
			if strings.EqualFold(hex.EncodeToString(pk), hex.EncodeToString(pkBytes)) {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, fmt.Errorf("%s: public key is not a custodian in this policy", f)
		}
		if _, dup := sigs[idx]; dup {
			continue
		}
		sig, err := multisig.SignCustodyMessage(msg, skBytes, pkBytes)
		if err != nil {
			return nil, fmt.Errorf("sign with %s: %w", f, err)
		}
		sigs[idx] = sig
		logger.Info("custodian %d signed (%s)", idx, f)
	}
	return sigs, nil
}

// custodyBalance reads an address's confirmed balance from a node's JSON-RPC.
func custodyBalance(rpcAddr, address string) (*big.Int, error) {
	raw, err := rpc.CallRPC(rpcAddr, "getbalance", []interface{}{address}, 30)
	if err != nil {
		return nil, err
	}
	var out struct {
		Balance string `json:"balance"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse getbalance: %w", err)
	}
	bal, ok := new(big.Int).SetString(strings.TrimSpace(out.Balance), 10)
	if !ok {
		return nil, fmt.Errorf("unparseable balance %q from %s", out.Balance, rpcAddr)
	}
	return bal, nil
}

// formatSignedSPX renders a signed nSPX delta in whole SPX for the verification
// line, so a reader can see at a glance whether every node credited the same
// amount. The exact nSPX value is printed alongside it.
func formatSignedSPX(nspx *big.Int) string {
	if nspx == nil {
		return "n/a"
	}
	return new(big.Int).Div(nspx, big.NewInt(1e18)).String() + " SPX (" + nspx.String() + " nSPX)"
}

// custodyTxReceipt is the node's verdict on one transaction: in a block,
// still pending, or rejected with a reason.
type custodyTxReceipt struct {
	Confirmed     bool   `json:"confirmed"`
	Height        uint64 `json:"height"`
	BlockHash     string `json:"blockhash"`
	InvalidReason string `json:"invalid_reason"`
}

// readCustodyTxReceipt fetches gettransactionreceipt once. An error means the
// status is UNKNOWN (transport/parse), which callers must treat as "do not
// spend" rather than "safe to spend"; an empty InvalidReason with
// Confirmed=false is simply "still pending".
func readCustodyTxReceipt(rpcAddr, txID string) (*custodyTxReceipt, error) {
	raw, err := rpc.CallRPC(rpcAddr, "gettransactionreceipt", []interface{}{txID}, 30)
	if err != nil {
		return nil, err
	}
	var receipt custodyTxReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return nil, fmt.Errorf("parse gettransactionreceipt: %w", err)
	}
	return &receipt, nil
}

// waitForCustodyTx polls gettransactionreceipt until the transaction is in a
// block, so the spend is verified against committed state rather than against
// an admission acknowledgement. A pool rejection surfaces as invalid_reason
// instead of a timeout, which is what makes an under-threshold broadcast
// (--allow-partial) produce a precise verdict.
func waitForCustodyTx(rpcAddr, txID string, timeoutSecs int) error {
	deadline := time.Now().Add(time.Duration(timeoutSecs) * time.Second)
	for {
		if receipt, err := readCustodyTxReceipt(rpcAddr, txID); err == nil {
			if receipt.Confirmed {
				logger.Info("custody spend confirmed in block %d (%s)", receipt.Height, receipt.BlockHash)
				return nil
			}
			if receipt.InvalidReason != "" {
				return fmt.Errorf("node rejected the custody spend: %s", receipt.InvalidReason)
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %ds waiting for %s to be confirmed in a block", timeoutSecs, txID)
		}
		time.Sleep(2 * time.Second)
	}
}
