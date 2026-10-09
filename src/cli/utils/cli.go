// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/cli.go
package utils

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/bind"
	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/consensus"
	logger "github.com/sphinxfndorg/protocol/src/console"
	"github.com/sphinxfndorg/protocol/src/core"
	"github.com/sphinxfndorg/protocol/src/network"
)

// Execute is the main entry point for the Sphinx blockchain CLI.
func Execute() error {
	// Route on first argument (subcommand vs legacy flag mode)
	if len(os.Args) > 1 && !isFlag(os.Args[1]) {
		switch os.Args[1] {
		case "node":
			return runNodeCmd(os.Args[2:])
		case "send-tx":
			return runSendTxCmd(os.Args[2:])
		case "get-balance":
			return runGetBalanceCmd(os.Args[2:])
		case "watch-tx":
			return runWatchTxCmd(os.Args[2:])
		case "stake":
			return runStakeCmd(os.Args[2:])
		case "slash":
			return runSlashCmd(os.Args[2:])
		case "ipfs":
			return runIPFSCmd(os.Args[2:])
		case "wallet":
			return runWalletCmd(os.Args[2:])
		case "multisig":
			return runMultisigCmd(os.Args[2:])
		case "localnet":
			return runLocalnetCmd(os.Args[2:])
		case "help", "--help", "-h":
			printHelp()
			return nil
		default:
			return fmt.Errorf("unknown subcommand %q — run with 'help' to see usage", os.Args[1])
		}
	}

	// Legacy mode: original flag-based dispatch
	return legacyExecute()
}

func isFlag(s string) bool {
	return len(s) > 0 && s[0] == '-'
}

// Default listen addresses. --port-offset shifts these, and only these, so
// several node processes can coexist on one machine. The UDP discovery port is
// derived by bind from the (possibly shifted) TCP port as TCP+1000.
const (
	defaultTCPAddr  = "127.0.0.1:30303"
	defaultHTTPAddr = "127.0.0.1:8545"
	defaultWSAddr   = "127.0.0.1:8600"
	defaultDataDir  = "data"
)

// applyPortOffset rewrites the DEFAULT listen addresses (and default datadir)
// by offset. An explicitly supplied value is never touched: the caller only
// reaches here with the flag defaults, and each field is compared against its
// default literal before being shifted.
//
// The default datadir is namespaced per node for EVERY offset, including 0:
// the bootstrap node resolves to data/node0 so it sits beside data/node1,
// data/node2, ... exactly like any other node, instead of writing its
// Node-…/config/custody tree straight into the data/ root. Only the LISTEN
// PORTS remain a no-op at offset 0 — their 30303/8545/8600 defaults are
// unchanged.
func applyPortOffset(offset int, tcpAddr, httpAddr, wsAddr, dataDir *string) {
	if dataDir != nil && *dataDir == defaultDataDir {
		*dataDir = fmt.Sprintf("data/node%d", offset)
	}
	if offset == 0 {
		return
	}
	if tcpAddr != nil && *tcpAddr == defaultTCPAddr {
		*tcpAddr = fmt.Sprintf("127.0.0.1:%d", 30303+offset)
	}
	if httpAddr != nil && *httpAddr == defaultHTTPAddr {
		*httpAddr = fmt.Sprintf("127.0.0.1:%d", 8545+offset)
	}
	if wsAddr != nil && *wsAddr == defaultWSAddr {
		*wsAddr = fmt.Sprintf("127.0.0.1:%d", 8700+offset)
	}
}

func validateProductionNodeStart(mode, networkType, tcpAddr, dataDir, seeds string, portOffset int) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	networkType = strings.ToLower(strings.TrimSpace(networkType))
	if mode == "" {
		mode = "development"
	}
	if mode != "development" && mode != "production" {
		return fmt.Errorf("--mode must be development or production, got %q", mode)
	}
	if mode != "production" {
		return nil
	}
	if networkType == "devnet" {
		return fmt.Errorf("--mode=production cannot run on --network=devnet; use --network=testnet or --network=mainnet with a pinned genesis")
	}
	if networkType != "testnet" && networkType != "mainnet" {
		return fmt.Errorf("--mode=production requires --network=testnet or --network=mainnet, got %q", networkType)
	}
	envName, pinnedDigest := productionGenesisDigestPin(networkType)
	if pinnedDigest == "" {
		return fmt.Errorf("--mode=production requires %s to pin the out-of-band genesis digest", envName)
	}
	if len(pinnedDigest) != 64 {
		return fmt.Errorf("--mode=production requires %s to be a 64-character hex genesis digest, got %d characters", envName, len(pinnedDigest))
	}
	if _, err := hex.DecodeString(pinnedDigest); err != nil {
		return fmt.Errorf("--mode=production requires %s to be valid hex: %w", envName, err)
	}
	if portOffset != 0 {
		return fmt.Errorf("--mode=production refuses --port-offset=%d; set explicit --tcp-addr, --http-port, --ws-port, --udp-port, and --datadir", portOffset)
	}
	if strings.TrimSpace(seeds) == "" {
		return fmt.Errorf("--mode=production requires --seeds with reachable bootnodes or DNS discovery")
	}
	if dataDir == "" || dataDir == defaultDataDir || strings.HasPrefix(filepath.Clean(dataDir), filepath.Clean(defaultDataDir)+string(os.PathSeparator)) {
		return fmt.Errorf("--mode=production requires an explicit persistent --datadir, not %q", dataDir)
	}
	if !filepath.IsAbs(dataDir) {
		return fmt.Errorf("--mode=production requires an absolute persistent --datadir, not %q", dataDir)
	}
	host, _, err := net.SplitHostPort(tcpAddr)
	if err != nil {
		return fmt.Errorf("--mode=production requires --tcp-addr as public host:port: %w", err)
	}
	if isLocalProductionHost(host) {
		return fmt.Errorf("--mode=production requires a stable public --tcp-addr, got %q", tcpAddr)
	}
	return nil
}

func productionGenesisDigestPin(networkType string) (envName, pinnedDigest string) {
	envName = "SPHINX_MAINNET_GENESIS_DIGEST"
	if strings.ToLower(strings.TrimSpace(networkType)) == "testnet" {
		envName = "SPHINX_TESTNET_GENESIS_DIGEST"
	}
	return envName, strings.TrimSpace(os.Getenv(envName))
}

func isLocalProductionHost(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsUnspecified()
}

func printHelp() {
	// Use fmt.Print directly to avoid format string parsing issues
	// since the help text contains % characters that logger.Info would try to parse
	fmt.Print(`Sphinx blockchain CLI

SUBCOMMANDS
  node          Start a validator node
  localnet      Start N real validator nodes in one command (devnet quorum testing)
  send-tx       Send a transaction from one address to another
  get-balance   Query the balance of an address
  watch-tx      Poll until a transaction is confirmed
  stake         Submit a delayed Stake or Unstake transaction
  slash         Submit chain-verifiable double-sign evidence
  ipfs          IPFS + on-chain NFT mint, verify and repin
                (note: a local IPFS daemon is NOT durable storage — it stops
                 serving content when it goes offline. Set
                 SPHINX_IPFS_PINNING_SERVICE and SPHINX_IPFS_PINNING_TOKEN to
                 mirror every pin to a remote pinning service (Pinata) so
                 retrievability does not depend on this machine. Use
                 'ipfs repin' to re-pin a payload whose anchor recorded only a
                 local content hash.)
  wallet        Manage ` + common.SPIFPrefix + ` wallets (init, list, burn, send)
              Burn coins: send SPX to ` + common.DefaultBurnAddress + ` (provably unspendable)
  multisig      M-of-N custody for the genesis vault / CGE escrow
                  devnet  --role escrow|vault --custodians N --threshold M
                          (writes the policy JSON the node auto-loads, plus
                           N custodian key files; run BEFORE starting nodes)
                  spend   --policy policy.json --to <addr> --amount-spx <n> \\
                          --keys-dir <dir> --rpc 127.0.0.1:8700 \\
                          [--verify-rpc 127.0.0.1:8701 ...]
                          (LIVE: fetches the nonce, signs the canonical spend
                           message with M of N custodian keys, broadcasts the
                           witness-authorized transaction, waits for the block,
                           then prints the recipient balance from every node.
                           Add --allow-partial to prove a below-threshold
                           broadcast is rejected.
                           Add --watch [--interval 10s] to poll the custodial
                           balance and spend --amount whenever it covers it;
                           Ctrl-C stops after the current cycle. With
                           --dry-run, --watch only prints the balance.
                           Add --dry-run --out <file> to write the signed
                           transaction (a proposal) for the node's always-on
                           watcher to broadcast. With --watch and NO
                           --to/--amount the command BECOMES that watcher in
                           the foreground: it scans --proposals-dir (default
                           config/spend_proposals) and broadcasts threshold-
                           signed proposals, deduped by transaction id.)
                  create  --pubkey <files...> --threshold M --domain <s> --out policy.json
                  message --policy policy.json --kind spend|cge-release|dev-module \\
                          --receiver <addr> --amount-spx <n> --expiry <unix> \\
                          [--nonce <n>]            (spend: account nonce / dev-module: module id)
                          [--milestone-nspx <n>]   (cge-release ONLY: cumulative unlocked
                                                   target naming the milestone; required —
                                                   vesting witnesses bind the milestone,
                                                   never a block height)
                          --out msg.msg            (builds the exact bytes custodians sign)
                  sign    --policy policy.json --tx msg.msg --key <keyfile> --out sig.json
                  combine --policy policy.json --sig sig1.json --sig sig2.json \\
                          --expiry <unix> --release-time <unix> --out witness.json
                  coverage --policy config/genesis_state.json \\
                           [--dir config/cge_witnesses] [--rpc 127.0.0.1:8700] \\
                           [--now <unix>] [--horizon <unix>] [--json]
                          (PRE-FLIGHT for enforcing CGE releases: audits the
                           staged witness files and reports, per time-based
                           recipient, whether a valid witness reaches past the
                           horizon — then exits non-zero if ANY recipient is
                           uncovered. Run this before enabling enforcement:
                           an uncovered recipient is not protected, it is
                           silently skipped.)
TOKENOMICS OVERVIEW
  Genesis Supply: 1,170,000,000 SPX (23.4% of 5B max supply) — 1,040,000,000 SPX remainder + 130,000,000 SPX sold (Angel Round + Public ICO), both funded in block 0
  Funding Rounds:
    Angel Round: 30,000,000 SPX @ $0.06 = $1.8M
    Private Sale: 70,000,000 SPX @ $0.24 = $16.8M
    Public ICO: 100,000,000 SPX @ $0.36 = $36.0M
    Total Raised: $54.6M (200,000,000 SPX sold, 16.1% of genesis)

GENESIS DOCUMENT — initial chain state
Every node reads <datadir>/config/genesis_state.json. The first devnet node
authors its own genesis; later nodes fetch that document from seeds. There is
no genesis-create command and no configured node-count flag.

How it reaches a node:
  * devnet — the first node authors its own document, and a node started with
              --seeds fetches it from the network (retrying while the
              bootstrap node is still signing).
    * any other network — there is NO automatic fetch. The file must be placed at
                <datadir>/config/genesis_state.json out of band (copy/scp it)
                BEFORE the node starts. Mainnet/testnet also require
                SPHINX_MAINNET_GENESIS_DIGEST or SPHINX_TESTNET_GENESIS_DIGEST;
                without both the file and the pin, startup refuses to guess.

  A node derives its own identity from --tcp-addr as Node-<host:port>, so the
  node_id recorded in genesis_state.json must match that exact string.

CONSENSUS
Validator membership comes from chain state. Connected peers do not become
validators merely by joining, and peer count does not affect consensus,
genesis, sync, or readiness. A block commits only when validators holding
STRICTLY more than 2/3 of active stake have voted. VDF-derived proposer
selection runs over that same active validator set.

REAL-DEVICE QUICK START (ETH/BTC style — no pre-agreed node count)
  Each machine runs independently; peer discovery is via --seeds.
  Nodes can join or leave the network at any time — late joiners automatically
  sync the full blockchain from peers before participating in consensus.

  # Node 1 (bootnode / first validator) — holds the genesis document.
  # On devnet, the first node authors genesis on startup.
  go run main.go node --role=validator \
      --tcp-addr=<PUBLIC_IP_1>:30303 \
      --http-port=<PUBLIC_IP_1>:8545 \
      --datadir=data --pbft

  # Node 2 — joins by pointing at Node 1 (can be started anytime)
  go run main.go node --role=validator \
      --tcp-addr=<PUBLIC_IP_2>:30303 \
      --http-port=<PUBLIC_IP_2>:8545 \
      --seeds=<PUBLIC_IP_1>:30303 \
      --datadir=data --pbft

  # Node 3+ — same pattern; any known node can be used as seed
  # Nodes can be started minutes, hours, or days after the network is live
  go run main.go node --role=validator \
      --tcp-addr=<PUBLIC_IP_3>:30303 \
      --seeds=<PUBLIC_IP_1>:30303,<PUBLIC_IP_2>:30303 \
      --datadir=data --pbft

  Peer connectivity is transport only. Readiness and proposer/consensus
  membership are derived from active chain state, never a connected-peer count.
  A peer must be admitted by chain state before it contributes stake or votes.

EIP-1459 DNS DISCOVERY (cryptographically authenticated bootstrap)
  Instead of plain IP seeds, you can use enrtree:// URLs. The node list
  is published as a signed Merkle tree in DNS TXT records. Clients verify
  the SPHINCS+ signature against the public key embedded in the URL, so
  even a compromised DNS server cannot inject fake peers.

  # Using a DNS discovery tree as the only seed
  go run main.go node --role=validator \
      --tcp-addr=<PUBLIC_IP>:30303 \
      --seeds=enrtree://<PUBKEY_HEX>@nodes.sphinx.network \
      --datadir=data --pbft

  # Mixing DNS trees with plain seeds (DNS resolved first, then PEX)
  go run main.go node --role=validator \
      --tcp-addr=<PUBLIC_IP>:30303 \
      --seeds=enrtree://<PUBKEY_HEX>@nodes.sphinx.network,1.2.3.4:30303 \
      --datadir=data --pbft

SAME-MACHINE / DEV QUICK START (one node or any number of peers)
  Start a fresh devnet node; it authors its own genesis. Additional processes
  use unique local ports/datadirs and the first node as a seed. Joining changes
  peer connectivity only. Validator membership comes from chain state; no
  command predeclares a node count or generates a validator roster.

  # Terminal 1 — first node
  go run main.go node --role=validator --pbft

  # Terminal 2 — peer; can join later and sync from Terminal 1
  go run main.go node --role=validator --port-offset=1 \
      --seeds=127.0.0.1:30303 --pbft

  # Terminal 3+ — same pattern; each process uses a distinct port offset
  go run main.go node --role=validator --port-offset=2 \
      --seeds=127.0.0.1:30303 --pbft

  WALLET RPC = 8700 + --port-offset; UDP discovery port = TCP + 1000.
`)
}

// StartPBFTNodeMode is a compatibility wrapper around bind.StartNode.
//
// portOffset is a LOCAL addressing convenience (default listen ports + default
// datadir) and never affects validator membership.
func StartPBFTNodeMode(dataDir string, nodeConfig network.NodePortConfig, portOffset int, vdfParams *consensus.VDFParams, rewardAddress string) error {
	return bind.StartNode(dataDir, nodeConfig, portOffset, vdfParams, "devnet", "", rewardAddress)
}

// runNodeCmd handles the "node" subcommand
func runNodeCmd(args []string) error {
	fs := flag.NewFlagSet("node", flag.ExitOnError)

	role := fs.String("role", "validator", "Node role: validator | sender | receiver | none")
	tcpAddr := fs.String("tcp-addr", defaultTCPAddr, "TCP address for P2P (host:port)")
	udpPort := fs.String("udp-port", "", "UDP port for peer discovery (defaults to this node's TCP port + 1000)")
	httpPort := fs.String("http-port", defaultHTTPAddr, "HTTP JSON-RPC listen address")
	wsPort := fs.String("ws-port", defaultWSAddr, "WebSocket/wallet-RPC listen address")
	seeds := fs.String("seeds", "", "Comma-separated seed node UDP addresses or enrtree:// DNS discovery URLs")
	dataDir := fs.String("datadir", "data", "Directory for LevelDB storage")
	portOffset := fs.Int("port-offset", 0, "Per-process port offset: shifts ONLY the default tcp/http/udp/wallet-RPC ports (and the default datadir). It never changes a validator's node ID or membership.")
	configFile := fs.String("config", "", "Path to JSON node-config file (optional)")
	pbftMode := fs.Bool("pbft", false, "Enable PBFT consensus mode")
	mode := fs.String("mode", "development", "Run mode: development, production")
	networkFlag := fs.String("network", "devnet", "Network type: devnet, testnet, mainnet")
	rewardAddress := fs.String("reward-address", "", common.SPIFPrefix+" wallet address to stake and receive block rewards from (required for real validator participation; peers verify its on-chain balance before granting validator status — see help for details)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// --port-offset shifts ONLY the default listen ports and the default
	// datadir. It is a local addressing convenience for running several node
	// processes on one machine; it never selects a mode, a validator set, or a
	// node identity. An explicit --tcp-addr/--http-port/--ws-port/--datadir
	// always wins.
	applyPortOffset(*portOffset, tcpAddr, httpPort, wsPort, dataDir)
	common.SetDataDir(*dataDir)

	// Build the NodePortConfig for THIS process. A node no longer describes a
	// slot in a pre-agreed set of N nodes — only its own listen addresses.
	// Validator membership comes from chain state (genesis + Stake txs), never
	// from a count supplied on the command line.
	var nodeConfig network.NodePortConfig

	if *configFile != "" {
		configs, err := network.LoadFromFile(*configFile)
		if err != nil {
			return fmt.Errorf("failed to load config file: %v", err)
		}
		nodeConfig, err = configFileEntry(configs, *portOffset)
		if err != nil {
			return err
		}
	} else {
		nodeConfig = network.NodePortConfig{
			TCPAddr:  *tcpAddr,
			UDPPort:  *udpPort,
			HTTPPort: *httpPort,
			WSPort:   *wsPort,
			Role:     bind.ParseRoles(*role, 1)[0],
		}
	}

	// Set defaults if not already set
	if nodeConfig.TCPAddr == "" {
		nodeConfig.TCPAddr = *tcpAddr
	}
	if nodeConfig.UDPPort == "" {
		nodeConfig.UDPPort = *udpPort
	}
	if nodeConfig.HTTPPort == "" {
		nodeConfig.HTTPPort = *httpPort
	}
	if nodeConfig.WSPort == "" {
		nodeConfig.WSPort = *wsPort
	}

	// Fail production shapes before any devnet/localnet side effect can run.
	// bind.StartNode validates the selected genesis document against the same
	// pin after loading it; this guard catches unsafe command shapes earlier.
	if err := validateProductionNodeStart(*mode, *networkFlag, nodeConfig.TCPAddr, *dataDir, *seeds, *portOffset); err != nil {
		return err
	}

	// Multisig treasury spend broadcast is always on — no flags, no
	// destination or amount to configure, and no custodian keys. The node
	// doesn't need to be told what to spend: it scans config/spend_proposals
	// for spends the custodian quorum already signed (each carries its own
	// destination/amount/nonce inside the signed payload), re-verifies each
	// against the live policy, and broadcasts it. It never authorizes a spend
	// on its own — the node re-verifies the witness at admission too (see
	// multisig.CheckSpendWitness).
	//
	// Genesis distribution and CGE vesting release are separate, already-
	// automatic flows (block 0 minting and applyCGEReleases respectively);
	// this watcher does not touch either.
	var autoSpendArgs []string
	// ★ DEVNET BUNDLE FETCH — must run BEFORE anything touches genesis and
	// before custody setup: a joiner (seeds != "") with an incomplete
	// local bundle fetches the PUBLIC bundle over the network from its seeds,
	// verifying the document before it touches disk, retrying while the
	// bootstrap is still signing. Network transport only; custody/ never.
	if wait, ferr := bind.EnsureDevnetBundleFromSeeds(*networkFlag, *seeds, *dataDir); ferr != nil {
		return fmt.Errorf("devnet bundle fetch: %w", ferr)
	} else if wait > 0 {
		logger.Info("DEVNET BUNDLE: joiner waited %s for the bootstrap bundle", wait.Round(time.Second))
	}
	proposalsDir := core.CustodyProposalsDirForDataDir(*dataDir)
	if _, statErr := os.Stat(proposalsDir); statErr != nil && *dataDir != "" {
		if _, legacyErr := os.Stat(custodyProposalsDir); legacyErr == nil {
			proposalsDir = custodyProposalsDir
		}
	}

	// ★ REPORT THE EFFECTIVE UDP PORT, NOT THE EMPTY FLAG.
	//
	// --udp-port deliberately defaults to "" so that bind can derive the DHT
	// port from the node's own TCP address as TCP+1000 (see sameBoxDHTUDPPort
	// and the bind SECTION 7 wiring). Logging nodeConfig.UDPPort verbatim
	// therefore printed "udp=" with nothing after it on every single node, even
	// though a real discovery port was in use — which reads as "discovery is
	// off" in exactly the log line an operator checks when peers fail to
	// connect. Resolve the same TCP+1000 value here so the startup line
	// reports what the node will actually bind, and keeps matching the README.
	effectiveUDPPort := nodeConfig.UDPPort
	if effectiveUDPPort == "" {
		if _, portStr, splitErr := net.SplitHostPort(nodeConfig.TCPAddr); splitErr == nil && portStr != "" {
			if tcpPortNum, convErr := strconv.Atoi(portStr); convErr == nil {
				effectiveUDPPort = strconv.Itoa(tcpPortNum + bind.DHTUDPPortOffset)
			}
		}
	}
	if effectiveUDPPort == "" {
		effectiveUDPPort = "(derived at bind)"
	}

	logger.Info("Starting node role=%s tcp=%s udp=%s rpc=%s seeds=%q data=%s pbft=%v mode=%s network=%s",
		*role, nodeConfig.TCPAddr, effectiveUDPPort, nodeConfig.HTTPPort, *seeds, *dataDir, *pbftMode, *mode, *networkFlag)

	// ── Peer discovery is decided by flags/config, never by a node count ──
	//
	// A node's start-up behaviour does not depend on how many other nodes the
	// operator expects to exist:
	//   - a non-empty --seeds (plain addresses and/or enrtree:// DNS trees)
	//     makes the node dial out and discover peers via seeds + PEX/DHT;
	//   - no --seeds means the node relies on inbound connections and any
	//     default DNS tree the network config defines.
	// Validator membership is never inferred here — it comes from chain state
	// (the genesis file, then on-chain Stake/Unstake transactions). A small
	// peer count while the validator set is large is a liveness condition, not
	// a configuration error, and is never treated as one.
	if *pbftMode && strings.TrimSpace(*seeds) == "" {
		logger.Info("PBFT enabled with no --seeds: relying on inbound peers / default discovery tree; validator set comes from chain state")
	}

	// Threshold-gated multisig watch loop runs alongside the node in THIS
	// process whenever a multisig policy is provisioned — every node runs
	// it identically, no flags, no per-terminal configuration. The watcher
	// may reach its first cycle before this node's wallet RPC is listening;
	// an unreadable balance is transient and simply retries next interval.
	if autoSpendArgs != nil {
		logger.Info("auto multisig spend enabled: %s", strings.Join(autoSpendArgs, " "))
		go func() {
			if err := runMultisigSpend(autoSpendArgs); err != nil {
				logger.Error("auto multisig spend watcher stopped: %v", err)
			} else {
				logger.Info("auto multisig spend watcher stopped")
			}
		}()
	}

	var vdfParams *consensus.VDFParams

	// ════════════════════════════════════════════════════════════════════
	// ★ DEVNET AUTO-CUSTODY MUST BE THE FIRST THING THAT TOUCHES GENESIS.
	//
	// bind.StartNode derives VDF parameters after it has authored or loaded the
	// complete genesis document. The CLI must not call core.GetGenesisHash()
	// earlier: on a cold devnet datadir auto-custody has written only the
	// policy/witness sections at this point, so an eager hash would freeze a
	// zero-validator genesis before StartNode can add this validator.
	// ════════════════════════════════════════════════════════════════════
	custody, custodyErr := core.AutoProvisionDevnetCustody(core.DevnetCustodyOptions{
		NetworkType:   *networkFlag,
		BootstrapNode: *seeds == "",
		DataDir:       *dataDir,
	})
	if custodyErr != nil {
		return fmt.Errorf("devnet auto-custody: %w", custodyErr)
	}
	if custody != nil && custody.Enabled {
		if violErr := core.GenesisCustodyOrderingViolation(); violErr != nil {
			return fmt.Errorf("devnet auto-custody: %w", violErr)
		}
		logger.Warn("DEVNET AUTO-CUSTODY armed before genesis: vault=%s escrow=%s signer=%v replay=%v",
			custody.VaultAddress, custody.EscrowAddress, custody.SigningNode, custody.ReplayNode)
	}
	genesisDoc, genesisErr := core.LoadGenesisFile(*dataDir)
	if genesisErr != nil {
		if !os.IsNotExist(genesisErr) {
			return fmt.Errorf("load genesis document for custody watcher: %w", genesisErr)
		}
	} else if genesisDoc != nil && genesisDoc.EscrowMultisig != nil {
		if _, err := core.LoadEscrowPolicy(*dataDir); err != nil {
			return fmt.Errorf("load escrow policy from genesis document: %w", err)
		}
		// Dial the SAME address bind.StartNode binds. Reading the flag
		// (*wsPort) here instead of nodeConfig.WSPort made a --config node
		// listen on the file's ws_port while this watcher dialled
		// 8700+offset.
		walletRPC := network.ResolveWalletRPCAddr(nodeConfig.WSPort, *portOffset)
		spendArgs, err := autoWatchArgs(
			core.GenesisStateFilePathForDataDir(*dataDir), walletRPC, proposalsDir)
		if err != nil {
			return err
		}
		autoSpendArgs = spendArgs
	} else {
		logger.Info("no escrow_multisig section in %s — auto multisig spend watcher disabled (run \"multisig devnet --role escrow\" to enable treasury spends)",
			core.GenesisStateFilePathForDataDir(*dataDir))
	}

	if *pbftMode {
		logger.Info("═══════════════════════════════════════════════════════════════")
		logger.Info("=== STARTING PBFT CONSENSUS MODE ===")
		logger.Info("The validator set comes from chain state (the genesis document + Stake transactions), not from a node count")
		logger.Info("")
		logger.Info("QUORUM (identical at every height, including block 1)")
		logger.Info("   - a block commits only when validators holding STRICTLY > 2/3 of the")
		logger.Info("     staked validator set's total stake have voted")
		logger.Info("   - no stake means no vote: unstaked peers never reach quorum")
		logger.Info("   - there is no 'blocks 0-1 need no stake' phase")
		logger.Info("   - VDF-derived leader selection runs over that same staked set")
		logger.Info("═══════════════════════════════════════════════════════════════")
		logger.Info("VDF parameters will be derived after genesis is authored/loaded")

		logger.Info("Node will continue running - press Ctrl+C to stop")

		return bind.StartNode(*dataDir, nodeConfig, *portOffset, vdfParams, *networkFlag, *seeds, *rewardAddress)
	}

	// Single node mode — PBFT not requested on the command line. Consensus
	// still activates on its own once the genesis/staked validator set reaches
	// the BFT minimum; nothing here waits for a peer count.
	logger.Info("=== STARTING NODE WITHOUT --pbft ===")
	logger.Info("Consensus is driven by the on-chain validator set; --pbft only tunes startup logging")
	logger.Info("Node will continue running - press Ctrl+C to stop")

	return bind.StartNode(*dataDir, nodeConfig, *portOffset, nil, *networkFlag, *seeds, *rewardAddress)
}

// runSendTxCmd handles the "send-tx" subcommand
func runSendTxCmd(args []string) error {
	fs := flag.NewFlagSet("send-tx", flag.ExitOnError)

	rpcURL := fs.String("rpc", "http://127.0.0.1:8545", "JSON-RPC endpoint of the source node")
	from := fs.String("from", "", "Sender address (required)")
	to := fs.String("to", "", "Receiver address (required)")
	amount := fs.String("amount", "0", "Amount in SPX (e.g. 100)")
	gasLimit := fs.String("gas-limit", "21000", "Gas limit")
	gasPrice := fs.String("gas-price", "1", "Gas price in gSPX")
	nonce := fs.Uint64("nonce", 0, "Sender nonce (omit to auto-fetch)")
	keyFile := fs.String("key", "", "Path to private key file (optional; uses node key if omitted)")
	wait := fs.Bool("wait", true, "Wait for transaction confirmation before returning")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" || *to == "" {
		return fmt.Errorf("--from and --to are required")
	}

	return SendTransaction(SendTxOptions{
		RPCURL:   *rpcURL,
		From:     *from,
		To:       *to,
		Amount:   *amount,
		GasLimit: *gasLimit,
		GasPrice: *gasPrice,
		Nonce:    *nonce,
		KeyFile:  *keyFile,
		Wait:     *wait,
	})
}

// runGetBalanceCmd handles the "get-balance" subcommand
func runGetBalanceCmd(args []string) error {
	fs := flag.NewFlagSet("get-balance", flag.ExitOnError)

	rpcURL := fs.String("rpc", "127.0.0.1:8700", "wallet JSON-RPC address (host:port)")
	address := fs.String("address", "", "Address to query (required)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *address == "" {
		return fmt.Errorf("--address is required")
	}

	return GetBalance(GetBalanceOptions{
		RPCURL:  *rpcURL,
		Address: *address,
	})
}

// runWatchTxCmd handles the "watch-tx" subcommand
func runWatchTxCmd(args []string) error {
	fs := flag.NewFlagSet("watch-tx", flag.ExitOnError)

	rpcURL := fs.String("rpc", "http://127.0.0.1:8545", "JSON-RPC endpoint")
	txID := fs.String("txid", "", "Transaction ID to watch (required)")
	timeoutSecs := fs.Int("timeout", 120, "Seconds before giving up")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *txID == "" {
		return fmt.Errorf("--txid is required")
	}

	return WatchTransaction(WatchTxOptions{
		RPCURL:      *rpcURL,
		TxID:        *txID,
		TimeoutSecs: *timeoutSecs,
	})
}

func runStakeCmd(args []string) error {
	fs := flag.NewFlagSet("stake", flag.ContinueOnError)
	rpcURL := fs.String("rpc", "http://127.0.0.1:8545", "JSON-RPC endpoint")
	action := fs.String("action", "", "stake or unstake")
	from := fs.String("from", "", "SPIF address funding the stake (required)")
	validatorID := fs.String("validator-id", "", "Node identity to admit or exit (required)")
	validatorKeyFile := fs.String("validator-key", "", "Node identity keys directory or private.key file (required for stake)")
	amount := fs.String("amount", "", "Stake amount in whole SPX (required for stake)")
	gasLimit := fs.String("gas-limit", "21000", "Gas limit")
	gasPrice := fs.String("gas-price", "1", "Gas price in gSPX")
	nonce := fs.Uint64("nonce", 0, "Sender nonce (omit to auto-fetch)")
	keyFile := fs.String("key", "", "Path to private key file (required)")
	wait := fs.Bool("wait", true, "Wait for transaction confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *action != "stake" && *action != "unstake" {
		return fmt.Errorf("--action must be stake or unstake")
	}
	if *from == "" || *validatorID == "" || *keyFile == "" {
		return fmt.Errorf("--from, --validator-id, and --key are required")
	}
	if *action == "stake" && *validatorKeyFile == "" {
		return fmt.Errorf("--validator-key is required for stake")
	}
	if !common.ValidateSPIFAddress(*from) {
		return fmt.Errorf("invalid SPIF address %q", *from)
	}
	return SendStakeTransaction(StakeTxOptions{
		RPCURL:           *rpcURL,
		Action:           *action,
		From:             *from,
		ValidatorID:      *validatorID,
		ValidatorKeyFile: *validatorKeyFile,
		Amount:           *amount,
		GasLimit:         *gasLimit,
		GasPrice:         *gasPrice,
		Nonce:            *nonce,
		KeyFile:          *keyFile,
		Wait:             *wait,
	})
}

func runSlashCmd(args []string) error {
	fs := flag.NewFlagSet("slash", flag.ContinueOnError)
	rpcURL := fs.String("rpc", "http://127.0.0.1:8545", "JSON-RPC endpoint")
	from := fs.String("from", "", "SPIF address paying the transaction fee (required)")
	evidenceFile := fs.String("evidence", "", "JSON file containing signed conflicting votes (required)")
	gasLimit := fs.String("gas-limit", "21000", "Gas limit")
	gasPrice := fs.String("gas-price", "1", "Gas price in gSPX")
	nonce := fs.Uint64("nonce", 0, "Sender nonce (omit to auto-fetch)")
	keyFile := fs.String("key", "", "Path to transaction signing key file (required)")
	wait := fs.Bool("wait", true, "Wait for transaction confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" || *evidenceFile == "" || *keyFile == "" {
		return fmt.Errorf("--from, --evidence, and --key are required")
	}
	if !common.ValidateSPIFAddress(*from) {
		return fmt.Errorf("invalid SPIF address %q", *from)
	}
	return SendDoubleSignEvidenceTransaction(SlashTxOptions{
		RPCURL:       *rpcURL,
		From:         *from,
		EvidenceFile: *evidenceFile,
		GasLimit:     *gasLimit,
		GasPrice:     *gasPrice,
		Nonce:        *nonce,
		KeyFile:      *keyFile,
		Wait:         *wait,
	})
}

// configFileEntry resolves --config to THIS process's node configuration.
//
// A --config file describes one node's listen addresses, so a single-node
// document is the expected shape. When the file holds exactly one entry it is
// used as-is, whatever --port-offset is (the offset has already shifted the
// flag defaults, and an explicit --config always wins over them).
//
// ★ REPORTED, NOT DECIDED (Phase 1, item B): this USED to be
// `if *portOffset < 0 || *portOffset >= len(configs) { error }; nodeConfig =
// configs[*portOffset]` — i.e. --port-offset was an INDEX into the config file.
// That is the same class of limit as the removed index range check that Phase 1
// removed, and it contradicts --port-offset's documented contract ("shifts ONLY the
// default tcp/http/udp/wallet-RPC ports and the default datadir; never changes
// a validator's node ID or membership"). --port-offset is a LOCAL addressing
// convenience; a config file is an operator-authored description of one node's
// addresses. Indexing one by the other couples two unrelated things and makes
// a multi-entry file a de-facto pre-agreed node roster again.
//
// A file with more than one entry is therefore AMBIGUOUS, not out of range. It
// is refused with a message that names the alternatives, because picking one
// silently would be exactly the "which node am I?" decision this whole change
// set exists to remove. Restoring multi-entry support (one entry per --port-offset
// value, or an explicit --select/--name) is a deliberate API decision and is
// left to the operator.
func configFileEntry(configs []network.NodePortConfig, portOffset int) (network.NodePortConfig, error) {
	switch {
	case len(configs) == 0:
		return network.NodePortConfig{}, fmt.Errorf("--config file holds no node entries")
	case len(configs) == 1:
		return configs[0], nil
	default:
		return network.NodePortConfig{}, fmt.Errorf(
			"--config file holds %d node entries, but a --config file describes ONE node's listen addresses. "+
				"Use a single-entry file (--port-offset is a local port/datadir shift and is deliberately NOT an index into this file). "+
				"If you intended to run several nodes, give each one its own config file, or pass --tcp-addr/--http-port/--ws-port/--datadir per process "+
				"(portOffset=%d)", len(configs), portOffset)
	}
}

// legacyExecute handles the original flag-parsing path
func legacyExecute() error {
	cfg := &Config{}

	flag.StringVar(&cfg.configFile, "config", "", "Path to node configuration JSON file")
	flag.StringVar(&cfg.roles, "roles", "none", "Comma-separated node roles")
	flag.StringVar(&cfg.tcpAddr, "tcp-addr", "", "TCP address (e.g., 127.0.0.1:30303)")
	flag.StringVar(&cfg.udpPort, "udp-port", "", "UDP port for discovery (e.g., 30304)")
	flag.StringVar(&cfg.httpPort, "http-port", "", "HTTP port for API (e.g., 127.0.0.1:8545)")
	flag.StringVar(&cfg.wsPort, "ws-port", "", "WebSocket port (e.g., 127.0.0.1:8600)")
	flag.StringVar(&cfg.seedNodes, "seeds", "", "Comma-separated seed node UDP addresses or enrtree:// DNS discovery URLs")
	flag.StringVar(&cfg.dataDir, "datadir", "data", "Directory for LevelDB storage")
	flag.IntVar(&cfg.portOffset, "port-offset", 0, "Per-process port offset (shifts only default listen ports and datadir)")
	flag.StringVar(&cfg.rewardAddress, "reward-address", "", common.SPIFPrefix+" wallet address to stake and receive block rewards from")

	flag.Parse()

	if flag.NFlag() == 0 {
		return fmt.Errorf("no flags or subcommand given — run with 'help' for usage, " +
			"or pass -datadir/-seeds/etc. to start a production node " +
			"(the recommended form is the 'node' subcommand: go run main.go node --help)")
	}

	var nodeConfig network.NodePortConfig

	if cfg.configFile != "" {
		configs, err := network.LoadFromFile(cfg.configFile)
		if err != nil {
			return fmt.Errorf("failed to load config file: %v", err)
		}
		nodeConfig, err = configFileEntry(configs, cfg.portOffset)
		if err != nil {
			return err
		}
	} else {
		nodeConfig = network.NodePortConfig{
			TCPAddr:  cfg.tcpAddr,
			UDPPort:  cfg.udpPort,
			HTTPPort: cfg.httpPort,
			WSPort:   cfg.wsPort,
			Role:     bind.ParseRoles(cfg.roles, 1)[0],
		}
	}

	return bind.StartNode(cfg.dataDir, nodeConfig, cfg.portOffset, nil, "devnet", cfg.seedNodes, cfg.rewardAddress)
}

// runWalletCmd handles the "wallet" subcommand
func runWalletCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("wallet subcommand requires 'init', 'list', 'burn' or 'send'")
	}

	switch args[0] {
	case "init":
		return runWalletInitCmd(args[1:])
	case "list":
		return runWalletListCmd(args[1:])
	case "burn":
		return runWalletBurnCmd(args[1:])
	case "send":
		return runWalletSendCmd(args[1:])
	default:
		return fmt.Errorf("unknown wallet subcommand %q — use 'init', 'list', 'burn', or 'send'", args[0])
	}
}

// runWalletInitCmd handles "wallet init"
func runWalletInitCmd(args []string) error {
	fs := flag.NewFlagSet("wallet init", flag.ExitOnError)

	passphrase := fs.String("passphrase", "", "Passphrase to encrypt the wallet (required)")
	network := fs.String("network", "mainnet", "Network: mainnet, testnet, devnet")
	label := fs.String("label", "", "Human-readable label for the wallet")
	dataDir := fs.String("datadir", "", "Directory for wallet data (default: ~/.sphinx/wallet)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *passphrase == "" {
		return fmt.Errorf("--passphrase is required")
	}

	info, err := InitWallet(WalletConfig{
		Passphrase: *passphrase,
		Network:    *network,
		Label:      *label,
		DataDir:    *dataDir,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize wallet: %w", err)
	}

	fmt.Printf("\nWallet initialized successfully!\n\n")
	fmt.Printf("Address:        %s\n", info.Address)
	fmt.Printf("Public Key:     %s...\n", info.PublicKeyHex[:32])
	fmt.Printf("Network:        %s (ChainID: %d)\n", info.Network, info.ChainID)
	fmt.Printf("Key File:       %s\n", info.KeyFile)
	fmt.Printf("Created:        %s\n\n", info.CreatedAt)
	fmt.Printf("Next steps:\n")
	fmt.Printf("  1. Fund this address with SPX tokens\n")
	fmt.Printf("  2. Send transactions: sphinx-cli send-tx --from %s --to <RECIPIENT> --amount <AMOUNT> --key %s\n", info.Address, info.KeyFile)
	fmt.Printf("  3. Run a validator: sphinx-cli node --role=validator --reward-address=%s\n\n", info.Address)

	return nil
}

// runWalletBurnCmd handles "wallet burn" — burn ceremony tooling.
//
//   - `wallet burn --show-default` prints the protocol's default,
//     hardcoded burn address (no key material involved).
//   - `wallet burn --new` runs a fresh one-time burn ceremony: a real
//     SPHINCS+ key pair is generated with an ephemeral random passphrase that
//     is wiped immediately, nothing is written to disk, and only the new DEAD
//     address + public key are printed for the operator to record.
func runWalletBurnCmd(args []string) error {
	fs := flag.NewFlagSet("wallet burn", flag.ExitOnError)

	showDefault := fs.Bool("show-default", false, "Print the protocol default burn address")
	newCeremony := fs.Bool("new", false, "Run a fresh one-time burn ceremony (nothing is saved to disk)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Default: show the canonical burn address.
	if !*newCeremony || *showDefault {
		fmt.Printf("\nDefault burn address (provably unspendable):\n\n")
		fmt.Printf("  Address:    %s\n", common.DefaultBurnAddress)
		fmt.Printf("  Public Key: %s\n\n", common.DefaultBurnPublicKeyHex)
		fmt.Printf("To burn coins, send SPX to that address:\n")
		fmt.Printf("  sphinx-cli send-tx --from <YOUR_SPIF_ADDRESS> --to \"%s\" --amount <AMOUNT> --key <KEYFILE>\n\n", common.DefaultBurnAddress)
		fmt.Printf("Note: DEAD addresses are receive-only — consensus rejects any\n")
		fmt.Printf("transaction that tries to spend FROM a burn address.\n\n")
		if !*newCeremony {
			return nil
		}
	}

	info, err := BurnAddressCeremony()
	if err != nil {
		return fmt.Errorf("burn ceremony failed: %w", err)
	}

	fmt.Printf("\nFresh burn ceremony complete (NOT saved — record these now):\n\n")
	fmt.Printf("  Address:    %s\n", info.Address)
	fmt.Printf("  Public Key: %s\n\n", info.PublicKeyHex)
	fmt.Printf("The private key was destroyed: the random passphrase was wiped from\n")
	fmt.Printf("memory and the encrypted blob was never written to disk. No one —\n")
	fmt.Printf("including you — can ever spend from this address. To use it, send\n")
	fmt.Printf("SPX to it like any other recipient.\n\n")
	return nil
}

// runWalletListCmd handles "wallet list"
func runWalletListCmd(args []string) error {
	dataDir := ""
	if len(args) > 0 && !isFlag(args[0]) {
		dataDir = args[0]
	}

	wallets, err := ListWallets(dataDir)
	if err != nil {
		return fmt.Errorf("failed to list wallets: %w", err)
	}

	if len(wallets) == 0 {
		fmt.Println("No wallets found. Create one with: sphinx-cli wallet init")
		return nil
	}

	fmt.Printf("\nFound %d wallet(s):\n\n", len(wallets))
	for i, w := range wallets {
		fmt.Printf("%d. Address:      %s\n", i+1, w.Address)
		fmt.Printf("   Public Key:   %s...\n", w.PublicKeyHex[:32])
		fmt.Printf("   Network:      %s\n", w.Network)
		fmt.Printf("   Key File:     %s\n", w.KeyFile)
		fmt.Printf("   Fingerprint:  %s\n\n", w.Fingerprint)
	}
	return nil
}

// runWalletSendCmd handles "wallet send" — send SPX using key file
// This finds the key file for the sender address and uses it to sign the transaction
func runWalletSendCmd(args []string) error {
	fs := flag.NewFlagSet("wallet send", flag.ExitOnError)

	rpcURL := fs.String("rpc", "http://127.0.0.1:8545", "JSON-RPC endpoint")
	from := fs.String("from", "", "Sender "+common.SPIFPrefix+" address (required)")
	to := fs.String("to", "", "Recipient "+common.SPIFPrefix+" address (required)")
	amount := fs.String("amount", "", "Amount in SPX (required)")
	dataDir := fs.String("datadir", "", "Wallet data directory (default: ~/.sphinx/wallet)")
	wait := fs.Bool("wait", true, "Wait for transaction confirmation")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" || *to == "" || *amount == "" {
		return fmt.Errorf("--from, --to, and --amount are required")
	}

	// Validate addresses using common/hexutil.go
	if !common.ValidateSPIFAddress(*from) {
		return fmt.Errorf("invalid sender "+common.SPIFPrefix+" address: %s", *from)
	}
	if !common.ValidateSPIFAddress(*to) {
		return fmt.Errorf("invalid recipient "+common.SPIFPrefix+" address: %s", *to)
	}

	// Determine wallet directory
	walletDir := *dataDir
	if walletDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory: %w", err)
		}
		walletDir = filepath.Join(home, ".sphinx", "wallet")
	}

	fmt.Printf("Sending %s SPX from %s to %s...\n", *amount, *from, *to)

	// Find the key file for this address
	keyFile, err := findKeyFileForAddress(walletDir, *from)
	if err != nil {
		return fmt.Errorf("failed to find key file for address %s: %w", *from, err)
	}

	// Load the private key from the key file
	// Note: The key file contains the encrypted private key as hex
	// For full vault integration with passphrase decryption, use the USI GUI pattern
	skBytes, err := loadKeyFromKeyFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to load key: %w", err)
	}

	// Use the existing send-tx path with the loaded key
	// Write key to temp file for send-tx path
	tmpKeyFile, err := writeTempKeyFile(skBytes, *from)
	if err != nil {
		return fmt.Errorf("failed to create temp key file: %w", err)
	}
	defer os.Remove(tmpKeyFile)

	return SendTransaction(SendTxOptions{
		RPCURL:   *rpcURL,
		From:     *from,
		To:       *to,
		Amount:   *amount,
		GasLimit: "21000",
		GasPrice: "1",
		Nonce:    0, // auto-fetch
		KeyFile:  tmpKeyFile,
		Wait:     *wait,
	})
}

// loadKeyFromKeyFile loads a SPHINCS+ private key from a key file
// The key file contains the private key as hex-encoded string
func loadKeyFromKeyFile(keyFile string) ([]byte, error) {
	// Read the key file
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Parse the key file
	var keyFileData struct {
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
	}
	if err := json.Unmarshal(data, &keyFileData); err != nil {
		return nil, fmt.Errorf("failed to parse key file: %w", err)
	}

	// Decode the private key (it's stored as hex in the key file)
	skBytes, err := hex.DecodeString(keyFileData.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	return skBytes, nil
}

// writeTempKeyFile writes a temporary key file for use with SendTransaction
func writeTempKeyFile(skBytes []byte, address string) (string, error) {
	tmpDir := os.TempDir()
	tmpFile := filepath.Join(tmpDir, fmt.Sprintf("sphinx-key-%s.json", address[:16]))

	keyData := map[string]string{
		"private_key": hex.EncodeToString(skBytes),
		"address":     address,
	}

	data, err := json.Marshal(keyData)
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return "", err
	}

	return tmpFile, nil
}

// findKeyFileForAddress finds the .key.json file for a given SPIF address
func findKeyFileForAddress(dataDir, address string) (string, error) {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return "", err
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".key.json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dataDir, entry.Name()))
		if err != nil {
			continue
		}
		var info struct {
			Address string `json:"address"`
		}
		if err := json.Unmarshal(data, &info); err != nil {
			continue
		}
		if info.Address == address {
			return filepath.Join(dataDir, entry.Name()), nil
		}
	}
	return "", fmt.Errorf("no key file found for address %s in %s", address, dataDir)
}

// runIPFSCmd handles the "ipfs" subcommand with mint/verify/repin sub-subcommands.
func runIPFSCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("ipfs subcommand requires 'mint', 'verify' or 'repin'")
	}

	switch args[0] {
	case "mint":
		return runIPFSMintCmd(args[1:])
	case "verify":
		return runIPFSVerifyCmd(args[1:])
	case "repin":
		return runIPFSRepinCmd(args[1:])
	default:
		return fmt.Errorf("unknown ipfs subcommand %q — use 'mint', 'verify' or 'repin'", args[0])
	}
}

// runIPFSMintCmd handles "ipfs mint" — upload content to IPFS and anchor on Sphinx.
func runIPFSMintCmd(args []string) error {
	fs := flag.NewFlagSet("ipfs mint", flag.ExitOnError)

	rpcURL := fs.String("rpc", "http://127.0.0.1:8545", "Sphinx node JSON-RPC endpoint")
	subject := fs.String("subject", "", "Subject/creator of the NFT (required)")
	name := fs.String("name", "", "NFT name (required)")
	description := fs.String("description", "", "NFT description")
	imageURL := fs.String("image", "", "Image URL (IPFS URI or HTTP)")
	externalURL := fs.String("external-url", "", "External URL for the NFT")
	contentFile := fs.String("content-file", "", "Path to raw content file to upload")
	ipfsAddr := fs.String("ipfs-addr", "", "IPFS API address (default from SPHINX_IPFS_ADDR, else http://127.0.0.1:5001)")
	gatewayURL := fs.String("gateway", "", "IPFS gateway base URL (default from SPHINX_IPFS_GATEWAY, else http://127.0.0.1:8080)")
	disableIPFS := fs.Bool("disable-ipfs", false, "Explicitly mint with NO upload: records a local content hash (spxhash-…) instead of a retrievable IPFS CID. The mint is still anchored, but nobody can fetch the content — this is an opt-in, offline-only mode")
	mintID := fs.String("mint-id", "", "Mint ID (auto-generated if empty)")
	from := fs.String("from", "", "Sender address for the on-chain transaction (required)")
	keyFile := fs.String("key", "", "Path to private key file for signing (required)")
	gasLimit := fs.String("gas-limit", "50000", "Gas limit for the anchor transaction")
	gasPrice := fs.String("gas-price", "1", "Gas price in gSPX")
	wait := fs.Bool("wait", true, "Wait for transaction confirmation")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *subject == "" {
		return fmt.Errorf("--subject is required")
	}
	if *name == "" && *contentFile == "" {
		return fmt.Errorf("either --name (for metadata) or --content-file (for raw content) is required")
	}
	if *from == "" {
		return fmt.Errorf("--from (sender address) is required for the on-chain anchor transaction")
	}
	if *keyFile == "" {
		return fmt.Errorf("--key (private key file) is required for signing the on-chain transaction")
	}

	var content []byte
	if *contentFile != "" {
		var err error
		content, err = os.ReadFile(*contentFile)
		if err != nil {
			return fmt.Errorf("read content file: %w", err)
		}
	}

	_, err := RunMint(MintOptions{
		RPCURL:         *rpcURL,
		Subject:        *subject,
		Name:           *name,
		Description:    *description,
		Image:          *imageURL,
		ExternalURL:    *externalURL,
		Content:        content,
		ContentFile:    *contentFile,
		IPFSAddr:       *ipfsAddr,
		GatewayBaseURL: *gatewayURL,
		DisableIPFS:    *disableIPFS,
		MintID:         *mintID,
		From:           *from,
		KeyFile:        *keyFile,
		GasLimit:       *gasLimit,
		GasPrice:       *gasPrice,
		Wait:           *wait,
	})
	return err
}

// runIPFSRepinCmd handles "ipfs repin" — re-pin the payload behind an existing
// anchor so media that only ever lived on the minter's disk stays retrievable
// going forward (and report the per-anchor evidence an audit needs).
func runIPFSRepinCmd(args []string) error {
	fs := flag.NewFlagSet("ipfs repin", flag.ExitOnError)

	rpcURL := fs.String("rpc", "http://127.0.0.1:8545", "Sphinx node JSON-RPC endpoint")
	mintID := fs.String("mint-id", "", "Mint ID whose recorded commitment should be re-pinned")
	txID := fs.String("txid", "", "Transaction ID (on-chain anchor) to re-pin — preferred, it reads the permanent record")
	file := fs.String("file", "", "Path to the ORIGINAL payload file the mint committed to (required)")
	ipfsAddr := fs.String("ipfs-addr", "", "IPFS API address (default from SPHINX_IPFS_ADDR, else http://127.0.0.1:5001)")
	gatewayURL := fs.String("gateway", "", "IPFS gateway base URL (default from SPHINX_IPFS_GATEWAY, else http://127.0.0.1:8080)")
	jsonOut := fs.Bool("json", false, "Emit the result as JSON (useful for audit collection)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *mintID == "" && *txID == "" {
		return fmt.Errorf("either --mint-id or --txid is required")
	}

	result, err := RunRepin(RepinOptions{
		RPCURL:         *rpcURL,
		MintID:         *mintID,
		TxID:           *txID,
		File:           *file,
		IPFSAddr:       *ipfsAddr,
		GatewayBaseURL: *gatewayURL,
	})
	if err != nil {
		return err
	}
	if *jsonOut && result != nil {
		enc, encErr := json.MarshalIndent(result, "", "  ")
		if encErr != nil {
			return encErr
		}
		fmt.Printf("%s\n", enc)
	}
	// A refusal (mismatched file, failed pin) is reported inside the result;
	// surface it as a non-zero exit so scripts cannot mistake it for success.
	if result != nil && result.Error != "" {
		return fmt.Errorf("%s", result.Error)
	}
	return nil
}
func runIPFSVerifyCmd(args []string) error {
	fs := flag.NewFlagSet("ipfs verify", flag.ExitOnError)

	rpcURL := fs.String("rpc", "http://127.0.0.1:8545", "Sphinx node JSON-RPC endpoint")
	mintID := fs.String("mint-id", "", "Mint ID to verify")
	txID := fs.String("txid", "", "Transaction ID (on-chain anchor) to verify")
	gatewayURL := fs.String("gateway", "", "IPFS gateway base URL (defaults to https://ipfs.io)")
	skipFetch := fs.Bool("skip-fetch", false, "Skip fetching content from IPFS gateway")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *mintID == "" && *txID == "" {
		return fmt.Errorf("either --mint-id or --txid is required")
	}

	_, err := RunVerify(VerifyOptions{
		RPCURL:           *rpcURL,
		MintID:           *mintID,
		TxID:             *txID,
		GatewayBaseURL:   *gatewayURL,
		SkipContentFetch: *skipFetch,
	})
	return err
}
