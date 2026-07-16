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
		case "ipfs":
			return runIPFSCmd(os.Args[2:])
		case "wallet":
			return runWalletCmd(os.Args[2:])
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

func printHelp() {
	// Use fmt.Print directly to avoid format string parsing issues
	// since the help text contains % characters that logger.Info would try to parse
	fmt.Print(`Sphinx blockchain CLI

SUBCOMMANDS
  node          Start a validator node
  send-tx       Send a transaction from one address to another
  get-balance   Query the balance of an address
  watch-tx      Poll until a transaction is confirmed
  ipfs          IPFS + on-chain NFT mint and verify
  wallet        Manage SPIF wallets (init, list)

TOKENOMICS OVERVIEW
  Genesis Supply: 1,240,000,000 SPX (24.8% of 5B max supply)
  Funding Rounds:
    Angel Round: 30,000,000 SPX @ $0.06 = $1.8M
    Private Sale: 70,000,000 SPX @ $0.24 = $16.8M
    Public ICO: 100,000,000 SPX @ $0.36 = $36.0M
    Total Raised: $54.6M (200,000,000 SPX sold, 16.1% of genesis)

HYBRID CONSENSUS INFORMATION
  Blocks 0-1:   VDF-PBFT (no stake required for validators)
  Blocks 2+:    VDF+Stake PBFT (validators must have minimum stake)

REAL-DEVICE QUICK START (ETH/BTC style — no pre-agreed node count)
  Each machine runs independently; peer discovery is via --seeds.
  Nodes can join or leave the network at any time — late joiners automatically
  sync the full blockchain from peers before participating in consensus.

  # Node 1 (bootnode / first validator)
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

  PBFT activates automatically once >= 3 validators are connected.
  Late-joining nodes sync automatically and join consensus when caught up.
  No --nodes or --node-index required.

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

SAME-BOX / DEV QUICK START (all nodes on one machine)
  For local development and testing. Nodes can be started in any order and
  late-joining nodes will automatically sync from peers.

  # Terminal 1 — first validator (creates genesis block)
  go run main.go node --role=validator --tcp-addr=127.0.0.1:30303 \
      --udp-port=30304 --http-port=127.0.0.1:8545 --datadir=data/validator \
      --nodes=3 --pbft

  # Terminal 2 — can be started anytime, even after Terminal 1 is running
  go run main.go node --role=validator --tcp-addr=127.0.0.1:30304 \
      --udp-port=30305 --http-port=127.0.0.1:8546 --datadir=data/validator2 \
      --node-index=1 --nodes=3 --pbft

  # Terminal 3 — can also be delayed; will sync automatically
  go run main.go node --role=validator --tcp-addr=127.0.0.1:30305 \
      --udp-port=30306 --http-port=127.0.0.1:8547 --datadir=data/validator3 \
      --node-index=2 --nodes=3 --pbft

  TIP: To test late-joiner sync, start Terminal 1, wait for it to produce a few
  blocks, then start Terminal 2 and/or 3 — they will automatically catch up.

LEGACY COMMANDS
  go run main.go -test-nodes=3     Run PBFT integration test (single process)
  go run main.go                   Run default two-node network (single process)
`)
}

// StartPBFTNodeMode is a wrapper for StartDistributedNode to maintain compatibility
func StartPBFTNodeMode(dataDir string, nodeConfig network.NodePortConfig, totalNodes, nodeIndex int, vdfParams *consensus.VDFParams, rewardAddress string) error {
	return bind.StartNode(dataDir, nodeConfig, totalNodes, nodeIndex, vdfParams, "devnet", "", rewardAddress)
}

// runNodeCmd handles the "node" subcommand
func runNodeCmd(args []string) error {
	fs := flag.NewFlagSet("node", flag.ExitOnError)

	role := fs.String("role", "validator", "Node role: validator | sender | receiver | none")
	tcpAddr := fs.String("tcp-addr", "127.0.0.1:30303", "TCP address for P2P (host:port)")
	udpPort := fs.String("udp-port", "30304", "UDP port for peer discovery")
	httpPort := fs.String("http-port", "127.0.0.1:8545", "HTTP JSON-RPC listen address")
	wsPort := fs.String("ws-port", "127.0.0.1:8600", "WebSocket listen address")
	seeds := fs.String("seeds", "", "Comma-separated seed node UDP addresses or enrtree:// DNS discovery URLs")
	dataDir := fs.String("datadir", "data", "Directory for LevelDB storage")
	nodeIndex := fs.Int("node-index", 0, "Node index within this machine's port range (same-box harness only; ignored in real-device mode)")
	configFile := fs.String("config", "", "Path to JSON node-config file (optional)")
	numNodes := fs.Int("nodes", 1, "Total nodes in the network (same-box harness only; real-device mode discovers validators dynamically)")
	pbftMode := fs.Bool("pbft", false, "Enable PBFT consensus mode")
	mode := fs.String("mode", "development", "Run mode: development, production")
	maxPeers := fs.Int("max-peers", 50, "Maximum peer connections (production mode)")
	networkFlag := fs.String("network", "devnet", "Network type: devnet, testnet, mainnet")
	rewardAddress := fs.String("reward-address", "", "SPIF wallet address to stake and receive block rewards from (required for real validator participation; peers verify its on-chain balance before granting validator status — see help for details)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Build the NodePortConfig using network package
	var nodeConfig network.NodePortConfig

	if *configFile != "" {
		configs, err := network.LoadFromFile(*configFile)
		if err != nil {
			return fmt.Errorf("failed to load config file: %v", err)
		}
		if *nodeIndex < 0 || *nodeIndex >= len(configs) {
			return fmt.Errorf("node-index %d out of range for %d configs", *nodeIndex, len(configs))
		}
		nodeConfig = configs[*nodeIndex]
	} else {
		roles := bind.ParseRoles(*role, *numNodes)

		flagOverrides := map[string]string{}
		if *tcpAddr != "" {
			flagOverrides[fmt.Sprintf("tcpAddr%d", *nodeIndex)] = *tcpAddr
		}
		if *udpPort != "" {
			flagOverrides[fmt.Sprintf("udpPort%d", *nodeIndex)] = *udpPort
		}
		if *httpPort != "" {
			flagOverrides[fmt.Sprintf("httpPort%d", *nodeIndex)] = *httpPort
		}
		if *wsPort != "" {
			flagOverrides[fmt.Sprintf("wsPort%d", *nodeIndex)] = *wsPort
		}
		if *seeds != "" {
			flagOverrides["seeds"] = *seeds
		}
		if *mode == "production" {
			flagOverrides["maxPeers"] = strconv.Itoa(*maxPeers)
		}

		configs, err := network.GetNodePortConfigs(*numNodes, roles, flagOverrides)
		if err != nil {
			return fmt.Errorf("failed to generate node configs: %v", err)
		}
		if *nodeIndex < 0 || *nodeIndex >= len(configs) {
			return fmt.Errorf("node-index %d out of range for %d nodes", *nodeIndex, *numNodes)
		}
		nodeConfig = configs[*nodeIndex]
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

	logger.Info("Starting node role=%s tcp=%s udp=%s rpc=%s seeds=%q data=%s pbft=%v mode=%s network=%s",
		*role, nodeConfig.TCPAddr, nodeConfig.UDPPort, nodeConfig.HTTPPort, *seeds, *dataDir, *pbftMode, *mode, *networkFlag)

	// ── Determine mode: real-device, seed-based, or same-box ──
	//
	// real-device mode: non-loopback --tcp-addr (public IP or hostname).
	//   Peers discovered dynamically via --seeds / DNS + PEX.
	//   --nodes and --node-index are ignored.
	//
	// seed-based mode: loopback --tcp-addr WITH --seeds provided.
	//   Like real-device mode: the node discovers peers via --seeds.
	//   --nodes and --node-index are NOT required (no same-box harness).
	//   This is the recommended way to test late-joiner sync on localhost.
	//
	// same-box mode: loopback --tcp-addr WITHOUT --seeds.
	//   Uses the legacy hardcoded 32307+ port range.
	//   Requires --nodes=3 and --node-index for peer pre-registration.
	isRealDevice := false
	isSeedBased := false
	if *tcpAddr != "" {
		host, _, splitErr := net.SplitHostPort(*tcpAddr)
		if splitErr != nil {
			host = *tcpAddr
		}
		if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
			isRealDevice = true
		} else if host != "" && host != "localhost" && net.ParseIP(host) == nil {
			isRealDevice = true // hostname, assume non-loopback
		}
	}
	// If --seeds is provided (even for loopback), treat as seed-based mode.
	// The node discovers peers dynamically and does NOT need the same-box
	// harness with pre-registered peer addresses.
	if *seeds != "" && strings.TrimSpace(*seeds) != "" {
		isSeedBased = true
	}

	if *pbftMode && !isRealDevice && !isSeedBased && *numNodes < 3 {
		return fmt.Errorf("same-box PBFT mode requires at least 3 total nodes (--nodes=3), got %d", *numNodes)
	}
	// ★ FIX: In seed-based mode (loopback with --seeds), preserve --nodes for
	// local multi-node testing. Only set numNodes=1 for true real-device mode
	// (non-loopback IP). This allows 3-node local testing with --seeds to work
	// correctly.
	if *pbftMode && isRealDevice && *numNodes > 1 {
		logger.Info("Real-device mode (non-loopback IP): --nodes=%d ignored; validator count derived from peer discovery", *numNodes)
		*numNodes = 1 // normalise so same-box harness arrays aren't synthesised
	}
	// For seed-based mode on loopback, keep the user's --nodes value so that
	// local multi-node tests (e.g., 3 nodes with --seeds=127.0.0.1:30303) work.

	var vdfParams *consensus.VDFParams

	if *pbftMode {
		logger.Info("═══════════════════════════════════════════════════════════════")
		logger.Info("=== STARTING HYBRID PBFT CONSENSUS MODE ===")
		logger.Info("This node will participate in hybrid consensus with %d total validators", *numNodes)
		logger.Info("")
		logger.Info("PHASE 1 (Blocks 0-1): VDF-PBFT (no stake required)")
		logger.Info("   - All nodes can participate as validators")
		logger.Info("   - VDF-based leader selection only")
		logger.Info("   - Genesis block and Block 1 use this phase")
		logger.Info("")
		logger.Info("PHASE 2 (Blocks 2+): VDF+Stake PBFT")
		logger.Info("   - Validators must have minimum stake")
		logger.Info("   - VDF + stake-based leader selection")
		logger.Info("   - Secure consensus after initial distribution")
		logger.Info("═══════════════════════════════════════════════════════════════")

		if *mode == "production" && *numNodes > 100 {
			logger.Info("Production optimization: Limited peer connections enabled")
		}

		// Derive VDF parameters
		expectedGenesisHash := core.GetGenesisHash()
		logger.Info("Deriving VDF parameters from genesis hash: %s", expectedGenesisHash)

		rawGenesisHash := expectedGenesisHash
		if len(rawGenesisHash) > 8 && rawGenesisHash[:8] == "GENESIS_" {
			rawGenesisHash = rawGenesisHash[8:]
			logger.Info("Using raw genesis hash: %s", rawGenesisHash)
		}

		consensus.InitVDFFromGenesis(func() (string, error) {
			return rawGenesisHash, nil
		})

		vdfParamsTemp, err := consensus.LoadCanonicalVDFParams()
		if err != nil {
			return fmt.Errorf("failed to load VDF parameters: %w", err)
		}
		vdfParams = &vdfParamsTemp

		logger.Info("VDF parameters derived successfully:")
		logger.Info("   Discriminant D: %d bits", vdfParams.Discriminant.BitLen())
		logger.Info("   T (iterations): %d", vdfParams.T)

		logger.Info("Node will continue running - press Ctrl+C to stop")

		return bind.StartNode(*dataDir, nodeConfig, *numNodes, *nodeIndex, vdfParams, *networkFlag, *seeds, *rewardAddress)
	}

	// Single node mode
	logger.Info("=== STARTING SINGLE NODE MODE (NO PBFT) ===")
	logger.Info("This mode is for development/testing only")
	logger.Info("To participate in hybrid consensus and mine blocks:")
	logger.Info("  1. Start 2 more validator nodes with --pbft flag")
	logger.Info("  2. Total 3+ nodes will enable PBFT consensus")
	logger.Info("Node will continue running - press Ctrl+C to stop")

	return bind.StartNode(*dataDir, nodeConfig, *numNodes, *nodeIndex, nil, *networkFlag, *seeds, *rewardAddress)
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

	rpcURL := fs.String("rpc", "http://127.0.0.1:8545", "JSON-RPC endpoint")
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

// legacyExecute handles the original flag-parsing path
func legacyExecute() error {
	cfg := &Config{}
	testCfg := &TestConfig{}

	flag.StringVar(&cfg.configFile, "config", "", "Path to node configuration JSON file")
	flag.IntVar(&cfg.numNodes, "nodes", 1, "Number of nodes to initialise")
	flag.StringVar(&cfg.roles, "roles", "none", "Comma-separated node roles")
	flag.StringVar(&cfg.tcpAddr, "tcp-addr", "", "TCP address (e.g., 127.0.0.1:30303)")
	flag.StringVar(&cfg.udpPort, "udp-port", "", "UDP port for discovery (e.g., 30304)")
	flag.StringVar(&cfg.httpPort, "http-port", "", "HTTP port for API (e.g., 127.0.0.1:8545)")
	flag.StringVar(&cfg.wsPort, "ws-port", "", "WebSocket port (e.g., 127.0.0.1:8600)")
	flag.StringVar(&cfg.seedNodes, "seeds", "", "Comma-separated seed node UDP addresses or enrtree:// DNS discovery URLs")
	flag.StringVar(&cfg.dataDir, "datadir", "data", "Directory for LevelDB storage")
	flag.IntVar(&cfg.nodeIndex, "node-index", 0, "Index of the node to run")
	flag.StringVar(&cfg.rewardAddress, "reward-address", "", "SPIF wallet address to stake and receive block rewards from")
	flag.IntVar(&testCfg.NumNodes, "test-nodes", 0,
		"Run the PBFT integration test with N validator nodes (0 = disabled)")

	flag.BoolVar(&cfg.legacyCluster, "legacy-cluster", false,
		"Run the deprecated same-process 3-node devnet harness (requires simultaneous "+
			"startup, does not support late-joining nodes). Opt-in only.")

	flag.Parse()

	if cfg.legacyCluster {
		logger.Warn("-legacy-cluster requested: using RunMultipleNodesInternal(), " +
			"a same-process 3-node harness that does NOT support late joiners. " +
			"Use the 'node' subcommand or -seeds for production multi-node networks.")
		return bind.RunMultipleNodesInternal()
	}

	if flag.NFlag() == 0 {
		return fmt.Errorf("no flags or subcommand given — run with 'help' for usage, " +
			"or pass -datadir/-seeds/etc. to start a production node " +
			"(pass -legacy-cluster to explicitly opt into the deprecated same-process harness)")
	}

	var nodeConfig network.NodePortConfig

	if cfg.configFile != "" {
		configs, err := network.LoadFromFile(cfg.configFile)
		if err != nil {
			return fmt.Errorf("failed to load config file: %v", err)
		}
		if cfg.nodeIndex < 0 || cfg.nodeIndex >= len(configs) {
			return fmt.Errorf("node-index %d out of range for %d configs", cfg.nodeIndex, len(configs))
		}
		nodeConfig = configs[cfg.nodeIndex]
	} else {
		roles := bind.ParseRoles(cfg.roles, cfg.numNodes)
		flagOverrides := make(map[string]string)

		if cfg.tcpAddr != "" {
			flagOverrides[fmt.Sprintf("tcpAddr%d", cfg.nodeIndex)] = cfg.tcpAddr
		}
		if cfg.udpPort != "" {
			flagOverrides[fmt.Sprintf("udpPort%d", cfg.nodeIndex)] = cfg.udpPort
		}
		if cfg.httpPort != "" {
			flagOverrides[fmt.Sprintf("httpPort%d", cfg.nodeIndex)] = cfg.httpPort
		}
		if cfg.wsPort != "" {
			flagOverrides[fmt.Sprintf("wsPort%d", cfg.nodeIndex)] = cfg.wsPort
		}
		if cfg.seedNodes != "" {
			flagOverrides["seeds"] = cfg.seedNodes
		}

		configs, err := network.GetNodePortConfigs(cfg.numNodes, roles, flagOverrides)
		if err != nil {
			return fmt.Errorf("failed to generate node configs: %v", err)
		}
		if cfg.nodeIndex < 0 || cfg.nodeIndex >= len(configs) {
			return fmt.Errorf("node-index %d out of range for %d nodes", cfg.nodeIndex, cfg.numNodes)
		}
		nodeConfig = configs[cfg.nodeIndex]
	}

	return bind.StartNode(cfg.dataDir, nodeConfig, cfg.numNodes, cfg.nodeIndex, nil, "devnet", cfg.seedNodes, cfg.rewardAddress)
}

// runWalletCmd handles the "wallet" subcommand
func runWalletCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("wallet subcommand requires 'init' or 'list'")
	}

	switch args[0] {
	case "init":
		return runWalletInitCmd(args[1:])
	case "list":
		return runWalletListCmd(args[1:])
	case "send":
		return runWalletSendCmd(args[1:])
	default:
		return fmt.Errorf("unknown wallet subcommand %q — use 'init', 'list', or 'send'", args[0])
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
	from := fs.String("from", "", "Sender SPIF address (required)")
	to := fs.String("to", "", "Recipient SPIF address (required)")
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
		return fmt.Errorf("invalid sender SPIF address: %s", *from)
	}
	if !common.ValidateSPIFAddress(*to) {
		return fmt.Errorf("invalid recipient SPIF address: %s", *to)
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

// runIPFSCmd handles the "ipfs" subcommand with mint/verify sub-subcommands.
func runIPFSCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("ipfs subcommand requires 'mint' or 'verify'")
	}

	switch args[0] {
	case "mint":
		return runIPFSMintCmd(args[1:])
	case "verify":
		return runIPFSVerifyCmd(args[1:])
	default:
		return fmt.Errorf("unknown ipfs subcommand %q — use 'mint' or 'verify'", args[0])
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
	ipfsAddr := fs.String("ipfs-addr", "http://127.0.0.1:5001", "IPFS API address")
	gatewayURL := fs.String("gateway", "http://127.0.0.1:8080", "IPFS gateway base URL")
	disableIPFS := fs.Bool("disable-ipfs", false, "Disable real IPFS and use fallback mode")
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

// runIPFSVerifyCmd handles "ipfs verify" — verify a minted NFT on Sphinx + IPFS.
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
