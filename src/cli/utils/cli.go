// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/cli/utils/cli.gos
package utils

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/sphinxorg/protocol/src/bind"
	"github.com/sphinxorg/protocol/src/consensus"
	"github.com/sphinxorg/protocol/src/core"
	logger "github.com/sphinxorg/protocol/src/log"
	"github.com/sphinxorg/protocol/src/network"
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
	logger.Info(`Sphinx blockchain CLI

SUBCOMMANDS
  node          Start a validator node (mines genesis block, distributes vault funds)
  send-tx       Send a transaction from one address to another
  get-balance   Query the balance of an address
  watch-tx      Poll until a transaction is confirmed

HYBRID CONSENSUS INFORMATION
  Blocks 0-1:   VDF-PBFT (no stake required for validators)
  Blocks 2+:    VDF+Stake PBFT (validators must have minimum stake)

QUICK START
  # Terminal 1 – Validator Node (First node - creates genesis block & distributes funds)
  go run main.go node --role=validator --tcp-addr=127.0.0.1:30303 \
      --udp-port=30304 --http-port=127.0.0.1:8545 --datadir=data/validator --pbft

  # Terminal 2 – Second Validator Node
  go run main.go node --role=validator --tcp-addr=127.0.0.1:30304 \
      --udp-port=30305 --http-port=127.0.0.1:8546 --datadir=data/validator2 \
      --node-index=1 --nodes=3 --pbft

  # Terminal 3 – Third Validator Node
  go run main.go node --role=validator --tcp-addr=127.0.0.1:30305 \
      --udp-port=30306 --http-port=127.0.0.1:8547 --datadir=data/validator3 \
      --node-index=2 --nodes=3 --pbft

LEGACY COMMANDS
  go run main.go -test-nodes=3     Run PBFT integration test (single process)
  go run main.go                   Run default two-node network (single process)`)
}

// StartPBFTNodeMode is a wrapper for StartDistributedNode to maintain compatibility
func StartPBFTNodeMode(dataDir string, nodeConfig network.NodePortConfig, totalNodes, nodeIndex int, vdfParams *consensus.VDFParams) error {
	return StartNode(dataDir, nodeConfig, totalNodes, nodeIndex, vdfParams, "devnet")
}

// runNodeCmd handles the "node" subcommand
func runNodeCmd(args []string) error {
	fs := flag.NewFlagSet("node", flag.ExitOnError)

	role := fs.String("role", "validator", "Node role: validator | sender | receiver | none")
	tcpAddr := fs.String("tcp-addr", "127.0.0.1:30303", "TCP address for P2P (host:port)")
	udpPort := fs.String("udp-port", "30304", "UDP port for peer discovery")
	httpPort := fs.String("http-port", "127.0.0.1:8545", "HTTP JSON-RPC listen address")
	wsPort := fs.String("ws-port", "127.0.0.1:8600", "WebSocket listen address")
	seeds := fs.String("seeds", "", "Comma-separated seed node UDP addresses")
	dataDir := fs.String("datadir", "data", "Directory for LevelDB storage")
	nodeIndex := fs.Int("node-index", 0, "Node index when sharing a config file")
	configFile := fs.String("config", "", "Path to JSON node-config file (optional)")
	numNodes := fs.Int("nodes", 1, "Total nodes in the network (used for config generation)")
	pbftMode := fs.Bool("pbft", false, "Enable PBFT consensus mode (requires at least 3 nodes total)")
	mode := fs.String("mode", "development", "Run mode: development, production")
	maxPeers := fs.Int("max-peers", 50, "Maximum peer connections (production mode)")
	networkFlag := fs.String("network", "devnet", "Network type: devnet, testnet, mainnet")

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

	logger.Infof("Starting node role=%s tcp=%s udp=%s rpc=%s seeds=%q data=%s pbft=%v mode=%s network=%s",
		*role, nodeConfig.TCPAddr, nodeConfig.UDPPort, nodeConfig.HTTPPort, *seeds, *dataDir, *pbftMode, *mode, *networkFlag)

	// Check PBFT requirements
	if *pbftMode && *numNodes < 3 {
		return fmt.Errorf("PBFT mode requires at least 3 total nodes (--nodes=3), got %d", *numNodes)
	}

	var vdfParams *consensus.VDFParams

	if *pbftMode {
		logger.Info("═══════════════════════════════════════════════════════════════")
		logger.Info("=== STARTING HYBRID PBFT CONSENSUS MODE ===")
		logger.Info("This node will participate in hybrid consensus with %d total validators", *numNodes)
		logger.Info("")
		logger.Info("🔓 PHASE 1 (Blocks 0-1): VDF-PBFT (no stake required)")
		logger.Info("   - All nodes can participate as validators")
		logger.Info("   - VDF-based leader selection only")
		logger.Info("   - Genesis block and Block 1 use this phase")
		logger.Info("")
		logger.Info("🔒 PHASE 2 (Blocks 2+): VDF+Stake PBFT")
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

		logger.Info("✅ VDF parameters derived successfully:")
		logger.Info("   Discriminant D: %d bits", vdfParams.Discriminant.BitLen())
		logger.Info("   T (iterations): %d", vdfParams.T)

		logger.Info("Node will continue running - press Ctrl+C to stop")

		return StartNode(*dataDir, nodeConfig, *numNodes, *nodeIndex, vdfParams, *networkFlag)
	}

	// Single node mode
	logger.Info("=== STARTING SINGLE NODE MODE (NO PBFT) ===")
	logger.Info("This mode is for development/testing only")
	logger.Info("To participate in hybrid consensus and mine blocks:")
	logger.Info("  1. Start 2 more validator nodes with --pbft flag")
	logger.Info("  2. Total 3+ nodes will enable PBFT consensus")
	logger.Info("Node will continue running - press Ctrl+C to stop")

	return StartNode(*dataDir, nodeConfig, *numNodes, *nodeIndex, nil, *networkFlag)
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
	flag.StringVar(&cfg.seedNodes, "seeds", "", "Comma-separated seed node UDP addresses")
	flag.StringVar(&cfg.dataDir, "datadir", "data", "Directory for LevelDB storage")
	flag.IntVar(&cfg.nodeIndex, "node-index", 0, "Index of the node to run")
	flag.IntVar(&testCfg.NumNodes, "test-nodes", 0,
		"Run the PBFT integration test with N validator nodes (0 = disabled)")

	flag.Parse()

	if flag.NFlag() == 0 {
		return bind.RunMultipleNodesInternal()
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

	return StartNode(cfg.dataDir, nodeConfig, cfg.numNodes, cfg.nodeIndex, nil, "devnet")
}
