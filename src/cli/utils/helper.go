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

// go/src/cli/utils/helper.go
package utils

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sphinxorg/protocol/src/common"
	"github.com/sphinxorg/protocol/src/consensus"
	"github.com/sphinxorg/protocol/src/core"
	config "github.com/sphinxorg/protocol/src/core/sphincs/config"
	key "github.com/sphinxorg/protocol/src/core/sphincs/key/backend"

	sign "github.com/sphinxorg/protocol/src/core/sphincs/sign/backend"
	database "github.com/sphinxorg/protocol/src/core/state"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	security "github.com/sphinxorg/protocol/src/handshake"
	logger "github.com/sphinxorg/protocol/src/log"
	"github.com/sphinxorg/protocol/src/network"
	"github.com/sphinxorg/protocol/src/params/commit"
	params "github.com/sphinxorg/protocol/src/params/denom"
	"github.com/sphinxorg/protocol/src/rpc"
	"github.com/sphinxorg/protocol/src/state"
	"github.com/syndtr/goleveldb/leveldb"
)

// CallConsensus runs the full PBFT integration test using natural stake-weighted
// RANDAO leader election instead of manually forcing a leader.
func CallConsensus(numNodes int) error {
	if numNodes < 3 {
		return fmt.Errorf("PBFT requires at least 3 validator nodes, got %d", numNodes)
	}

	// State variables for tracking test progress
	var firstBlock consensus.Block
	var firstGenesisHash string

	// ========== BLOCKCHAIN IDENTIFICATION AND CONFIGURATION ==========
	logger.Info("=== SPHINX BLOCKCHAIN IDENTIFICATION ===")

	// Retrieve and display mainnet chain parameters
	chainParams := commit.SphinxChainParams()
	logger.Info("Chain: %s", chainParams.ChainName)
	logger.Info("Chain ID: %d", chainParams.ChainID)
	logger.Info("Symbol: %s", chainParams.Symbol)
	logger.Info("Protocol Version: %s", chainParams.Version)
	logger.Info("Genesis Time: %s", time.Unix(chainParams.GenesisTime, 0).Format(time.RFC1123))
	logger.Info("Genesis Hash: %s", chainParams.GenesisHash)
	logger.Info("Magic Number: 0x%x", chainParams.MagicNumber)
	logger.Info("Default Port: %d", chainParams.DefaultPort)
	logger.Info("BIP44 Coin Type: %d", chainParams.BIP44CoinType)
	logger.Info("Ledger Name: %s", chainParams.LedgerName)

	// Display SPX token economics and denominations
	tokenInfo := params.GetSPXTokenInfo()
	logger.Info("Token Name: %s", tokenInfo.Name)
	logger.Info("Token Symbol: %s", tokenInfo.Symbol)
	logger.Info("Decimals: %d", tokenInfo.Decimals)
	logger.Info("Total Supply: %.2f %s", float64(tokenInfo.TotalSupply), tokenInfo.Symbol)
	logger.Info("Base Unit: nSPX (1e0)")
	logger.Info("Intermediate Unit: gSPX (1e9)")
	logger.Info("Main Unit: SPX (1e18)")

	// Generate and display standard wallet derivation paths
	walletPaths := map[string]string{
		"BIP44":  fmt.Sprintf("m/44'/%d'/0'/0/0", chainParams.BIP44CoinType),
		"BIP49":  fmt.Sprintf("m/49'/%d'/0'/0/0", chainParams.BIP44CoinType),
		"BIP84":  fmt.Sprintf("m/84'/%d'/0'/0/0", chainParams.BIP44CoinType),
		"Ledger": fmt.Sprintf("m/44'/%d'/0'", chainParams.BIP44CoinType),
	}
	logger.Info("Wallet Derivation Paths:")
	for name, path := range walletPaths {
		logger.Info("  %s: %s", name, path)
	}

	// Determine network configuration
	networkType := "mainnet"
	networkDisplayName := "Sphinx Mainnet"

	switch chainName := chainParams.ChainName; chainName {
	case "Sphinx Devnet":
		networkType = "devnet"
		networkDisplayName = "Sphinx Devnet"
	case "Sphinx Testnet":
		networkType = "testnet"
		networkDisplayName = "Sphinx Testnet"
	default:
		networkType = "mainnet"
		networkDisplayName = "Sphinx Mainnet"
	}

	logger.Info("Network: %s", networkDisplayName)
	logger.Info("Consensus: PBFT")
	logger.Info("========================================")

	// ========== TEST ENVIRONMENT SETUP ==========
	testDataDir := common.DataDir
	if _, err := os.Stat(testDataDir); err == nil {
		logger.Info("Cleaning up previous test data...")
		if err := os.RemoveAll(testDataDir); err != nil {
			return fmt.Errorf("failed to clean test data: %v", err)
		}
		logger.Info("Previous test data cleaned successfully")
	}

	// Ensure the base data directory exists
	if err := os.MkdirAll(testDataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	// Debug consensus message types
	inspectConsensusTypes()

	// ========== NODE INFRASTRUCTURE INITIALIZATION ==========
	var wg sync.WaitGroup
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize node components
	dbs := make([]*leveldb.DB, numNodes)
	sphincsMgrs := make([]*sign.SphincsManager, numNodes)
	blockchains := make([]*core.Blockchain, numNodes)
	consensusEngines := make([]*consensus.Consensus, numNodes)
	networkNodes := make([]*network.Node, numNodes)

	// Generate network addresses and validator IDs FIRST
	networkAddresses := make([]string, numNodes)
	validatorIDs := make([]string, numNodes)
	for i := 0; i < numNodes; i++ {
		address := fmt.Sprintf("127.0.0.1:%d", 32307+i)
		networkAddresses[i] = address
		validatorIDs[i] = fmt.Sprintf("Node-%s", address)
	}

	// Create a map of signing services for key exchange
	signingServices := make(map[string]*consensus.SigningService)

	// Initialize each validator node
	for i := 0; i < numNodes; i++ {
		address := networkAddresses[i]
		nodeID := validatorIDs[i]

		// Create node data directory
		if err := common.EnsureNodeDirs(address); err != nil {
			return fmt.Errorf("failed to create node directories for %s: %v", address, err)
		}
		logger.Info("Created directories for node: %s", nodeID)

		// Initialize LevelDB storage
		db, err := leveldb.OpenFile(common.GetLevelDBPath(address), nil)
		if err != nil {
			return fmt.Errorf("failed to open LevelDB for node %s: %v", nodeID, err)
		}
		dbs[i] = db

		// Convert LevelDB to database.DB interface
		nodeDB, err := database.NewLevelDB(common.GetLevelDBPath(address))
		if err != nil {
			return fmt.Errorf("failed to create database for node %s: %v", nodeID, err)
		}

		// Create actual network node
		networkNode := network.NewNode(
			address,
			"127.0.0.1",
			fmt.Sprintf("%d", 32307+i),
			fmt.Sprintf("%d", 32308+i),
			true,
			network.RoleValidator,
			nodeDB,
		)

		if networkNode == nil {
			return fmt.Errorf("failed to create network node %s", nodeID)
		}

		networkNodes[i] = networkNode
		logger.Info("Created network node %s with keys stored in config directory", nodeID)

		// Initialize SPHINCS+ cryptographic components
		km, err := key.NewKeyManager()
		if err != nil {
			return err
		}
		sphincsParams, err := config.NewSPHINCSParameters()
		if err != nil {
			return err
		}
		sphincsMgrs[i] = sign.NewSphincsManager(db, km, sphincsParams)

		// ========== NODE MANAGER AND PEER CONNECTIONS ==========
		var dhtInstance network.DHT = nil

		// Initialize node manager
		nodeMgr := network.NewNodeManager(16, dhtInstance, nodeDB)

		// Create and add local node
		if err := nodeMgr.CreateLocalNode(
			address,
			"127.0.0.1",
			fmt.Sprintf("%d", 32307+i),
			fmt.Sprintf("%d", 32308+i),
			network.RoleValidator,
		); err != nil {
			return fmt.Errorf("failed to create local node for node manager: %v", err)
		}

		// Add all validator nodes as peers
		for j := range validatorIDs {
			if i != j {
				remoteAddress := networkAddresses[j]
				remoteNode := network.NewNode(
					remoteAddress,
					"127.0.0.1",
					fmt.Sprintf("%d", 32307+j),
					fmt.Sprintf("%d", 32308+j),
					false,
					network.RoleValidator,
					nil,
				)
				if remoteNode != nil {
					nodeMgr.AddNode(remoteNode)
				}
			}
		}

		logger.Info("%s peer connections established", nodeID)

		// ========== BLOCKCHAIN SETUP ==========
		bc, err := core.NewBlockchain(common.GetBlockchainDataDir(address), nodeID, validatorIDs, networkType)
		if err != nil {
			return fmt.Errorf("node %s blockchain initialization failed: %v", nodeID, err)
		}

		// Capture genesis block from first node for validation
		if i == 0 {
			firstBlock = bc.GetLatestBlock()
			if firstBlock != nil {
				firstGenesisHash = firstBlock.GetHash()
				logger.Info("Captured genesis block: height=%d, hash=%s",
					firstBlock.GetHeight(), firstGenesisHash)
			} else {
				logger.Warn("No genesis block found for node 0")
				firstGenesisHash = "unknown-genesis-hash"
			}
		}

		// Display node chain configuration
		chainInfo := bc.GetChainInfo()
		logger.Info("%s Chain Configuration:", nodeID)
		logger.Info("  Chain: %s", chainInfo["chain_name"])
		logger.Info("  Chain ID: %d", chainInfo["chain_id"])
		logger.Info("  Symbol: %s", chainInfo["symbol"])
		logger.Info("  Version: %s", chainInfo["version"])
		logger.Info("  Magic Number: %s", chainInfo["magic_number"])
		logger.Info("  BIP44 Coin Type: %d", chainInfo["bip44_coin_type"])
		logger.Info("  Ledger Name: %s", chainInfo["ledger_name"])

		// Validate storage layer
		logger.Info("%s: Validating storage layer...", nodeID)
		if debugErr := bc.DebugStorage(); debugErr != nil {
			logger.Warn("%s storage validation warning: %v", nodeID, debugErr)
		}
		blockchains[i] = bc

		// ========== CONSENSUS CONFIGURATION ==========
		testNodeMgr := network.NewCallNodeManager()

		// Add all validator nodes as peers
		for _, id := range validatorIDs {
			testNodeMgr.AddPeer(id)
		}

		// Initialize SPHINCS+ signing service
		keyManager, err := key.NewKeyManager()
		if err != nil {
			return fmt.Errorf("failed to create key manager for node %s: %v", nodeID, err)
		}

		// Get SPHINCS parameters
		sphincsParams, err = config.NewSPHINCSParameters()
		if err != nil {
			return fmt.Errorf("failed to get SPHINCS parameters for node %s: %v", nodeID, err)
		}

		// Initialize SPHINCS manager
		sphincsManager := sign.NewSphincsManager(db, keyManager, sphincsParams)

		// Create signing service
		signingService := consensus.NewSigningService(sphincsManager, keyManager, nodeID)

		// Store the signing service
		signingServices[nodeID] = signingService

		// Get the minimum stake from core chain parameters
		coreChainParams := core.GetSphinxChainParams()
		minStakeAmount := coreChainParams.ConsensusConfig.MinStakeAmount

		// Log it to verify
		minSPX := new(big.Int).Div(minStakeAmount, big.NewInt(1e18))
		logger.Info("📊 Min stake from params: %d SPX (%v nSPX)", minSPX.Uint64(), minStakeAmount)

		// Pass to consensus
		cons := consensus.NewConsensus(
			nodeID,
			testNodeMgr,
			bc,
			signingService,
			bc.CommitBlock,
			minStakeAmount,
		)

		// Initialize stake - now using validator set methods
		validatorSet := cons.GetValidatorSet()
		if validatorSet != nil {
			// Get the minimum stake from the validator set itself
			stakeSPX := validatorSet.GetMinStakeSPX()

			err := validatorSet.AddValidator(nodeID, stakeSPX)
			if err != nil {
				logger.Warn("Failed to add validator %s with stake %d SPX: %v", nodeID, stakeSPX, err)
			} else {
				logger.Info("✅ Validator %s initialized with %d SPX stake (from chain parameters)", nodeID, stakeSPX)
			}
		}

		consensusEngines[i] = cons
		bc.SetConsensusEngine(cons)
		bc.SetConsensus(cons)

		// Register consensus with network layer
		network.RegisterConsensus(nodeID, cons)

		// Set a long timeout to prevent automatic view changes during test
		cons.SetTimeout(1 * time.Hour)

		// Start consensus engine
		if err := cons.Start(); err != nil {
			return fmt.Errorf("failed to start consensus for node %s: %v", nodeID, err)
		}

		// Allow consensus engine to fully initialize
		time.Sleep(100 * time.Millisecond)
	}

	// ========== CROSS-REGISTER ALL VALIDATORS IN EVERY NODE'S VALIDATOR SET ==========
	logger.Info("=== REGISTERING ALL VALIDATORS ACROSS ALL NODES ===")

	coreChainParams := core.GetSphinxChainParams()
	minStakeAmount := coreChainParams.ConsensusConfig.MinStakeAmount
	minSPX := new(big.Int).Div(minStakeAmount, big.NewInt(1e18)).Uint64()

	for i := 0; i < numNodes; i++ {
		vs := consensusEngines[i].GetValidatorSet()
		if vs == nil {
			logger.Warn("Node %s has nil validator set", validatorIDs[i])
			continue
		}
		for j := 0; j < numNodes; j++ {
			if i == j {
				continue
			}
			if err := vs.AddValidator(validatorIDs[j], minSPX); err != nil {
				logger.Warn("Failed to register %s in %s validator set: %v",
					validatorIDs[j], validatorIDs[i], err)
			} else {
				logger.Info("Registered %s in %s validator set with %d SPX",
					validatorIDs[j], validatorIDs[i], minSPX)
			}
		}
		logger.Info("Node %s now has %d validators registered", validatorIDs[i], numNodes)
	}
	logger.Info("=== VALIDATOR CROSS-REGISTRATION COMPLETE ===")

	// ========== GENESIS BLOCK CONSISTENCY VALIDATION ==========
	logger.Info("=== VALIDATING GENESIS BLOCK CONSISTENCY ===")

	expectedGenesisHash := core.GetGenesisHash()
	logger.Info("Expected genesis hash for all nodes: %s", expectedGenesisHash)

	for i := 0; i < numNodes; i++ {
		genesis := blockchains[i].GetLatestBlock()
		if genesis == nil || genesis.GetHeight() != 0 {
			return fmt.Errorf("node %s failed to initialize genesis block", validatorIDs[i])
		}

		actualHash := genesis.GetHash()
		logger.Info("%s genesis: height=%d, hash=%s", validatorIDs[i], genesis.GetHeight(), actualHash)

		if actualHash != expectedGenesisHash {
			normalizedActual := actualHash
			normalizedExpected := expectedGenesisHash

			if strings.HasPrefix(actualHash, "GENESIS_") && len(actualHash) > 8 {
				normalizedActual = actualHash[8:]
			}
			if strings.HasPrefix(expectedGenesisHash, "GENESIS_") && len(expectedGenesisHash) > 8 {
				normalizedExpected = expectedGenesisHash[8:]
			}

			if normalizedActual != normalizedExpected {
				return fmt.Errorf("genesis block hash mismatch: %s=%s (normalized: %s) expected=%s (normalized: %s)",
					validatorIDs[i], actualHash, normalizedActual, expectedGenesisHash, normalizedExpected)
			}
		}
	}
	logger.Info("✅ All nodes have consistent genesis blocks: %s", expectedGenesisHash)

	// ========== KEY EXCHANGE ==========
	logger.Info("=== EXCHANGING PUBLIC KEYS BETWEEN NODES ===")
	exchangePublicKeys(signingServices, validatorIDs)

	// Verify key directories
	logger.Info("=== VERIFYING KEY DIRECTORY CREATION ===")
	for i := 0; i < numNodes; i++ {
		address := networkAddresses[i]
		nodeID := validatorIDs[i]
		keysDir := common.GetKeysDataDir(address)

		if _, err := os.Stat(keysDir); os.IsNotExist(err) {
			logger.Warn("Keys directory not created for node %s: %s", nodeID, keysDir)
		} else {
			logger.Info("Keys directory exists for node %s: %s", nodeID, keysDir)

			privateKeyPath := common.GetPrivateKeyPath(address)
			publicKeyPath := common.GetPublicKeyPath(address)

			if _, err := os.Stat(privateKeyPath); err == nil {
				logger.Info("  Private key file exists: %s", privateKeyPath)
			} else {
				logger.Warn("  Private key file missing: %s", privateKeyPath)
			}

			if _, err := os.Stat(publicKeyPath); err == nil {
				logger.Info("  Public key file exists: %s", publicKeyPath)
			} else {
				logger.Warn("  Public key file missing: %s", publicKeyPath)
			}
		}
	}

	// ========== JSON-RPC SERVER INITIALIZATION ==========
	for i := 0; i < numNodes; i++ {
		address := networkAddresses[i]
		nodeID := validatorIDs[i]

		logger.Info("Setting up RPC server for node with address: %s", address)

		msgCh := make(chan *security.Message, 100)
		rpcSrv := rpc.NewServer(msgCh, blockchains[i])

		go func(ch chan *security.Message, srv *rpc.Server, nodeIdx int, nodeAddr string) {
			for secMsg := range ch {
				if secMsg.Type != "rpc" {
					continue
				}

				data, ok := secMsg.Data.([]byte)
				if !ok {
					logger.Warn("%s: Invalid RPC data type: %T", validatorIDs[nodeIdx], secMsg.Data)
					continue
				}

				var rpcMsg rpc.Message
				if err := rpcMsg.Unmarshal(data); err != nil {
					logger.Warn("%s: Failed to unmarshal RPC message: %v", validatorIDs[nodeIdx], err)
					continue
				}

				resp, err := srv.HandleRequest(data)
				if err != nil {
					logger.Warn("%s: RPC request handling error: %v", validatorIDs[nodeIdx], err)
					continue
				}

				addr := rpcMsg.From.Address.String()
				conn, err := net.Dial("udp", addr)
				if err != nil {
					logger.Warn("%s: Failed to connect to %s: %v", validatorIDs[nodeIdx], addr, err)
					continue
				}
				secResp := &security.Message{Type: "rpc", Data: resp}
				enc, _ := secResp.Encode()
				conn.Write(enc)
				conn.Close()
			}
		}(msgCh, rpcSrv, i, address)

		httpPort := 8545 + i
		logger.Info("%s JSON-RPC server listening on http://127.0.0.1:%d", nodeID, httpPort)
	}

	// Allow nodes to synchronize genesis state
	logger.Info("Synchronizing genesis blocks across nodes...")
	time.Sleep(3 * time.Second)

	// Verify all nodes have properly initialized genesis
	for i := 0; i < numNodes; i++ {
		genesis := blockchains[i].GetLatestBlock()
		if genesis == nil || genesis.GetHeight() != 0 {
			return fmt.Errorf("node %s failed to initialize genesis block", validatorIDs[i])
		}
		logger.Info("%s genesis: height=%d, hash=%s", validatorIDs[i], genesis.GetHeight(), genesis.GetHash())
	}

	// ========== TRANSACTION CREATION AND PROPAGATION ==========
	logger.Info("=== CREATING AND DISTRIBUTING MULTIPLE TRANSACTIONS VIA NOTES ===")

	// Create 10 notes with different balances
	notes := []*types.Note{
		{To: "bob", From: "alice", Fee: 1000.0, Storage: "test-storage-1"},
		{To: "charlie", From: "bob", Fee: 500.0, Storage: "test-storage-2"},
		{To: "alice", From: "charlie", Fee: 200.0, Storage: "test-storage-3"},
		{To: "david", From: "alice", Fee: 1500.0, Storage: "test-storage-4"},
		{To: "emma", From: "bob", Fee: 750.0, Storage: "test-storage-5"},
		{To: "frank", From: "charlie", Fee: 300.0, Storage: "test-storage-6"},
		{To: "grace", From: "david", Fee: 1200.0, Storage: "test-storage-7"},
		{To: "henry", From: "emma", Fee: 800.0, Storage: "test-storage-8"},
		{To: "alice", From: "frank", Fee: 400.0, Storage: "test-storage-9"},
		{To: "bob", From: "grace", Fee: 950.0, Storage: "test-storage-10"},
	}

	// Convert notes to transactions
	transactions := make([]*types.Transaction, len(notes))
	for i, note := range notes {
		transactions[i] = note.ToTxs(uint64(i+1), big.NewInt(21000), big.NewInt(1))
		logger.Info("Created transaction from note: %s → %s (Amount: %s, ID: %s)",
			transactions[i].Sender, transactions[i].Receiver, transactions[i].Amount.String(), transactions[i].ID)
	}

	// Distribute transactions across all nodes
	for i := 0; i < numNodes; i++ {
		nodeID := validatorIDs[i]
		nodeSuccessCount := 0

		for _, tx := range transactions {
			txCopy := &types.Transaction{
				ID:        tx.ID,
				Sender:    tx.Sender,
				Receiver:  tx.Receiver,
				Amount:    new(big.Int).Set(tx.Amount),
				GasLimit:  new(big.Int).Set(tx.GasLimit),
				GasPrice:  new(big.Int).Set(tx.GasPrice),
				Nonce:     tx.Nonce,
				Timestamp: tx.Timestamp,
				Signature: make([]byte, len(tx.Signature)),
			}
			copy(txCopy.Signature, tx.Signature)

			if err := blockchains[i].AddTransaction(txCopy); err != nil {
				logger.Warn("%s failed to add transaction %s: %v", nodeID, tx.ID, err)
			} else {
				nodeSuccessCount++
			}
		}

		logger.Info("%s added %d/%d transactions to mempool", nodeID, nodeSuccessCount, len(transactions))
	}

	// Log transaction details
	logger.Info("=== TRANSACTION DETAILS ===")
	for i, tx := range transactions {
		logger.Info("TX%d: %s → %s (Amount: %s, Gas: %s, ID: %s)",
			i+1, tx.Sender, tx.Receiver, tx.Amount.String(), tx.GasLimit.String(), tx.ID)
	}
	logger.Info("Total transactions created: %d", len(transactions))

	// Give a short time for transactions to propagate
	logger.Info("Waiting briefly for transactions to propagate...")
	time.Sleep(2 * time.Second)

	// ========== NATURAL STAKE-WEIGHTED RANDAO LEADER ELECTION ==========
	// Each consensus engine runs its own stake-weighted RANDAO selection.
	// The terminal will reveal which node is elected and why.
	logger.Info("=== INITIATING NATURAL LEADER ELECTION (STAKE-WEIGHTED RANDAO) ===")
	logger.Info("Running stake-weighted RANDAO proposer selection on all %d nodes...", numNodes)

	for i := 0; i < numNodes; i++ {
		// UpdateLeaderStatus triggers the internal updateLeaderStatus() which:
		//   1. Gets the current slot from TimeConverter
		//   2. Derives the RANDAO seed for that slot
		//   3. Runs StakeWeightedSelector.SelectProposer(epoch, seed)
		//   4. Sets c.isLeader = (selected.ID == c.nodeID)
		// The result is logged as either:
		//   "✅ Node X selected as proposer for slot Y with stake Z SPX"
		//   "Node X NOT selected for slot Y (selected: Y with Z SPX)"
		consensusEngines[i].UpdateLeaderStatus()
	}

	// Brief pause so all goroutines flush their log lines before we read IsLeader()
	time.Sleep(200 * time.Millisecond)

	// ========== REVEAL ELECTION RESULT ==========
	logger.Info("=== LEADER ELECTION RESULT ===")

	electedLeaderIndex := -1
	for i := 0; i < numNodes; i++ {
		if consensusEngines[i].IsLeader() {
			logger.Info("🏆 ELECTED LEADER : %s (stake-weighted RANDAO)", validatorIDs[i])
			electedLeaderIndex = i
		} else {
			logger.Info("   Follower       : %s", validatorIDs[i])
		}
	}

	// Safety fallback: if RANDAO produced no leader (e.g. all stakes equal and
	// slot boundary lands between nodes), fall back to deterministic round-robin
	// for view 0 so the test can complete.
	if electedLeaderIndex == -1 {
		// Log each node's elected leader for diagnosis
		for i := 0; i < numNodes; i++ {
			logger.Error("Node %s electedLeaderID=%s, isLeader=%v",
				validatorIDs[i],
				consensusEngines[i].GetElectedLeaderID(),
				consensusEngines[i].IsLeader())
		}
		return fmt.Errorf("RANDAO elected no leader — all nodes must agree on a single winner; check genesis time alignment")
	}

	leaderNode := blockchains[electedLeaderIndex]
	leaderConsensus := consensusEngines[electedLeaderIndex]
	leaderID := validatorIDs[electedLeaderIndex]

	// Confirm the elected leader's mempool is ready
	pendingTxs := leaderNode.GetMempool().GetPendingTransactions()
	txCount := len(pendingTxs)
	logger.Info("Leader %s has %d pending transactions in mempool.", leaderID, txCount)

	if txCount == 0 {
		return fmt.Errorf("leader mempool is empty, cannot start consensus")
	}

	// ========== LEADER CREATES AND PROPOSES BLOCK ==========
	logger.Info("=== LEADER CREATING BLOCK ===")

	newBlock, err := leaderNode.CreateBlock()
	if err != nil {
		return fmt.Errorf("failed to create block: %v", err)
	}

	logger.Info("✅ Leader %s created block: height=%d, hash=%s, transactions=%d",
		leaderID, newBlock.GetHeight(), newBlock.GetHash(), len(newBlock.Body.TxsList))

	// Wrap in consensus.Block adapter and broadcast proposal to all peers
	consensusBlock := core.NewBlockHelper(newBlock)

	logger.Info("Leader %s proposing block %s...", leaderID, consensusBlock.GetHash())
	if err := leaderConsensus.ProposeBlock(consensusBlock); err != nil {
		logger.Error("❌ Leader %s failed to propose block: %v", leaderID, err)
		return fmt.Errorf("leader failed to propose block: %v", err)
	}
	logger.Info("✅ Block proposed successfully by elected leader %s", leaderID)

	// ========== WAIT FOR CONSENSUS TO COMPLETE ==========
	logger.Info("Waiting for consensus to complete...")
	time.Sleep(2 * time.Second)

	// Enhanced consensus diagnostics
	logger.Info("=== ENHANCED CONSENSUS STATE DIAGNOSTICS ===")
	for i := 0; i < numNodes; i++ {
		leaderStatus := "follower"
		if consensusEngines[i].IsLeader() {
			leaderStatus = "LEADER"
		}
		pendingTxs := blockchains[i].GetMempool().GetPendingTransactions()
		txCount := len(pendingTxs)
		logger.Info("%s: %s, pending_txs=%d", validatorIDs[i], leaderStatus, txCount)
	}
	logger.Info("====================================")

	// Set timeout for consensus completion
	const timeout = 60 * time.Second
	start := time.Now()
	logger.Info("Waiting for block commitment (timeout: %v)...", timeout)

	checkInterval := 1 * time.Second
	progressTicker := time.NewTicker(checkInterval)
	defer progressTicker.Stop()

	lastProgressLog := time.Now()
	timeoutReached := false
	consensusOK := false

	// Monitor for block commitment
	for range progressTicker.C {
		if time.Since(start) > timeout {
			timeoutReached = true
			break
		}

		allAtHeight1 := true
		committedNodes := 0

		for i := 0; i < numNodes; i++ {
			latest := blockchains[i].GetLatestBlock()
			if latest == nil || latest.GetHeight() < 1 {
				allAtHeight1 = false
			} else {
				committedNodes++
			}

			if time.Since(lastProgressLog) > 10*time.Second {
				if latest == nil {
					logger.Info("Progress: %s at height 0 (genesis)", validatorIDs[i])
				} else {
					logger.Info("Progress: %s at height %d", validatorIDs[i], latest.GetHeight())
				}
				lastProgressLog = time.Now()
			}
		}

		if allAtHeight1 {
			logger.Info("🎉 SUCCESS: All %d nodes reached block height 1!", numNodes)
			consensusOK = true
			break
		} else if committedNodes > 0 {
			logger.Info("📈 Progress: %d/%d nodes committed block 1", committedNodes, numNodes)
		}
	}

	if timeoutReached {
		logger.Info("=== CONSENSUS TIMEOUT DIAGNOSTICS ===")
		for i := 0; i < numNodes; i++ {
			latest := blockchains[i].GetLatestBlock()
			hasPendingTxs := false
			if len(transactions) > 0 {
				hasPendingTxs = blockchains[i].HasPendingTx(transactions[0].ID)
			}

			if latest != nil {
				logger.Info("%s: height=%d, hash=%s, pending_txs=%v, leader=%v",
					validatorIDs[i], latest.GetHeight(), latest.GetHash(), hasPendingTxs, consensusEngines[i].IsLeader())
			} else {
				logger.Info("%s: no blocks, pending_txs=%v, leader=%v",
					validatorIDs[i], hasPendingTxs, consensusEngines[i].IsLeader())
			}
		}
		logger.Info("======================================")
		return fmt.Errorf("consensus timeout after %v", timeout)
	}

	// ========== BLOCKCHAIN STATE CONSISTENCY VALIDATION ==========
	firstBlock = blockchains[0].GetLatestBlock()
	if firstBlock == nil {
		return fmt.Errorf("%s has no committed block", validatorIDs[0])
	}
	firstHash := firstBlock.GetHash()
	for i := 1; i < numNodes; i++ {
		block := blockchains[i].GetLatestBlock()
		if block == nil {
			return fmt.Errorf("%s has no committed block", validatorIDs[i])
		}
		h := block.GetHash()
		if h != firstHash {
			return fmt.Errorf("block hash mismatch: %s=%s %s=%s", validatorIDs[0], firstHash, validatorIDs[i], h)
		}
	}

	logger.Info("=== PBFT INTEGRATION TEST SUCCESSFUL ===")

	// ========== COMPREHENSIVE CHAIN STATE CAPTURE ==========
	logger.Info("=== CAPTURING FINAL CHAIN STATE ===")

	nodes := make([]*state.NodeInfo, numNodes)

	for i := 0; i < numNodes; i++ {
		address := networkAddresses[i]
		nodeID := validatorIDs[i]

		logger.Info("Collecting node info for: %s", nodeID)

		b := blockchains[i].GetLatestBlock()
		if b == nil {
			logger.Warn("No block found for node %s", nodeID)
			nodes[i] = &state.NodeInfo{
				NodeID:      nodeID,
				NodeName:    nodeID,
				NodeAddress: address,
				ChainInfo:   make(map[string]interface{}),
				BlockHeight: 0,
				BlockHash:   "no-block",
				MerkleRoot:  "unknown",
				Timestamp:   time.Now().Format(time.RFC3339),
			}
			continue
		}

		var merkleRoot string
		if blockAdapter, ok := b.(*core.BlockHelper); ok {
			underlyingBlock := blockAdapter.GetUnderlyingBlock()
			merkleRootBytes := underlyingBlock.CalculateTxsRoot()
			merkleRoot = hex.EncodeToString(merkleRootBytes)
		} else {
			merkleRoot = "unknown"
			logger.Warn("Could not get underlying block for %s", nodeID)
		}

		chainInfo := blockchains[i].GetChainInfo()
		if chainInfo == nil {
			chainInfo = make(map[string]interface{})
			logger.Warn("Chain info was nil for %s, created empty", nodeID)
		}

		nodeInfo := &state.NodeInfo{
			NodeID:      nodeID,
			NodeName:    nodeID,
			NodeAddress: address,
			ChainInfo:   chainInfo,
			BlockHeight: b.GetHeight(),
			BlockHash:   b.GetHash(),
			MerkleRoot:  merkleRoot,
			Timestamp:   time.Now().Format(time.RFC3339),
		}

		if nodeInfo.NodeID == "" || nodeInfo.NodeName == "" {
			logger.Error("❌ Node info has empty ID/Name for %s", nodeID)
		}

		nodes[i] = nodeInfo
		logger.Info("✅ Collected node info for: %s", nodeID)
	}

	// Final verification
	logger.Info("=== FINAL NODES ARRAY VERIFICATION ===")
	validCount := 0
	for i, node := range nodes {
		if node == nil {
			logger.Error("❌ Node %d is NIL!", i)
		} else if node.NodeID == "" {
			logger.Error("❌ Node %d has empty NodeID!", i)
		} else {
			validCount++
			logger.Info("✅ Node %d: %s (%s) - Height: %d",
				i, node.NodeID, node.NodeAddress, node.BlockHeight)
		}
	}

	if validCount != numNodes {
		logger.Warn("⚠️  Only %d/%d nodes collected properly, but continuing anyway", validCount, numNodes)
	} else {
		logger.Info("✅ All %d nodes collected successfully", validCount)
	}

	logger.Info("=== SAVING CHAIN STATE TO ALL NODES ===")

	for i := 0; i < numNodes; i++ {
		nodeID := validatorIDs[i]
		logger.Info("--- Saving chain state for %s ---", nodeID)

		stateMachine := blockchains[i].GetStateMachine()
		if stateMachine == nil {
			logger.Warn("%s: No state machine available, skipping final state initialization", nodeID)
		} else {
			logger.Info("Initializing final states for %s", nodeID)

			if err := stateMachine.ForcePopulateFinalStates(); err != nil {
				logger.Warn("%s: Failed to populate final states: %v", nodeID, err)
			} else {
				logger.Info("%s: Successfully force populated final states", nodeID)
			}

			stateMachine.SyncFinalStatesNow()
			logger.Info("%s: Synced final states with consensus", nodeID)

			finalStates := stateMachine.GetFinalStates()
			logger.Info("%s: Final states ready - %d entries", nodeID, len(finalStates))

			for j, state := range finalStates {
				if state != nil {
					logger.Info("  %s FinalState %d: block=%s, merkle=%s, status=%s",
						nodeID, j, state.BlockHash, state.MerkleRoot, state.Status)
				}
			}
		}

		if i > 0 {
			time.Sleep(100 * time.Millisecond)
		}

		nodesCopy := make([]*state.NodeInfo, len(nodes))
		copy(nodesCopy, nodes)

		if len(nodesCopy) == 0 {
			logger.Error("❌ nodesCopy is EMPTY for %s!", nodeID)
			continue
		}

		validInCopy := 0
		for j, node := range nodesCopy {
			if node == nil {
				logger.Warn("Node %d in copy is nil for %s", j, nodeID)
			} else {
				validInCopy++
				if node.NodeID == "" {
					logger.Warn("Node %d has empty NodeID for %s", j, nodeID)
				}
			}
		}

		logger.Info("Nodes copy for %s: %d valid nodes out of %d total", nodeID, validInCopy, len(nodesCopy))

		if validInCopy == 0 {
			logger.Error("❌ No valid nodes in copy for %s, skipping save", nodeID)
			continue
		}

		maxRetries := 3
		for attempt := 1; attempt <= maxRetries; attempt++ {
			logger.Info("Attempt %d/%d to save chain state for %s", attempt, maxRetries, nodeID)

			err := blockchains[i].StoreChainState(nodesCopy)
			if err != nil {
				logger.Warn("Attempt %d failed for %s: %v", attempt, nodeID, err)

				if attempt == maxRetries {
					logger.Error("❌ ALL attempts failed for %s", nodeID)

					logger.Info("Trying fallback basic state save for %s", nodeID)
					if basicErr := blockchains[i].SaveBasicChainState(); basicErr != nil {
						logger.Error("❌ Basic state also failed for %s: %v", nodeID, basicErr)
					} else {
						logger.Info("✅ Basic state saved as fallback for %s", nodeID)
					}
				} else {
					time.Sleep(200 * time.Millisecond)
				}
			} else {
				logger.Info("✅ Successfully saved chain state for %s on attempt %d", nodeID, attempt)
				break
			}
		}
	}

	logger.Info("=== CHAIN STATE CAPTURE COMPLETED ===")

	// Display detailed block information
	logger.Info("=== BLOCK DATA WITH MERKLE ROOTS ===")
	for i := 0; i < numNodes; i++ {
		latestBlock := blockchains[i].GetLatestBlock()
		if latestBlock != nil {
			if blockAdapter, ok := latestBlock.(*core.BlockHelper); ok {
				underlyingBlock := blockAdapter.GetUnderlyingBlock()
				merkleRoot := hex.EncodeToString(underlyingBlock.CalculateTxsRoot())

				logger.Info("%s Block Details:", validatorIDs[i])
				logger.Info("  Height: %d", latestBlock.GetHeight())
				logger.Info("  Hash: %s", latestBlock.GetHash())
				logger.Info("  Merkle Root: %s", merkleRoot)
				logger.Info("  Magic Number: 0x%x", chainParams.MagicNumber)
				logger.Info("  Transaction Count: %d", len(underlyingBlock.Body.TxsList))
				logger.Info("  Timestamp: %d", underlyingBlock.Header.Timestamp)
			}
		}
	}

	// Generate comprehensive blockchain data reports
	logger.Info("=== FINAL BLOCKCHAIN STATE ANALYSIS ===")
	for i := 0; i < numNodes; i++ {
		PrintBlockchainData(blockchains[i], validatorIDs[i])
	}

	// Persist complete chain state to storage
	if err := blockchains[0].StoreChainState(nodes); err != nil {
		logger.Warn("Chain state persistence failed: %v", err)
	} else {
		logger.Info("✅ Chain state successfully persisted with Merkle roots")
	}

	logger.Info("Chain state verification deferred (VerifyState method unavailable)")
	logger.Info("Test artifacts consolidated into chain_state.json")

	// ========== RESOURCE CLEANUP AND SHUTDOWN ==========
	cancel()
	wg.Wait()
	for i := 0; i < numNodes; i++ {
		_ = dbs[i].Close()
		_ = blockchains[i].Close()
	}

	logger.Info("=== PBFT INTEGRATION TEST COMPLETED ===")
	logger.Info("Test artifacts:")
	logger.Info("  - data/Node-127.0.0.1:32307/blockchain/state/chain_state.json")

	if !consensusOK {
		return fmt.Errorf("consensus validation failed - nodes did not reach agreement")
	}

	return nil
}

// inspectConsensusTypes logs the consensus message types for debugging
func inspectConsensusTypes() {
	logger.Info("=== CONSENSUS TYPE INSPECTION ===")
	proposal := &consensus.Proposal{}
	vote := &consensus.Vote{}
	timeout := &consensus.TimeoutMsg{}
	logger.Info("Proposal type: %T", proposal)
	logger.Info("Vote type: %T", vote)
	logger.Info("TimeoutMsg type: %T", timeout)
	logger.Info("=== END TYPE INSPECTION ===")
}

// PrintBlockchainData prints detailed blockchain data for a node
func PrintBlockchainData(bc *core.Blockchain, nodeID string) {
	latestBlock := bc.GetLatestBlock()
	if latestBlock == nil {
		logger.Info("Node %s: No blocks available", nodeID)
		return
	}

	chainParams := bc.GetChainParams()

	if blockAdapter, ok := latestBlock.(*core.BlockHelper); ok {
		underlyingBlock := blockAdapter.GetUnderlyingBlock()
		txsRoot := hex.EncodeToString(underlyingBlock.Header.TxsRoot)
		calculatedMerkleRoot := hex.EncodeToString(underlyingBlock.CalculateTxsRoot())
		rootsMatch := txsRoot == calculatedMerkleRoot

		logger.Info("=== NODE %s BLOCKCHAIN DATA ===", nodeID)
		logger.Info("Block Height: %d", latestBlock.GetHeight())
		logger.Info("Block Hash: %s", latestBlock.GetHash())
		logger.Info("TxsRoot (from header): %s", txsRoot)
		logger.Info("MerkleRoot (calculated): %s", calculatedMerkleRoot)
		logger.Info("TxsRoot = MerkleRoot: %v", rootsMatch)
		logger.Info("Magic Number: 0x%x", chainParams.MagicNumber)
		logger.Info("Timestamp: %d", underlyingBlock.Header.Timestamp)
		logger.Info("Difficulty: %s", underlyingBlock.Header.Difficulty.String())
		logger.Info("Nonce: %s", underlyingBlock.Header.Nonce)
		logger.Info("Gas Limit: %s", underlyingBlock.Header.GasLimit.String())
		logger.Info("Gas Used: %s", underlyingBlock.Header.GasUsed.String())
		logger.Info("Transaction Count: %d", len(underlyingBlock.Body.TxsList))
		logger.Info("Chain ID: %d", chainParams.ChainID)
		logger.Info("Chain Name: %s", chainParams.ChainName)
		logger.Info("=================================")

		if !rootsMatch {
			logger.Warn("❌ WARNING: TxsRoot does not match MerkleRoot!")
		}
	}
}
