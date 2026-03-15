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
// This function sets up a multi-node network, initializes all components,
// creates transactions, runs leader election, and validates consensus.
func CallConsensus(numNodes int) error {
	// Validate minimum node requirement for PBFT (needs at least 3 nodes for fault tolerance)
	if numNodes < 3 {
		return fmt.Errorf("PBFT requires at least 3 validator nodes, got %d", numNodes)
	}

	// State variables for tracking test progress
	var firstBlock consensus.Block // Stores the first block for validation
	var firstGenesisHash string    // Stores the genesis hash for comparison

	// ========== BLOCKCHAIN IDENTIFICATION AND CONFIGURATION ==========
	logger.Info("=== SPHINX BLOCKCHAIN IDENTIFICATION ===")

	// Retrieve and display mainnet chain parameters from commit package
	chainParams := commit.SphinxChainParams()
	logger.Info("Chain: %s", chainParams.ChainName)                                             // Display chain name (Mainnet/Testnet/Devnet)
	logger.Info("Chain ID: %d", chainParams.ChainID)                                            // Display unique chain identifier
	logger.Info("Symbol: %s", chainParams.Symbol)                                               // Display token symbol (SPX)
	logger.Info("Protocol Version: %s", chainParams.Version)                                    // Display protocol version
	logger.Info("Genesis Time: %s", time.Unix(chainParams.GenesisTime, 0).Format(time.RFC1123)) // Genesis timestamp
	logger.Info("Genesis Hash: %s", chainParams.GenesisHash)                                    // Genesis block hash
	logger.Info("Magic Number: 0x%x", chainParams.MagicNumber)                                  // Network magic number for message validation
	logger.Info("Default Port: %d", chainParams.DefaultPort)                                    // Default P2P port
	logger.Info("BIP44 Coin Type: %d", chainParams.BIP44CoinType)                               // BIP44 coin type for wallet derivation
	logger.Info("Ledger Name: %s", chainParams.LedgerName)                                      // Ledger hardware wallet app name

	// Display SPX token economics and denominations from params package
	tokenInfo := params.GetSPXTokenInfo()
	logger.Info("Token Name: %s", tokenInfo.Name)                                          // Token name (Sphinx)
	logger.Info("Token Symbol: %s", tokenInfo.Symbol)                                      // Token symbol (SPX)
	logger.Info("Decimals: %d", tokenInfo.Decimals)                                        // Number of decimal places (18)
	logger.Info("Total Supply: %.2f %s", float64(tokenInfo.TotalSupply), tokenInfo.Symbol) // Total token supply
	logger.Info("Base Unit: nSPX (1e0)")                                                   // Nano SPX (smallest unit)
	logger.Info("Intermediate Unit: gSPX (1e9)")                                           // Giga SPX (intermediate unit)
	logger.Info("Main Unit: SPX (1e18)")                                                   // Main SPX unit

	// Generate and display standard wallet derivation paths based on BIP44 coin type
	walletPaths := map[string]string{
		"BIP44":  fmt.Sprintf("m/44'/%d'/0'/0/0", chainParams.BIP44CoinType), // Legacy path
		"BIP49":  fmt.Sprintf("m/49'/%d'/0'/0/0", chainParams.BIP44CoinType), // SegWit path
		"BIP84":  fmt.Sprintf("m/84'/%d'/0'/0/0", chainParams.BIP44CoinType), // Native SegWit path
		"Ledger": fmt.Sprintf("m/44'/%d'/0'", chainParams.BIP44CoinType),     // Ledger hardware wallet path
	}
	logger.Info("Wallet Derivation Paths:")
	for name, path := range walletPaths {
		logger.Info("  %s: %s", name, path)
	}

	// Determine network configuration based on chain name
	// In helper.go — change the default networkType so every node boots as devnet.
	// Swap this out for "testnet" or "mainnet" when you promote the chain.
	networkType := "devnet" // hardcoded — change to "testnet" or "mainnet" to promote
	networkDisplayName := "Sphinx Devnet"

	// The switch is now just for display purposes when NOT overriding:
	if chainParams.ChainName == "Sphinx Testnet" {
		networkDisplayName = "Sphinx Testnet"
	} else if chainParams.ChainName == "Sphinx Devnet" {
		networkDisplayName = "Sphinx Devnet"
	}

	logger.Info("Network: %s", networkDisplayName)
	logger.Info("Consensus: PBFT") // Practical Byzantine Fault Tolerance
	logger.Info("========================================")

	// ========== TEST ENVIRONMENT SETUP ==========
	testDataDir := common.DataDir // Get base data directory path
	// Check if test data directory exists and clean it for a fresh test
	if _, err := os.Stat(testDataDir); err == nil {
		logger.Info("Cleaning up previous test data...")
		if err := os.RemoveAll(testDataDir); err != nil {
			return fmt.Errorf("failed to clean test data: %v", err)
		}
		logger.Info("Previous test data cleaned successfully")
	}

	// Ensure the base data directory exists with proper permissions
	if err := os.MkdirAll(testDataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	// Debug consensus message types by logging their structures
	inspectConsensusTypes()

	// ========== NODE INFRASTRUCTURE INITIALIZATION ==========
	var wg sync.WaitGroup                                 // WaitGroup for goroutine synchronization
	_, cancel := context.WithCancel(context.Background()) // Context for graceful shutdown
	defer cancel()                                        // Ensure cancel is called on function exit

	// Initialize slices to hold node components for all nodes
	dbs := make([]*leveldb.DB, numNodes)                       // LevelDB instances for each node
	sphincsMgrs := make([]*sign.SphincsManager, numNodes)      // SPHINCS+ crypto managers
	blockchains := make([]*core.Blockchain, numNodes)          // Blockchain instances
	consensusEngines := make([]*consensus.Consensus, numNodes) // Consensus engines
	networkNodes := make([]*network.Node, numNodes)            // Network node instances

	// Generate network addresses and validator IDs FIRST
	// This ensures consistent addressing across all nodes
	networkAddresses := make([]string, numNodes) // P2P addresses (IP:port)
	validatorIDs := make([]string, numNodes)     // Unique validator identifiers
	for i := 0; i < numNodes; i++ {
		// Create incrementing ports starting from base port 32307
		address := fmt.Sprintf("127.0.0.1:%d", 32307+i)
		networkAddresses[i] = address
		validatorIDs[i] = fmt.Sprintf("Node-%s", address) // Node-ID format
	}

	// Create a map of signing services for key exchange between nodes
	signingServices := make(map[string]*consensus.SigningService)

	// Initialize each validator node in the network
	for i := 0; i < numNodes; i++ {
		address := networkAddresses[i] // Get node's network address
		nodeID := validatorIDs[i]      // Get node's validator ID

		// Create node data directory structure (blockchain, keys, etc.)
		if err := common.EnsureNodeDirs(address); err != nil {
			return fmt.Errorf("failed to create node directories for %s: %v", address, err)
		}
		logger.Info("Created directories for node: %s", nodeID)

		// Initialize LevelDB storage for blockchain data
		db, err := leveldb.OpenFile(common.GetLevelDBPath(address), nil)
		if err != nil {
			return fmt.Errorf("failed to open LevelDB for node %s: %v", nodeID, err)
		}
		dbs[i] = db // Store database reference

		// Convert LevelDB to database.DB interface for compatibility
		nodeDB, err := database.NewLevelDB(common.GetLevelDBPath(address))
		if err != nil {
			return fmt.Errorf("failed to create database for node %s: %v", nodeID, err)
		}

		// Create actual network node with P2P capabilities
		networkNode := network.NewNode(
			address,                    // Full address (IP:port)
			"127.0.0.1",                // Local IP
			fmt.Sprintf("%d", 32307+i), // P2P port
			fmt.Sprintf("%d", 32308+i), // RPC port (offset by 1)
			true,                       // Is validator node
			network.RoleValidator,      // Node role
			nodeDB,                     // Database instance
		)

		if networkNode == nil {
			return fmt.Errorf("failed to create network node %s", nodeID)
		}

		networkNodes[i] = networkNode // Store network node
		logger.Info("Created network node %s with keys stored in config directory", nodeID)

		// Initialize SPHINCS+ cryptographic components for post-quantum security
		km, err := key.NewKeyManager() // Create key manager
		if err != nil {
			return err
		}
		sphincsParams, err := config.NewSPHINCSParameters() // Get SPHINCS+ parameters
		if err != nil {
			return err
		}
		// Create SPHINCS+ manager for signing and verification
		sphincsMgrs[i] = sign.NewSphincsManager(db, km, sphincsParams)

		// ========== NODE MANAGER AND PEER CONNECTIONS ==========
		var dhtInstance network.DHT = nil // Distributed Hash Table (disabled for test)

		// Initialize node manager for peer management
		nodeMgr := network.NewNodeManager(16, dhtInstance, nodeDB) // Max 16 peers

		// Create and add local node to the manager
		if err := nodeMgr.CreateLocalNode(
			address,                    // Local node address
			"127.0.0.1",                // Local IP
			fmt.Sprintf("%d", 32307+i), // P2P port
			fmt.Sprintf("%d", 32308+i), // RPC port
			network.RoleValidator,      // Node role
		); err != nil {
			return fmt.Errorf("failed to create local node for node manager: %v", err)
		}

		// Add all other validator nodes as peers to this node
		for j := range validatorIDs {
			if i != j { // Skip self
				remoteAddress := networkAddresses[j]
				// Create remote node representation
				remoteNode := network.NewNode(
					remoteAddress,
					"127.0.0.1",
					fmt.Sprintf("%d", 32307+j),
					fmt.Sprintf("%d", 32308+j),
					false, // Not local
					network.RoleValidator,
					nil, // No DB for remote nodes
				)
				if remoteNode != nil {
					nodeMgr.AddNode(remoteNode) // Add to peer list
				}
			}
		}

		logger.Info("%s peer connections established", nodeID)

		// ========== BLOCKCHAIN SETUP ==========
		// Create new blockchain instance for this node
		bc, err := core.NewBlockchain(common.GetBlockchainDataDir(address), nodeID, validatorIDs, networkType)
		if err != nil {
			return fmt.Errorf("node %s blockchain initialization failed: %v", nodeID, err)
		}
		bc.SetStorageDB(nodeDB)

		// Execute genesis block now that the DB handle is live.
		// This fires mintBlockReward for block 0, crediting the vault with
		// the full 1,000,000,000 SPX that block 1 will distribute.
		if err := bc.ExecuteGenesisBlock(); err != nil {
			logger.Warn("ExecuteGenesisBlock failed for %s: %v", nodeID, err)
		} else {
			logger.Info("✅ Genesis vault funded for %s", nodeID)
		}

		// Capture genesis block from first node for validation against other nodes
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

		// Display node chain configuration for verification
		chainInfo := bc.GetChainInfo()
		logger.Info("%s Chain Configuration:", nodeID)
		logger.Info("  Chain: %s", chainInfo["chain_name"])
		logger.Info("  Chain ID: %d", chainInfo["chain_id"])
		logger.Info("  Symbol: %s", chainInfo["symbol"])
		logger.Info("  Version: %s", chainInfo["version"])
		logger.Info("  Magic Number: %s", chainInfo["magic_number"])
		logger.Info("  BIP44 Coin Type: %d", chainInfo["bip44_coin_type"])
		logger.Info("  Ledger Name: %s", chainInfo["ledger_name"])

		// Validate storage layer integrity
		logger.Info("%s: Validating storage layer...", nodeID)
		if debugErr := bc.DebugStorage(); debugErr != nil {
			logger.Warn("%s storage validation warning: %v", nodeID, debugErr)
		}
		blockchains[i] = bc // Store blockchain instance

		// ========== CONSENSUS CONFIGURATION ==========
		// Create test node manager for consensus (simplified for testing)
		testNodeMgr := network.NewCallNodeManager()

		// Add all validator nodes as peers to the test manager
		for _, id := range validatorIDs {
			testNodeMgr.AddPeer(id)
		}

		// Initialize SPHINCS+ signing service for cryptographic operations
		keyManager, err := key.NewKeyManager() // Create key manager
		if err != nil {
			return fmt.Errorf("failed to create key manager for node %s: %v", nodeID, err)
		}

		// Get SPHINCS parameters for signature scheme
		sphincsParams, err = config.NewSPHINCSParameters()
		if err != nil {
			return fmt.Errorf("failed to get SPHINCS parameters for node %s: %v", nodeID, err)
		}

		// Initialize SPHINCS manager for signing operations
		sphincsManager := sign.NewSphincsManager(db, keyManager, sphincsParams)

		// Create signing service that wraps SPHINCS+ functionality
		signingService := consensus.NewSigningService(sphincsManager, keyManager, nodeID)

		// Store the signing service for key exchange later
		signingServices[nodeID] = signingService

		// Get the minimum stake from core chain parameters
		coreChainParams := core.GetSphinxChainParams()
		minStakeAmount := coreChainParams.ConsensusConfig.MinStakeAmount

		// Log minimum stake for verification
		minSPX := new(big.Int).Div(minStakeAmount, big.NewInt(1e18))
		logger.Info("📊 Min stake from params: %d SPX (%v nSPX)", minSPX.Uint64(), minStakeAmount)

		// Pass to consensus - create new consensus engine instance
		cons := consensus.NewConsensus(
			nodeID,
			testNodeMgr,
			bc,
			signingService,
			nil, // onCommit is nil — blockChain.CommitBlock already commits
			minStakeAmount,
		)

		// Initialize stake - now using validator set methods
		validatorSet := cons.GetValidatorSet() // Get validator set from consensus
		if validatorSet != nil {
			// Get the minimum stake from the validator set itself
			stakeSPX := validatorSet.GetMinStakeSPX()

			// Add this node as a validator with minimum stake
			err := validatorSet.AddValidator(nodeID, stakeSPX)
			if err != nil {
				logger.Warn("Failed to add validator %s with stake %d SPX: %v", nodeID, stakeSPX, err)
			} else {
				logger.Info("✅ Validator %s initialized with %d SPX stake (from chain parameters)", nodeID, stakeSPX)
			}
		}

		consensusEngines[i] = cons  // Store consensus engine
		bc.SetConsensusEngine(cons) // Link blockchain to consensus
		bc.SetConsensus(cons)       // Set consensus reference

		// Register consensus with network layer for message handling
		network.RegisterConsensus(nodeID, cons)

		// Set a long timeout to prevent automatic view changes during test
		cons.SetTimeout(1 * time.Hour)

		// Start consensus engine (launches goroutines for message handling)
		if err := cons.Start(); err != nil {
			return fmt.Errorf("failed to start consensus for node %s: %v", nodeID, err)
		}

		// Allow consensus engine to fully initialize before proceeding
		time.Sleep(100 * time.Millisecond)
	}

	// ========== CROSS-REGISTER ALL VALIDATORS IN EVERY NODE'S VALIDATOR SET ==========
	// This ensures every node recognizes all other nodes as validators
	logger.Info("=== REGISTERING ALL VALIDATORS ACROSS ALL NODES ===")

	// Get chain parameters for stake configuration
	coreChainParams := core.GetSphinxChainParams()
	minStakeAmount := coreChainParams.ConsensusConfig.MinStakeAmount
	// Convert to SPX units for display
	minSPX := new(big.Int).Div(minStakeAmount, big.NewInt(1e18)).Uint64()

	// For each node, add all other nodes to its validator set
	for i := 0; i < numNodes; i++ {
		vs := consensusEngines[i].GetValidatorSet() // Get validator set
		if vs == nil {
			logger.Warn("Node %s has nil validator set", validatorIDs[i])
			continue
		}
		// Add each other node as validator
		for j := 0; j < numNodes; j++ {
			if i == j {
				continue // Skip self (already added)
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
	// Verify that all nodes have the same genesis block
	logger.Info("=== VALIDATING GENESIS BLOCK CONSISTENCY ===")

	expectedGenesisHash := core.GetGenesisHash() // Get expected genesis hash
	logger.Info("Expected genesis hash for all nodes: %s", expectedGenesisHash)

	// Check each node's genesis block
	for i := 0; i < numNodes; i++ {
		genesis := blockchains[i].GetLatestBlock()
		if genesis == nil || genesis.GetHeight() != 0 {
			return fmt.Errorf("node %s failed to initialize genesis block", validatorIDs[i])
		}

		actualHash := genesis.GetHash()
		logger.Info("%s genesis: height=%d, hash=%s", validatorIDs[i], genesis.GetHeight(), actualHash)

		// Handle potential "GENESIS_" prefix in hash strings
		if actualHash != expectedGenesisHash {
			normalizedActual := actualHash
			normalizedExpected := expectedGenesisHash

			// Strip "GENESIS_" prefix if present
			if strings.HasPrefix(actualHash, "GENESIS_") && len(actualHash) > 8 {
				normalizedActual = actualHash[8:]
			}
			if strings.HasPrefix(expectedGenesisHash, "GENESIS_") && len(expectedGenesisHash) > 8 {
				normalizedExpected = expectedGenesisHash[8:]
			}

			// Compare normalized hashes
			if normalizedActual != normalizedExpected {
				return fmt.Errorf("genesis block hash mismatch: %s=%s (normalized: %s) expected=%s (normalized: %s)",
					validatorIDs[i], actualHash, normalizedActual, expectedGenesisHash, normalizedExpected)
			}
		}
	}
	logger.Info("✅ All nodes have consistent genesis blocks: %s", expectedGenesisHash)

	// ========== KEY EXCHANGE ==========
	// Exchange public keys between nodes for signature verification
	logger.Info("=== EXCHANGING PUBLIC KEYS BETWEEN NODES ===")
	exchangePublicKeys(signingServices, validatorIDs)

	// Verify key directories were created properly
	logger.Info("=== VERIFYING KEY DIRECTORY CREATION ===")
	for i := 0; i < numNodes; i++ {
		address := networkAddresses[i]
		nodeID := validatorIDs[i]
		keysDir := common.GetKeysDataDir(address) // Get keys directory path

		// Check if keys directory exists
		if _, err := os.Stat(keysDir); os.IsNotExist(err) {
			logger.Warn("Keys directory not created for node %s: %s", nodeID, keysDir)
		} else {
			logger.Info("Keys directory exists for node %s: %s", nodeID, keysDir)

			// Check private and public key files
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
	// Set up RPC servers for each node to handle API requests
	for i := 0; i < numNodes; i++ {
		address := networkAddresses[i]
		nodeID := validatorIDs[i]

		logger.Info("Setting up RPC server for node with address: %s", address)

		// Create message channel for RPC communication
		msgCh := make(chan *security.Message, 100)
		// Create new RPC server for this node
		rpcSrv := rpc.NewServer(msgCh, blockchains[i])

		// Start goroutine to handle RPC messages
		go func(ch chan *security.Message, srv *rpc.Server, nodeIdx int, nodeAddr string) {
			// Process incoming messages
			for secMsg := range ch {
				// Only process RPC type messages
				if secMsg.Type != "rpc" {
					continue
				}

				// Extract data from message
				data, ok := secMsg.Data.([]byte)
				if !ok {
					logger.Warn("%s: Invalid RPC data type: %T", validatorIDs[nodeIdx], secMsg.Data)
					continue
				}

				// Unmarshal RPC message
				var rpcMsg rpc.Message
				if err := rpcMsg.Unmarshal(data); err != nil {
					logger.Warn("%s: Failed to unmarshal RPC message: %v", validatorIDs[nodeIdx], err)
					continue
				}

				// Handle the RPC request
				resp, err := srv.HandleRequest(data)
				if err != nil {
					logger.Warn("%s: RPC request handling error: %v", validatorIDs[nodeIdx], err)
					continue
				}

				// Send response back to client
				addr := rpcMsg.From.Address.String()
				conn, err := net.Dial("udp", addr)
				if err != nil {
					logger.Warn("%s: Failed to connect to %s: %v", validatorIDs[nodeIdx], addr, err)
					continue
				}
				// Encode and send secure response
				secResp := &security.Message{Type: "rpc", Data: resp}
				enc, _ := secResp.Encode()
				conn.Write(enc)
				conn.Close()
			}
		}(msgCh, rpcSrv, i, address)

		// Log RPC endpoint (HTTP port starts at 8545)
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

	// Load the canonical genesis allocation list. Each entry maps an address to
	// its initial balance (e.g. Founders, Reserve, Treasury, Community, Validators).
	// Block 1 will execute these transfers, moving funds from the genesis vault to
	// every recipient defined here.
	allocs := core.DefaultGenesisAllocations()
	if len(allocs) == 0 {
		return fmt.Errorf("DefaultGenesisAllocations is empty")
	}

	// Build one Note per allocation. Notes are the human-readable precursor to a
	// signed Transaction — they carry the sender, recipient, and exact amount in
	// nSPX without any float64 precision loss.
	notes := make([]*types.Note, len(allocs))
	for i, alloc := range allocs {
		notes[i] = &types.Note{
			From:       core.GenesisVaultAddress,
			To:         alloc.Address,
			Fee:        0,                                   // Fee field is unused; AmountNSPX drives the transfer
			AmountNSPX: new(big.Int).Set(alloc.BalanceNSPX), // Copy to avoid mutating the allocation table
			Storage:    fmt.Sprintf("genesis-dist-%d-%s", i, alloc.Label),
		}
		logger.Info("Note[%d]: vault → %s (%s) %s nSPX",
			i, alloc.Address, alloc.Label, alloc.BalanceNSPX.String())
	}

	// Convert each Note into a signed Transaction. Genesis distribution transfers
	// are protocol-level operations, so gas is set to zero — charging gas against
	// the vault being drained would leave it short for the final recipient.
	// Nonces are tracked per sender so sequential txs from the vault don't collide.
	transactions := make([]*types.Transaction, len(notes))
	senderNonces := make(map[string]uint64)
	for i, note := range notes {
		nonce := senderNonces[note.From]
		transactions[i] = note.ToTxs(nonce, big.NewInt(0), big.NewInt(0)) // gasLimit=0, gasPrice=0
		senderNonces[note.From]++
	}

	// Replicate the full transaction set into every node's mempool so that
	// whichever node wins leader election already has all txs ready to include
	// in the next block. Each tx is deep-copied to prevent shared-pointer races
	// between nodes running in separate goroutines.
	for i := 0; i < numNodes; i++ {
		nodeID := validatorIDs[i]
		nodeSuccessCount := 0

		for _, tx := range transactions {
			// Deep copy: Amount, GasLimit, GasPrice are *big.Int (pointer types),
			// and Signature is a byte slice — all must be copied, not shared.
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
	// Log transaction details for verification
	logger.Info("=== TRANSACTION DETAILS ===")
	for i, tx := range transactions {
		logger.Info("TX%d: %s → %s (Amount: %s, Gas: %s, ID: %s)",
			i+1, tx.Sender, tx.Receiver, tx.Amount.String(), tx.GasLimit.String(), tx.ID)
	}
	logger.Info("Total transactions created: %d", len(transactions))

	// Give a short time for transactions to propagate through the network
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
	// Determine which node was elected leader
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

	// Get references to the elected leader's components
	leaderNode := blockchains[electedLeaderIndex]           // Leader's blockchain
	leaderConsensus := consensusEngines[electedLeaderIndex] // Leader's consensus engine
	leaderID := validatorIDs[electedLeaderIndex]            // Leader's ID

	// Confirm the elected leader's mempool is ready with transactions
	pendingTxs := leaderNode.GetMempool().GetPendingTransactions()
	txCount := len(pendingTxs)
	logger.Info("Leader %s has %d pending transactions in mempool.", leaderID, txCount)

	if txCount == 0 {
		return fmt.Errorf("leader mempool is empty, cannot start consensus")
	}

	// ========== LEADER CREATES AND PROPOSES BLOCK ==========
	logger.Info("=== LEADER CREATING BLOCK ===")

	// Create a new block from pending transactions
	newBlock, err := leaderNode.CreateBlock()
	if err != nil {
		return fmt.Errorf("failed to create block: %v", err)
	}

	logger.Info("✅ Leader %s created block: height=%d, hash=%s, transactions=%d",
		leaderID, newBlock.GetHeight(), newBlock.GetHash(), len(newBlock.Body.TxsList))

	// Wrap in consensus.Block adapter for consensus layer compatibility
	consensusBlock := core.NewBlockHelper(newBlock)

	// Propose the block to all peers
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
		// Check pending transactions in each node's mempool
		pendingTxs := blockchains[i].GetMempool().GetPendingTransactions()
		txCount := len(pendingTxs)
		logger.Info("%s: %s, pending_txs=%d", validatorIDs[i], leaderStatus, txCount)
	}
	logger.Info("====================================")

	// Set timeout for consensus completion
	const timeout = 3 * time.Minute
	start := time.Now()
	logger.Info("Waiting for block commitment (timeout: %v)...", timeout)

	checkInterval := 1 * time.Second
	progressTicker := time.NewTicker(checkInterval)
	defer progressTicker.Stop()

	lastProgressLog := time.Now()
	timeoutReached := false
	consensusOK := false

	// Monitor for block commitment across all nodes
	for range progressTicker.C {
		// Check if timeout has been reached
		if time.Since(start) > timeout {
			timeoutReached = true
			break
		}

		allAtHeight1 := true
		committedNodes := 0

		// Check each node's latest block height
		for i := 0; i < numNodes; i++ {
			latest := blockchains[i].GetLatestBlock()
			if latest == nil || latest.GetHeight() < 1 {
				allAtHeight1 = false
			} else {
				committedNodes++
			}

			// Log progress every 10 seconds
			if time.Since(lastProgressLog) > 10*time.Second {
				if latest == nil {
					logger.Info("Progress: %s at height 0 (genesis)", validatorIDs[i])
				} else {
					logger.Info("Progress: %s at height %d", validatorIDs[i], latest.GetHeight())
				}
				lastProgressLog = time.Now()
			}
		}

		// Check if all nodes have reached height 1 (consensus achieved)
		if allAtHeight1 {
			logger.Info("🎉 SUCCESS: All %d nodes reached block height 1!", numNodes)
			consensusOK = true
			break
		} else if committedNodes > 0 {
			logger.Info("📈 Progress: %d/%d nodes committed block 1", committedNodes, numNodes)
		}
	}

	// Handle timeout case with detailed diagnostics
	if timeoutReached {
		logger.Info("=== CONSENSUS TIMEOUT DIAGNOSTICS ===")
		for i := 0; i < numNodes; i++ {
			latest := blockchains[i].GetLatestBlock()
			hasPendingTxs := false
			// Check if first transaction is still pending
			if len(transactions) > 0 {
				hasPendingTxs = blockchains[i].HasPendingTx(transactions[0].ID)
			}

			// Log detailed state for each node
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
	// Verify all nodes have the same latest block hash
	firstBlock = blockchains[0].GetLatestBlock()
	if firstBlock == nil {
		return fmt.Errorf("%s has no committed block", validatorIDs[0])
	}
	firstHash := firstBlock.GetHash()
	// Compare each node's latest block with the first node's
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
	// Capture final state of all nodes for persistence
	logger.Info("=== CAPTURING FINAL CHAIN STATE ===")

	nodes := make([]*state.NodeInfo, numNodes) // Array to hold node info

	// Collect node information from each node
	for i := 0; i < numNodes; i++ {
		address := networkAddresses[i]
		nodeID := validatorIDs[i]

		logger.Info("Collecting node info for: %s", nodeID)

		// Get latest block from blockchain
		b := blockchains[i].GetLatestBlock()
		if b == nil {
			logger.Warn("No block found for node %s", nodeID)
			// Create placeholder node info if block missing
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

		// Calculate merkle root from block transactions
		var merkleRoot string
		if blockAdapter, ok := b.(*core.BlockHelper); ok {
			underlyingBlock := blockAdapter.GetUnderlyingBlock()
			merkleRootBytes := underlyingBlock.CalculateTxsRoot()
			merkleRoot = hex.EncodeToString(merkleRootBytes)
		} else {
			merkleRoot = "unknown"
			logger.Warn("Could not get underlying block for %s", nodeID)
		}

		// Get chain information
		chainInfo := blockchains[i].GetChainInfo()
		if chainInfo == nil {
			chainInfo = make(map[string]interface{})
			logger.Warn("Chain info was nil for %s, created empty", nodeID)
		}

		// Create comprehensive node info
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

		// Validate node info has required fields
		if nodeInfo.NodeID == "" || nodeInfo.NodeName == "" {
			logger.Error("❌ Node info has empty ID/Name for %s", nodeID)
		}

		nodes[i] = nodeInfo
		logger.Info("✅ Collected node info for: %s", nodeID)
	}

	// Final verification of collected nodes
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

	// Log collection results
	if validCount != numNodes {
		logger.Warn("⚠️  Only %d/%d nodes collected properly, but continuing anyway", validCount, numNodes)
	} else {
		logger.Info("✅ All %d nodes collected successfully", validCount)
	}

	logger.Info("=== SAVING CHAIN STATE TO ALL NODES ===")

	// Save chain state to each node's storage
	for i := 0; i < numNodes; i++ {
		nodeID := validatorIDs[i]
		logger.Info("--- Saving chain state for %s ---", nodeID)

		// Get state machine for final state management
		stateMachine := blockchains[i].GetStateMachine()
		if stateMachine == nil {
			logger.Warn("%s: No state machine available, skipping final state initialization", nodeID)
		} else {
			logger.Info("Initializing final states for %s", nodeID)

			// Force populate final states from consensus signatures
			if err := stateMachine.ForcePopulateFinalStates(); err != nil {
				logger.Warn("%s: Failed to populate final states: %v", nodeID, err)
			} else {
				logger.Info("%s: Successfully force populated final states", nodeID)
			}

			// Sync final states with consensus
			stateMachine.SyncFinalStatesNow()
			logger.Info("%s: Synced final states with consensus", nodeID)

			// Get and log final states
			finalStates := stateMachine.GetFinalStates()
			logger.Info("%s: Final states ready - %d entries", nodeID, len(finalStates))

			// Log each final state entry
			for j, state := range finalStates {
				if state != nil {
					logger.Info("  %s FinalState %d: block=%s, merkle=%s, status=%s",
						nodeID, j, state.BlockHash, state.MerkleRoot, state.Status)
				}
			}
		}

		// Small delay between nodes to avoid race conditions
		if i > 0 {
			time.Sleep(100 * time.Millisecond)
		}

		// Create a copy of nodes array for storage
		nodesCopy := make([]*state.NodeInfo, len(nodes))
		copy(nodesCopy, nodes)

		// Validate copy has valid nodes
		if len(nodesCopy) == 0 {
			logger.Error("❌ nodesCopy is EMPTY for %s!", nodeID)
			continue
		}

		// Count valid nodes in copy
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

		// Skip if no valid nodes to save
		if validInCopy == 0 {
			logger.Error("❌ No valid nodes in copy for %s, skipping save", nodeID)
			continue
		}

		// Attempt to save chain state with retries
		maxRetries := 3
		for attempt := 1; attempt <= maxRetries; attempt++ {
			logger.Info("Attempt %d/%d to save chain state for %s", attempt, maxRetries, nodeID)

			// Store chain state in node's storage
			err := blockchains[i].StoreChainState(nodesCopy)
			if err != nil {
				logger.Warn("Attempt %d failed for %s: %v", attempt, nodeID, err)

				// If all retries failed, try fallback
				if attempt == maxRetries {
					logger.Error("❌ ALL attempts failed for %s", nodeID)

					// Try basic state save as fallback
					logger.Info("Trying fallback basic state save for %s", nodeID)
					if basicErr := blockchains[i].SaveBasicChainState(); basicErr != nil {
						logger.Error("❌ Basic state also failed for %s: %v", nodeID, basicErr)
					} else {
						logger.Info("✅ Basic state saved as fallback for %s", nodeID)
					}
				} else {
					// Wait before retry
					time.Sleep(200 * time.Millisecond)
				}
			} else {
				logger.Info("✅ Successfully saved chain state for %s on attempt %d", nodeID, attempt)
				break
			}
		}
	}

	logger.Info("=== CHAIN STATE CAPTURE COMPLETED ===")

	// Display detailed block information for all nodes
	logger.Info("=== BLOCK DATA WITH MERKLE ROOTS ===")
	for i := 0; i < numNodes; i++ {
		latestBlock := blockchains[i].GetLatestBlock()
		if latestBlock != nil {
			if blockAdapter, ok := latestBlock.(*core.BlockHelper); ok {
				underlyingBlock := blockAdapter.GetUnderlyingBlock()
				merkleRoot := hex.EncodeToString(underlyingBlock.CalculateTxsRoot())

				// Log comprehensive block details
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

	// Generate comprehensive blockchain data reports for each node
	logger.Info("=== FINAL BLOCKCHAIN STATE ANALYSIS ===")
	for i := 0; i < numNodes; i++ {
		PrintBlockchainData(blockchains[i], validatorIDs[i])
	}

	// Persist complete chain state to storage (node 0 as reference)
	if err := blockchains[0].StoreChainState(nodes); err != nil {
		logger.Warn("Chain state persistence failed: %v", err)
	} else {
		logger.Info("✅ Chain state successfully persisted with Merkle roots")
	}

	logger.Info("Chain state verification deferred (VerifyState method unavailable)")
	logger.Info("Test artifacts consolidated into chain_state.json")

	// ========== RESOURCE CLEANUP AND SHUTDOWN ==========
	cancel()  // Cancel context to stop goroutines
	wg.Wait() // Wait for goroutines to finish
	// Close all database connections
	for i := 0; i < numNodes; i++ {
		_ = dbs[i].Close()         // Close LevelDB
		_ = blockchains[i].Close() // Close blockchain
	}

	logger.Info("=== PBFT INTEGRATION TEST COMPLETED ===")
	logger.Info("Test artifacts:")
	logger.Info("  - data/Node-127.0.0.1:32307/blockchain/state/chain_state.json")

	// Return error if consensus was not achieved
	if !consensusOK {
		return fmt.Errorf("consensus validation failed - nodes did not reach agreement")
	}

	return nil
}

// inspectConsensusTypes logs the consensus message types for debugging
// This helps verify the correct types are being used in the consensus layer
func inspectConsensusTypes() {
	logger.Info("=== CONSENSUS TYPE INSPECTION ===")
	// Create empty instances of each consensus message type
	proposal := &consensus.Proposal{}
	vote := &consensus.Vote{}
	timeout := &consensus.TimeoutMsg{}
	// Log their types for debugging
	logger.Info("Proposal type: %T", proposal)
	logger.Info("Vote type: %T", vote)
	logger.Info("TimeoutMsg type: %T", timeout)
	logger.Info("=== END TYPE INSPECTION ===")
}

// PrintBlockchainData prints detailed blockchain data for a node
// This provides comprehensive information about a node's blockchain state
func PrintBlockchainData(bc *core.Blockchain, nodeID string) {
	// Get latest block
	latestBlock := bc.GetLatestBlock()
	if latestBlock == nil {
		logger.Info("Node %s: No blocks available", nodeID)
		return
	}

	// Get chain parameters
	chainParams := bc.GetChainParams()

	// Extract block details using BlockHelper if available
	if blockAdapter, ok := latestBlock.(*core.BlockHelper); ok {
		underlyingBlock := blockAdapter.GetUnderlyingBlock()
		// Get merkle roots for comparison
		txsRoot := hex.EncodeToString(underlyingBlock.Header.TxsRoot)
		calculatedMerkleRoot := hex.EncodeToString(underlyingBlock.CalculateTxsRoot())
		rootsMatch := txsRoot == calculatedMerkleRoot

		// Print comprehensive block information
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

		// Warn if merkle roots don't match
		if !rootsMatch {
			logger.Warn("❌ WARNING: TxsRoot does not match MerkleRoot!")
		}
	}
}
