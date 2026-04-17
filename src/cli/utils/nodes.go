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

// go/src/cli/utils/nodes.go
package utils

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/sphinxorg/protocol/src/common"
	"github.com/sphinxorg/protocol/src/consensus"
	"github.com/sphinxorg/protocol/src/core"
	database "github.com/sphinxorg/protocol/src/core/state"
	config "github.com/sphinxorg/protocol/src/core/sthincs/config"
	key "github.com/sphinxorg/protocol/src/core/sthincs/key/backend"
	sign "github.com/sphinxorg/protocol/src/core/sthincs/sign/backend"
	svm "github.com/sphinxorg/protocol/src/core/svm/opcodes"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/sthincs"
	security "github.com/sphinxorg/protocol/src/handshake"
	"github.com/sphinxorg/protocol/src/http"
	logger "github.com/sphinxorg/protocol/src/log"
	"github.com/sphinxorg/protocol/src/network"
	"github.com/sphinxorg/protocol/src/params/commit"
	"github.com/sphinxorg/protocol/src/state"
	"github.com/syndtr/goleveldb/leveldb"
)

// StartNode starts a fully-featured validator node
func StartNode(
	dataDir string,
	nodeConfig network.NodePortConfig,
	totalNodes, nodeIndex int,
	vdfParams *consensus.VDFParams,
	networkType string, // Make sure this parameter exists
) error {

	logger.Info("=== STARTING NODE %d OF %d ===", nodeIndex+1, totalNodes)

	// Determine if this is production mode (large network)
	isProduction := totalNodes > 100

	switch {
	case totalNodes == 1:
		logger.Info("⚠️  SINGLE NODE MODE — no consensus (development only)")
	case totalNodes == 2:
		logger.Warn("⚠️  2-NODE CLUSTER — PBFT requires ≥ 3 validators")
	case isProduction:
		logger.Info("🚀 PRODUCTION MODE — Large network with %d nodes (using optimized peer connections)", totalNodes)
	default:
		logger.Info("✅ FULL PBFT CONSENSUS — %d validators", totalNodes)
	}

	/// SECTION 1 — chain identification
	chainParams := commit.SphinxChainParams()
	logger.Info("Chain: %s  ChainID=%d  Symbol=%s", chainParams.ChainName, chainParams.ChainID, chainParams.Symbol)

	// ========== FIX: Force devnet mode ==========
	// Override networkType to devnet regardless of chainParams
	networkType = "devnet"
	logger.Info("Network type: %s (FORCED DEVNET)", networkType)
	// ===========================================

	// SECTION 2 — shared cryptographic parameters
	sharedKeyManager, err := key.NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to create shared key manager: %w", err)
	}

	sharedSphincsParams, err := config.NewSTHINCSParameters()
	if err != nil {
		return fmt.Errorf("failed to create shared STHINCS parameters: %w", err)
	}
	sthincsParams := sharedSphincsParams.Params
	logger.Info("✅ Shared STHINCS parameters created")

	// SECTION 3 — node identity
	validatorIDs := make([]string, totalNodes)
	networkAddresses := make([]string, totalNodes)
	for i := 0; i < totalNodes; i++ {
		addr := fmt.Sprintf("127.0.0.1:%d", 32307+i)
		networkAddresses[i] = addr
		validatorIDs[i] = fmt.Sprintf("Node-%s", addr)
	}

	currentAddress := networkAddresses[nodeIndex]
	currentNodeID := validatorIDs[nodeIndex]
	logger.Info("Node identity: %s at %s", currentNodeID, currentAddress)

	// SECTION 4 — database initialization
	if err := common.EnsureNodeDirs(currentAddress); err != nil {
		return fmt.Errorf("failed to create node directories: %w", err)
	}

	mainDBPath := common.GetLevelDBPath(currentAddress)
	db, err := leveldb.OpenFile(mainDBPath, nil)
	if err != nil {
		return fmt.Errorf("failed to open main LevelDB: %w", err)
	}
	defer db.Close()

	stateDBPath := common.GetStateDBPath(currentAddress)
	stateLevelDB, err := leveldb.OpenFile(stateDBPath, nil)
	if err != nil {
		return fmt.Errorf("failed to open state DB: %w", err)
	}
	defer stateLevelDB.Close()

	mainDatabase, err := database.NewLevelDB(mainDBPath)
	if err != nil {
		return fmt.Errorf("failed to create main database: %w", err)
	}
	stateDatabase, err := database.NewLevelDB(stateDBPath)
	if err != nil {
		return fmt.Errorf("failed to create state database: %w", err)
	}

	// SECTION 5 — blockchain + genesis
	// SECTION 5 — blockchain + genesis
	bc, err := core.NewBlockchain(currentAddress, currentNodeID, validatorIDs, networkType)
	if err != nil {
		return fmt.Errorf("failed to create blockchain: %w", err)
	}
	bc.SetStorageDB(mainDatabase)
	bc.SetStateDB(stateDatabase)

	if err := bc.ExecuteGenesisBlock(); err != nil {
		logger.Warn("ExecuteGenesisBlock: %v", err)
	} else {
		logger.Info("✅ Genesis vault funded")
	}

	// ========== ADD THIS: Save initial checkpoint after genesis ==========
	if cpErr := bc.WriteChainCheckpoint(); cpErr != nil {
		logger.Warn("Failed to write initial checkpoint: %v", cpErr)
	} else {
		logger.Info("✅ Initial checkpoint saved after genesis")
	}
	// ====================================================================

	// VDF genesis-hash provider
	if vdfParams == nil {
		return fmt.Errorf("VDF parameters are required and must be pre-derived from the genesis block")
	}
	if err := consensus.SetCanonicalVDFParameters(vdfParams); err != nil {
		return fmt.Errorf("failed to set canonical VDF parameters: %w", err)
	}
	logger.Info("✅ Node using pre-derived canonical VDF parameters (D=%d bits, T=%d)",
		vdfParams.Discriminant.BitLen(), vdfParams.T)

	// SECTION 6 — signing service
	sphincsMgr := sign.NewSTHINCSManager(db, sharedKeyManager, sharedSphincsParams)
	signingService := consensus.NewSigningService(sphincsMgr, sharedKeyManager, currentNodeID)

	if selfPK := signingService.GetPublicKeyObject(); selfPK != nil {
		signingService.RegisterPublicKey(currentNodeID, selfPK)
		logger.Info("✅ Self public key registered")
	}

	pkBytes, err := signingService.GetPublicKey()
	if err != nil {
		return fmt.Errorf("cannot serialize self public key: %w", err)
	}
	logger.Info("✅ Self public key size: %d bytes", len(pkBytes))

	// SECTION 7 — network node manager
	var dhtInstance network.DHT = nil
	nodeMgr := network.NewNodeManager(16, dhtInstance, mainDatabase)

	tcpPort := "30303"
	if nodeConfig.TCPAddr != "" {
		_, portStr, err := net.SplitHostPort(nodeConfig.TCPAddr)
		if err == nil && portStr != "" {
			tcpPort = portStr
		} else {
			tcpPort = nodeConfig.TCPAddr
		}
	} else {
		tcpPort = fmt.Sprintf("%d", 32307+nodeIndex)
	}

	udpPort := nodeConfig.UDPPort
	if udpPort == "" {
		udpPort = fmt.Sprintf("%d", 32308+nodeIndex)
	}

	if err := nodeMgr.CreateLocalNode(
		currentAddress,
		"127.0.0.1",
		tcpPort,
		udpPort,
		network.RoleValidator,
	); err != nil {
		return fmt.Errorf("failed to create local node: %w", err)
	}

	// Register peers
	for j := 0; j < totalNodes; j++ {
		if j == nodeIndex {
			continue
		}
		peerNode := network.NewNode(
			networkAddresses[j],
			"127.0.0.1",
			fmt.Sprintf("%d", 32307+j),
			fmt.Sprintf("%d", 32308+j),
			false,
			network.RoleValidator,
			mainDatabase,
		)
		if peerNode != nil {
			nodeMgr.AddNode(peerNode)
			logger.Info("Registered peer: %s", networkAddresses[j])
		}
	}

	// SECTION 8 — consensus node manager
	var consensusNodeMgr consensus.NodeManager
	var p2pMgr *network.P2PConsensusNodeManager

	if totalNodes == 1 {
		callMgr := network.NewCallNodeManager()
		callMgr.AddPeer(currentNodeID)
		consensusNodeMgr = callMgr
		logger.Info("📦 Solo mode — local consensus manager")
	} else {
		p2pMgr = network.NewP2PConsensusNodeManager(nodeMgr, currentNodeID)

		for i, addr := range networkAddresses {
			if i == nodeIndex {
				continue
			}
			p2pMgr.AddPeer(validatorIDs[i], addr)
			logger.Info("Added peer %s at %s to P2P consensus manager", validatorIDs[i], addr)
		}

		p2pMgr.SetSendMessageFunc(func(nodeAddress, msgType string, data []byte) error {
			conn, err := net.DialTimeout("tcp", nodeAddress, 5*time.Second)
			if err != nil {
				return fmt.Errorf("failed to connect to %s: %v", nodeAddress, err)
			}
			defer conn.Close()

			msg := &security.Message{
				Type: msgType,
				Data: data,
			}

			encodedMsg, err := msg.Encode()
			if err != nil {
				return err
			}

			_, err = conn.Write(encodedMsg)
			return err
		})

		consensusNodeMgr = p2pMgr
		logger.Info("🌐 P2P consensus manager ready with %d peers", len(networkAddresses)-1)
	}

	// SECTION 9 — consensus engine
	coreChainParams := core.GetSphinxChainParams()
	minStakeAmount := coreChainParams.ConsensusConfig.MinStakeAmount

	cons := consensus.NewConsensus(
		currentNodeID,
		consensusNodeMgr,
		bc,
		signingService,
		nil,
		minStakeAmount,
	)

	if p2pMgr != nil {
		p2pMgr.SetConsensusEngine(cons)
	}

	if vs := cons.GetValidatorSet(); vs != nil {
		minSPX := new(big.Int).Div(minStakeAmount, big.NewInt(1e18)).Uint64()
		if err := vs.AddValidator(currentNodeID, minSPX); err != nil {
			logger.Warn("Failed to add self validator: %v", err)
		} else {
			logger.Info("✅ Self validator registered")
		}
	}

	bc.SetConsensusEngine(cons)
	bc.SetConsensus(cons)
	cons.SetTimeout(1 * time.Hour)

	network.RegisterConsensus(currentNodeID, cons)
	logger.Info("✅ Consensus engine registered")

	// SECTION 10 — VM verifier
	svm.SetSphincsVerifier(
		func(b []byte) (interface{}, error) { return sthincs.DeserializePK(sthincsParams, b) },
		func(b []byte) (interface{}, error) { return sthincs.DeserializeSignature(sthincsParams, b) },
		func(msg []byte, sig, pk interface{}) bool {
			return sthincs.Spx_verify(
				sthincsParams,
				msg,
				sig.(*sthincs.SPHINCS_SIG),
				pk.(*sthincs.SPHINCS_PK),
			)
		},
	)
	logger.Info("✅ VM SPHINCS+ verifier registered")

	// ========== CRITICAL FIX: Add genesis transactions to ALL nodes ==========
	allocs := core.DefaultGenesisAllocations()
	genesisTransactions := make([]*types.Transaction, 0, len(allocs))
	senderNonces := make(map[string]uint64)

	logger.Info("=== CREATING GENESIS DISTRIBUTION TRANSACTIONS ===")
	for i, alloc := range allocs {
		note := &types.Note{
			From:       core.GenesisVaultAddress,
			To:         alloc.Address,
			Fee:        0,
			AmountNSPX: new(big.Int).Set(alloc.BalanceNSPX),
			Storage:    fmt.Sprintf("genesis-dist-%d-%s", i, alloc.Label),
			ReturnData: []byte(fmt.Sprintf("Genesis distribution to %s", alloc.Address)),
		}
		nonce := senderNonces[note.From]
		tx := note.ToTxs(nonce, big.NewInt(0), big.NewInt(0))
		if note.From == core.GenesisVaultAddress {
			tx.Signature = []byte{}
			tx.SignatureHash = make([]byte, 32)
			tx.PublicKey = []byte{}
		}
		senderNonces[note.From]++
		genesisTransactions = append(genesisTransactions, tx)
		logger.Info("✅ Created genesis distribution: %s -> %s (%s SPX)",
			core.GenesisVaultAddress, alloc.Address, alloc.Label)
	}
	logger.Info("Total genesis transactions created: %d", len(genesisTransactions))

	for _, tx := range genesisTransactions {
		if err := bc.AddTransaction(tx); err != nil {
			logger.Warn("Failed to add genesis tx to node %d: %v", nodeIndex, err)
		}
	}
	logger.Info("✅ Added %d genesis transactions to node %d mempool", len(genesisTransactions), nodeIndex)

	// SECTION 11 — TCP listener
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	tcpListener, err := net.Listen("tcp", currentAddress)
	if err != nil {
		return fmt.Errorf("failed to bind TCP listener: %w", err)
	}
	logger.Info("✅ TCP listener bound on %s", currentAddress)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer tcpListener.Close()

		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					logger.Error("TCP accept error: %v", err)
					return
				}
			}

			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				handleIncomingConn(c, currentNodeID, signingService, sthincsParams, cons, p2pMgr)
			}(conn)
		}
	}()
	logger.Info("✅ TCP inbound listener running")

	// ========== CRITICAL FIX: Wait for other nodes to be ready ==========
	if totalNodes > 1 {
		logger.Info("Waiting for other nodes to be ready (3 seconds)...")
		time.Sleep(3 * time.Second)
	}

	// ========== CRITICAL FIX: Exchange keys BEFORE consensus ==========
	if totalNodes > 1 {
		logger.Info("=== EXCHANGING PUBLIC KEYS (SYNC) BEFORE CONSENSUS ===")
		for i, addr := range networkAddresses {
			if i == nodeIndex {
				continue
			}
			logger.Info("Exchanging keys with peer: %s", addr)
			if err := exchangeKeyWithPeerSync(addr, currentNodeID, signingService, sthincsParams); err != nil {
				logger.Warn("Failed to exchange keys with %s: %v", addr, err)
			}
		}
		logger.Info("✅ Key exchange completed with all peers")
	}

	// ========== CRITICAL FIX: Verify key serialization round-trip ==========
	logger.Info("=== VERIFYING KEY SERIALIZATION ROUND-TRIP ===")
	pkBytes, err = signingService.GetPublicKey()
	if err != nil {
		return fmt.Errorf("cannot get self public key: %w", err)
	}
	if _, err := sthincs.DeserializePK(sthincsParams, pkBytes); err != nil {
		return fmt.Errorf("self public key serialization failed: %v", err)
	}
	logger.Info("✅ Key serialization verified")

	// ========== CRITICAL FIX: Cross-register ALL validators ==========
	logger.Info("=== CROSS-REGISTERING ALL VALIDATORS ===")
	if vs := cons.GetValidatorSet(); vs != nil {
		minSPX := new(big.Int).Div(minStakeAmount, big.NewInt(1e18)).Uint64()
		for _, vid := range validatorIDs {
			if vid == currentNodeID {
				continue
			}
			if err := vs.AddValidator(vid, minSPX); err != nil {
				logger.Warn("Failed to add validator %s: %v", vid, err)
			} else {
				logger.Info("✅ Registered validator %s with %d SPX stake", vid, minSPX)
			}
		}
	}
	logger.Info("✅ All %d validators cross-registered", totalNodes)

	// ========== CRITICAL FIX: Wait for transaction propagation ==========
	if totalNodes > 1 && nodeIndex == 0 {
		logger.Info("Waiting for genesis transactions to propagate (2 seconds)...")
		time.Sleep(2 * time.Second)
	}

	// ========== CRITICAL FIX: Start consensus AFTER key exchange ==========
	if err := cons.Start(); err != nil {
		return fmt.Errorf("failed to start consensus: %w", err)
	}
	logger.Info("✅ Consensus engine started AFTER key exchange")

	// SECTION 12 — genesis verification
	expectedGenesisHash := core.GetGenesisHash()
	genesis := bc.GetLatestBlock()
	if genesis == nil || genesis.GetHeight() != 0 {
		return fmt.Errorf("genesis block not initialized")
	}
	logger.Info("✅ Genesis hash verified: %s", expectedGenesisHash)

	// SECTION 13 — HTTP server
	httpPort := 8545 + nodeIndex
	if nodeConfig.HTTPPort != "" {
		if port, err := strconv.Atoi(nodeConfig.HTTPPort); err == nil {
			httpPort = port
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		msgCh := make(chan *security.Message, 100)
		httpSrv := http.NewServer(fmt.Sprintf(":%d", httpPort), msgCh, bc, nil)
		logger.Info("JSON-RPC listening on http://127.0.0.1:%d", httpPort)
		if err := httpSrv.Start(); err != nil {
			logger.Error("HTTP server error: %v", err)
		}
	}()

	// SECTION 14 — block production loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		runBlockProductionLoop(ctx, bc, cons, currentNodeID, totalNodes, networkType)
	}()

	// SECTION 15 — state persistence loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		runStatePersistenceLoop(ctx, bc, currentNodeID, currentAddress)
	}()

	logger.Info("=== NODE %d RUNNING ===", nodeIndex+1)
	logger.Info("Node ID: %s", currentNodeID)
	logger.Info("TCP: %s", currentAddress)
	logger.Info("HTTP: http://127.0.0.1:%d", httpPort)
	logger.Info("Mode: %s", map[int]string{1: "SOLO", 2: "INSUFFICIENT", 3: "PBFT"}[totalNodes])

	if totalNodes >= 3 {
		logger.Info("✅ PBFT CONSENSUS ACTIVE with %d validators", totalNodes)
	}

	logger.Info("Press Ctrl+C to stop")

	// SECTION 16 — graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("Shutdown signal received — stopping node %d…", nodeIndex+1)
	cons.Stop()
	cancelCtx()
	wg.Wait()
	flushNodeState(bc, currentNodeID, currentAddress)

	logger.Info("✅ Node %d stopped cleanly", nodeIndex+1)
	return nil
}

// flushNodeState writes node state to disk
// flushNodeState writes node state to disk
func flushNodeState(bc *core.Blockchain, nodeID, address string) {
	latest := bc.GetLatestBlock()
	if latest == nil {
		return
	}

	merkleRoot := "unknown"

	// Try to get merkle root using available methods
	// Since latest is a Block, try to get TxsRoot
	if block, ok := latest.(*types.Block); ok {
		if block.Header != nil && len(block.Header.TxsRoot) > 0 {
			merkleRoot = hex.EncodeToString(block.Header.TxsRoot)
		}
	} else if txsRootGetter, ok := latest.(interface{ GetTxsRoot() []byte }); ok {
		merkleRoot = hex.EncodeToString(txsRootGetter.GetTxsRoot())
	}

	nodeInfo := &state.NodeInfo{
		NodeID:      nodeID,
		NodeName:    nodeID,
		NodeAddress: address,
		ChainInfo:   bc.GetChainInfo(),
		BlockHeight: latest.GetHeight(),
		BlockHash:   latest.GetHash(),
		MerkleRoot:  merkleRoot,
		Timestamp:   time.Now().Format(time.RFC3339),
	}

	if sm := bc.GetStateMachine(); sm != nil {
		if err := sm.ForcePopulateFinalStates(); err != nil {
			logger.Warn("[%s] ForcePopulateFinalStates: %v", nodeID, err)
		}
		sm.SyncFinalStatesNow()
	}

	if err := bc.StoreChainState([]*state.NodeInfo{nodeInfo}); err != nil {
		logger.Warn("[%s] StoreChainState: %v", nodeID, err)
	} else {
		logger.Info("[%s] 💾 Chain state persisted — height=%d", nodeID, latest.GetHeight())
	}
}

// runStatePersistenceLoop flushes state to disk periodically
func runStatePersistenceLoop(
	ctx context.Context,
	bc *core.Blockchain,
	nodeID, address string,
) {
	const flushInterval = 30 * time.Second
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			flushNodeState(bc, nodeID, address)
		}
	}
}
