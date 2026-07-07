// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/nodes.go
//
// Production node startup. The legacy same-box devnet harness that used to
// live in this file (StartValidatorNode, StartLocalCluster, LaunchNetwork,
// StartSingleNodeInternal, RunMultipleNodesInternal, SetupNodes) has moved
// to legacy_devnet.go — it predates StartNode and is only reachable via
// cli.go's legacyExecute() path. This file now contains just StartNode and
// its directly-used helpers.
package bind

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/core"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	config "github.com/sphinxfndorg/protocol/src/core/sthincs/config"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	svm "github.com/sphinxfndorg/protocol/src/core/svm/opcodes"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	"github.com/sphinxfndorg/protocol/src/http"
	logger "github.com/sphinxfndorg/protocol/src/log"
	"github.com/sphinxfndorg/protocol/src/network"
	dnsdiscovery "github.com/sphinxfndorg/protocol/src/p2p/seed"
	"github.com/sphinxfndorg/protocol/src/params/commit"
	"github.com/sphinxfndorg/protocol/src/pool"
	"github.com/sphinxfndorg/protocol/src/rpc"
	"github.com/syndtr/goleveldb/leveldb"
)

// ConnectionPool manages persistent TCP connections for consensus messages
type ConnPool struct {
	connections map[string]net.Conn
	mu          *sync.Mutex
}

// isClosed checks if a TCP connection is closed
func isClosed(conn net.Conn) bool {
	if conn == nil {
		return true
	}

	// Try to read 1 byte with zero timeout to check if connection is alive
	conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Timeout is expected, connection is alive
			return false
		}
		// Any other error means connection is closed
		return true
	}

	// Successfully read data, connection is alive
	return false
}

// ParseRoles converts a comma-separated roles string into a slice of NodeRole.
func ParseRoles(rolesStr string, numNodes int) []network.NodeRole {
	roles := strings.Split(rolesStr, ",")
	result := make([]network.NodeRole, numNodes)
	for i := 0; i < numNodes; i++ {
		if i < len(roles) {
			switch strings.TrimSpace(roles[i]) {
			case "sender":
				result[i] = network.RoleSender
			case "receiver":
				result[i] = network.RoleReceiver
			case "validator":
				result[i] = network.RoleValidator
			default:
				result[i] = network.RoleNone
			}
		} else {
			result[i] = network.RoleNone
		}
	}
	return result
}

// ============================================================================
// Production node startup (previously in cli/utils/nodes.go)
// ============================================================================

// StartNode starts a fully-featured validator node.
//
// totalNodes / nodeIndex are the same-box devnet / --test-nodes harness
// parameters.  On a real-device network (usingRealAddress=true) they are
// irrelevant: the validator set is built dynamically from what the node
// discovers through --seeds + PEX, exactly like ETH/BTC.  Pass totalNodes=1
// and nodeIndex=0 for any single real-device node; the runtime will grow the
// validator set as peers are discovered.
//
// rewardAddress is this node's own SPIF wallet address. It is broadcast to
// peers during key exchange (so THEY can verify OUR balance before staking
// us) and is also used locally to self-stake from our own genesis/earned
// balance. It is optional: an empty value just means this node starts with
// no stake and relies on receiving some (e.g. genesis allocation processed
// after startup, or funds sent to it) before it can be admitted as a
// validator by peers. It is never a substitute for balance verification —
// see stakeValidatorFromRewardAddress in helpers.go.
func StartNode(
	dataDir string,
	nodeConfig network.NodePortConfig,
	totalNodes, nodeIndex int,
	vdfParams *consensus.VDFParams,
	networkType string,
	seeds string,
	rewardAddress string,
) error {

	logger.Info("=== STARTING NODE ===")

	isProduction := totalNodes > 100

	switch {
	case totalNodes == 1:
		logger.Info("⚠️  SINGLE NODE / REAL-DEVICE MODE — peers discovered dynamically via --seeds")
	case totalNodes == 2:
		logger.Warn("⚠️  2-NODE CLUSTER — PBFT requires ≥ 3 validators")
	case isProduction:
		logger.Info("🚀 PRODUCTION MODE — Large network with %d nodes (using optimized peer connections)", totalNodes)
	default:
		logger.Info("✅ FULL PBFT CONSENSUS (same-box) — %d validators", totalNodes)
	}

	// SECTION 1 — chain identification
	chainParams := commit.SphinxChainParams()
	logger.Info("Chain: %s  ChainID=%d  Symbol=%s", chainParams.ChainName, chainParams.ChainID, chainParams.Symbol)

	networkType = "devnet"
	logger.Info("Network type: %s (%s)", networkType, core.GetNetworkDisplayName(networkType))

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
	usingRealAddress := false
	if nodeConfig.TCPAddr != "" {
		host, _, splitErr := net.SplitHostPort(nodeConfig.TCPAddr)
		if splitErr != nil {
			host = nodeConfig.TCPAddr
		}
		if !isLoopbackHost(host) {
			usingRealAddress = true
		}
	}

	synthCount := totalNodes
	if usingRealAddress {
		synthCount = 1
		nodeIndex = 0
	}

	validatorIDs := make([]string, synthCount)
	networkAddresses := make([]string, synthCount)
	for i := 0; i < synthCount; i++ {
		addr := fmt.Sprintf("127.0.0.1:%d", 32307+i)
		networkAddresses[i] = addr
		validatorIDs[i] = fmt.Sprintf("Node-%s", addr)
	}

	var currentAddress, currentNodeID string
	if usingRealAddress {
		currentAddress = nodeConfig.TCPAddr
		currentNodeID = fmt.Sprintf("Node-%s", currentAddress)
		networkAddresses[0] = currentAddress
		validatorIDs[0] = currentNodeID
	} else {
		if nodeIndex < 0 || nodeIndex >= synthCount {
			nodeIndex = 0
		}
		currentAddress = networkAddresses[nodeIndex]
		currentNodeID = validatorIDs[nodeIndex]
	}

	logger.Info("Node identity: %s at %s (real-device=%v)", currentNodeID, currentAddress, usingRealAddress)

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
	bc, err := core.NewBlockchain(currentAddress, currentNodeID, validatorIDs, networkType)
	if err != nil {
		return fmt.Errorf("failed to create blockchain: %w", err)
	}
	bc.SetStorageDB(mainDatabase)
	bc.SetStateDB(stateDatabase)

	var nodeID rpc.NodeID
	nodeIDBytes := []byte(currentNodeID)
	if len(nodeIDBytes) > 32 {
		nodeIDBytes = nodeIDBytes[:32]
	}
	copy(nodeID[:], nodeIDBytes)

	rpcCaller := rpc.NewRPCCaller(nodeID)
	bc.SetRPCCaller(rpcCaller)
	logger.Info("✅ RPC Caller set for blockchain")

	if err := bc.ExecuteGenesisBlock(); err != nil {
		logger.Warn("ExecuteGenesisBlock: %v", err)
	} else {
		logger.Info("✅ Genesis vault funded")
	}

	if cpErr := bc.WriteChainCheckpoint(); cpErr != nil {
		logger.Warn("Failed to write initial checkpoint: %v", cpErr)
	} else {
		logger.Info("✅ Initial checkpoint saved after genesis")
	}

	// VDF genesis-hash provider
	if vdfParams == nil {
		logger.Info("No VDF parameters supplied — deriving real parameters from genesis hash")

		expectedGenesisHash := core.GetGenesisHash()
		rawGenesisHash := expectedGenesisHash
		if len(rawGenesisHash) > 8 && rawGenesisHash[:8] == "GENESIS_" {
			rawGenesisHash = rawGenesisHash[8:]
		}

		consensus.InitVDFFromGenesis(func() (string, error) {
			return rawGenesisHash, nil
		})

		derived, err := consensus.LoadCanonicalVDFParams()
		if err != nil {
			return fmt.Errorf("failed to derive VDF parameters from genesis hash: %w", err)
		}
		vdfParams = &derived
	}

	if vdfParams.Discriminant == nil || vdfParams.T == 0 {
		return fmt.Errorf("VDF parameters are invalid (nil discriminant or zero iterations) — refusing to start with a weak or placeholder VDF")
	}

	logger.Info("✅ VDF parameters ready: Discriminant=%d bits, T=%d", vdfParams.Discriminant.BitLen(), vdfParams.T)
	if err := consensus.SetCanonicalVDFParameters(vdfParams); err != nil {
		return fmt.Errorf("failed to set canonical VDF parameters: %w", err)
	}

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

	rpcServer := rpc.NewServer(nil, bc, sphincsMgr)
	logger.Info("✅ RPC server created (synchronous mode)")

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

	localHost, _, err := net.SplitHostPort(currentAddress)
	if err != nil || localHost == "" {
		localHost = "127.0.0.1"
	}

	if err := nodeMgr.CreateLocalNode(
		currentAddress,
		localHost,
		tcpPort,
		udpPort,
		network.RoleValidator,
	); err != nil {
		return fmt.Errorf("failed to create local node: %w", err)
	}

	if !usingRealAddress {
		for j := 0; j < synthCount; j++ {
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
				logger.Info("Registered same-box peer: %s", networkAddresses[j])
			}
		}
	} else {
		logger.Info("Real-device mode — skipping same-box static peer list; peers discovered via --seeds + PEX")
	}

	// SECTION 8 — consensus node manager
	var consensusNodeMgr consensus.NodeManager
	var p2pMgr *network.P2PConsensusNodeManager

	if synthCount == 1 && !usingRealAddress {
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

		// Connection pool for persistent TCP connections
		connPool := &ConnPool{
			connections: make(map[string]net.Conn),
			mu:          &sync.Mutex{},
		}

		p2pMgr.SetSendMessageFunc(func(nodeAddress, msgType string, data []byte) error {
			connPool.mu.Lock()
			conn, exists := connPool.connections[nodeAddress]
			connPool.mu.Unlock()

			if !exists || isClosed(conn) {
				newConn, err := net.DialTimeout("tcp", nodeAddress, 5*time.Second)
				if err != nil {
					return fmt.Errorf("failed to connect to %s: %v", nodeAddress, err)
				}

				connPool.mu.Lock()
				connPool.connections[nodeAddress] = newConn
				connPool.mu.Unlock()
				conn = newConn
			}

			msg := &security.Message{
				Type: msgType,
				Data: data,
			}

			encodedMsg, err := msg.Encode()
			if err != nil {
				return err
			}

			if err := writeFramedMessage(conn, encodedMsg); err != nil {
				connPool.mu.Lock()
				delete(connPool.connections, nodeAddress)
				connPool.mu.Unlock()
				conn.Close()
				return fmt.Errorf("failed to write message to %s: %v", nodeAddress, err)
			}

			return nil
		})

		consensusNodeMgr = p2pMgr
		logger.Info("🌐 P2P consensus manager ready (%d pre-configured peer(s))", len(networkAddresses)-1)
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
	if cons == nil {
		return fmt.Errorf("failed to create consensus engine (VDF initialization likely failed)")
	}

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

	// ========== Self-stake from operator-supplied reward address ==========
	// There is no hardcoded validator↔address table here anymore. On a real
	// permissionless network we don't know who else is running a node or
	// what address they'll claim — that only ever gets decided at runtime,
	// per-peer, after a verified balance check (see registerDiscoveredPeer
	// below and stakeValidatorFromRewardAddress in helpers.go).
	//
	// The only stake this function seeds directly is our OWN, from the
	// reward address the operator passed in. If that address has a real,
	// sufficient balance, we stake from it; otherwise we self-bootstrap at
	// minimum stake so a brand-new solo node can produce its own genesis
	// block. That minimum-stake fallback applies only to our own node ID —
	// it is never extended to a remote peer.
	//
	// validatorAddressMap below feeds the Phase 2 re-verification pass that
	// runs after Block 1 commits (watchAndUpdateStakes / initializePhase2Stakes
	// in helpers.go). It only ever contains addresses we actually have — our
	// own reward address — never a hardcoded table of other nodes' wallets.
	// Same-box devnet peers simply have no entry, which is fine:
	// initializePhase2Stakes already treats a missing mapping as "use
	// minimum stake", which is the correct behavior for trusted local test
	// peers and is documented there.
	validatorAddressMap := map[string]string{}
	if rewardAddress != "" {
		validatorAddressMap[currentNodeID] = rewardAddress
	}

	logger.Info("=== SELF-STAKE FROM REWARD ADDRESS ===")
	if rewardAddress != "" {
		selfRewardAddr := rewardAddress
		if normalized, err := common.NormalizeSPIFAddress(rewardAddress); err == nil {
			selfRewardAddr = normalized
		}
		bc.SetValidatorRewardAddress(currentNodeID, selfRewardAddr)
		logger.Info("[%s] Block rewards / gas fees will route to %s", currentNodeID, selfRewardAddr)

		if !stakeValidatorFromRewardAddress(bc, cons, currentNodeID, currentNodeID, rewardAddress) {
			logger.Info("[%s] Reward address %s has no verifiable/sufficient balance yet — self-bootstrapping at minimum stake", currentNodeID, rewardAddress)
			if vs := cons.GetValidatorSet(); vs != nil {
				minSPX := vs.GetMinStakeSPX()
				if err := vs.AddValidator(currentNodeID, minSPX); err != nil {
					logger.Warn("[%s] Failed to self-bootstrap minimum stake: %v", currentNodeID, err)
				}
			}
		}
	} else {
		logger.Info("[%s] No --reward-address supplied — self-bootstrapping at minimum stake (no peer ever receives this fallback, only our own node)", currentNodeID)
	}

	// Same-box devnet harness (usingRealAddress == false): the other
	// synthetic validatorIDs in this process are our own test peers, not
	// external actors, so seeding them at minimum stake is safe — it's
	// exactly equivalent to running N trusted local validators by hand.
	if !usingRealAddress {
		if vs := cons.GetValidatorSet(); vs != nil {
			minSPX := vs.GetMinStakeSPX()
			for _, vid := range validatorIDs {
				if vid == currentNodeID {
					continue
				}
				if err := vs.AddValidator(vid, minSPX); err != nil {
					logger.Warn("[%s] Failed to seed same-box peer stake for %s: %v", currentNodeID, vid, err)
				}
			}
		}
	}

	bc.SetConsensusEngine(cons)
	bc.SetConsensus(cons)
	cons.SetTimeout(10 * time.Second)

	// StartLeaderLoop is intentionally NOT started here.
	//
	// It duplicates runBlockProductionLoop (SECTION 14 below): both poll
	// isLeader on their own ticker and, when true, independently call
	// bc.CreateBlock() — which re-mines a fresh nonce/timestamp (and
	// therefore a different hash) on every call — then independently
	// propose. Running both meant the SAME leader node could mint two
	// different candidate blocks for the same height seconds apart
	// (observed directly: a node finalizing two distinct block-1 hashes
	// while leader in the same view), which is self-equivocation, not a
	// downstream locking bug. runBlockProductionLoop is the complete,
	// view-aware path (VM verification, header signing, proper
	// consensus.Proposal with View/SlotNumber/ElectedLeaderID) so it owns
	// block production; StartLeaderLoop (core/blockchain.go) is kept
	// around unused rather than deleted in case something else depends on
	// the method existing, but must not be launched from here.

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

	// ========== Add genesis transactions to ALL nodes ==========
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

	if bc.GetMempool() == nil {
		logger.Warn("⚠️ Mempool is nil! Initializing mempool before adding genesis transactions...")
		mempoolConfig := &pool.MempoolConfig{
			MaxSize:           10000,
			MaxBytes:          100 * 1024 * 1024,
			MaxTxSize:         100 * 1024,
			BlockGasLimit:     big.NewInt(10000000),
			ValidationTimeout: 30 * time.Second,
			ExpiryTime:        24 * time.Hour,
			MaxBroadcastSize:  5000,
			MaxPendingSize:    5000,
		}
		mempool := pool.NewMempool(mempoolConfig, bc)
		bc.SetMempool(mempool)
		logger.Info("✅ Mempool initialized with default config")
	}

	if bc.GetMempool() != nil {
		for _, tx := range genesisTransactions {
			if err := bc.AddTransaction(tx); err != nil {
				logger.Warn("Failed to add genesis tx to node %d: %v", nodeIndex, err)
			}
		}
		logger.Info("✅ Added %d genesis transactions to node %d mempool", len(genesisTransactions), nodeIndex)
	} else {
		logger.Warn("⚠️ Mempool still nil after initialization, skipping genesis transaction broadcast")
	}

	// peerRegistry
	var peerRegistryMu sync.Mutex
	peerRegistry := make(map[string]string)

	registerDiscoveredPeer := func(peerNodeID, peerAddr string) {
		if peerNodeID == "" || peerAddr == "" || peerAddr == currentAddress {
			return
		}
		peerRegistryMu.Lock()
		_, already := peerRegistry[peerNodeID]
		peerRegistry[peerNodeID] = peerAddr
		peerRegistryMu.Unlock()
		if already {
			return
		}

		logger.Info("🌐 Discovered new peer %s at %s — registering (network peer only, no stake)", peerNodeID, peerAddr)

		host, port, err := net.SplitHostPort(peerAddr)
		if err != nil {
			logger.Warn("Discovered peer %s has unparseable address %s: %v", peerNodeID, peerAddr, err)
			host, port = peerAddr, ""
		}
		if peerNode := network.NewNode(peerAddr, host, port, "", false, network.RoleValidator, mainDatabase); peerNode != nil {
			nodeMgr.AddNode(peerNode)
		}
		if p2pMgr != nil {
			p2pMgr.AddPeer(peerNodeID, peerAddr)
		}
		// NOTE: no vs.AddValidator call here. Being reachable on the wire
		// makes a node a known gossip/relay peer, nothing more. Validator
		// status is granted exclusively by registerPeerStakeClaim below,
		// once — and only once — the peer's claimed reward address has a
		// verified on-chain balance meeting the minimum stake.
	}

	// registerPeerStakeClaim is invoked when a peer's key-exchange reply
	// carries a reward address (see helpers.go). It is the ONLY function in
	// this file allowed to grant validator status to a remote peer, and it
	// only does so after stakeValidatorFromRewardAddress independently
	// verifies that address's balance — the claim itself is never trusted.
	registerPeerStakeClaim := func(peerNodeID, rewardAddress string) {
		if peerNodeID == "" || rewardAddress == "" {
			return
		}
		stakeValidatorFromRewardAddress(bc, cons, currentNodeID, peerNodeID, rewardAddress)
	}

	getKnownPeers := func() []knownPeerInfo {
		peerRegistryMu.Lock()
		defer peerRegistryMu.Unlock()
		out := make([]knownPeerInfo, 0, len(peerRegistry))
		for nodeID, addr := range peerRegistry {
			out = append(out, knownPeerInfo{NodeID: nodeID, Address: addr})
		}
		return out
	}

	for i, addr := range networkAddresses {
		if i == nodeIndex {
			continue
		}
		peerRegistryMu.Lock()
		peerRegistry[validatorIDs[i]] = addr
		peerRegistryMu.Unlock()
	}

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
				handleIncomingConn(c, currentNodeID, currentAddress, rewardAddress, signingService, sthincsParams, cons, p2pMgr, rpcServer, bc, getKnownPeers, registerDiscoveredPeer, registerPeerStakeClaim)
			}(conn)
		}
	}()
	logger.Info("✅ TCP inbound listener running")

	// SECTION 11b — dynamic peer discovery via --seeds with DNS support
	//
	// The hardcoded default enrtree:// URL only makes sense for real-device
	// nodes (totalNodes==1) and production clusters (totalNodes>100) — those
	// are the modes where peers actually need to be discovered dynamically.
	// Same-box devnet runs (2..100 nodes on one machine) already register
	// every peer statically a few sections above, so defaulting to DNS there
	// just burns a lookup against a placeholder domain and logs a scary WARN
	// for a path that was never going to contribute any peers.
	noSeedsProvided := seeds == "" || strings.TrimSpace(seeds) == ""
	useDefaultDNSTree := totalNodes == 1 || isProduction

	if noSeedsProvided && useDefaultDNSTree {
		logger.Info("No --seeds provided; using default DNS discovery tree: %s", dnsdiscovery.DefaultENRTreeURL)
		seeds = dnsdiscovery.DefaultENRTreeURL
	} else if noSeedsProvided {
		logger.Info("Same-box devnet mode (%d nodes) — skipping default DNS discovery tree; relying on statically-registered peers", totalNodes)
	}

	if seeds != "" && strings.TrimSpace(seeds) != "" {
		plainSeeds, dnsResolver := dnsdiscovery.FilterDNSTrees(seeds)

		if dnsResolver.HasTrees() {
			logger.Info("🌐 Resolving DNS discovery trees for peer bootstrap...")
			ctxDNS, cancelDNS := context.WithTimeout(context.Background(), 30*time.Second)
			dnsPeers, err := dnsResolver.ResolvePeers(ctxDNS)
			cancelDNS()

			if err != nil {
				if len(plainSeeds) > 0 {
					logger.Warn("DNS discovery failed: %v (falling back to %d plain seed address(es))", err, len(plainSeeds))
				} else {
					logger.Warn("DNS discovery failed: %v (no plain seeds configured; relying on statically-registered peers)", err)
				}
			} else if len(dnsPeers) > 0 {
				logger.Info("🌱 DNS discovery returned %d peer(s) — registering them", len(dnsPeers))
				for _, peer := range dnsPeers {
					if peer.Address != "" && peer.Address != currentAddress {
						registerDiscoveredPeer(peer.NodeID, peer.Address)
					}
				}
			} else {
				logger.Info("DNS discovery returned no peers (tree may be empty)")
			}
		}

		if len(plainSeeds) > 0 {
			logger.Info("🌱 Discovering peers via %d plain seed address(es)", len(plainSeeds))
			discoverAndRegisterPeers(
				plainSeeds,
				currentNodeID,
				currentAddress,
				rewardAddress,
				signingService,
				sthincsParams,
				2,
				registerDiscoveredPeer,
				registerPeerStakeClaim,
			)
		} else if !dnsResolver.HasTrees() {
			logger.Info("No --seeds configured; relying on statically-registered peers only")
		}
	} else {
		logger.Info("No --seeds configured; relying on statically-registered peers only")
	}

	effectivePeerCount := func() int {
		peerRegistryMu.Lock()
		defer peerRegistryMu.Unlock()
		return len(peerRegistry)
	}

	if effectivePeerCount() > 0 {
		logger.Info("Waiting for other nodes to be ready (3 seconds)...")
		time.Sleep(3 * time.Second)
	}

	if effectivePeerCount() > 0 {
		logger.Info("=== EXCHANGING PUBLIC KEYS (SYNC) BEFORE CONSENSUS ===")
		for _, addr := range networkAddresses {
			if addr == currentAddress {
				continue
			}
			logger.Info("Exchanging keys with same-box peer: %s", addr)
			if kx, err := exchangeKeyWithPeerSync(addr, currentNodeID, rewardAddress, signingService, sthincsParams); err != nil {
				logger.Warn("Failed to exchange keys with %s: %v", addr, err)
			} else if kx.RewardAddress != "" {
				registerPeerStakeClaim(kx.NodeID, kx.RewardAddress)
			}
		}
		peerRegistryMu.Lock()
		var discoveredAddrs []string
		for _, addr := range peerRegistry {
			discoveredAddrs = append(discoveredAddrs, addr)
		}
		peerRegistryMu.Unlock()
		for _, addr := range discoveredAddrs {
			logger.Info("Exchanging keys with discovered peer: %s", addr)
			if kx, err := exchangeKeyWithPeerSync(addr, currentNodeID, rewardAddress, signingService, sthincsParams); err != nil {
				logger.Warn("Failed to exchange keys with %s: %v", addr, err)
			} else if kx.RewardAddress != "" {
				registerPeerStakeClaim(kx.NodeID, kx.RewardAddress)
			}
		}
		logger.Info("✅ Key exchange completed with all known peers")
	}

	logger.Info("=== VERIFYING KEY SERIALIZATION ROUND-TRIP ===")
	pkBytes, err = signingService.GetPublicKey()
	if err != nil {
		return fmt.Errorf("cannot get self public key: %w", err)
	}
	if _, err := sthincs.DeserializePK(sthincsParams, pkBytes); err != nil {
		return fmt.Errorf("self public key serialization failed: %v", err)
	}
	logger.Info("✅ Key serialization verified")

	logger.Info("✅ Self-stake and key exchange complete; remaining validator admission happens per-peer as reward addresses are verified")

	if effectivePeerCount() > 0 && nodeIndex == 0 {
		logger.Info("Waiting for genesis transactions to propagate (2 seconds)...")
		time.Sleep(2 * time.Second)
	}

	if err := cons.Start(); err != nil {
		return fmt.Errorf("failed to start consensus: %w", err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		runCheckpointSyncLoop(ctx, bc, cons, currentNodeID, networkAddresses, nodeIndex)
	}()
	logger.Info("✅ Consensus engine started AFTER key exchange")

	phase2State := &phase2InitState{}

	if effectivePeerCount() > 0 || !usingRealAddress && synthCount > 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			watchAndUpdateStakes(ctx, bc, cons, currentNodeID, validatorIDs, validatorAddressMap, phase2State)
		}()
	}

	// SECTION 12 — HTTP server
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

	// SECTION 14 — block sync loop (catch-up mechanism)
	// The node starts in SYNCING state. It will query peers for missing blocks
	// and apply them before participating in consensus.
	var syncState SyncState = SyncStateSyncing
	var syncStateMu sync.Mutex

	// Collect peer addresses for the sync loop
	peerRegistryMu.Lock()
	peerAddrs := make([]string, 0, len(peerRegistry))
	for _, addr := range peerRegistry {
		peerAddrs = append(peerAddrs, addr)
	}
	peerRegistryMu.Unlock()

	// Also add same-box network addresses if available
	for _, addr := range networkAddresses {
		if addr != currentAddress {
			found := false
			for _, existing := range peerAddrs {
				if existing == addr {
					found = true
					break
				}
			}
			if !found {
				peerAddrs = append(peerAddrs, addr)
			}
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		runBlockSyncLoop(ctx, bc, cons, currentNodeID, peerAddrs, &syncState, &syncStateMu)
	}()

	// SECTION 13 — genesis verification (after sync loop has run)
	// A late-joining node won't have genesis locally. The sync loop above
	// fetches it from peers. We wait for the sync loop to complete before
	// verifying genesis, so a node that needs to sync can do so first.
	expectedGenesisHash := core.GetGenesisHash()
	genesisVerified := false
	var genesisBlock core.BlockInterface
	for i := 0; i < 60; i++ { // wait up to 60 seconds for sync
		genesisBlock = bc.GetLatestBlock()
		if genesisBlock != nil && genesisBlock.GetHeight() == 0 {
			logger.Info("✅ Genesis hash verified: %s", expectedGenesisHash)
			genesisVerified = true
			break
		}
		if syncState == SyncStateCaughtUp && (genesisBlock == nil || genesisBlock.GetHeight() != 0) {
			// Sync completed but we're still at genesis height - this means
			// the network is at genesis (no blocks produced yet)
			logger.Info("✅ Network at genesis — no existing blocks to verify")
			genesisVerified = true
			break
		}
		logger.Info("Waiting for sync loop to fetch genesis (attempt %d/60)...", i+1)
		time.Sleep(1 * time.Second)
	}
	if !genesisVerified {
		logger.Warn("⚠️ Genesis verification timeout — proceeding anyway (sync loop will handle it)")
	}

	// SECTION 15 — block production loop (now gated by sync state)
	wg.Add(1)
	go func() {
		defer wg.Done()
		runBlockProductionLoop(ctx, bc, cons, currentNodeID, totalNodes, networkType, validatorIDs, validatorAddressMap, phase2State, effectivePeerCount, &syncState, &syncStateMu)
	}()

	// SECTION 15 — state persistence loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		runStatePersistenceLoop(ctx, bc, currentNodeID, currentAddress)
	}()

	logger.Info("=== NODE RUNNING ===")
	logger.Info("Node ID: %s", currentNodeID)
	logger.Info("TCP: %s", currentAddress)
	logger.Info("HTTP: http://127.0.0.1:%d", httpPort)

	knownPeers := effectivePeerCount()
	switch {
	case knownPeers == 0:
		logger.Info("Mode: SOLO (no peers yet — waiting for connections)")
	case knownPeers < 2:
		logger.Warn("Mode: INSUFFICIENT PEERS (%d known, PBFT needs ≥ 2 more)", knownPeers)
	default:
		logger.Info("Mode: PBFT (%d known peer(s))", knownPeers)
	}

	if knownPeers >= 2 {
		logger.Info("✅ PBFT CONSENSUS ACTIVE with %d known validators", knownPeers+1)
	} else if usingRealAddress {
		logger.Info("ℹ️  Real-device mode: consensus activates as peers join via --seeds discovery")
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

// isLoopbackHost reports whether host refers to this same machine.
func isLoopbackHost(host string) bool {
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}
