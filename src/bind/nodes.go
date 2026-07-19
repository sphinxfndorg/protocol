// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/nodes.go
//
// Production node startup. The legacy same-box devnet harness that used to
// live in this file (StartValidatorNode, StartLocalCluster, LaunchNetwork,
// StartSingleNodeInternal, RunMultipleNodesInternal, SetupNodes) has moved
// to legacy.go — it predates StartNode and is only reachable via
// cli.go's legacyExecute() path. This file now contains just StartNode and
// its directly-used helpers.
package bind

import (
	"context"
	"encoding/hex"
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
	logger "github.com/sphinxfndorg/protocol/src/console"
	"github.com/sphinxfndorg/protocol/src/core"
	svm "github.com/sphinxfndorg/protocol/src/core/kernel/opcodes"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	config "github.com/sphinxfndorg/protocol/src/core/sthincs/config"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	"github.com/sphinxfndorg/protocol/src/dht"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	"github.com/sphinxfndorg/protocol/src/http"
	"github.com/sphinxfndorg/protocol/src/network"
	dnsdiscovery "github.com/sphinxfndorg/protocol/src/p2p/seed"
	"github.com/sphinxfndorg/protocol/src/params/commit"
	"github.com/sphinxfndorg/protocol/src/rpc"
	"github.com/sphinxfndorg/protocol/src/state"
	"github.com/sphinxfndorg/protocol/src/transport"
	"github.com/syndtr/goleveldb/leveldb"
	"go.uber.org/zap"
)

// ConnectionPool manages persistent TCP connections for consensus messages
type ConnPool struct {
	connections map[string]net.Conn
	mu          sync.Mutex
}

// Get retrieves a live connection from the pool, or nil if none exists.
func (p *ConnPool) Get(addr string) net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	conn := p.connections[addr]
	if conn == nil {
		return nil
	}
	// If the pooled connection is already closed, discard it.
	if isClosed(conn) {
		delete(p.connections, addr)
		return nil
	}
	return conn
}

// Put stores a connection in the pool. Any previously pooled connection for
// the same address is closed and replaced. Passing nil removes the entry.
func (p *ConnPool) Put(addr string, conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if old, ok := p.connections[addr]; ok && old != nil {
		// Ignore close error; we're just cleaning up
		_ = old.Close()
	}
	if conn == nil {
		delete(p.connections, addr)
	} else {
		p.connections[addr] = conn
	}
}

// CloseAll closes every pooled connection and clears the map.
func (p *ConnPool) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range p.connections {
		if conn != nil {
			_ = conn.Close()
		}
	}
	p.connections = make(map[string]net.Conn)
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

	// ════════════════════════════════════════════════════════════════════
	// ★ FIX: Respect --datadir flag. Without this, all path resolution
	// (GetNodeDataDir, GetLevelDBPath, etc.) falls back to the default
	// directory "data" regardless of what the user passed.
	// ════════════════════════════════════════════════════════════════════
	common.SetDataDir(dataDir)

	// ── Create interactive dashboard ──
	r := logger.Default()
	log := logger.NewLogger(r)
	progress := logger.NewBlockchainProgress(r, log)
	progress.Status().SetTitle("SPHINX Node")
	progress.StartNodeStartup()
	defer progress.Stop()

	// Let core.CreateBlock report block production / merkle root / state
	// root / nonce mining to this dashboard, regardless of which path
	// invokes it (solo mining, PBFT leader loop, ...). See
	// core.SetUIProgress for why this crosses the bind -> core package
	// boundary as a registration call rather than a constructor argument.
	core.SetUIProgress(progress)
	defer core.SetUIProgress(nil)

	logger.Info("=== STARTING NODE ===")

	isProduction := totalNodes > 100

	switch {
	case totalNodes == 1:
		logger.Info("SINGLE NODE / REAL-DEVICE MODE — peers discovered dynamically via --seeds")
	case totalNodes == 2:
		logger.Warn("2-NODE CLUSTER — PBFT requires ≥ 3 validators")
	case isProduction:
		logger.Info("PRODUCTION MODE — Large network with %d nodes (using optimized peer connections)", totalNodes)
	default:
		logger.Info("FULL PBFT CONSENSUS (same-box) — %d validators", totalNodes)
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
	logger.Info("Shared STHINCS parameters created")

	// SECTION 3 — node identity
	// ── Determine real-device vs same-box mode ──
	// real-device mode: the user provided a public / non-loopback IP.
	//   In this mode we don't pre-configure peer addresses; discovery
	//   happens via --seeds / DNS + PEX.  synthCount = 1.
	//
	// same-box mode: all nodes on loopback, using the legacy hardcoded
	//   32307+ port range.  synthCount = totalNodes.
	//
	// ★ FIX: When --tcp-addr is explicitly provided by the user (even for
	// loopback like 127.0.0.1:30303), use it as the node's own address.
	// The old code went to the else branch for all loopback addresses,
	// silently replacing e.g. 127.0.0.1:30303 with 127.0.0.1:32307.
	// Now we detect that nodeConfig.TCPAddr differs from the default
	// hardcoded port and honour the user's choice.
	usingRealAddress := false
	userProvidedTCP := false
	if nodeConfig.TCPAddr != "" {
		host, _, splitErr := net.SplitHostPort(nodeConfig.TCPAddr)
		if splitErr != nil {
			host = nodeConfig.TCPAddr
		}
		if !isLoopbackHost(host) {
			usingRealAddress = true
		}
		// Check if the port differs from the default same-box port
		_, portStr, _ := net.SplitHostPort(nodeConfig.TCPAddr)
		defaultPort := fmt.Sprintf("%d", 32307+nodeIndex)
		if portStr != "" && portStr != defaultPort {
			userProvidedTCP = true
		}
	}

	// ★ FIX: synthCount determines whether we generate static peer addresses.
	// - real-device mode (public IP): synthCount = 1, peers via seeds/DHT
	// - custom loopback ports with --nodes/--node-index AND --seeds: synthCount = totalNodes
	//   (peers are derived from the custom port using nodeIndex offset)
	// - custom loopback ports with --nodes/--node-index but NO --seeds: synthCount = 1
	//   (bootstrap node — must enter SOLO_MODE, not wait for nonexistent peers)
	// - custom loopback ports with no --nodes: synthCount = 1, no static peers
	// - legacy same-box (no --tcp-addr): synthCount = totalNodes, hardcoded 32307+
	synthCount := totalNodes
	if usingRealAddress {
		synthCount = 1
		nodeIndex = 0
	}
	// Bootstrap node (no --seeds) must use solo mode regardless of --nodes.
	// Without this, synthCount=3 makes it use P2P consensus manager, and the
	// sync loop blocks forever waiting for peers that don't exist yet.
	if seeds == "" && synthCount > 1 {
		synthCount = 1
		nodeIndex = 0
	}

	var currentAddress, currentNodeID string
	validatorIDs := make([]string, synthCount)
	networkAddresses := make([]string, synthCount)

	// Determine the base host and port for generating peer addresses.
	// When userProvidedTCP, parse the actual address; otherwise use 32307+.
	baseHost := "127.0.0.1"
	basePort := 32307
	if userProvidedTCP || usingRealAddress {
		h, pStr, err := net.SplitHostPort(nodeConfig.TCPAddr)
		if err == nil {
			baseHost = h
			if p, err := strconv.Atoi(pStr); err == nil {
				basePort = p - nodeIndex // Derive base: port - nodeIndex
			}
		}
	}

	for i := 0; i < synthCount; i++ {
		addr := fmt.Sprintf("%s:%d", baseHost, basePort+i)
		networkAddresses[i] = addr
		validatorIDs[i] = fmt.Sprintf("Node-%s", addr)
	}

	if synthCount == 1 {
		// Single-node mode: use the actual address from config/seed
		if userProvidedTCP || usingRealAddress {
			currentAddress = nodeConfig.TCPAddr
		} else {
			currentAddress = networkAddresses[nodeIndex]
		}
		currentNodeID = fmt.Sprintf("Node-%s", currentAddress)
	} else {
		if nodeIndex < 0 || nodeIndex >= synthCount {
			nodeIndex = 0
		}
		currentAddress = networkAddresses[nodeIndex]
		currentNodeID = validatorIDs[nodeIndex]
	}

	logger.Info("Node identity: %s at %s (real-device=%v, datadir=%s)", currentNodeID, currentAddress, usingRealAddress, dataDir)

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

	// ★ FIX: signingService construction moved up from SECTION 6 (below) to
	// here, BEFORE core.NewBlockchain()/bc.FinishInit(). Those calls build
	// genesis synchronously (createGenesisBlock -> GenesisState.BuildBlock),
	// and BuildBlock now signs the genesis block using whichever signer was
	// registered via core.SetGenesisSigner — so the signer has to exist and
	// be registered before genesis gets built, not after. Everything this
	// needs (db, sharedKeyManager, sharedSphincsParams, currentNodeID) is
	// already available at this point.
	sphincsMgr := sign.NewSTHINCSManager(db, sharedKeyManager, sharedSphincsParams)
	signingService := consensus.NewSigningService(sphincsMgr, sharedKeyManager, currentNodeID)

	if selfPK := signingService.GetPublicKeyObject(); selfPK != nil {
		signingService.RegisterPublicKey(currentNodeID, selfPK)
		logger.Info("Self public key registered")
	}

	// Only the node that's actually bootstrapping a fresh chain should sign
	// genesis — a late joiner downloads genesis (and its signature) from
	// peers via the sync loop instead of minting its own.
	if seeds == "" {
		core.SetGenesisSigner(signingService, currentNodeID)
	}

	// SECTION 5 — blockchain + genesis
	//
	// ★ FIX: core.NewBlockchain() now defers chain loading / genesis creation
	// (via core.WithDeferredInit()) so we can attach mainDatabase/stateDatabase
	// to bc.storage BEFORE that runs. Previously bc.SetStorageDB/bc.SetStateDB
	// were called AFTER core.NewBlockchain() returned — too late, since a
	// fresh node's chain loading calls ExecuteGenesisBlock() synchronously,
	// which needs bc.storage.GetDB() to already have a handle. That ordering
	// gap caused "no shared database handle" / "failed to open stateDB"
	// panics on first-run genesis creation. bc.FinishInit() now does that
	// deferred work, once the DB handles are attached.
	bc, err := core.NewBlockchain(currentAddress, currentNodeID, validatorIDs, networkType, seeds != "", core.WithDeferredInit())
	if err != nil {
		return fmt.Errorf("failed to create blockchain: %w", err)
	}
	bc.SetStorageDB(mainDatabase)
	bc.SetStateDB(stateDatabase)
	if err := bc.FinishInit(currentNodeID); err != nil {
		return fmt.Errorf("failed to create blockchain: %w", err)
	}

	var nodeID rpc.NodeID
	nodeIDBytes := []byte(currentNodeID)
	if len(nodeIDBytes) > 32 {
		nodeIDBytes = nodeIDBytes[:32]
	}
	copy(nodeID[:], nodeIDBytes)

	rpcCaller := rpc.NewRPCCaller(nodeID)
	bc.SetRPCCaller(rpcCaller)
	logger.Info("RPC Caller set for blockchain")

	// Late joiners MUST NOT execute/patch genesis locally.
	// genesis execution (vault funding) must happen only on the first node that
	// created genesis in its own storage.
	if !bc.IsLateJoiner() {
		if err := bc.ExecuteGenesisBlock(); err != nil {
			logger.Warn("ExecuteGenesisBlock: %v", err)
		} else {
			logger.Info("Genesis vault funded")
		}

		if cpErr := bc.WriteChainCheckpoint(); cpErr != nil {
			logger.Warn("Failed to write initial checkpoint: %v", cpErr)
		} else {
			logger.Info("Initial checkpoint saved after genesis")
		}
	} else {
		logger.Info("Late-joiner mode: skipping ExecuteGenesisBlock() and initial checkpoint; will sync genesis+blocks from peers")
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

	logger.Info("VDF parameters ready: Discriminant=%d bits, T=%d", vdfParams.Discriminant.BitLen(), vdfParams.T)
	if err := consensus.SetCanonicalVDFParameters(vdfParams); err != nil {
		return fmt.Errorf("failed to set canonical VDF parameters: %w", err)
	}

	// SECTION 6 — signing service
	// (sphincsMgr/signingService were constructed earlier, in SECTION 4,
	// before core.NewBlockchain — see the ★ FIX comment there. Only the
	// public-key serialization/logging below still happens here.)
	pkBytes, err := signingService.GetPublicKey()
	if err != nil {
		return fmt.Errorf("cannot serialize self public key: %w", err)
	}
	logger.Info("Self public key size: %d bytes", len(pkBytes))

	rpcServer := rpc.NewServer(nil, bc, sphincsMgr)
	logger.Info("RPC server created (synchronous mode)")

	// SECTION 7 — network node manager
	// ── Parse TCP/UDP addresses first (needed for local node + DHT) ──
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

	// ════════════════════════════════════════════════════════════════════
	// ★ FIX: Wire up the Kademlia DHT for iterative peer discovery.
	// Previously this was hardcoded nil — the DHT interface existed and
	// a full implementation lived in src/dht/, but StartNode never
	// instantiated it. Now we create a real DHT instance bound to our
	// UDP port, giving the NodeManager true Kademlia iterative lookups
	// instead of relying solely on static seeds + PEX gossip.
	// ════════════════════════════════════════════════════════════════════
	udpPortNum := 32308 + nodeIndex
	if nodeConfig.UDPPort != "" {
		if p, err := strconv.Atoi(nodeConfig.UDPPort); err == nil {
			udpPortNum = p
		}
	}

	localUDPAddr := &net.UDPAddr{IP: net.ParseIP(localHost), Port: udpPortNum}

	// Parse seed addresses into UDP router addresses for DHT join
	var dhtRouters []net.UDPAddr
	if seeds != "" {
		for _, seed := range strings.Split(seeds, ",") {
			seed = strings.TrimSpace(seed)
			if seed == "" {
				continue
			}
			// Skip enrtree:// URLs — those are DNS, not plain UDP routers
			if strings.HasPrefix(seed, "enrtree://") {
				continue
			}
			if h, p, err := net.SplitHostPort(seed); err == nil {
				sp, _ := strconv.Atoi(p)
				dhtRouters = append(dhtRouters, net.UDPAddr{IP: net.ParseIP(h), Port: sp})
			}
		}
	}

	// If no routers from seeds and not same-box, try the default DNS seed
	if len(dhtRouters) == 0 && usingRealAddress {
		logger.Info("No DHT routers from --seeds; DHT will bootstrap via DNS discovery tree + PEX")
	}

	dhtCfg := dht.Config{
		Proto:   "udp4",
		Address: *localUDPAddr,
		Routers: dhtRouters,
		Secret:  0, // Zero means no secret filtering
	}

	zapLogger, err := zap.NewProduction()
	if err != nil {
		return fmt.Errorf("failed to create zap logger for DHT: %w", err)
	}

	dhtInstance, err := dht.NewDHT(dhtCfg, zapLogger)
	if err != nil {
		logger.Warn("Failed to create DHT instance: %v — continuing without Kademlia peer discovery", err)
		// Non-fatal: fall back to static seeds + PEX gossip
		dhtInstance = nil
	} else {
		logger.Info("Kademlia DHT initialised on %s with %d router(s)", localUDPAddr.String(), len(dhtRouters))

		// Start the DHT in a background goroutine
		if startErr := dhtInstance.Start(); startErr != nil {
			logger.Warn("Failed to start DHT: %v — continuing without Kademlia", startErr)
		} else {
			logger.Info("Kademlia DHT started — iterative peer lookup/routing is now active")
		}
	}

	nodeMgr := network.NewNodeManager(16, dhtInstance, mainDatabase)

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
	//
	// ★ FIX: ALWAYS build a real, network-capable P2PConsensusNodeManager —
	// never a local-only CallNodeManager — regardless of synthCount.
	//
	// A real blockchain cannot force every node to start at the same time,
	// and the genesis/bootstrap node in particular must be able to mine
	// solo with zero peers present, then have late joiners fold in live
	// whenever they happen to connect, with no restart and no rewiring.
	//
	// registerDiscoveredPeer (below, ~line 787) already implements exactly
	// that: on every newly-discovered peer it calls p2pMgr.AddPeer(...) so
	// the transport layer picks up new validators dynamically at runtime.
	// But that call is guarded by `if p2pMgr != nil`, and the old code left
	// p2pMgr nil whenever synthCount==1 (i.e. exactly the bootstrap-node
	// case) — so the dynamic join path silently no-op'd on the one node
	// that most needs it. The bootstrap node then entered "PBFT mode" via
	// the solo-to-PBFT handoff in helpers.go with its consensus engine
	// still wired to a manager with zero real peers and no way to ever gain
	// any, which is the root cause of the "solo miner stuck" symptom.
	//
	// Solo-vs-PBFT behavior itself is unaffected by this change — that is
	// still decided purely by effectiveValidatorCount() in helpers.go,
	// which already tracks live peer discovery via peerRegistry. This
	// change only ensures the actual message transport is real and
	// listening from block 0, so that by the time effectiveValidatorCount()
	// says "3 validators known", p2pMgr already has those peers wired in
	// and can actually send/receive prepare/vote/commit over TCP.
	var consensusNodeMgr consensus.NodeManager
	p2pMgr := network.NewP2PConsensusNodeManager(nodeMgr, currentNodeID)

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

		if err := writeFramedMessage(conn, encodedMsg); err != nil {
			return fmt.Errorf("failed to write message to %s: %v", nodeAddress, err)
		}

		return nil
	})

	consensusNodeMgr = p2pMgr
	if synthCount == 1 && !usingRealAddress {
		logger.Info("P2P consensus manager ready (0 pre-configured peers — solo/genesis start, peers join dynamically)")
	} else {
		logger.Info("P2P consensus manager ready (%d pre-configured peer(s))", len(networkAddresses)-1)
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
			logger.Info("Self validator registered")
		}
	}

	// ========== Self-stake from operator-supplied reward address ==========
	// There is no hardcoded validator↔address table here anymore. On a real
	// permissionless network we don't know who else is running a node or
	// what address they'll claim — that only ever gets decided at runtime,
	// per-peer, after a verified balance check (see registerDiscoveredPeer
	// below and registerPeerStakeClaim in helpers.go).
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
	logger.Info("Consensus engine registered")

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
	logger.Info("VM SPHINCS+ verifier registered")

	// ★ REMOVED: this block used to build the same 9 genesis allocations
	// from core.DefaultGenesisAllocations() a second time, as ordinary
	// signed transactions, and push them through bc.AddTransaction() —
	// the same validation path used for regular user transactions.
	//
	// It ran unconditionally on every node (bootstrap AND late-joiners)
	// and its output (`genesisTransactions`) was never read by anything
	// else — not passed to ExecuteGenesisBlock(), not included in the
	// genesis block. Genesis funding is already handled correctly above
	// by bc.ExecuteGenesisBlock() (bootstrap-node-only, gated on
	// !bc.IsLateJoiner() at line ~338), which applies the allocations
	// directly to state without going through mempool validation.
	//
	// Because these transactions came from the trusted, unsigned
	// GenesisVaultAddress (tx.Signature / tx.PublicKey deliberately left
	// empty a few lines below), they could never pass normal transaction
	// validation, which expects a real signature and bounded OP_RETURN
	// data. Confirmed against logs from all three nodes in the 3-node
	// devnet test (bootstrap and both late-joiners): every single run,
	// all 9/9 "genesis distribution" transactions failed —
	// 4 with "OP_RETURN size exceeded" (the longer hash-style allocation
	// addresses push ReturnData over the limit) and 5 with "nonce
	// validation failed: VM nonce validation failed: error executing
	// opcode 0x36 at pc=19: stack underflow" (the empty Signature/
	// PublicKey breaks the VM's nonce-derivation path for every
	// GenesisVaultAddress-signed transaction that gets that far). None
	// of the 9 ever succeeded, on any node, in any observed run — this
	// block did nothing but log 9 misleading WARNs per node startup.

	// peerRegistry is the address book: nodeID -> address, used for
	// effectivePeerCount()/getKnownPeers() bookkeeping and gossip. It may
	// be pre-populated (see the static same-box registration below) before
	// a peer's real key exchange completes, so it must NOT be used as the
	// dedup guard for one-time side effects (AddNode/AddPeer/stake grant)
	// — otherwise a pre-registered peer's real registration silently
	// no-ops the very first (and only) time it would actually run.
	var peerRegistryMu sync.Mutex
	peerRegistry := make(map[string]string)

	// registeredPeers tracks which peer IDs have already had their
	// one-time side effects (AddNode/p2pMgr.AddPeer/stake grant) applied.
	// This is intentionally a separate set from peerRegistry — see above.
	var registeredMu sync.Mutex
	registeredPeers := make(map[string]bool)

	registerDiscoveredPeer := func(peerNodeID, peerAddr string) {
		if peerNodeID == "" || peerAddr == "" || peerAddr == currentAddress {
			return
		}
		peerRegistryMu.Lock()
		peerRegistry[peerNodeID] = peerAddr
		peerCount := len(peerRegistry)
		peerRegistryMu.Unlock()

		registeredMu.Lock()
		already := registeredPeers[peerNodeID]
		registeredPeers[peerNodeID] = true
		registeredMu.Unlock()
		if already {
			return
		}

		logger.Info("Discovered new peer %s at %s — registering as network peer", peerNodeID, peerAddr)

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

		// Update dashboard with peer count
		progress.CheckNetworkHealth(true, peerCount)

		// ★ FIX: Grant minimum stake to the peer as a validator immediately.
		// Previously, validator status was only granted by registerPeerStakeClaim,
		// which requires a non-empty reward-address from the peer's key-exchange
		// reply AND a verified on-chain balance. In test/devnet mode (no
		// --reward-address flag), both conditions fail, so every peer is
		// permanently excluded from the validator set — each node sees only
		// itself as a validator (32 SPX), PBFT quorum is permanently impossible,
		// and "100% quorum" reports are fraudulent (each node voting alone).
		//
		// Granting minimum stake here is safe because:
		//   1. This is a permissioned network — every peer is operator-configured.
		//   2. registerPeerStakeClaim (when a reward address IS available) will
		//      STILL run later and upgrade the stake via SetStakeFromBalance.
		//   3. Phase 2 initialization (initializePhase2Stakes) also re-verifies
		//      actual balances after block 1 and can correct the stake upward.
		if vs := cons.GetValidatorSet(); vs != nil {
			minSPX := vs.GetMinStakeSPX()
			if err := vs.AddValidator(peerNodeID, minSPX); err != nil {
				logger.Warn("[%s] Failed to grant minimum stake to discovered peer %s: %v", currentNodeID, peerNodeID, err)
			} else {
				logger.Info("[%s] Granted minimum stake (%d SPX) to discovered peer %s", currentNodeID, minSPX, peerNodeID)
			}
		}
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

	// ★ FIX: Only pre-register same-box peers if this node has --seeds
	// (i.e. it expects peers to already exist). The bootstrap node
	// (no --seeds) must NOT pre-register peers because they may not be
	// running yet — doing so makes effectivePeerCount() > 0, and the
	// block production loop then jumps straight to PBFT mode without
	// ever entering SOLO_MODE, leaving the bootstrap node stuck at
	// genesis forever.
	//
	// Instead, same-box peers are registered later via key exchange
	// (see "=== EXCHANGING PUBLIC KEYS (SYNC) BEFORE CONSENSUS ==="
	// below) once they actually connect. For the SAME-BOX DEVNET MODE
	// fallback (below, around line 975), we only pre-register when
	// the node has --seeds, so late-joiners can discover the bootstrap
	// node. The bootstrap node itself registers no one in advance.
	if seeds != "" {
		for i, addr := range networkAddresses {
			if i == nodeIndex {
				continue
			}
			peerRegistryMu.Lock()
			peerRegistry[validatorIDs[i]] = addr
			peerRegistryMu.Unlock()
		}
	}

	// SECTION 11 — TCP listener
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	tcpListener, err := net.Listen("tcp", currentAddress)
	if err != nil {
		return fmt.Errorf("failed to bind TCP listener: %w", err)
	}
	logger.Info("TCP listener bound on %s", currentAddress)

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
	logger.Info("TCP inbound listener running")

	// SECTION 11a — dedicated wallet/JSON-RPC listener
	//
	// currentAddress (above) is the P2P gossip port, served by
	// handleIncomingConn, which only understands the plain, unencrypted
	// P2P message types (key_exchange, peer_exchange, checkpoint,
	// get_blocks, consensus messages, legacy "rpc"). It has no "jsonrpc"
	// case, so wallets/CLI tooling built against rpc.CallRPC (which speaks
	// handshake-authenticated, encrypted JSON-RPC 2.0 framing — see that
	// function's doc comment) cannot talk to it.
	//
	// transport.TCPServer (go/src/transport/tcp.go) is the listener that
	// actually implements that protocol: PerformHandshake, then a decode
	// loop that dispatches msg.Type == "jsonrpc" to rpcServer.HandleRequest
	// and writes back an encrypted, framed response. It already exists and
	// is already correct — bind.BindTCPServers wires it up for the
	// same-box devnet harness (legacy.go) — but production StartNode never
	// instantiated one, so it sat unused while wallets dialed the P2P port
	// instead and got silently misrouted or dropped.
	//
	// Rather than teach handleIncomingConn a second, incompatible wire
	// format (the two protocols aren't reliably distinguishable by peeking
	// bytes — this one starts with raw X25519 key material, the P2P one
	// starts with a length-prefixed JSON envelope), we run
	// transport.NewTCPServer as a second, dedicated listener on its own
	// port. nodeConfig.WSPort already reserves a per-node port for exactly
	// this kind of "operator/tooling-facing" traffic (see port.go's
	// baseWSPort) and was otherwise unused in production startup — no
	// separate WebSocket server is started here — so we reuse that slot
	// rather than adding a new flag/config field.
	//
	// ★ FIX: cli.go's --ws-port flag is declared with a fixed literal
	// default ("127.0.0.1:8600"). Go's flag package can't distinguish "the
	// operator explicitly passed --ws-port=127.0.0.1:8600" from "the
	// operator didn't touch the flag at all" — both look identical after
	// parsing — so cli.go's flagOverrides always sets wsPort<N> to that
	// same literal string for every node index, and GetNodePortConfigs
	// dutifully assigns it to every same-box node's WSPort. Multiple
	// same-box nodes therefore all report nodeConfig.WSPort ==
	// "127.0.0.1:8600" and the second one to reach Start() panics with
	// "address already in use" (exactly the failure mode
	// StartTCPListener above works around for --tcp-addr via
	// userProvidedTCP). We apply the same technique here: treat the
	// well-known unmodified default as "not actually set for this node"
	// and derive a per-nodeIndex address instead. An operator who
	// deliberately passes a distinct --ws-port for each node (i.e. any
	// value other than the bare default) is still honoured as-is.
	const unsetWSPortDefault = "127.0.0.1:8600"
	rpcListenAddr := nodeConfig.WSPort
	if rpcListenAddr == "" || rpcListenAddr == unsetWSPortDefault {
		rpcListenAddr = fmt.Sprintf("127.0.0.1:%d", 8700+nodeIndex)
	}
	rpcMsgCh := make(chan *security.Message, 100)
	walletRPCServer := transport.NewTCPServer(rpcListenAddr, rpcMsgCh, rpcServer, nil)
	if err := walletRPCServer.Start(); err != nil {
		return fmt.Errorf("failed to bind wallet RPC listener on %s: %w", rpcListenAddr, err)
	}
	logger.Info("Wallet/JSON-RPC listener bound on %s", rpcListenAddr)

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
			logger.Info("Resolving DNS discovery trees for peer bootstrap...")
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
				logger.Info("DNS discovery returned %d peer(s) — registering them", len(dnsPeers))
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
			logger.Info("Discovering peers via %d plain seed address(es)", len(plainSeeds))
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
				progress, // pass dashboard
			)
		} else if !dnsResolver.HasTrees() {
			logger.Info("No --seeds configured; relying on statically-registered peers only")
		}
	} else {
		logger.Info("No --seeds configured; relying on statically-registered peers only")
	}

	knownPeerCount := func() int {
		peerRegistryMu.Lock()
		defer peerRegistryMu.Unlock()
		return len(peerRegistry)
	}

	// effectivePeerCount is deliberately stricter than knownPeerCount: a
	// configured seed is contactable, but not an active validator until it has
	// completed discovery/key exchange.
	effectivePeerCount := func() int {
		// peerRegistry is an address book and intentionally includes static
		// seed/config entries before their process is reachable. Only peers
		// that completed discovery/key exchange are live participants.
		registeredMu.Lock()
		defer registeredMu.Unlock()
		return len(registeredPeers)
	}

	if knownPeerCount() > 0 {
		logger.Info("Waiting for other nodes to be ready (3 seconds)...")
		time.Sleep(3 * time.Second)
	}

	if knownPeerCount() > 0 {
		logger.Info("=== EXCHANGING PUBLIC KEYS (SYNC) BEFORE CONSENSUS ===")
		for _, addr := range networkAddresses {
			if addr == currentAddress {
				continue
			}
			logger.Info("Exchanging keys with same-box peer: %s", addr)
			if kx, err := exchangeKeyWithPeerSync(addr, currentNodeID, rewardAddress, core.GetGenesisHash(), signingService, sthincsParams); err != nil {
				logger.Warn("Failed to exchange keys with %s: %v", addr, err)
			} else {
				// Register the peer's node ID and address from the key exchange
				registerDiscoveredPeer(kx.NodeID, addr)
				if kx.RewardAddress != "" {
					registerPeerStakeClaim(kx.NodeID, kx.RewardAddress)
				}
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
			if kx, err := exchangeKeyWithPeerSync(addr, currentNodeID, rewardAddress, core.GetGenesisHash(), signingService, sthincsParams); err != nil {
				logger.Warn("Failed to exchange keys with %s: %v", addr, err)
			} else if kx.RewardAddress != "" {
				registerPeerStakeClaim(kx.NodeID, kx.RewardAddress)
			}
		}
		logger.Info("Key exchange completed with all known peers")
	} else if seeds != "" {
		// Same-box devnet mode with --seeds: pre-register peers so the sync
		// loop can find them. The bootstrap node (no --seeds) must NOT
		// pre-register — it needs to enter SOLO_MODE and mine blocks alone
		// until peers actually connect via TCP.
		logger.Info("=== SAME-BOX DEVNET MODE: Registering static peers ===")
		for i, addr := range networkAddresses {
			if i == nodeIndex {
				continue
			}
			// Register in peerRegistry with correct node ID for effectivePeerCount()
			peerRegistry[validatorIDs[i]] = addr
			logger.Info("[%s] Pre-registered same-box peer: %s at %s", currentNodeID, validatorIDs[i], addr)
		}
	} else {
		logger.Info("[%s] No --seeds — bootstrap node, no peers pre-registered (will enter SOLO_MODE)", currentNodeID)
	}

	logger.Info("=== VERIFYING KEY SERIALIZATION ROUND-TRIP ===")
	pkBytes, err = signingService.GetPublicKey()
	if err != nil {
		return fmt.Errorf("cannot get self public key: %w", err)
	}
	if _, err := sthincs.DeserializePK(sthincsParams, pkBytes); err != nil {
		return fmt.Errorf("self public key serialization failed: %v", err)
	}
	logger.Info("Key serialization verified")

	logger.Info("Self-stake and key exchange complete; remaining validator admission happens per-peer as reward addresses are verified")

	if knownPeerCount() > 0 && nodeIndex == 0 {
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
	logger.Info("Consensus engine started AFTER key exchange")

	// Node initialization is complete; mark startup as done
	progress.CompleteNodeStartup()

	phase2State := &phase2InitState{}

	if knownPeerCount() > 0 || !usingRealAddress && synthCount > 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			watchAndUpdateStakes(ctx, bc, cons, currentNodeID, validatorIDs, validatorAddressMap, phase2State)
		}()
	}

	// SECTION 12 — HTTP server
	httpPort := 8545 + nodeIndex
	httpListenAddr := fmt.Sprintf(":%d", httpPort)
	if nodeConfig.HTTPPort != "" {
		// ★ FIX: Parse the full address (could be "127.0.0.1:8546" or just "8546")
		if _, portStr, err := net.SplitHostPort(nodeConfig.HTTPPort); err == nil {
			// Full address provided (host:port)
			httpListenAddr = nodeConfig.HTTPPort
			if port, err := strconv.Atoi(portStr); err == nil {
				httpPort = port
			}
		} else if port, err := strconv.Atoi(nodeConfig.HTTPPort); err == nil {
			// Just a port number provided
			httpPort = port
			httpListenAddr = fmt.Sprintf(":%d", httpPort)
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		msgCh := make(chan *security.Message, 100)
		httpSrv := http.NewServer(httpListenAddr, msgCh, bc, nil)
		logger.Info("JSON-RPC listening on http://%s", httpListenAddr)
		if err := httpSrv.Start(); err != nil {
			logger.Error("HTTP server error: %v", err)
		}
	}()

	// SECTION 14 — block sync loop (catch-up mechanism)
	// The node starts in SYNCING state. It will query peers for missing blocks
	// and apply them before participating in consensus.
	var syncState SyncState = SyncStateSyncing
	var syncStateMu sync.Mutex

	// ★ FIX: Build a live peer-address accessor instead of a one-time
	// snapshot. A static []string captured here reflects peerRegistry only
	// as of THIS instant — for the bootstrap node (no --seeds) that's always
	// empty, since peers connect in and get added to peerRegistry afterward.
	// The old snapshot never grew again for the sync goroutine's lifetime,
	// so the bootstrap node could join PBFT (which does read peerRegistry
	// live via effectivePeerCount) but could never actually sync/catch-up
	// against those same peers. peerAddrsFunc re-reads the mutex-protected
	// registry plus same-box network addresses on every call, so the sync
	// loop always sees currently-known peers.
	peerAddrsFunc := func() []string {
		peerRegistryMu.Lock()
		addrs := make([]string, 0, len(peerRegistry)+len(networkAddresses))
		for _, addr := range peerRegistry {
			addrs = append(addrs, addr)
		}
		peerRegistryMu.Unlock()

		for _, addr := range networkAddresses {
			if addr != currentAddress {
				found := false
				for _, existing := range addrs {
					if existing == addr {
						found = true
						break
					}
				}
				if !found {
					addrs = append(addrs, addr)
				}
			}
		}
		return addrs
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		runBlockSyncLoop(ctx, bc, cons, currentNodeID, peerAddrsFunc, &syncState, &syncStateMu, progress)
	}()

	// SECTION 13 — genesis verification (after sync loop has run)
	// A late-joining node won't have genesis locally. The sync loop above
	// fetches it from peers. We wait for the sync loop to complete before
	// verifying genesis, so a node that needs to sync can do so first.
	//
	// ★ FIX: Wait INDEFINITELY for genesis, not just 60 seconds. A late joiner
	// may need to wait for peers to come online, and a 60-second timeout is
	// arbitrary and harmful — it causes the node to proceed without genesis,
	// which then causes all subsequent operations to fail. The sync loop
	// (runBlockSyncLoop) will eventually fetch genesis from peers; we just
	// need to wait for it.
	//
	// For solo nodes (no peers), genesis is created locally in NewBlockchain
	// and is immediately available, so the wait is instant.
	expectedGenesisHash := core.GetGenesisHash()
	genesisVerified := false
	var genesisBlock core.BlockInterface

	// Check if genesis is already available (solo node or first node)
	genesisBlock = bc.GetLatestBlock()
	if genesisBlock != nil && genesisBlock.GetHeight() == 0 {
		logger.Info("Genesis block already present: %s", expectedGenesisHash)
		genesisVerified = true
	}

	// For nodes with peers (late joiners or multi-node networks), wait for
	// the sync loop to fetch genesis. We wait indefinitely with periodic
	// logging so the operator can see progress.
	if !genesisVerified && knownPeerCount() > 0 {
		logger.Info("Waiting for sync loop to fetch genesis from peers (will wait indefinitely)...")
		checkTicker := time.NewTicker(1 * time.Second)
		defer checkTicker.Stop()
		lastLog := time.Now()
	genesisLoop:
		for {
			genesisBlock = bc.GetLatestBlock()
			if genesisBlock != nil && genesisBlock.GetHeight() == 0 {
				logger.Info("Genesis hash verified: %s", expectedGenesisHash)
				genesisVerified = true
				break genesisLoop
			}
			// Also check if sync completed (network at genesis, no blocks yet)
			syncStateMu.Lock()
			currentSync := syncState
			syncStateMu.Unlock()
			if currentSync == SyncStateCaughtUp {
				logger.Info("Sync completed — network at genesis (no blocks produced yet)")
				genesisVerified = true
				break genesisLoop
			}
			if time.Since(lastLog) > 10*time.Second {
				logger.Info("Still waiting for genesis from peers (syncState=%s)...", currentSync.String())
				lastLog = time.Now()
			}
			select {
			case <-checkTicker.C:
			case <-ctx.Done():
				logger.Warn("Context cancelled while waiting for genesis")
				genesisVerified = false
				break genesisLoop
			}
		}
	}

	if !genesisVerified {
		logger.Warn("Genesis not verified — proceeding anyway (sync loop will handle it)")
	}

	// SECTION 15 — block production loop (now gated by sync state)
	wg.Add(1)
	go func() {
		defer wg.Done()
		runBlockProductionLoop(ctx, bc, cons, currentNodeID, totalNodes, networkType,
			validatorIDs, validatorAddressMap, phase2State, effectivePeerCount,
			&syncState, &syncStateMu, progress)
	}()

	// SECTION 15 — state persistence loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		runStatePersistenceLoop(ctx, bc, currentNodeID, currentAddress)
	}()

	logger.Info("=== NODE RUNNING ===")
	logger.Info("Node ID: %s", currentNodeID)
	logger.Info("TCP (P2P gossip): %s", currentAddress)
	logger.Info("TCP (wallet/JSON-RPC): %s", rpcListenAddr)
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
		logger.Info("PBFT CONSENSUS ACTIVE with %d known validators", knownPeers+1)
	} else if usingRealAddress {
		logger.Info("Real-device mode: consensus activates as peers join via --seeds discovery")
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

	logger.Info("Node %d stopped cleanly", nodeIndex+1)
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

// ============================================================================
// State persistence
// ============================================================================

// flushNodeState persists the current node state.
func flushNodeState(bc *core.Blockchain, nodeID, address string) {
	latest := bc.GetLatestBlock()
	if latest == nil {
		return
	}

	merkleRoot := "unknown"

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

	// Preserve already-known peer entries so each node's chain_state.json
	// reflects the full network view instead of overwriting it with only
	// our local node.
	if err := bc.SaveBasicChainState(); err != nil {
		// SaveBasicChainState already preserves nodes[] if the full file exists,
		// and falls back to an empty nodes array on first run.
		logger.Warn("[%s] SaveBasicChainState (preload/merge): %v", nodeID, err)
	}

	// Load existing chain state and merge our current node info into it.
	if err := func() error {
		cs, err := bc.GetStorage().LoadCompleteChainState()
		if err != nil {
			// If we can't load the complete state, fall back to storing our
			// single node entry so we at least write a valid chain_state.json.
			return bc.StoreChainState([]*state.NodeInfo{nodeInfo})
		}
		if cs == nil {
			return bc.StoreChainState([]*state.NodeInfo{nodeInfo})
		}
		// Merge: update/insert by NodeID.
		merged := make([]*state.NodeInfo, 0, len(cs.Nodes)+1)
		seen := make(map[string]bool)
		for _, n := range cs.Nodes {
			if n == nil {
				continue
			}
			if n.NodeID == nodeInfo.NodeID {
				merged = append(merged, nodeInfo)
				seen[n.NodeID] = true
				continue
			}
			merged = append(merged, n)
			seen[n.NodeID] = true
		}
		if !seen[nodeInfo.NodeID] {
			merged = append(merged, nodeInfo)
		}

		return bc.StoreChainState(merged)
	}(); err != nil {
		logger.Warn("[%s] StoreChainState: %v", nodeID, err)
	} else {
		logger.Info("[%s] Chain state persisted — height=%d", nodeID, latest.GetHeight())
	}

}

// runStatePersistenceLoop periodically persists node state.
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
