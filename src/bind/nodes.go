// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/nodes.go
//
// Production node startup. The legacy same-box devnet harness that used to
// live in this file (StartValidatorNode, StartLocalCluster, LaunchNetwork,
// StartSingleNodeInternal, RunMultipleNodesInternal, SetupNodes) is GONE: it
// predated StartNode, hardcoded a 3-node cluster on fixed 32307+ ports with
// Node-0/1/2 identities that no genesis document could name, and was reachable
// only via cli.go's -legacy-cluster flag. Both legacy.go and that flag were
// removed. This file now contains just StartNode and its directly-used helpers.
package bind

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
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

// DHTUDPPortOffset is the fixed offset added to a node's TCP port to derive the
// UDP port its Kademlia discovery instance binds (TCP 30303 -> UDP 31303).
//
// It is exported because the CLI startup line reports the EFFECTIVE discovery
// port. --udp-port defaults to empty on purpose so bind can apply this
// derivation to the node's real listen address; logging the empty flag printed
// "udp=" with no value and read as "discovery is off" in the one line an
// operator checks when peers fail to connect.
const DHTUDPPortOffset = 1000

// sameBoxDHTUDPPortOffset is the package-local alias kept so the existing
// bind-internal call sites read unchanged.
const sameBoxDHTUDPPortOffset = DHTUDPPortOffset

// sameBoxDHTUDPPort returns the deterministic UDP port used by a same-box
// node's Kademlia instance. The public seed syntax is a TCP address, so using
// its TCP port as a UDP router port cannot work. In localhost test mode, every
// node derives the same mapping without changing TCP key exchange or PEX.
func sameBoxDHTUDPPort(tcpAddr string) (int, error) {
	_, portStr, err := net.SplitHostPort(tcpAddr)
	if err != nil {
		return 0, fmt.Errorf("invalid TCP address %q for DHT port derivation: %w", tcpAddr, err)
	}
	tcpPort, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid TCP port %q for DHT port derivation: %w", portStr, err)
	}
	udpPort := tcpPort + sameBoxDHTUDPPortOffset
	if udpPort < 1 || udpPort > 65535 {
		return 0, fmt.Errorf("derived DHT UDP port %d from TCP port %d is out of range", udpPort, tcpPort)
	}
	return udpPort, nil
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
func ParseRoles(rolesStr string, count int) []network.NodeRole {
	roles := strings.Split(rolesStr, ",")
	result := make([]network.NodeRole, count)
	for i := 0; i < count; i++ {
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
// Validator membership is NEVER taken from the command line or from a peer
// count. The node loads the genesis file from its datadir (via the devnet
// bundle path), syncs from --seeds/PEX, and learns the current validator set
// only from chain state. portOffset is a purely local addressing convenience:
// it shifts default listen ports/datadir and nothing else.
//
// rewardAddress is payout metadata advertised during key exchange. It never
// grants validator membership; membership is established by genesis or a
// committed Stake transaction.
// startNodeFn is the seam StartNode calls. It exists so a test can prove the
// wrapper forwards exactly the zero NodeOptions — the CLI-identical gate —
// without booting a node (see lifecycle_test.go).
var startNodeFn = StartNodeWithOptions

// StartNode runs a full node with the CLI's host integration: no programmatic
// stop channel, the process-wide console renderer, and the live dashboard.
//
// It is precisely StartNodeWithOptions(..., NodeOptions{}). Every host-specific
// branch inside StartNodeWithOptions is false for the zero value, so this path
// is byte-for-byte the behaviour the CLI has always had.
func StartNode(
	dataDir string,
	nodeConfig network.NodePortConfig,
	portOffset int,
	vdfParams *consensus.VDFParams,
	networkType string,
	seeds string,
	rewardAddress string,
) error {
	return startNodeFn(dataDir, nodeConfig, portOffset, vdfParams, networkType, seeds, rewardAddress, NodeOptions{})
}

// StartNodeWithOptions is StartNode plus the two things a host process needs
// that a terminal does not provide: a programmatic stop signal and ownership of
// the log stream (see NodeOptions). With NodeOptions{} it IS StartNode.
//
// A nil return therefore means "ran and shut down cleanly", not "still
// running": the caller decides what happens next (quit, restart, report).
func StartNodeWithOptions(
	dataDir string,
	nodeConfig network.NodePortConfig,
	portOffset int,
	vdfParams *consensus.VDFParams,
	networkType string,
	seeds string,
	rewardAddress string,
	opts NodeOptions,
) error {

	// ════════════════════════════════════════════════════════════════════
	// ★ FIX: Respect --datadir flag. Without this, all path resolution
	// (GetNodeDataDir, GetLevelDBPath, etc.) falls back to the default
	// directory "data" regardless of what the user passed.
	// ════════════════════════════════════════════════════════════════════
	common.SetDataDir(dataDir)

	// ── Create interactive dashboard ──
	//
	// A host (NodeOptions) may take over the log stream and/or ask for no live
	// dashboard at all. Both are process-wide console switches, flipped BEFORE
	// the renderer is first used so no live region can be created behind the
	// host's back. With the zero NodeOptions neither is touched, so this is
	// exactly the CLI's renderer and dashboard.
	if opts.LogWriter != nil {
		logger.SetDefaultWriter(opts.LogWriter)
	}
	if opts.DisableDashboard {
		logger.DisableLiveRegion()
	}

	r := logger.Default()
	log := logger.NewLogger(r)
	progress := logger.NewBlockchainProgress(r, log)
	progress.Status().SetTitle("SPHINX Node")
	if !opts.DisableDashboard {
		progress.StartNodeStartup()
	}
	defer progress.Stop()

	// Let core.CreateBlock report block production / merkle root / state
	// root / nonce mining to this dashboard, regardless of which path
	// invokes it (solo mining, PBFT leader loop, ...). See
	// core.SetUIProgress for why this crosses the bind -> core package
	// boundary as a registration call rather than a constructor argument.
	//
	// With the dashboard disabled we pass nil deliberately: core then falls
	// back to its plain logger.Info lines instead of animating.
	if opts.DisableDashboard {
		core.SetUIProgress(nil)
	} else {
		core.SetUIProgress(progress)
	}
	defer core.SetUIProgress(nil)

	if !opts.isZero() {
		logger.Info("[HOST] Starting node embedded in a host process (stop channel: %t, log writer: %t, dashboard: %t)",
			opts.Stop != nil, opts.LogWriter != nil, !opts.DisableDashboard)
	}

	logger.Info("=== STARTING NODE ===")

	logger.Info("Peer discovery: %s", discoveryModeDesc(seeds))
	logger.Info("Validator membership comes from chain state (genesis file, then Stake/Unstake transactions) — never from a configured node count")

	// ════════════════════════════════════════════════════════════════════
	// ★ DEVNET AUTO-CUSTODY — must run BEFORE SECTION 1 below.
	// ★ DEVNET BUNDLE FETCH — runs BEFORE auto-custody (hence before the
	// first GetGenesisHash() call): a joiner (seeds != "") with an incomplete
	// local bundle fetches the PUBLIC bundle over the network from its seeds,
	// verifying every file before it touches disk, retrying while the
	// bootstrap is still signing. Bootstrap nodes, non-devnet networks, and
	// nodes whose datadir already holds the bundle do nothing. Network
	// transport only — no same-host directory reads; custody/ never served.
	// ════════════════════════════════════════════════════════════════════
	if wait, ferr := ensureDevnetBundleFromSeeds(networkType, seeds, dataDir); ferr != nil {
		return fmt.Errorf("devnet bundle fetch: %w", ferr)
	} else if wait > 0 {
		logger.Info("DEVNET BUNDLE: joiner waited %s for the bootstrap bundle", wait.Round(time.Second))
	}
	//
	// Resolving chain parameters calls core.GetGenesisHash(), which is a
	// process-global sync.Once that BUILDS block 0 on first use. Block 0's
	// distributions are authorized by the genesis vault, so the vault policy,
	// the escrow policy and (for the producing node) the block-0 authorizer
	// all have to exist before that one-time build — otherwise the node caches
	// an unsigned block 0 that the genesis guard then refuses.
	//
	// Devnet-only and fail-closed: on testnet/mainnet this is a no-op, and the
	// first node (no --seeds) is the only one allowed to GENERATE the policies.
	// ════════════════════════════════════════════════════════════════════
	devnetCustody, custodyErr := core.AutoProvisionDevnetCustody(core.DevnetCustodyOptions{
		NetworkType:   networkType,
		BootstrapNode: seeds == "",
		DataDir:       dataDir,
	})
	if custodyErr != nil {
		return fmt.Errorf("devnet auto-custody: %w", custodyErr)
	}
	genesisPolicyFile, err := core.LoadGenesisFile(dataDir)
	if err != nil {
		return fmt.Errorf("load genesis document before block construction: %w", err)
	}
	if genesisPolicyFile != nil && genesisPolicyFile.EscrowMultisig != nil {
		if _, err := core.RegisterEscrowPolicy(genesisPolicyFile.EscrowMultisig); err != nil {
			return fmt.Errorf("register escrow policy from genesis document: %w", err)
		}
	}
	// If something already computed genesis before we got here (a host that
	// called core.GetGenesisHash() first), the block-0 vault address is frozen
	// and provisioning can no longer affect it. Fail loudly here rather than let
	// it surface later as a misleading "insufficient balance" executing block 0.
	if devnetCustody != nil && devnetCustody.Enabled {
		if violErr := core.GenesisCustodyOrderingViolation(); violErr != nil {
			return fmt.Errorf("devnet auto-custody: %w", violErr)
		}
	}

	// ── DEVNET REWARD KEY (auto-generated) ─────────────────────────────────
	// Every devnet node gets its own reward keypair on first start, so the
	// three-command flow never asks anyone to paste an address or supply key
	// material. An explicit --reward-address always wins; this only fills the
	// gap when the operator did not supply one.
	//
	// The key is load-or-create, so a restart yields the SAME address — which
	// matters because that address is what the bootstrap faucet funds and what
	// peers verify a balance for.
	//
	// Devnet only: guarded by DevnetAutoCustodyRequested above (devnetCustody
	// is non-nil exactly on devnet), so this cannot run on a value-bearing
	// chain.
	if devnetCustody != nil && devnetCustody.Enabled && strings.TrimSpace(rewardAddress) == "" {
		devReward, _, _, rkErr := LoadOrCreateDevnetRewardKey(dataDir)
		if rkErr != nil {
			return fmt.Errorf("create devnet reward key: %w", rkErr)
		}
		rewardAddress = devReward
		logger.Info("DEVNET REWARD KEY: auto-generated %s (datadir %s) — no --reward-address needed", devReward, core.DevnetRewardKeyDir(dataDir))
	}

	// SECTION 1 — chain identification
	// Use the correct chain parameters for the running network type.
	// Previously this used commit.SphinxChainParams() which always returns mainnet
	// parameters (ChainID=7331), even when running in devnet mode (ChainID=73310).
	// Now we resolve the correct params based on the networkType parameter.
	var coreChainParams *core.SphinxChainParameters
	switch networkType {
	case "testnet":
		coreChainParams = core.GetTestnetChainParams()
	case "devnet":
		coreChainParams = core.GetDevnetChainParams()
	default:
		coreChainParams = core.GetSphinxChainParams()
	}
	logger.Info("Chain: %s  ChainID=%d  Symbol=%s", coreChainParams.ChainName, coreChainParams.ChainID, coreChainParams.Symbol)

	// Belt-and-braces phase gate: if auto-custody engaged, the chain the node
	// actually resolved must be devnet. This is the check that makes it
	// impossible for devnet-only auto-provisioned keys to arm on a chain that
	// carries value, even if the --network selector and the parameter table
	// ever drift apart.
	if devnetCustody != nil && devnetCustody.Enabled && !coreChainParams.IsDevnet() {
		return fmt.Errorf("devnet auto-custody engaged for --network=%q but resolved %s (ChainID=%d), which is not devnet — refusing to start with devnet-only auto-provisioned custody material",
			networkType, coreChainParams.ChainName, coreChainParams.ChainID)
	}
	if devnetCustody != nil && devnetCustody.Enabled {
		logger.Warn("DEVNET AUTO-CUSTODY ACTIVE: vault=%s escrow=%s signer=%v replay=%v — this custody set is devnet convenience, NOT real M-of-N security.",
			devnetCustody.VaultAddress, devnetCustody.EscrowAddress, devnetCustody.SigningNode, devnetCustody.ReplayNode)
	}

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
	//
	// A node has exactly ONE identity: Node-<its own --tcp-addr>. There is no
	// synthesized roster of "node 0..N-1": --port-offset is a purely local
	// addressing convenience and never an identity. The validator set is read
	// from chain state (the genesis file, then Stake/Unstake transactions);
	// the peer set is learned from --seeds + PEX. Neither is derived from, or
	// bounded by, a configured node count.
	host, _, splitErr := net.SplitHostPort(nodeConfig.TCPAddr)
	if splitErr != nil {
		host = nodeConfig.TCPAddr
	}
	if strings.TrimSpace(host) == "" || strings.TrimSpace(nodeConfig.TCPAddr) == "" {
		return fmt.Errorf("a listen address is required: pass --tcp-addr (e.g. 127.0.0.1:30303)")
	}
	usingRealAddress := !isLoopbackHost(host)

	currentAddress := nodeConfig.TCPAddr
	currentNodeID := fmt.Sprintf("Node-%s", currentAddress)

	// validatorIDs carries ONLY this node's own identity as an initialisation
	// hint. It is deliberately NOT a validator set: consensus membership is
	// filled from chain state. No peer list is synthesized — peers are learned
	// through --seeds + PEX, never from a configured node count.
	validatorIDs := []string{currentNodeID}

	logger.Info("Node identity: %s at %s (public-ip=%v, datadir=%s)", currentNodeID, currentAddress, usingRealAddress, dataDir)

	// ── GENESIS DOCUMENT ───────────────────────────────────────────────────
	// <datadir>/config/genesis_state.json is the ONLY source of the initial
	// validator set. Nothing below derives membership from a flag, a peer count,
	// or a synthesized roster.
	//
	// ★ NO PRIVILEGED NODE. There is no "bootstrap terminal", no node count, and
	// no designated first node: every node runs this same code and the
	// FIRST ONE TO START authors the network's genesis, naming only itself. A
	// node that finds a document already there (its own from a previous run, or
	// one fetched over the devnet bundle from --seeds) reads it instead.
	//
	// The set then GROWS only through chain-state stake admission — not by
	// re-authoring genesis or predeclaring a node count.
	//
	// It must be settled BEFORE core.NewBlockchain, because the document's chain
	// parameters (EpochBlocks) are resolved into the chain params there.
	authorGenesis, genesisFileErr := core.GenesisNeedsAuthoring(dataDir)
	if genesisFileErr != nil {
		return fmt.Errorf("genesis file: %w", genesisFileErr)
	}
	var genesisFile *core.GenesisStateFile
	if !authorGenesis {
		genesisFile, genesisFileErr = core.LoadGenesisFile(dataDir)
		if genesisFileErr != nil {
			return fmt.Errorf("genesis file: %w", genesisFileErr)
		}
		core.SetGenesisEpochBlocks(genesisFile.Chain.EpochBlocks)
		if networkType == "mainnet" || networkType == "testnet" {
			envName := "SPHINX_MAINNET_GENESIS_DIGEST"
			if networkType == "testnet" {
				envName = "SPHINX_TESTNET_GENESIS_DIGEST"
			}
			pinnedDigest := strings.TrimSpace(os.Getenv(envName))
			if err := core.ValidatePinnedGenesisDocument(genesisFile, networkType, pinnedDigest); err != nil {
				return fmt.Errorf("pinned %s genesis validation failed (%s): %w", networkType, envName, err)
			}
		}
		logger.Info("GENESIS FILE: %d initial validator(s), epoch_blocks=%d, network=%s",
			len(genesisFile.Validators), genesisFile.Chain.EpochBlocks, genesisFile.Chain.Network)
	} else if networkType != "devnet" {
		envName := "SPHINX_MAINNET_GENESIS_DIGEST"
		if networkType == "testnet" {
			envName = "SPHINX_TESTNET_GENESIS_DIGEST"
		}
		return fmt.Errorf("--network=%s requires a pre-agreed genesis document and out-of-band pinned digest (%s); self-authoring is devnet-only",
			networkType, envName)
	}

	// SECTION 4 — database initialization
	if err := common.EnsureNodeDirs(currentAddress); err != nil {
		return fmt.Errorf("failed to create node directories: %w", err)
	}

	// ★ ONE HANDLE PER PATH. goleveldb holds an exclusive OS lock (flock) on a
	// database directory, and that lock is NOT re-entrant across separate
	// os.Open calls — not even inside a single process. Opening the same path
	// twice therefore fails with EAGAIN ("resource temporarily unavailable"),
	// and database.NewLevelDB now refuses to paper over that by deleting the
	// LOCK file (see its comment: unlinking LOCK while another handle has the
	// database open is how two writers end up on one set of files).
	//
	// This node needs the raw *leveldb.DB for the main database (the STHINCS
	// manager persists SPHINCS+ keys through it, below) AND the database.DB
	// wrapper for the same directory, so it opens it once and wraps that
	// handle. The state database is only ever used through the wrapper — the
	// second, unused raw handle that used to be opened here was dead code that
	// existed solely to be closed again.
	mainDBPath := common.GetLevelDBPath(currentAddress)
	db, err := leveldb.OpenFile(mainDBPath, nil)
	if err != nil {
		return fmt.Errorf("failed to open main LevelDB: %w", err)
	}
	defer db.Close()

	stateDBPath := common.GetStateDBPath(currentAddress)

	mainDatabase, err := database.NewLevelDBWithHandle(mainDBPath, db)
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
	//
	// ★ ONE PERSISTENT IDENTITY. The consensus keypair is loaded from the
	// node's own persisted keys (Node-<address>/keys — the same files
	// network.NewNode uses) via NodeIdentityKeys, NOT generated per start:
	//   - first start (no key files at all) → created once and persisted
	//   - every later start → strict fail-closed load; a damaged pair aborts
	//     startup instead of silently minting a new identity (which would
	//     break peers' node_id<->key pinning and re-sign historical blocks
	//     under an unknown key)
	// This key is what key exchange, PBFT signature verification and the
	// genesis header signature all use — one keypair, loaded, never regenerated.
	identitySK, identityPK, identityCreated, identityErr := network.NodeIdentityKeys(mainDatabase, currentAddress)
	if identityErr != nil {
		return fmt.Errorf("failed to load node identity keys for %s: %w", currentAddress, identityErr)
	}
	if identityCreated {
		logger.Info("Created new node identity keypair for %s (persisted at %s)", currentNodeID, common.GetKeysDataDir(currentAddress))
	}
	sphincsMgr := sign.NewSTHINCSManager(db, sharedKeyManager, sharedSphincsParams)
	signingService, err := consensus.NewSigningService(sphincsMgr, sharedKeyManager, currentNodeID, identitySK, identityPK)
	if err != nil {
		return fmt.Errorf("failed to create signing service: %w", err)
	}

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
	// ── AUTHOR GENESIS IF NOBODY HAS ───────────────────────────────────────
	// Whoever starts first creates the network's genesis. Done here (not at the
	// LoadGenesisFile above) because the document must record this node's
	// PUBLIC KEY, and the signing service — which owns it — is built in
	// SECTION 4. It must still happen BEFORE NewBlockchain, because the
	// document's chain parameters are resolved into the chain params there.
	if authorGenesis {
		// ★ WHO MAY AUTHOR GENESIS is decided by one pure function, tested in
		// helpers.go. It is asked ONLY when this datadir holds no validator set,
		// so a node that already has a document never reaches it.
		decision := genesisAuthoringDecision(seeds, networkType, dataDir)
		if decision != GenesisMayAuthor {
			return genesisAuthoringError(decision, seeds, networkType, dataDir, genesisFileErr)
		}

		selfPubKey := ""
		if pk, pkErr := signingService.GetPublicKey(); pkErr == nil {
			selfPubKey = hex.EncodeToString(pk)
		}
		selfReward := ""
		if rewardAddress != "" {
			if norm, nErr := common.NormalizeSPIFAddress(rewardAddress); nErr == nil {
				selfReward = norm
			} else {
				selfReward = rewardAddress
			}
		}

		// The bootstrap node also owns the devnet faucet. Its address is
		// recorded in the document as a funded account (see correction #4: this
		// is a `funded_accounts` row, applied at block-0 execution, so it does
		// NOT enter block 0's TxsRoot and does NOT change the genesis hash).
		// The key is generated only here, only on the authoring node.
		faucetAddr := ""
		if faucetAddr, _, _, err = LoadOrCreateDevnetFaucetKey(dataDir); err != nil {
			return fmt.Errorf("create devnet faucet key: %w", err)
		}

		genesisFileErr = core.CreateGenesisForSelf(dataDir, networkType, currentNodeID, selfPubKey, selfReward, faucetAddr)
		if genesisFileErr != nil {
			return fmt.Errorf("author genesis for this network: %w", genesisFileErr)
		}
		genesisFile, genesisFileErr = core.LoadGenesisFile(dataDir)
		if genesisFileErr != nil {
			return fmt.Errorf("re-read genesis after authoring: %w", genesisFileErr)
		}
		core.SetGenesisEpochBlocks(genesisFile.Chain.EpochBlocks)
		logger.Info("GENESIS AUTHORED: no document existed, so this node created it naming only itself (%s)", currentNodeID)
		logger.Info("GENESIS: further validators join by staking from a funded reward address; the set grows as they do")
		logger.Info("DEVNET FAUCET ALLOCATION: %s holds %s nSPX; operators can manually fund joiners with up to %s nSPX (min stake + fee reserve); no node list",
			faucetAddr, core.FaucetPoolNSPX().String(), core.FaucetPayoutNSPX().String())
		logger.Info("GENESIS FILE: %d initial validator(s), epoch_blocks=%d, network=%s",
			len(genesisFile.Validators), genesisFile.Chain.EpochBlocks, genesisFile.Chain.Network)
	}

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

	// ★ ATTACH THE GENESIS DOCUMENT BEFORE ANYTHING CAN EXECUTE GENESIS.
	//
	// The document is loaded above (and authored first on a fresh devnet), but
	// it used to live only in this local variable. ExecuteGenesisBlock runs
	// from FinishInit further down, and it needs the document to build the
	// epoch-0 validator snapshot — the set that governs heights 1..EpochBlocks-1,
	// without which no block can be produced at all.
	//
	// Retaining it here is what makes the snapshot builder order-independent: it
	// reads the same validated bytes the loader checked, rather than depending
	// on a live validator set that is not attached until much later.
	if genesisFile != nil {
		bc.SetGenesisDocument(genesisFile)
	}
	// ★ FIX: wire the STHINCS manager built in SECTION 4 onto the blockchain.
	// Without this, bc.sphincsManager stays nil for the life of the process:
	// rpc.NewServer (below) receives sphincsMgr directly and works fine, but
	// nothing was ever propagating it onto bc itself. That silent gap meant
	// the mempool's admission-time check (which tolerates a nil manager by
	// falling back to SVM-only verification) accepted transactions that
	// commit-time auth (core/tx_auth.go's validateTransactionAuth, which
	// treats a nil manager as fatal: "STHINCS manager is not configured")
	// could never actually commit — a transaction gets validated into the
	// pending pool, a leader builds and gets full PBFT quorum on a block
	// containing it, and CommitBlock rejects it every single time. PBFT
	// then treats that as a lost race, resets to PhaseIdle, and retries the
	// identical block forever: height stops advancing and the mempool shows
	// the same transaction "pending" indefinitely.
	//
	// Set it before FinishInit (which builds/attaches the mempool
	// internally) so that path's own SetMempool call already sees a
	// non-nil manager. SyncSTHINCSManager afterward is a belt-and-suspenders
	// re-propagation in case FinishInit or something later replaces the
	// mempool instance.
	bc.SetSTHINCSManager(sphincsMgr)
	bc.SetStorageDB(mainDatabase)
	bc.SetStateDB(stateDatabase)

	// ★ Attach the durable validator-snapshot store and replay any snapshots
	// already on disk. This MUST happen before the node verifies or accepts any
	// block: VerifyBlockAttestations is height-keyed and fails CLOSED, so a node
	// that restarted mid-epoch and did not replay has no record of the set
	// governing the epoch it is serving and would reject every block until it
	// re-crossed a boundary.
	if err := bc.AttachSnapshotStore(); err != nil {
		return fmt.Errorf("failed to attach validator snapshot store: %w", err)
	}

	if err := bc.FinishInit(currentNodeID); err != nil {
		return fmt.Errorf("failed to create blockchain: %w", err)
	}
	bc.SyncSTHINCSManager()

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

	artifactPath := filepath.Join(common.GetBlockchainDataDir(currentAddress), "artifact-db")
	rpcServer := rpc.NewServerWithArtifactPath(nil, bc, sphincsMgr, artifactPath)
	logger.Info("RPC server created (synchronous mode); artifact DB path: %s", artifactPath)

	// getsyncstatus provider: runBlockSyncLoop publishes observational
	// snapshots into this tracker (see rpc.SetSyncStatusProvider and the
	// observeSync call sites in helpers.go). Registered here — before any
	// listener serves — under the same set-once-before-serving contract as
	// SetTxRelay below.
	syncStatusTracker := rpc.NewSyncStatusTracker()
	rpcServer.SetSyncStatusProvider(syncStatusTracker.Get)

	// SECTION 7 — network node manager
	// ── Parse TCP/UDP addresses first (needed for local node + DHT) ──
	tcpPort := nodeConfig.TCPAddr
	if _, portStr, err := net.SplitHostPort(nodeConfig.TCPAddr); err == nil && portStr != "" {
		tcpPort = portStr
	}

	// DHT UDP ports are derived from the node's TCP port as TCP+1000 so a
	// plain TCP seed can be translated to the actual UDP router without
	// carrying a second address in the key-exchange message. An explicit
	// --udp-port wins.
	udpPort := ""
	derivedUDP, err := sameBoxDHTUDPPort(currentAddress)
	if err != nil {
		return fmt.Errorf("derive DHT UDP port: %w", err)
	}
	udpPortNum := derivedUDP
	if usingRealAddress && nodeConfig.UDPPort != "" {
		if p, perr := strconv.Atoi(nodeConfig.UDPPort); perr == nil {
			udpPortNum = p
		}
	}
	udpPort = strconv.Itoa(udpPortNum)

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
				tcpPort, convErr := strconv.Atoi(p)
				if convErr != nil {
					logger.Warn("Ignoring DHT seed %q with invalid TCP port: %v", seed, convErr)
					continue
				}
				routerPort := tcpPort
				if !usingRealAddress {
					derived, deriveErr := sameBoxDHTUDPPort(net.JoinHostPort(h, p))
					if deriveErr != nil {
						logger.Warn("Ignoring DHT seed %q: %v", seed, deriveErr)
						continue
					}
					routerPort = derived
				}
				router := net.UDPAddr{IP: net.ParseIP(h), Port: routerPort}
				dhtRouters = append(dhtRouters, router)
				logger.Info("DHT seed %s translated to router %s", seed, router.String())
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

	// Peers are NOT synthesized here. There is no "same-box" roster derived
	// from a node count: peers enter nodeMgr/p2pMgr only through discovery
	// (--seeds, DNS trees, PEX) and a completed key exchange below. A node
	// with no peers yet simply waits — that is a liveness condition, never a
	// configuration error.
	logger.Info("Static peer roster: none — peers are discovered via --seeds/PEX and admitted after key exchange")

	// SECTION 8 — consensus node manager
	//
	// ★ FIX: ALWAYS build a real, network-capable P2PConsensusNodeManager —
	// never a local-only CallNodeManager.
	//
	// A real blockchain cannot force every node to start at the same time,
	// and the genesis/bootstrap node in particular must be able to produce
	// its own genesis then have late joiners fold in live whenever they
	// happen to connect, with no restart and no rewiring.
	//
	// registerDiscoveredPeer (below) already implements exactly that: on
	// every newly-discovered peer it calls p2pMgr.AddPeer(...) so the
	// transport layer picks up new peers dynamically at runtime.
	//
	// Solo-vs-PBFT behavior itself is decided by effectiveValidatorCount()
	// in helpers.go from the STAKED validator set (never from raw peer count).
	var consensusNodeMgr consensus.NodeManager
	p2pMgr := network.NewP2PConsensusNodeManager(nodeMgr, currentNodeID)

	// No peers are pre-added: the p2pMgr roster is populated only by
	// registerDiscoveredPeer/ensureDialbackAdmitted after a verified key
	// exchange. Pre-seeding it from a synthetic node count would put
	// unverified members on the consensus broadcast list.

	// Wire the RPC server's outbound transaction relay to the P2P manager so
	// wallet-submitted transactions (sendrawtransaction — e.g. USI mint
	// anchors) are gossiped to every peer. Without this the tx exists ONLY
	// in this node's mempool: whichever PBFT leader doesn't hold it builds
	// blocks without it, and since leadership rotates the anchor can sit
	// uncommitted forever (the USI "Confirmed: pending" bug).
	rpcServer.SetTxRelay(func(tx *types.Transaction) {
		if err := p2pMgr.BroadcastMessage("transaction", tx); err != nil {
			logger.Warn("RPC tx relay: broadcast of tx %s failed: %v", tx.ID, err)
		}
	})

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
	logger.Info("P2P consensus manager ready (peers are added only after a verified key exchange)")

	// SECTION 9 — consensus engine
	coreChainParams = core.GetSphinxChainParams()
	minStakeAmount := coreChainParams.ConsensusConfig.MinStakeAmount

	cons := consensus.NewConsensus(
		currentNodeID,
		consensusNodeMgr,
		bc,
		signingService,
		nil,
		minStakeAmount,
		// REQUIRED FastForward attestation verifier. It resolves operator keys
		// from the replayed chain's StateDB and verifies each signature with the
		// single shared consensus primitive, so catch-up blocks are verified
		// cryptographically even though this node has never handshook with the
		// peers it is replaying from. There is no nil-accept path: FastForward
		// rejects when this is nil.
		func(blk consensus.Block) error {
			tb, ok := blk.(*types.Block)
			if !ok {
				return fmt.Errorf("FastForward verifier received a %T, not a *types.Block", blk)
			}
			return core.VerifyBlockAttestations(tb,
				core.NewChainStateKeyResolver(bc),
				core.NewConsensusAttestationVerifier())
		},
	)
	if cons == nil {
		return fmt.Errorf("failed to create consensus engine (VDF initialization likely failed)")
	}
	cons.SetParticipationGate(bc.IsValidatorPausedForHeight)

	if p2pMgr != nil {
		p2pMgr.SetConsensusEngine(cons)
	}

	// ★ REMOVED (Phase 1, step 2 — self-grant): this block used to run
	//   `vs.AddValidator(currentNodeID, minSPX)` UNCONDITIONALLY, ~65 lines
	//   BEFORE the self-stake switch below. It handed every starting node a
	//   minimum-stake seat no matter what the genesis document said, so a node
	//   NOT listed in genesis_state.json still put itself into the live
	//   validator set — and therefore into quorum denominators and leader
	//   rotation — purely because it booted. seedGenesisValidators (below) only
	//   ADDS the genesis validators, so it never removed that seat.
	//
	// The switch below is the single decision point and is exhaustive:
	//   genesisSeededSelf        → seat and stake come from genesis_state.json
	//   genesisFile != nil       → peer only until a Stake tx admits this node
	//   no genesis file + address → verified on-chain balance, else min stake
	//   no genesis file, no addr  → min stake
	// and GetMinStakeSPX() returns exactly the value the deleted block computed
	// inline (minStakeAmount / 1e18, with vs.minStakeAmount being the same
	// minStakeAmount handed to NewConsensus above), so no behaviour is lost.
	if vs := cons.GetValidatorSet(); vs == nil {
		return fmt.Errorf("consensus validator set is unavailable")
	}

	// A reward address is payout metadata only. It never grants validator
	// membership; only the genesis set or committed Stake transactions do.

	// ── GENESIS FILE → consensus validator set ───────────────────────────
	// Load the initial validator set from chain data. This is the ONLY place
	// initial membership is established; every node that reads the same file
	// computes the same set, hence the same leaders and the same quorum.
	// Public keys are registered up front so attestation signatures from
	// genesis validators verify without waiting for a handshake.
	// ★ MEMBERSHIP BOOTSTRAP — ONE OWNER, deferred to just after the engine is
	// attached (see below).
	//
	// The genesis document is attached to the node, the consensus validator set
	// is seeded from it, and the epoch-0 snapshot is built and cross-checked — in
	// that order, in one call, so the sequence cannot drift.
	//
	// This previously happened in two places far apart: seeding ran here, while
	// the epoch-0 snapshot was taken from inside ExecuteGenesisBlock, which runs
	// ~300 lines EARLIER. A fresh devnet node therefore reached block production
	// with no epoch-0 snapshot and logged "validator snapshot for height 1 is
	// unavailable" forever.
	genesisSeededSelf := false

	logger.Info("=== REWARD ADDRESS CONFIGURATION ===")
	// The local reward address is payout metadata only.
	if rewardAddress != "" {
		selfRewardAddr := rewardAddress
		if normalized, err := common.NormalizeSPIFAddress(rewardAddress); err == nil {
			selfRewardAddr = normalized
		}
		bc.SetValidatorRewardAddress(currentNodeID, selfRewardAddr)
		logger.Info("[%s] Block rewards / gas fees will route to %s", currentNodeID, selfRewardAddr)
	}

	switch {
	case genesisSeededSelf:
		// This node's seat and stake came from the genesis file. Never
		// overwrite them with a minimum-stake bootstrap: doing so would let
		// two nodes disagree about this validator's weight (and hence about
		// leaders and quorum) depending on local timing.
		logger.Info("[%s] Self stake comes from the genesis file — no self-bootstrap needed", currentNodeID)

	case genesisFile != nil:
		// A genesis file defines this network's validator set and this node is
		// not in it. It therefore participates as a PEER only: a Stake
		// transaction applied by consensus is the only way to join.
		// Self-granting a seat here would put an unstaked node into quorum
		// math and leader rotation purely because it happened to start.
		logger.Info("[%s] Not listed in the genesis file — participating as a peer only until a Stake transaction admits this node", currentNodeID)

	case rewardAddress != "":
		logger.Info("[%s] Reward address %s does not grant validator membership; a committed Stake transaction is required", currentNodeID, rewardAddress)

	default:
		// No reward address at all: nothing to verify, so no seat. Same rule as
		// above — membership comes from the genesis document or from a Stake
		// transaction, never from the mere fact that a process started.
		logger.Info("[%s] No reward address and no genesis entry — participating as a peer only (validator membership comes from the genesis document or a Stake transaction)", currentNodeID)
	}

	bc.SetConsensusEngine(cons)
	bc.SetConsensus(cons)

	// ★ MEMBERSHIP BOOTSTRAP — ONE OWNER, AND IT RUNS HERE.
	//
	// The genesis document is attached, the consensus validator set is seeded
	// from it, and the epoch-0 snapshot is built and cross-checked — in that
	// order, in one call, so the sequence cannot drift.
	//
	// It must run AFTER SetConsensus above, because the cross-check reads the
	// validator set through the blockchain's live view of the engine. Seeding
	// alone is not enough: a set that is populated but not attached is
	// indistinguishable from an unseeded one, which is precisely the state that
	// made the original failure invisible.
	//
	// It previously happened in two places far apart: seeding ran here, while
	// the epoch-0 snapshot was taken from inside ExecuteGenesisBlock, ~300 lines
	// EARLIER. A fresh devnet node therefore reached block production with no
	// epoch-0 snapshot and logged "validator snapshot for height 1 is
	// unavailable" every ten seconds forever.
	if genesisFile != nil {
		if err := bc.BootstrapGenesisValidatorSet(genesisFile, func(gf *core.GenesisStateFile) error {
			seeded, seedErr := seedGenesisValidators(cons, signingService, sthincsParams, gf, currentNodeID, bc)
			if seedErr != nil {
				return seedErr
			}
			genesisSeededSelf = seeded
			logger.Info("GENESIS FILE: seeded %d validators into the consensus set (%s nSPX total)",
				len(gf.Validators), cons.GetValidatorSet().GetTotalStake().String())
			return nil
		}); err != nil {
			return fmt.Errorf("bootstrap genesis validator set: %w", err)
		}
		// ★ Seal the set to genesis seeding. From here the ONLY ways membership
		// can change are QueueValidator (deferred to a boundary) and
		// ProcessEpochTransition. Without this, any later caller of
		// AddGenesisValidator — including a retry path — could add a live member
		// with vote weight and no boundary, outside chain state.
		cons.GetValidatorSet().SealGenesis()
	}
	if err := bc.ReplayStakeTransactions(); err != nil {
		return fmt.Errorf("replay committed stake transactions: %w", err)
	}
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
	// registered-peer bookkeeping and gossip. It may
	// be pre-populated (see the static same-box registration below) before
	// a peer's real key exchange completes, so it must NOT be used as the
	// dedup guard for one-time side effects (AddNode/AddPeer/stake grant)
	// — otherwise a pre-registered peer's real registration silently
	// no-ops the very first (and only) time it would actually run.
	var peerRegistryMu sync.Mutex
	peerRegistry := make(map[string]string)

	// registeredPeers tracks which peer IDs have already had their
	// one-time address-book side effects applied.
	// This is intentionally a separate set from peerRegistry — see above.
	var registeredMu sync.Mutex
	registeredPeers := make(map[string]bool)

	// dialbackMu guards the dial-back admission state below.
	var dialbackMu sync.Mutex
	dialbackPending := make(map[string]bool)
	dialbackVerified := make(map[string]bool)

	// admitVerifiedPeer records a completed handshake to peerAddr and admits
	// the peer to the p2pMgr transport. It must ONLY be called after a full
	// key exchange with that exact address succeeded and the peer's identity
	// matched the claim (ensureDialbackAdmitted enforces both; the startup
	// key-exchange loops satisfy them by construction).
	admitVerifiedPeer := func(peerNodeID, peerAddr string) {
		if peerNodeID == "" || peerAddr == "" || peerAddr == currentAddress {
			return
		}
		dialbackMu.Lock()
		already := dialbackVerified[peerNodeID]
		dialbackVerified[peerNodeID] = true
		dialbackMu.Unlock()
		if already {
			return
		}
		if p2pMgr != nil {
			p2pMgr.AddPeer(peerNodeID, peerAddr)
		}
		logger.Info("[%s] Peer %s admitted to the P2P transport after successful handshake to %s",
			currentNodeID, peerNodeID, peerAddr)
	}

	// A reward-address claim is metadata only. Consensus membership can only
	// change when a committed Stake transaction is replayed from chain state.
	registerPeerStakeClaim := func(peerNodeID, rewardAddress string) {
		if peerNodeID != "" && rewardAddress != "" {
			logger.Debug("[%s] Ignoring peer reward-address claim from %s for validator admission",
				currentNodeID, peerNodeID)
		}
	}

	// ensureDialbackAdmitted is the ONLY path that adds peers to p2pMgr,
	// and only after a full key-exchange handshake (challenge-response
	// included) to the DERIVED address has succeeded and the identity that
	// answers that address matches the claim:
	//
	//   - Address book (peerRegistry) may be fed by remote claims — it is
	//     discovery data only.
	//   - p2pMgr is a transport broadcast list only. Its membership does not
	//     affect validator snapshots, proposer selection, or quorum weight.
	//   - The dial-back also proves address ↔ node_id binding: an attacker
	//     who claims a victim's identity gets an address on the attacker's
	//     own IP (only the port is claimed), and the victim's real node
	//     answering that address with a different ID is rejected.
	ensureDialbackAdmitted := func(peerNodeID, peerAddr string) {
		if peerNodeID == "" || peerAddr == "" || peerAddr == currentAddress {
			return
		}
		dialbackMu.Lock()
		if dialbackVerified[peerNodeID] || dialbackPending[peerNodeID] {
			dialbackMu.Unlock()
			return
		}
		dialbackPending[peerNodeID] = true
		dialbackMu.Unlock()

		go func() {
			kx, err := exchangeKeyWithPeerSync(peerAddr, currentAddress, currentNodeID, rewardAddress, core.GetGenesisHash(), signingService, sthincsParams)
			dialbackMu.Lock()
			delete(dialbackPending, peerNodeID)
			dialbackMu.Unlock()
			if err != nil {
				logger.Warn("[%s] Dial-back handshake to %s failed — %s stays in the address book only (a later discovery event may retry): %v",
					currentNodeID, peerAddr, peerNodeID, err)
				return
			}
			if kx.NodeID != peerNodeID {
				logger.Warn("[%s] Address %s answered as %s, not the claimed %s — rejecting address binding",
					currentNodeID, peerAddr, kx.NodeID, peerNodeID)
				// Drop the bogus address-book binding created from the claim.
				peerRegistryMu.Lock()
				if peerRegistry[peerNodeID] == peerAddr {
					delete(peerRegistry, peerNodeID)
				}
				peerRegistryMu.Unlock()
				return
			}
			admitVerifiedPeer(peerNodeID, peerAddr)
			if kx.RewardAddress != "" {
				registerPeerStakeClaim(kx.NodeID, kx.RewardAddress)
			}
		}()
	}

	registerDiscoveredPeer := func(peerNodeID, peerAddr string) {
		if peerNodeID == "" || peerAddr == "" || peerAddr == currentAddress {
			return
		}
		peerRegistryMu.Lock()
		peerRegistry[peerNodeID] = peerAddr
		peerCount := len(peerRegistry)
		peerRegistryMu.Unlock()

		// Kick (or retry) dial-back verification BEFORE the one-time dedup
		// below: address book first, p2p transport only after the handshake
		// to this address succeeds. Repeated discovery events for the same
		// peer act as retries when a previous attempt failed.
		ensureDialbackAdmitted(peerNodeID, peerAddr)

		registeredMu.Lock()
		already := registeredPeers[peerNodeID]
		registeredPeers[peerNodeID] = true
		registeredMu.Unlock()
		if already {
			return
		}

		logger.Info("Discovered new peer %s at %s — address book only until dial-back succeeds", peerNodeID, peerAddr)

		host, port, err := net.SplitHostPort(peerAddr)
		if err != nil {
			logger.Warn("Discovered peer %s has unparseable address %s: %v", peerNodeID, peerAddr, err)
			host, port = peerAddr, ""
		}
		// RoleNone: discovered peers are discovery/address-book entries, not
		// validators. consensus never sees nodeMgr nodes (it reads p2pMgr),
		// and NodeManager.SelectValidator requires RoleValidator — either
		// way a RoleNone entry is excluded from quorum/rotation math.
		if peerNode := network.NewNode(peerAddr, host, port, "", false, network.RoleNone, mainDatabase); peerNode != nil {
			nodeMgr.AddNode(peerNode)
		}

		// Update dashboard with peer count
		progress.CheckNetworkHealth(true, peerCount)

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

	// plainSeedAddrs are the operator's configured plain gossip seeds — the
	// addresses the sync loops are allowed to DIAL. This is NOT a peer list and
	// NOT a roster: peerRegistry below stays populated only by real discovery
	// and verified key exchanges, so nothing here can be mistaken for a
	// pre-agreed node set or for validator membership. A node that starts alone
	// still has an empty peerRegistry and still holds no stake; these addresses
	// are transport input only, and every response is still verified (genesis
	// hash, attestations, chain continuity).
	plainSeedAddrs := make([]string, 0, 2)
	if seeds != "" {
		for _, seed := range strings.Split(seeds, ",") {
			seed = strings.TrimSpace(seed)
			// enrtree:// is a DNS tree, not a dialable gossip address.
			if seed == "" || strings.HasPrefix(seed, "enrtree://") {
				continue
			}
			plainSeedAddrs = append(plainSeedAddrs, seed)
		}
		if len(plainSeedAddrs) > 0 {
			logger.Info("Block sync will retry these configured seed address(es) while the address book is still empty: %s",
				strings.Join(plainSeedAddrs, ", "))
		}
	}

	// peerAddrsFunc is the live peer address book (discovery only, never a
	// synthesized roster), UNION the operator's configured plain --seeds.
	//
	// The union matters for diagnosability and for making progress. The
	// address book is only populated by a peer that has already completed a
	// verified key exchange, so a joiner whose seed rejects it (wrong genesis,
	// seed still booting, seed down) had an EMPTY list and could only log
	// "No peers reachable — tried addresses ()" — naming nothing, in the very
	// line the troubleshooting table tells operators to read. Worse, the block
	// sync loop then had no address to retry, so it could not recover even
	// once the seed came up.
	//
	// Self is excluded so a node never tries to dial itself.
	peerAddrsFunc := func() []string {
		peerRegistryMu.Lock()
		defer peerRegistryMu.Unlock()
		addrs := make([]string, 0, len(peerRegistry)+len(plainSeedAddrs))
		seen := make(map[string]bool, len(peerRegistry)+len(plainSeedAddrs))
		for _, addr := range peerRegistry {
			if addr == "" || seen[addr] {
				continue
			}
			seen[addr] = true
			addrs = append(addrs, addr)
		}
		for _, addr := range plainSeedAddrs {
			if addr == "" || addr == currentAddress || seen[addr] {
				continue
			}
			seen[addr] = true
			addrs = append(addrs, addr)
		}
		return addrs
	}

	// SECTION 11 — TCP listener
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	tcpListener, err := net.Listen("tcp", currentAddress)
	if err != nil {
		return fmt.Errorf("failed to bind TCP listener: %w", err)
	}
	// Ask the kernel what we actually got: identical to currentAddress for an
	// explicit host:port, and the only correct answer for port 0 or a wildcard
	// host. It is a runtime fact, so it never touches the persisted chain params.
	boundAddress := tcpListener.Addr().String()
	bc.SetListenAddr(boundAddress)
	logger.Info("TCP listener bound on %s", boundAddress)
	// Register this node's OWN datadir as its PUBLIC bundle source for the
	// devnet bundle endpoint (handleIncomingConn "devnet_bundle_request").
	// Only devnet nodes serve; only allowlisted PUBLIC files; custody/ never.
	if core.DevnetAutoCustodyRequested(networkType) {
		core.RegisterDevnetBundleDataDir(currentAddress, dataDir)
	}

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
	// is already correct, but before this section production StartNode
	// never instantiated one (only the now-deleted same-box harness did), so
	// it sat unused while wallets dialed the P2P port instead and got
	// silently misrouted or dropped.
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
	// ★ wallet/JSON-RPC listen address. ResolveWalletRPCAddr is the single
	// source of truth: the CLI custody watcher resolves the same value from the
	// same nodeConfig.WSPort, so the two cannot disagree.
	rpcListenAddr := network.ResolveWalletRPCAddr(nodeConfig.WSPort, portOffset)
	rpcMsgCh := make(chan *security.Message, 100)
	walletRPCServer := transport.NewTCPServer(rpcListenAddr, rpcMsgCh, rpcServer, nil)
	if err := walletRPCServer.Start(); err != nil {
		return fmt.Errorf("failed to bind wallet RPC listener on %s: %w", rpcListenAddr, err)
	}
	logger.Info("Wallet/JSON-RPC listener bound on %s", rpcListenAddr)

	// SECTION 11b — dynamic peer discovery via --seeds with DNS support
	//
	// Discovery behaviour is decided by flags/config, never by a node count:
	// an absent --seeds simply means "use the network's default DNS discovery
	// tree", exactly as a real-device node does. There is no count-based
	// branch that disables it.
	noSeedsProvided := seeds == "" || strings.TrimSpace(seeds) == ""

	if noSeedsProvided {
		logger.Info("No --seeds provided; using default DNS discovery tree: %s", dnsdiscovery.DefaultENRTreeURL)
		seeds = dnsdiscovery.DefaultENRTreeURL
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

	// discoveredPeerCount is the OLD meaning of "effective" peers: peers that
	// completed discovery/key exchange at least once. It says nothing about
	// whether the peer can receive a PBFT proposal yet, so it is only used
	// for startup log lines. Consensus gating uses the stake-weighted readiness
	// calculation below, not a peer count.
	discoveredPeerCount := func() int {
		registeredMu.Lock()
		defer registeredMu.Unlock()
		return len(registeredPeers)
	}

	// ★ FIX (chain stuck at height 0 / first proposal lost): readiness used to
	// return len(registeredPeers) — "this peer has done a key exchange
	// with me" — and runBlockProductionLoop treated that as "this validator can
	// take part in PBFT". On a fresh 3-node devnet the followers need 60-75s
	// after their first key exchange to finish startup (each SPHINCS+
	// challenge/response costs ~9s), install genesis from the bootstrap node
	// and open their sync gate. The bootstrap node saw "3 validators known"
	// ~1s after the third node's first contact, proposed block 1 immediately,
	// and that proposal reached followers that had no genesis yet, so it was
	// silently dropped. Nothing re-sends it, so the round only recovered after
	// the 90s commit timeout + a view change.
	//
	// A peer now counts only when it answers get_blocks with ChainReady=true
	// (genesis installed; on followers this happens strictly after cons.Start,
	// and just before their PBFT sync gate opens) continuously for
	// peerReadySettle. The settle window covers the ~4s between "genesis
	// installed" and "sync gate open" on a follower — it is a heuristic; the
	// proper fix is a consensus-ready flag in the get_blocks reply.
	const (
		peerReadyProbeInterval = 2 * time.Second
		peerReadySettle        = 6 * time.Second
	)
	var peerReadyMu sync.Mutex
	peerReadySince := make(map[string]time.Time) // addr -> first continuous "ready" probe
	peerProbeInFlight := make(map[string]bool)   // addr -> a probe goroutine is still running

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(peerReadyProbeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			peerRegistryMu.Lock()
			addrs := make([]string, 0, len(peerRegistry))
			for _, a := range peerRegistry {
				if a != "" && a != currentAddress {
					addrs = append(addrs, a)
				}
			}
			peerRegistryMu.Unlock()

			for _, addr := range addrs {
				peerReadyMu.Lock()
				busy := peerProbeInFlight[addr]
				if !busy {
					peerProbeInFlight[addr] = true
				}
				peerReadyMu.Unlock()
				if busy {
					continue
				}
				go func(addr string) {
					resp, err := requestBlocksFromPeer(addr, 0, 0)
					ready := err == nil && resp != nil && resp.ChainReady

					peerReadyMu.Lock()
					delete(peerProbeInFlight, addr)
					if ready {
						if _, ok := peerReadySince[addr]; !ok {
							peerReadySince[addr] = time.Now()
							logger.Debug("[%s] Peer %s has genesis — starting readiness settle window", currentNodeID, addr)
						}
					} else {
						delete(peerReadySince, addr)
					}
					peerReadyMu.Unlock()
				}(addr)
			}
		}
	}()

	// stakedReadyValidatorCount counts validators that are BOTH in the ACTIVE
	// STAKED set (from chain state) and READY to receive consensus messages
	// (the probe-settled peers above), plus this node when it is staked. It is
	// the only count that gates PBFT startup. Unstaked peers are connectivity
	// only and are never counted — they do not enter quorum math or leader
	// rotation either.
	stakedReadyValidatorCount := func() int {
		if cons == nil {
			return 0
		}
		vs := cons.GetValidatorSet()
		if vs == nil {
			return 0
		}
		staked := make(map[string]bool)
		for _, id := range vs.ActiveValidatorIDs(0) {
			staked[id] = true
		}
		if len(staked) == 0 {
			return 0
		}
		ready := 0
		if staked[currentNodeID] {
			ready++
		}

		// Map registered peer node IDs -> addresses, then keep the ones that
		// are staked AND probe-settled.
		registeredMu.Lock()
		peerIDs := make([]string, 0, len(registeredPeers))
		for id := range registeredPeers {
			peerIDs = append(peerIDs, id)
		}
		registeredMu.Unlock()

		peerRegistryMu.Lock()
		idAddrs := make(map[string]string, len(peerIDs))
		for _, id := range peerIDs {
			if a, ok := peerRegistry[id]; ok && a != "" {
				idAddrs[id] = a
			}
		}
		peerRegistryMu.Unlock()

		now := time.Now()
		peerReadyMu.Lock()
		defer peerReadyMu.Unlock()
		for id, a := range idAddrs {
			if !staked[id] {
				continue
			}
			if since, ok := peerReadySince[a]; ok && now.Sub(since) >= peerReadySettle {
				ready++
			}
		}
		return ready
	}

	// stakedReadyStake is the stake-weighted twin of stakedReadyValidatorCount,
	// and it is what the PBFT readiness GATE actually uses.
	//
	// ★ WHY STAKE, NOT COUNT. The gate used to wait for
	// consensus.MinValidators (3) ready validators, which is a hard-coded node
	// number in a consensus-adjacent path and cannot express unequal stakes.
	// The protocol's actual condition is that strictly more than 2/3 of the
	// ACTIVE snapshot's stake is ready (ready*3 > total*2), so that is what is
	// measured here.
	//
	// Consequences, all of them correct:
	//   - 1 validator: holds 100% of the stake, so it is ready immediately and
	//     commits its own blocks;
	//   - 2 validators: BOTH must be ready (1 of 2 is only 1/2);
	//   - 3 validators: ALL THREE must be ready, because 2 of 3 is exactly 2/3
	//     and the rule is STRICTLY more;
	//   - 4 validators: 3 of 4 suffice, so one may be offline.
	//
	// READINESS IS CHAIN STATE + VERIFIED SYNC, NEVER PEER COUNT. `active`
	// comes from the on-chain validator set filtered by the height-derived
	// epoch, and a peer counts as ready only once the readiness probe has seen
	// it answer with ChainReady for the settle window. A connected peer that
	// is not in `active` cannot appear in either number no matter how many of
	// them there are — see TestComputeReadyStake_UnstakedPeersAreInvisible.
	stakedReadyStake := func() (ready, total *big.Int) {
		zero := func() (*big.Int, *big.Int) { return big.NewInt(0), big.NewInt(0) }
		if cons == nil {
			return zero()
		}
		vs := cons.GetValidatorSet()
		if vs == nil {
			return zero()
		}
		// ★ THE EPOCH IS DERIVED FROM HEIGHT, not from the view.
		// consensus.currentEpoch is view-derived (view / SlotsPerEpoch) and two
		// nodes in different views would disagree about it — which is exactly
		// what a readiness gate must not depend on. Deriving it from the chain
		// height via consensus.EpochForHeight makes every node at the same height
		// compute the same active set.
		active := vs.GetActiveValidators(consensus.EpochForHeight(cons.GetCurrentHeight()))
		if len(active) == 0 {
			return zero()
		}

		// A peer counts as READY only once the readiness probe has seen it
		// answer with ChainReady continuously for the settle window. Anything
		// else — merely connected, merely registered — is not ready.
		isPeerReady := func(id string) bool {
			peerRegistryMu.Lock()
			addr, ok := peerRegistry[id]
			peerRegistryMu.Unlock()
			if !ok || addr == "" {
				return false
			}
			now := time.Now()
			peerReadyMu.Lock()
			defer peerReadyMu.Unlock()
			since, ok := peerReadySince[addr]
			return ok && now.Sub(since) >= peerReadySettle
		}

		return computeReadyStake(active, currentNodeID, isPeerReady)
	}

	logger.Info("=== EXCHANGING PUBLIC KEYS (SYNC) BEFORE CONSENSUS ===")

	// ★ FIX (slow follower startup): every exchangeKeyWithPeerSync costs
	// ~9s (a SPHINCS+ signature on each side). The two loops below used
	// to exchange with the SAME peers again and again — once during seed
	// discovery, once here in the same-box loop, once more in the
	// discovered-peer loop (plus a background dial-back). Each follower
	// spent ~40s of its 60-75s startup repeating handshakes that had
	// already succeeded, which is exactly the window in which the
	// bootstrap node was already proposing. Exchanging once per address
	// is sufficient: the responder pins node_id<->key on the first
	// verified handshake and a repeat is a no-op for it.
	exchangedAddrs := make(map[string]bool)
	addrAlreadyVerified := func(addr string) bool {
		peerRegistryMu.Lock()
		var ids []string
		for id, a := range peerRegistry {
			if a == addr {
				ids = append(ids, id)
			}
		}
		peerRegistryMu.Unlock()
		dialbackMu.Lock()
		defer dialbackMu.Unlock()
		for _, id := range ids {
			if dialbackVerified[id] {
				return true
			}
		}
		return false
	}

	// No static roster exists anymore: peers reach this point only via
	// discovery (seeds/DNS/PEX) and are handled by the discovered-peer
	// loop below.
	peerRegistryMu.Lock()
	var discoveredAddrs []string
	for _, addr := range peerRegistry {
		discoveredAddrs = append(discoveredAddrs, addr)
	}
	peerRegistryMu.Unlock()
	for _, addr := range discoveredAddrs {
		if exchangedAddrs[addr] || addrAlreadyVerified(addr) {
			logger.Info("Key exchange with %s already completed — skipping repeat handshake", addr)
			continue
		}
		logger.Info("Exchanging keys with discovered peer: %s", addr)
		if kx, err := exchangeKeyWithPeerSync(addr, currentAddress, currentNodeID, rewardAddress, core.GetGenesisHash(), signingService, sthincsParams); err != nil {
			logger.Warn("Failed to exchange keys with %s: %v", addr, err)
		} else {
			exchangedAddrs[addr] = true
			admitVerifiedPeer(kx.NodeID, addr)
			registerDiscoveredPeer(kx.NodeID, addr)
			if kx.RewardAddress != "" {
				registerPeerStakeClaim(kx.NodeID, kx.RewardAddress)
			}
		}
	}
	logger.Info("Key exchange completed with all discovered peers")

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

	if err := cons.Start(); err != nil {
		return fmt.Errorf("failed to start consensus: %w", err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		runCheckpointSyncLoop(ctx, bc, cons, currentNodeID, peerAddrsFunc, currentAddress)
	}()
	logger.Info("Consensus engine started AFTER key exchange")

	// Node initialization is complete; mark startup as done
	progress.CompleteNodeStartup()

	// SECTION 12 — HTTP server
	httpPort := 8545 + portOffset
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

	// The server object is built HERE (it only wires routes; nothing is bound
	// until Start) so the shutdown path holds a reference to Stop(). Start()
	// itself is non-blocking — it spawns gin's own listener goroutine — so
	// running it in a goroutine merely preserves the previous launch shape.
	httpMsgCh := make(chan *security.Message, 100)
	httpSrv := http.NewServer(httpListenAddr, httpMsgCh, bc, nil)
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("JSON-RPC listening on http://%s", httpListenAddr)
		if err := httpSrv.Start(); err != nil {
			logger.Error("HTTP server error: %v", err)
		}
	}()

	// SECTION 14 — block sync loop (catch-up mechanism)
	// The node starts in SYNCING state. It will query peers for missing blocks
	// and apply them before participating in consensus.

	// ============================================================================
	// computeReadyStake — the pure arithmetic behind the PBFT readiness gate
	//
	// ★ READINESS IS DEFINED HERE, AND IT IS TWO INPUTS, NOT A PEER COUNT:
	//
	//	active    the on-chain validator set filtered to the height-derived epoch.
	//	          A validator that is pending, slashed, or retired is NOT in it,
	//	          so it contributes to neither number.
	//	isPeerReady(id)  whether that specific validator peer has been observed
	//	          to answer with ChainReady continuously for the settle window.
	//	          Self is always ready.
	//
	// A connected-but-unstaked peer cannot reach either number, because it is not
	// in `active` at all — no number of them changes the result. That is the
	// property TestComputeReadyStake_UnstakedPeersAreInvisible pins.
	//
	// Extracted from the startup closure so it can be tested without booting a node.
	// ============================================================================
	var syncState SyncState = SyncStateSyncing
	var syncStateMu sync.Mutex

	// ★ peerAddrsFunc (defined in SECTION 8, right after getKnownPeers) is a
	// live accessor over the mutex-protected address book, not a one-time
	// snapshot, so this sync goroutine always sees currently-known peers —
	// including peers that connect AFTER the node started.
	wg.Add(1)
	go func() {
		defer wg.Done()
		runBlockSyncLoop(ctx, bc, cons, currentNodeID, peerAddrsFunc, &syncState, &syncStateMu, progress, syncStatusTracker)
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
	if !genesisVerified {
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
		runBlockProductionLoop(ctx, bc, cons, currentNodeID, networkType,
			stakedReadyValidatorCount, stakedReadyStake, &syncState, &syncStateMu, progress)
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

	knownPeers := discoveredPeerCount()
	// The startup banner reports CONNECTIVITY only. PBFT readiness is decided
	// by runBlockProductionLoop from the staked validator set, not from a
	// configured node count, so a small peer count is not an error.
	switch {
	case knownPeers == 0:
		logger.Info("Mode: no peers connected yet — waiting for discovered peers; consensus follows chain state")
	default:
		logger.Info("Mode: connected (%d known peer(s))", knownPeers)
	}

	logger.Info("Press Ctrl+C to stop")

	// SECTION 16 — graceful shutdown
	//
	// Three equivalent sources: SIGINT/SIGTERM (the CLI), opts.Stop (a host
	// process such as the GUI), or the node context. signal.Stop removes this
	// registration on the way out, so a stopped node leaves no live handler
	// behind — which matters when the same process starts another node.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	reason := waitForShutdown(ctx, opts.Stop, sigCh)
	if reason == shutdownBySignal {
		// Unchanged CLI wording.
		logger.Info("Shutdown signal received — stopping node…")
	} else {
		logger.Info("Shutdown requested (%s) — stopping node…", reason)
	}

	// Ordered teardown — context → consensus → transports → DHT → wait →
	// flush → databases. See nodeShutdown.run for why each step is in that
	// position; every resource is released explicitly, which is what makes an
	// in-process restart possible (previously none of the listeners or
	// databases was ever closed).
	(&nodeShutdown{
		consensus:    cons,
		stateMachine: bc.GetStateMachine(),
		mempool:      bc.GetMempool(),
		tpsMonitor:   bc.GetTPSMonitor(),
		rpcServer:    rpcServer,
		cancelCtx:    cancelCtx,
		p2pListener:  tcpListener,
		walletRPC:    walletRPCServer,
		httpSrv:      httpSrv,
		dht:          dhtInstance,
		wait:         &wg,
		flush: func() {
			flushNodeState(bc, currentNodeID, currentAddress)
		},
		databases: []io.Closer{mainDatabase, stateDatabase},
	}).run()

	logger.Info("Node stopped cleanly")
	return nil
}

// discoveryModeDesc describes how this node will look for peers, purely from
// flags/config — never from a node count.
func discoveryModeDesc(seeds string) string {
	if strings.TrimSpace(seeds) == "" {
		return "default DNS discovery tree + PEX (no --seeds given)"
	}
	return "operator-provided --seeds + DNS trees + PEX"
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

// ============================================================================
// computeReadyStake — the pure arithmetic behind the PBFT readiness gate
//
// ★ READINESS IS DEFINED HERE, AND IT IS TWO INPUTS, NOT A PEER COUNT:
//
//	active       the on-chain validator set filtered to the height-derived
//	             epoch. A validator that is pending, slashed or retired is
//	             NOT in it, so it contributes to neither number.
//	isPeerReady  whether that specific validator peer has been observed to
//	             answer with ChainReady continuously for the settle window.
//	             Self is always ready for itself.
//
// A connected-but-unstaked peer cannot reach either number, because it is not
// in `active` at all — no number of them changes the result. That is the
// property TestComputeReadyStake_UnstakedPeersAreInvisible pins.
//
// Extracted out of the startup closure so it is testable without booting a node.
// ============================================================================
func computeReadyStake(active []*consensus.StakedValidator, selfID string, isPeerReady func(id string) bool) (ready, total *big.Int) {
	ready = big.NewInt(0)
	total = big.NewInt(0)
	for _, v := range active {
		if v == nil || v.StakeAmount == nil || v.StakeAmount.Sign() <= 0 {
			continue
		}
		amt := new(big.Int).Set(v.StakeAmount)
		total = new(big.Int).Add(total, amt)
		if v.ID == selfID {
			ready = new(big.Int).Add(ready, amt)
			continue
		}
		if isPeerReady != nil && isPeerReady(v.ID) {
			ready = new(big.Int).Add(ready, amt)
		}
	}
	return ready, total
}
