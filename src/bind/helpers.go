// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/helpers.go
//
// Helper types and functions for node startup, moved from cli/utils
// to consolidate all node startup logic in the bind package.

package bind

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/core"
	svm "github.com/sphinxfndorg/protocol/src/core/kernel/opcodes"
	vmachine "github.com/sphinxfndorg/protocol/src/core/kernel/vm"
	spxKey "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	usiKey "github.com/sphinxfndorg/protocol/src/usi/core/key"

	logger "github.com/sphinxfndorg/protocol/src/console"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	"github.com/sphinxfndorg/protocol/src/rpc"
)

// writeFramedMessage writes a length-prefixed message to the connection.
func writeFramedMessage(conn net.Conn, data []byte) error {
	// Write 4-byte big-endian length prefix
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := conn.Write(lenBuf); err != nil {
		return fmt.Errorf("writing length prefix: %w", err)
	}
	// Write payload
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("writing payload: %w", err)
	}
	return nil
}

// frameReadTimeout bounds how long an ordinary protocol frame may take to
// arrive. Ordinary messages (challenges, requests, gossip) are request/reply
// exchanges a peer can answer without heavy computation, so this stays short.
const frameReadTimeout = 10 * time.Second

// handshakeSignTimeout bounds reads that must wait for a peer to COMPUTE a
// SPHINCS+ signature: the auth_proof that answers a challenge, and the signed
// key_exchange / peer_exchange reply.
//
// With the production 128s parameter set a single Spx_sign costs on the order
// of ten seconds of CPU (measured ~11.4s sign / ~4.5s keygen on one modern
// laptop), while verification costs only milliseconds. frameReadTimeout is
// therefore too short for these reads: an honest peer that is still signing
// would be dropped mid-handshake on all but the fastest hardware. The generous
// bound only ever delays a genuinely silent/stalled connection, and each
// connection is served by its own goroutine.
const handshakeSignTimeout = 60 * time.Second

// readFramedMessage reads a length-prefixed message from the connection using
// the ordinary frame deadline. Use readFramedMessageWithTimeout for reads that
// have to wait for a peer's signature computation.
func readFramedMessage(conn net.Conn) ([]byte, error) {
	return readFramedMessageWithTimeout(conn, frameReadTimeout)
}

// readFramedMessageWithTimeout reads a length-prefixed message from the
// connection, failing if a complete frame does not arrive within timeout.
func readFramedMessageWithTimeout(conn net.Conn, timeout time.Duration) ([]byte, error) {
	// Read 4-byte big-endian length prefix
	conn.SetReadDeadline(time.Now().Add(timeout))
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("reading length prefix: %w", err)
	}
	size := binary.BigEndian.Uint32(lenBuf[:])
	if size == 0 || size > 16*1024*1024 { // Sanity cap: 16MB
		return nil, fmt.Errorf("implausible message size: %d", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, fmt.Errorf("reading %d-byte payload: %w", size, err)
	}
	return data, nil
}

// ============================================================================
// Checkpoint sync
// ============================================================================

// baseWalletRPCPort is the base port of a node's dedicated wallet/JSON-RPC
// listener (the transport.TCPServer started in StartNode SECTION 11a). It
// mirrors network.port.go's baseWSPort (8700) and nodes.go's
// "8700+port-offset" fallback used when --ws-port is unset or left at the CLI
// default ("127.0.0.1:8600").
const baseWalletRPCPort = 8700

// devnetBaseTCPPort is the P2P gossip port used by --port-offset 0 and the
// anchor of the local port convention (tcp = 30303+offset, wallet RPC =
// 8700+offset) used when several node processes share one machine.
const devnetBaseTCPPort = 30303

// peerWaitLogInterval rate-limits the two "waiting for peers" messages in this
// file: runBlockSyncLoop's "No peers reachable" WARN and
// runBlockProductionLoop's "Sync in progress" INFO heartbeat. Both are emitted
// from retry/poll loops that run for as long as a node waits on peers which
// simply are not up yet — the normal state during a network's startup race,
// and again whenever a peer process dies. Unthrottled they produced 20-40
// near-identical lines a minute, burying the actionable lines around them.
// 30s keeps an operator informed without the flood, and the limiter's
// "(+N suppressed)" suffix preserves the count of folded attempts.
const peerWaitLogInterval = 30 * time.Second

// walletRPCAddressForNode translates a peer's P2P gossip address to its
// dedicated wallet/JSON-RPC listener.
//
// bc.SyncCheckpoints → rpc.CallRPC speaks handshake-authenticated, encrypted
// JSON-RPC 2.0 framing and therefore MUST dial the peer's dedicated wallet
// listener — NOT its P2P gossip port. The P2P gossip listener
// (handleIncomingConn, nodes.go SECTION 11) uses a plain, length-prefixed
// wire format and has no "jsonrpc" case: when CallRPC connects to it, the
// server reads the client's raw Kyber768/X25519 handshake bytes as a message
// length, rejects the frame and resets the connection ("RPC call failed:
// handshake ... connection reset by peer").
//
// There is no static peer roster any more, so the translation uses the
// --port-offset port convention above. A peer whose TCP port does not sit in
// that range has no derivable wallet port and is skipped (""), never dialled
// at a guessed one.
func walletRPCAddressForNode(peerP2PAddr string) string {
	host, portStr, err := net.SplitHostPort(peerP2PAddr)
	if err != nil {
		return ""
	}
	if host == "" {
		host = "127.0.0.1"
	}
	tcp, convErr := strconv.Atoi(portStr)
	if convErr != nil {
		return ""
	}
	offset := tcp - devnetBaseTCPPort
	if offset < 0 || offset > 1000 {
		return ""
	}
	return fmt.Sprintf("%s:%d", host, baseWalletRPCPort+offset)
}

// runCheckpointSyncLoop periodically syncs checkpoints.
//
// peerAddrsFunc returns the CURRENT discovered peer address book (the same
// source the block-sync loop uses). selfAddr is this node's own P2P address,
// which is always excluded from the peer pull. There is no static roster: a
// node with no peers still broadcasts its own checkpoints when leader.
func runCheckpointSyncLoop(
	ctx context.Context,
	bc *core.Blockchain,
	cons *consensus.Consensus,
	nodeID string,
	peerAddrsFunc func() []string,
	selfAddr string,
) {
	// syncFromPeers pulls a checkpoint from the first responsive peer.
	syncFromPeers := func() bool {
		if bc.GetLatestBlock() == nil {
			logger.Debug("[%s] No local chain yet; skipping checkpoint sync until genesis is installed", nodeID)
			return false
		}
		if peerAddrsFunc == nil {
			return false
		}
		peers := peerAddrsFunc()
		for _, p2pAddr := range peers {
			if p2pAddr == selfAddr {
				continue
			}
			logger.Info("[%s] Syncing checkpoint from %s...", nodeID, p2pAddr)
			peerRPCAddr := walletRPCAddressForNode(p2pAddr)
			if peerRPCAddr == "" {
				logger.Debug("[%s] No derivable wallet-RPC port for peer %s — skipping", nodeID, p2pAddr)
				continue
			}
			if err := bc.SyncCheckpoints(peerRPCAddr); err != nil {
				logger.Debug("[%s] Failed to sync checkpoint from %s: %v", nodeID, peerRPCAddr, err)
				continue
			}
			logger.Info("[%s] Synced checkpoint from %s", nodeID, peerRPCAddr)
			return true
		}
		return false
	}

	time.Sleep(3 * time.Second)
	syncedOnce := syncFromPeers()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// The initial pull can race peer startup (connection refused).
			// Keep retrying until at least one peer has answered so a late
			// joiner is never stranded without a peer checkpoint.
			if !syncedOnce {
				syncedOnce = syncFromPeers()
			}

			if cons == nil || !cons.IsLeader() || bc.GetLatestBlock() == nil {
				continue
			}

			logger.Info("[%s] Broadcasting checkpoint to peers", nodeID)
			if err := cons.BroadcastCheckpoint(); err != nil {
				logger.Warn("[%s] Failed to broadcast checkpoint: %v", nodeID, err)
				continue
			}

			if err := bc.WriteChainCheckpoint(); err != nil {
				logger.Warn("[%s] Failed to write local checkpoint: %v", nodeID, err)
			}
		}
	}
}

// seedGenesisValidators loads the initial validator set from the genesis file
// into consensus. This is the ONLY place initial membership is established:
// every node that reads the same file computes the same set, hence the same
// leader rotation and quorum denominators. It registers the peer public keys
// up front so genesis-validator signatures verify without waiting for a
// key-exchange handshake.
//
// It never invents a validator that the file does not list, and it never
// touches the number of nodes.
func seedGenesisValidators(
	cons *consensus.Consensus,
	signingService *consensus.SigningService,
	params *parameters.Parameters,
	gf *core.GenesisStateFile,
	selfNodeID string,
	bc *core.Blockchain,
) (bool, error) {
	vs := cons.GetValidatorSet()
	if vs == nil {
		return false, fmt.Errorf("consensus validator set is unavailable")
	}
	selfSeeded := false
	for _, v := range gf.Validators {
		stakeNSPX := gf.StakeNSPX(v.NodeID)
		if stakeNSPX == nil || stakeNSPX.Sign() <= 0 {
			return false, fmt.Errorf("validator %s: bad genesis stake %q", v.NodeID, v.StakeNSPX)
		}
		// nSPX straight through: no whole-SPX truncation (Checkpoint 1b 1b).
		if err := vs.AddGenesisValidator(v.NodeID, stakeNSPX); err != nil {
			return false, fmt.Errorf("validator %s: %w", v.NodeID, err)
		}
		if v.RewardAddress != "" && bc != nil {
			addr := common.CanonicalSPIFAddress(v.RewardAddress)
			bc.SetValidatorRewardAddress(v.NodeID, addr)
		}
		if v.NodeID == selfNodeID {
			selfSeeded = true
			continue // self's key is registered by StartNode itself
		}
		if v.PublicKey == "" || signingService == nil || params == nil {
			continue
		}
		pkHex := v.PublicKey
		if len(pkHex) >= 2 && (pkHex[:2] == "0x" || pkHex[:2] == "0X") {
			pkHex = pkHex[2:]
		}
		pkBytes, derr := hex.DecodeString(pkHex)
		if derr != nil {
			logger.Warn("genesis file: validator %s has unparseable public key: %v", v.NodeID, derr)
			continue
		}
		pk, kerr := sthincs.DeserializePK(params, pkBytes)
		if kerr != nil {
			logger.Warn("genesis file: cannot deserialize public key for %s: %v", v.NodeID, kerr)
			continue
		}
		signingService.RegisterPublicKey(v.NodeID, pk)
	}
	return selfSeeded, nil
}

// ============================================================================
// Block sync / catch-up mechanism
// ============================================================================

// requestBlocksFromPeer dials a peer, sends a GetBlocksRequest for the given
// height range, and returns the response. It is a blocking call that should
// be called from the sync loop goroutine.
//
// Detailed logging captures the exact bytes sent and received to diagnose
// serialization or I/O issues during late-joiner sync.
func requestBlocksFromPeer(peerAddr string, fromHeight, toHeight uint64) (*GetBlocksResponse, error) {
	req := GetBlocksRequest{
		FromHeight: fromHeight,
		ToHeight:   toHeight,
		MaxResults: 500,
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal get_blocks request: %w", err)
	}

	logger.Debug("requestBlocksFromPeer[%s]: REQUEST JSON: %s", peerAddr, string(reqBytes))

	conn, err := net.DialTimeout("tcp", peerAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()
	// ★ FIX: no read deadline existed, so a peer that accepted the connection
	// but never answered (e.g. blocked behind the leader's chain lock while it
	// signs a block) parked this call — and the sync loop / readiness prober
	// behind it — forever.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	msg := security.Message{Type: "get_blocks", Data: reqBytes}
	encodedMsg, err := msg.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode failed: %w", err)
	}

	logger.Debug("requestBlocksFromPeer[%s]: WIRE MSG (hex): %x", peerAddr, encodedMsg)
	logger.Debug("requestBlocksFromPeer[%s]: WIRE MSG (len=%d)", peerAddr, len(encodedMsg))

	if err := writeFramedMessage(conn, encodedMsg); err != nil {
		return nil, fmt.Errorf("send failed: %w", err)
	}

	replyData, err := readFramedMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("receive failed: %w", err)
	}

	logger.Debug("requestBlocksFromPeer[%s]: REPLY RAW (hex): %x", peerAddr, replyData)
	logger.Debug("requestBlocksFromPeer[%s]: REPLY RAW (len=%d)", peerAddr, len(replyData))

	var reply security.Message
	if err := json.Unmarshal(replyData, &reply); err != nil {
		return nil, fmt.Errorf("decode failed: %w", err)
	}

	logger.Debug("requestBlocksFromPeer[%s]: REPLY TYPE=%s, DATA_LEN=%d", peerAddr, reply.Type, len(reply.Data))

	if reply.Type != "get_blocks" {
		return nil, fmt.Errorf("unexpected reply type: %s", reply.Type)
	}

	var resp GetBlocksResponse
	if err := json.Unmarshal(reply.Data, &resp); err != nil {
		logger.Error("requestBlocksFromPeer[%s]: Failed to unmarshal GetBlocksResponse: %v\n  Data (hex): %x\n  Data (str): %s",
			peerAddr, err, reply.Data, string(reply.Data))
		return nil, fmt.Errorf("unmarshal response failed: %w", err)
	}

	logger.Debug("requestBlocksFromPeer[%s]: RESPONSE: tip_height=%d, chain_ready=%t, blocks_count=%d, error=%q",
		peerAddr, resp.TipHeight, resp.ChainReady, len(resp.Blocks), resp.Error)

	if resp.Error != "" {
		return nil, fmt.Errorf("peer error: %s", resp.Error)
	}
	return &resp, nil
}

// getPeerTipHeight asks a single peer for its current chain tip height by
// requesting a single block at height 0 (genesis) and reading the TipHeight
// from the response. This is a lightweight way to learn the network tip.
func getPeerTipHeight(peerAddr string) (uint64, error) {
	logger.Debug("getPeerTipHeight[%s]: Querying peer for tip height", peerAddr)
	resp, err := requestBlocksFromPeer(peerAddr, 0, 0)
	if err != nil {
		logger.Warn("getPeerTipHeight[%s]: Failed: %v", peerAddr, err)
		return 0, err
	}
	logger.Debug("getPeerTipHeight[%s]: Peer tip height=%d", peerAddr, resp.TipHeight)
	return resp.TipHeight, nil
}

// runBlockSyncLoop runs the initial block download / catch-up loop.
//
// It starts in SyncStateSyncing, queries peers for the current network tip
// height, then requests and applies missing blocks sequentially. Each block
// is validated (parent hash chain continuity) before being committed locally.
// The loop repeats until local height is within 1 block of the network tip.
//
// Once caught up, it transitions to SyncStateCaughtUp. The caller
// (runBlockProductionLoop) should check the sync state and only begin PBFT
// participation after the state reaches SyncStateConsensusParticipant.
//
// This loop NEVER gives up — it retries with exponential backoff (up to 5 minutes)
// and keeps trying all known peers indefinitely until the node is caught up.
//
// It also publishes OBSERVATIONAL snapshots of the values it already computed
// (local height, network tip, reachable peers, sync state) to the
// getsyncstatus provider via observeSync (see rpc.SyncStatusTracker). Those
// calls have no return value any branch consults and cannot affect control
// flow; they only make the existing state readable to wallets.
func runBlockSyncLoop(
	ctx context.Context,
	bc *core.Blockchain,
	cons *consensus.Consensus,
	nodeID string,
	peerAddrsFunc func() []string,
	syncState *SyncState,
	syncStateMu *sync.Mutex,
	progress *logger.BlockchainProgress, // NEW
	tracker *rpc.SyncStatusTracker, // NEW — observational only: feeds getsyncstatus
) {
	logger.Info("[%s] Block sync loop started (state=%s)", nodeID, syncState.String())

	// observeSync publishes this loop's ALREADY-COMPUTED view of the world to
	// the wallet-facing getsyncstatus provider (see src/rpc/syncstatus.go).
	// It only READS *syncState under the same mutex the loop's own
	// transitions use, takes no result the loop acts on, and must be called
	// only while syncStateMu is NOT held (the closure locks it itself).
	observeSync := func(highestPeerHeight uint64, reachablePeers int) {
		syncStateMu.Lock()
		state := *syncState
		syncStateMu.Unlock()
		tracker.Observe(rpc.SyncStatus{
			Syncing:                state == SyncStateSyncing,
			CurrentHeight:          bc.GetBlockCount(),
			HighestKnownPeerHeight: highestPeerHeight,
			PeerCount:              reachablePeers,
			State:                  state.String(),
		})
	}

	const (
		maxBatchSize        uint64 = 500
		baseRetryInterval          = 1 * time.Second
		maxRetryInterval           = 5 * time.Minute
		backoffMultiplier          = 2
		peerRefreshInterval        = 30 * time.Second
	)

	currentRetryInterval := baseRetryInterval
	consecutiveFailures := 0
	lastPeerRefresh := time.Now()
	peerFailureCount := make(map[string]int)

	// noPeerSyncLog rate-limits the "No peers reachable" line emitted in the
	// retry branch below. Keyed per node so one node's retries can never
	// suppress another's (the same-box devnet and the bind tests run several
	// nodes inside one process). See the branch for why the cadence needs a
	// bound at all.
	noPeerSyncLog := logger.Limited("bind:no-peers:"+nodeID, peerWaitLogInterval)

	// resyncOnDivergenceCount prevents infinite recovery loops: if we've
	// already attempted recovery this many times in a single sync-loop
	// lifetime, we stop trying and let the operator intervene.
	const maxResyncAttempts = 3
	resyncAttempts := 0

	// Track sync progress for the dashboard
	var syncStarted bool
	var totalBlocksToSync int64 // blocks-behind delta, used only for the log line below
	// syncTargetHeight is the absolute network tip height. Both arguments to
	// progress.StartBlockSync/UpdateBlockSync must be absolute heights (see
	// the solo-mining call site further down, which passes blk.GetHeight()
	// for both current and total). Previously totalBlocksToSync (a relative
	// "blocks behind" delta computed once when a sync pass started) was
	// passed as the total while an absolute height was passed as current —
	// that mismatch produced a "Height 13 / 1" / "Sync 1300.0%" dashboard
	// corruption: current kept climbing to the real absolute height while
	// total stayed frozen at whatever small delta existed when the pass began.
	var syncTargetHeight int64

	for {
		select {
		case <-ctx.Done():
			logger.Info("[%s] Block sync loop shutting down", nodeID)
			return
		default:
		}

		// Read the live peer list on every iteration so newly discovered
		// addresses are included in subsequent sync requests. The list is
		// transport input only; local readiness is not inferred from its size.
		peerAddrs := peerAddrsFunc()

		localTip := bc.GetLatestBlock()
		localHeight := uint64(0)
		hasGenesis := false
		if localTip != nil {
			localHeight = localTip.GetHeight()
			hasGenesis = true
		}
		if hasGenesis {
			syncStateMu.Lock()
			if *syncState == SyncStateSyncing {
				*syncState = SyncStateCaughtUp
				logger.Info("[%s] Local chain is initialized — sync readiness is based on chain state", nodeID)
				if syncStarted {
					syncStarted = false
				}
			}
			syncStateMu.Unlock()
		}

		logger.Debug("[%s] Sync loop: localHeight=%d, hasGenesis=%v, retryInterval=%v",
			nodeID, localHeight, hasGenesis, currentRetryInterval)

		if time.Since(lastPeerRefresh) > peerRefreshInterval {
			logger.Debug("[%s] Refreshing peer list (last refresh %v ago)", nodeID, time.Since(lastPeerRefresh))
			peerFailureCount = make(map[string]int)
			lastPeerRefresh = time.Now()
		}

		// ── QUERY PEERS FOR NETWORK TIP ──
		networkTip := uint64(0)
		bestPeerAddr := ""
		reachablePeers := 0
		peerResponded := false
		for _, addr := range peerAddrs {
			if addr == "" {
				continue
			}
			tip, err := getPeerTipHeight(addr)
			if err != nil {
				logger.Debug("[%s] Peer %s failed tip query: %v", nodeID, addr, err)
				continue
			}
			peerResponded = true
			reachablePeers++
			// ★ FIX 1: keep the first reachable peer as fallback even if tip=0
			if bestPeerAddr == "" {
				bestPeerAddr = addr
			}
			if tip > networkTip {
				networkTip = tip
				bestPeerAddr = addr
			}
		}
		// [observational] Publish this pass's already-computed view: highest
		// reachable peer tip + how many peers answered. No branch below
		// consults this; getsyncstatus reads it.
		observeSync(networkTip, reachablePeers)

		if !peerResponded {
			// ★ FIX: this is the one actionable line when a node is waiting
			// for peers that are not up yet (e.g. node 2/3 of a same-box
			// devnet still booting, or a crashed peer), so name the addresses
			// that were tried. It previously reported only "tried 3 peers",
			// which told an operator nothing — the addresses here are the P2P
			// gossip ports, i.e. the ones that must have a listener for the
			// other node to be considered up. Throttled through
			// logger.Limited(peerWaitLogInterval): the backoff below starts
			// at 1s and doubles, so this branch is hit on every retry and an
			// unthrottled WARN flooded the first minute of a healthy startup
			// race. The limiter appends "(+N suppressed)", so the operator
			// can still see how many attempts happened inside the window.
			noPeerSyncLog.Warn("[%s] No peers reachable — tried addresses (%s); backing off before retry (is the other node running?)",
				nodeID, strings.Join(peerAddrs, ", "))
			logger.Debug("[%s] No peers reachable — tried addresses (%s)",
				nodeID, strings.Join(peerAddrs, ", "))
			consecutiveFailures++
			currentRetryInterval = time.Duration(float64(currentRetryInterval) * backoffMultiplier)
			if currentRetryInterval > maxRetryInterval {
				currentRetryInterval = maxRetryInterval
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(currentRetryInterval):
			}
			continue
		}

		// ── GENESIS HANDLING ──
		if !hasGenesis {
			logger.Info("[%s] No genesis block locally – fetching from peer %s", nodeID, bestPeerAddr)
			resp, err := requestBlocksFromPeer(bestPeerAddr, 0, 0)
			if err != nil || len(resp.Blocks) == 0 {
				logger.Warn("[%s] Failed to fetch genesis from %s: %v", nodeID, bestPeerAddr, err)
				consecutiveFailures++
				currentRetryInterval = time.Duration(float64(currentRetryInterval) * backoffMultiplier)
				if currentRetryInterval > maxRetryInterval {
					currentRetryInterval = maxRetryInterval
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(currentRetryInterval):
				}
				continue
			}
			genesisBlock := resp.Blocks[0]
			if genesisBlock == nil || genesisBlock.GetHeight() != 0 {
				logger.Warn("[%s] Peer %s returned invalid genesis block", nodeID, bestPeerAddr)
				consecutiveFailures++
				currentRetryInterval = time.Duration(float64(currentRetryInterval) * backoffMultiplier)
				if currentRetryInterval > maxRetryInterval {
					currentRetryInterval = maxRetryInterval
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(currentRetryInterval):
				}
				continue
			}
			// ★ GUARD: never adopt a peer's genesis unverified. A hostile peer
			// can serve its OWN genesis naming ITS OWN validator, and from
			// then on every block it offers verifies perfectly against that
			// chain. The local genesis was authored here or derived from the
			// verified bundle (devnet), or pinned out-of-band (mainnet), so its
			// commitments are the anchor. A mismatch is a hard refusal and the
			// peer is scored, because there is no honest explanation for
			// serving a different chain.
			// ★ THE ANCHOR MUST NOT BE "whatever happens to be stored at height
			// 0". A late joiner never stores one — it skips genesis execution
			// and syncs block 0 from a peer — so bc.GetBlockByNumber(0) is nil
			// there, and this guard then refused EVERY genesis with "no local
			// genesis block to verify the peer's against", leaving the joiner at
			// height 0 forever despite having reachable peers. Fall back to the
			// in-memory genesis block this node derived INDEPENDENTLY from its
			// own genesis document (authored here, or fetched and verified from
			// the bootstrap before startup). Every check inside
			// VerifyPeerGenesis still applies — document digest, active-snapshot
			// hash and full block hash — so nothing is weakened.
			localGenesis := bc.GetBlockByNumber(0)
			if localGenesis == nil {
				localGenesis = core.LocalGenesisAnchor()
			}
			if err := core.VerifyPeerGenesis(genesisBlock, localGenesis); err != nil {
				logger.Error("[%s] REFUSED peer genesis from %s: %v — staying at height 0",
					nodeID, bestPeerAddr, err)
				peerFailureCount[bestPeerAddr]++
				consecutiveFailures++
				currentRetryInterval = time.Duration(float64(currentRetryInterval) * backoffMultiplier)
				if currentRetryInterval > maxRetryInterval {
					currentRetryInterval = maxRetryInterval
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(currentRetryInterval):
				}
				continue
			}
			if existing := bc.GetBlockByNumber(0); existing != nil &&
				existing.GetHash() == genesisBlock.GetHash() {
				// Identical genesis: replacing would be a no-op that still
				// rewrites storage and re-executes block 0. Skip it.
				logger.Info("[%s] Peer genesis matches local genesis (%s) — no replacement needed",
					nodeID, genesisBlock.GetHash())
				hasGenesis = true
				localHeight = 0
				consecutiveFailures = 0
				continue
			}
			if err := bc.ReplaceGenesis(genesisBlock); err != nil {
				logger.Error("[%s] Failed to replace genesis: %v", nodeID, err)
				consecutiveFailures++
				currentRetryInterval = time.Duration(float64(currentRetryInterval) * backoffMultiplier)
				if currentRetryInterval > maxRetryInterval {
					currentRetryInterval = maxRetryInterval
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(currentRetryInterval):
				}
				continue
			}
			logger.Info("[%s] Genesis block installed (hash=%s)", nodeID, genesisBlock.GetHash())

			// ════════════════════════════════════════════════════════════════════
			// ★ FIX: Execute genesis right after installing it.
			// ════════════════════════════════════════════════════════════════════
			// The genesis block's body carries one distribution transaction per
			// allocation (Sender: GenesisVaultAddress), but nothing funds the
			// vault or applies those transactions until ExecuteGenesisBlock runs.
			// createGenesisBlock() calls it for the first node, but a late
			// joiner only ever goes through ReplaceGenesis — without this call
			// its vault and every allocation address (including validator
			// stake addresses) stay at zero balance forever, which
			// IsDistributionComplete() used to silently read as "distribution
			// already complete" because an unfunded vault also has a zero
			// balance. ExecuteGenesisBlock is idempotent, so this is safe even
			// if some other path already funded it.
			if err := bc.ExecuteGenesisBlock(); err != nil {
				logger.Error("[%s] Failed to execute genesis block: %v", nodeID, err)
			} else {
				logger.Info("[%s] Genesis block executed — vault funded and allocations distributed", nodeID)
				// Late joiners only ever install genesis through this path, so
				// without recording it here their TPS monitor permanently shows
				// 0 genesis transactions while the bootstrap node shows N.
				if tps := bc.GetTPSMonitor(); tps != nil {
					txCount := uint64(len(genesisBlock.Body.TxsList))
					for i := uint64(0); i < txCount; i++ {
						tps.RecordTransaction()
					}
					tps.RecordBlock(txCount, 5*time.Second)
				}
				// Keep the persisted TPS tracker in lock-step with the live
				// monitor. Late joiners bypass createGenesisBlock(), which is
				// normally where storage records block 0; omitting it leaves
				// transactions_per_block without genesis and a max of zero.
				if store := bc.GetStorage(); store != nil {
					metrics := store.GetTPSMetrics()
					hasGenesis := false
					for _, entry := range metrics.TransactionsPerBlock {
						if entry.BlockHeight == 0 && entry.BlockHash == genesisBlock.GetHash() {
							hasGenesis = true
							break
						}
					}
					if !hasGenesis {
						for range genesisBlock.Body.TxsList {
							store.RecordTransaction()
						}
						store.RecordBlock(genesisBlock, 5*time.Second)
					}
				}
			}
			// ════════════════════════════════════════════════════════════════════

			// ★ FIX: After replacing genesis with the peer's canonical version,
			// clear any locally-mined blocks (block 1+) that reference the old
			// genesis. Without this, the sync loop tries to download block 2+
			// from the peer but the parent hash of block 2 doesn't match this
			// node's locally-mined block 1 — causing a permanent "parent hash
			// mismatch" stall. Clearing the chain ensures all blocks are
			// re-downloaded from scratch from the peer's genesis.
			bc.ClearChainAfter(0)

			// Write genesis_state.json from the downloaded genesis block
			if err := bc.WriteGenesisStateFromBlock(genesisBlock); err != nil {
				logger.Warn("[%s] Failed to write genesis state file: %v", nodeID, err)
			} else {
				logger.Info("[%s] Genesis state file written after syncing genesis", nodeID)
			}

			// ════════════════════════════════════════════════════════════════════
			// ★ FIX 2: Reset VDF parameters and RANDAO after genesis replacement
			// ════════════════════════════════════════════════════════════════════
			if cons != nil {
				// Reload VDF parameters from the new genesis hash.
				// (You need to implement LoadCanonicalVDFParamsFromHash or modify
				// the existing loader to accept a hash. For simplicity, we call
				// LoadCanonicalVDFParams which uses the global genesis hash
				// provider. Since we just replaced the genesis block, ensure that
				// the provider returns the new hash. Alternatively, you can pass
				// the hash directly. Here we assume the provider is updated.)
				newVDFParams, err := consensus.LoadCanonicalVDFParams()
				if err != nil {
					logger.Error("[%s] Failed to load VDF params for new genesis: %v", nodeID, err)
				} else {
					if err := consensus.SetCanonicalVDFParameters(&newVDFParams); err != nil {
						logger.Warn("[%s] Failed to set canonical VDF params: %v", nodeID, err)
					}
				}
				// Reset the RANDAO instance inside the consensus engine.
				if err := cons.ResetRANDAO(genesisBlock); err != nil {
					logger.Error("[%s] Failed to reset RANDAO after genesis sync: %v", nodeID, err)
				} else {
					logger.Info("[%s] RANDAO re-initialized with new genesis", nodeID)
				}
			}
			// ════════════════════════════════════════════════════════════════════

			consecutiveFailures = 0
			currentRetryInterval = baseRetryInterval
			continue
		}

		// ── Now we have genesis ──
		// ★ FIX: Verify our genesis hash matches the peer's. If not, the peer
		// is on a different chain (different genesis timestamp → different hash).
		// Fetch the peer's genesis and replace ours, then clear locally-mined
		// blocks so the chain is consistent.
		if hasGenesis && bestPeerAddr != "" {
			peerGenesisResp, err := requestBlocksFromPeer(bestPeerAddr, 0, 0)
			if err == nil && len(peerGenesisResp.Blocks) > 0 {
				peerGenesis := peerGenesisResp.Blocks[0]
				localGenesis := bc.GetBlockByNumber(0)
				if localGenesis != nil && peerGenesis != nil && localGenesis.GetHash() != peerGenesis.GetHash() {
					// ★ GUARD (second call site): the "local differs from
					// peer" branch is where a hostile peer most obviously
					// wants to win. The local genesis is the anchor; a peer
					// that does not match it is refused and scored, and this
					// node keeps its own chain instead of clearing it.
					if guardErr := core.VerifyPeerGenesis(peerGenesis, localGenesis); guardErr != nil {
						logger.Error("[%s] REFUSED divergent genesis from peer %s: %v — keeping local genesis, local=%s peer=%s",
							nodeID, bestPeerAddr, guardErr,
							localGenesis.GetHash(), peerGenesis.GetHash())
						peerFailureCount[bestPeerAddr]++
						consecutiveFailures++
					} else {
						logger.Info("[%s] Local genesis hash differs from peer %s — replacing genesis and clearing chain", nodeID, bestPeerAddr)
						if err := bc.ReplaceGenesis(peerGenesis); err != nil {
							logger.Warn("[%s] Failed to replace genesis: %v", nodeID, err)
						} else {
							bc.ClearChainAfter(0)
							logger.Info("[%s] Genesis replaced with peer's version — re-downloading chain from scratch", nodeID)
							// Same fix as the initial-install site above: a
							// replaced genesis is unexecuted genesis. Fund the
							// vault and apply the embedded distribution txs now,
							// or every allocation stays at zero balance again.
							if err := bc.ExecuteGenesisBlock(); err != nil {
								logger.Error("[%s] Failed to execute replaced genesis block: %v", nodeID, err)
							} else {
								logger.Info("[%s] Replaced genesis block executed — vault funded and allocations distributed", nodeID)
								if tps := bc.GetTPSMonitor(); tps != nil {
									txCount := uint64(len(peerGenesis.Body.TxsList))
									for i := uint64(0); i < txCount; i++ {
										tps.RecordTransaction()
									}
									tps.RecordBlock(txCount, 5*time.Second)
								}
							}
							// Reset local height so we re-download from block 1
							localHeight = 0
							hasGenesis = true
						}
					}
				}
			}
		}

		if networkTip == 0 {
			syncStateMu.Lock()
			if hasGenesis && *syncState == SyncStateSyncing {
				*syncState = SyncStateCaughtUp
				logger.Info("[%s] Local genesis is available and no peer tip is ahead — transitioning to CAUGHT_UP", nodeID)
				if syncStarted {
					syncStarted = false
				}
			}
			syncStateMu.Unlock()
			observeSync(networkTip, reachablePeers) // [observational] post-transition state
			// Keep retrying even if genesis has not arrived yet. A missing genesis
			// document is not evidence that this node is synchronized.
			logger.Info("[%s] Entering periodic sync check mode — will re-check every 10s", nodeID)
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
				continue
			}
		}

		if localHeight >= networkTip {
			// ★ FIX: Mark CAUGHT_UP on first pass, then enter periodic check.
			// After reaching network tip, don't exit — keep monitoring for new
			// blocks. This allows a node to stay synchronized without restarting.
			syncStateMu.Lock()
			if *syncState == SyncStateSyncing {
				*syncState = SyncStateCaughtUp
				logger.Info("[%s] Caught up at height %d (network tip %d) — entering periodic sync check",
					nodeID, localHeight, networkTip)
				if syncStarted {
					syncStarted = false
				}
			}
			syncStateMu.Unlock()
			observeSync(networkTip, reachablePeers) // [observational] post-transition state
			// Stay in loop, re-check periodically for new blocks
			logger.Info("[%s] Monitoring for new blocks — will re-check every 10s", nodeID)
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
				continue
			}
		}

		// ── START SYNCING ──
		// If we are behind, start the sync progress bar if not already started
		syncTargetHeight = int64(networkTip)
		if !syncStarted {
			totalBlocksToSync = int64(networkTip - localHeight)
			progress.StartBlockSync(syncTargetHeight)
			syncStarted = true
			logger.Info("[%s] Started block sync: %d blocks behind", nodeID, totalBlocksToSync)
		}

		fromHeight := localHeight + 1
		toHeight := networkTip
		if toHeight-fromHeight+1 > maxBatchSize {
			toHeight = fromHeight + maxBatchSize - 1
		}

		logger.Info("[%s] Syncing blocks %d -> %d from %s (local=%d, network=%d)",
			nodeID, fromHeight, toHeight, bestPeerAddr, localHeight, networkTip)

		resp, err := requestBlocksFromPeer(bestPeerAddr, fromHeight, toHeight)
		if err != nil {
			logger.Warn("[%s] Failed to request blocks from %s: %v", nodeID, bestPeerAddr, err)
			peerFailureCount[bestPeerAddr]++
			consecutiveFailures++
			currentRetryInterval = time.Duration(float64(currentRetryInterval) * backoffMultiplier)
			if currentRetryInterval > maxRetryInterval {
				currentRetryInterval = maxRetryInterval
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(currentRetryInterval):
			}
			continue
		}

		if len(resp.Blocks) == 0 {
			logger.Warn("[%s] Peer %s returned 0 blocks for range %d-%d", nodeID, bestPeerAddr, fromHeight, toHeight)
			peerFailureCount[bestPeerAddr]++
			consecutiveFailures++
			currentRetryInterval = time.Duration(float64(currentRetryInterval) * backoffMultiplier)
			if currentRetryInterval > maxRetryInterval {
				currentRetryInterval = maxRetryInterval
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(currentRetryInterval):
			}
			continue
		}

		consecutiveFailures = 0
		currentRetryInterval = baseRetryInterval
		peerFailureCount[bestPeerAddr] = 0

		applied := 0
		for _, blk := range resp.Blocks {
			if blk == nil {
				continue
			}
			currentTip := bc.GetLatestBlock()
			if currentTip != nil && blk.GetPrevHash() != currentTip.GetHash() {
				logger.Warn("[%s] Block %d parent hash mismatch: expected %s, got %s — stopping batch",
					nodeID, blk.GetHeight(), currentTip.GetHash()[:16], blk.GetPrevHash()[:16])
				break
			}
			if currentTip != nil && blk.GetHeight() != currentTip.GetHeight()+1 {
				logger.Warn("[%s] Block %d is not contiguous (tip=%d) — stopping batch",
					nodeID, blk.GetHeight(), currentTip.GetHeight())
				break
			}
			if cons != nil && blk.GetHeight() > 0 {
				// ── Authority check ──────────────────────────────────────────
				// ★ NO "solo-mined" SKIP ANYMORE. The old code read an empty
				// attestation list as permission to skip verification, which
				// let a peer hand this node an arbitrary chain of unattested
				// blocks whose only property was that parent hashes linked.
				// VerifyBlockAuthority decides from the snapshot that governs
				// the height: a quorum certificate when the block has one, and
				// otherwise a verified proposer signature, and only while the
				// governing snapshot has a single member. The key comes from
				// replayed chain state and the verifier is the shared
				// consensus primitive, so this is cryptographic even with no
				// handshake history.
				if err := core.VerifyBlockAuthority(blk,
					core.NewChainStateKeyResolver(bc),
					core.NewConsensusAttestationVerifier(),
					core.NewConsensusBlockProposerSignatureVerifier()); err != nil {
					logger.Error("[%s] Block %d failed authority verification: %v — rejecting batch from peer %s",
						nodeID, blk.GetHeight(), err, bestPeerAddr)
					applied = 0
					break
				}
			}
			wrapped := core.NewBlockHelper(blk)
			commitErr := bc.CommitBlock(wrapped)
			if commitErr != nil {
				// ── STATE DIVERGENCE RECOVERY ──
				// CommitBlock refuses to commit when the locally executed state
				// root differs from the block header's claimed state root. This
				// means the local state has diverged from the network — the only
				// safe remedy is to wipe everything and resync from genesis.
				if strings.Contains(commitErr.Error(), "state root mismatch") {
					if resyncAttempts >= maxResyncAttempts {
						logger.Error("[%s] State divergence at block %d but max resync attempts (%d) exhausted — giving up",
							nodeID, blk.GetHeight(), maxResyncAttempts)
						break
					}
					resyncAttempts++
					logger.Warn("[%s] STATE DIVERGENCE at block %d — wiping chain and resyncing from genesis (attempt %d/%d)",
						nodeID, blk.GetHeight(), resyncAttempts, maxResyncAttempts)

					// Wipe all blockchain state (account records, supply counters,
					// validator stakes, stored blocks, in-memory chain).
					if resetErr := bc.ResetForResync(); resetErr != nil {
						logger.Error("[%s] ResetForResync failed: %v — giving up", nodeID, resetErr)
						break
					}

					// Reset sync state so we re-download genesis and the full chain.
					localHeight = 0
					hasGenesis = false
					syncStateMu.Lock()
					*syncState = SyncStateSyncing
					syncStateMu.Unlock()
					applied = 0

					// Clear the progress bar so it restarts cleanly.
					if syncStarted {
						syncStarted = false
					}

					logger.Info("[%s] State wiped — will re-download genesis from peers", nodeID)
					// Break out of the block loop; the outer loop will re-fetch
					// genesis and start over.
					break
				}

				logger.Error("[%s] Failed to commit synced block %d: %v", nodeID, blk.GetHeight(), commitErr)
				break
			}
			applied++
			// Update progress after each block (or batch)
			if syncStarted {
				latestLocal := bc.GetLatestBlock()
				if latestLocal != nil {
					progress.UpdateBlockSync(int64(latestLocal.GetHeight()), syncTargetHeight)
				}
			}
		}

		if applied > 0 {
			newLocal := bc.GetLatestBlock()
			if newLocal != nil {
				logger.Info("[%s] Applied %d/%d synced blocks (now at height %d)",
					nodeID, applied, len(resp.Blocks), newLocal.GetHeight())
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// ============================================================================
// Block production loop
// ============================================================================

// runBlockProductionLoop runs continuous block production with PBFT consensus.
//
// It checks the syncState before entering the PBFT loop. A node in SYNCING
// state will NOT participate in PBFT rounds (no voting, no proposing). It
// will wait until the sync loop transitions it to CAUGHT_UP, then transition
// itself to CONSENSUS_PARTICIPANT and begin full PBFT participation.
func runBlockProductionLoop(
	ctx context.Context,
	bc *core.Blockchain,
	cons *consensus.Consensus,
	nodeID string,
	networkType string,
	validatorReadyCountFunc func() int,
	// readyStakeFunc returns the stake of validators that are both in the
	// ACTIVE staked set and READY, plus the total active stake. The readiness
	// GATE uses this (strictly > 2/3 of stake), not validatorReadyCountFunc,
	// which is retained only for the dashboard's "active/total" display.
	readyStakeFunc func() (ready, total *big.Int),
	syncState *SyncState,
	syncStateMu *sync.Mutex,
	progress *logger.BlockchainProgress, // NEW
) {
	// Set initial consensus status: PAUSED while syncing
	progress.SetConsensusStatus("PAUSED — synchronizing")

	const (
		singleNodeInterval  = 10 * time.Second
		multiNodeRoundDelay = 3 * time.Second
	)

	// effectiveValidatorCount reports how many validators can take part in
	// PBFT right now: validators in the ACTIVE STAKED set (chain state) that
	// are also READY (probe-settled), plus self when staked. It never clamps
	// to a configured node count — there is no such count any more — and it
	// never counts raw peers: an unstaked peer is connectivity only and does
	// not appear here, in quorum math, or in leader rotation.
	effectiveValidatorCount := func() int {
		if validatorReadyCountFunc != nil {
			return validatorReadyCountFunc()
		}
		return 0
	}

	// stakedSetSize is the size of the active staked validator set from chain
	// state. It is used only to bound the solo-mode check and the dashboard
	// denominator — never to gate PBFT by a configured count.
	stakedSetSize := func() int {
		if cons == nil {
			return 0
		}
		vs := cons.GetValidatorSet()
		if vs == nil {
			return 0
		}
		return len(vs.ActiveValidatorIDs(0))
	}
	isSoleLocalValidator := func() bool {
		if cons == nil {
			return false
		}
		vs := cons.GetValidatorSet()
		if vs == nil {
			return false
		}
		active := vs.ActiveValidatorIDs(0)
		return len(active) == 1 && active[0] == nodeID
	}

	// readyStakeHoldsQuorum is the readiness gate: STRICTLY more than 2/3 of the
	// active snapshot's stake must be ready (ready*3 > total*2) — the same
	// arithmetic a block commit uses. No node COUNT appears anywhere in it.
	//
	// readyStakeFunc is supplied by the caller because the peer-readiness
	// bookkeeping (peerRegistry / registeredPeers / peerReadySince) lives in
	// StartNodeWithOptions, not here. Keeping the ARITHMETIC here and the
	// READINESS INPUT outside means the gate itself has no access to peer or
	// node counts at all.
	readyStakeHoldsQuorum := func() (bool, *big.Int, *big.Int) {
		if readyStakeFunc == nil {
			return false, big.NewInt(0), big.NewInt(0)
		}
		ready, total := readyStakeFunc()
		if ready == nil {
			ready = big.NewInt(0)
		}
		if total == nil || total.Sign() <= 0 {
			return false, ready, big.NewInt(0)
		}
		lhs := new(big.Int).Mul(new(big.Int).Set(ready), big.NewInt(3))
		rhs := new(big.Int).Mul(new(big.Int).Set(total), big.NewInt(2))
		return lhs.Cmp(rhs) > 0, ready, total
	}

	// toSPX renders nSPX for the human-readable wait message.
	toSPX := func(n *big.Int) string {
		if n == nil {
			return "0"
		}
		return new(big.Float).Quo(new(big.Float).SetInt(n), new(big.Float).SetInt64(1e18)).Text('f', 2)
	}

	// ──────────────────────────────────────────────────────────────────────
	// SYNC STATE GATE: A node in SYNCING state must NOT participate in PBFT.
	// ──────────────────────────────────────────────────────────────────────
	// ★ FIX: this loop polls the sync state every 3s for as long as the node
	// is catching up — including the very common "the peers I was configured
	// with are not up yet" case, which can last minutes. It used to print its
	// INFO heartbeat on every poll (~20 identical lines a minute), which
	// buried the single actionable line produced by the block sync loop
	// ("No peers reachable — tried N (...)") and made a healthy, waiting node
	// look like it was spinning. The per-node limiter keeps the first line
	// plus one per peerWaitLogInterval ("(+N suppressed)" shows how many
	// polls were folded in); every poll still leaves a Debug line, and the
	// dashboard's consensus status ("PAUSED — synchronizing", set above) is
	// the live indicator.
	syncWaitLog := logger.Limited("bind:sync-wait:"+nodeID, peerWaitLogInterval)
	for {
		syncStateMu.Lock()
		currentSyncState := *syncState
		syncStateMu.Unlock()

		if currentSyncState == SyncStateSyncing {
			syncWaitLog.Info("[%s] Sync in progress — waiting to catch up before joining PBFT (state=%s)",
				nodeID, currentSyncState.String())
			logger.Debug("[%s] Sync in progress — waiting to catch up before joining PBFT (state=%s)",
				nodeID, currentSyncState.String())
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			continue
		}

		if currentSyncState == SyncStateCaughtUp {
			// Transition to full consensus participation
			syncStateMu.Lock()
			*syncState = SyncStateConsensusParticipant
			syncStateMu.Unlock()
			if cons != nil {
				cons.SetSyncReady(true)
				logger.Info("[%s] Sync gate opened — node may now participate in PBFT", nodeID)
				// Update consensus status to ACTIVE
				progress.SetConsensusStatus("ACTIVE — validating")
			}
			logger.Info("[%s] Transitioning to CONSENSUS_PARTICIPANT — joining PBFT rounds", nodeID)
			break
		}

		// CONSENSUS_PARTICIPANT — proceed to PBFT
		break
	}

	// ── SOLO MODE (policy decision remains open) ──
	// This mode is now selected from active chain membership only. Connectivity
	// and startup flags do not determine whether this node produces solo blocks.
	// Phase 1 preserves the existing single-validator path pending an operator
	// decision on whether standalone solo production should exist at all.
	if isSoleLocalValidator() {
		logger.Info("[%s] SOLO MODE — this node is the sole active validator", nodeID)
		progress.SetConsensusStatus("ACTIVE — solo mining")

		blockTicker := time.NewTicker(singleNodeInterval)
		defer blockTicker.Stop()
		peerCheckTicker := time.NewTicker(5 * time.Second)
		defer peerCheckTicker.Stop()

		// ★ FATAL AFTER REPEATED INVARIANT FAILURES.
		//
		// A node whose epoch-0 snapshot is missing cannot ever produce block 1,
		// because CreateBlock fails closed on it. That used to log one ERROR
		// every 10 seconds forever: the process looked alive, the dashboard
		// showed no progress, and an operator had no signal that it would never
		// recover. Retrying cannot help — the precondition is structural, not
		// transient.
		//
		// Scoped deliberately to a NARROW error class. A node legitimately
		// waiting for peers, a leader, or a sync catch-up must keep retrying, so
		// ordinary CreateBlock errors are NOT fatal. Only a missing/inconsistent
		// validator snapshot is treated as an invariant violation, because
		// nothing this loop can do will ever change that answer.
		var (
			lastInvariantErr string
			invariantRepeats int
		)

		for {
			select {
			case <-ctx.Done():
				return

			case <-blockTicker.C:
				blk, err := bc.CreateBlock()
				if err != nil {
					// Is this the structural class (never recoverable), or an
					// ordinary transient/expected error (keep retrying)?
					msg := err.Error()
					switch {
					case strings.Contains(msg, "validator snapshot for height") &&
						strings.Contains(msg, "is unavailable"):
						if msg == lastInvariantErr {
							invariantRepeats++
						} else {
							lastInvariantErr = msg
							invariantRepeats = 1
						}
						if invariantRepeats >= 3 {
							logger.Error("[%s] FATAL: block production failed %d consecutive times with an unrecoverable invariant violation: %v",
								nodeID, invariantRepeats, err)
							logger.Error("[%s] The epoch-0 validator snapshot is missing or does not match genesis. "+
								"This node CANNOT produce block %d and never will without intervention. Stopping instead of logging the same error forever.",
								nodeID, 1)
							if progress != nil {
								progress.SetConsensusStatus("FATAL — missing validator snapshot")
							}
							os.Exit(1)
						}
						logger.Error("[%s] solo mine error (invariant violation %d/3): %v",
							nodeID, invariantRepeats, err)
						continue
					default:
						// Transient or expected (waiting on peers, a leader, a
						// sync, a full mempool): reset the invariant counter and
						// keep retrying, exactly as before.
						lastInvariantErr = ""
						invariantRepeats = 0
						logger.Error("[%s] solo mine error: %v", nodeID, err)
						continue
					}
				}
				lastInvariantErr = ""
				invariantRepeats = 0
				wrapped := core.NewBlockHelper(blk)
				if err := bc.CommitBlock(wrapped); err != nil {
					logger.Error("[%s] solo commit error: %v", nodeID, err)
					continue
				}
				pending := bc.GetMempool().GetPendingTransactions()
				logger.Info("[%s] Solo-mined and committed block height=%d txs=%d", nodeID, blk.GetHeight(), len(pending))

				// NEW: keep the dashboard's Height/Sync fields in sync with reality —
				// this is the only place a solo-mining node's tip advances, and the
				// peer-sync path (StartBlockSync/UpdateBlockSync) never runs when
				// there are no peers, so without this the UI stays frozen at 0/0
				// forever even as blocks are actually being produced.
				progress.UpdateBlockSync(int64(blk.GetHeight()), int64(blk.GetHeight()))

				progress.UpdateMempoolActivity(len(pending), 0)

			case <-peerCheckTicker.C:
				// Solo→PBFT handoff uses the SAME stake-weighted gate as the
				// readiness check below: handing off while only part of the
				// stake is ready would re-introduce the silent >2/3-stake stall
				// that gate exists to prevent.
				//
				// ★ Note this is deliberately NOT "ready*3 > total*2" alone:
				// this node alone already satisfies that (it holds 100% of a
				// 1-validator set), so the handoff additionally requires the
				// active set to have actually GROWN past just this node.
				// Otherwise a solo node would hand off to PBFT on its own,
				// which is the same chain in a worse shape.
				handoffOK, hReady, hTotal := readyStakeHoldsQuorum()
				if handoffOK && stakedSetSize() > 1 {
					logger.Info("[%s] validators holding %s / %s SPX (> 2/3 of the active stake) are ready — initiating solo-to-PBFT handoff", nodeID, toSPX(hReady), toSPX(hTotal))
					soloTip := bc.GetLatestBlock()
					soloHeight := uint64(0)
					if soloTip != nil {
						soloHeight = soloTip.GetHeight()
					}
					logger.Info("[%s] Solo-mined tip at height %d (hash=%s) — preparing to align with peers",
						nodeID, soloHeight, soloTip.GetHash()[:16])

					syncTimeout := time.After(60 * time.Second)
					synced := false
					for !synced {
						select {
						case <-ctx.Done():
							return
						case <-syncTimeout:
							logger.Warn("[%s] Timed out waiting to sync before PBFT transition — proceeding anyway", nodeID)
							synced = true
						default:
							syncStateMu.Lock()
							currentSyncState := *syncState
							syncStateMu.Unlock()

							localTip := bc.GetLatestBlock()
							localHeight := uint64(0)
							if localTip != nil {
								localHeight = localTip.GetHeight()
							}

							// ★ FIX: was `currentSyncState == SyncStateCaughtUp`. By the
							// time SOLO MODE detects peers and reaches this handoff, the
							// SYNC STATE GATE at the top of this function has *already*
							// advanced *syncState from SyncStateCaughtUp to
							// SyncStateConsensusParticipant (it does that immediately at
							// startup for a bootstrap node, before any peers exist) — so
							// an exact match against CaughtUp can never be true again.
							// This loop then always burned the full 60s syncTimeout
							// before updating the dashboard, even though the real
							// consensus engine (driven independently via the message
							// handlers registered in consensusRegistry) kept proposing,
							// voting, and committing blocks the entire time — the chain
							// itself was fine, only the dashboard/status were stuck.
							// Checking "not still syncing" covers both states the gate
							// may have left us in and matches the comment's actual
							// intent: don't proceed while SyncStateSyncing.
							if currentSyncState != SyncStateSyncing {
								logger.Info("[%s] Sync state is %s (not syncing, local height=%d) — now switching to PBFT",
									nodeID, currentSyncState.String(), localHeight)
								synced = true
							} else {
								time.Sleep(1 * time.Second)
							}
						}
					}
					postSyncTip := bc.GetLatestBlock()
					if postSyncTip != nil {
						postSyncHeight := postSyncTip.GetHeight()
						logger.Info("[%s] Post-sync tip at height %d (hash=%s) — entering PBFT aligned with peers",
							nodeID, postSyncHeight, postSyncTip.GetHash()[:16])
					}
					// Update consensus status after handoff
					progress.SetConsensusStatus("ACTIVE — validating")
					goto afterSolo
				}
			}
		}
	afterSolo:
		// continue to PBFT setup below
	}

	// ── PBFT READINESS GATE ──
	// The ONE condition is the protocol's own: strictly more than 2/3 of the
	// ACTIVE snapshot's stake must be ready (ready*3 > total*2). There is no
	// node count here, and no reference to consensus.MinValidators.
	//
	// ★ WHY THE OLD COUNT GATE WAS WRONG. It waited for
	// consensus.MinValidators (3) staked+ready validators. A node that authored
	// its own genesis is a legitimate 1-validator chain: its single validator
	// holds 100% of the stake, so it clears >2/3 immediately and commits its
	// own blocks. Requiring 3 made a self-authored network unable to leave
	// SOLO MODE at all — it would wait forever for two peers that had no reason
	// to exist yet.
	if ok, ready, total := readyStakeHoldsQuorum(); !ok {
		logger.Warn("[%s] Block-production suspended: validators holding > 2/3 of the active stake must be ready (have %s / %s SPX) — waiting for validators to become reachable",
			nodeID, toSPX(ready), toSPX(total))
		progress.SetConsensusStatus("PAUSED — insufficient validators")
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		validatorWaitLog := logger.Limited("bind:validator-wait:"+nodeID, peerWaitLogInterval)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Only validators that are BOTH in the active staked set AND
				// ready (genesis installed + probe-settled) contribute. Unstaked
				// peers never appear here.
				if ok, ready, total := readyStakeHoldsQuorum(); ok {
					logger.Info("[%s] Validators holding %s / %s SPX (> 2/3 of the active stake) are ready — starting PBFT block production",
						nodeID, toSPX(ready), toSPX(total))
					progress.SetConsensusStatus("ACTIVE — validating")
					goto startPBFT
				}
				validatorWaitLog.Info("[%s] Waiting for validators holding > 2/3 of the active stake to be ready (%s / %s SPX)…",
					nodeID, toSPX(ready), toSPX(total))
			}
		}
	}

startPBFT:

	logger.Info("[%s] Waiting for P2P broadcast layer to stabilize before PBFT...", nodeID)

	broadcastReadyTimeout := time.After(30 * time.Second)
	broadcastReady := false

	for !broadcastReady {
		select {
		case <-ctx.Done():
			return
		case <-broadcastReadyTimeout:
			logger.Warn("[%s] Broadcast layer stabilization timeout (30s) — proceeding to PBFT", nodeID)
			broadcastReady = true
		default:
			syncStateMu.Lock()
			currentSync := *syncState
			syncStateMu.Unlock()

			if currentSync != SyncStateSyncing {
				logger.Info("[%s] Sync complete — P2P layer ready (syncState=%s)", nodeID, currentSync.String())
				broadcastReady = true
				continue
			}

			// While syncing, a node that is already ready for more than 2/3 of
			// the stake polls faster, because it is about to be able to
			// propose. Same stake-weighted condition, no node count.
			if ok, _, _ := readyStakeHoldsQuorum(); ok {
				time.Sleep(500 * time.Millisecond)
				continue
			}

			time.Sleep(1 * time.Second)
		}
	}

	var currentHeight uint64 = 0
	latestBlock := bc.GetLatestBlock()
	if latestBlock != nil {
		currentHeight = latestBlock.GetHeight()
	}

	// ★ FIX: PBFT rounds can begin now. Restart the view-change clock so time
	// spent waiting for peers to boot isn't counted against the first round.
	cons.MarkRoundStart()

	logger.Info("[%s] Starting PBFT consensus. Current height: %d", nodeID, currentHeight)

	// ★ FIX: seed the dashboard with the real height right away. The loop
	// below only calls progress.UpdateBlockSync when chainHeight differs
	// from currentHeight — but currentHeight was just set FROM the real
	// chain a few lines up, so the very first iteration always sees "no
	// change" and skips the update. That's harmless for a node starting
	// fresh at height 0, but for a node arriving here after the solo→PBFT
	// handoff (where the real chain may have already advanced past the
	// dashboard's last solo-mining update via the independent
	// consensus-message path) it left the dashboard permanently frozen at
	// the stale pre-handoff height until the next block changed it.
	progress.UpdateBlockSync(int64(currentHeight), int64(currentHeight))

	// The dashboard denominator is the active staked set (chain state), never
	// a configured network size — "ready" is the staked+ready count.
	progress.UpdateValidatorStatus(effectiveValidatorCount(), stakedSetSize())

	const roundStallObservationInterval = 15 * time.Second
	var (
		stallHeight uint64
		stallView   uint64
		stallLeader string
		stallSince  time.Time
	)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		latestBlock = bc.GetLatestBlock()
		if latestBlock != nil {
			chainHeight := latestBlock.GetHeight()
			if chainHeight != currentHeight {
				currentHeight = chainHeight
				cons.SetCurrentHeight(currentHeight)
				logger.Debug("[%s] Chain height synced to %d", nodeID, currentHeight)
				stallHeight, stallView, stallLeader = 0, 0, ""

				// NEW: mirror the solo-mining dashboard update here. Blocks a
				// follower learns about between its own leader rounds are
				// detected here; without this the dashboard froze at whatever
				// height it last held while this node was only following.
				progress.UpdateBlockSync(int64(currentHeight), int64(currentHeight))
			}

		}

		// Update mempool and validator counts periodically
		if bc.GetMempool() != nil {
			pending := bc.GetMempool().GetPendingTransactions()
			// Estimate TPS: we don't have a real TPS counter, just pass 0 or compute from block times
			progress.UpdateMempoolActivity(len(pending), 0)
		}
		progress.UpdateValidatorStatus(effectiveValidatorCount(), stakedSetSize())

		proposalView, electedLeader, isLeader := cons.RefreshLeaderStatus()
		if electedLeader == "" {
			logger.Warn("[%s] No elected leader found, forcing re-election...", nodeID)
			time.Sleep(200 * time.Millisecond)
			proposalView, electedLeader, isLeader = cons.RefreshLeaderStatus()
			if electedLeader == "" {
				logger.Warn("[%s] Still no elected leader, waiting...", nodeID)
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
				continue
			}
		}

		// Update consensus round info (if available)
		if cons != nil {
			// We don't have explicit round/totalRounds/quorum/totalValidators from the engine,
			// but we can pass current view as round, and some defaults.
			// For now, just pass 0 values to avoid breaking the UI; the status line will show
			// "Consensus    ACTIVE — validating" which is sufficient.
			// Alternatively, we could extract from the engine if it exposes these.
			// We'll keep it simple.
		}

		if stallHeight != currentHeight || stallView != proposalView || stallLeader != electedLeader {
			stallHeight, stallView, stallLeader = currentHeight, proposalView, electedLeader
			stallSince = time.Now()
		} else if time.Since(stallSince) > roundStallObservationInterval {
			// View changes are owned by Consensus.consensusLoop, which knows
			// whether a proposal is being verified or votes are in flight. This
			// loop used to force one after 15 seconds without that context,
			// racing normal localhost storage/signature work and causing needless
			// leader rotations. Record the observation and let the single,
			// activity-aware PBFT watchdog decide whether recovery is required.
			logger.Debug("[%s] No height change for %v at height=%d view=%d (leader=%s); waiting for consensus watchdog",
				nodeID, roundStallObservationInterval, currentHeight, proposalView, electedLeader)
			stallSince = time.Now()
		}

		if !isLeader {
			logger.Debug("[%s] FOLLOWER MODE — waiting for leader proposal (height=%d, electedLeader=%s)",
				nodeID, currentHeight, electedLeader)
			select {
			case <-ctx.Done():
				return
			case <-time.After(multiNodeRoundDelay):
			}
			continue
		}
		if electedLeader != nodeID {
			logger.Warn("[%s] Fresh election mismatch: electedLeader=%s, local node=%s, skipping proposal for view %d",
				nodeID, electedLeader, nodeID, proposalView)
			select {
			case <-ctx.Done():
				return
			case <-time.After(multiNodeRoundDelay):
			}
			continue
		}

		currentHeightCheck := bc.GetLatestBlock().GetHeight()
		if currentHeightCheck != currentHeight {
			logger.Info("[%s] Chain height changed from %d to %d, skipping proposal",
				nodeID, currentHeight, currentHeightCheck)
			currentHeight = currentHeightCheck
			cons.SetCurrentHeight(currentHeight)
			continue
		}

		logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logger.Info("[%s] LEADER MODE ACTIVE — proposing block for height %d", nodeID, currentHeight+1)
		logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		pending := bc.GetMempool().GetPendingTransactions()
		if len(pending) == 0 {
			logger.Info("[%s] Leader — mempool empty, creating empty block", nodeID)
		}

		newBlock, err := bc.CreateBlock()
		if err != nil {
			logger.Error("[%s] CreateBlock failed: %v", nodeID, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(multiNodeRoundDelay):
			}
			continue
		}

		logger.Info("[%s] Created block height=%d txs=%d", nodeID, newBlock.GetHeight(), len(pending))

		consensusVM := vmachine.NewVM([]byte{byte(svm.PUSH1), 0x01})
		if err := consensusVM.Run(); err != nil {
			logger.Error("[%s] Consensus VM error: %v", nodeID, err)
			continue
		}
		result, err := consensusVM.GetResult()
		if err != nil || result != 1 {
			logger.Error("[%s] Block failed consensus VM rules", nodeID)
			continue
		}
		logger.Info("[%s] VM: Consensus verification passed", nodeID)

		wrapped := core.NewBlockHelper(newBlock)

		signingService := cons.GetSigningService()
		// ★ FIX: bc.CreateBlock() already signs the header (executor.go,
		// cs.SignBlockHeader) — the same SignBlock call, over the same hash.
		// Signing again here cost a second ~5s SPHINCS+ signature on every
		// proposal, on the critical path before the proposal is even
		// broadcast. Only sign if CreateBlock could not.
		if signingService != nil && len(newBlock.Header.ProposerSignature) == 0 {
			if err := signingService.SignBlock(wrapped); err != nil {
				logger.Error("[%s] Failed to sign block header: %v", nodeID, err)
				continue
			}
			logger.Info("[%s] Block header signed", nodeID)
		} else if signingService != nil {
			logger.Debug("[%s] Block header already signed by CreateBlock — skipping duplicate signature", nodeID)
		}

		proposalSlot := proposalView
		logger.Info("[%s] Using view %d as proposal slot for block proposal", nodeID, proposalSlot)

		var concreteBlock interface{}
		if getter, ok := wrapped.(interface{ GetUnderlyingBlock() interface{} }); ok {
			concreteBlock = getter.GetUnderlyingBlock()
		} else {
			concreteBlock = newBlock
		}

		blockData, err := json.Marshal(concreteBlock)
		if err != nil {
			logger.Error("[%s] Failed to serialize block: %v", nodeID, err)
			continue
		}

		proposal := &consensus.Proposal{
			BlockData:       blockData,
			View:            proposalView,
			ProposerID:      nodeID,
			Signature:       []byte{},
			ElectedLeaderID: electedLeader,
			SlotNumber:      proposalSlot,
			Block:           wrapped,
		}

		if signingService != nil {
			if err := signingService.SignProposal(proposal); err != nil {
				logger.Error("[%s] Failed to sign proposal: %v", nodeID, err)
				continue
			}
		}

		cons.HandleProposal(proposal)
		time.Sleep(100 * time.Millisecond)

		if err := cons.BroadcastProposal(proposal); err != nil {
			logger.Error("[%s] BroadcastProposal failed: %v", nodeID, err)
			continue
		}

		logger.Info("[%s] Block proposed and broadcast, waiting for consensus...", nodeID)

		// Wait for this round to commit. The budget must exceed the cost of a
		// full round of SPHINCS+ signatures (block header + proposal + prepare
		// + commit, roughly 4×5s plus verification and network margin) or the
		// leader gives up mid-round and the round is thrown away.
		commitTimeout := time.After(90 * time.Second)
		commitTicker := time.NewTicker(1 * time.Second)

		committed := false
		for !committed {
			select {
			case <-ctx.Done():
				commitTicker.Stop()
				return
			case <-commitTimeout:
				// Advance the view. Re-proposing under the same view re-elects
				// the same leader and reproduces the same non-committing round
				// forever (the observed height-13 stall). Bumping the view
				// changes the RANDAO seed, so the next round can elect a
				// different proposer and make progress.
				logger.Warn("[%s] Timeout waiting for block commitment at height %d — advancing view to re-elect a leader",
					nodeID, currentHeight+1)
				cons.StartViewChange()
				committed = true
			case <-commitTicker.C:
				latest := bc.GetLatestBlock()
				if latest != nil && latest.GetHeight() > currentHeight {
					currentHeight = latest.GetHeight()
					cons.SetCurrentHeight(currentHeight)

					if bc.GetTPSMonitor() != nil {
						stats := bc.GetTPSMonitor().GetStats()
						logger.Info("[%s] TPS STATS after block %d: blocks_processed=%v, total_txs=%v, avg_txs_per_block=%.2f",
							nodeID, currentHeight,
							stats["blocks_processed"],
							stats["total_transactions"],
							stats["avg_transactions_per_block"])
					}

					logger.Info("[%s] Block committed! Height now: %d", nodeID, currentHeight)

					// NEW: this ticker loop is a third, independent place
					// currentHeight advances — entirely separate from both the
					// solo-mining branch and the top-of-loop follower check
					// (both already patched). A node only hit this path while
					// it was LEADER; without this call, the dashboard froze
					// the moment a node started winning leader rounds, even
					// though it kept committing blocks correctly (confirmed by
					// "Block committed! Height now: 13" while the dashboard
					// still showed 6/6).
					progress.UpdateBlockSync(int64(currentHeight), int64(currentHeight))

					committed = true
				}
			}
		}
		commitTicker.Stop()

		if cpErr := bc.WriteChainCheckpoint(); cpErr != nil {
			logger.Warn("[%s] Failed to write chain checkpoint: %v", nodeID, cpErr)
		} else {
			phase := "devnet"
			if bc.IsDistributionComplete() {
				phase = "mainnet/testnet"
			}
			logger.Info("[%s] Checkpoint saved at height %d (phase: %s, network: %s)",
				nodeID, currentHeight, phase, networkType)
		}

		cons.UpdateLeaderStatus()
		electedLeader = cons.GetElectedLeaderID()
		if electedLeader == "" {
			logger.Warn("[%s] No leader elected after commit, will retry next loop", nodeID)
		} else {
			logger.Info("[%s] Next leader: %s (isLeader=%v)", nodeID, electedLeader, cons.IsLeader())
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(multiNodeRoundDelay):
		}
	}
}

// ============================================================================
// DEVNET-ONLY: per-node reward keys and the bootstrap faucet key.
//
// ★ WHY THIS IS HERE AND NOT IN core. Deriving a SPHINCS public key's SPIF
// address requires usi/core/key, and that package imports core — so a
// core -> usi/core/key edge is an import cycle. This host already imports both,
// so generate-or-load lives here and core keeps only the pure ledger.
//
// ★ WHAT IT BUYS. The main flow is three `node` commands and nothing else, so
// nobody is asked to supply a key or paste an address. Each node auto-generates
// ONE reward keypair in its own datadir on first start, and the node that
// authored genesis additionally generates the faucet key it pays joiners from.
//
// ★ LOAD-OR-CREATE, NEVER REPLACE. A restart must yield the SAME address: it
// is what peers verify a balance for and what block rewards accrue to. Minting
// a fresh key each start would strand the old balance.
//
// ★ DEVNET ONLY, FAIL-CLOSED. Every entry point is reached only behind
// core.DevnetAutoCustodyRequested(networkType).
// ============================================================================

// devnetKeyFile is the on-disk shape of a generated reward/faucet key. The
// private key is hex so the file is inspectable without a Go runtime.
type devnetKeyFile struct {
	Address    string `json:"address"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// LoadOrCreateDevnetRewardKey returns this node's own devnet reward key,
// generating and persisting one under the datadir on first use.
func LoadOrCreateDevnetRewardKey(datadir string) (address string, sk, pk []byte, err error) {
	return loadOrCreateDevnetKey(core.DevnetRewardKeyDir(datadir))
}

// LoadOrCreateDevnetFaucetKey is LoadOrCreateDevnetRewardKey for the bootstrap
// node's faucet. Only the node that authored genesis creates one.
func LoadOrCreateDevnetFaucetKey(datadir string) (address string, sk, pk []byte, err error) {
	return loadOrCreateDevnetKey(core.DevnetFaucetKeyDir(datadir))
}

// loadOrCreateDevnetKey is the shared load-or-create for both key kinds.
func loadOrCreateDevnetKey(dir string) (string, []byte, []byte, error) {
	if dir == "" {
		return "", nil, nil, fmt.Errorf("devnet key needs a datadir")
	}
	path := filepath.Join(dir, "key.json")

	// Existing key: load it, never replace.
	if data, readErr := os.ReadFile(path); readErr == nil {
		var rec devnetKeyFile
		if json.Unmarshal(data, &rec) == nil && rec.PublicKey != "" && rec.PrivateKey != "" {
			skBytes, derr := hex.DecodeString(strings.TrimPrefix(rec.PrivateKey, "0x"))
			if derr != nil {
				return "", nil, nil, fmt.Errorf("devnet key %s holds an unparseable private_key: %w", path, derr)
			}
			pkBytes, derr := hex.DecodeString(strings.TrimPrefix(rec.PublicKey, "0x"))
			if derr != nil {
				return "", nil, nil, fmt.Errorf("devnet key %s holds an unparseable public_key: %w", path, derr)
			}
			return rec.Address, skBytes, pkBytes, nil
		}
		// Present-but-unreadable is FATAL, never silently replaced: minting a
		// fresh key here would orphan a funded address.
		return "", nil, nil, fmt.Errorf("devnet key %s is present but unreadable — refusing to replace it (a new key would strand the existing balance)", path)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, nil, fmt.Errorf("create devnet key dir %s: %w", dir, err)
	}
	km, err := spxKey.NewKeyManager()
	if err != nil {
		return "", nil, nil, fmt.Errorf("devnet key manager: %w", err)
	}
	skKey, pkKey, err := km.GenerateKey()
	if err != nil {
		return "", nil, nil, fmt.Errorf("generate devnet key: %w", err)
	}
	skBytes, pkBytes, err := km.SerializeKeyPair(skKey, pkKey)
	if err != nil {
		return "", nil, nil, fmt.Errorf("serialize devnet key: %w", err)
	}
	addr, err := devnetAddressForPublicKey(pkBytes)
	if err != nil {
		return "", nil, nil, err
	}
	body, err := json.MarshalIndent(devnetKeyFile{
		Address:    addr,
		PrivateKey: hex.EncodeToString(skBytes),
		PublicKey:  hex.EncodeToString(pkBytes),
	}, "", "  ")
	if err != nil {
		return "", nil, nil, err
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		return "", nil, nil, fmt.Errorf("write %s: %w", path, err)
	}
	return addr, skBytes, pkBytes, nil
}

// devnetAddressForPublicKey renders a SPHINCS public key as the canonical
// raw-hex SPIF address that state keys and balance lookups use — the same
// derivation used for devnet reward keys, so a faucet-funded address and any
// other valid reward address are indistinguishable to the state DB.
func devnetAddressForPublicKey(pkBytes []byte) (string, error) {
	formatted := usiKey.GetPublicKeyFingerprintFromBytes(pkBytes, usiKey.OrgSPIF)
	canonical := common.CanonicalSPIFAddress(formatted)
	if !common.ValidateSPIFAddress(canonical) {
		return "", fmt.Errorf("derived address %q is not a valid SPIF address", formatted)
	}
	return canonical, nil
}

// ValidatorIDPrefix labels the key-derived validator identity.
const ValidatorIDPrefix = "VKID-"

// ValidatorIDFromPublicKey derives a validator's stable identity from its
// SPHINCS+ public key.
//
// It reuses the repository's existing address convention exactly — the same
// SHAKE256-with-org -> FormatOrgAddress -> CanonicalSPIFAddress chain
// devnetAddressForPublicKey uses — so no new hashing or encoding scheme is
// introduced. The fingerprint is relabelled with ValidatorIDPrefix so a
// validator identity can never be mistaken for a spendable SPIF address.
//
// This lives in bind rather than consensus because consensus must not import
// usi/core/key (it would close a usi/core/key -> core -> consensus cycle), and
// the fingerprint primitive lives in usi/core/key.
//
// Unlike the address-derived "Node-<host:port>" form, the result does not change
// when the node's listen address changes.
func ValidatorIDFromPublicKey(pk []byte) (string, error) {
	if len(pk) == 0 {
		return "", fmt.Errorf("validator public key is empty")
	}
	fingerprint := usiKey.GetPublicKeyFingerprintFromBytes(pk, usiKey.OrgSPIF)
	canonical := common.CanonicalSPIFAddress(fingerprint)
	if !common.ValidateSPIFAddress(canonical) {
		return "", fmt.Errorf("derived validator id %q is not a valid SPIF fingerprint", fingerprint)
	}
	return ValidatorIDPrefix + strings.TrimPrefix(canonical, common.SPIFPrefix), nil
}

// ValidatorIDAliasEntry records that one validator is reachable under two
// identity strings: the key-derived form and the address-derived
// "Node-<host:port>" form.
//
// Both remain valid. This exists so a later migration can translate between them
// without re-deriving either side.
type ValidatorIDAliasEntry struct {
	KeyDerivedID  string `json:"key_derived_id"`
	AddressID     string `json:"address_id"`
	PublicKeyHex  string `json:"public_key_hex"`
	ListenAddress string `json:"listen_address,omitempty"`
}

// ValidatorIDAliases maps between the two validator identity forms. It is
// additive: nothing in consensus, the snapshot key, or the wire formats reads
// it yet.
type ValidatorIDAliases struct {
	mu sync.RWMutex
	// byKeyDerived maps the key-derived form to the address form.
	byKeyDerived map[string]string
	// byAddress maps the address form to the key-derived form.
	byAddress map[string]string
}

// NewValidatorIDAliases returns an empty alias registry.
func NewValidatorIDAliases() *ValidatorIDAliases {
	return &ValidatorIDAliases{
		byKeyDerived: make(map[string]string),
		byAddress:    make(map[string]string),
	}
}

// Register records the two identity forms for one validator. A repeated
// keyDerivedID bound to a different addressID is rejected so the mapping cannot
// silently diverge.
func (r *ValidatorIDAliases) Register(entry ValidatorIDAliasEntry) error {
	if entry.KeyDerivedID == "" || entry.AddressID == "" {
		return fmt.Errorf("validator alias needs both a key-derived and an address-derived id")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, ok := r.byKeyDerived[entry.KeyDerivedID]; ok && prev != entry.AddressID {
		return fmt.Errorf("validator %s is already aliased to %s, refusing to remap to %s",
			entry.KeyDerivedID, prev, entry.AddressID)
	}
	r.byKeyDerived[entry.KeyDerivedID] = entry.AddressID
	r.byAddress[entry.AddressID] = entry.KeyDerivedID
	return nil
}

// AddressIDFor returns the address-derived id for a key-derived id.
func (r *ValidatorIDAliases) AddressIDFor(keyDerivedID string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	addr, ok := r.byKeyDerived[keyDerivedID]
	return addr, ok
}

// KeyDerivedIDFor returns the key-derived id for an address-derived id.
func (r *ValidatorIDAliases) KeyDerivedIDFor(addressID string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.byAddress[addressID]
	return id, ok
}

// Len reports how many validators are registered.
func (r *ValidatorIDAliases) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byKeyDerived)
}

// ============================================================================
// Genesis authoring decision
//
// Extracted from StartNodeWithOptions so the "who may author genesis" rule is
// a pure, testable function rather than an inline branch buried in a long
// startup path. It is the single place that answers: may this process write a
// genesis document?
//
// The rule, in order:
//  1. A node given --seeds is a JOINER. The network already exists; a document
//     it authored would name only itself and fork the chain at block 1. Never.
//  2. Auto-authoring is DEVNET-ONLY. On any other network a missing document is
//     a provisioning error, and guessing membership/chain parameters on a
//     value-bearing chain is exactly what must not happen.
//  3. Otherwise, and only otherwise, this node is the first one up and may
//     author a document naming only itself.
//
// It is consulted ONLY when core.GenesisNeedsAuthoring reported that the
// datadir holds no validator set. A node that already has a document never
// reaches here, so it can never overwrite one.
// ============================================================================

// GenesisAuthoringDecision is the outcome of genesisAuthoringDecision.
type GenesisAuthoringDecision int

const (
	// GenesisMayAuthor: devnet, no --seeds, no document — author it.
	GenesisMayAuthor GenesisAuthoringDecision = iota
	// GenesisRefuseJoiner: --seeds was given but no document arrived.
	GenesisRefuseJoiner
	// GenesisRefuseNonDevnet: not devnet and no document.
	GenesisRefuseNonDevnet
)

// genesisAuthoringDecision decides whether a node with no genesis document may
// author one. seeds is the raw --seeds value; networkType the resolved
// --network. It reads NO globals and touches NO disk, so every branch is
// testable in isolation.
func genesisAuthoringDecision(seeds, networkType, dataDir string) GenesisAuthoringDecision {
	// 1. A joiner never authors. Checked FIRST: a joiner pointed at a non-devnet
	//  network must still get the joiner rule, because that is the condition
	//  that makes authoring unsafe here.
	//
	//  ★ DELIBERATELY NOT strings.TrimSpace(seeds) == "" (the test used by the
	//  peer-DISCOVERY path, which treats a blank seed list as "no outbound
	//  dials"). Here the question is different and the answer is stricter: if
	//  the operator passed --seeds AT ALL, they believe a network already
	//  exists. Treating --seeds="   " as "no seeds" would let that node author
	//  its own genesis and fork the chain at block 1 — the exact failure this
	//  rule exists to prevent. Blank seeds are an operator typo, and failing
	//  closed on a typo is correct.
	if seeds != "" {
		return GenesisRefuseJoiner
	}
	// 2. Devnet only.
	if !core.DevnetAutoCustodyRequested(networkType) {
		return GenesisRefuseNonDevnet
	}
	// 3. First node up on devnet: author.
	return GenesisMayAuthor
}

// genesisAuthoringError renders the operator-facing message for a refusal. It
// names the document path and the reason, because "it did not start" with no
// explanation is the failure mode this decision exists to prevent.
func genesisAuthoringError(d GenesisAuthoringDecision, seeds, networkType, dataDir string, fetchErr error) error {
	path := core.GenesisStateFilePathForDataDir(dataDir)
	switch d {
	case GenesisRefuseJoiner:
		return fmt.Errorf("refusing to author genesis: this node was given --seeds=%q, so the network already has a genesis document, but none was fetched (fetch error: %v). "+
			"A joiner must never create its own genesis — a document naming only this node would fork the chain at block 1. "+
			"Check that the seed is running and serving its public bundle; the document lives at %s", seeds, fetchErr, path)
	case GenesisRefuseNonDevnet:
		return fmt.Errorf("no genesis document at %s and --network=%q is not devnet: auto-authoring genesis is devnet-only, "+
			"so this node cannot safely guess the network's membership or chain parameters. Place the document at %s (copy it from a peer) and start again",
			path, networkType, path)
	default:
		return fmt.Errorf("internal error: unexpected genesis authoring decision %d", d)
	}
}
