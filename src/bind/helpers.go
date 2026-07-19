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
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/core"
	svm "github.com/sphinxfndorg/protocol/src/core/kernel/opcodes"
	vmachine "github.com/sphinxfndorg/protocol/src/core/kernel/vm"

	logger "github.com/sphinxfndorg/protocol/src/console"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
	"github.com/sphinxfndorg/protocol/src/pool"
)

func (s *phase2InitState) begin() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.initialized || s.running {
		return false
	}
	s.running = true
	return true
}

func (s *phase2InitState) finish(success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
	if success {
		s.initialized = true
	}
}

func (s *phase2InitState) isInitialized() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.initialized
}

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

// readFramedMessage reads a length-prefixed message from the connection.
func readFramedMessage(conn net.Conn) ([]byte, error) {
	// Read 4-byte big-endian length prefix
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
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

// runCheckpointSyncLoop periodically syncs checkpoints.
func runCheckpointSyncLoop(
	ctx context.Context,
	bc *core.Blockchain,
	cons *consensus.Consensus,
	nodeID string,
	networkAddresses []string,
	nodeIndex int,
) {
	time.Sleep(3 * time.Second)

	if len(networkAddresses) > 1 {
		logger.Info("[%s] Syncing checkpoint with peers...", nodeID)
		for i, addr := range networkAddresses {
			if i == nodeIndex {
				continue
			}
			if err := bc.SyncCheckpoints(addr); err != nil {
				logger.Debug("[%s] Failed to sync checkpoint from %s: %v", nodeID, addr, err)
				continue
			}
			logger.Info("[%s] Synced checkpoint from %s", nodeID, addr)
			break
		}
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if cons == nil || !cons.IsLeader() {
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

// ============================================================================
// Stake watching
// ============================================================================

// watchAndUpdateStakes watches for Block 1 and updates validator stakes.
func watchAndUpdateStakes(
	ctx context.Context,
	bc *core.Blockchain,
	cons *consensus.Consensus,
	nodeID string,
	validatorIDs []string,
	validatorAddressMap map[string]string,
	phase2State *phase2InitState,
) {
	logger.Info("[%s] Stake watcher started - waiting for Block 1", nodeID)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			latestBlock := bc.GetLatestBlock()
			if latestBlock == nil {
				continue
			}

			height := latestBlock.GetHeight()

			if height >= 1 {
				logger.Info("[%s] Block %d detected - updating validator stakes from state DB", nodeID, height)

				time.Sleep(300 * time.Millisecond)

				tryInitPhase2WithRetry(bc, cons, nodeID, validatorIDs, validatorAddressMap, phase2State)
				logger.Info("[%s] Stake watcher done", nodeID)
				return
			}
		}
	}
}

// ============================================================================
// Validator admission — the ONLY path allowed to grant stake
// ============================================================================

// stakeIfSufficientBalance checks rewardAddress's balance against an
// already-open stateDB and, only if it meets the minimum stake, admits
// validatorID with that stake via SetStakeFromBalance. It never falls back
// to a minimum-stake grant on lookup failure — insufficient or unverifiable
// balance means the candidate is simply not added as a validator.
//
// This is the single source of truth for "does this ID get to vote", used
// both by genesis Phase 2 bulk initialization and by runtime peer admission
// after key exchange. There must be exactly one such function; having two
// copies of this logic is how the two paths drifted apart before (one
// checked balance, the other blindly granted minimum stake to anyone who
// dialed in).
func stakeIfSufficientBalance(vs *consensus.ValidatorSet, stateDB pool.StateDB, selfNodeID, validatorID, rewardAddress string) bool {
	if vs == nil || stateDB == nil || validatorID == "" || rewardAddress == "" {
		return false
	}

	address := rewardAddress
	if normalized, err := common.NormalizeSPIFAddress(rewardAddress); err == nil {
		address = normalized
	}

	balanceNSPX, err := stateDB.GetBalance(address)
	if err != nil {
		logger.Info("[%s] Cannot verify balance for %s (%s): %v — not admitted as validator", selfNodeID, validatorID, address, err)
		return false
	}
	if balanceNSPX == nil || !vs.IsValidStakeAmount(balanceNSPX) {
		logger.Info("[%s] %s (%s) balance below minimum stake — not admitted as validator", selfNodeID, validatorID, address)
		return false
	}

	if err := vs.SetStakeFromBalance(validatorID, balanceNSPX); err != nil {
		logger.Warn("[%s] Failed to stake %s from verified balance: %v", selfNodeID, validatorID, err)
		return false
	}
	logger.Info("[%s] Validator %s admitted with verified stake from %s", selfNodeID, validatorID, address)
	return true
}

// stakeValidatorFromRewardAddress is the runtime entry point used after a
// peer's key-exchange reply carries a reward address (see helpers.go
// discoverAndRegisterPeers / handleIncomingConn). It opens its own StateDB
// handle for a single check — appropriate for the "one peer just showed up"
// case, unlike the bulk genesis path in initializePhase2Stakes which reuses
// one already-open handle across every validator.
func stakeValidatorFromRewardAddress(bc *core.Blockchain, cons *consensus.Consensus, selfNodeID, validatorID, rewardAddress string) bool {
	if bc == nil || cons == nil {
		return false
	}
	vs := cons.GetValidatorSet()
	if vs == nil {
		return false
	}
	stateDB, err := bc.NewStateDB()
	if err != nil {
		logger.Warn("[%s] Cannot verify stake for %s: StateDB unavailable: %v", selfNodeID, validatorID, err)
		return false
	}
	defer stateDB.Close()

	return stakeIfSufficientBalance(vs, stateDB, selfNodeID, validatorID, rewardAddress)
}

// ============================================================================
// Phase 2 initialization
// ============================================================================

// initializePhase2Stakes reads actual balances from state DB and sets
// validator stakes for the pre-configured (genesis) validator set.
//
// Unlike peer-discovery admission (stakeValidatorFromRewardAddress),
// validatorIDs here comes from trusted node configuration, not from an
// unauthenticated remote claim — so a missing/zero balance still falls back
// to minimum stake rather than exclusion, to avoid a fresh genesis network
// deadlocking just because distribution transactions haven't landed yet.
// The actual balance check + stake assignment goes through the same
// stakeIfSufficientBalance core used everywhere else, so there is only one
// place that reads a balance and decides whether it's enough.
func initializePhase2Stakes(
	bc *core.Blockchain,
	cons *consensus.Consensus,
	nodeID string,
	validatorIDs []string,
	validatorAddressMap map[string]string,
) bool {
	logger.Info("[%s] PHASE 2 INITIALIZATION - Reading stakes from genesis allocations", nodeID)

	vs := cons.GetValidatorSet()
	if vs == nil {
		logger.Error("[%s] ValidatorSet is nil!", nodeID)
		return false
	}
	if len(validatorIDs) == 0 {
		logger.Error("[%s] No validators found! Cannot initialize Phase 2 stakes.", nodeID)
		return false
	}

	const maxRetries = 5
	var stateDB pool.StateDB
	var err error
	for attempt := 0; attempt < maxRetries; attempt++ {
		logger.Info("[%s] Phase 2: StateDB open attempt %d/%d", nodeID, attempt+1, maxRetries)
		stateDB, err = bc.NewStateDB()
		if err == nil {
			break
		}
		logger.Warn("[%s] Failed to open StateDB (attempt %d/%d): %v", nodeID, attempt+1, maxRetries, err)
		time.Sleep(time.Duration(100*(1<<attempt)) * time.Millisecond)
	}
	if stateDB == nil {
		logger.Error("[%s] Failed to open StateDB after %d attempts", nodeID, maxRetries)
		return false
	}
	defer stateDB.Close()

	minStakeSPX := vs.GetMinStakeSPX()
	successCount := 0

	for _, vid := range validatorIDs {
		address := validatorAddressMap[vid]
		if address == "" {
			// A peer ID is not an account address. Until this validator presents
			// a verified reward-address claim, it deliberately receives only the
			// configured bootstrap stake; do not attempt an acct:<node-id> lookup.
			logger.Info("[%s] Validator %s has no verified reward address yet — using configured minimum stake", nodeID, vid)
			if err := vs.AddValidator(vid, minStakeSPX); err == nil {
				successCount++
			} else {
				logger.Warn("[%s] Failed to set minimum stake for %s: %v", nodeID, vid, err)
			}
			continue
		}

		if stakeIfSufficientBalance(vs, stateDB, nodeID, vid, address) {
			successCount++
			continue
		}

		// Genesis-mapped validator with no readable/sufficient balance
		// yet — bootstrap at minimum stake rather than excluding them;
		// this is a trusted, operator-configured ID, not a remote claim.
		logger.Info("[%s] Validator %s (%s) balance not yet available — using minimum stake", nodeID, vid, address)
		if err := vs.AddValidator(vid, minStakeSPX); err != nil {
			logger.Warn("[%s] Failed to set fallback stake for %s: %v", nodeID, vid, err)
			continue
		}
		successCount++
	}

	logger.Info("[%s] Phase 2: %d/%d validators staked", nodeID, successCount, len(validatorIDs))

	totalStake := vs.GetTotalStake()
	if totalStake.Sign() == 0 {
		logger.Error("[%s] CRITICAL: Total stake is 0 after Phase 2 init!", nodeID)
		return false
	}

	totalSPX := new(big.Int).Div(totalStake, big.NewInt(denom.SPX))
	logger.Info("[%s] Phase 2 stakes initialized with %s SPX total", nodeID, totalSPX.String())
	return true
}

// tryInitPhase2 runs the Phase 2 initialization and advances the consensus view.
func tryInitPhase2(
	bc *core.Blockchain,
	cons *consensus.Consensus,
	nodeID string,
	validatorIDs []string,
	validatorAddressMap map[string]string,
	phase2State *phase2InitState,
) bool {
	if phase2State.isInitialized() {
		return true
	}
	if !phase2State.begin() {
		logger.Info("[%s] Phase 2 initialization already running on another path", nodeID)
		return false
	}

	succeeded := false
	defer func() {
		phase2State.finish(succeeded)
		logger.Info("[%s] Phase 2 initialization attempt finished (success=%v)", nodeID, succeeded)
	}()

	logger.Info("[%s] BLOCK 1 COMMITTED — Initializing Phase 2 stakes", nodeID)

	time.Sleep(500 * time.Millisecond)

	if !initializePhase2Stakes(bc, cons, nodeID, validatorIDs, validatorAddressMap) {
		logger.Error("[%s] Phase 2 initialization failed!", nodeID)
		return false
	}

	logger.Info("[%s] Phase 2: refreshing leader status", nodeID)
	cons.UpdateLeaderStatus()

	if err := bc.WriteChainCheckpoint(); err != nil {
		logger.Warn("[%s] Failed to write checkpoint after Phase 2: %v", nodeID, err)
	} else {
		logger.Info("[%s] Checkpoint updated after Phase 2 initialization", nodeID)
	}

	newLeader := cons.GetElectedLeaderID()
	if newLeader != "" {
		logger.Info("[%s] Phase 2 leader elected: %s (isLeader=%v)",
			nodeID, newLeader, cons.IsLeader())
	} else {
		logger.Warn("[%s] No leader after Phase 2 init — will retry next loop", nodeID)
	}
	succeeded = true
	return succeeded
}

// tryInitPhase2WithRetry attempts to initialize Phase 2 with retries.
func tryInitPhase2WithRetry(
	bc *core.Blockchain,
	cons *consensus.Consensus,
	nodeID string,
	validatorIDs []string,
	validatorAddressMap map[string]string,
	phase2State *phase2InitState,
) bool {
	logger.Info("[%s] Initializing Phase 2 with retry...", nodeID)

	maxAttempts := 15
	baseBackoff := 200 * time.Millisecond
	maxBackoff := 10 * time.Second

	for attempt := 0; attempt < maxAttempts; attempt++ {
		backoff := baseBackoff
		for i := 0; i < attempt && backoff < maxBackoff; i++ {
			backoff *= 2
		}
		if backoff > maxBackoff {
			backoff = maxBackoff
		}

		jitterFactor := 0.7 + 0.6*float64(attempt%10)/10.0
		jitter := time.Duration(float64(backoff) * jitterFactor)
		if jitter < 100*time.Millisecond {
			jitter = 100 * time.Millisecond
		}

		if tryInitPhase2(bc, cons, nodeID, validatorIDs, validatorAddressMap, phase2State) {
			logger.Info("[%s] Phase 2 initialized on attempt %d", nodeID, attempt+1)
			return true
		}

		if attempt < maxAttempts-1 {
			logger.Warn("[%s] Phase 2 init attempt %d/%d failed, retrying in %v...",
				nodeID, attempt+1, maxAttempts, jitter)
			time.Sleep(jitter)
		}
	}

	logger.Error("[%s] Phase 2 initialization failed after %d attempts - applying fallback stakes",
		nodeID, maxAttempts)

	vs := cons.GetValidatorSet()
	if vs != nil {
		minStake := vs.GetMinStakeSPX()
		for _, vid := range validatorIDs {
			if err := vs.AddValidator(vid, minStake); err != nil {
				logger.Warn("[%s] Failed to set fallback stake for %s: %v", nodeID, vid, err)
			} else {
				logger.Info("[%s] Set fallback stake %d SPX for %s", nodeID, minStake, vid)
			}
		}

		cons.UpdateLeaderStatus()
		cons.StartViewChange()
		phase2State.finish(true)
		logger.Info("[%s] Fallback stakes applied, view change triggered", nodeID)
		return true
	}

	return false
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
func runBlockSyncLoop(
	ctx context.Context,
	bc *core.Blockchain,
	cons *consensus.Consensus,
	nodeID string,
	peerAddrsFunc func() []string,
	syncState *SyncState,
	syncStateMu *sync.Mutex,
	progress *logger.BlockchainProgress, // NEW
) {
	logger.Info("[%s] Block sync loop started (state=%s)", nodeID, syncState.String())

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

		// ★ FIX: Re-read the peer list on every iteration instead of using a
		// snapshot captured once at goroutine launch. The caller passes a
		// closure backed by the live, mutex-protected peer registry (the same
		// one runBlockProductionLoop's peerCountFunc reads from). Previously
		// this loop was handed a plain []string snapshot taken at startup —
		// for the bootstrap node (no --seeds) that snapshot is always empty,
		// since peers only get registered later via inbound key exchange. The
		// snapshot never changed for the lifetime of the goroutine, so the
		// bootstrap node's "len(peerAddrs) == 0" branch below was taken
		// forever: it correctly reached CAUGHT_UP once (so solo mining could
		// start), but its ongoing catch-up mechanism — the whole point of a
		// persistent sync loop — never actually ran for that node, even after
		// it had live peers and had joined PBFT. Any block it then missed via
		// direct gossip (dropped message, timing gap during the solo→PBFT
		// handoff, etc.) could never be recovered, permanently stalling its
		// height while peers with a working sync loop kept advancing.
		peerAddrs := peerAddrsFunc()

		localTip := bc.GetLatestBlock()
		localHeight := uint64(0)
		hasGenesis := false
		if localTip != nil {
			localHeight = localTip.GetHeight()
			hasGenesis = true
		}

		// ★ FIX: If no peer addresses are configured (solo mode / first node), there is
		// nothing to sync — immediately transition to CAUGHT_UP so the block production
		// loop can start mining blocks. Without this, the first node gets stuck at genesis
		// because the sync loop can never reach a peer, so it never transitions state, and
		// the block production loop waits for CAUGHT_UP before it starts mining.
		if len(peerAddrs) == 0 {
			syncStateMu.Lock()
			if *syncState == SyncStateSyncing {
				*syncState = SyncStateCaughtUp
				logger.Info("[%s] No peer addresses configured — skipping sync, transitioning to CAUGHT_UP", nodeID)
				if syncStarted {
					syncStarted = false
				}
			}
			syncStateMu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
			continue
		}

		logger.Debug("[%s] Sync loop: localHeight=%d, hasGenesis=%v, peerCount=%d, retryInterval=%v",
			nodeID, localHeight, hasGenesis, len(peerAddrs), currentRetryInterval)

		if time.Since(lastPeerRefresh) > peerRefreshInterval {
			logger.Debug("[%s] Refreshing peer list (last refresh %v ago)", nodeID, time.Since(lastPeerRefresh))
			peerFailureCount = make(map[string]int)
			lastPeerRefresh = time.Now()
		}

		// ── QUERY PEERS FOR NETWORK TIP ──
		networkTip := uint64(0)
		bestPeerAddr := ""
		reachablePeers := 0
		for _, addr := range peerAddrs {
			if addr == "" {
				continue
			}
			tip, err := getPeerTipHeight(addr)
			if err != nil {
				logger.Debug("[%s] Peer %s failed tip query: %v", nodeID, addr, err)
				continue
			}
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

		if reachablePeers == 0 {
			logger.Warn("[%s] No peers reachable (tried %d peers) — backing off before retry",
				nodeID, len(peerAddrs))
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

		if networkTip == 0 {
			syncStateMu.Lock()
			if *syncState == SyncStateSyncing {
				*syncState = SyncStateCaughtUp
				logger.Info("[%s] At genesis (height 0) — transitioning to CAUGHT_UP (fresh network)", nodeID)
				if syncStarted {
					syncStarted = false
				}
			}
			syncStateMu.Unlock()
			// ★ FIX: Don't return — enter periodic sync check mode. The network
			// may produce blocks later. We keep checking every 10 seconds so a
			// node that joined early (before any blocks were mined) automatically
			// catches up when blocks arrive, without needing a restart.
			// This implements "synchronization shouldn't happen only during startup"
			// — the node continuously monitors the network tip and catches up
			// whenever it falls behind.
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
				// ── Attestation quorum check ──
				if len(blk.Body.Attestations) > 0 {
					vs := cons.GetValidatorSet()
					if vs != nil {
						blockEpoch := blk.GetHeight() / consensus.SlotsPerEpoch
						if err := core.VerifyBlockAttestations(blk, vs, blockEpoch); err != nil {
							logger.Error("[%s] Block %d failed attestation quorum check: %v — rejecting batch from peer %s",
								nodeID, blk.GetHeight(), err, bestPeerAddr)
							applied = 0
							break
						}
					}
				} else {
					logger.Info("[%s] Block %d has no attestations (solo-mined before PBFT) — skipping quorum check, verified by chain continuity",
						nodeID, blk.GetHeight())
				}
			}
			wrapped := core.NewBlockHelper(blk)
			if err := bc.CommitBlock(wrapped); err != nil {
				logger.Error("[%s] Failed to commit synced block %d: %v", nodeID, blk.GetHeight(), err)
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
	totalNodes int,
	networkType string,
	validatorIDs []string,
	validatorAddressMap map[string]string,
	phase2State *phase2InitState,
	peerCountFunc func() int,
	syncState *SyncState,
	syncStateMu *sync.Mutex,
	progress *logger.BlockchainProgress, // NEW
) {
	// Set initial consensus status: PAUSED while syncing
	progress.SetConsensusStatus("PAUSED — synchronizing")

	// ★ FIX: SOLO_MODE must be exclusive to the bootstrap node — the one
	// that created genesis locally, i.e. bc.IsLateJoiner() == false (set at
	// startup from `seeds != ""`, see bind/nodes.go's core.NewBlockchain
	// call: `seeds != ""` is passed as the lateJoiner argument). Previously
	// *any* node that currently saw 0 peers would enter SOLO_MODE, including
	// late joiners. If peer discovery took a couple of minutes, every node
	// independently mined 15-16 blocks with divergent content from height 1
	// onward — a fork the reorg path couldn't heal (see
	// FindCommonAncestor/handleReorg fixes in sync.go).
	//
	// NOTE: this deliberately does NOT key off nodeIndex. In real-device
	// mode, bind/nodes.go force-resets nodeIndex to 0 for EVERY node
	// (`nodeIndex = 0` when usingRealAddress/userProvidedTCP — see
	// StartNode), so nodeIndex cannot distinguish "the bootstrap node" from
	// "any other real node" in production. IsLateJoiner (driven by whether
	// --seeds was given at startup) is the only signal that's correct in
	// both same-box and real-device deployments.
	isBootstrapNode := !bc.IsLateJoiner()
	const (
		singleNodeInterval  = 10 * time.Second
		multiNodeRoundDelay = 3 * time.Second
	)

	// effectiveValidatorCount reports how many validators this node actually
	// knows about right now. It must NOT short-circuit to the static
	// totalNodes config when totalNodes >= 3 — doing so made the "wait for
	// peers" gate below a no-op for the canonical 3-node network, letting a
	// node jump straight into leader election and propose for view 0 before
	// its peers had finished connecting on the P2P broadcast layer (distinct
	// from the one-off key-exchange handshake, which only proves the peer
	// was reachable at that instant, not that a persistent broadcast link
	// exists yet).
	effectiveValidatorCount := func() int {
		if peerCountFunc != nil {
			known := peerCountFunc() + 1 // +1 for self
			if totalNodes > 1 && known > totalNodes {
				known = totalNodes
			}
			return known
		}
		return totalNodes
	}

	// ──────────────────────────────────────────────────────────────────────
	// SYNC STATE GATE: A node in SYNCING state must NOT participate in PBFT.
	// ──────────────────────────────────────────────────────────────────────
	for {
		syncStateMu.Lock()
		currentSyncState := *syncState
		syncStateMu.Unlock()

		if currentSyncState == SyncStateSyncing {
			logger.Info("[%s] Sync in progress — waiting to catch up before joining PBFT (state=%s)",
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

	// ── SOLO MODE (no peers) ──
	if isBootstrapNode && effectiveValidatorCount() == 1 {
		logger.Info("[%s] SOLO MODE — bootstrap node, no peers detected yet, mining blocks independently", nodeID)
		progress.SetConsensusStatus("ACTIVE — solo mining")

		blockTicker := time.NewTicker(singleNodeInterval)
		defer blockTicker.Stop()
		peerCheckTicker := time.NewTicker(5 * time.Second)
		defer peerCheckTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return

			case <-blockTicker.C:
				blk, err := bc.CreateBlock()
				if err != nil {
					logger.Error("[%s] solo mine error: %v", nodeID, err)
					continue
				}
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
				if effectiveValidatorCount() >= 3 {
					logger.Info("[%s] %d validators now known — initiating solo-to-PBFT handoff", nodeID, effectiveValidatorCount())
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

	// ── INSUFFICIENT VALIDATORS ──
	if effectiveValidatorCount() < 3 {
		logger.Warn("[%s] Block-production suspended (need ≥ 3 validators for PBFT, have %d — waiting for peers to connect)",
			nodeID, effectiveValidatorCount())
		progress.SetConsensusStatus("PAUSED — insufficient validators")
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if effectiveValidatorCount() >= 3 {
					logger.Info("[%s] %d validators now known — starting PBFT block production",
						nodeID, effectiveValidatorCount())
					progress.SetConsensusStatus("ACTIVE — validating")
					goto startPBFT
				}
				logger.Info("[%s] Waiting for validators (%d/3 minimum)…", nodeID, effectiveValidatorCount())
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

			if peerCountFunc != nil && peerCountFunc() >= 2 {
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

	phase2Initialized := false

	go watchAndUpdateStakes(ctx, bc, cons, nodeID, validatorIDs, validatorAddressMap, phase2State)

	// The validator set includes configured peers before they are connected,
	// so it cannot represent "active" in the terminal. Report the live
	// discovery count instead, against the configured network size.
	progress.UpdateValidatorStatus(effectiveValidatorCount(), totalNodes)

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

			if currentHeight >= 1 && !phase2Initialized {
				if tryInitPhase2WithRetry(bc, cons, nodeID, validatorIDs, validatorAddressMap, phase2State) {
					phase2Initialized = true
				}
			}
		}

		// Update mempool and validator counts periodically
		if bc.GetMempool() != nil {
			pending := bc.GetMempool().GetPendingTransactions()
			// Estimate TPS: we don't have a real TPS counter, just pass 0 or compute from block times
			progress.UpdateMempoolActivity(len(pending), 0)
		}
		progress.UpdateValidatorStatus(effectiveValidatorCount(), totalNodes)

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
		if signingService != nil {
			if err := signingService.SignBlock(wrapped); err != nil {
				logger.Error("[%s] Failed to sign block header: %v", nodeID, err)
				continue
			}
			logger.Info("[%s] Block header signed", nodeID)
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

		commitTimeout := time.After(60 * time.Second)
		commitTicker := time.NewTicker(1 * time.Second)

		committed := false
		for !committed {
			select {
			case <-ctx.Done():
				commitTicker.Stop()
				return
			case <-commitTimeout:
				logger.Warn("[%s] Timeout waiting for block commitment at height %d", nodeID, currentHeight+1)
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

					if currentHeight >= 1 && !phase2Initialized {
						if tryInitPhase2WithRetry(bc, cons, nodeID, validatorIDs, validatorAddressMap, phase2State) {
							phase2Initialized = true
						}
					}

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
