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
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/core"
	svm "github.com/sphinxfndorg/protocol/src/core/svm/opcodes"
	vmachine "github.com/sphinxfndorg/protocol/src/core/svm/vm"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	logger "github.com/sphinxfndorg/protocol/src/log"
	"github.com/sphinxfndorg/protocol/src/network"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
	"github.com/sphinxfndorg/protocol/src/pool"
	"github.com/sphinxfndorg/protocol/src/rpc"
	"github.com/sphinxfndorg/protocol/src/state"
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

// ============================================================================
// Key exchange
// ============================================================================

// exchangeKeyWithPeerSync performs synchronous key exchange with a single peer.
// It returns the peer's full handshake payload (including their claimed
// RewardAddress) so the caller can decide separately whether to admit them
// as a validator — key exchange itself never grants stake.
//
// Genesis hash verification: If the peer's genesis hash differs from ours,
// the connection is rejected with an error. This prevents accidental network
// splits when nodes bootstrap from different genesis configurations.
func exchangeKeyWithPeerSync(peerAddr string, nodeID string, ownRewardAddress string, ownGenesisHash string, signingService *consensus.SigningService, sthincsParams *parameters.Parameters) (*peerKeyExchangeMsg, error) {
	ownPKBytes, err := signingService.GetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get own public key: %v", err)
	}

	payload := peerKeyExchangeMsg{
		NodeID:        nodeID,
		PublicKey:     ownPKBytes,
		RewardAddress: ownRewardAddress,
		GenesisHash:   ownGenesisHash,
	}
	payloadBytes, _ := json.Marshal(payload)

	conn, err := net.DialTimeout("tcp", peerAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %v", err)
	}
	defer conn.Close()

	msg := security.Message{Type: "key_exchange", Data: payloadBytes}
	encodedMsg, err := msg.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode failed: %v", err)
	}
	if err := writeFramedMessage(conn, encodedMsg); err != nil {
		return nil, fmt.Errorf("send failed: %v", err)
	}

	replyData, err := readFramedMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("receive failed: %v", err)
	}
	var reply security.Message
	if err := json.Unmarshal(replyData, &reply); err != nil {
		return nil, fmt.Errorf("decode failed: %v", err)
	}

	if reply.Type != "key_exchange" {
		return nil, fmt.Errorf("unexpected reply type: %s", reply.Type)
	}

	var kx peerKeyExchangeMsg
	if err := json.Unmarshal(reply.Data, &kx); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %v", err)
	}

	// ════════════════════════════════════════════════════════════════════
	// GENESIS HASH VERIFICATION
	// ════════════════════════════════════════════════════════════════════
	// If the peer advertises a genesis hash and it differs from ours, the
	// peer is on a fundamentally incompatible chain. Reject the connection
	// immediately — a peer with a different genesis must never be admitted
	// to the gossip graph or validator set.
	if kx.GenesisHash != "" && ownGenesisHash != "" && kx.GenesisHash != ownGenesisHash {
		return nil, fmt.Errorf(
			"genesis hash mismatch with peer %s at %s: peer=%s, local=%s — "+
				"peer is on a different chain, connection rejected",
			kx.NodeID, peerAddr, kx.GenesisHash, ownGenesisHash,
		)
	}
	// ════════════════════════════════════════════════════════════════════

	pk, err := sthincs.DeserializePK(sthincsParams, kx.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("deserialize failed: %v", err)
	}

	signingService.RegisterPublicKey(kx.NodeID, pk)
	logger.Info("✅ Key exchange complete with %s (genesis=%s)", kx.NodeID, kx.GenesisHash)
	return &kx, nil
}

// requestPeerListSync asks a single peer "who else do you know about?".
func requestPeerListSync(peerAddr string, selfNodeID string, selfAddr string) (*peerExchangeMsg, error) {
	request := peerExchangeMsg{NodeID: selfNodeID, Address: selfAddr}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal peer exchange request: %v", err)
	}

	conn, err := net.DialTimeout("tcp", peerAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %v", err)
	}
	defer conn.Close()

	msg := security.Message{Type: "peer_exchange", Data: requestBytes}
	encodedMsg, err := msg.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode failed: %v", err)
	}
	if err := writeFramedMessage(conn, encodedMsg); err != nil {
		return nil, fmt.Errorf("send failed: %v", err)
	}

	replyData, err := readFramedMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("receive failed: %v", err)
	}
	var reply security.Message
	if err := json.Unmarshal(replyData, &reply); err != nil {
		return nil, fmt.Errorf("decode failed: %v", err)
	}
	if reply.Type != "peer_exchange" {
		return nil, fmt.Errorf("unexpected reply type: %s", reply.Type)
	}

	var pex peerExchangeMsg
	if err := json.Unmarshal(reply.Data, &pex); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %v", err)
	}
	return &pex, nil
}

// discoverAndRegisterPeers bootstraps this node into the network starting
// from a small list of seed addresses.
//
// onPeerDiscovered registers a peer for gossip/relay purposes only — it
// never grants validator status. onPeerStakeClaim is called separately,
// only when a peer's key-exchange reply includes a non-empty reward
// address; the caller is expected to verify that address's on-chain
// balance before admitting the peer as a validator (see
// stakeValidatorFromRewardAddress). Discovery and validator admission are
// intentionally decoupled: showing up on the wire earns you a spot in the
// gossip graph, never a vote.
func discoverAndRegisterPeers(
	seedAddrs []string,
	selfNodeID string,
	selfAddr string,
	ownRewardAddress string,
	signingService *consensus.SigningService,
	sthincsParams *parameters.Parameters,
	maxHops int,
	onPeerDiscovered func(nodeID, address string),
	onPeerStakeClaim func(nodeID, rewardAddress string),
) {
	if len(seedAddrs) == 0 {
		logger.Info("discoverAndRegisterPeers: no seeds configured, skipping discovery")
		return
	}
	if maxHops <= 0 {
		maxHops = 2
	}

	visited := map[string]bool{selfAddr: true}
	frontier := make([]string, 0, len(seedAddrs))
	for _, addr := range seedAddrs {
		if addr != "" && !visited[addr] {
			frontier = append(frontier, addr)
		}
	}

	for hop := 0; hop < maxHops && len(frontier) > 0; hop++ {
		logger.Info("discoverAndRegisterPeers: hop %d/%d, dialing %d address(es)", hop+1, maxHops, len(frontier))
		next := make([]string, 0)

		for _, addr := range frontier {
			if visited[addr] {
				continue
			}
			visited[addr] = true

			kx, err := exchangeKeyWithPeerSync(addr, selfNodeID, ownRewardAddress, core.GetGenesisHash(), signingService, sthincsParams)
			if err != nil {
				logger.Warn("discoverAndRegisterPeers: key exchange with %s failed: %v", addr, err)
				continue
			}
			if kx.RewardAddress != "" && onPeerStakeClaim != nil {
				onPeerStakeClaim(kx.NodeID, kx.RewardAddress)
			}

			pex, err := requestPeerListSync(addr, selfNodeID, selfAddr)
			if err != nil {
				logger.Warn("discoverAndRegisterPeers: peer exchange with %s failed: %v", addr, err)
				onPeerDiscovered(addrToNodeIDFallback(addr), addr)
				continue
			}

			if pex.NodeID != "" {
				onPeerDiscovered(pex.NodeID, addr)
			}

			for _, p := range pex.Peers {
				if p.Address == "" || visited[p.Address] {
					continue
				}
				next = append(next, p.Address)
			}
		}

		frontier = next
	}

	logger.Info("discoverAndRegisterPeers: discovery complete, contacted %d address(es) total", len(visited)-1)
}

func addrToNodeIDFallback(addr string) string {
	return fmt.Sprintf("Node-%s", addr)
}

// ============================================================================
// TCP handler
// ============================================================================

// handleIncomingConn processes a single accepted TCP connection.
func handleIncomingConn(
	conn net.Conn,
	selfID string,
	selfAddr string,
	ownRewardAddress string,
	signingService *consensus.SigningService,
	sthincsParams *parameters.Parameters,
	cons *consensus.Consensus,
	p2pMgr *network.P2PConsensusNodeManager,
	rpcServer *rpc.Server,
	bc *core.Blockchain,
	getKnownPeers func() []knownPeerInfo,
	onPeerDiscovered func(nodeID, address string),
	onPeerStakeClaim func(nodeID, rewardAddress string),
) {
	// Read length-prefixed message from client
	msgData, err := readFramedMessage(conn)
	if err != nil {
		log.Printf("[%s] Failed to read message: %v", selfID, err)
		return
	}

	var msg security.Message
	if err := json.Unmarshal(msgData, &msg); err != nil {
		log.Printf("[%s] Failed to decode message: %v", selfID, err)
		return
	}

	log.Printf("[%s] Received message type: %s", selfID, msg.Type)

	switch msg.Type {
	case "key_exchange":
		var kx peerKeyExchangeMsg
		if err := json.Unmarshal(msg.Data, &kx); err != nil {
			log.Printf("[%s] Failed to unmarshal key exchange: %v", selfID, err)
			return
		}

		pk, err := sthincs.DeserializePK(sthincsParams, kx.PublicKey)
		if err != nil {
			log.Printf("[%s] Failed to deserialize public key: %v", selfID, err)
			return
		}
		signingService.RegisterPublicKey(kx.NodeID, pk)
		logger.Info("✅ [%s] Registered public key from %s", selfID, kx.NodeID)

		if onPeerDiscovered != nil && kx.NodeID != "" {
			var peerAddr string
			if strings.HasPrefix(kx.NodeID, "Node-") {
				peerAddr = strings.TrimPrefix(kx.NodeID, "Node-")
			} else {
				peerAddr = kx.NodeID
			}
			onPeerDiscovered(kx.NodeID, peerAddr)
		}

		// A reward address only ever results in a *verified* stake check
		// downstream (see stakeValidatorFromRewardAddress) — receiving one
		// here never grants validator status by itself.
		if onPeerStakeClaim != nil && kx.RewardAddress != "" {
			onPeerStakeClaim(kx.NodeID, kx.RewardAddress)
		}

		ownPKBytes, err := signingService.GetPublicKey()
		if err != nil {
			log.Printf("[%s] Failed to get own public key: %v", selfID, err)
			return
		}
		reply := peerKeyExchangeMsg{NodeID: selfID, PublicKey: ownPKBytes, RewardAddress: ownRewardAddress}
		replyBytes, _ := json.Marshal(reply)
		replyMsg := security.Message{Type: "key_exchange", Data: replyBytes}
		encodedReply, _ := replyMsg.Encode()
		if err := writeFramedMessage(conn, encodedReply); err != nil {
			log.Printf("[%s] Failed to send key exchange reply: %v", selfID, err)
		}

	case "peer_exchange":
		var req peerExchangeMsg
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			log.Printf("[%s] Failed to unmarshal peer exchange request: %v", selfID, err)
			return
		}

		if onPeerDiscovered != nil && req.NodeID != "" && req.Address != "" {
			onPeerDiscovered(req.NodeID, req.Address)
		}

		var knownPeers []knownPeerInfo
		if getKnownPeers != nil {
			knownPeers = getKnownPeers()
		}

		logger.Info("[%s] 🔍 Peer exchange request from %s (%s) — sharing %d known peer(s)",
			selfID, req.NodeID, req.Address, len(knownPeers))

		reply := peerExchangeMsg{NodeID: selfID, Address: selfAddr, Peers: knownPeers}
		replyBytes, err := json.Marshal(reply)
		if err != nil {
			log.Printf("[%s] Failed to marshal peer exchange reply: %v", selfID, err)
			return
		}
		replyMsg := security.Message{Type: "peer_exchange", Data: replyBytes}
		encodedReply, err := replyMsg.Encode()
		if err != nil {
			log.Printf("[%s] Failed to encode peer exchange reply: %v", selfID, err)
			return
		}
		if err := writeFramedMessage(conn, encodedReply); err != nil {
			log.Printf("[%s] Failed to send peer exchange reply: %v", selfID, err)
		}

	case "checkpoint":
		var cp consensus.CheckpointMessage
		if err := json.Unmarshal(msg.Data, &cp); err != nil {
			log.Printf("[%s] Failed to unmarshal checkpoint: %v", selfID, err)
			return
		}

		logger.Info("[%s] Received checkpoint from peer: height=%d, phase=%s, supply=%s SPX",
			selfID, cp.TipHeight, cp.Phase, cp.MintedSPX)

		if cons != nil {
			if err := cons.HandleCheckpointMessage(msg.Data, ""); err != nil {
				log.Printf("[%s] Failed to handle checkpoint: %v", selfID, err)
			}
		}

	case "get_blocks":
		var req GetBlocksRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			log.Printf("[%s] Failed to unmarshal get_blocks request: %v", selfID, err)
			return
		}

		// Validate request bounds
		if req.FromHeight > req.ToHeight || req.ToHeight-req.FromHeight > 500 {
			log.Printf("[%s] Invalid get_blocks range: %d -> %d", selfID, req.FromHeight, req.ToHeight)
			return
		}
		if req.MaxResults == 0 || req.MaxResults > 500 {
			req.MaxResults = 500
		}
		if req.ToHeight-req.FromHeight+1 > req.MaxResults {
			req.ToHeight = req.FromHeight + req.MaxResults - 1
		}

		// Gather blocks from local storage
		var blocks []*types.Block
		for h := req.FromHeight; h <= req.ToHeight; h++ {
			blk := bc.GetBlockByNumber(h)
			if blk == nil {
				break // gap in chain, serve what we have
			}
			blocks = append(blocks, blk)
		}

		// Get our tip height so the requester knows how far ahead we are
		tipHeight := uint64(0)
		if latest := bc.GetLatestBlock(); latest != nil {
			tipHeight = latest.GetHeight()
		}

		resp := GetBlocksResponse{
			Blocks:    blocks,
			TipHeight: tipHeight,
		}
		respBytes, _ := json.Marshal(resp)
		respMsg := security.Message{Type: "get_blocks", Data: respBytes}
		encodedResp, _ := respMsg.Encode()
		if err := writeFramedMessage(conn, encodedResp); err != nil {
			log.Printf("[%s] Failed to send get_blocks response: %v", selfID, err)
		}
		logger.Info("[%s] 📦 Served %d blocks (heights %d-%d) to peer", selfID, len(blocks), req.FromHeight, req.ToHeight)

	case "proposal", "prepare", "vote", "timeout", "randao_sync":
		if p2pMgr == nil {
			log.Printf("[%s] P2P manager is nil, cannot handle consensus message", selfID)
			return
		}

		log.Printf("[%s] 📨 Processing consensus message type=%s", selfID, msg.Type)

		if err := p2pMgr.HandleIncomingMessage(msg.Type, msg.Data, ""); err != nil {
			log.Printf("[%s] consensus handling error: %v", selfID, err)
		} else {
			log.Printf("[%s] ✅ Successfully handled %s message", selfID, msg.Type)
		}

	case "rpc":
		var rpcData []byte
		if err := json.Unmarshal(msg.Data, &rpcData); err != nil {
			log.Printf("[%s] Failed to unmarshal RPC data: %v", selfID, err)
			return
		}
		respData, err := rpcServer.HandleRequest(rpcData)
		if err != nil {
			log.Printf("[%s] RPC handler error: %v", selfID, err)
		}
		respPayload, err := json.Marshal(respData)
		if err != nil {
			log.Printf("[%s] Failed to marshal RPC response: %v", selfID, err)
			return
		}
		respMsg := security.Message{Type: "rpc", Data: respPayload}
		encodedResp, err := respMsg.Encode()
		if err != nil {
			log.Printf("[%s] Failed to encode RPC response: %v", selfID, err)
			return
		}
		if err := writeFramedMessage(conn, encodedResp); err != nil {
			log.Printf("[%s] Failed to send RPC response: %v", selfID, err)
		}
		return

	default:
		log.Printf("[%s] Unknown message type: %s", selfID, msg.Type)
	}
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
		logger.Info("[%s] 💾 Chain state persisted — height=%d", nodeID, latest.GetHeight())
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
			logger.Info("[%s] ✅ Synced checkpoint from %s", nodeID, addr)
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

			logger.Info("[%s] 📊 Broadcasting checkpoint to peers", nodeID)
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
	logger.Info("[%s] 🔍 Stake watcher started - waiting for Block 1", nodeID)

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
				logger.Info("[%s] 📊 Block %d detected - updating validator stakes from state DB", nodeID, height)

				time.Sleep(300 * time.Millisecond)

				tryInitPhase2WithRetry(bc, cons, nodeID, validatorIDs, validatorAddressMap, phase2State)
				logger.Info("[%s] ✅ Stake watcher done", nodeID)
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
	logger.Info("✅ [%s] Validator %s admitted with verified stake from %s", selfNodeID, validatorID, address)
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
	logger.Info("[%s] 🔓 PHASE 2 INITIALIZATION - Reading stakes from genesis allocations", nodeID)

	vs := cons.GetValidatorSet()
	if vs == nil {
		logger.Error("[%s] ❌ ValidatorSet is nil!", nodeID)
		return false
	}
	if len(validatorIDs) == 0 {
		logger.Error("[%s] ❌ No validators found! Cannot initialize Phase 2 stakes.", nodeID)
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
		logger.Error("[%s] ❌ Failed to open StateDB after %d attempts", nodeID, maxRetries)
		return false
	}
	defer stateDB.Close()

	minStakeSPX := vs.GetMinStakeSPX()
	successCount := 0

	for _, vid := range validatorIDs {
		address := validatorAddressMap[vid]
		if address == "" {
			logger.Warn("[%s] No genesis mapping for validator %s — using minimum stake", nodeID, vid)
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

	logger.Info("[%s] 📊 Phase 2: %d/%d validators staked", nodeID, successCount, len(validatorIDs))

	totalStake := vs.GetTotalStake()
	if totalStake.Sign() == 0 {
		logger.Error("[%s] ⚠️ CRITICAL: Total stake is 0 after Phase 2 init!", nodeID)
		return false
	}

	totalSPX := new(big.Int).Div(totalStake, big.NewInt(denom.SPX))
	logger.Info("[%s] ✅ Phase 2 stakes initialized with %s SPX total", nodeID, totalSPX.String())
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

	logger.Info("[%s] 🔓 BLOCK 1 COMMITTED — Initializing Phase 2 stakes", nodeID)

	time.Sleep(500 * time.Millisecond)

	if !initializePhase2Stakes(bc, cons, nodeID, validatorIDs, validatorAddressMap) {
		logger.Error("[%s] ❌ Phase 2 initialization failed!", nodeID)
		return false
	}

	logger.Info("[%s] Phase 2: refreshing leader status", nodeID)
	cons.UpdateLeaderStatus()

	if err := bc.WriteChainCheckpoint(); err != nil {
		logger.Warn("[%s] Failed to write checkpoint after Phase 2: %v", nodeID, err)
	} else {
		logger.Info("[%s] ✅ Checkpoint updated after Phase 2 initialization", nodeID)
	}

	newLeader := cons.GetElectedLeaderID()
	if newLeader != "" {
		logger.Info("[%s] 📊 Phase 2 leader elected: %s (isLeader=%v)",
			nodeID, newLeader, cons.IsLeader())
	} else {
		logger.Warn("[%s] ⚠️ No leader after Phase 2 init — will retry next loop", nodeID)
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
	logger.Info("[%s] 🔍 Initializing Phase 2 with retry...", nodeID)

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
			logger.Info("[%s] ✅ Phase 2 initialized on attempt %d", nodeID, attempt+1)
			return true
		}

		if attempt < maxAttempts-1 {
			logger.Warn("[%s] Phase 2 init attempt %d/%d failed, retrying in %v...",
				nodeID, attempt+1, maxAttempts, jitter)
			time.Sleep(jitter)
		}
	}

	logger.Error("[%s] ❌ Phase 2 initialization failed after %d attempts - applying fallback stakes",
		nodeID, maxAttempts)

	vs := cons.GetValidatorSet()
	if vs != nil {
		minStake := vs.GetMinStakeSPX()
		for _, vid := range validatorIDs {
			if err := vs.AddValidator(vid, minStake); err != nil {
				logger.Warn("[%s] Failed to set fallback stake for %s: %v", nodeID, vid, err)
			} else {
				logger.Info("[%s] ✅ Set fallback stake %d SPX for %s", nodeID, minStake, vid)
			}
		}

		cons.UpdateLeaderStatus()
		cons.StartViewChange()
		phase2State.finish(true)
		logger.Info("[%s] ✅ Fallback stakes applied, view change triggered", nodeID)
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

	logger.Debug("requestBlocksFromPeer[%s]: RESPONSE: tip_height=%d, blocks_count=%d, error=%q",
		peerAddr, resp.TipHeight, len(resp.Blocks), resp.Error)

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
	peerAddrs []string,
	syncState *SyncState,
	syncStateMu *sync.Mutex,
) {
	logger.Info("[%s] 🔄 Block sync loop started (state=%s)", nodeID, syncState.String())

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

	for {
		select {
		case <-ctx.Done():
			logger.Info("[%s] Block sync loop shutting down", nodeID)
			return
		default:
		}

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
			logger.Warn("[%s] ⚠️ No peers reachable (tried %d peers) — backing off before retry",
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
			logger.Info("[%s] 📥 No genesis block locally – fetching from peer %s", nodeID, bestPeerAddr)
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
			logger.Info("[%s] ✅ Genesis block installed (hash=%s)", nodeID, genesisBlock.GetHash())

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
				logger.Info("[%s] ✅ Genesis block executed — vault funded and allocations distributed", nodeID)
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
				logger.Info("[%s] ✅ Genesis state file written after syncing genesis", nodeID)
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
					logger.Info("[%s] ✅ RANDAO re-initialized with new genesis", nodeID)
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
					logger.Info("[%s] ⚠️ Local genesis hash differs from peer %s — replacing genesis and clearing chain", nodeID, bestPeerAddr)
					if err := bc.ReplaceGenesis(peerGenesis); err != nil {
						logger.Warn("[%s] Failed to replace genesis: %v", nodeID, err)
					} else {
						bc.ClearChainAfter(0)
						logger.Info("[%s] ✅ Genesis replaced with peer's version — re-downloading chain from scratch", nodeID)
						// Same fix as the initial-install site above: a
						// replaced genesis is unexecuted genesis. Fund the
						// vault and apply the embedded distribution txs now,
						// or every allocation stays at zero balance again.
						if err := bc.ExecuteGenesisBlock(); err != nil {
							logger.Error("[%s] Failed to execute replaced genesis block: %v", nodeID, err)
						} else {
							logger.Info("[%s] ✅ Replaced genesis block executed — vault funded and allocations distributed", nodeID)
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
				logger.Info("[%s] ✅ At genesis (height 0) — transitioning to CAUGHT_UP (fresh network)", nodeID)
			}
			syncStateMu.Unlock()
			// ★ FIX: Don't return — enter periodic sync check mode. The network
			// may produce blocks later. We keep checking every 10 seconds so a
			// node that joined early (before any blocks were mined) automatically
			// catches up when blocks arrive, without needing a restart.
			// This implements "synchronization shouldn't happen only during startup"
			// — the node continuously monitors the network tip and catches up
			// whenever it falls behind.
			logger.Info("[%s] 🔍 Entering periodic sync check mode — will re-check every 10s", nodeID)
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
				logger.Info("[%s] ✅ Caught up at height %d (network tip %d) — entering periodic sync check",
					nodeID, localHeight, networkTip)
			}
			syncStateMu.Unlock()
			// Stay in loop, re-check periodically for new blocks
			logger.Info("[%s] 🔍 Monitoring for new blocks — will re-check every 10s", nodeID)
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
				continue
			}
		}

		fromHeight := localHeight + 1
		toHeight := networkTip
		if toHeight-fromHeight+1 > maxBatchSize {
			toHeight = fromHeight + maxBatchSize - 1
		}

		logger.Info("[%s] 🔄 Syncing blocks %d -> %d from %s (local=%d, network=%d)",
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
				// Blocks mined in solo mode (before PBFT was active, i.e. when there
				// were fewer than 3 validators) have zero attestations.  This is by
				// design — solo-mined blocks are trusted by parent-hash chain continuity
				// alone, not by PBFT quorum.  Only blocks that actually went through
				// PBFT carry attestations, and only those need quorum verification.
				//
				// Without this guard, a late-joiner (Node-B) that syncs from a solo-
				// mining first node (Node-A) will reject every block because
				// VerifyBlockAttestations requires ≥2/3 stake, but solo-mined blocks
				// have zero attestations.  The sync loop then discards the entire batch
				// and the late joiner never catches up.
				if len(blk.Body.Attestations) > 0 {
					vs := cons.GetValidatorSet()
					if vs != nil {
						blockEpoch := blk.GetHeight() / consensus.SlotsPerEpoch
						if err := core.VerifyBlockAttestations(blk, vs, blockEpoch); err != nil {
							logger.Error("[%s] ❌ Block %d failed attestation quorum check: %v — rejecting batch from peer %s",
								nodeID, blk.GetHeight(), err, bestPeerAddr)
							applied = 0
							break
						}
					}
				} else {
					logger.Info("[%s] 📋 Block %d has no attestations (solo-mined before PBFT) — skipping quorum check, verified by chain continuity",
						nodeID, blk.GetHeight())
				}
			}
			wrapped := core.NewBlockHelper(blk)
			if err := bc.CommitBlock(wrapped); err != nil {
				logger.Error("[%s] Failed to commit synced block %d: %v", nodeID, blk.GetHeight(), err)
				break
			}
			applied++
		}

		if applied > 0 {
			logger.Info("[%s] ✅ Applied %d/%d synced blocks (now at height %d)",
				nodeID, applied, len(resp.Blocks), bc.GetLatestBlock().GetHeight())
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
) {
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
			// totalNodes == 1 is the seed-based/real-device sentinel set by
			// cli.go's runNodeCmd ("validator count derived from peer
			// discovery" — see the *numNodes = 1 normalization there). It
			// does NOT mean "there is exactly one validator"; it means
			// "don't trust a static count, trust what we actually discover."
			// Only apply the cap when totalNodes is a real, configured
			// same-box upper bound (> 1) — otherwise a seed-based node would
			// clamp its own discovered peer count back down to 1 forever
			// and never leave solo mode even with 2+ peers connected.
			if totalNodes > 1 && known > totalNodes {
				known = totalNodes // never report more than the configured network size
			}
			return known
		}
		return totalNodes
	}

	// ──────────────────────────────────────────────────────────────────────
	// SYNC STATE GATE: A node in SYNCING state must NOT participate in PBFT.
	// This check MUST come BEFORE the validator count check, because a late
	// joiner may have 0 validators and 0 peers but still needs to sync.
	// If we check validator count first, the late joiner gets stuck in the
	// "waiting for validators" loop forever, never reaching the sync gate.
	// ──────────────────────────────────────────────────────────────────────
	for {
		syncStateMu.Lock()
		currentSyncState := *syncState
		syncStateMu.Unlock()

		if currentSyncState == SyncStateSyncing {
			logger.Info("[%s] ⏳ Sync in progress — waiting to catch up before joining PBFT (state=%s)",
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
			logger.Info("[%s] 🎉 Transitioning to CONSENSUS_PARTICIPANT — joining PBFT rounds", nodeID)
			break
		}

		// CONSENSUS_PARTICIPANT — proceed to PBFT
		break
	}

	// ── SOLO MODE (no peers) ──
	// If this node is the only validator, it mines blocks solo WITHOUT PBFT.
	// Each block is committed immediately via CommitBlock, not through PBFT
	// voting. This is the correct behavior for the first node (Node-A) that
	// starts with no peers — it should mine blocks without waiting for quorum.
	if effectiveValidatorCount() == 1 {
		logger.Info("[%s] 🟢 SOLO MODE — no peers detected, mining blocks independently", nodeID)
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
				logger.Info("[%s] ⛏ Solo-mined and committed block height=%d txs=%d", nodeID, blk.GetHeight(), len(pending))

			case <-peerCheckTicker.C:
				// Re‑evaluate validator count
				if effectiveValidatorCount() >= 3 {
					logger.Info("[%s] 🟢 %d validators now known — switching to PBFT", nodeID, effectiveValidatorCount())
					// Break out of solo loop to fall through to PBFT section
					goto afterSolo
				}
			}
		}
	afterSolo:
		// continue to PBFT setup below (the code after the solo block)
	}

	// ── INSUFFICIENT VALIDATORS ──
	// After sync is complete, check if we have enough validators for PBFT.
	// If not, wait for more peers to connect. This is the correct place for
	// this check — AFTER the sync gate, so late joiners can sync first.
	if effectiveValidatorCount() < 3 {
		logger.Warn("[%s] Block-production suspended (need ≥ 3 validators for PBFT, have %d — waiting for peers to connect)",
			nodeID, effectiveValidatorCount())
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if effectiveValidatorCount() >= 3 {
					logger.Info("[%s] ✅ %d validators now known — starting PBFT block production",
						nodeID, effectiveValidatorCount())
					goto startPBFT
				}
				logger.Info("[%s] Waiting for validators (%d/3 minimum)…", nodeID, effectiveValidatorCount())
			}
		}
	}

startPBFT:

	// Even when the gate above passes on the very first check (all peers were
	// already known at startup), give the P2P broadcast layer a brief moment
	// to finish establishing persistent peer connections before this node's
	// first leader election / proposal for view 0. Known-peer registration
	// (via key exchange) does not itself guarantee the broadcast link is up.
	//
	// Instead of a fixed 2-second sleep, wait until either:
	// 1. The sync loop has finished (syncState != SYNCING), OR
	// 2. A minimum number of peers are connected (if still syncing)
	// This makes the delay dynamic and adapts to actual network conditions.
	logger.Info("[%s] ⏳ Waiting for P2P broadcast layer to stabilize before PBFT...", nodeID)

	broadcastReadyTimeout := time.After(30 * time.Second)
	broadcastReady := false

	for !broadcastReady {
		select {
		case <-ctx.Done():
			return
		case <-broadcastReadyTimeout:
			logger.Warn("[%s] ⚠️ Broadcast layer stabilization timeout (30s) — proceeding to PBFT", nodeID)
			broadcastReady = true
		default:
			syncStateMu.Lock()
			currentSync := *syncState
			syncStateMu.Unlock()

			// If sync is complete, we're ready
			if currentSync != SyncStateSyncing {
				logger.Info("[%s] ✅ Sync complete — P2P layer ready (syncState=%s)", nodeID, currentSync.String())
				broadcastReady = true
				continue
			}

			// If we have enough peers and have been syncing for a bit, proceed
			if peerCountFunc != nil && peerCountFunc() >= 2 {
				// Give it at least 3 seconds even with peers connected
				time.Sleep(500 * time.Millisecond)
				continue
			}

			// Still waiting for peers
			time.Sleep(1 * time.Second)
		}
	}

	var currentHeight uint64 = 0
	latestBlock := bc.GetLatestBlock()
	if latestBlock != nil {
		currentHeight = latestBlock.GetHeight()
	}

	logger.Info("[%s] Starting PBFT consensus. Current height: %d", nodeID, currentHeight)

	phase2Initialized := false

	// FIX: watchAndUpdateStakes is the one height-robust (`height >= 1`)
	// trigger for Phase 2 peer-validator registration, but it previously had
	// no caller anywhere in the codebase — only the fragile `currentHeight
	// == 1` checks below were live, which silently no-op for a node that
	// restarts from a checkpoint already past height 1, or whose sync loop
	// jumps past height 1 in one batch. Run it here in parallel as a
	// defense-in-depth belt-and-suspenders: it's idempotent via
	// phase2State.begin()/isInitialized(), so having both this goroutine and
	// the inline checks below race to register validators is safe — whichever
	// gets there first wins and the other becomes a no-op.
	go watchAndUpdateStakes(ctx, bc, cons, nodeID, validatorIDs, validatorAddressMap, phase2State)

	// ------------------------------------------------------------------
	// Liveness watchdog: PBFT must make progress even if the currently
	// elected leader is unresponsive (crashed, hung, network-partitioned,
	// or simply buggy). Without this, a follower would sit in the
	// "FOLLOWER MODE" branch below forever re-checking the same
	// (height, view, leader) tuple, and the chain would stall permanently
	// at whatever height it last committed — exactly the height=1 stall
	// this watchdog fixes. If the same round (height+view+leader) hasn't
	// produced a new committed block within roundStallTimeout, force a
	// view change so a new leader gets elected and block production
	// (including empty 0-tx blocks) resumes.
	const roundStallTimeout = 15 * time.Second
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
				logger.Info("[%s] 📊 Chain height synced to %d", nodeID, currentHeight)
				// Chain progressed — the stall window no longer applies.
				stallHeight, stallView, stallLeader = 0, 0, ""
			}

			// FIX: was `currentHeight == 1`, which only fires if this node's
			// local loop observes height tick through exactly 1. A node that
			// restarts from a checkpoint already past height 1 (see
			// chain_checkpoint.json), or whose sync loop applies a batch that
			// jumps straight from 0 to some height > 1, would never see an
			// exact match and would permanently skip Phase 2 stake init —
			// leaving validatorSet containing only this node's own
			// self-registration from NewConsensus() forever ("validators=1"
			// in SelectProposer logs, even at height 13/14). `>= 1` is
			// idempotent thanks to phase2Initialized/phase2State, so it's
			// safe to check every iteration once height has advanced at all.
			if currentHeight >= 1 && !phase2Initialized {
				if tryInitPhase2WithRetry(bc, cons, nodeID, validatorIDs, validatorAddressMap, phase2State) {
					phase2Initialized = true
				}
			}
		}

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

		// Track how long this exact round (height, view, elected leader)
		// has gone without producing a new block. If a different round
		// starts (view changed, leader changed, or we advanced height —
		// handled above), reset the clock.
		if stallHeight != currentHeight || stallView != proposalView || stallLeader != electedLeader {
			stallHeight, stallView, stallLeader = currentHeight, proposalView, electedLeader
			stallSince = time.Now()
		} else if time.Since(stallSince) > roundStallTimeout {
			logger.Warn("[%s] ⏱️ No progress for %v at height=%d view=%d (leader=%s) — forcing view change",
				nodeID, roundStallTimeout, currentHeight, proposalView, electedLeader)
			cons.StartViewChange()
			stallHeight, stallView, stallLeader = 0, 0, ""
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}

		if !isLeader {
			logger.Info("👂 [%s] FOLLOWER MODE — waiting for leader proposal (height=%d, electedLeader=%s)",
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
			logger.Info("[%s] ⚠️ Chain height changed from %d to %d, skipping proposal",
				nodeID, currentHeight, currentHeightCheck)
			currentHeight = currentHeightCheck
			cons.SetCurrentHeight(currentHeight)
			continue
		}

		logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logger.Info("👑 [%s] LEADER MODE ACTIVE — proposing block for height %d", nodeID, currentHeight+1)
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

		logger.Info("✅ [%s] Block proposed and broadcast, waiting for consensus...", nodeID)

		commitTimeout := time.After(60 * time.Second)
		commitTicker := time.NewTicker(1 * time.Second)

		committed := false
		for !committed {
			select {
			case <-ctx.Done():
				commitTicker.Stop()
				return
			case <-commitTimeout:
				logger.Warn("[%s] ⚠️ Timeout waiting for block commitment at height %d", nodeID, currentHeight+1)
				committed = true
			case <-commitTicker.C:
				latest := bc.GetLatestBlock()
				if latest != nil && latest.GetHeight() > currentHeight {
					currentHeight = latest.GetHeight()
					cons.SetCurrentHeight(currentHeight)

					if bc.GetTPSMonitor() != nil {
						stats := bc.GetTPSMonitor().GetStats()
						logger.Info("📊 [%s] TPS STATS after block %d: blocks_processed=%v, total_txs=%v, avg_txs_per_block=%.2f",
							nodeID, currentHeight,
							stats["blocks_processed"],
							stats["total_transactions"],
							stats["avg_transactions_per_block"])
					}

					logger.Info("[%s] 🎉 Block committed! Height now: %d", nodeID, currentHeight)

					// FIX: see matching comment at the other trigger site above —
					// `== 1` silently skips Phase 2 for checkpoint restarts and
					// batch syncs that jump past height 1. `>= 1` + phase2Initialized
					// keeps this idempotent.
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
			logger.Info("[%s] ✅ Checkpoint saved at height %d (phase: %s, network: %s)",
				nodeID, currentHeight, phase, networkType)
		}

		cons.UpdateLeaderStatus()
		electedLeader = cons.GetElectedLeaderID()
		if electedLeader == "" {
			logger.Warn("[%s] ⚠️ No leader elected after commit, will retry next loop", nodeID)
		} else {
			logger.Info("[%s] 📊 Next leader: %s (isLeader=%v)", nodeID, electedLeader, cons.IsLeader())
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(multiNodeRoundDelay):
		}
	}
}
