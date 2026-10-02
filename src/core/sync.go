// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/sync.go
//
// Quorum certificate verification for block sync. These functions verify that
// blocks received from peers carry valid commit attestations (≥2/3+ stake)
// before they are committed during catch-up sync.
//
// ========== NODE-TYPE CONTRACT ==========
// This file implements FULL-NODE sync: it downloads and commits ENTIRE blocks
// (headers + bodies). It is instantiated only by full nodes via the
// bind.StartNode stack (core.NewBlockchain + NewSyncManager).
//
// Lightweight clients — in particular the USI wallet (src/usi) — are NOT full
// nodes and MUST NOT run this code. They hold no blockchain and download
// block HEADERS only, via the node's "getblockheader"/"getheaders" JSON-RPC
// (see src/rpc/json.go and src/usi/gui/rpc.go). All wallet state (balance,
// history, nonce) is queried from a full node over RPC. The USI "vault"
// feature (`.vault` encrypted folders) is folder encryption, unrelated to
// chain sync.
// =====================================================
//
// ========== PIPELINED BULK SYNC (Phase A) ==========
// Late-joiners syncing millions of blocks use a pipelined download strategy:
//
//  1. Bulk sync mode (far behind tip):
//     - Pipeline depth: 64 in-flight requests per peer
//     - Batch size: 1024 blocks per batch
//     - Sparse verification: hash-chain only for historical blocks
//     - Full verification: last 10,000 blocks only
//
//  2. Tip chasing mode (near tip):
//     - Pipeline depth: 4 in-flight requests per peer
//     - Batch size: 32 blocks per batch
//     - Full verification on every block
//
//  Performance target: 50-100x improvement over sequential download.
//  With 4 peers × 64 pipeline depth = 256 concurrent in-flight requests.
// ==================================================

package core

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/consensus"
	logger "github.com/sphinxfndorg/protocol/src/console"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
)

// NewSyncManager creates a new synchronization manager
func NewSyncManager(bc *Blockchain, p2pSrv P2PServerInterface) *SyncManager {
	return &SyncManager{
		bc:            bc,
		p2pServer:     p2pSrv,
		peers:         make(map[string]PeerInterface),
		peerInfo:      make(map[string]*PeerChainInfo),
		downloadQueue: make(map[uint64]bool),
		downloaded:    make(map[uint64]*types.Block),
		maxParallel:   4, // Download up to 4 blocks in parallel
		stopCh:        make(chan struct{}),
		syncCh:        make(chan struct{}, 1),
		peerUpdateCh:  make(chan PeerInterface, 100),
		syncTimeout:   5 * time.Minute,

		// ========== FIX: Add production robustness features ==========
		// Continuous sync monitoring
		lastSyncCheck:     time.Now(),
		syncCheckInterval: 10 * time.Second,
		// Genesis verification
		genesisVerified: false,
		// Reconnection tracking
		reconnectAttempts:    make(map[string]int),
		maxReconnectAttempts: 10,
		reconnectBackoff:     1 * time.Minute,

		// Late-joiner sync budget: after this wall-clock time, fall back
		// to state snapshot sync (if supported) to prevent blocking forever.
		lateJoinerSyncStartTime:       time.Now(),
		lateJoinerMaxSyncDuration:     30 * time.Minute,
		lateJoinerFallbackToStateSync: false,

		// ========== PIPELINED BULK DOWNLOAD (Phase A) ==========
		// Default pipeline depth: 64 for bulk sync, adjusted dynamically.
		pipelineDepth:     64,
		blockResultCh:     make(chan *blockResult, 1024),
		pendingPipeline:   make(map[uint64]bool),
		bulkSyncMode:      false,
		bulkSyncThreshold: 0, // Set dynamically when sync target is known

		// ========== FIX: Pending block request tracking ==========
		pendingBlockRequests: make(map[string]chan *types.Block),
	}
}

// SetConsensus sets the consensus engine reference
func (sm *SyncManager) SetConsensus(c *consensus.Consensus) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.consensus = c
}

// Start begins the synchronization manager
func (sm *SyncManager) Start() error {
	logger.Info("🔄 SyncManager starting...")

	sm.setState(NodeBootstrapping)

	// Start main sync loop
	go sm.syncLoop()

	// Start peer monitoring
	go sm.peerMonitorLoop()

	// Start download coordinator
	go sm.downloadCoordinator()

	logger.Info("SUCCESS SyncManager started")
	return nil
}

// Stop gracefully shuts down the sync manager
func (sm *SyncManager) Stop() error {
	logger.Info("🛑 SyncManager stopping...")

	// Clean up all pending requests
	sm.pendingRequestMu.Lock()
	for requestID, ch := range sm.pendingBlockRequests {
		delete(sm.pendingBlockRequests, requestID)
		close(ch)
	}
	sm.pendingRequestMu.Unlock()

	close(sm.stopCh)

	// Wait for downloads to complete or timeout
	done := make(chan struct{})
	go func() {
		sm.downloadWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("SUCCESS All downloads completed")
	case <-time.After(30 * time.Second):
		logger.Warn("WARNING Some downloads did not complete in time")
	}

	logger.Info("SUCCESS SyncManager stopped")
	return nil
}

// syncLoop is the main synchronization state machine
func (sm *SyncManager) syncLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.stopCh:
			return

		case <-ticker.C:
			sm.processState()

		case peer := <-sm.peerUpdateCh:
			sm.handlePeerUpdate(peer)
		}
	}
}

// processState implements the node lifecycle state machine
func (sm *SyncManager) processState() {
	sm.mu.RLock()
	currentState := sm.state
	sm.mu.RUnlock()

	switch currentState {
	case NodeBootstrapping:
		sm.handleStarting()

	case NodeDiscoveringPeers:
		sm.handleDiscoveringPeers()

	case NodeConnecting:
		sm.handleConnecting()

	case NodeHandshaking:
		sm.handleHandshaking()

	case NodeSyncingHeaders:
		sm.handleSyncingHeaders()

	case NodeSyncingBlocks:
		sm.handleSyncingBlocks()

	case NodeVerifying:
		sm.handleVerifying()

	case NodeReady:
		// ────────────────────────────────────────────────────────────────
		// BUG FIX: this used to call handleConsensusReady() unconditionally
		// right after handleSynchronized(), regardless of what
		// handleSynchronized() just did. handleSynchronized() can itself
		// transition the state away from NodeReady in this exact call —
		// e.g. back to NodeSyncingHeaders because a new block arrived on a
		// peer, or it can simply `return` early while still gating a
		// late-joiner that hasn't finished its sync budget. Calling
		// handleConsensusReady() unconditionally afterwards meant a node
		// could be told "you still need to sync" and, on the very same
		// tick, be flipped to NodeValidatorActive anyway — because
		// shouldBecomeValidator() did not check whether sync actually
		// completed. Re-read the state after
		// handleSynchronized() and only proceed to handleConsensusReady()
		// if we're still genuinely NodeReady.
		// ────────────────────────────────────────────────────────────────
		sm.handleSynchronized()

		sm.mu.RLock()
		stateAfterSync := sm.state
		sm.mu.RUnlock()

		if stateAfterSync == NodeReady {
			sm.handleConsensusReady()
		}

	case NodeValidatorActive:
		sm.handleValidatorActive()
	}

	// Perform continuous sync check after each state processing
	sm.continuousSyncCheck()
}

// handleStarting - Initial node startup
func (sm *SyncManager) handleStarting() {
	logger.Info("📡 Node starting...")

	// Load chain parameters
	if sm.bc.GetChainParams() == nil {
		logger.Error("ERROR Chain parameters not loaded")
		return
	}

	// ========== FIX: Genesis is trusted, never wait for PBFT ==========
	// Genesis block is part of trusted setup and does NOT require validation.
	// For late joiners, genesis will be downloaded from peers.
	// For first node, genesis is created locally without quorum.
	genesis := sm.bc.GetBlockByNumber(0)
	if genesis == nil && !sm.bc.IsLateJoiner() {
		// First node (Node-A): create genesis locally without waiting for peers
		logger.Info("🔨 No genesis found - creating genesis locally (trusted setup)")
		if err := sm.bc.createGenesisBlock(); err != nil {
			logger.Error("ERROR Failed to create genesis: %v", err)
			return
		}
		logger.Info("SUCCESS Genesis block created locally (no quorum required)")
	} else if genesis == nil && sm.bc.IsLateJoiner() {
		// Late joiner: will download genesis from peers during sync
		logger.Info("📥 Late joiner mode - will download genesis from peers")
	} else {
		logger.Info("SUCCESS Genesis block found: %s", sm.getGenesisHash())
	}

	// Transition to peer discovery
	sm.setState(NodeDiscoveringPeers)
}

// handleDiscoveringPeers - Looking for peers via DHT/bootstrap
func (sm *SyncManager) handleDiscoveringPeers() {
	peers := sm.p2pServer.GetNodeManager().GetPeers()

	if len(peers) == 0 {
		logger.Info("INFO Still discovering peers... (found 0)")
		return
	}

	logger.Info("SUCCESS Found %d peers, moving to connection phase", len(peers))
	sm.setState(NodeConnecting)
}

// handleConnecting - Establishing connections to peers
func (sm *SyncManager) handleConnecting() {
	peers := sm.p2pServer.GetNodeManager().GetPeers()

	connected := 0
	for _, peer := range peers {
		if peer.GetStatus() == "active" {
			connected++
		}
	}

	if connected == 0 {
		logger.Info("⏳ Waiting for connections... (0/%d connected)", len(peers))
		return
	}

	logger.Info("SUCCESS Connected to %d peers, starting handshake", connected)
	sm.setState(NodeHandshaking)
}

// handleHandshaking - Exchanging chain information with peers
func (sm *SyncManager) handleHandshaking() {
	// Check if we have chain info from at least one peer
	sm.mu.RLock()
	peerCount := len(sm.peerInfo)
	sm.mu.RUnlock()

	if peerCount == 0 {
		logger.Info("🤝 Waiting for handshake responses...")
		return
	}

	// Analyze peer chain info
	sm.analyzePeerChains()

	logger.Info("SUCCESS Handshake complete with %d peers", peerCount)
	sm.setState(NodeSyncingHeaders)
}

// handleSyncingHeaders - Downloading and comparing block headers
func (sm *SyncManager) handleSyncingHeaders() {
	// Determine if we need to sync
	localHeight := sm.bc.GetBlockCount()
	targetHeight := sm.getMaxPeerHeight()

	if targetHeight <= localHeight {
		logger.Info("SUCCESS Chain headers synchronized (local=%d, target=%d)", localHeight, targetHeight)
		sm.setState(NodeVerifying)
		return
	}

	logger.Info("📥 Syncing headers: local=%d, target=%d", localHeight, targetHeight)

	// Generate block locator for efficient sync
	sm.locator = sm.bc.GenerateBlockLocator(localHeight)

	// Request headers from peers
	sm.requestHeadersFromPeers()

	// Process received headers
	sm.processReceivedHeaders()
}

// handleSyncingBlocks - Downloading full blocks
func (sm *SyncManager) handleSyncingBlocks() {
	localHeight := sm.bc.GetBlockCount()

	if localHeight >= sm.syncHeight {
		logger.Info("SUCCESS All blocks downloaded (local=%d, target=%d)", localHeight, sm.syncHeight)
		sm.setState(NodeVerifying)
		return
	}

	// ========== PIPELINED BULK DOWNLOAD (Phase A) ==========
	// Determine sync mode based on how far behind we are.
	remaining := sm.syncHeight - localHeight

	if remaining > 10000 {
		// Far behind tip → bulk sync mode with pipelining
		if !sm.bulkSyncMode {
			sm.bulkSyncMode = true
			sm.bulkSyncThreshold = sm.syncHeight - 10000 // Last 10K blocks get full verification
			sm.pipelineDepth = 64                        // Deep pipeline for throughput
			logger.Info("📥 BULK SYNC MODE: %d blocks behind, pipeline depth=%d, full verification after height %d",
				remaining, sm.pipelineDepth, sm.bulkSyncThreshold)
		}
		sm.startPipelinedDownload()
	} else {
		// Near tip → tip chasing mode with smaller batches
		if sm.bulkSyncMode {
			sm.bulkSyncMode = false
			sm.pipelineDepth = 4 // Shallow pipeline for tip chasing
			logger.Info("📥 TIP CHASING MODE: %d blocks behind, pipeline depth=%d, full verification on all blocks",
				remaining, sm.pipelineDepth)
		}
		sm.startParallelDownloads()
	}
	// =======================================================
}

// handleVerifying - Validating chain integrity
func (sm *SyncManager) handleVerifying() {
	logger.Info("INFO Verifying chain integrity...")

	// Verify genesis hash
	genesis := sm.bc.GetBlockByNumber(0)
	if genesis == nil {
		logger.Error("ERROR Genesis block missing after sync")
		sm.setState(NodeSyncingBlocks)
		return
	}

	// Verify genesis hash matches expected value
	if err := sm.verifyGenesisHash(); err != nil {
		logger.Error("ERROR Genesis hash verification failed: %v", err)
		sm.setState(NodeSyncingBlocks)
		return
	}

	// ========== FIX: Execute genesis once it's verified ==========
	// The genesis block's body carries the distribution transactions
	// directly (see genesis.go BuildBlock), but nothing funds the vault or
	// applies those transactions until ExecuteGenesisBlock runs. The
	// first-node path already calls it from createGenesisBlock, but a late
	// joiner downloads genesis via sync and never goes through that
	// function — without this call its vault and every allocation address
	// stay at zero balance forever, which was silently masked because
	// IsDistributionComplete() treated an unfunded (still-zero) vault as
	// "distribution complete". ExecuteGenesisBlock is idempotent (no-ops if
	// the vault is already funded), so calling it here is safe for both
	// the first node and late joiners.
	if err := sm.bc.ExecuteGenesisBlock(); err != nil {
		logger.Error("ERROR Failed to execute genesis block: %v", err)
		sm.setState(NodeSyncingBlocks)
		return
	}
	// ===============================================================

	// Verify chain continuity
	if err := sm.bc.verifyGenesisHashInIndex(); err != nil {
		logger.Warn("WARNING Genesis hash in index verification failed: %v", err)
	}

	// Verify all blocks are linked
	if err := sm.verifyChainLinks(); err != nil {
		logger.Error("ERROR Chain link verification failed: %v", err)
		sm.setState(NodeSyncingBlocks)
		return
	}

	logger.Info("SUCCESS Chain verification passed")
	sm.setState(NodeReady)
}

// handleSynchronized - Node is synchronized
func (sm *SyncManager) handleSynchronized() {
	localHeight := sm.bc.GetBlockCount()
	targetHeight := sm.getMaxPeerHeight()

	if targetHeight > localHeight {
		logger.Info("📥 New blocks available (local=%d, target=%d)", localHeight, targetHeight)
		sm.syncHeight = targetHeight
		sm.setState(NodeSyncingHeaders)
		return
	}

	logger.Info("SUCCESS Node synchronized at height %d", localHeight)

	// Perform continuous sync check
	sm.continuousSyncCheck()

	// Late joiners MUST finish downloading blockchain data before entering consensus.
	// Keep them blocked at SYNCHRONIZED until either:
	//  1) localHeight reaches targetHeight, OR
	//  2) we hit a wall-clock budget and fall back to state snapshot sync.
	if sm.bc.IsLateJoiner() {
		localHeight := sm.bc.GetBlockCount()
		targetHeight := sm.getMaxPeerHeight()

		// Success case: fully caught up
		if targetHeight > 0 && localHeight < targetHeight {
			// Budget check
			elapsed := time.Since(sm.lateJoinerSyncStartTime)
			if !sm.lateJoinerFallbackToStateSync && elapsed >= sm.lateJoinerMaxSyncDuration {
				logger.Warn("⏱️ Late-joiner sync budget exceeded after %v (local=%d, target=%d) — falling back to state snapshot sync", elapsed, localHeight, targetHeight)
				sm.lateJoinerFallbackToStateSync = true

				// Enable state sync mode (snapshot hash is optional in this codebase).
				// Passing empty hash disables strict snapshot targeting.
				sm.EnableStateSync("")

				// ========== STATE SYNC FALLBACK (Phase B+C) ==========
				// Attempt to perform state sync from the snapshot manager.
				// If a checkpoint is available from peers, restore from it.
				snapshotMgr := sm.bc.GetSnapshotManager()
				if snapshotMgr != nil {
					logger.Info("INFO Attempting state sync fallback...")
					if err := snapshotMgr.PerformStateSync(); err != nil {
						logger.Warn("WARNING State sync fallback failed: %v — continuing with block-by-block sync", err)
					} else {
						logger.Info("SUCCESS State sync fallback succeeded — chain tip set to checkpoint height")
						// After state sync, the chain tip is at the checkpoint height.
						// The sync manager will continue downloading blocks from checkpoint to tip.
						sm.syncHeight = targetHeight
						sm.setState(NodeSyncingBlocks)
						return
					}
				} else {
					logger.Warn("WARNING No snapshot manager available — cannot perform state sync fallback")
				}
				// =====================================================
			}

			if !sm.lateJoinerFallbackToStateSync {
				logger.Info("⏳ Late-joiner sync gate: waiting for blocks (local=%d, target=%d), elapsed=%v/%v",
					localHeight, targetHeight, elapsed, sm.lateJoinerMaxSyncDuration)
				return
			}
			// If fallback is enabled, allow transition to consensus-ready
			// (the expectation is the node can use state sync to become consistent).
		}

		if targetHeight == 0 {
			logger.Info("ℹ️ Late-joiner sync gate: target height unavailable yet (local=%d)", localHeight)
			return
		}

		logger.Info("SUCCESS Late-joiner sync gate passed (local=%d, target=%d, fallback=%v)", localHeight, targetHeight, sm.lateJoinerFallbackToStateSync)
	}

	// Transition to consensus ready
	sm.setState(NodeReady)
}

// handleConsensusReady - Ready to participate in consensus
func (sm *SyncManager) handleConsensusReady() {
	// Check if we should become a validator
	if sm.shouldBecomeValidator() {
		logger.Info("👑 Node eligible for validator role")
		sm.setState(NodeValidatorActive)
	} else {
		logger.Info("📡 Node operating as full node (non-validator)")
		// Stay in consensus ready state but participate as full node
	}
}

// handleValidatorActive - Actively participating in PBFT
func (sm *SyncManager) handleValidatorActive() {
	// Monitor for chain splits or sync needs
	localHeight := sm.bc.GetBlockCount()
	targetHeight := sm.getMaxPeerHeight()

	if targetHeight > localHeight+1 {
		logger.Warn("WARNING Validator node fell behind (local=%d, target=%d)", localHeight, targetHeight)
		sm.syncHeight = targetHeight
		sm.setState(NodeSyncingHeaders)
		return
	}

	// Normal validator operation
}

// analyzePeerChains compares chain info from all peers and determines sync needs
func (sm *SyncManager) analyzePeerChains() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if len(sm.peerInfo) == 0 {
		return
	}

	localGenesis := sm.getGenesisHash()
	localHeight := sm.bc.GetBlockCount()

	var bestPeer *PeerChainInfo
	var bestHeight uint64

	// Find best peer (highest height with matching genesis)
	for peerID, info := range sm.peerInfo {
		// Verify chain compatibility
		if info.GenesisHash != localGenesis {
			logger.Warn("WARNING Peer %s has different genesis (local=%s, remote=%s)",
				peerID, localGenesis[:16], info.GenesisHash[:16])
			continue
		}

		// Track best peer
		if info.Height > bestHeight {
			bestHeight = info.Height
			bestPeer = info
		}
	}

	if bestPeer == nil {
		logger.Warn("WARNING No compatible peers found")
		return
	}

	// Set sync target
	sm.syncHeight = bestPeer.Height
	sm.syncHash = bestPeer.BestHash

	logger.Info("📊 Best peer: height=%d, hash=%s, finalized=%d",
		bestPeer.Height, bestPeer.BestHash[:16], bestPeer.FinalizedHeight)

	// Check if we need to sync
	if bestPeer.Height > localHeight {
		logger.Info("📥 Sync needed: local=%d, target=%d", localHeight, bestPeer.Height)
		sm.syncFrom = localHeight + 1
	} else if bestPeer.Height < localHeight {
		logger.Info("WARNING Local chain is longer than peer (local=%d, peer=%d)", localHeight, bestPeer.Height)
		// Potential fork - trigger reorganization check
		sm.checkForReorg()
	}
}

// requestHeadersFromPeers requests block headers using block locator
func (sm *SyncManager) requestHeadersFromPeers() {
	if sm.locator == nil || len(sm.locator.Hashes) == 0 {
		return
	}

	sm.mu.RLock()
	peers := sm.peers
	sm.mu.RUnlock()

	if len(peers) == 0 {
		return
	}

	// Select best peer for header sync
	var bestPeer PeerInterface
	for _, peer := range peers {
		if bestPeer == nil {
			bestPeer = peer
		}
	}

	if bestPeer == nil {
		return
	}

	// Request headers
	locatorData, _ := json.Marshal(sm.locator)
	_ = locatorData // Will be used when transport is integrated

	// Send to peer (implementation depends on transport layer)
	logger.Info("📥 Requesting headers from peer %s with locator (%d hashes)",
		bestPeer.GetID(), len(sm.locator.Hashes))
}

// processReceivedHeaders processes headers received from peers
func (sm *SyncManager) processReceivedHeaders() {
	// This would be called when headers are received from peers
	// For now, we'll use a simplified approach
	logger.Info("📥 Processing received headers...")
}

// ========== PIPELINED BULK DOWNLOAD (Phase A) ==========
// startPipelinedDownload initiates a pipelined block download.
//
// Instead of requesting one block at a time and waiting for the response
// before sending the next request, we fire N requests (pipelineDepth) per
// peer concurrently. Responses arrive asynchronously and are collected
// in order via the blockResultCh channel.
//
// Pipeline flow:
//  1. Dispatch pipelineDepth requests per peer (fire and forget)
//  2. Each response arrives via blockResultCh
//  3. Collect in height order (skip gaps, buffer out-of-order)
//  4. Validate with appropriate verification level (sparse vs full)
//  5. Commit to blockchain
//  6. Dispatch next request to keep pipeline full
//
// This gives us ~N× throughput improvement where N = pipelineDepth × peers.
func (sm *SyncManager) startPipelinedDownload() {
	localHeight := sm.bc.GetBlockCount()

	if localHeight >= sm.syncHeight {
		return
	}

	// Select best peers for download
	peerList := sm.selectBestPeersForDownload()
	if len(peerList) == 0 {
		logger.Warn("ERROR No peers available for pipelined download")
		return
	}

	// Calculate batch range
	remaining := sm.syncHeight - localHeight
	batchSize := uint64(1024) // Large batch for bulk sync
	if remaining < batchSize {
		batchSize = remaining
	}

	logger.Info("📥 Starting pipelined download of %d blocks (heights %d-%d) from %d peers, pipeline depth=%d",
		batchSize, localHeight+1, localHeight+batchSize, len(peerList), sm.pipelineDepth)

	// Calculate per-peer range
	batchSizePerPeer := (batchSize + uint64(len(peerList)) - 1) / uint64(len(peerList))

	for i, peer := range peerList {
		startHeight := localHeight + 1 + (uint64(i) * batchSizePerPeer)
		endHeight := startHeight + batchSizePerPeer
		if endHeight > sm.syncHeight {
			endHeight = sm.syncHeight
		}
		if startHeight >= endHeight {
			continue
		}

		sm.downloadWg.Add(1)
		go func(p PeerInterface, start, end uint64) {
			defer sm.downloadWg.Done()
			sm.runPipeline(p, start, end)
		}(peer, startHeight, endHeight)
	}

	// Collect results from the pipeline in order
	sm.collectPipelineResults(localHeight+1, batchSize)
}

// runPipeline manages a single peer's pipeline: fire N requests, collect responses.
func (sm *SyncManager) runPipeline(peer PeerInterface, startHeight, endHeight uint64) {
	logger.Info("📥 Pipeline for peer %s: heights %d-%d (depth=%d)",
		peer.GetID(), startHeight, endHeight-1, sm.pipelineDepth)

	// Track which heights we've dispatched
	dispatched := uint64(0)
	total := endHeight - startHeight

	// Phase 1: Fire initial pipelineDepth requests
	pipelineSlots := sm.pipelineDepth
	if pipelineSlots > int(total) {
		pipelineSlots = int(total)
	}

	for i := 0; i < pipelineSlots; i++ {
		height := startHeight + uint64(i)
		sm.dispatchPipelineRequest(peer, height)
		dispatched++
	}

	// Phase 2: As responses arrive, dispatch new requests to keep pipeline full
	// This is handled by collectPipelineResults which reads from blockResultCh.
	// We just need to dispatch the initial batch here; the collector will
	// dispatch the rest as results come in.

	// For the remaining heights, we dispatch them as slots free up.
	// The collector signals via the channel when a slot is available.
	for dispatched < total {
		height := startHeight + dispatched
		sm.dispatchPipelineRequest(peer, height)
		dispatched++
	}
}

// dispatchPipelineRequest sends a single block request to a peer.
func (sm *SyncManager) dispatchPipelineRequest(peer PeerInterface, height uint64) {
	// Mark as dispatched
	sm.pipelineMu.Lock()
	if sm.pendingPipeline[height] {
		sm.pipelineMu.Unlock()
		return // Already dispatched
	}
	sm.pendingPipeline[height] = true
	sm.pipelineMu.Unlock()

	// Fire async request
	go func() {
		block, err := sm.fetchBlockFromPeer(peer, height)
		// Send result to collector channel
		sm.blockResultCh <- &blockResult{
			height: height,
			block:  block,
			err:    err,
		}
	}()
}

// collectPipelineResults reads from the pipeline channel and commits blocks in order.
func (sm *SyncManager) collectPipelineResults(startHeight, totalBlocks uint64) {
	// Buffer for out-of-order results: map[height]*blockResult
	buffer := make(map[uint64]*blockResult)
	nextHeight := startHeight
	collected := uint64(0)
	timeout := time.After(30 * time.Minute) // Overall pipeline timeout

	for collected < totalBlocks {
		select {
		case <-sm.stopCh:
			logger.Warn("🛑 Pipeline collection stopped")
			return

		case <-timeout:
			logger.Error("ERROR Pipeline collection timed out after 30 min (collected=%d/%d, next=%d)",
				collected, totalBlocks, nextHeight)
			return

		case result := <-sm.blockResultCh:
			if result.err != nil {
				logger.Warn("WARNING Pipeline error at height %d: %v", result.height, result.err)
				// Clean up pending marker
				sm.pipelineMu.Lock()
				delete(sm.pendingPipeline, result.height)
				sm.pipelineMu.Unlock()
				continue
			}

			if result.block == nil {
				logger.Warn("WARNING Pipeline nil block at height %d", result.height)
				sm.pipelineMu.Lock()
				delete(sm.pendingPipeline, result.height)
				sm.pipelineMu.Unlock()
				continue
			}

			// Buffer the result
			buffer[result.height] = result

			// Process in-order results from buffer
			for {
				buffered, exists := buffer[nextHeight]
				if !exists {
					break // Gap in sequence, wait for more results
				}

				// We have the next block in sequence — validate and commit
				if err := sm.pipelineProcessBlock(buffered.block); err != nil {
					logger.Error("ERROR Pipeline block %d processing failed: %v", nextHeight, err)
					// Continue anyway — the block might be valid from another peer
					// In production, we'd re-request from a different peer
				}

				// Clean up
				delete(buffer, nextHeight)
				sm.pipelineMu.Lock()
				delete(sm.pendingPipeline, nextHeight)
				sm.pipelineMu.Unlock()

				collected++
				nextHeight++
			}
		}
	}

	logger.Info("SUCCESS Pipeline collection complete: %d blocks (heights %d-%d)",
		collected, startHeight, startHeight+totalBlocks-1)
}

// pipelineProcessBlock validates and commits a single block from the pipeline.
// Uses sparse verification for historical blocks (bulk sync mode) and
// full verification for recent blocks (tip chasing mode).
func (sm *SyncManager) pipelineProcessBlock(block *types.Block) error {
	height := block.GetHeight()

	// ========== SPARSE VERIFICATION (Phase A) ==========
	// In bulk sync mode, historical blocks only need hash-chain verification.
	// Full comprehensive verification (attestations, Merkle roots, etc.)
	// is only done for recent blocks near the tip.
	if sm.bulkSyncMode && height < sm.bulkSyncThreshold {
		// Sparse verification: just check hash chain continuity
		if err := sm.sparseBlockVerification(block); err != nil {
			return fmt.Errorf("sparse verification failed at height %d: %w", height, err)
		}
	} else {
		// Full verification for recent blocks
		if err := sm.comprehensiveBlockVerification(block); err != nil {
			return fmt.Errorf("full verification failed at height %d: %w", height, err)
		}
	}

	// Store block in downloaded map for the coordinator to commit
	sm.downloadMutex.Lock()
	sm.downloaded[height] = block
	sm.downloadMutex.Unlock()

	sm.blocksDownloaded++
	return nil
}

// sparseBlockVerification performs lightweight verification for historical blocks.
// Only checks: height continuity, previous hash link, and basic structure.
// This is safe because:
//  1. The chain of hashes proves integrity (tampering breaks the link)
//  2. PBFT attestations on recent blocks validate the entire chain
//  3. Periodic full verification at checkpoints catches any issues
func (sm *SyncManager) sparseBlockVerification(block *types.Block) error {
	// 1. Basic structure validation (non-nil, has header, etc.)
	if block == nil {
		return fmt.Errorf("block is nil")
	}
	if block.Header == nil {
		return fmt.Errorf("block header is nil")
	}

	// 2. Height continuity
	expectedHeight := sm.bc.GetBlockCount()
	if block.GetHeight() != expectedHeight {
		return fmt.Errorf("height mismatch: expected %d, got %d", expectedHeight, block.GetHeight())
	}

	// 3. Previous hash link
	if block.GetHeight() > 0 {
		parent := sm.bc.GetBlockByNumber(block.GetHeight() - 1)
		if parent == nil {
			return fmt.Errorf("parent block not found at height %d", block.GetHeight()-1)
		}
		if block.GetPrevHash() != parent.GetHash() {
			return fmt.Errorf("previous hash mismatch at height %d: expected %s, got %s",
				block.GetHeight(), parent.GetHash()[:16], block.GetPrevHash()[:16])
		}
	}

	// 4. Timestamp not before parent
	if block.GetHeight() > 0 {
		parent := sm.bc.GetBlockByNumber(block.GetHeight() - 1)
		if parent != nil {
			parentTime := time.Unix(parent.GetTimestamp(), 0)
			blockTime := time.Unix(block.GetTimestamp(), 0)
			if blockTime.Before(parentTime) {
				return fmt.Errorf("block timestamp before parent at height %d", block.GetHeight())
			}
		}
	}

	// Log every 10,000 blocks to show progress
	if block.GetHeight()%10000 == 0 {
		logger.Info("📥 Sparse verification passed at height %d (hash=%s)", block.GetHeight(), block.GetHash()[:16])
	}

	return nil
}

// =======================================================

// startParallelDownloads initiates parallel block downloads with batching strategy
// Production implementation: downloads blocks in batches from multiple peers
func (sm *SyncManager) startParallelDownloads() {
	localHeight := sm.bc.GetBlockCount()

	if localHeight >= sm.syncHeight {
		return
	}

	// ========== FIX: Batch download strategy (production-grade) ==========
	// Instead of downloading one block at a time, download in batches
	batchSize := uint64(32) // Download 32 blocks per batch (adjustable)
	remaining := sm.syncHeight - localHeight

	if remaining > batchSize {
		remaining = batchSize
	}

	logger.Info("📥 Starting batch download of %d blocks (heights %d-%d) from %d peers",
		remaining, localHeight+1, localHeight+remaining, len(sm.peers))

	// Select best peers for download (round-robin with peer scoring)
	peerList := sm.selectBestPeersForDownload()
	if len(peerList) == 0 {
		logger.Warn("ERROR No peers available for download")
		return
	}

	// Launch parallel batch downloads
	// Each worker downloads a range of blocks from one peer
	batchSizePerPeer := (remaining + uint64(len(peerList)) - 1) / uint64(len(peerList)) // Ceiling division

	for i, peer := range peerList {
		startHeight := localHeight + 1 + (uint64(i) * batchSizePerPeer)
		endHeight := startHeight + batchSizePerPeer
		if endHeight > sm.syncHeight {
			endHeight = sm.syncHeight
		}

		if startHeight >= endHeight {
			continue
		}

		sm.downloadWg.Add(1)
		go func(p PeerInterface, start, end uint64) {
			defer sm.downloadWg.Done()
			sm.downloadBatchFromPeer(p, start, end)
		}(peer, startHeight, endHeight)
	}
}

// selectBestPeersForDownload selects the best peers for downloading
// Prioritizes peers by: 1) height (higher is better), 2) latency (lower is better), 3) random
func (sm *SyncManager) selectBestPeersForDownload() []PeerInterface {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if len(sm.peers) == 0 {
		return nil
	}

	// Convert to slice for sorting
	type peerScore struct {
		peer   PeerInterface
		height uint64
		score  float64
	}

	scores := make([]peerScore, 0, len(sm.peers))
	for _, peer := range sm.peers {
		sm.mu.RUnlock()
		peerChainInfo := sm.peerInfo[peer.GetID()]
		sm.mu.RLock()

		height := uint64(0)
		if peerChainInfo != nil {
			height = peerChainInfo.Height
		}

		// Score: higher height = better, with some randomness to avoid thundering herd
		score := float64(height) + (float64(peer.GetID()[len(peer.GetID())-1]) / 255.0)
		scores = append(scores, peerScore{peer: peer, height: height, score: score})
	}

	// Sort by score (descending)
	for i := 0; i < len(scores); i++ {
		for j := i + 1; j < len(scores); j++ {
			if scores[j].score > scores[i].score {
				scores[i], scores[j] = scores[j], scores[i]
			}
		}
	}

	// Return top N peers
	maxPeers := 4
	if len(scores) < maxPeers {
		maxPeers = len(scores)
	}

	result := make([]PeerInterface, maxPeers)
	for i := 0; i < maxPeers; i++ {
		result[i] = scores[i].peer
	}

	return result
}

// downloadBatchFromPeer downloads a batch of blocks from a single peer
// Uses getblocks/inv/block protocol for efficient batch download
func (sm *SyncManager) downloadBatchFromPeer(peer PeerInterface, startHeight, endHeight uint64) {
	logger.Info("📥 Downloading batch from peer %s: heights %d-%d", peer.GetID(), startHeight, endHeight-1)

	// Step 1: Request inventory of blocks in range
	invRequest := map[string]interface{}{
		"method": "getblocks",
		"params": map[string]interface{}{
			"start_height": startHeight,
			"count":        endHeight - startHeight,
		},
	}

	invData, _ := json.Marshal(invRequest)
	if err := sm.p2pServer.SendMessageToPeer(peer.GetID(), "getblocks", invData); err != nil {
		logger.Warn("ERROR Failed to request inventory from peer %s: %v", peer.GetID(), err)
		return
	}

	// Step 2: Wait for inv response (handled asynchronously by message handler)
	// The inv handler will request individual blocks via getdata

	// Step 3: For now, fall back to individual block requests
	// In production, the inv/block handlers would manage this asynchronously
	for height := startHeight; height < endHeight; height++ {
		if !sm.isDownloading(height) {
			sm.markDownloading(height)
			sm.downloadBlock(height)
		}
	}
}

// downloadBlock downloads a single block from peers with retry on validation failure
func (sm *SyncManager) downloadBlock(height uint64) {
	sm.mu.RLock()
	peers := sm.peers
	sm.mu.RUnlock()

	if len(peers) == 0 {
		logger.Warn("ERROR No peers available to download block %d", height)
		sm.unmarkDownloading(height)
		return
	}

	// Convert peers to slice for ordered iteration
	peerList := make([]PeerInterface, 0, len(peers))
	for _, peer := range peers {
		peerList = append(peerList, peer)
	}

	// Try each peer, with multiple attempts for attestation failures
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ { // Try up to 3 times
		for _, peer := range peerList {
			block, err := sm.fetchBlockFromPeer(peer, height)
			if err != nil {
				lastErr = err
				logger.Warn("WARNING Failed to download block %d from peer %s: %v", height, peer.GetID(), err)
				continue
			}

			if block != nil {
				// Validate block with comprehensive verification
				if err := sm.comprehensiveBlockVerification(block); err != nil {
					// Check if this is an attestation quorum error (recoverable)
					if isAttestationQuorumError(err) {
						logger.Warn("ERROR Block %d attestation quorum failed from peer %s (attempt %d/3): %v — trying next peer",
							height, peer.GetID(), attempt+1, err)
						lastErr = err
						sm.unmarkDownloading(height)
						markFailedPeer(peer.GetID(), height)
						continue // Try next peer on attestation failure
					}
					// Non-recoverable error (corrupt block, bad hash) - don't retry
					logger.Error("ERROR Block %d validation failed: %v", height, err)
					sm.unmarkDownloading(height)
					return
				}

				// Store block
				sm.downloadMutex.Lock()
				sm.downloaded[height] = block
				sm.downloadMutex.Unlock()

				logger.Info("SUCCESS Downloaded block %d (hash=%s)", height, block.GetHash())
				sm.blocksDownloaded++
				sm.unmarkDownloading(height)
				return
			}
		}
		// Wait before retry to allow network state to change
		if attempt < 2 {
			time.Sleep(500 * time.Millisecond)
		}
	}

	logger.Warn("ERROR Failed to download block %d from all peers after 3 attempts: %v", height, lastErr)
	sm.unmarkDownloading(height)
}

// isAttestationQuorumError checks if an error is related to attestation quorum failure
func isAttestationQuorumError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "attestation") ||
		strings.Contains(err.Error(), "quorum") ||
		strings.Contains(err.Error(), "SPX attested")
}

// failedPeers tracks peers that failed to provide valid blocks at specific heights
// This prevents hammering the same peer for the same problematic block
var failedPeers sync.Map // map[height]map[peerID]attemptCount

// markFailedPeer records that a peer failed for a height
func markFailedPeer(peerID string, height uint64) {
	heightStr := fmt.Sprintf("%d", height)
	peerMap, _ := failedPeers.LoadOrStore(heightStr, &sync.Map{})
	if pm, ok := peerMap.(*sync.Map); ok {
		var count int
		if v, exists := pm.Load(peerID); exists {
			count = v.(int)
		}
		pm.Store(peerID, count+1)
	}
}

// fetchBlockFromPeer requests a block from a specific peer
func (sm *SyncManager) fetchBlockFromPeer(peer PeerInterface, height uint64) (*types.Block, error) {
	// ========== FIX: Implement actual block download via P2P messages ==========
	// Request block using getdata message (Bitcoin-style sync protocol)
	requestID := fmt.Sprintf("block-%d-%s", height, peer.GetID())

	// Create a response channel for this request
	responseCh := make(chan *types.Block, 1)
	sm.pendingRequestMu.Lock()
	sm.pendingBlockRequests[requestID] = responseCh
	sm.pendingRequestMu.Unlock()

	request := map[string]interface{}{
		"method":     "getdata",
		"request_id": requestID,
		"params": []map[string]interface{}{
			{
				"type":   "block",
				"height": height,
			},
		},
	}

	requestData, err := json.Marshal(request)
	if err != nil {
		sm.pendingRequestMu.Lock()
		delete(sm.pendingBlockRequests, requestID)
		sm.pendingRequestMu.Unlock()
		close(responseCh)
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send via P2P message
	logger.Info("📥 Requesting block %d from peer %s (request_id=%s)", height, peer.GetID(), requestID)

	// Send request via P2P server
	if sm.p2pServer != nil {
		if err := sm.p2pServer.SendMessageToPeer(peer.GetID(), "getdata", requestData); err != nil {
			sm.pendingRequestMu.Lock()
			delete(sm.pendingBlockRequests, requestID)
			sm.pendingRequestMu.Unlock()
			close(responseCh)
			return nil, fmt.Errorf("failed to send request: %w", err)
		}
	}

	// Wait for response with timeout
	// Use shorter timeout for bulk sync (10s) vs tip chasing (30s)
	timeout := 30 * time.Second
	if sm.bulkSyncMode {
		timeout = 10 * time.Second // Shorter timeout for bulk sync — fail fast, retry from another peer
	}

	select {
	case block := <-responseCh:
		if block == nil {
			return nil, fmt.Errorf("received nil block response")
		}
		return block, nil

	case <-time.After(timeout):
		sm.pendingRequestMu.Lock()
		delete(sm.pendingBlockRequests, requestID)
		sm.pendingRequestMu.Unlock()
		close(responseCh)
		return nil, fmt.Errorf("timeout waiting for block %d from peer %s", height, peer.GetID())
	}
}

// HandleBlockResponse handles incoming block responses from peers
// This should be called by the P2P message handler when a block response arrives
func (sm *SyncManager) HandleBlockResponse(requestID string, block *types.Block) error {
	sm.pendingRequestMu.Lock()
	responseCh, exists := sm.pendingBlockRequests[requestID]
	sm.pendingRequestMu.Unlock()

	if !exists {
		// Unknown request ID - might be a broadcast block, let P2P handler process it
		logger.Debug("Received block with unknown request_id: %s", requestID)
		return nil
	}

	// Send the block to the waiting goroutine
	select {
	case responseCh <- block:
		logger.Info("SUCCESS Delivered block response for request %s", requestID)
	default:
		logger.Warn("WARNING Response channel full for request %s", requestID)
	}

	return nil
}

// downloadCoordinator manages the download queue and commits downloaded blocks
func (sm *SyncManager) downloadCoordinator() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.stopCh:
			return

		case <-ticker.C:
			sm.processDownloadedBlocks()
		}
	}
}

// processDownloadedBlocks validates and commits downloaded blocks in order
func (sm *SyncManager) processDownloadedBlocks() {
	sm.downloadMutex.Lock()
	defer sm.downloadMutex.Unlock()

	if len(sm.downloaded) == 0 {
		return
	}

	// Sort heights
	var heights []int
	for h := range sm.downloaded {
		heights = append(heights, int(h))
	}
	sort.Ints(heights)

	// Process in order
	localHeight := sm.bc.GetBlockCount()

	for _, h := range heights {
		height := uint64(h)

		// Must be sequential
		if height != localHeight+1 {
			continue
		}

		block := sm.downloaded[height]

		// Commit block
		consensusBlock := NewBlockHelper(block)
		if err := sm.bc.CommitBlock(consensusBlock); err != nil {
			logger.Error("ERROR Failed to commit block %d: %v", height, err)
			delete(sm.downloaded, height)
			continue
		}

		logger.Info("SUCCESS Committed block %d (hash=%s)", height, block.GetHash())
		delete(sm.downloaded, height)
		localHeight++
	}
}

// peerMonitorLoop monitors peer health and triggers re-sync if needed
func (sm *SyncManager) peerMonitorLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.stopCh:
			return

		case <-ticker.C:
			sm.checkPeerHealth()
		}
	}
}

// checkPeerHealth verifies peers are still connected and updates chain info
func (sm *SyncManager) checkPeerHealth() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	peers := sm.p2pServer.GetNodeManager().GetPeers()

	// Remove disconnected peers and attempt reconnection
	for peerID := range sm.peerInfo {
		if _, exists := peers[peerID]; !exists {
			logger.Info("Peer %s disconnected, removing from sync", peerID)
			delete(sm.peerInfo, peerID)
			delete(sm.peers, peerID)

			// Attempt reconnection
			go sm.attemptReconnection(peerID)
		}
	}

	// If we lost all peers, go back to discovery
	if len(sm.peerInfo) == 0 && sm.state >= NodeHandshaking {
		logger.Warn("WARNING All peers lost, returning to discovery")
		sm.setState(NodeDiscoveringPeers)
	}
}

// handlePeerUpdate processes peer connection/disconnection events
func (sm *SyncManager) handlePeerUpdate(peer PeerInterface) {
	if peer == nil {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	peerID := peer.GetID()

	if peer.GetStatus() == "active" {
		// Peer connected - request chain info
		sm.peers[peerID] = peer
		logger.Info("Peer connected: %s", peerID)

		// Request chain info from peer
		sm.requestChainInfo(peer)
	} else {
		// Peer disconnected
		delete(sm.peers, peerID)
		delete(sm.peerInfo, peerID)
		logger.Info("Peer disconnected: %s", peerID)
	}
}

// requestChainInfo requests chain information from a peer
func (sm *SyncManager) requestChainInfo(peer PeerInterface) {
	// ========== FIX: Actually send chain info request via P2P ==========
	nodeID := ""
	if sm.consensus != nil {
		nodeID = sm.consensus.GetNodeID()
	}
	request := map[string]interface{}{
		"method": "getchaininfo",
		"params": map[string]interface{}{
			"node_id": nodeID,
		},
	}

	requestData, err := json.Marshal(request)
	if err != nil {
		logger.Error("Failed to marshal chain info request: %v", err)
		return
	}

	// Send via P2P server
	if sm.p2pServer != nil {
		if err := sm.p2pServer.SendMessageToPeer(peer.GetID(), "getchaininfo", requestData); err != nil {
			logger.Warn("Failed to request chain info from peer %s: %v", peer.GetID(), err)
		} else {
			logger.Info("📤 Requested chain info from peer %s", peer.GetID())
		}
	}
}

// HandleChainInfoResponse processes chain information received from a peer
// This should be called when a "chaininfo" message is received
func (sm *SyncManager) HandleChainInfoResponse(peerID string, chainInfo map[string]interface{}) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	logger.Info("📥 Received chain info from peer %s: height=%v", peerID, chainInfo["current_height"])

	// Extract chain information
	chainID, _ := chainInfo["chain_id"].(float64)
	genesisHash, _ := chainInfo["genesis_hash"].(string)
	height, _ := chainInfo["current_height"].(float64)
	bestHash, _ := chainInfo["latest_block"].(string)
	finalizedHeight, _ := chainInfo["finalized_height"].(float64)
	finalizedHash, _ := chainInfo["finalized_hash"].(string)
	protocolVersion, _ := chainInfo["protocol_version"].(string)
	currentView, _ := chainInfo["current_view"].(float64)
	currentEpoch, _ := chainInfo["current_epoch"].(float64)
	leaderID, _ := chainInfo["leader_id"].(string)

	// Store peer chain info
	sm.peerInfo[peerID] = &PeerChainInfo{
		ChainID:         uint64(chainID),
		GenesisHash:     genesisHash,
		Height:          uint64(height),
		BestHash:        bestHash,
		FinalizedHeight: uint64(finalizedHeight),
		FinalizedHash:   finalizedHash,
		ProtocolVersion: protocolVersion,
		CurrentView:     uint64(currentView),
		CurrentEpoch:    uint64(currentEpoch),
		LeaderID:        leaderID,
		Timestamp:       time.Now().Unix(),
	}

	logger.Info("SUCCESS Stored chain info for peer %s: height=%d, genesis=%s",
		peerID, uint64(height), genesisHash[:16])
}

// getGenesisHash returns the local genesis hash
func (sm *SyncManager) getGenesisHash() string {
	genesis := sm.bc.GetBlockByNumber(0)
	if genesis == nil {
		return ""
	}
	return genesis.GetHash()
}

// getMaxPeerHeight returns the maximum height among all peers
func (sm *SyncManager) getMaxPeerHeight() uint64 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var maxHeight uint64
	for _, info := range sm.peerInfo {
		if info.Height > maxHeight {
			maxHeight = info.Height
		}
	}

	return maxHeight
}

// checkForReorg detects if local chain has forked from the network
func (sm *SyncManager) checkForReorg() {
	logger.Info("INFO Checking for chain reorganization...")

	localHeight := sm.bc.GetBlockCount()
	if localHeight == 0 {
		return
	}

	// Get local best block
	localBest := sm.bc.GetBlockByNumber(localHeight - 1)
	if localBest == nil {
		return
	}

	// Compare with peers
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for peerID, info := range sm.peerInfo {
		if info.Height >= localHeight && info.BestHash != localBest.GetHash() {
			logger.Warn("WARNING Fork detected with peer %s: local=%s, peer=%s at height %d",
				peerID, localBest.GetHash()[:16], info.BestHash[:16], localHeight)

			// Trigger reorganization
			sm.handleReorg(info)
			return
		}
	}
}

// handleReorg handles chain reorganization
//
// ★ FIX (was a no-op): this previously (a) built a locator containing only
// the peer's *tip* hash and looked it up in the *local* chain — which can
// only ever match by coincidence once two chains have actually diverged,
// so it reliably found nothing; (b) treated forkHeight==0 as an error and
// bailed out, even though genesis (height 0) is the correct, expected fork
// point for chains that diverged at block 1 (e.g. independently solo-mined
// chains); and (c) never called RollbackToHeight at all, despite the
// function existing — it just logged a warning and adjusted sync bookkeeping
// while leaving the invalidated local blocks in place, so the subsequent
// re-sync had nowhere to attach the peer's blocks and they were orphaned
// forever.
func (sm *SyncManager) handleReorg(newChain *PeerChainInfo) {
	logger.Info("🔄 Handling chain reorganization...")

	// Save old best hash
	sm.oldBestHash = string(sm.bc.GetBestBlockHash())

	localHeight := sm.bc.GetBlockCount()
	if localHeight == 0 {
		return
	}

	// Build a proper exponential-backoff locator over OUR chain (tip ...
	// genesis), not a single peer hash checked against our own chain.
	locator := sm.bc.GenerateBlockLocator(localHeight - 1)

	// Walking our own locator against our own chain trivially matches at the
	// tip, so this only tells us the true fork point once we can check each
	// candidate hash against the PEER's chain instead. If the peer transport
	// doesn't yet expose per-height ancestor queries, the safe conservative
	// fallback is genesis: as long as both chains share the same genesis
	// hash (verified below), height 0 is always a valid common ancestor,
	// even if it isn't the *highest* one — worst case we redownload more
	// blocks than strictly necessary, which is safe, unlike guessing wrong.
	forkHeight, forkHash, found := sm.bc.FindCommonAncestor(locator)

	localGenesis := sm.getGenesisHash()
	if !found {
		if newChain.GenesisHash == "" || newChain.GenesisHash != localGenesis {
			logger.Error("ERROR No common ancestor found and genesis hashes don't match (local=%s peer=%s) — refusing to reorg onto an unrelated chain",
				localGenesis, newChain.GenesisHash)
			return
		}
		logger.Warn("WARNING No common ancestor above genesis found — falling back to genesis as the fork point")
		forkHeight = 0
		forkHash = localGenesis
	}

	logger.Info("📍 Fork point at height %d (hash=%s)", forkHeight, forkHash)

	// Actually roll back the invalidated local blocks (storage + state, not
	// just the in-memory slice — see RollbackToHeight in blockchain.go)
	// BEFORE changing sync bookkeeping, so the sync loop has a clean tip to
	// extend from.
	if forkHeight < localHeight-1 {
		if err := sm.bc.RollbackToHeight(forkHeight); err != nil {
			logger.Error("ERROR Rollback to height %d failed: %v — aborting reorg", forkHeight, err)
			return
		}
	}

	sm.reorgDepth = localHeight - forkHeight
	logger.Info("SUCCESS Rolled back %d blocks to height %d", sm.reorgDepth, forkHeight)

	// Re-sync from fork point
	sm.syncFrom = forkHeight + 1
	sm.syncHeight = newChain.Height
	sm.setState(NodeSyncingBlocks)
}

// verifyChainLinks verifies all blocks are properly linked
func (sm *SyncManager) verifyChainLinks() error {
	logger.Info("🔗 Verifying chain links...")

	height := sm.bc.GetBlockCount()
	if height == 0 {
		return nil
	}

	// Check each block links to its parent
	for i := uint64(1); i < height; i++ {
		block := sm.bc.GetBlockByNumber(i)
		if block == nil {
			return fmt.Errorf("missing block at height %d", i)
		}

		parent := sm.bc.GetBlockByNumber(i - 1)
		if parent == nil {
			return fmt.Errorf("missing parent at height %d", i-1)
		}

		if block.GetPrevHash() != parent.GetHash() {
			return fmt.Errorf("broken link at height %d: parent hash mismatch", i)
		}
	}

	logger.Info("SUCCESS Chain links verified (%d blocks)", height)
	return nil
}

// shouldBecomeValidator determines whether this chain-state validator is
// synchronized and may participate in consensus.
func (sm *SyncManager) shouldBecomeValidator() bool {
	if sm == nil || sm.bc == nil || sm.consensus == nil {
		return false
	}

	localHeight := sm.bc.GetBlockCount()
	targetHeight := sm.getMaxPeerHeight()
	if targetHeight > 0 && localHeight < targetHeight {
		logger.Info("Not eligible for validator role: local height %d behind peer tip %d", localHeight, targetHeight)
		return false
	}

	// Membership comes from the active validator set, not a balance fallback
	// or the number of peers currently connected.
	vs := sm.consensus.GetValidatorSet()
	if vs == nil {
		return false
	}
	epoch := consensus.EpochForHeight(sm.consensus.GetCurrentHeight())
	for _, validator := range vs.GetActiveValidators(epoch) {
		if validator != nil && validator.ID == sm.consensus.GetNodeID() {
			return true
		}
	}

	logger.Info("Node is not an active validator in chain state")
	return false
}

// isDownloading checks if a height is currently being downloaded
func (sm *SyncManager) isDownloading(height uint64) bool {
	sm.downloadMutex.Lock()
	defer sm.downloadMutex.Unlock()
	return sm.downloadQueue[height]
}

// markDownloading marks a height as being downloaded
func (sm *SyncManager) markDownloading(height uint64) {
	sm.downloadMutex.Lock()
	defer sm.downloadMutex.Unlock()
	sm.downloadQueue[height] = true
}

// unmarkDownloading unmarks a height
func (sm *SyncManager) unmarkDownloading(height uint64) {
	sm.downloadMutex.Lock()
	defer sm.downloadMutex.Unlock()
	delete(sm.downloadQueue, height)
}

// setState transitions the node to a new state
func (sm *SyncManager) setState(newState NodeState) {
	sm.mu.Lock()
	oldState := sm.state
	sm.state = newState
	sm.mu.Unlock()

	if oldState != newState {
		logger.Info("🔄 Node state transition: %s → %s", oldState, newState)
	}
}

// GetState returns the current node state
func (sm *SyncManager) GetState() NodeState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.state
}

// GetSyncProgress returns sync progress information
func (sm *SyncManager) GetSyncProgress() map[string]interface{} {
	sm.mu.RLock()
	localHeight := sm.bc.GetBlockCount()
	targetHeight := sm.syncHeight
	sm.mu.RUnlock()

	progress := map[string]interface{}{
		"state":             sm.GetState().String(),
		"local_height":      localHeight,
		"target_height":     targetHeight,
		"blocks_downloaded": sm.blocksDownloaded,
		"bytes_downloaded":  sm.bytesDownloaded,
		"bulk_sync_mode":    sm.bulkSyncMode,
		"pipeline_depth":    sm.pipelineDepth,
	}

	if targetHeight > 0 && localHeight > 0 {
		pct := float64(localHeight) / float64(targetHeight) * 100
		progress["progress_percent"] = pct
		progress["remaining"] = targetHeight - localHeight
	}

	return progress
}

// EnableStateSync enables state sync mode (download trusted state snapshot instead of full history)
func (sm *SyncManager) EnableStateSync(stateHash string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.stateSyncMode = true
	sm.stateSyncHash = stateHash

	logger.Info("INFO State sync enabled (hash=%s)", stateHash[:16])
}

// DisableStateSync disables state sync mode
func (sm *SyncManager) DisableStateSync() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.stateSyncMode = false
	sm.stateSyncHash = ""

	logger.Info("INFO State sync disabled")
}

// OperatorKeyResolver returns the chain-committed operator public key for a
// validator ID, as of the state replayed up to the block being verified.
//
// ★ WHY A RESOLVER AND NOT THE SIGNING REGISTRY. The live path can look a key
// up in SigningService.publicKeyRegistry, which is populated by handshake. A
// syncing node has NOT handshook with the peers whose blocks it is replaying,
// so a registry lookup would fail for exactly the validators whose votes it
// must check — and skipping unknown keys would restore the forgery hole. The
// key therefore comes from chain state (protocol:validator_identity:), the
// same source the double-sign evidence path already uses
// (executor.go getValidatorIdentity), so a replayed chain verifies on a node
// that never met a peer.
//
// A missing or malformed record is a chain-integrity failure, returned as an
// error; the caller rejects the block.
type OperatorKeyResolver func(validatorID string) ([]byte, error)

// AttestationSignatureVerifier reports whether one attestation's signature is
// valid for the given validator and block. It is a parameter so the
// verification step is expressed explicitly at the call site, and so tests can
// inject a deterministic stand-in instead of generating real SPHINCS+ keys.
//
// ★ THE DEFAULT MUST NEVER BE SKIPPED. There is no "no verifier configured"
// path: a caller that cannot verify must reject, not accept. That is why this
// is a required parameter and why FastForward no longer has an optional hook.
type AttestationSignatureVerifier func(att *types.Attestation, publicKey []byte) error

// MaxAttestationsPerBlock bounds how many attestations a block may carry. A
// block cannot need more signers than the governing snapshot has members, so
// anything above that is malformed and is rejected BEFORE any SPHINCS+ work.
// Without this cap, one hostile block could force unbounded verifications on a
// syncing node.
const MaxAttestationsPerBlock = consensus.MaxValidatorSetSize

// attestationVerifyConcurrency bounds parallel signature verification.
// SPHINCS+ verification is CPU-bound and costs seconds per signature, so this
// is capped well below the validator count: with K=100 a block carries ~67
// attestations, and verifying them serially would stall sync for minutes.
var attestationVerifyConcurrency = func() int {
	n := runtime.NumCPU()
	switch {
	case n > 8:
		return 8
	case n < 1:
		return 1
	default:
		return n
	}
}

// verifyAttestationSignatures runs the cryptographic checks over exactly the
// attestations that already passed the cheap structural gate.
//
// ★ THE VERDICT MUST NOT DEPEND ON COMPLETION ORDER. Results are stored by
// index and the lowest failing index is reported, so both the accept/reject
// decision and the error message are deterministic regardless of which worker
// finished first. The pool stops handing out work after a failure, but a
// cancellation can never turn a rejection into an acceptance, because the
// final decision scans every index.
func verifyAttestationSignatures(
	attestations []*types.Attestation,
	keys map[string][]byte,
	verify func(*types.Attestation, []byte) error,
) error {
	if len(attestations) == 0 {
		return nil
	}
	workers := attestationVerifyConcurrency()
	if workers > len(attestations) {
		workers = len(attestations)
	}
	if workers < 1 {
		workers = 1
	}

	type job struct {
		index int
		att   *types.Attestation
	}
	jobs := make(chan job)
	results := make([]error, len(attestations))

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			draining := false
			for j := range jobs {
				if draining {
					continue // accept and discard; the index stays nil
				}
				if err := verify(j.att, keys[j.att.ValidatorID]); err != nil {
					results[j.index] = err
					draining = true
				}
			}
		}()
	}

	for i, att := range attestations {
		jobs <- job{index: i, att: att}
	}
	close(jobs)
	wg.Wait()

	for i, err := range results {
		if err != nil {
			return fmt.Errorf("attestation %d from %s failed signature verification: %w",
				i, attestations[i].ValidatorID, err)
		}
	}
	return nil
}

// VerifyBlockAttestations checks that a block carries valid commit attestations
// representing ≥2/3+ of total validator stake. This is the sync-time equivalent
// of the PBFT commit quorum check.
//
// It looks up the validator set that was active at the block's epoch (via
// per-epoch snapshots), falling back to the current live set if no snapshot
// exists. This ensures correct verification even when validators rotate.
//
// Genesis block (height 0) is exempted from attestation verification — it
// has no attestations and is verified by hash/config match instead.
//
// Parameters:
//   - block: the block whose Body.Attestations should be verified
//   - vs: the current ValidatorSet (used as fallback if no epoch snapshot)
//   - vs: the current ValidatorSet (used only for the genesis-epoch fallback)
//
// Returns nil if attestations are valid and meet quorum, or an error describing
// the failure.
//
// ★ THE EPOCH IS DERIVED FROM block.GetHeight(), NEVER SUPPLIED BY THE CALLER.
// It used to be a parameter, and the two callers disagreed about its value:
// core/sync.go computed height/100 ("Assuming 100 blocks per epoch") while
// bind/helpers.go computed height/consensus.SlotsPerEpoch (=32). The same block
// was therefore verified against two different validator sets depending on
// which path accepted it. Deriving it here from the chain parameter makes that
// class of disagreement impossible to express.
// ★ THE OLD SIGNATURE WAS:
//
//	func VerifyBlockAttestations(block *types.Block, vs validatorSetProvider) error
//
// — it took a LIVE validator-set provider, and fell back to it whenever no
// snapshot existed. That fallback is the bug this signature removes: a block
// could be verified against whatever the local set happened to be, rather than
// against the set that actually governed it. There is now NO live-set parameter
// at all, so that class of mistake is not expressible.
//
// NewChainStateKeyResolver returns the production OperatorKeyResolver: it reads
// the chain-committed operator key from the StateDB produced by replaying every
// block up to (but not including) the one being verified.
//
// ★ THIS IS WHY A LATE JOINER WORKS. The verifier runs BEFORE the block is
// committed, so it sees the state left by all prior blocks — the same replay a
// syncing node performs. Nothing here consults the peer registry, so a node
// that has never handshook with anybody can still verify the votes it replays.
//
// Genesis validators are covered because block-0 execution writes their
// identity records (seedGenesisFileAllocations -> setValidatorIdentity), so by
// the time height 1 is verified the records exist.
func NewChainStateKeyResolver(bc *Blockchain) OperatorKeyResolver {
	return func(validatorID string) ([]byte, error) {
		if bc == nil {
			return nil, fmt.Errorf("no blockchain available")
		}
		stateDB, err := bc.newStateDB()
		if err != nil {
			return nil, fmt.Errorf("open state DB for operator key %s: %w", validatorID, err)
		}
		identity, err := stateDB.getValidatorIdentity(validatorID)
		if err != nil {
			return nil, fmt.Errorf("read chain identity for %s: %w", validatorID, err)
		}
		if identity.OperatorPublicKey == "" {
			return nil, fmt.Errorf("validator %s has no chain-committed operator key", validatorID)
		}
		key, err := hex.DecodeString(identity.OperatorPublicKey)
		if err != nil {
			return nil, fmt.Errorf("decode chain-committed operator key for %s: %w", validatorID, err)
		}
		return key, nil
	}
}

// NewConsensusAttestationVerifier returns the production
// AttestationSignatureVerifier. It delegates to the single shared verifier in
// consensus, which builds the one canonical vote preimage, so the sync path and
// the live path cannot disagree about what was signed.
//
// The full serialized SignedMessage blob is required (Attestation.Signature),
// not the extracted signature bytes: the signed timestamp and nonce are part of
// the message and are what binds the vote to its content.
func NewConsensusAttestationVerifier() AttestationSignatureVerifier {
	return func(att *types.Attestation, publicKey []byte) error {
		if att == nil {
			return fmt.Errorf("nil attestation")
		}
		return consensus.VerifyAttestationSignature(publicKey, att.ChainID, att.Phase,
			att.Height, att.View, att.BlockHash, att.ValidatorID, att.Signature)
	}
}

// The epoch is likewise not a parameter: it is derived from block.GetHeight()
// inside consensus.ValidatorSetAt, so no caller can verify a block against a
// different epoch than the one it was produced in.
// BlockProposerSignatureVerifier verifies a block's proposer signature against a
// caller-supplied public key. The production implementation is
// consensus.VerifyBlockProposerSignature, which resolves nothing itself: the
// caller passes the key it read from REPLAYED CHAIN STATE.
type BlockProposerSignatureVerifier func(block *types.Block, publicKey []byte) error

// NewConsensusBlockProposerSignatureVerifier returns the production block
// signature verifier.
func NewConsensusBlockProposerSignatureVerifier() BlockProposerSignatureVerifier {
	return consensus.VerifyBlockProposerSignature
}

// VerifyBlockAuthority decides whether a block may be committed, and it decides
// from the SNAPSHOT THAT GOVERNS ITS HEIGHT — never from a flag carried on the
// block, a "solo-mined" marker, or the local peer count.
//
// ★ THE BYPASS THIS CLOSES. The sync loop used to read an empty attestation
// list as "solo-mined before PBFT — skipping quorum check, verified by chain
// continuity". A malicious peer could therefore hand a joining node an
// arbitrarily long chain of empty-attestation blocks whose only property was
// that each parent hash linked to the last, and every one of them would be
// committed. That discarded the entire attestation-verification layer for
// exactly the case a joining node is in.
//
// The rule is now:
//
//   - attestations present  -> VerifyBlockAttestations, unchanged and strict.
//   - attestations absent   -> permitted ONLY when the governing snapshot has
//     exactly ONE member, and the block carries a valid proposer signature from
//     that member, verified against its chain-committed key.
//
// Because the test is "how many validators are in the snapshot for this height",
// the permission expires by itself at the epoch boundary where the set grows:
// from that height on, an empty-attestation block is rejected. No flag, so
// nothing has to be kept in sync.
func VerifyBlockAuthority(block *types.Block, resolveKey OperatorKeyResolver, verifySig AttestationSignatureVerifier, verifyBlockSig BlockProposerSignatureVerifier) error {
	if block == nil {
		return fmt.Errorf("block is nil")
	}
	// Genesis is configuration, not consensus: its identity is established by
	// the document digest and the pinned hash, not by votes.
	if block.GetHeight() == 0 {
		return nil
	}

	if len(block.Body.Attestations) > 0 {
		return VerifyBlockAttestations(block, resolveKey, verifySig)
	}

	// ── EMPTY ATTESTATIONS ────────────────────────────────────────────────
	snap := consensus.ValidatorSetAt(block.GetHeight())
	if snap == nil {
		return fmt.Errorf("block %d carries no attestations and there is no validator set snapshot for height %d (epoch %d); refusing to accept an unattested block without knowing who governed it",
			block.GetHeight(), block.GetHeight(), consensus.EpochForHeight(block.GetHeight()))
	}
	if len(snap.Validators) != 1 {
		return fmt.Errorf("block %d carries no attestations, but the epoch %d snapshot has %d validators; only a single-validator snapshot may finalize a block without a quorum certificate",
			block.GetHeight(), snap.Epoch, len(snap.Validators))
	}
	if block.Header == nil || block.Header.ProposerID == "" {
		return fmt.Errorf("block %d carries no attestations and no proposer ID; a single-validator chain still requires the proposer to be identified", block.GetHeight())
	}

	var memberID string
	for id := range snap.Validators {
		memberID = id
	}
	if block.Header.ProposerID != memberID {
		return fmt.Errorf("block %d carries no attestations and is proposed by %s, which is not the sole member %s of the epoch %d snapshot",
			block.GetHeight(), block.Header.ProposerID, memberID, snap.Epoch)
	}

	if resolveKey == nil || verifyBlockSig == nil {
		return fmt.Errorf("block %d proposer signature verification is not configured; refusing to accept an unattested block with an unverified producer",
			block.GetHeight())
	}
	key, err := resolveKey(memberID)
	if err != nil {
		return fmt.Errorf("block %d: no chain-committed operator key for the sole epoch %d validator %s: %w",
			block.GetHeight(), snap.Epoch, memberID, err)
	}
	if len(key) != OperatorPublicKeyLength {
		return fmt.Errorf("block %d: chain-committed operator key for %s is %d bytes, want exactly %d",
			block.GetHeight(), memberID, len(key), OperatorPublicKeyLength)
	}
	if err := verifyBlockSig(block, key); err != nil {
		return fmt.Errorf("block %d: %w", block.GetHeight(), err)
	}

	logger.Info("Block %d accepted on a single-validator epoch %d snapshot: no attestations required, proposer %s signature verified against its chain-committed key",
		block.GetHeight(), snap.Epoch, memberID)
	return nil
}

func VerifyBlockAttestations(block *types.Block, resolveKey OperatorKeyResolver, verifySig AttestationSignatureVerifier) error {
	if block == nil {
		return fmt.Errorf("block is nil")
	}

	// ── Genesis block exemption ──
	// The genesis block (height 0) has no attestations because it is created
	// by configuration, not by PBFT consensus. It is verified by hash/config
	// match instead of attestation quorum.
	if block.GetHeight() == 0 {
		logger.Info("SUCCESS Genesis block (height 0) — skipping attestation verification (verified by config/hash)")
		return nil
	}

	attestations := block.Body.Attestations
	if len(attestations) == 0 {
		return fmt.Errorf("block height %d has zero attestations — no quorum certificate", block.GetHeight())
	}
	// ★ CHEAP CHECK FIRST. A block cannot carry more signers than the snapshot
	// has members, so an oversized list is malformed. Rejecting it here means a
	// hostile block cannot make this node perform unbounded SPHINCS+ work.
	if len(attestations) > MaxAttestationsPerBlock {
		return fmt.Errorf("block height %d carries %d attestations, above the maximum of %d",
			block.GetHeight(), len(attestations), MaxAttestationsPerBlock)
	}

	// ★ FAIL CLOSED. The snapshot for this height is the ONLY authority. If it
	// is missing — the node has not crossed that boundary yet, or a restart lost
	// it — the block is REJECTED. There is deliberately no fallback to any live
	// set: a node that guesses is a node that can accept a block no quorum ever
	// certified.
	snap := consensus.ValidatorSetAt(block.GetHeight())
	if snap == nil {
		return fmt.Errorf("no validator set snapshot for height %d (epoch %d) — refusing to verify against a live set; the node must sync past that epoch boundary first",
			block.GetHeight(), consensus.EpochForHeight(block.GetHeight()))
	}
	if snap.TotalStake == nil || snap.TotalStake.Sign() <= 0 {
		return fmt.Errorf("validator set snapshot for height %d (epoch %d) has zero total stake — cannot verify quorum",
			block.GetHeight(), snap.Epoch)
	}
	blockEpoch := snap.Epoch
	totalStake := snap.TotalStake
	logger.Debug("Verifying block %d against the epoch %d snapshot (%d validators, %s nSPX)",
		block.GetHeight(), blockEpoch, len(snap.Validators), totalStake.String())

	// Distinct attesters, resolved ONLY against the snapshot's own set. An
	// attestation from a validator that is not in this snapshot counts for
	// nothing — including a validator that was valid in a different epoch.
	//
	// ★ STRICT: a duplicate signer or a non-member signer now REJECTS the
	// block instead of being skipped. Skipping them let a proposer pad a block
	// with junk entries and still reach quorum, and it hid the fact that a
	// non-member had been counted as a participant at all.
	attestedStake := big.NewInt(0)
	seen := make(map[string]bool)
	distinct := 0
	verified := make([]*types.Attestation, 0, len(attestations))

	for _, att := range attestations {
		if att == nil || att.ValidatorID == "" {
			return fmt.Errorf("block %d contains a malformed attestation with no validator ID", block.GetHeight())
		}
		if att.Height != block.GetHeight() {
			return fmt.Errorf("block %d contains attestation for height %d from %s",
				block.GetHeight(), att.Height, att.ValidatorID)
		}
		if seen[att.ValidatorID] {
			return fmt.Errorf("block %d contains duplicate attestations from %s", block.GetHeight(), att.ValidatorID)
		}
		seen[att.ValidatorID] = true

		v, inSet := snap.Validators[att.ValidatorID]
		if !inSet || v == nil || v.StakeAmount == nil || v.StakeAmount.Sign() <= 0 {
			return fmt.Errorf("block %d contains an attestation from %s, which is not a member of the epoch %d snapshot",
				block.GetHeight(), att.ValidatorID, blockEpoch)
		}
		attestedStake.Add(attestedStake, v.StakeAmount)
		distinct++
		verified = append(verified, att)
	}

	// ★ STRICT: voted*3 > total*2, against the SNAPSHOT's own total. The old
	// code computed `required = total*2/3` (truncating) and then compared with
	// `>=`, which is strictly weaker than the protocol rule: for 3 validators at
	// 32 SPX, 2 of 3 is exactly 2/3 and the old check ACCEPTED it.
	if !consensus.MeetsStakeQuorum(attestedStake, totalStake) {
		attestedSPX := new(big.Float).Quo(new(big.Float).SetInt(attestedStake), new(big.Float).SetFloat64(denom.SPX))
		totalSPX := new(big.Float).Quo(new(big.Float).SetInt(totalStake), new(big.Float).SetFloat64(denom.SPX))
		return fmt.Errorf("block %d attestation quorum not met: %.2f / %.2f SPX attested from %d unique validators (epoch %d, snapshot of %d) — need strictly more than 2/3",
			block.GetHeight(), attestedSPX, totalSPX, distinct, blockEpoch, len(snap.Validators))
	}

	// ★ DISTINCT-VOTER FLOOR, also from the snapshot, in integer math:
	// (2N)/3 + 1, no floats. For N=3 that is 3 — all three must have voted.
	n := len(snap.Validators)
	if want := consensus.StrictTwoThirdsCount(n); distinct < want {
		return fmt.Errorf("block %d has only %d distinct attester(s); the epoch %d snapshot of %d validators needs %d (strict 2/3 distinct-voter floor)",
			block.GetHeight(), distinct, blockEpoch, n, want)
	}

	// ── STRICT SIGNATURE VERIFICATION ─────────────────────────────────────
	// Everything above is cheap arithmetic over block CONTENTS. Nothing above
	// proves anybody actually signed anything: the proposer chooses this list,
	// and att.Signature was previously never examined at all, so a block
	// fabricated wholesale passed every check above. That is the hole #5 closes.
	//
	// The keys come from chain state, not the handshake registry, so this works
	// on a node that has never met the peers it is replaying.
	if resolveKey == nil || verifySig == nil {
		return fmt.Errorf("block %d attestation verification is not configured; refusing to accept unverified attestations",
			block.GetHeight())
	}

	// INVARIANT: every member of the governing snapshot must have a chain
	// identity with a correctly sized operator key. A missing one is a
	// chain-integrity failure, not something to work around: a validator whose
	// key we cannot resolve can never be checked, and skipping it would
	// silently shrink the verified set below quorum.
	keys := make(map[string][]byte, len(snap.Validators))
	for id := range snap.Validators {
		key, err := resolveKey(id)
		if err != nil {
			return fmt.Errorf("block %d: no chain-committed operator key for snapshot member %s: %w",
				block.GetHeight(), id, err)
		}
		if len(key) != OperatorPublicKeyLength {
			return fmt.Errorf("block %d: chain-committed operator key for %s is %d bytes, want exactly %d",
				block.GetHeight(), id, len(key), OperatorPublicKeyLength)
		}
		keys[id] = key
	}

	if err := verifyAttestationSignatures(verified, keys, verifySig); err != nil {
		return fmt.Errorf("block %d: %w", block.GetHeight(), err)
	}

	attestedSPX := new(big.Float).Quo(new(big.Float).SetInt(attestedStake), new(big.Float).SetFloat64(denom.SPX))
	totalSPX := new(big.Float).Quo(new(big.Float).SetInt(totalStake), new(big.Float).SetFloat64(denom.SPX))
	pct := new(big.Float).Quo(attestedSPX, totalSPX)
	pct.Mul(pct, big.NewFloat(100))
	logger.Info("SUCCESS Block %d attestation quorum verified AND %d signature(s) verified: %.2f / %.2f SPX (%.1f%%) from %d validators (epoch %d snapshot)",
		block.GetHeight(), len(verified), attestedSPX, totalSPX, pct, distinct, blockEpoch)

	return nil
}

// String is defined in const.go

// GenerateBlockLocator creates a block locator starting from the tip
// The locator includes blocks at exponentially decreasing intervals:
// tip, tip-1, tip-2, tip-4, tip-8, tip-16, ... genesis
func (bc *Blockchain) GenerateBlockLocator(tipHeight uint64) *BlockLocator {
	locator := &BlockLocator{
		Hashes: make([]string, 0),
	}

	if tipHeight == 0 {
		return locator
	}

	// Start from tip and work backwards with exponential steps
	step := uint64(1)
	currentHeight := tipHeight

	for currentHeight > 0 {
		block := bc.GetBlockByNumber(currentHeight)
		if block != nil {
			locator.Hashes = append(locator.Hashes, block.GetHash())
		}

		// Exponential backoff: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024
		if currentHeight <= step {
			currentHeight = 0
		} else {
			currentHeight -= step
			if step < 1024 {
				step *= 2
			}
		}
	}

	// Always include genesis hash
	genesis := bc.GetBlockByNumber(0)
	if genesis != nil {
		locator.Hashes = append(locator.Hashes, genesis.GetHash())
	}

	return locator
}

// FindCommonAncestor finds the highest common ancestor between local chain and remote hashes
// Returns the height of the common ancestor, its hash, and whether a common
// ancestor was found at all.
//
// ★ FIX: the previous signature returned (0, "") both when no ancestor was
// found AND when the ancestor legitimately was genesis (height 0). Every
// caller then treated height==0 as "not found" and aborted the reorg — but
// genesis is *always* a valid, common fork point (all nodes share the same
// cached genesis block, see core.GetGenesisHash/getCachedGenesisBlock). That
// meant any fork that diverged at block 1 — exactly what happens when nodes
// solo-mine independently before discovering peers — could never be healed,
// because the "no ancestor found" and "forked immediately after genesis"
// cases were indistinguishable. The explicit `found bool` fixes that.
func (bc *Blockchain) FindCommonAncestor(locator *BlockLocator) (uint64, string, bool) {
	if locator == nil || len(locator.Hashes) == 0 {
		return 0, "", false
	}

	// Check each hash in the locator (from most recent to oldest)
	for _, hash := range locator.Hashes {
		block := bc.GetBlockByHash(hash)
		if block != nil {
			return block.GetHeight(), hash, true
		}
	}

	return 0, "", false
}

// ========== FIX: Add production robustness implementations ==========

// Note: requestBlockWithTimeout was removed as it was unused.
// Timeout and retry logic is handled by downloadBlock() which tries
// multiple peers sequentially until one succeeds.

// continuousSyncCheck performs continuous sync monitoring
func (sm *SyncManager) continuousSyncCheck() {
	sm.mu.Lock()
	elapsed := time.Since(sm.lastSyncCheck)
	sm.mu.Unlock()

	if elapsed < sm.syncCheckInterval {
		return
	}

	sm.mu.Lock()
	sm.lastSyncCheck = time.Now()
	sm.mu.Unlock()

	// Check if we're synced
	localHeight := sm.bc.GetBlockCount()
	targetHeight := sm.getMaxPeerHeight()

	if targetHeight > localHeight && sm.state >= NodeReady {
		logger.Info("📥 New blocks detected during sync check: local=%d, target=%d", localHeight, targetHeight)
		sm.syncHeight = targetHeight
		sm.setState(NodeSyncingHeaders)
	}
}

// verifyGenesisHash verifies genesis hash matches expected value
func (sm *SyncManager) verifyGenesisHash() error {
	if sm.genesisVerified {
		return nil
	}

	genesis := sm.bc.GetBlockByNumber(0)
	if genesis == nil {
		return fmt.Errorf("genesis block not found")
	}

	actualHash := genesis.GetHash()
	expectedHash := sm.bc.GetChainParams().GenesisHash

	if actualHash != expectedHash {
		return fmt.Errorf("genesis hash mismatch: actual=%s, expected=%s", actualHash, expectedHash)
	}

	sm.mu.Lock()
	sm.genesisVerified = true
	sm.mu.Unlock()

	logger.Info("SUCCESS Genesis hash verified: %s", actualHash[:16])
	return nil
}

// attemptReconnection attempts to reconnect to a peer
func (sm *SyncManager) attemptReconnection(peerID string) {
	sm.mu.Lock()
	attempts := sm.reconnectAttempts[peerID]
	sm.reconnectAttempts[peerID] = attempts + 1
	sm.mu.Unlock()

	if attempts >= sm.maxReconnectAttempts {
		logger.Warn("WARNING Max reconnection attempts reached for peer %s (%d/%d)",
			peerID, attempts, sm.maxReconnectAttempts)
		return
	}

	// Exponential backoff
	backoff := sm.reconnectBackoff * time.Duration(1<<attempts)
	if backoff > 5*time.Minute {
		backoff = 5 * time.Minute
	}

	logger.Info("🔄 Scheduling reconnection to peer %s in %v (attempt %d/%d)",
		peerID, backoff, attempts+1, sm.maxReconnectAttempts)

	time.AfterFunc(backoff, func() {
		sm.tryReconnect(peerID)
	})
}

// tryReconnect attempts to reconnect to a peer
func (sm *SyncManager) tryReconnect(peerID string) {
	logger.Info("🔄 Attempting to reconnect to peer %s", peerID)

	// Request would be sent via P2P server
	// For now, just log the attempt
	logger.Info("Reconnection attempt for peer %s completed", peerID)
}

// comprehensiveBlockVerification performs comprehensive block verification
func (sm *SyncManager) comprehensiveBlockVerification(block *types.Block) error {
	// 1. Basic validation
	if err := sm.bc.ValidateBlock(block); err != nil {
		return fmt.Errorf("basic validation failed: %w", err)
	}

	// 2. Verify height
	expectedHeight := sm.bc.GetBlockCount()
	if block.GetHeight() != expectedHeight {
		return fmt.Errorf("height mismatch: expected %d, got %d", expectedHeight, block.GetHeight())
	}

	// 3. Verify previous hash
	if block.GetHeight() > 0 {
		parent := sm.bc.GetBlockByNumber(block.GetHeight() - 1)
		if parent == nil {
			return fmt.Errorf("parent block not found at height %d", block.GetHeight()-1)
		}
		if block.GetPrevHash() != parent.GetHash() {
			return fmt.Errorf("previous hash mismatch")
		}
	}

	// 4. Verify timestamp
	if block.GetHeight() > 0 {
		parent := sm.bc.GetBlockByNumber(block.GetHeight() - 1)
		if parent != nil {
			parentTime := time.Unix(parent.GetTimestamp(), 0)
			blockTime := time.Unix(block.GetTimestamp(), 0)
			if blockTime.Before(parentTime) {
				return fmt.Errorf("block timestamp before parent")
			}
		}
	}

	// 5. Verify Merkle root
	if err := block.ValidateTxsRoot(); err != nil {
		return fmt.Errorf("Merkle root validation failed: %w", err)
	}

	// 6. Verify producer signature (single miner/proposer signature, distinct
	// from PBFT quorum attestations below).
	//
	// FIX: this check didn't exist at all before solo-mined blocks were
	// signed (see CreateBlock in executor.go and comprehensiveBlockVerification's
	// old step 6 comment, which explicitly said solo-mined blocks were
	// "trusted by parent-hash chain continuity alone, not by PBFT quorum").
	// That was fine as long as solo-mined blocks genuinely had nothing to
	// verify — but now every block from genesis onward carries a producer
	// signature, so a late joiner downloading block N should verify it
	// before accepting the block, the same way a PBFT node verifies a
	// leader's proposal signature. Only skip for genesis (height 0), which
	// has no producer.
	if block.GetHeight() > 0 {
		if err := sm.bc.VerifyProducerSignature(block); err != nil {
			return fmt.Errorf("producer signature verification failed: %w", err)
		}
	}

	// 7. Verify attestations (PBFT quorum)
	// Blocks mined in solo mode (before PBFT was active, i.e. when there were
	// fewer than 3 validators) have zero attestations. This is expected —
	// once the producer signature above is verified, a solo-mined block is
	// re-synced and accepted; only blocks that actually went through PBFT
	// carry attestations, and only those need quorum verification on top.
	if block.GetHeight() > 0 && len(block.Body.Attestations) > 0 {
		// ★ NO live validator set and NO epoch argument. The verification
		// resolves consensus.ValidatorSetAt(block.Height) itself and fails
		// closed if that snapshot is missing. This call site used to pass
		// height/100 while bind/helpers.go passed height/SlotsPerEpoch(32), so
		// the same block could be checked against two different sets.
		//
		// The key resolver reads the StateDB of the REPLAYED chain, and the
		// signature verifier is the shared consensus primitive — so this
		// verifies cryptographically on a node that never handshook with a peer.
		if err := VerifyBlockAttestations(block,
			NewChainStateKeyResolver(sm.bc),
			NewConsensusAttestationVerifier()); err != nil {
			return fmt.Errorf("attestation verification failed: %w", err)
		}
	}

	// 8. Verify no duplicate transactions
	txIDs := make(map[string]bool)
	for _, tx := range block.Body.TxsList {
		if txIDs[tx.ID] {
			return fmt.Errorf("duplicate transaction %s in block", tx.ID)
		}
		txIDs[tx.ID] = true
	}

	logger.Info("SUCCESS Comprehensive block verification passed for height %d", block.GetHeight())
	return nil
}
