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

// go/src/consensus/consensus.go
package consensus

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/sphinxorg/protocol/src/common"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	logger "github.com/sphinxorg/protocol/src/log"
	denom "github.com/sphinxorg/protocol/src/params/denom"
)

// Workflow:  ProposeBlock → processProposal → processPrepareVote → processVote → commitBlock → CommitBlock → StoreBlock → storeBlockToDisk.

// NewConsensus creates a new consensus instance with context
func NewConsensus(
	nodeID string,
	nodeManager NodeManager,
	blockchain BlockChain,
	signingService *SigningService,
	onCommit func(Block) error,
	minStakeAmount *big.Int, // NEW: Add this parameter
) *Consensus {

	ctx, cancel := context.WithCancel(context.Background())

	// Initialize PoS components
	genesisSeed := [32]byte{0x53, 0x50, 0x48, 0x58} // "SPHX"
	randao := NewRANDAO(genesisSeed)

	// Create validator set with the provided minimum stake
	validatorSet := NewValidatorSet(minStakeAmount) // Pass it here

	selector := NewStakeWeightedSelector(validatorSet)
	timeConverter := NewTimeConverter(time.Now()) // Will be set properly

	// Add self as validator with stake from blockchain
	if blockchain != nil {
		// Get stake from blockchain state
		stake := blockchain.GetValidatorStake(nodeID)
		if stake != nil {
			// Use the validator set's minimum stake for comparison
			minStake := validatorSet.GetMinStakeAmount()
			if stake.Cmp(minStake) >= 0 {
				// Convert from nSPX to SPX for AddValidator
				stakeSPX := new(big.Int).Div(stake, big.NewInt(denom.SPX))
				validatorSet.AddValidator(nodeID, uint64(stakeSPX.Int64()))
			}
		}

		// Add self with minimum stake if not already added
		if validatorSet.validators[nodeID] == nil {
			minStakeSPX := validatorSet.GetMinStakeSPX()
			logger.Info("Adding self %s with minimum stake %d SPX", nodeID, minStakeSPX)
			validatorSet.AddValidator(nodeID, minStakeSPX)
		}
	}

	return &Consensus{
		nodeID:           nodeID,
		nodeManager:      nodeManager,
		blockChain:       blockchain,
		signingService:   signingService,
		currentView:      0,
		currentHeight:    0,
		phase:            PhaseIdle,
		quorumFraction:   0.67,
		timeout:          300 * time.Second,
		receivedVotes:    make(map[string]map[string]*Vote),
		prepareVotes:     make(map[string]map[string]*Vote),
		sentVotes:        make(map[string]bool),
		sentPrepareVotes: make(map[string]bool),
		proposalCh:       make(chan *Proposal, 100),
		voteCh:           make(chan *Vote, 1000),
		timeoutCh:        make(chan *TimeoutMsg, 100),
		prepareCh:        make(chan *Vote, 1000),
		onCommit:         onCommit,
		ctx:              ctx,
		cancel:           cancel,
		lastViewChange:   common.GetTimeService().Now(),
		viewChangeMutex:  sync.Mutex{},
		lastBlockTime:    common.GetTimeService().Now(),

		// New PoS fields
		validatorSet:         validatorSet,
		randao:               randao,
		selector:             selector,
		timeConverter:        timeConverter,
		useStakeWeighted:     true,
		weightedPrepareVotes: make(map[string]*big.Int),
		weightedCommitVotes:  make(map[string]*big.Int),
		attestations:         make(map[uint64][]*Attestation),
	}
}

// Start begins the consensus process by launching all message handlers
// Returns error if consensus cannot be started
func (c *Consensus) Start() error {
	logger.Info("Consensus started for node %s", c.nodeID)

	// Start message handlers in separate goroutines
	go c.handleProposals()    // Handle incoming block proposals
	go c.handleVotes()        // Handle incoming commit votes
	go c.handlePrepareVotes() // Handle incoming prepare votes
	go c.handleTimeouts()     // Handle timeout messages
	go c.consensusLoop()      // Main consensus loop

	return nil
}

// GetNodeID returns the node ID of this consensus instance
func (c *Consensus) GetNodeID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nodeID
}

// Add this method to consensus.go
func (c *Consensus) SetTimeout(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timeout = d
}

// Stop halts the consensus process and cleans up resources
// Returns error if consensus cannot be stopped properly
func (c *Consensus) Stop() error {
	logger.Info("Consensus stopped for node %s", c.nodeID)
	c.cancel() // Cancel context to signal all goroutines to stop
	return nil
}

// ProposeBlock proposes a new block for consensus (called by leader)
// block: The block to be proposed for consensus
// Returns error if node is not leader or proposal fails
// ProposeBlock with proper signing
func (c *Consensus) ProposeBlock(block Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isLeader {
		return fmt.Errorf("node %s is not the leader", c.nodeID)
	}

	// IMPORTANT: Sign the block itself BEFORE creating the proposal
	if c.signingService != nil {
		// block must already have its hash finalized via FinalizeHash()
		if err := c.signingService.SignBlock(block); err != nil {
			return fmt.Errorf("failed to sign block header: %w", err)
		}
	}

	// After SignBlock succeeds
	if direct, ok := block.(*types.Block); ok {
		direct.Header.CommitStatus = "proposed"
		direct.Header.SigValid = false
	} else if helper, ok := block.(interface{ GetUnderlyingBlock() *types.Block }); ok {
		if ub := helper.GetUnderlyingBlock(); ub != nil {
			ub.Header.CommitStatus = "proposed"
			ub.Header.SigValid = false
		}
	}

	proposal := &Proposal{
		Block:      block,
		View:       c.currentView,
		ProposerID: c.nodeID,
		Signature:  []byte{},
	}

	// Sign the proposal envelope too (existing behavior)
	if c.signingService != nil {
		if err := c.signingService.SignProposal(proposal); err != nil {
			return fmt.Errorf("failed to sign proposal: %w", err)
		}
	}

	return c.broadcastProposal(proposal)
}

// HandleProposal processes incoming block proposals from other nodes
// proposal: The received block proposal
// Returns error if consensus is stopped or channel is full
func (c *Consensus) HandleProposal(proposal *Proposal) error {
	select {
	case c.proposalCh <- proposal:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("consensus stopped")
	}
}

// HandleVote processes incoming commit votes from other validators
// vote: The received commit vote
// Returns error if consensus is stopped or channel is full
func (c *Consensus) HandleVote(vote *Vote) error {
	select {
	case c.voteCh <- vote:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("consensus stopped")
	}
}

// HandlePrepareVote processes incoming prepare votes from other validators
// vote: The received prepare vote
// Returns error if consensus is stopped or channel is full
func (c *Consensus) HandlePrepareVote(vote *Vote) error {
	select {
	case c.prepareCh <- vote:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("consensus stopped")
	}
}

// HandleTimeout processes incoming timeout messages for view changes
// timeout: The received timeout message
// Returns error if consensus is stopped or channel is full
func (c *Consensus) HandleTimeout(timeout *TimeoutMsg) error {
	select {
	case c.timeoutCh <- timeout:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("consensus stopped")
	}
}

// GetCurrentView returns the current view number
// View represents the current consensus round
func (c *Consensus) GetCurrentView() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentView
}

// IsLeader returns whether this node is the current leader
// Leader is responsible for proposing blocks in the current view
func (c *Consensus) IsLeader() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isLeader
}

// GetPhase returns the current consensus phase
// Phase indicates the progress in the PBFT consensus protocol
func (c *Consensus) GetPhase() ConsensusPhase {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.phase
}

// GetCurrentHeight returns the current block height
// Height represents the number of blocks committed in the chain
func (c *Consensus) GetCurrentHeight() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentHeight
}

// Private methods

// Add to consensus.go - new method
func (c *Consensus) shouldPreventViewChange() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Don't change view if we're in active consensus phases
	if c.phase == PhasePrePrepared || c.phase == PhasePrepared {
		return true
	}

	// Don't change view if we've received recent votes
	if len(c.receivedVotes) > 0 || len(c.prepareVotes) > 0 {
		return true
	}

	return false
}

// consensusLoop is the main consensus loop that handles view change timeouts
// Monitors for view timeouts and initiates view changes when necessary
func (c *Consensus) consensusLoop() {
	viewTimer := time.NewTimer(c.timeout)
	defer viewTimer.Stop()

	for {
		select {
		case <-viewTimer.C:
			// Check if we should prevent view change
			if c.shouldPreventViewChange() {
				logger.Info("🛑 Preventing view change - active consensus")
				viewTimer.Reset(10 * time.Second) // Short retry
				continue
			}

			// Check if we're already at height > 0 (genesis already committed)
			c.mu.RLock()
			currentHeight := c.currentHeight
			c.mu.RUnlock()

			if currentHeight == 0 {
				// Special case: at genesis, we should wait longer
				logger.Info("⏳ At genesis height, extending view change timeout")
				viewTimer.Reset(30 * time.Second)
				continue
			}

			c.startViewChange()
			viewTimer.Reset(c.timeout)

		case <-c.ctx.Done():
			logger.Info("Consensus loop stopped for node %s", c.nodeID)
			return
		}
	}
}

// handleProposals processes incoming block proposals from the proposal channel
// Continuously reads proposals and processes them until consensus stops
func (c *Consensus) handleProposals() {
	for {
		select {
		case proposal, ok := <-c.proposalCh:
			if !ok {
				return // Channel closed
			}
			c.processProposal(proposal)
		case <-c.ctx.Done():
			logger.Info("Proposal handler stopped for node %s", c.nodeID)
			return
		}
	}
}

// handleVotes processes incoming commit votes from the vote channel
// Continuously reads votes and processes them until consensus stops
func (c *Consensus) handleVotes() {
	for {
		select {
		case vote, ok := <-c.voteCh:
			if !ok {
				return // Channel closed
			}
			c.processVote(vote)
		case <-c.ctx.Done():
			logger.Info("Vote handler stopped for node %s", c.nodeID)
			return
		}
	}
}

// handlePrepareVotes processes incoming prepare votes from the prepare channel
// Continuously reads prepare votes and processes them until consensus stops
func (c *Consensus) handlePrepareVotes() {
	for {
		select {
		case vote, ok := <-c.prepareCh:
			if !ok {
				return // Channel closed
			}
			c.processPrepareVote(vote)
		case <-c.ctx.Done():
			logger.Info("Prepare vote handler stopped for node %s", c.nodeID)
			return
		}
	}
}

// handleTimeouts processes incoming timeout messages from the timeout channel
// Continuously reads timeout messages and processes them until consensus stops
func (c *Consensus) handleTimeouts() {
	for {
		select {
		case timeout, ok := <-c.timeoutCh:
			if !ok {
				return // Channel closed
			}
			c.processTimeout(timeout)
		case <-c.ctx.Done():
			logger.Info("Timeout handler stopped for node %s", c.nodeID)
			return
		}
	}
}

// updateLeaderStatus updates the leader status based on current view and validators
// updateLeaderStatus with stake-weighted selection
func (c *Consensus) updateLeaderStatus() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.useStakeWeighted {
		// Fallback to round-robin for testing
		c.updateLeaderStatusRoundRobin()
		return
	}

	// Get current slot/epoch
	currentSlot := c.timeConverter.CurrentSlot()
	currentEpoch := currentSlot / SlotsPerEpoch

	// Check for epoch transition
	if currentEpoch > c.currentEpoch {
		c.onEpochTransition(currentEpoch)
	}

	// Get randomness seed for this slot
	seed := c.randao.GetSeed(currentSlot)

	// Select proposer by stake weight
	selected := c.selector.SelectProposer(currentEpoch, seed)

	if selected == nil {
		c.isLeader = false
		logger.Warn("No validator selected for slot %d", currentSlot)
		return
	}

	c.isLeader = (selected.ID == c.nodeID)

	if c.isLeader {
		logger.Info("✅ Node %s selected as proposer for slot %d with stake %.2f SPX",
			c.nodeID, currentSlot, selected.GetStakeInSPX())
	} else {
		logger.Info("Node %s NOT selected for slot %d (selected: %s with %.2f SPX)",
			c.nodeID, currentSlot, selected.ID, selected.GetStakeInSPX())
	}
}

// onEpochTransition handles epoch changes
func (c *Consensus) onEpochTransition(newEpoch uint64) {
	logger.Info("🔄 Entering epoch %d", newEpoch)

	// Process attestations from previous epoch
	if newEpoch > 0 {
		c.processEpochAttestations(newEpoch - 1)
	}

	c.currentEpoch = newEpoch
}

// Fallback round-robin (keep for testing)
func (c *Consensus) updateLeaderStatusRoundRobin() {
	validators := c.getValidators()
	if len(validators) == 0 {
		c.isLeader = false
		return
	}

	sort.Strings(validators)
	leaderIndex := int(c.currentView) % len(validators)
	expectedLeader := validators[leaderIndex]
	c.isLeader = (expectedLeader == c.nodeID)
}

// FIXED: processProposal with proper signature creation
// FIXED: processProposal with proper signature creation
func (c *Consensus) processProposal(proposal *Proposal) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get nonce safely - handle the multiple return values
	nonce, err := proposal.Block.GetCurrentNonce()
	nonceStr := "unknown"
	if err != nil {
		logger.Warn("Failed to get block nonce: %v", err)
	} else {
		nonceStr = fmt.Sprintf("%d", nonce)
	}

	logger.Info("🔍 DEBUG: Processing proposal for block %s at view %d from %s, nonce: %s",
		proposal.Block.GetHash(), proposal.View, proposal.ProposerID, nonceStr)

	// Use existing block validation
	if err := c.blockChain.ValidateBlock(proposal.Block); err != nil {
		logger.Warn("❌ Block validation failed: %v", err)
		return
	}

	// Check if we already have a prepared block for this height
	if c.preparedBlock != nil && c.preparedBlock.GetHeight() == proposal.Block.GetHeight() {
		logger.Warn("❌ Already have prepared block for height %d, ignoring duplicate proposal",
			proposal.Block.GetHeight())
		return
	}

	// Verify signature if signing service is available
	if c.signingService != nil && len(proposal.Signature) > 0 {
		valid, err := c.signingService.VerifyProposal(proposal)
		if err != nil {
			logger.Warn("❌ Error verifying proposal signature from %s: %v", proposal.ProposerID, err)
			return
		}
		if !valid {
			logger.Warn("❌ Invalid proposal signature from %s", proposal.ProposerID)
			return
		}
		logger.Info("✅ Valid signature for proposal from %s", proposal.ProposerID)
	} else {
		logger.Warn("⚠️ No signing service or empty signature, skipping verification")
	}

	// After the existing proposal signature check, also verify the block signature:
	if c.signingService != nil {
		valid, err := c.signingService.VerifyBlockSignature(proposal.Block)
		if err != nil || !valid {
			logger.Warn("❌ Invalid block header signature from proposer %s: %v",
				proposal.ProposerID, err)
			return
		}
		logger.Info("✅ Block header signature verified for block %s", proposal.Block.GetHash())
	}

	// Mark it verified on the underlying block
	if direct, ok := proposal.Block.(*types.Block); ok {
		direct.Header.SigValid = true
		direct.Header.CommitStatus = "proposed"
	} else if helper, ok := proposal.Block.(interface{ GetUnderlyingBlock() *types.Block }); ok {
		if ub := helper.GetUnderlyingBlock(); ub != nil {
			ub.Header.SigValid = true
			ub.Header.CommitStatus = "proposed"
		}
	}

	// CRITICAL FIX: CAPTURE PROPOSAL SIGNATURE - THIS WAS MISSING!
	signedMsg, err := DeserializeSignedMessage(proposal.Signature)
	var signatureHex string
	if err != nil {
		logger.Warn("Failed to deserialize signed message for storage: %v", err)
		signatureHex = hex.EncodeToString(proposal.Signature)
	} else {
		signatureHex = hex.EncodeToString(signedMsg.Signature)
	}

	consensusSig := &ConsensusSignature{
		BlockHash:    proposal.Block.GetHash(),
		BlockHeight:  proposal.Block.GetHeight(),
		SignerNodeID: proposal.ProposerID,
		Signature:    signatureHex,
		MessageType:  "proposal",
		View:         proposal.View,
		Timestamp:    common.GetTimeService().GetCurrentTimeInfo().ISOLocal,
		Valid:        true,
		MerkleRoot:   "pending_calculation",
		Status:       "proposed",
	}

	// ADD THE SIGNATURE - THIS IS THE CRITICAL MISSING LINE!
	c.addConsensusSig(consensusSig)
	logger.Info("✅ Added proposal signature for block %s", proposal.Block.GetHash())

	// Rest of the existing validation logic...
	if proposal.View < c.currentView {
		logger.Warn("❌ Stale proposal for view %d, current view %d", proposal.View, c.currentView)
		return
	}

	if proposal.View > c.currentView {
		logger.Info("🔄 Advancing view from %d to %d", c.currentView, proposal.View)
		c.currentView = proposal.View
		c.resetConsensusState()
		c.updateLeaderStatus()
	}

	currentHeight := c.blockChain.GetLatestBlock().GetHeight()
	if proposal.Block.GetHeight() != currentHeight+1 {
		logger.Warn("❌ Invalid block height: expected %d, got %d",
			currentHeight+1, proposal.Block.GetHeight())
		return
	}

	if !c.isValidLeader(proposal.ProposerID, proposal.View) {
		logger.Warn("❌ Invalid leader %s for view %d", proposal.ProposerID, proposal.View)
		return
	}

	logger.Info("✅ Node %s accepting proposal for block %s at view %d (height %d, nonce: %s)",
		c.nodeID, proposal.Block.GetHash(), proposal.View, proposal.Block.GetHeight(), nonceStr)

	c.preparedBlock = proposal.Block
	c.preparedView = proposal.View
	c.phase = PhasePrePrepared

	logger.Info("💾 Stored prepared block: hash=%s, view=%d, phase=%v, nonce=%s",
		proposal.Block.GetHash(), proposal.View, c.phase, nonceStr)

	c.sendPrepareVote(proposal.Block.GetHash(), proposal.View)
}

// CacheMerkleRoot stores a merkle root in the local cache
func (c *Consensus) CacheMerkleRoot(blockHash, merkleRoot string) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	if c.merkleRootCache == nil {
		c.merkleRootCache = make(map[string]string)
	}
	c.merkleRootCache[blockHash] = merkleRoot
	logger.Info("Cached merkle root for block %s: %s", blockHash, merkleRoot)
}

// GetCachedMerkleRoot retrieves a merkle root from the local cache
func (c *Consensus) GetCachedMerkleRoot(blockHash string) string {
	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()

	if c.merkleRootCache != nil {
		if root, exists := c.merkleRootCache[blockHash]; exists {
			return root
		}
	}
	return ""
}

// determineStatusFromMessageType maps message types to status strings
func (c *Consensus) StatusFromMsgType(messageType string) string {
	switch messageType {
	case "proposal":
		return "proposed"
	case "prepare":
		return "prepared"
	case "commit":
		return "committed"
	case "timeout":
		return "view_change"
	default:
		return "processed"
	}
}

// processPrepareVote handles a received prepare vote
// Tracks prepare votes and progresses to prepared phase when quorum is reached
// processPrepareVote handles a received prepare vote
// Enhanced processPrepareVote method
// Enhanced processPrepareVote with stake tracking
func (c *Consensus) processPrepareVote(vote *Vote) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify signature
	if c.signingService != nil && len(vote.Signature) > 0 {
		valid, err := c.signingService.VerifyVote(vote)
		if err != nil || !valid {
			logger.Warn("Invalid prepare vote signature from %s", vote.VoterID)
			return
		}
	}

	// Initialize vote tracking - DO THIS ONCE
	if c.prepareVotes[vote.BlockHash] == nil {
		c.prepareVotes[vote.BlockHash] = make(map[string]*Vote)
		c.weightedPrepareVotes[vote.BlockHash] = big.NewInt(0)
	}

	// Check if already voted
	if _, exists := c.prepareVotes[vote.BlockHash][vote.VoterID]; exists {
		return
	}

	// Store the prepare vote
	c.prepareVotes[vote.BlockHash][vote.VoterID] = vote

	// Add stake weight
	stake := c.getValidatorStake(vote.VoterID)
	c.weightedPrepareVotes[vote.BlockHash].Add(c.weightedPrepareVotes[vote.BlockHash], stake)

	// Log in SPX
	stakeSPX := new(big.Float).Quo(
		new(big.Float).SetInt(stake),
		new(big.Float).SetFloat64(denom.SPX),
	)

	logger.Info("📊 Prepare vote: %s, block=%s, stake=%.2f SPX",
		vote.VoterID, vote.BlockHash, stakeSPX)

	totalVotes := len(c.prepareVotes[vote.BlockHash])
	quorumSize := c.calculateQuorumSize(c.getTotalNodes())

	logger.Info("📊 Prepare vote received: node=%s, from=%s, block=%s, votes=%d/%d, phase=%v, prepared=%v",
		c.nodeID, vote.VoterID, vote.BlockHash, totalVotes, quorumSize, c.phase, c.preparedBlock != nil)

	// Check if we have enough prepare votes to progress
	if c.hasPrepareQuorum(vote.BlockHash) {
		logger.Info("🎉 PREPARE QUORUM ACHIEVED for block %s at view %d", vote.BlockHash, vote.View)

		// CRITICAL FIX: Ensure we have the prepared block
		if c.preparedBlock == nil || c.preparedBlock.GetHash() != vote.BlockHash {
			logger.Warn("❌ No prepared block found for hash %s (have: %v)",
				vote.BlockHash, c.preparedBlock != nil)
			if c.preparedBlock != nil {
				logger.Warn("   Current prepared block hash: %s", c.preparedBlock.GetHash())
			}
			return
		}

		// CAPTURE PREPARE VOTE SIGNATURE
		signedMsg, err := DeserializeSignedMessage(vote.Signature)
		var signatureHex string
		if err != nil {
			logger.Warn("Failed to deserialize prepare vote for storage: %v", err)
			signatureHex = hex.EncodeToString(vote.Signature)
		} else {
			signatureHex = hex.EncodeToString(signedMsg.Signature)
		}

		consensusSig := &ConsensusSignature{
			BlockHash:    vote.BlockHash,
			BlockHeight:  c.currentHeight,
			SignerNodeID: vote.VoterID,
			Signature:    signatureHex,
			MessageType:  "prepare",
			View:         vote.View,
			Timestamp:    common.GetTimeService().GetCurrentTimeInfo().ISOLocal,
			Valid:        true,
			MerkleRoot:   "pending_calculation",
			Status:       "prepared",
		}
		c.addConsensusSig(consensusSig)

		// Move to prepared phase only if we're in pre-prepared phase
		if c.phase == PhasePrePrepared {
			c.phase = PhasePrepared
			c.lockedBlock = c.preparedBlock
			if direct, ok := c.preparedBlock.(*types.Block); ok {
				direct.Header.CommitStatus = "prepared"
			} else if helper, ok := c.preparedBlock.(interface{ GetUnderlyingBlock() *types.Block }); ok {
				if ub := helper.GetUnderlyingBlock(); ub != nil {
					ub.Header.CommitStatus = "prepared"
				}
			}

			// Send commit vote
			c.voteForBlock(vote.BlockHash, vote.View)
		} else {
			logger.Info("⚠️ Already in phase %v, skipping phase transition", c.phase)
		}
	}
}

// CORRECTED: Safe merkle root extraction without interface changes
func (c *Consensus) addConsensusSig(sig *ConsensusSignature) {
	c.signatureMutex.Lock()
	defer c.signatureMutex.Unlock()

	logger.Info("🔄 Adding consensus signature for block %s (type: %s)",
		sig.BlockHash, sig.MessageType)

	// PRIORITY 1: Try our internal cache (fast)
	if sig.MerkleRoot == "" {
		cachedRoot := c.GetCachedMerkleRoot(sig.BlockHash)
		if cachedRoot != "" {
			sig.MerkleRoot = cachedRoot
			logger.Info("✅ SUCCESS: Got merkle root from internal cache: %s", sig.MerkleRoot)
		}
	}

	// PRIORITY 2: Extract from block using reflection or specific methods
	if sig.MerkleRoot == "" || sig.MerkleRoot == "pending_calculation" {
		logger.Info("🔍 Looking up block %s in storage for merkle root", sig.BlockHash)
		block := c.blockChain.GetBlockByHash(sig.BlockHash)
		if block != nil {
			sig.MerkleRoot = c.extractMerkleRootFromBlock(block)
			if sig.MerkleRoot != "" && sig.MerkleRoot != "pending_calculation" {
				c.CacheMerkleRoot(sig.BlockHash, sig.MerkleRoot)
				logger.Info("✅ SUCCESS: Extracted merkle root: %s", sig.MerkleRoot)
			}
		} else {
			sig.MerkleRoot = fmt.Sprintf("not_in_storage_%s", sig.BlockHash[:8])
			logger.Warn("⚠️ Block not found in storage yet: %s", sig.BlockHash)
		}
	}

	// EMERGENCY FALLBACK: Never leave it empty
	if sig.MerkleRoot == "" {
		sig.MerkleRoot = fmt.Sprintf("emergency_fallback_%s", sig.BlockHash[:8])
		logger.Error("🚨 CRITICAL: Used emergency fallback for merkle root!")
	}

	// Ensure status is never empty
	if sig.Status == "" {
		sig.Status = c.StatusFromMsgType(sig.MessageType)
		logger.Info("✅ Set status: %s", sig.Status)
	}

	c.consensusSignatures = append(c.consensusSignatures, sig)

	logger.Info("🎯 FINAL - Added signature: block=%s, merkle_root=%s, status=%s",
		sig.BlockHash, sig.MerkleRoot, sig.Status)
}

// Helper method to extract merkle root from any block type
func (c *Consensus) extractMerkleRootFromBlock(block Block) string {
	// Try to get the underlying block from BlockHelper
	if blockHelper, ok := block.(interface{ GetUnderlyingBlock() *types.Block }); ok {
		if underlyingBlock := blockHelper.GetUnderlyingBlock(); underlyingBlock != nil {
			if underlyingBlock.Header != nil && len(underlyingBlock.Header.TxsRoot) > 0 {
				return fmt.Sprintf("%x", underlyingBlock.Header.TxsRoot)
			}
		}
	}

	// Try direct type assertion to *types.Block (if possible)
	// This might work if the blockchain returns the actual types.Block
	val := reflect.ValueOf(block)
	if val.Kind() == reflect.Ptr {
		elem := val.Elem()
		if elem.Type().Name() == "Block" {
			// Try to access Header field via reflection
			headerField := elem.FieldByName("Header")
			if headerField.IsValid() {
				txsRootField := headerField.FieldByName("TxsRoot")
				if txsRootField.IsValid() && !txsRootField.IsZero() {
					return fmt.Sprintf("%x", txsRootField.Interface())
				}
			}
		}
	}

	// Last resort: check if block has a method to get transactions
	if txGetter, ok := block.(interface{ GetTransactions() []interface{} }); ok {
		txs := txGetter.GetTransactions()
		if len(txs) > 0 {
			// Calculate merkle root from transactions if possible
			return fmt.Sprintf("calculated_from_%d_txs", len(txs))
		}
	}

	return fmt.Sprintf("no_merkle_info_%s", block.GetHash()[:8])
}

// DebugConsensusSignaturesDeep provides deep debugging of consensus signatures
func (c *Consensus) DebugConsensusSignaturesDeep() {
	c.signatureMutex.RLock()
	defer c.signatureMutex.RUnlock()

	logger.Info("🔍 DEEP DEBUG: Current consensus signatures (%d total):", len(c.consensusSignatures))
	for i, sig := range c.consensusSignatures {
		logger.Info("  Signature %d:", i)
		logger.Info("    - BlockHash: %s", sig.BlockHash)
		logger.Info("    - BlockHeight: %d", sig.BlockHeight)
		logger.Info("    - MessageType: %s", sig.MessageType)
		logger.Info("    - MerkleRoot: '%s' (len=%d)", sig.MerkleRoot, len(sig.MerkleRoot))
		logger.Info("    - Status: '%s' (len=%d)", sig.Status, len(sig.Status))
		logger.Info("    - Valid: %t", sig.Valid)
		logger.Info("    - Timestamp: %s", sig.Timestamp)

		// Check if block exists in blockchain
		block := c.blockChain.GetBlockByHash(sig.BlockHash)
		if block != nil {
			logger.Info("    - Block exists in chain: true")
			if typesBlock, ok := block.(*types.Block); ok {
				if typesBlock.Header != nil {
					logger.Info("    - Header.TxsRoot: %x (len=%d)", typesBlock.Header.TxsRoot, len(typesBlock.Header.TxsRoot))
				} else {
					logger.Info("    - Header is nil")
				}
			} else {
				logger.Info("    - Block type assertion failed")
			}
		} else {
			logger.Info("    - Block exists in chain: false")
		}
	}
}

// Add this method to your consensus.go file
// ForcePopulateAllSignatures ensures all existing signatures have proper merkle_root and status
func (c *Consensus) ForcePopulateAllSignatures() {
	c.signatureMutex.Lock()
	defer c.signatureMutex.Unlock()

	logger.Info("🔄 Force populating all consensus signatures")

	for i, sig := range c.consensusSignatures {
		// Force re-population of merkle_root and status
		originalMerkleRoot := sig.MerkleRoot
		originalStatus := sig.Status

		// CORRECTED: Safer type handling
		block := c.blockChain.GetBlockByHash(sig.BlockHash)
		if block != nil {
			var merkleRoot string

			switch b := block.(type) {
			case *types.Block:
				if b.Header != nil && len(b.Header.TxsRoot) > 0 {
					merkleRoot = fmt.Sprintf("%x", b.Header.TxsRoot)
				}
			case Block:
				// Try to get merkle root via interface methods
				if merkleRootGetter, ok := b.(interface{ GetMerkleRoot() string }); ok {
					merkleRoot = merkleRootGetter.GetMerkleRoot()
				}
			}

			if merkleRoot != "" {
				sig.MerkleRoot = merkleRoot
			} else {
				sig.MerkleRoot = fmt.Sprintf("no_merkle_info_%s", sig.BlockHash[:8])
			}
		} else {
			sig.MerkleRoot = fmt.Sprintf("block_not_found_%s", sig.BlockHash[:8])
			logger.Warn("⚠️ Block not found for hash %s", sig.BlockHash)
		}

		if sig.Status == "" {
			switch sig.MessageType {
			case "proposal":
				sig.Status = "proposed"
			case "prepare":
				sig.Status = "prepared"
			case "commit":
				sig.Status = "committed"
			case "timeout":
				sig.Status = "view_change"
			default:
				sig.Status = "unknown"
			}
			logger.Debug("✅ Force populated status for %s: %s", sig.BlockHash, sig.Status)
		}

		logger.Info("🔄 Signature %d: block=%s, merkle_root=%s->%s, status=%s->%s",
			i, sig.BlockHash, originalMerkleRoot, sig.MerkleRoot, originalStatus, sig.Status)
	}

	logger.Info("✅ Force population completed for %d signatures", len(c.consensusSignatures))
}

func (c *Consensus) GetConsensusSignatures() []*ConsensusSignature {
	c.signatureMutex.RLock()
	defer c.signatureMutex.RUnlock()

	// Return a copy to avoid concurrent modification
	signatures := make([]*ConsensusSignature, len(c.consensusSignatures))
	copy(signatures, c.consensusSignatures)
	return signatures
}

// processVote handles a received commit vote
// Tracks commit votes and commits block when quorum is reached
// Enhanced processVote method to ensure commit happens
// Enhanced processVote method
// Enhanced processVote with stake tracking
func (c *Consensus) processVote(vote *Vote) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify signature
	if c.signingService != nil && len(vote.Signature) > 0 {
		valid, err := c.signingService.VerifyVote(vote)
		if err != nil || !valid {
			logger.Warn("Invalid vote signature from %s", vote.VoterID)
			return
		}
	}

	// Initialize vote tracking
	if c.receivedVotes[vote.BlockHash] == nil {
		c.receivedVotes[vote.BlockHash] = make(map[string]*Vote)
		c.weightedCommitVotes[vote.BlockHash] = big.NewInt(0)
	}

	// Check if already voted
	if _, exists := c.receivedVotes[vote.BlockHash][vote.VoterID]; exists {
		return
	}

	// Store the commit vote
	c.receivedVotes[vote.BlockHash][vote.VoterID] = vote

	// Get stake - FIX: Always get stake from validator set
	stake := c.getValidatorStake(vote.VoterID)

	// CRITICAL FIX: If stake is zero, check if it's self and assign default
	if stake.Cmp(big.NewInt(0)) == 0 {
		if vote.VoterID == c.nodeID {
			// Self-stake should always be set
			stake = new(big.Int).Mul(big.NewInt(32), big.NewInt(denom.SPX))
			logger.Info("⚠️ Self stake was zero, using default: 32 SPX")
		} else {
			logger.Warn("⚠️ Vote from %s has zero stake", vote.VoterID)
		}
	}

	// Add stake weight
	c.weightedCommitVotes[vote.BlockHash].Add(c.weightedCommitVotes[vote.BlockHash], stake)

	// Log in SPX
	stakeSPX := new(big.Float).Quo(
		new(big.Float).SetInt(stake),
		new(big.Float).SetFloat64(denom.SPX),
	)

	logger.Info("📊 Commit vote: %s, block=%s, stake=%.2f SPX",
		vote.VoterID, vote.BlockHash, stakeSPX)

	totalVotes := len(c.receivedVotes[vote.BlockHash])
	quorumSize := c.calculateQuorumSize(c.getTotalNodes())

	logger.Info("📊 Commit vote received: node=%s, from=%s, block=%s, votes=%d/%d, phase=%v",
		c.nodeID, vote.VoterID, vote.BlockHash, totalVotes, quorumSize, c.phase)

	// Check if we have enough commit votes to commit the block
	if c.hasQuorum(vote.BlockHash) {
		logger.Info("🎉 COMMIT QUORUM ACHIEVED for block %s at view %d", vote.BlockHash, vote.View)

		// Find the block to commit
		var blockToCommit Block
		if c.lockedBlock != nil && c.lockedBlock.GetHash() == vote.BlockHash {
			blockToCommit = c.lockedBlock
		} else if c.preparedBlock != nil && c.preparedBlock.GetHash() == vote.BlockHash {
			blockToCommit = c.preparedBlock
		} else {
			logger.Warn("❌ No block found to commit for hash %s", vote.BlockHash)
			return
		}

		// Ensure we're in the correct phase
		if c.phase != PhaseCommitted {
			c.phase = PhaseCommitted
			logger.Info("🚀 Moving to COMMITTED phase for block %s", vote.BlockHash)
		}

		// CAPTURE COMMIT VOTE SIGNATURE
		signedMsg, err := DeserializeSignedMessage(vote.Signature)
		var signatureHex string
		if err != nil {
			logger.Warn("Failed to deserialize commit vote for storage: %v", err)
			signatureHex = hex.EncodeToString(vote.Signature)
		} else {
			signatureHex = hex.EncodeToString(signedMsg.Signature)
		}

		consensusSig := &ConsensusSignature{
			BlockHash:    vote.BlockHash,
			BlockHeight:  c.currentHeight,
			SignerNodeID: vote.VoterID,
			Signature:    signatureHex,
			MessageType:  "commit",
			View:         vote.View,
			Timestamp:    common.GetTimeService().GetCurrentTimeInfo().ISOLocal,
			Valid:        true,
			MerkleRoot:   "pending_calculation",
			Status:       "committed",
		}
		c.addConsensusSig(consensusSig)

		// Commit the block
		c.commitBlock(blockToCommit)
	}
}

// processTimeout handles a received timeout message with proper mutex handling
func (c *Consensus) processTimeout(timeout *TimeoutMsg) {
	c.mu.Lock()
	defer c.mu.Unlock() // Use defer to ensure unlock happens exactly once

	logger.Debug("Processing timeout from %s for view %d (current view: %d)",
		timeout.VoterID, timeout.View, c.currentView)

	// Verify signature if signing service is available
	if c.signingService != nil && len(timeout.Signature) > 0 {
		valid, err := c.signingService.VerifyTimeout(timeout)
		if err != nil {
			logger.Warn("Error verifying timeout signature from %s: %v", timeout.VoterID, err)
			return // Mutex will be unlocked by defer
		}
		if !valid {
			logger.Warn("Invalid timeout signature from %s", timeout.VoterID)
			return // Mutex will be unlocked by defer
		}
		logger.Debug("✅ Valid timeout signature from %s", timeout.VoterID)
	} else if c.signingService == nil {
		logger.Warn("WARNING: No signing service, accepting unsigned timeout from %s", timeout.VoterID)
	} else {
		logger.Warn("WARNING: Empty signature from %s, accepting timeout", timeout.VoterID)
	}

	// Only process timeouts for future views
	if timeout.View > c.currentView {
		logger.Info("View change requested to view %d by %s", timeout.View, timeout.VoterID)
		c.currentView = timeout.View
		c.lastViewChange = common.GetTimeService().Now() // Use centralized time
		c.resetConsensusState()

		// Update leader status immediately
		validators := c.getValidators()
		c.updateLeaderStatusWithValidators(validators)

		logger.Info("View change completed: node=%s, new_view=%d, leader=%v",
			c.nodeID, c.currentView, c.isLeader)
	} else if timeout.View == c.currentView {
		logger.Debug("Ignoring timeout for current view %d", timeout.View)
	} else {
		logger.Debug("Ignoring stale timeout for view %d (current: %d)", timeout.View, c.currentView)
	}
	// Mutex automatically unlocked by defer
}

// sendPrepareVote sends a prepare vote for a specific block
// blockHash: The hash of the block being voted on
// view: The consensus view number
// sendPrepareVote with proper signing
func (c *Consensus) sendPrepareVote(blockHash string, view uint64) {
	if c.sentPrepareVotes[blockHash] {
		return
	}

	prepareVote := &Vote{
		BlockHash: blockHash,
		View:      view,
		VoterID:   c.nodeID,
		Signature: []byte{}, // Initialize empty
	}

	// Sign the prepare vote
	if c.signingService != nil {
		if err := c.signingService.SignVote(prepareVote); err != nil {
			logger.Warn("Failed to sign prepare vote: %v", err)
			return
		}
	} else {
		logger.Warn("WARNING: No signing service available, sending unsigned prepare vote")
	}

	// Mark vote as sent and broadcast it
	c.sentPrepareVotes[blockHash] = true
	c.broadcastPrepareVote(prepareVote)

	logger.Info("Node %s sent prepare vote for block %s at view %d", c.nodeID, blockHash, view)
}

// voteForBlock sends a commit vote for a specific block
// blockHash: The hash of the block being voted on
// view: The consensus view number
// Enhanced voteForBlock method with logging
func (c *Consensus) voteForBlock(blockHash string, view uint64) {
	if c.sentVotes[blockHash] {
		logger.Debug("Already sent commit vote for block %s", blockHash)
		return
	}

	// Find the block to vote for (for logging)
	var blockToVote Block
	if c.lockedBlock != nil && c.lockedBlock.GetHash() == blockHash {
		blockToVote = c.lockedBlock
	} else if c.preparedBlock != nil && c.preparedBlock.GetHash() == blockHash {
		blockToVote = c.preparedBlock
	} else {
		logger.Warn("❌ No block found to vote for hash %s", blockHash)
		return
	}

	vote := &Vote{
		BlockHash: blockHash,
		View:      view,
		VoterID:   c.nodeID,
		Signature: []byte{},
	}

	// Sign the commit vote
	if c.signingService != nil {
		if err := c.signingService.SignVote(vote); err != nil {
			logger.Warn("Failed to sign commit vote: %v", err)
			return
		}
	}

	// Mark vote as sent and broadcast it
	c.sentVotes[blockHash] = true
	c.broadcastVote(vote)

	logger.Info("🗳️ Node %s sent COMMIT vote for block %s (height %d) at view %d",
		c.nodeID, blockHash, blockToVote.GetHeight(), view)
}

// hasQuorum checks if enough commit votes have been received for a block
// blockHash: The hash of the block to check
// Returns true if commit quorum is achieved
// hasQuorum checks if enough stake has voted for a block
// hasQuorum checks if enough stake has voted for a block
func (c *Consensus) hasQuorum(blockHash string) bool {
	votes := c.receivedVotes[blockHash]
	if votes == nil {
		return false
	}

	// Calculate total stake that voted
	totalStakeVoted := big.NewInt(0)
	for voterID := range votes {
		stake := c.getValidatorStake(voterID)
		if stake != nil {
			totalStakeVoted.Add(totalStakeVoted, stake)
		}
	}

	// Store for later use
	c.weightedCommitVotes[blockHash] = totalStakeVoted

	// Get total active stake
	totalStake := c.validatorSet.GetTotalStake()

	// SAFETY CHECK: If total stake is zero, can't have quorum
	if totalStake == nil || totalStake.Cmp(big.NewInt(0)) == 0 {
		logger.Warn("Total stake is zero, cannot achieve quorum")
		return false
	}

	// Check if 2/3 of total stake voted
	requiredStake := new(big.Int).Mul(totalStake, big.NewInt(2))
	requiredStake.Div(requiredStake, big.NewInt(3))

	hasQuorum := totalStakeVoted.Cmp(requiredStake) >= 0

	if hasQuorum && totalStakeVoted.Cmp(big.NewInt(0)) > 0 {
		// Only log if we have positive stake values
		votedSPX := new(big.Float).Quo(
			new(big.Float).SetInt(totalStakeVoted),
			new(big.Float).SetFloat64(denom.SPX),
		)
		totalSPX := new(big.Float).Quo(
			new(big.Float).SetInt(totalStake),
			new(big.Float).SetFloat64(denom.SPX),
		)

		// SAFETY CHECK: Ensure totalSPX is not zero
		if totalSPX.Cmp(big.NewFloat(0)) != 0 {
			percentage := new(big.Float).Quo(votedSPX, totalSPX)
			percentage.Mul(percentage, big.NewFloat(100))
			logger.Info("🎯 Quorum achieved: %.2f / %.2f SPX voted (%.1f%%)",
				votedSPX, totalSPX, percentage)
		} else {
			logger.Info("🎯 Quorum achieved: %.2f SPX voted", votedSPX)
		}
	}

	return hasQuorum
}

// hasPrepareQuorum with stake weighting
func (c *Consensus) hasPrepareQuorum(blockHash string) bool {
	votes := c.prepareVotes[blockHash]
	if votes == nil {
		return false
	}

	totalStakeVoted := big.NewInt(0)
	for voterID := range votes {
		stake := c.getValidatorStake(voterID)
		if stake != nil {
			totalStakeVoted.Add(totalStakeVoted, stake)
		}
	}

	c.weightedPrepareVotes[blockHash] = totalStakeVoted

	totalStake := c.validatorSet.GetTotalStake()

	// SAFETY CHECK: If total stake is zero, can't have quorum
	if totalStake == nil || totalStake.Cmp(big.NewInt(0)) == 0 {
		logger.Warn("Total stake is zero, cannot achieve prepare quorum")
		return false
	}

	requiredStake := new(big.Int).Mul(totalStake, big.NewInt(2))
	requiredStake.Div(requiredStake, big.NewInt(3))

	return totalStakeVoted.Cmp(requiredStake) >= 0
}

// getValidatorStake retrieves a validator's stake
func (c *Consensus) getValidatorStake(validatorID string) *big.Int {
	c.validatorSet.mu.RLock()
	defer c.validatorSet.mu.RUnlock()

	if val, exists := c.validatorSet.validators[validatorID]; exists {
		return val.StakeAmount
	}
	return big.NewInt(0)
}

// calculateQuorumSize calculates the minimum number of votes needed for quorum
// totalNodes: Total number of active validator nodes
// Returns the quorum size (minimum votes required)
func (c *Consensus) calculateQuorumSize(totalNodes int) int {
	quorumSize := int(float64(totalNodes) * c.quorumFraction)
	if quorumSize < 1 {
		return 1 // Ensure at least 1 vote is required
	}
	return quorumSize
}

// getTotalNodes counts the total number of active validator nodes
// Includes both peers and self if this node is a validator
// Returns total count of active validators
func (c *Consensus) getTotalNodes() int {
	peers := c.nodeManager.GetPeers()
	validatorCount := 0

	// Count active validator peers
	for _, peer := range peers {
		node := peer.GetNode()
		if node.GetRole() == RoleValidator && node.GetStatus() == NodeStatusActive {
			validatorCount++
		}
	}

	// Include self if this node is a validator
	if c.isValidator() {
		validatorCount++
	}

	return validatorCount
}

// commitBlock commits a block to the blockchain
func (c *Consensus) commitBlock(block Block) {
	logger.Info("🚀 Node %s attempting to commit block %s at height %d",
		c.nodeID, block.GetHash(), block.GetHeight())

	currentHeight := c.blockChain.GetLatestBlock().GetHeight()
	if block.GetHeight() != currentHeight+1 {
		logger.Warn("❌ Block height mismatch: expected %d, got %d", currentHeight+1, block.GetHeight())
		return
	}

	// ✅ Extract the underlying *types.Block regardless of wrapper type
	var tb *types.Block

	// Direct type assertion first
	if direct, ok := block.(*types.Block); ok {
		tb = direct
		logger.Info("✅ commitBlock: direct *types.Block assertion succeeded")
	} else if helper, ok := block.(interface{ GetUnderlyingBlock() *types.Block }); ok {
		// Unwrap BlockHelper
		tb = helper.GetUnderlyingBlock()
		logger.Info("✅ commitBlock: unwrapped *types.Block from BlockHelper")
	}

	if tb == nil {
		logger.Error("❌ commitBlock: cannot extract *types.Block from %T — attestations will be missing", block)
	} else {
		tb.Header.CommitStatus = "committed"
		if len(tb.Header.ProposerSignature) > 0 {
			tb.Header.SigValid = true
		}

		// Snapshot votes immediately
		votesSnapshot := make(map[string]*Vote)
		if votes, exists := c.receivedVotes[block.GetHash()]; exists {
			for k, v := range votes {
				votesSnapshot[k] = v
			}
		}

		logger.Info("🔍 PRE-COMMIT vote snapshot for block %s: %d votes",
			block.GetHash(), len(votesSnapshot))

		if len(votesSnapshot) > 0 {
			tb.Body.Attestations = make([]*types.Attestation, 0, len(votesSnapshot))
			for voterID, vote := range votesSnapshot {
				att := &types.Attestation{
					ValidatorID: voterID,
					BlockHash:   block.GetHash(),
					View:        vote.View,
					Signature:   vote.Signature,
				}
				tb.Body.Attestations = append(tb.Body.Attestations, att)
			}
			logger.Info("✅ Attached %d attestations to block %s before commit",
				len(tb.Body.Attestations), block.GetHash())
		} else {
			logger.Warn("⚠️ No votes in snapshot for block %s — attestations will be empty",
				block.GetHash())
		}

		logger.Info("🔍 PRE-COMMIT attestation count for block %s: %d",
			block.GetHash(), len(tb.Body.Attestations))
	}

	if err := c.blockChain.CommitBlock(block); err != nil {
		logger.Error("❌ Error committing block: %v", err)
		return
	}

	if c.onCommit != nil {
		if err := c.onCommit(block); err != nil {
			logger.Warn("⚠️ Error in commit callback: %v", err)
		}
	}

	c.currentHeight = block.GetHeight()
	c.lastBlockTime = common.GetTimeService().Now()
	c.resetConsensusState()

	logger.Info("🎉 Node %s successfully committed block %s at height %d",
		c.nodeID, block.GetHash(), c.currentHeight)
}

// startViewChange initiates a view change to the next view with aggressive prevention
// to avoid rapid view changes and maintain consensus stability
func (c *Consensus) startViewChange() {
	// Try to acquire view change lock with timeout
	if !c.tryViewChangeLock() {
		logger.Debug("View change already in progress for node %s", c.nodeID)
		return
	}
	defer c.viewChangeMutex.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock() // Use defer to ensure unlock

	// Don't start view change if we're in active consensus
	if c.phase != PhaseIdle {
		logger.Debug("Skipping view change - active consensus in phase %v", c.phase)
		return
	}

	// INCREASE cooldown to 60 seconds
	if common.GetTimeService().Now().Sub(c.lastViewChange) < 60*time.Second {
		logger.Debug("Skipping view change for node %s (cooldown: %v)",
			c.nodeID, common.GetTimeService().Now().Sub(c.lastViewChange))
		return
	}

	// Don't start view change if we've committed a block recently (30 seconds)
	if c.currentHeight > 0 && common.GetTimeService().Now().Sub(c.lastBlockTime) < 30*time.Second {
		logger.Debug("Skipping view change - recent block activity")
		return
	}

	// Check if we have validators available
	validators := c.getValidators()
	if len(validators) == 0 {
		logger.Warn("Skipping view change - no validators available")
		c.mu.Unlock()
		return
	}

	newView := c.currentView + 1
	logger.Info("🔄 Node %s initiating view change to view %d (current height: %d, phase: %v)",
		c.nodeID, newView, c.currentHeight, c.phase)

	// Update consensus state
	c.currentView = newView
	c.lastViewChange = common.GetTimeService().Now() // Use centralized time
	c.resetConsensusState()

	// Update leader status
	c.updateLeaderStatusWithValidators(validators)

	c.mu.Unlock() // Unlock before network operations

	// Create and sign timeout message
	timeoutMsg := &TimeoutMsg{
		View:      newView,
		VoterID:   c.nodeID,
		Signature: []byte{},
		Timestamp: common.GetCurrentTimestamp(), // Use centralized time service
	}

	// Sign the timeout message if signing service is available
	if c.signingService != nil {
		if err := c.signingService.SignTimeout(timeoutMsg); err != nil {
			logger.Warn("Failed to sign timeout message for view %d: %v", newView, err)
			return // Don't re-lock, we're already unlocked
		}
	} else {
		logger.Warn("WARNING: No signing service available, sending unsigned timeout message")
	}

	// Broadcast timeout message to all peers
	if err := c.broadcastTimeout(timeoutMsg); err != nil {
		logger.Warn("Failed to broadcast timeout message for view %d: %v", newView, err)
		return // Don't re-lock
	}

	logger.Info("✅ View change initiated: node=%s, view=%d, new_leader=%v",
		c.nodeID, newView, c.isLeader)
}

// Helper method to safely acquire view change lock
// tryViewChangeLock attempts to acquire the view change lock with a timeout
// Returns true if lock was acquired, false otherwise
func (c *Consensus) tryViewChangeLock() bool {
	// Try to acquire the view change mutex without blocking for too long
	acquired := make(chan bool, 1)

	go func() {
		c.viewChangeMutex.Lock()
		acquired <- true
	}()

	select {
	case <-acquired:
		return true
	case <-time.After(100 * time.Millisecond):
		return false // Couldn't acquire lock in time
	case <-c.ctx.Done():
		return false // Consensus stopped
	}
}

// updateLeaderStatusWithValidators updates the leader status based on current view and validators
func (c *Consensus) updateLeaderStatusWithValidators(validators []string) {
	if len(validators) == 0 {
		c.isLeader = false
		logger.Warn("No validators available for leader election")
		return
	}

	// Sort validators for deterministic leader selection
	sort.Strings(validators)

	// Round-robin leader selection based on view number
	leaderIndex := int(c.currentView) % len(validators)
	expectedLeader := validators[leaderIndex]

	c.isLeader = (expectedLeader == c.nodeID)

	if c.isLeader {
		logger.Info("✅ Node %s elected as leader for view %d (index %d/%d, validators: %v)",
			c.nodeID, c.currentView, leaderIndex, len(validators), validators)
	} else {
		logger.Debug("Node %s is NOT leader for view %d (leader is %s, index %d/%d)",
			c.nodeID, c.currentView, expectedLeader, leaderIndex, len(validators))
	}
}

// resetConsensusState resets the consensus state to initial values
// Called when starting new view or after block commitment
func (c *Consensus) resetConsensusState() {
	c.phase = PhaseIdle
	c.lockedBlock = nil
	c.preparedBlock = nil
	c.preparedView = 0
	c.receivedVotes = make(map[string]map[string]*Vote)
	c.prepareVotes = make(map[string]map[string]*Vote)
	c.sentVotes = make(map[string]bool)
	c.sentPrepareVotes = make(map[string]bool)

	logger.Debug("Consensus state reset for node %s (view: %d)", c.nodeID, c.currentView)
}

// isValidLeader checks if a node is the legitimate leader for a given view
// nodeID: The node ID to check
// view: The consensus view number
// Returns true if the node is the legitimate leader for this view
// isValidLeader checks if a node is the legitimate leader for a given view
func (c *Consensus) isValidLeader(nodeID string, view uint64) bool {
	validators := c.getValidators()
	if len(validators) == 0 {
		return false
	}

	// Sort validators for deterministic leader selection
	sort.Strings(validators)

	// Round-robin leader selection based on view number
	leaderIndex := int(view) % len(validators)
	expectedLeader := validators[leaderIndex]

	isValid := expectedLeader == nodeID

	// Enhanced logging for debugging
	if isValid {
		logger.Info("✅ Valid leader: %s for view %d (index %d/%d)",
			nodeID, view, leaderIndex, len(validators))
	} else {
		logger.Info("❌ Invalid leader: expected %s for view %d (index %d/%d), got %s",
			expectedLeader, view, leaderIndex, len(validators), nodeID)
		logger.Info("   Validators: %v", validators)
	}

	return isValid
}

// getValidators gets the list of active validator node IDs without duplicates
// Enhanced getValidators with better error handling and logging
// getValidators gets the list of active validator node IDs without duplicates
func (c *Consensus) getValidators() []string {
	peers := c.nodeManager.GetPeers()
	validatorSet := make(map[string]bool)
	validators := []string{}

	// Always include self if we're a validator
	if c.isValidator() {
		validatorSet[c.nodeID] = true
		validators = append(validators, c.nodeID)
	}

	// Collect validator peers
	for _, peer := range peers {
		node := peer.GetNode()
		if node != nil && node.GetRole() == RoleValidator && node.GetStatus() == NodeStatusActive {
			nodeID := node.GetID()
			if !validatorSet[nodeID] && nodeID != "" {
				validatorSet[nodeID] = true
				validators = append(validators, nodeID)
			}
		}
	}

	// Sort for deterministic ordering
	sort.Strings(validators)

	if len(validators) == 0 {
		logger.Error("CRITICAL: No validators found for consensus!")
		// Return at least self to prevent complete failure
		return []string{c.nodeID}
	}

	return validators
}

// isValidator checks if this node is a validator
// isValidator checks if this node is a validator
func (c *Consensus) isValidator() bool {
	self := c.nodeManager.GetNode(c.nodeID)
	return self != nil && self.GetRole() == RoleValidator
}

// SetLastBlockTime updates the last block time to track recent block activity
// This should be called whenever a block is committed
func (c *Consensus) SetLastBlockTime(blockTime time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastBlockTime = blockTime
	logger.Debug("Updated last block time for node %s: %v", c.nodeID, blockTime)
}

// GetConsensusState returns a string representation of the current consensus state for debugging
func (c *Consensus) GetConsensusState() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	preparedHash := ""
	if c.preparedBlock != nil {
		preparedHash = c.preparedBlock.GetHash()
	}

	lockedHash := ""
	if c.lockedBlock != nil {
		lockedHash = c.lockedBlock.GetHash()
	}

	// Use centralized time service for time calculations
	currentTime := common.GetTimeService().Now()
	lastViewChangeDuration := currentTime.Sub(c.lastViewChange)
	lastBlockTimeDuration := currentTime.Sub(c.lastBlockTime)

	return fmt.Sprintf(
		"Node=%s, View=%d, Phase=%v, Leader=%v, Height=%d, "+
			"PreparedBlock=%s, LockedBlock=%s, PreparedView=%d, "+
			"LastViewChange=%v, LastBlockTime=%v, "+
			"PrepareVotes=%d, CommitVotes=%d",
		c.nodeID, c.currentView, c.phase, c.isLeader, c.currentHeight,
		preparedHash, lockedHash, c.preparedView,
		lastViewChangeDuration, lastBlockTimeDuration,
		len(c.prepareVotes), len(c.receivedVotes),
	)
}

// Network communication methods
// broadcastProposal broadcasts a block proposal to all peers
// proposal: The proposal to broadcast
// Returns error if broadcast fails
func (c *Consensus) broadcastProposal(proposal *Proposal) error {
	logger.Info("Broadcasting proposal for block %s at view %d",
		proposal.Block.GetHash(), proposal.View)
	return c.nodeManager.BroadcastMessage("proposal", proposal)
}

// broadcastVote broadcasts a commit vote to all peers
// vote: The vote to broadcast
// Returns error if broadcast fails
func (c *Consensus) broadcastVote(vote *Vote) error {
	logger.Info("Broadcasting commit vote for block %s at view %d", vote.BlockHash, vote.View)
	return c.nodeManager.BroadcastMessage("vote", vote)
}

// broadcastPrepareVote broadcasts a prepare vote to all peers
// vote: The prepare vote to broadcast
// Returns error if broadcast fails
func (c *Consensus) broadcastPrepareVote(vote *Vote) error {
	logger.Info("Broadcasting prepare vote for block %s at view %d", vote.BlockHash, vote.View)
	return c.nodeManager.BroadcastMessage("prepare", vote)
}

// broadcastTimeout broadcasts a timeout message to all peers
// timeout: The timeout message to broadcast
// Returns error if broadcast fails
func (c *Consensus) broadcastTimeout(timeout *TimeoutMsg) error {
	logger.Info("Broadcasting timeout for view %d", timeout.View)
	return c.nodeManager.BroadcastMessage("timeout", timeout)
}

// SetLeader sets the leader status for this node
// isLeader: Boolean indicating whether this node should be leader
// Used for testing or manual leader assignment
func (c *Consensus) SetLeader(isLeader bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isLeader = isLeader
	logger.Info("Node %s leader status set to %t", c.nodeID, isLeader)
}
