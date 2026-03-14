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
	minStakeAmount *big.Int,
) *Consensus {

	// Create a cancellable context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize RANDAO with genesis seed for deterministic randomness
	genesisSeed := [32]byte{0x53, 0x50, 0x48, 0x58} // "SPHX"
	randao := NewRANDAO(genesisSeed)

	// Create validator set with minimum stake requirement
	validatorSet := NewValidatorSet(minStakeAmount)

	// Create stake-weighted selector for leader election
	selector := NewStakeWeightedSelector(validatorSet)

	// Use the blockchain's genesis time so every node starts slot counting
	// from the same anchor, producing identical slot numbers and seeds.
	var genesisTime time.Time
	if blockchain != nil {
		genesisTime = blockchain.GetGenesisTime()
	}
	if genesisTime.IsZero() {
		// Fallback: hardcoded genesis timestamp if blockchain doesn't provide one
		genesisTime = time.Unix(1732070400, 0)
	}
	// Create time converter for slot calculations
	timeConverter := NewTimeConverter(genesisTime)

	// Add this node as a validator if it has sufficient stake
	if blockchain != nil {
		// Get this node's stake from the blockchain
		stake := blockchain.GetValidatorStake(nodeID)
		if stake != nil {
			minStake := validatorSet.GetMinStakeAmount()
			// Check if node meets minimum stake requirement
			if stake.Cmp(minStake) >= 0 {
				// Convert to SPX units (div by denomination)
				stakeSPX := new(big.Int).Div(stake, big.NewInt(denom.SPX))
				validatorSet.AddValidator(nodeID, uint64(stakeSPX.Int64()))
			}
		}
		// If node not in validator set, add with minimum stake
		if validatorSet.validators[nodeID] == nil {
			minStakeSPX := validatorSet.GetMinStakeSPX()
			logger.Info("Adding self %s with minimum stake %d SPX", nodeID, minStakeSPX)
			validatorSet.AddValidator(nodeID, minStakeSPX)
		}
	}

	// Return initialized consensus instance with all components
	return &Consensus{
		nodeID:               nodeID,                            // Unique identifier for this node
		nodeManager:          nodeManager,                       // Manages peer connections
		blockChain:           blockchain,                        // Reference to blockchain storage
		signingService:       signingService,                    // Handles cryptographic signatures
		currentView:          0,                                 // Current consensus view (round)
		currentHeight:        0,                                 // Current blockchain height
		phase:                PhaseIdle,                         // Current consensus phase
		quorumFraction:       0.67,                              // 2/3 majority requirement
		timeout:              300 * time.Second,                 // View change timeout
		receivedVotes:        make(map[string]map[string]*Vote), // Commit votes by block hash
		prepareVotes:         make(map[string]map[string]*Vote), // Prepare votes by block hash
		sentVotes:            make(map[string]bool),             // Track sent commit votes
		sentPrepareVotes:     make(map[string]bool),             // Track sent prepare votes
		proposalCh:           make(chan *Proposal, 100),         // Proposal channel buffer
		voteCh:               make(chan *Vote, 1000),            // Vote channel buffer
		timeoutCh:            make(chan *TimeoutMsg, 100),       // Timeout channel buffer
		prepareCh:            make(chan *Vote, 1000),            // Prepare vote channel buffer
		onCommit:             onCommit,                          // Callback for block commit
		ctx:                  ctx,                               // Context for cancellation
		cancel:               cancel,                            // Cancel function
		lastViewChange:       common.GetTimeService().Now(),     // Last view change timestamp
		viewChangeMutex:      sync.Mutex{},                      // Mutex for view change
		lastBlockTime:        common.GetTimeService().Now(),     // Last block commit timestamp
		validatorSet:         validatorSet,                      // Set of active validators
		randao:               randao,                            // RANDAO instance for randomness
		selector:             selector,                          // Leader selector
		timeConverter:        timeConverter,                     // Slot time converter
		useStakeWeighted:     true,                              // Use stake-weighted leader election
		weightedPrepareVotes: make(map[string]*big.Int),         // Weighted prepare votes by stake
		weightedCommitVotes:  make(map[string]*big.Int),         // Weighted commit votes by stake
		attestations:         make(map[uint64][]*Attestation),   // Attestations by epoch
		electedLeaderID:      "",                                // Set by UpdateLeaderStatus
	}
}

// Start begins the consensus operation by launching all goroutines
func (c *Consensus) Start() error {
	logger.Info("Consensus started for node %s", c.nodeID)
	// Start goroutines for handling different message types
	go c.handleProposals()    // Handle incoming block proposals
	go c.handleVotes()        // Handle incoming commit votes
	go c.handlePrepareVotes() // Handle incoming prepare votes
	go c.handleTimeouts()     // Handle incoming timeout messages
	go c.consensusLoop()      // Main consensus loop for view changes
	return nil
}

// GetNodeID returns the node's identifier
func (c *Consensus) GetNodeID() string {
	c.mu.RLock() // Read lock for thread safety
	defer c.mu.RUnlock()
	return c.nodeID
}

// SetTimeout updates the view change timeout duration
func (c *Consensus) SetTimeout(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timeout = d
}

// Stop gracefully shuts down the consensus instance
func (c *Consensus) Stop() error {
	logger.Info("Consensus stopped for node %s", c.nodeID)
	c.cancel() // Cancel context to stop all goroutines
	return nil
}

// UpdateLeaderStatus runs the stake-weighted RANDAO proposer selection for the
// current slot and stores the result in electedLeaderID so that every node
// uses the exact same leader identity when validating incoming proposals.
//
// Terminal output per node:
//
//	Node X selected as proposer for slot Y with stake Z SPX
//	Node X NOT selected for slot Y (selected: Z with W SPX)
func (c *Consensus) UpdateLeaderStatus() {
	c.updateLeaderStatus() // Call private implementation
}

// updateLeaderStatus is the private implementation.
func (c *Consensus) updateLeaderStatus() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Fall back to round-robin if stake-weighted selection is disabled
	if !c.useStakeWeighted {
		c.updateLeaderStatusRoundRobin()
		return
	}

	// Get current slot and epoch from time converter
	currentSlot := c.timeConverter.CurrentSlot()
	currentEpoch := currentSlot / SlotsPerEpoch

	// Handle epoch transition if we've moved to a new epoch
	if currentEpoch > c.currentEpoch {
		c.onEpochTransition(currentEpoch)
	}

	// Get RANDAO seed for current slot and select proposer
	seed := c.randao.GetSeed(currentSlot)
	selected := c.selector.SelectProposer(currentEpoch, seed)

	// Handle case where no validator was selected
	if selected == nil {
		c.isLeader = false
		c.electedLeaderID = ""
		c.electedSlot = 0
		logger.Warn("No validator selected for slot %d", currentSlot)
		return
	}

	// Store the elected leader information
	c.electedLeaderID = selected.ID
	c.electedSlot = currentSlot // Store the slot used for election
	c.isLeader = (selected.ID == c.nodeID)

	// Log selection status with appropriate formatting
	if c.isLeader {
		logger.Info("✅ Node %s selected as proposer for slot %d with stake %.2f SPX",
			c.nodeID, currentSlot, selected.GetStakeInSPX())
	} else {
		logger.Info("   Node %s NOT selected for slot %d (selected: %s with %.2f SPX)",
			c.nodeID, currentSlot, selected.ID, selected.GetStakeInSPX())
	}
}

// GetElectedLeaderID returns the RANDAO-elected leader from the last UpdateLeaderStatus call.
func (c *Consensus) GetElectedLeaderID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.electedLeaderID
}

// ProposeBlock creates and broadcasts a new block proposal when this node is the leader
func (c *Consensus) ProposeBlock(block Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify this node is actually the leader
	if !c.isLeader {
		return fmt.Errorf("node %s is not the leader", c.nodeID)
	}

	// Sign the block header if signing service is available
	if c.signingService != nil {
		if err := c.signingService.SignBlock(block); err != nil {
			return fmt.Errorf("failed to sign block header: %w", err)
		}
	}

	// Update block metadata for tracking
	if direct, ok := block.(*types.Block); ok {
		direct.Header.CommitStatus = "proposed"
		direct.Header.SigValid = false
	} else if helper, ok := block.(interface{ GetUnderlyingBlock() *types.Block }); ok {
		if ub := helper.GetUnderlyingBlock(); ub != nil {
			ub.Header.CommitStatus = "proposed"
			ub.Header.SigValid = false
		}
	}

	// Use the slot from election time, NOT current slot.
	// By the time ProposeBlock is called, the slot may have advanced,
	// causing followers to re-derive a different winner from the new slot.
	proposalSlot := c.electedSlot
	if proposalSlot == 0 {
		proposalSlot = c.timeConverter.CurrentSlot() // Fallback if election slot not set
	}

	// Create the proposal message
	proposal := &Proposal{
		Block:           block,
		View:            c.currentView,
		ProposerID:      c.nodeID,
		Signature:       []byte{},
		ElectedLeaderID: c.electedLeaderID,
		SlotNumber:      proposalSlot, // Use the election slot, not current slot
	}

	// Sign the proposal if signing service is available
	if c.signingService != nil {
		if err := c.signingService.SignProposal(proposal); err != nil {
			return fmt.Errorf("failed to sign proposal: %w", err)
		}
	}

	// Broadcast the proposal to all peers
	return c.broadcastProposal(proposal)
}

// HandleProposal queues an incoming proposal for processing
func (c *Consensus) HandleProposal(proposal *Proposal) error {
	select {
	case c.proposalCh <- proposal: // Send to proposal channel
		return nil
	case <-c.ctx.Done(): // Check if consensus is stopping
		return fmt.Errorf("consensus stopped")
	}
}

// HandleVote queues an incoming commit vote for processing
func (c *Consensus) HandleVote(vote *Vote) error {
	select {
	case c.voteCh <- vote: // Send to vote channel
		return nil
	case <-c.ctx.Done(): // Check if consensus is stopping
		return fmt.Errorf("consensus stopped")
	}
}

// HandlePrepareVote queues an incoming prepare vote for processing
func (c *Consensus) HandlePrepareVote(vote *Vote) error {
	select {
	case c.prepareCh <- vote: // Send to prepare channel
		return nil
	case <-c.ctx.Done(): // Check if consensus is stopping
		return fmt.Errorf("consensus stopped")
	}
}

// HandleTimeout queues an incoming timeout message for processing
func (c *Consensus) HandleTimeout(timeout *TimeoutMsg) error {
	select {
	case c.timeoutCh <- timeout: // Send to timeout channel
		return nil
	case <-c.ctx.Done(): // Check if consensus is stopping
		return fmt.Errorf("consensus stopped")
	}
}

// GetCurrentView returns the current consensus view number
func (c *Consensus) GetCurrentView() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentView
}

// IsLeader returns whether this node is currently the leader
func (c *Consensus) IsLeader() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isLeader
}

// GetPhase returns the current consensus phase
func (c *Consensus) GetPhase() ConsensusPhase {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.phase
}

// GetCurrentHeight returns the current blockchain height
func (c *Consensus) GetCurrentHeight() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentHeight
}

// shouldPreventViewChange determines if view change should be blocked due to active consensus
func (c *Consensus) shouldPreventViewChange() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	// Block view change if we're in prepare phases
	if c.phase == PhasePrePrepared || c.phase == PhasePrepared {
		return true
	}
	// Block view change if we have pending votes
	if len(c.receivedVotes) > 0 || len(c.prepareVotes) > 0 {
		return true
	}
	return false
}

// consensusLoop is the main loop that manages view change timeouts
func (c *Consensus) consensusLoop() {
	// Create timer for view change timeout
	viewTimer := time.NewTimer(c.timeout)
	defer viewTimer.Stop() // Ensure timer is stopped on exit

	for {
		select {
		case <-viewTimer.C: // View change timeout triggered
			// Check if we should prevent view change due to active consensus
			if c.shouldPreventViewChange() {
				logger.Info("🛑 Preventing view change - active consensus")
				viewTimer.Reset(10 * time.Second) // Short retry
				continue
			}

			// Check if we're at genesis height
			c.mu.RLock()
			currentHeight := c.currentHeight
			c.mu.RUnlock()

			if currentHeight == 0 {
				logger.Info("⏳ At genesis height, extending view change timeout")
				viewTimer.Reset(30 * time.Second) // Longer timeout for genesis
				continue
			}

			// Initiate view change
			c.startViewChange()
			viewTimer.Reset(c.timeout) // Reset timer for next view change

		case <-c.ctx.Done(): // Consensus stopping
			logger.Info("Consensus loop stopped for node %s", c.nodeID)
			return
		}
	}
}

// handleProposals processes incoming block proposals from the proposal channel
func (c *Consensus) handleProposals() {
	for {
		select {
		case proposal, ok := <-c.proposalCh:
			if !ok { // Channel closed
				return
			}
			c.processProposal(proposal) // Process the proposal
		case <-c.ctx.Done(): // Consensus stopping
			logger.Info("Proposal handler stopped for node %s", c.nodeID)
			return
		}
	}
}

// handleVotes processes incoming commit votes from the vote channel
func (c *Consensus) handleVotes() {
	for {
		select {
		case vote, ok := <-c.voteCh:
			if !ok { // Channel closed
				return
			}
			c.processVote(vote) // Process the vote
		case <-c.ctx.Done(): // Consensus stopping
			logger.Info("Vote handler stopped for node %s", c.nodeID)
			return
		}
	}
}

// handlePrepareVotes processes incoming prepare votes from the prepare channel
func (c *Consensus) handlePrepareVotes() {
	for {
		select {
		case vote, ok := <-c.prepareCh:
			if !ok { // Channel closed
				return
			}
			c.processPrepareVote(vote) // Process the prepare vote
		case <-c.ctx.Done(): // Consensus stopping
			logger.Info("Prepare vote handler stopped for node %s", c.nodeID)
			return
		}
	}
}

// handleTimeouts processes incoming timeout messages from the timeout channel
func (c *Consensus) handleTimeouts() {
	for {
		select {
		case timeout, ok := <-c.timeoutCh:
			if !ok { // Channel closed
				return
			}
			c.processTimeout(timeout) // Process the timeout
		case <-c.ctx.Done(): // Consensus stopping
			logger.Info("Timeout handler stopped for node %s", c.nodeID)
			return
		}
	}
}

// onEpochTransition handles logic when moving to a new epoch
func (c *Consensus) onEpochTransition(newEpoch uint64) {
	// NOTE: c.mu is already held by the caller — do NOT lock here.
	logger.Info("🔄 Entering epoch %d", newEpoch)
	// Process attestations from the previous epoch
	if newEpoch > 0 {
		c.processEpochAttestations(newEpoch - 1)
	}
	c.currentEpoch = newEpoch // Update current epoch
}

// updateLeaderStatusRoundRobin elects a leader using round-robin selection
func (c *Consensus) updateLeaderStatusRoundRobin() {
	// Get list of validators
	validators := c.getValidators()
	if len(validators) == 0 {
		c.isLeader = false
		c.electedLeaderID = ""
		return
	}
	// Sort for deterministic ordering
	sort.Strings(validators)
	// Select leader based on current view
	leaderIndex := int(c.currentView) % len(validators)
	expectedLeader := validators[leaderIndex]
	c.electedLeaderID = expectedLeader
	c.isLeader = (expectedLeader == c.nodeID)
}

// processProposal validates and processes an incoming block proposal.
// Leader validation uses electedLeaderID set by UpdateLeaderStatus, so
// follower nodes accept the same RANDAO-elected winner the leader elected itself as.
func (c *Consensus) processProposal(proposal *Proposal) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get block nonce for logging
	nonce, err := proposal.Block.GetCurrentNonce()
	nonceStr := "unknown"
	if err != nil {
		logger.Warn("Failed to get block nonce: %v", err)
	} else {
		nonceStr = fmt.Sprintf("%d", nonce)
	}

	// Log proposal receipt
	logger.Info("🔍 Processing proposal for block %s at view %d from %s, nonce: %s",
		proposal.Block.GetHash(), proposal.View, proposal.ProposerID, nonceStr)

	// Validate the block itself
	if err := c.blockChain.ValidateBlock(proposal.Block); err != nil {
		logger.Warn("❌ Block validation failed: %v", err)
		return
	}

	// Check for duplicate proposal
	if c.preparedBlock != nil && c.preparedBlock.GetHash() == proposal.Block.GetHash() {
		logger.Warn("❌ Already have prepared block for height %d, ignoring duplicate proposal",
			proposal.Block.GetHeight())
		return
	}

	// Verify proposal signature if signing service available
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

	// Verify block header signature
	if c.signingService != nil {
		valid, err := c.signingService.VerifyBlockSignature(proposal.Block)
		if err != nil || !valid {
			logger.Warn("❌ Invalid block header signature from proposer %s: %v", proposal.ProposerID, err)
			return
		}
		logger.Info("✅ Block header signature verified for block %s", proposal.Block.GetHash())
	}

	// Update block metadata for tracking
	if direct, ok := proposal.Block.(*types.Block); ok {
		direct.Header.SigValid = true
		direct.Header.CommitStatus = "proposed"
	} else if helper, ok := proposal.Block.(interface{ GetUnderlyingBlock() *types.Block }); ok {
		if ub := helper.GetUnderlyingBlock(); ub != nil {
			ub.Header.SigValid = true
			ub.Header.CommitStatus = "proposed"
		}
	}

	// Add proposal signature to consensus signatures
	signatureHex := hex.EncodeToString(proposal.Signature)
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
	c.addConsensusSig(consensusSig)
	logger.Info("✅ Added proposal signature for block %s", proposal.Block.GetHash())

	// Check for stale proposal
	if proposal.View < c.currentView {
		logger.Warn("❌ Stale proposal for view %d, current view %d", proposal.View, c.currentView)
		return
	}

	// Handle view advancement if proposal is for a newer view
	if proposal.View > c.currentView {
		logger.Info("🔄 Advancing view from %d to %d", c.currentView, proposal.View)
		c.currentView = proposal.View
		c.resetConsensusState()
		// Re-run so electedLeaderID is refreshed for the new view
		c.updateLeaderStatus()
	}

	// Verify block height matches expected next height
	currentHeight := c.blockChain.GetLatestBlock().GetHeight()
	if proposal.Block.GetHeight() != currentHeight+1 {
		logger.Warn("❌ Invalid block height: expected %d, got %d",
			currentHeight+1, proposal.Block.GetHeight())
		return
	}

	// ── KEY FIX: Re-derive electedLeaderID from the proposal's own slot ──────
	// This eliminates the race where the follower's CurrentSlot() differs from
	// the leader's slot at proposal time, causing a different seed → different winner.
	if proposal.SlotNumber > 0 {
		// Calculate epoch from proposal's slot
		slotEpoch := proposal.SlotNumber / SlotsPerEpoch
		// Get RANDAO seed for that slot
		seed := c.randao.GetSeed(proposal.SlotNumber)
		// Select proposer for that epoch using the seed
		selected := c.selector.SelectProposer(slotEpoch, seed)
		if selected != nil {
			// Use the selected leader
			c.electedLeaderID = selected.ID
			logger.Info("🔄 Follower re-derived electedLeaderID=%s for slot %d (epoch %d)",
				c.electedLeaderID, proposal.SlotNumber, slotEpoch)
		} else {
			// If selection returned nil, accept the proposer's self-declared ID
			// and let signature verification be the security gate.
			logger.Warn("⚠️ SelectProposer returned nil for slot %d, trusting signed proposal", proposal.SlotNumber)
			c.electedLeaderID = proposal.ProposerID
		}
	} else if proposal.ElectedLeaderID != "" {
		// Older proposal without SlotNumber: use the embedded ElectedLeaderID.
		// Security relies entirely on the proposal signature in this path.
		logger.Warn("⚠️ Proposal has no SlotNumber, using embedded ElectedLeaderID=%s", proposal.ElectedLeaderID)
		c.electedLeaderID = proposal.ElectedLeaderID
	} else {
		// Last resort: re-run with current slot (original behaviour, may still race)
		c.updateLeaderStatus()
	}
	// ─────────────────────────────────────────────────────────────────────────

	// Validate that the proposer is the legitimate leader
	if !c.isValidLeader(proposal.ProposerID, proposal.View) {
		logger.Warn("❌ Invalid leader %s for view %d (electedLeaderID=%s)",
			proposal.ProposerID, proposal.View, c.electedLeaderID)
		return
	}

	// Accept the proposal
	logger.Info("✅ Node %s accepting proposal for block %s at view %d (height %d, nonce: %s)",
		c.nodeID, proposal.Block.GetHash(), proposal.View, proposal.Block.GetHeight(), nonceStr)

	// Store prepared block and move to pre-prepared phase
	c.preparedBlock = proposal.Block
	c.preparedView = proposal.View
	c.phase = PhasePrePrepared

	// Send prepare vote for this block
	c.sendPrepareVote(proposal.Block.GetHash(), proposal.View)
}

// CacheMerkleRoot stores a merkle root in cache for quick access
func (c *Consensus) CacheMerkleRoot(blockHash, merkleRoot string) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()
	// Initialize cache if needed
	if c.merkleRootCache == nil {
		c.merkleRootCache = make(map[string]string)
	}
	c.merkleRootCache[blockHash] = merkleRoot
	logger.Info("Cached merkle root for block %s: %s", blockHash, merkleRoot)
}

// GetCachedMerkleRoot retrieves a merkle root from cache
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

// StatusFromMsgType returns the appropriate status string for a message type
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

// processPrepareVote handles incoming prepare votes
func (c *Consensus) processPrepareVote(vote *Vote) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify vote signature if signing service available
	if c.signingService != nil && len(vote.Signature) > 0 {
		valid, err := c.signingService.VerifyVote(vote)
		if err != nil || !valid {
			logger.Warn("Invalid prepare vote signature from %s", vote.VoterID)
			return
		}
	}

	// Initialize vote tracking maps for this block if needed
	if c.prepareVotes[vote.BlockHash] == nil {
		c.prepareVotes[vote.BlockHash] = make(map[string]*Vote)
		c.weightedPrepareVotes[vote.BlockHash] = big.NewInt(0)
	}

	// Ignore duplicate votes
	if _, exists := c.prepareVotes[vote.BlockHash][vote.VoterID]; exists {
		return
	}

	// Store the vote
	c.prepareVotes[vote.BlockHash][vote.VoterID] = vote

	// Add voter's stake to weighted vote total
	stake := c.getValidatorStake(vote.VoterID)
	c.weightedPrepareVotes[vote.BlockHash].Add(c.weightedPrepareVotes[vote.BlockHash], stake)

	// Log vote receipt with stake amount in SPX
	stakeSPX := new(big.Float).Quo(new(big.Float).SetInt(stake), new(big.Float).SetFloat64(denom.SPX))
	logger.Info("📊 Prepare vote: %s, block=%s, stake=%.2f SPX", vote.VoterID, vote.BlockHash, stakeSPX)

	// Calculate current vote count and quorum requirements
	totalVotes := len(c.prepareVotes[vote.BlockHash])
	quorumSize := c.calculateQuorumSize(c.getTotalNodes())

	logger.Info("📊 Prepare vote received: node=%s, from=%s, block=%s, votes=%d/%d, phase=%v, prepared=%v",
		c.nodeID, vote.VoterID, vote.BlockHash, totalVotes, quorumSize, c.phase, c.preparedBlock != nil)

	// Check if we've achieved quorum for this block
	if c.hasPrepareQuorum(vote.BlockHash) {
		logger.Info("🎉 PREPARE QUORUM ACHIEVED for block %s at view %d", vote.BlockHash, vote.View)

		// Verify we have a prepared block for this hash
		if c.preparedBlock == nil || c.preparedBlock.GetHash() != vote.BlockHash {
			logger.Warn("❌ No prepared block found for hash %s (have: %v)", vote.BlockHash, c.preparedBlock != nil)
			if c.preparedBlock != nil {
				logger.Warn("   Current prepared block hash: %s", c.preparedBlock.GetHash())
			}
			return
		}

		// Add this vote to consensus signatures
		signatureHex := hex.EncodeToString(vote.Signature)
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

		// Transition to prepared phase if we're in pre-prepared
		if c.phase == PhasePrePrepared {
			c.phase = PhasePrepared
			c.lockedBlock = c.preparedBlock
			// Update block metadata
			if direct, ok := c.preparedBlock.(*types.Block); ok {
				direct.Header.CommitStatus = "prepared"
			} else if helper, ok := c.preparedBlock.(interface{ GetUnderlyingBlock() *types.Block }); ok {
				if ub := helper.GetUnderlyingBlock(); ub != nil {
					ub.Header.CommitStatus = "prepared"
				}
			}
			// Send commit vote for this block
			c.voteForBlock(vote.BlockHash, vote.View)
		} else {
			logger.Info("⚠️ Already in phase %v, skipping phase transition", c.phase)
		}
	}
}

// addConsensusSig adds a signature to the consensus signatures collection
func (c *Consensus) addConsensusSig(sig *ConsensusSignature) {
	c.signatureMutex.Lock()
	defer c.signatureMutex.Unlock()

	logger.Info("🔄 Adding consensus signature for block %s (type: %s)", sig.BlockHash, sig.MessageType)

	// Try to get merkle root from cache first
	if sig.MerkleRoot == "" {
		if cachedRoot := c.GetCachedMerkleRoot(sig.BlockHash); cachedRoot != "" {
			sig.MerkleRoot = cachedRoot
		}
	}

	// If merkle root still missing, try to extract from block
	if sig.MerkleRoot == "" || sig.MerkleRoot == "pending_calculation" {
		block := c.blockChain.GetBlockByHash(sig.BlockHash)
		if block != nil {
			sig.MerkleRoot = c.extractMerkleRootFromBlock(block)
			if sig.MerkleRoot != "" && sig.MerkleRoot != "pending_calculation" {
				c.CacheMerkleRoot(sig.BlockHash, sig.MerkleRoot)
			}
		} else {
			sig.MerkleRoot = fmt.Sprintf("not_in_storage_%s", sig.BlockHash[:8])
			logger.Warn("⚠️ Block not found in storage yet: %s", sig.BlockHash)
		}
	}

	// Emergency fallback if merkle root still empty
	if sig.MerkleRoot == "" {
		sig.MerkleRoot = fmt.Sprintf("emergency_fallback_%s", sig.BlockHash[:8])
		logger.Error("🚨 CRITICAL: Used emergency fallback for merkle root!")
	}

	// Set status if not already set
	if sig.Status == "" {
		sig.Status = c.StatusFromMsgType(sig.MessageType)
	}

	// Append to signatures collection
	c.consensusSignatures = append(c.consensusSignatures, sig)
	logger.Info("🎯 Added signature: block=%s, merkle_root=%s, status=%s", sig.BlockHash, sig.MerkleRoot, sig.Status)
}

// extractMerkleRootFromBlock attempts to extract the merkle root from a block
func (c *Consensus) extractMerkleRootFromBlock(block Block) string {
	// Try to get underlying block and extract from header
	if blockHelper, ok := block.(interface{ GetUnderlyingBlock() *types.Block }); ok {
		if ub := blockHelper.GetUnderlyingBlock(); ub != nil {
			if ub.Header != nil && len(ub.Header.TxsRoot) > 0 {
				return fmt.Sprintf("%x", ub.Header.TxsRoot)
			}
		}
	}

	// Try reflection to find TxsRoot field
	val := reflect.ValueOf(block)
	if val.Kind() == reflect.Ptr {
		elem := val.Elem()
		if elem.Type().Name() == "Block" {
			headerField := elem.FieldByName("Header")
			if headerField.IsValid() {
				txsRootField := headerField.FieldByName("TxsRoot")
				if txsRootField.IsValid() && !txsRootField.IsZero() {
					return fmt.Sprintf("%x", txsRootField.Interface())
				}
			}
		}
	}

	// Try to get from transaction count as fallback
	if txGetter, ok := block.(interface{ GetTransactions() []interface{} }); ok {
		if txs := txGetter.GetTransactions(); len(txs) > 0 {
			return fmt.Sprintf("calculated_from_%d_txs", len(txs))
		}
	}

	// Last resort fallback
	return fmt.Sprintf("no_merkle_info_%s", block.GetHash()[:8])
}

// DebugConsensusSignaturesDeep logs detailed information about all consensus signatures
func (c *Consensus) DebugConsensusSignaturesDeep() {
	c.signatureMutex.RLock()
	defer c.signatureMutex.RUnlock()

	logger.Info("🔍 DEEP DEBUG: Current consensus signatures (%d total):", len(c.consensusSignatures))
	for i, sig := range c.consensusSignatures {
		logger.Info("  Signature %d: block=%s, type=%s, merkle=%s, status=%s, valid=%t",
			i, sig.BlockHash, sig.MessageType, sig.MerkleRoot, sig.Status, sig.Valid)
	}
}

// ForcePopulateAllSignatures updates all signatures with current block information
func (c *Consensus) ForcePopulateAllSignatures() {
	c.signatureMutex.Lock()
	defer c.signatureMutex.Unlock()

	logger.Info("🔄 Force populating all consensus signatures")

	// Process each signature
	for i, sig := range c.consensusSignatures {
		originalMerkleRoot := sig.MerkleRoot
		originalStatus := sig.Status

		// Get block from blockchain
		block := c.blockChain.GetBlockByHash(sig.BlockHash)
		if block != nil {
			var merkleRoot string
			// Extract merkle root based on block type
			switch b := block.(type) {
			case *types.Block:
				if b.Header != nil && len(b.Header.TxsRoot) > 0 {
					merkleRoot = fmt.Sprintf("%x", b.Header.TxsRoot)
				}
			case Block:
				if g, ok := b.(interface{ GetMerkleRoot() string }); ok {
					merkleRoot = g.GetMerkleRoot()
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

		// Set status based on message type if missing
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
		}

		logger.Info("🔄 Signature %d: block=%s, merkle=%s->%s, status=%s->%s",
			i, sig.BlockHash, originalMerkleRoot, sig.MerkleRoot, originalStatus, sig.Status)
	}

	logger.Info("✅ Force population completed for %d signatures", len(c.consensusSignatures))
}

// GetConsensusSignatures returns a copy of all consensus signatures
func (c *Consensus) GetConsensusSignatures() []*ConsensusSignature {
	c.signatureMutex.RLock()
	defer c.signatureMutex.RUnlock()
	// Create a copy to avoid external modification
	signatures := make([]*ConsensusSignature, len(c.consensusSignatures))
	copy(signatures, c.consensusSignatures)
	return signatures
}

// processVote handles incoming commit votes
func (c *Consensus) processVote(vote *Vote) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify vote signature if signing service available
	if c.signingService != nil && len(vote.Signature) > 0 {
		valid, err := c.signingService.VerifyVote(vote)
		if err != nil || !valid {
			logger.Warn("Invalid vote signature from %s", vote.VoterID)
			return
		}
	}

	// Initialize vote tracking for this block if needed
	if c.receivedVotes[vote.BlockHash] == nil {
		c.receivedVotes[vote.BlockHash] = make(map[string]*Vote)
		c.weightedCommitVotes[vote.BlockHash] = big.NewInt(0)
	}

	// Ignore duplicate votes
	if _, exists := c.receivedVotes[vote.BlockHash][vote.VoterID]; exists {
		return
	}

	// Store the vote
	c.receivedVotes[vote.BlockHash][vote.VoterID] = vote

	// Get voter's stake
	stake := c.getValidatorStake(vote.VoterID)
	// Handle zero stake case
	if stake.Cmp(big.NewInt(0)) == 0 {
		if vote.VoterID == c.nodeID {
			// Self stake fallback
			stake = new(big.Int).Mul(big.NewInt(32), big.NewInt(denom.SPX))
			logger.Info("⚠️ Self stake was zero, using default: 32 SPX")
		} else {
			logger.Warn("⚠️ Vote from %s has zero stake", vote.VoterID)
		}
	}

	// Add stake to weighted vote total
	c.weightedCommitVotes[vote.BlockHash].Add(c.weightedCommitVotes[vote.BlockHash], stake)

	// Log vote receipt with stake amount
	stakeSPX := new(big.Float).Quo(new(big.Float).SetInt(stake), new(big.Float).SetFloat64(denom.SPX))
	logger.Info("📊 Commit vote: %s, block=%s, stake=%.2f SPX", vote.VoterID, vote.BlockHash, stakeSPX)

	// Calculate current vote count and quorum requirements
	totalVotes := len(c.receivedVotes[vote.BlockHash])
	quorumSize := c.calculateQuorumSize(c.getTotalNodes())
	logger.Info("📊 Commit vote received: node=%s, from=%s, block=%s, votes=%d/%d, phase=%v",
		c.nodeID, vote.VoterID, vote.BlockHash, totalVotes, quorumSize, c.phase)

	// Check if we've achieved quorum for this block
	if c.hasQuorum(vote.BlockHash) {
		logger.Info("🎉 COMMIT QUORUM ACHIEVED for block %s at view %d", vote.BlockHash, vote.View)

		// Determine which block to commit
		var blockToCommit Block
		if c.lockedBlock != nil && c.lockedBlock.GetHash() == vote.BlockHash {
			blockToCommit = c.lockedBlock
		} else if c.preparedBlock != nil && c.preparedBlock.GetHash() == vote.BlockHash {
			blockToCommit = c.preparedBlock
		} else {
			logger.Warn("❌ No block found to commit for hash %s", vote.BlockHash)
			return
		}

		// Move to committed phase if not already there
		if c.phase != PhaseCommitted {
			c.phase = PhaseCommitted
			logger.Info("🚀 Moving to COMMITTED phase for block %s", vote.BlockHash)
		}

		// Add this vote to consensus signatures
		signatureHex := hex.EncodeToString(vote.Signature)
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

// processTimeout handles incoming timeout messages for view changes
func (c *Consensus) processTimeout(timeout *TimeoutMsg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify timeout signature if signing service available
	if c.signingService != nil && len(timeout.Signature) > 0 {
		valid, err := c.signingService.VerifyTimeout(timeout)
		if err != nil || !valid {
			logger.Warn("Invalid timeout signature from %s: %v", timeout.VoterID, err)
			return
		}
	} else if c.signingService == nil {
		logger.Warn("WARNING: No signing service, accepting unsigned timeout from %s", timeout.VoterID)
	}

	// If timeout is for a higher view, perform view change
	if timeout.View > c.currentView {
		logger.Info("View change requested to view %d by %s", timeout.View, timeout.VoterID)
		c.currentView = timeout.View
		c.lastViewChange = common.GetTimeService().Now()
		c.resetConsensusState()
		c.updateLeaderStatusWithValidators(c.getValidators())
		logger.Info("View change completed: node=%s, new_view=%d, leader=%v", c.nodeID, c.currentView, c.isLeader)
	}
}

// sendPrepareVote creates and broadcasts a prepare vote for a block
func (c *Consensus) sendPrepareVote(blockHash string, view uint64) {
	// Check if already sent prepare vote for this block
	if c.sentPrepareVotes[blockHash] {
		return
	}

	// Create prepare vote message
	prepareVote := &Vote{
		BlockHash: blockHash,
		View:      view,
		VoterID:   c.nodeID,
		Signature: []byte{},
	}

	// Sign the vote if signing service available
	if c.signingService != nil {
		if err := c.signingService.SignVote(prepareVote); err != nil {
			logger.Warn("Failed to sign prepare vote: %v", err)
			return
		}
	}

	// Mark as sent and broadcast
	c.sentPrepareVotes[blockHash] = true
	c.broadcastPrepareVote(prepareVote)
	logger.Info("Node %s sent prepare vote for block %s at view %d", c.nodeID, blockHash, view)
}

// voteForBlock creates and broadcasts a commit vote for a block
func (c *Consensus) voteForBlock(blockHash string, view uint64) {
	// Check if already sent commit vote for this block
	if c.sentVotes[blockHash] {
		return
	}

	// Find the block to vote for
	var blockToVote Block
	if c.lockedBlock != nil && c.lockedBlock.GetHash() == blockHash {
		blockToVote = c.lockedBlock
	} else if c.preparedBlock != nil && c.preparedBlock.GetHash() == blockHash {
		blockToVote = c.preparedBlock
	} else {
		logger.Warn("❌ No block found to vote for hash %s", blockHash)
		return
	}

	// Create commit vote message
	vote := &Vote{
		BlockHash: blockHash,
		View:      view,
		VoterID:   c.nodeID,
		Signature: []byte{},
	}

	// Sign the vote if signing service available
	if c.signingService != nil {
		if err := c.signingService.SignVote(vote); err != nil {
			logger.Warn("Failed to sign commit vote: %v", err)
			return
		}
	}

	// Mark as sent and broadcast
	c.sentVotes[blockHash] = true
	c.broadcastVote(vote)
	logger.Info("🗳️ Node %s sent COMMIT vote for block %s (height %d) at view %d",
		c.nodeID, blockHash, blockToVote.GetHeight(), view)
}

// hasQuorum checks if a block has achieved commit quorum based on stake weight
func (c *Consensus) hasQuorum(blockHash string) bool {
	// Get votes for this block
	votes := c.receivedVotes[blockHash]
	if votes == nil {
		return false
	}

	// Calculate total stake that has voted
	totalStakeVoted := big.NewInt(0)
	for voterID := range votes {
		if stake := c.getValidatorStake(voterID); stake != nil {
			totalStakeVoted.Add(totalStakeVoted, stake)
		}
	}

	// Store weighted vote total
	c.weightedCommitVotes[blockHash] = totalStakeVoted

	// Get total stake from validator set
	totalStake := c.validatorSet.GetTotalStake()

	// Cannot achieve quorum if total stake is zero
	if totalStake == nil || totalStake.Cmp(big.NewInt(0)) == 0 {
		logger.Warn("Total stake is zero, cannot achieve quorum")
		return false
	}

	// Calculate required stake (2/3 of total)
	requiredStake := new(big.Int).Mul(totalStake, big.NewInt(2))
	requiredStake.Div(requiredStake, big.NewInt(3))

	// Check if quorum achieved
	hasQuorum := totalStakeVoted.Cmp(requiredStake) >= 0

	// Log quorum details if achieved
	if hasQuorum && totalStakeVoted.Cmp(big.NewInt(0)) > 0 {
		votedSPX := new(big.Float).Quo(new(big.Float).SetInt(totalStakeVoted), new(big.Float).SetFloat64(denom.SPX))
		totalSPX := new(big.Float).Quo(new(big.Float).SetInt(totalStake), new(big.Float).SetFloat64(denom.SPX))
		if totalSPX.Cmp(big.NewFloat(0)) != 0 {
			pct := new(big.Float).Quo(votedSPX, totalSPX)
			pct.Mul(pct, big.NewFloat(100))
			logger.Info("🎯 Quorum achieved: %.2f / %.2f SPX voted (%.1f%%)", votedSPX, totalSPX, pct)
		}
	}
	return hasQuorum
}

// hasPrepareQuorum checks if a block has achieved prepare quorum based on stake weight
func (c *Consensus) hasPrepareQuorum(blockHash string) bool {
	// Get prepare votes for this block
	votes := c.prepareVotes[blockHash]
	if votes == nil {
		return false
	}

	// Calculate total stake that has voted
	totalStakeVoted := big.NewInt(0)
	for voterID := range votes {
		if stake := c.getValidatorStake(voterID); stake != nil {
			totalStakeVoted.Add(totalStakeVoted, stake)
		}
	}

	// Store weighted vote total
	c.weightedPrepareVotes[blockHash] = totalStakeVoted

	// Get total stake from validator set
	totalStake := c.validatorSet.GetTotalStake()

	// Cannot achieve quorum if total stake is zero
	if totalStake == nil || totalStake.Cmp(big.NewInt(0)) == 0 {
		return false
	}

	// Calculate required stake (2/3 of total)
	requiredStake := new(big.Int).Mul(totalStake, big.NewInt(2))
	requiredStake.Div(requiredStake, big.NewInt(3))

	return totalStakeVoted.Cmp(requiredStake) >= 0
}

// getValidatorStake returns the stake amount for a validator
func (c *Consensus) getValidatorStake(validatorID string) *big.Int {
	c.validatorSet.mu.RLock()
	defer c.validatorSet.mu.RUnlock()
	if val, exists := c.validatorSet.validators[validatorID]; exists {
		return val.StakeAmount
	}
	return big.NewInt(0)
}

// calculateQuorumSize returns the number of votes needed for quorum
func (c *Consensus) calculateQuorumSize(totalNodes int) int {
	quorumSize := int(float64(totalNodes) * c.quorumFraction)
	if quorumSize < 1 {
		return 1 // Minimum quorum size is 1
	}
	return quorumSize
}

// getTotalNodes returns the total number of active validator nodes
func (c *Consensus) getTotalNodes() int {
	peers := c.nodeManager.GetPeers()
	validatorCount := 0
	// Count validator peers
	for _, peer := range peers {
		node := peer.GetNode()
		if node.GetRole() == RoleValidator && node.GetStatus() == NodeStatusActive {
			validatorCount++
		}
	}
	// Count self if validator
	if c.isValidator() {
		validatorCount++
	}
	return validatorCount
}

// commitBlock commits a block to the blockchain
func (c *Consensus) commitBlock(block Block) {
	logger.Info("🚀 Node %s attempting to commit block %s at height %d",
		c.nodeID, block.GetHash(), block.GetHeight())

	// Verify block height
	currentHeight := c.blockChain.GetLatestBlock().GetHeight()
	if block.GetHeight() != currentHeight+1 {
		logger.Warn("❌ Block height mismatch: expected %d, got %d", currentHeight+1, block.GetHeight())
		return
	}

	// Extract underlying block if needed
	var tb *types.Block
	if direct, ok := block.(*types.Block); ok {
		tb = direct
	} else if helper, ok := block.(interface{ GetUnderlyingBlock() *types.Block }); ok {
		tb = helper.GetUnderlyingBlock()
	}

	// Update block metadata if extraction succeeded
	if tb == nil {
		logger.Error("❌ commitBlock: cannot extract *types.Block from %T", block)
	} else {
		tb.Header.CommitStatus = "committed"
		if len(tb.Header.ProposerSignature) > 0 {
			tb.Header.SigValid = true
		}

		// Attach attestations from votes to the block
		votesSnapshot := make(map[string]*Vote)
		if votes, exists := c.receivedVotes[block.GetHash()]; exists {
			for k, v := range votes {
				votesSnapshot[k] = v
			}
		}

		if len(votesSnapshot) > 0 {
			tb.Body.Attestations = make([]*types.Attestation, 0, len(votesSnapshot))
			for voterID, vote := range votesSnapshot {
				tb.Body.Attestations = append(tb.Body.Attestations, &types.Attestation{
					ValidatorID: voterID,
					BlockHash:   block.GetHash(),
					View:        vote.View,
					Signature:   vote.Signature,
				})
			}
			logger.Info("✅ Attached %d attestations to block %s", len(tb.Body.Attestations), block.GetHash())
		} else {
			logger.Warn("⚠️ No votes in snapshot for block %s — attestations will be empty", block.GetHash())
		}
	}

	// Commit block to blockchain
	if err := c.blockChain.CommitBlock(block); err != nil {
		logger.Error("❌ Error committing block: %v", err)
		return
	}

	// Execute commit callback if provided
	if c.onCommit != nil {
		if err := c.onCommit(block); err != nil {
			logger.Warn("⚠️ Error in commit callback: %v", err)
		}
	}

	// Update consensus state
	c.currentHeight = block.GetHeight()
	c.lastBlockTime = common.GetTimeService().Now()
	c.resetConsensusState()

	logger.Info("🎉 Node %s successfully committed block %s at height %d",
		c.nodeID, block.GetHash(), c.currentHeight)
}

// startViewChange initiates a view change process
func (c *Consensus) startViewChange() {
	// Try to acquire view change lock
	if !c.tryViewChangeLock() {
		return
	}
	defer c.viewChangeMutex.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check conditions for view change
	if c.phase != PhaseIdle {
		return // Only change view in idle phase
	}
	if common.GetTimeService().Now().Sub(c.lastViewChange) < 60*time.Second {
		return // Rate limit view changes
	}
	if c.currentHeight > 0 && common.GetTimeService().Now().Sub(c.lastBlockTime) < 30*time.Second {
		return // Recent block committed, don't change view
	}

	// Get current validators
	validators := c.getValidators()
	if len(validators) == 0 {
		logger.Warn("Skipping view change - no validators available")
		c.mu.Unlock()
		return
	}

	// Calculate new view number
	newView := c.currentView + 1
	logger.Info("🔄 Node %s initiating view change to view %d", c.nodeID, newView)

	// Update consensus state
	c.currentView = newView
	c.lastViewChange = common.GetTimeService().Now()
	c.resetConsensusState()
	c.updateLeaderStatusWithValidators(validators)

	c.mu.Unlock()

	// Create and broadcast timeout message
	timeoutMsg := &TimeoutMsg{
		View:      newView,
		VoterID:   c.nodeID,
		Signature: []byte{},
		Timestamp: common.GetCurrentTimestamp(),
	}

	// Sign timeout if signing service available
	if c.signingService != nil {
		if err := c.signingService.SignTimeout(timeoutMsg); err != nil {
			logger.Warn("Failed to sign timeout message: %v", err)
			return
		}
	}

	// Broadcast timeout
	if err := c.broadcastTimeout(timeoutMsg); err != nil {
		logger.Warn("Failed to broadcast timeout message: %v", err)
	}
}

// tryViewChangeLock attempts to acquire the view change mutex with timeout
func (c *Consensus) tryViewChangeLock() bool {
	acquired := make(chan bool, 1)
	// Try to acquire lock in goroutine
	go func() {
		c.viewChangeMutex.Lock()
		acquired <- true
	}()
	// Wait for acquisition or timeout
	select {
	case <-acquired:
		return true
	case <-time.After(100 * time.Millisecond):
		return false
	case <-c.ctx.Done():
		return false
	}
}

// updateLeaderStatusWithValidators is used by view-change to elect leader by round-robin.
// It also stores the result in electedLeaderID so isValidLeader stays consistent.
func (c *Consensus) updateLeaderStatusWithValidators(validators []string) {
	if len(validators) == 0 {
		c.isLeader = false
		c.electedLeaderID = ""
		return
	}

	// Sort for deterministic selection
	sort.Strings(validators)
	// Select leader based on current view
	leaderIndex := int(c.currentView) % len(validators)
	expectedLeader := validators[leaderIndex]

	// Store elected leader
	c.electedLeaderID = expectedLeader
	c.isLeader = (expectedLeader == c.nodeID)

	// Log election result
	if c.isLeader {
		logger.Info("✅ Node %s elected as leader for view %d (index %d/%d)",
			c.nodeID, c.currentView, leaderIndex, len(validators))
	} else {
		logger.Debug("Node %s is NOT leader for view %d (leader: %s)",
			c.nodeID, c.currentView, expectedLeader)
	}
}

// resetConsensusState clears all consensus-related state for a new view
func (c *Consensus) resetConsensusState() {
	c.phase = PhaseIdle
	c.lockedBlock = nil
	c.preparedBlock = nil
	c.preparedView = 0
	c.receivedVotes = make(map[string]map[string]*Vote)
	c.prepareVotes = make(map[string]map[string]*Vote)
	c.sentVotes = make(map[string]bool)
	c.sentPrepareVotes = make(map[string]bool)
	// Note: do NOT clear electedLeaderID or electedSlot here —
	// they are still needed by ProposeBlock and isValidLeader after a reset.
}

// isValidLeader checks whether a proposer is the legitimate leader.
//
// It uses c.electedLeaderID which is populated by:
//   - UpdateLeaderStatus (RANDAO path, called from helper.go before proposal)
//   - updateLeaderStatusWithValidators (round-robin, called on view change)
//
// Both paths store a single consistent leader ID, so every node (leader and
// followers) agrees on who is allowed to propose.
func (c *Consensus) isValidLeader(nodeID string, view uint64) bool {
	// Use elected leader if available
	if c.electedLeaderID != "" {
		isValid := c.electedLeaderID == nodeID
		if isValid {
			logger.Info("✅ Valid leader (RANDAO/elected): %s for view %d", nodeID, view)
		} else {
			logger.Info("❌ Invalid leader: expected elected=%s for view %d, got=%s",
				c.electedLeaderID, view, nodeID)
		}
		return isValid
	}

	// Fallback: electedLeaderID not set (should not happen in normal operation)
	validators := c.getValidators()
	if len(validators) == 0 {
		return false
	}
	// Round-robin selection fallback
	sort.Strings(validators)
	leaderIndex := int(view) % len(validators)
	expectedLeader := validators[leaderIndex]
	isValid := expectedLeader == nodeID
	if isValid {
		logger.Info("✅ Valid leader (round-robin fallback): %s for view %d", nodeID, view)
	} else {
		logger.Info("❌ Invalid leader (round-robin fallback): expected %s for view %d, got %s",
			expectedLeader, view, nodeID)
	}
	return isValid
}

// getValidators returns a list of all active validator node IDs
func (c *Consensus) getValidators() []string {
	peers := c.nodeManager.GetPeers()
	validatorSet := make(map[string]bool)
	validators := []string{}

	// Add self if validator
	if c.isValidator() {
		validatorSet[c.nodeID] = true
		validators = append(validators, c.nodeID)
	}

	// Add validator peers
	for _, peer := range peers {
		node := peer.GetNode()
		if node != nil && node.GetRole() == RoleValidator && node.GetStatus() == NodeStatusActive {
			nodeID := node.GetID()
			// Avoid duplicates
			if !validatorSet[nodeID] && nodeID != "" {
				validatorSet[nodeID] = true
				validators = append(validators, nodeID)
			}
		}
	}

	// Sort for deterministic ordering
	sort.Strings(validators)

	// Ensure we always have at least this node
	if len(validators) == 0 {
		logger.Error("CRITICAL: No validators found for consensus!")
		return []string{c.nodeID}
	}

	return validators
}

// isValidator checks if this node is a validator
func (c *Consensus) isValidator() bool {
	self := c.nodeManager.GetNode(c.nodeID)
	return self != nil && self.GetRole() == RoleValidator
}

// SetLastBlockTime sets the timestamp of the last committed block
func (c *Consensus) SetLastBlockTime(blockTime time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastBlockTime = blockTime
}

// GetConsensusState returns a string representation of the current consensus state
func (c *Consensus) GetConsensusState() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Get block hashes for display
	preparedHash := ""
	if c.preparedBlock != nil {
		preparedHash = c.preparedBlock.GetHash()
	}
	lockedHash := ""
	if c.lockedBlock != nil {
		lockedHash = c.lockedBlock.GetHash()
	}

	currentTime := common.GetTimeService().Now()
	// Format state information
	return fmt.Sprintf(
		"Node=%s, View=%d, Phase=%v, Leader=%v, ElectedLeader=%s, Height=%d, "+
			"PreparedBlock=%s, LockedBlock=%s, PreparedView=%d, "+
			"LastViewChange=%v, LastBlockTime=%v, PrepareVotes=%d, CommitVotes=%d",
		c.nodeID, c.currentView, c.phase, c.isLeader, c.electedLeaderID, c.currentHeight,
		preparedHash, lockedHash, c.preparedView,
		currentTime.Sub(c.lastViewChange), currentTime.Sub(c.lastBlockTime),
		len(c.prepareVotes), len(c.receivedVotes),
	)
}

// broadcastProposal sends a proposal to all peers
func (c *Consensus) broadcastProposal(proposal *Proposal) error {
	logger.Info("Broadcasting proposal for block %s at view %d", proposal.Block.GetHash(), proposal.View)
	return c.nodeManager.BroadcastMessage("proposal", proposal)
}

// broadcastVote sends a commit vote to all peers
func (c *Consensus) broadcastVote(vote *Vote) error {
	logger.Info("Broadcasting commit vote for block %s at view %d", vote.BlockHash, vote.View)
	return c.nodeManager.BroadcastMessage("vote", vote)
}

// broadcastPrepareVote sends a prepare vote to all peers
func (c *Consensus) broadcastPrepareVote(vote *Vote) error {
	logger.Info("Broadcasting prepare vote for block %s at view %d", vote.BlockHash, vote.View)
	return c.nodeManager.BroadcastMessage("prepare", vote)
}

// broadcastTimeout sends a timeout message to all peers
func (c *Consensus) broadcastTimeout(timeout *TimeoutMsg) error {
	logger.Info("Broadcasting timeout for view %d", timeout.View)
	return c.nodeManager.BroadcastMessage("timeout", timeout)
}

// SetLeader manually sets the leader status (used for testing/debugging)
func (c *Consensus) SetLeader(isLeader bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isLeader = isLeader
	logger.Info("Node %s leader status set to %t", c.nodeID, isLeader)
}
