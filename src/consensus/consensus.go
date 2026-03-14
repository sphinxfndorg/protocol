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

	ctx, cancel := context.WithCancel(context.Background())

	genesisSeed := [32]byte{0x53, 0x50, 0x48, 0x58} // "SPHX"
	randao := NewRANDAO(genesisSeed)
	validatorSet := NewValidatorSet(minStakeAmount)
	selector := NewStakeWeightedSelector(validatorSet)
	// Use the blockchain's genesis time so every node starts slot counting
	// from the same anchor, producing identical slot numbers and seeds.
	var genesisTime time.Time
	if blockchain != nil {
		genesisTime = blockchain.GetGenesisTime()
	}
	if genesisTime.IsZero() {
		genesisTime = time.Unix(1732070400, 0) // fallback: hardcoded genesis timestamp
	}
	timeConverter := NewTimeConverter(genesisTime)

	if blockchain != nil {
		stake := blockchain.GetValidatorStake(nodeID)
		if stake != nil {
			minStake := validatorSet.GetMinStakeAmount()
			if stake.Cmp(minStake) >= 0 {
				stakeSPX := new(big.Int).Div(stake, big.NewInt(denom.SPX))
				validatorSet.AddValidator(nodeID, uint64(stakeSPX.Int64()))
			}
		}
		if validatorSet.validators[nodeID] == nil {
			minStakeSPX := validatorSet.GetMinStakeSPX()
			logger.Info("Adding self %s with minimum stake %d SPX", nodeID, minStakeSPX)
			validatorSet.AddValidator(nodeID, minStakeSPX)
		}
	}

	return &Consensus{
		nodeID:               nodeID,
		nodeManager:          nodeManager,
		blockChain:           blockchain,
		signingService:       signingService,
		currentView:          0,
		currentHeight:        0,
		phase:                PhaseIdle,
		quorumFraction:       0.67,
		timeout:              300 * time.Second,
		receivedVotes:        make(map[string]map[string]*Vote),
		prepareVotes:         make(map[string]map[string]*Vote),
		sentVotes:            make(map[string]bool),
		sentPrepareVotes:     make(map[string]bool),
		proposalCh:           make(chan *Proposal, 100),
		voteCh:               make(chan *Vote, 1000),
		timeoutCh:            make(chan *TimeoutMsg, 100),
		prepareCh:            make(chan *Vote, 1000),
		onCommit:             onCommit,
		ctx:                  ctx,
		cancel:               cancel,
		lastViewChange:       common.GetTimeService().Now(),
		viewChangeMutex:      sync.Mutex{},
		lastBlockTime:        common.GetTimeService().Now(),
		validatorSet:         validatorSet,
		randao:               randao,
		selector:             selector,
		timeConverter:        timeConverter,
		useStakeWeighted:     true,
		weightedPrepareVotes: make(map[string]*big.Int),
		weightedCommitVotes:  make(map[string]*big.Int),
		attestations:         make(map[uint64][]*Attestation),
		electedLeaderID:      "", // set by UpdateLeaderStatus
	}
}

func (c *Consensus) Start() error {
	logger.Info("Consensus started for node %s", c.nodeID)
	go c.handleProposals()
	go c.handleVotes()
	go c.handlePrepareVotes()
	go c.handleTimeouts()
	go c.consensusLoop()
	return nil
}

func (c *Consensus) GetNodeID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nodeID
}

func (c *Consensus) SetTimeout(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timeout = d
}

func (c *Consensus) Stop() error {
	logger.Info("Consensus stopped for node %s", c.nodeID)
	c.cancel()
	return nil
}

// UpdateLeaderStatus runs the stake-weighted RANDAO proposer selection for the
// current slot and stores the result in electedLeaderID so that every node
// uses the exact same leader identity when validating incoming proposals.
//
// Terminal output per node:
//
//	✅ Node X selected as proposer for slot Y with stake Z SPX
//	   Node X NOT selected for slot Y (selected: Z with W SPX)
func (c *Consensus) UpdateLeaderStatus() {
	c.updateLeaderStatus()
}

// updateLeaderStatus is the private implementation.
func (c *Consensus) updateLeaderStatus() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.useStakeWeighted {
		c.updateLeaderStatusRoundRobin()
		return
	}

	currentSlot := c.timeConverter.CurrentSlot()
	currentEpoch := currentSlot / SlotsPerEpoch

	if currentEpoch > c.currentEpoch {
		c.onEpochTransition(currentEpoch)
	}

	seed := c.randao.GetSeed(currentSlot)
	selected := c.selector.SelectProposer(currentEpoch, seed)

	if selected == nil {
		c.isLeader = false
		c.electedLeaderID = ""
		c.electedSlot = 0
		logger.Warn("No validator selected for slot %d", currentSlot)
		return
	}

	c.electedLeaderID = selected.ID
	c.electedSlot = currentSlot // ← store the slot used for election
	c.isLeader = (selected.ID == c.nodeID)

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

func (c *Consensus) ProposeBlock(block Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isLeader {
		return fmt.Errorf("node %s is not the leader", c.nodeID)
	}

	if c.signingService != nil {
		if err := c.signingService.SignBlock(block); err != nil {
			return fmt.Errorf("failed to sign block header: %w", err)
		}
	}

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
		proposalSlot = c.timeConverter.CurrentSlot() // fallback
	}

	proposal := &Proposal{
		Block:           block,
		View:            c.currentView,
		ProposerID:      c.nodeID,
		Signature:       []byte{},
		ElectedLeaderID: c.electedLeaderID,
		SlotNumber:      proposalSlot, // ← use the election slot, not current slot
	}

	if c.signingService != nil {
		if err := c.signingService.SignProposal(proposal); err != nil {
			return fmt.Errorf("failed to sign proposal: %w", err)
		}
	}

	return c.broadcastProposal(proposal)
}

func (c *Consensus) HandleProposal(proposal *Proposal) error {
	select {
	case c.proposalCh <- proposal:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("consensus stopped")
	}
}

func (c *Consensus) HandleVote(vote *Vote) error {
	select {
	case c.voteCh <- vote:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("consensus stopped")
	}
}

func (c *Consensus) HandlePrepareVote(vote *Vote) error {
	select {
	case c.prepareCh <- vote:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("consensus stopped")
	}
}

func (c *Consensus) HandleTimeout(timeout *TimeoutMsg) error {
	select {
	case c.timeoutCh <- timeout:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("consensus stopped")
	}
}

func (c *Consensus) GetCurrentView() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentView
}

func (c *Consensus) IsLeader() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isLeader
}

func (c *Consensus) GetPhase() ConsensusPhase {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.phase
}

func (c *Consensus) GetCurrentHeight() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentHeight
}

func (c *Consensus) shouldPreventViewChange() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.phase == PhasePrePrepared || c.phase == PhasePrepared {
		return true
	}
	if len(c.receivedVotes) > 0 || len(c.prepareVotes) > 0 {
		return true
	}
	return false
}

func (c *Consensus) consensusLoop() {
	viewTimer := time.NewTimer(c.timeout)
	defer viewTimer.Stop()

	for {
		select {
		case <-viewTimer.C:
			if c.shouldPreventViewChange() {
				logger.Info("🛑 Preventing view change - active consensus")
				viewTimer.Reset(10 * time.Second)
				continue
			}

			c.mu.RLock()
			currentHeight := c.currentHeight
			c.mu.RUnlock()

			if currentHeight == 0 {
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

func (c *Consensus) handleProposals() {
	for {
		select {
		case proposal, ok := <-c.proposalCh:
			if !ok {
				return
			}
			c.processProposal(proposal)
		case <-c.ctx.Done():
			logger.Info("Proposal handler stopped for node %s", c.nodeID)
			return
		}
	}
}

func (c *Consensus) handleVotes() {
	for {
		select {
		case vote, ok := <-c.voteCh:
			if !ok {
				return
			}
			c.processVote(vote)
		case <-c.ctx.Done():
			logger.Info("Vote handler stopped for node %s", c.nodeID)
			return
		}
	}
}

func (c *Consensus) handlePrepareVotes() {
	for {
		select {
		case vote, ok := <-c.prepareCh:
			if !ok {
				return
			}
			c.processPrepareVote(vote)
		case <-c.ctx.Done():
			logger.Info("Prepare vote handler stopped for node %s", c.nodeID)
			return
		}
	}
}

func (c *Consensus) handleTimeouts() {
	for {
		select {
		case timeout, ok := <-c.timeoutCh:
			if !ok {
				return
			}
			c.processTimeout(timeout)
		case <-c.ctx.Done():
			logger.Info("Timeout handler stopped for node %s", c.nodeID)
			return
		}
	}
}

func (c *Consensus) onEpochTransition(newEpoch uint64) {
	// NOTE: c.mu is already held by the caller — do NOT lock here.
	logger.Info("🔄 Entering epoch %d", newEpoch)
	if newEpoch > 0 {
		c.processEpochAttestations(newEpoch - 1)
	}
	c.currentEpoch = newEpoch
}

func (c *Consensus) updateLeaderStatusRoundRobin() {
	validators := c.getValidators()
	if len(validators) == 0 {
		c.isLeader = false
		c.electedLeaderID = ""
		return
	}
	sort.Strings(validators)
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

	nonce, err := proposal.Block.GetCurrentNonce()
	nonceStr := "unknown"
	if err != nil {
		logger.Warn("Failed to get block nonce: %v", err)
	} else {
		nonceStr = fmt.Sprintf("%d", nonce)
	}

	logger.Info("🔍 Processing proposal for block %s at view %d from %s, nonce: %s",
		proposal.Block.GetHash(), proposal.View, proposal.ProposerID, nonceStr)

	if err := c.blockChain.ValidateBlock(proposal.Block); err != nil {
		logger.Warn("❌ Block validation failed: %v", err)
		return
	}

	if c.preparedBlock != nil && c.preparedBlock.GetHash() == proposal.Block.GetHash() {
		logger.Warn("❌ Already have prepared block for height %d, ignoring duplicate proposal",
			proposal.Block.GetHeight())
		return
	}

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

	if c.signingService != nil {
		valid, err := c.signingService.VerifyBlockSignature(proposal.Block)
		if err != nil || !valid {
			logger.Warn("❌ Invalid block header signature from proposer %s: %v", proposal.ProposerID, err)
			return
		}
		logger.Info("✅ Block header signature verified for block %s", proposal.Block.GetHash())
	}

	if direct, ok := proposal.Block.(*types.Block); ok {
		direct.Header.SigValid = true
		direct.Header.CommitStatus = "proposed"
	} else if helper, ok := proposal.Block.(interface{ GetUnderlyingBlock() *types.Block }); ok {
		if ub := helper.GetUnderlyingBlock(); ub != nil {
			ub.Header.SigValid = true
			ub.Header.CommitStatus = "proposed"
		}
	}

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

	if proposal.View < c.currentView {
		logger.Warn("❌ Stale proposal for view %d, current view %d", proposal.View, c.currentView)
		return
	}

	if proposal.View > c.currentView {
		logger.Info("🔄 Advancing view from %d to %d", c.currentView, proposal.View)
		c.currentView = proposal.View
		c.resetConsensusState()
		// Re-run so electedLeaderID is refreshed for the new view
		c.updateLeaderStatus()
	}

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
		slotEpoch := proposal.SlotNumber / SlotsPerEpoch
		seed := c.randao.GetSeed(proposal.SlotNumber)
		selected := c.selector.SelectProposer(slotEpoch, seed)
		if selected != nil {
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

	if !c.isValidLeader(proposal.ProposerID, proposal.View) {
		logger.Warn("❌ Invalid leader %s for view %d (electedLeaderID=%s)",
			proposal.ProposerID, proposal.View, c.electedLeaderID)
		return
	}

	logger.Info("✅ Node %s accepting proposal for block %s at view %d (height %d, nonce: %s)",
		c.nodeID, proposal.Block.GetHash(), proposal.View, proposal.Block.GetHeight(), nonceStr)

	c.preparedBlock = proposal.Block
	c.preparedView = proposal.View
	c.phase = PhasePrePrepared

	c.sendPrepareVote(proposal.Block.GetHash(), proposal.View)
}

func (c *Consensus) CacheMerkleRoot(blockHash, merkleRoot string) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()
	if c.merkleRootCache == nil {
		c.merkleRootCache = make(map[string]string)
	}
	c.merkleRootCache[blockHash] = merkleRoot
	logger.Info("Cached merkle root for block %s: %s", blockHash, merkleRoot)
}

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

func (c *Consensus) processPrepareVote(vote *Vote) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.signingService != nil && len(vote.Signature) > 0 {
		valid, err := c.signingService.VerifyVote(vote)
		if err != nil || !valid {
			logger.Warn("Invalid prepare vote signature from %s", vote.VoterID)
			return
		}
	}

	if c.prepareVotes[vote.BlockHash] == nil {
		c.prepareVotes[vote.BlockHash] = make(map[string]*Vote)
		c.weightedPrepareVotes[vote.BlockHash] = big.NewInt(0)
	}

	if _, exists := c.prepareVotes[vote.BlockHash][vote.VoterID]; exists {
		return
	}

	c.prepareVotes[vote.BlockHash][vote.VoterID] = vote

	stake := c.getValidatorStake(vote.VoterID)
	c.weightedPrepareVotes[vote.BlockHash].Add(c.weightedPrepareVotes[vote.BlockHash], stake)

	stakeSPX := new(big.Float).Quo(new(big.Float).SetInt(stake), new(big.Float).SetFloat64(denom.SPX))

	logger.Info("📊 Prepare vote: %s, block=%s, stake=%.2f SPX", vote.VoterID, vote.BlockHash, stakeSPX)

	totalVotes := len(c.prepareVotes[vote.BlockHash])
	quorumSize := c.calculateQuorumSize(c.getTotalNodes())

	logger.Info("📊 Prepare vote received: node=%s, from=%s, block=%s, votes=%d/%d, phase=%v, prepared=%v",
		c.nodeID, vote.VoterID, vote.BlockHash, totalVotes, quorumSize, c.phase, c.preparedBlock != nil)

	if c.hasPrepareQuorum(vote.BlockHash) {
		logger.Info("🎉 PREPARE QUORUM ACHIEVED for block %s at view %d", vote.BlockHash, vote.View)

		if c.preparedBlock == nil || c.preparedBlock.GetHash() != vote.BlockHash {
			logger.Warn("❌ No prepared block found for hash %s (have: %v)", vote.BlockHash, c.preparedBlock != nil)
			if c.preparedBlock != nil {
				logger.Warn("   Current prepared block hash: %s", c.preparedBlock.GetHash())
			}
			return
		}

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
			c.voteForBlock(vote.BlockHash, vote.View)
		} else {
			logger.Info("⚠️ Already in phase %v, skipping phase transition", c.phase)
		}
	}
}

func (c *Consensus) addConsensusSig(sig *ConsensusSignature) {
	c.signatureMutex.Lock()
	defer c.signatureMutex.Unlock()

	logger.Info("🔄 Adding consensus signature for block %s (type: %s)", sig.BlockHash, sig.MessageType)

	if sig.MerkleRoot == "" {
		if cachedRoot := c.GetCachedMerkleRoot(sig.BlockHash); cachedRoot != "" {
			sig.MerkleRoot = cachedRoot
		}
	}

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

	if sig.MerkleRoot == "" {
		sig.MerkleRoot = fmt.Sprintf("emergency_fallback_%s", sig.BlockHash[:8])
		logger.Error("🚨 CRITICAL: Used emergency fallback for merkle root!")
	}

	if sig.Status == "" {
		sig.Status = c.StatusFromMsgType(sig.MessageType)
	}

	c.consensusSignatures = append(c.consensusSignatures, sig)
	logger.Info("🎯 Added signature: block=%s, merkle_root=%s, status=%s", sig.BlockHash, sig.MerkleRoot, sig.Status)
}

func (c *Consensus) extractMerkleRootFromBlock(block Block) string {
	if blockHelper, ok := block.(interface{ GetUnderlyingBlock() *types.Block }); ok {
		if ub := blockHelper.GetUnderlyingBlock(); ub != nil {
			if ub.Header != nil && len(ub.Header.TxsRoot) > 0 {
				return fmt.Sprintf("%x", ub.Header.TxsRoot)
			}
		}
	}

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

	if txGetter, ok := block.(interface{ GetTransactions() []interface{} }); ok {
		if txs := txGetter.GetTransactions(); len(txs) > 0 {
			return fmt.Sprintf("calculated_from_%d_txs", len(txs))
		}
	}

	return fmt.Sprintf("no_merkle_info_%s", block.GetHash()[:8])
}

func (c *Consensus) DebugConsensusSignaturesDeep() {
	c.signatureMutex.RLock()
	defer c.signatureMutex.RUnlock()

	logger.Info("🔍 DEEP DEBUG: Current consensus signatures (%d total):", len(c.consensusSignatures))
	for i, sig := range c.consensusSignatures {
		logger.Info("  Signature %d: block=%s, type=%s, merkle=%s, status=%s, valid=%t",
			i, sig.BlockHash, sig.MessageType, sig.MerkleRoot, sig.Status, sig.Valid)
	}
}

func (c *Consensus) ForcePopulateAllSignatures() {
	c.signatureMutex.Lock()
	defer c.signatureMutex.Unlock()

	logger.Info("🔄 Force populating all consensus signatures")

	for i, sig := range c.consensusSignatures {
		originalMerkleRoot := sig.MerkleRoot
		originalStatus := sig.Status

		block := c.blockChain.GetBlockByHash(sig.BlockHash)
		if block != nil {
			var merkleRoot string
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

func (c *Consensus) GetConsensusSignatures() []*ConsensusSignature {
	c.signatureMutex.RLock()
	defer c.signatureMutex.RUnlock()
	signatures := make([]*ConsensusSignature, len(c.consensusSignatures))
	copy(signatures, c.consensusSignatures)
	return signatures
}

func (c *Consensus) processVote(vote *Vote) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.signingService != nil && len(vote.Signature) > 0 {
		valid, err := c.signingService.VerifyVote(vote)
		if err != nil || !valid {
			logger.Warn("Invalid vote signature from %s", vote.VoterID)
			return
		}
	}

	if c.receivedVotes[vote.BlockHash] == nil {
		c.receivedVotes[vote.BlockHash] = make(map[string]*Vote)
		c.weightedCommitVotes[vote.BlockHash] = big.NewInt(0)
	}

	if _, exists := c.receivedVotes[vote.BlockHash][vote.VoterID]; exists {
		return
	}

	c.receivedVotes[vote.BlockHash][vote.VoterID] = vote

	stake := c.getValidatorStake(vote.VoterID)
	if stake.Cmp(big.NewInt(0)) == 0 {
		if vote.VoterID == c.nodeID {
			stake = new(big.Int).Mul(big.NewInt(32), big.NewInt(denom.SPX))
			logger.Info("⚠️ Self stake was zero, using default: 32 SPX")
		} else {
			logger.Warn("⚠️ Vote from %s has zero stake", vote.VoterID)
		}
	}

	c.weightedCommitVotes[vote.BlockHash].Add(c.weightedCommitVotes[vote.BlockHash], stake)

	stakeSPX := new(big.Float).Quo(new(big.Float).SetInt(stake), new(big.Float).SetFloat64(denom.SPX))
	logger.Info("📊 Commit vote: %s, block=%s, stake=%.2f SPX", vote.VoterID, vote.BlockHash, stakeSPX)

	totalVotes := len(c.receivedVotes[vote.BlockHash])
	quorumSize := c.calculateQuorumSize(c.getTotalNodes())
	logger.Info("📊 Commit vote received: node=%s, from=%s, block=%s, votes=%d/%d, phase=%v",
		c.nodeID, vote.VoterID, vote.BlockHash, totalVotes, quorumSize, c.phase)

	if c.hasQuorum(vote.BlockHash) {
		logger.Info("🎉 COMMIT QUORUM ACHIEVED for block %s at view %d", vote.BlockHash, vote.View)

		var blockToCommit Block
		if c.lockedBlock != nil && c.lockedBlock.GetHash() == vote.BlockHash {
			blockToCommit = c.lockedBlock
		} else if c.preparedBlock != nil && c.preparedBlock.GetHash() == vote.BlockHash {
			blockToCommit = c.preparedBlock
		} else {
			logger.Warn("❌ No block found to commit for hash %s", vote.BlockHash)
			return
		}

		if c.phase != PhaseCommitted {
			c.phase = PhaseCommitted
			logger.Info("🚀 Moving to COMMITTED phase for block %s", vote.BlockHash)
		}

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

		c.commitBlock(blockToCommit)
	}
}

func (c *Consensus) processTimeout(timeout *TimeoutMsg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.signingService != nil && len(timeout.Signature) > 0 {
		valid, err := c.signingService.VerifyTimeout(timeout)
		if err != nil || !valid {
			logger.Warn("Invalid timeout signature from %s: %v", timeout.VoterID, err)
			return
		}
	} else if c.signingService == nil {
		logger.Warn("WARNING: No signing service, accepting unsigned timeout from %s", timeout.VoterID)
	}

	if timeout.View > c.currentView {
		logger.Info("View change requested to view %d by %s", timeout.View, timeout.VoterID)
		c.currentView = timeout.View
		c.lastViewChange = common.GetTimeService().Now()
		c.resetConsensusState()
		c.updateLeaderStatusWithValidators(c.getValidators())
		logger.Info("View change completed: node=%s, new_view=%d, leader=%v", c.nodeID, c.currentView, c.isLeader)
	}
}

func (c *Consensus) sendPrepareVote(blockHash string, view uint64) {
	if c.sentPrepareVotes[blockHash] {
		return
	}

	prepareVote := &Vote{
		BlockHash: blockHash,
		View:      view,
		VoterID:   c.nodeID,
		Signature: []byte{},
	}

	if c.signingService != nil {
		if err := c.signingService.SignVote(prepareVote); err != nil {
			logger.Warn("Failed to sign prepare vote: %v", err)
			return
		}
	}

	c.sentPrepareVotes[blockHash] = true
	c.broadcastPrepareVote(prepareVote)
	logger.Info("Node %s sent prepare vote for block %s at view %d", c.nodeID, blockHash, view)
}

func (c *Consensus) voteForBlock(blockHash string, view uint64) {
	if c.sentVotes[blockHash] {
		return
	}

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

	if c.signingService != nil {
		if err := c.signingService.SignVote(vote); err != nil {
			logger.Warn("Failed to sign commit vote: %v", err)
			return
		}
	}

	c.sentVotes[blockHash] = true
	c.broadcastVote(vote)
	logger.Info("🗳️ Node %s sent COMMIT vote for block %s (height %d) at view %d",
		c.nodeID, blockHash, blockToVote.GetHeight(), view)
}

func (c *Consensus) hasQuorum(blockHash string) bool {
	votes := c.receivedVotes[blockHash]
	if votes == nil {
		return false
	}

	totalStakeVoted := big.NewInt(0)
	for voterID := range votes {
		if stake := c.getValidatorStake(voterID); stake != nil {
			totalStakeVoted.Add(totalStakeVoted, stake)
		}
	}

	c.weightedCommitVotes[blockHash] = totalStakeVoted
	totalStake := c.validatorSet.GetTotalStake()

	if totalStake == nil || totalStake.Cmp(big.NewInt(0)) == 0 {
		logger.Warn("Total stake is zero, cannot achieve quorum")
		return false
	}

	requiredStake := new(big.Int).Mul(totalStake, big.NewInt(2))
	requiredStake.Div(requiredStake, big.NewInt(3))

	hasQuorum := totalStakeVoted.Cmp(requiredStake) >= 0
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

func (c *Consensus) hasPrepareQuorum(blockHash string) bool {
	votes := c.prepareVotes[blockHash]
	if votes == nil {
		return false
	}

	totalStakeVoted := big.NewInt(0)
	for voterID := range votes {
		if stake := c.getValidatorStake(voterID); stake != nil {
			totalStakeVoted.Add(totalStakeVoted, stake)
		}
	}

	c.weightedPrepareVotes[blockHash] = totalStakeVoted
	totalStake := c.validatorSet.GetTotalStake()

	if totalStake == nil || totalStake.Cmp(big.NewInt(0)) == 0 {
		return false
	}

	requiredStake := new(big.Int).Mul(totalStake, big.NewInt(2))
	requiredStake.Div(requiredStake, big.NewInt(3))
	return totalStakeVoted.Cmp(requiredStake) >= 0
}

func (c *Consensus) getValidatorStake(validatorID string) *big.Int {
	c.validatorSet.mu.RLock()
	defer c.validatorSet.mu.RUnlock()
	if val, exists := c.validatorSet.validators[validatorID]; exists {
		return val.StakeAmount
	}
	return big.NewInt(0)
}

func (c *Consensus) calculateQuorumSize(totalNodes int) int {
	quorumSize := int(float64(totalNodes) * c.quorumFraction)
	if quorumSize < 1 {
		return 1
	}
	return quorumSize
}

func (c *Consensus) getTotalNodes() int {
	peers := c.nodeManager.GetPeers()
	validatorCount := 0
	for _, peer := range peers {
		node := peer.GetNode()
		if node.GetRole() == RoleValidator && node.GetStatus() == NodeStatusActive {
			validatorCount++
		}
	}
	if c.isValidator() {
		validatorCount++
	}
	return validatorCount
}

func (c *Consensus) commitBlock(block Block) {
	logger.Info("🚀 Node %s attempting to commit block %s at height %d",
		c.nodeID, block.GetHash(), block.GetHeight())

	currentHeight := c.blockChain.GetLatestBlock().GetHeight()
	if block.GetHeight() != currentHeight+1 {
		logger.Warn("❌ Block height mismatch: expected %d, got %d", currentHeight+1, block.GetHeight())
		return
	}

	var tb *types.Block
	if direct, ok := block.(*types.Block); ok {
		tb = direct
	} else if helper, ok := block.(interface{ GetUnderlyingBlock() *types.Block }); ok {
		tb = helper.GetUnderlyingBlock()
	}

	if tb == nil {
		logger.Error("❌ commitBlock: cannot extract *types.Block from %T", block)
	} else {
		tb.Header.CommitStatus = "committed"
		if len(tb.Header.ProposerSignature) > 0 {
			tb.Header.SigValid = true
		}

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

func (c *Consensus) startViewChange() {
	if !c.tryViewChangeLock() {
		return
	}
	defer c.viewChangeMutex.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.phase != PhaseIdle {
		return
	}
	if common.GetTimeService().Now().Sub(c.lastViewChange) < 60*time.Second {
		return
	}
	if c.currentHeight > 0 && common.GetTimeService().Now().Sub(c.lastBlockTime) < 30*time.Second {
		return
	}

	validators := c.getValidators()
	if len(validators) == 0 {
		logger.Warn("Skipping view change - no validators available")
		c.mu.Unlock()
		return
	}

	newView := c.currentView + 1
	logger.Info("🔄 Node %s initiating view change to view %d", c.nodeID, newView)

	c.currentView = newView
	c.lastViewChange = common.GetTimeService().Now()
	c.resetConsensusState()
	c.updateLeaderStatusWithValidators(validators)

	c.mu.Unlock()

	timeoutMsg := &TimeoutMsg{
		View:      newView,
		VoterID:   c.nodeID,
		Signature: []byte{},
		Timestamp: common.GetCurrentTimestamp(),
	}

	if c.signingService != nil {
		if err := c.signingService.SignTimeout(timeoutMsg); err != nil {
			logger.Warn("Failed to sign timeout message: %v", err)
			return
		}
	}

	if err := c.broadcastTimeout(timeoutMsg); err != nil {
		logger.Warn("Failed to broadcast timeout message: %v", err)
	}
}

func (c *Consensus) tryViewChangeLock() bool {
	acquired := make(chan bool, 1)
	go func() {
		c.viewChangeMutex.Lock()
		acquired <- true
	}()
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

	sort.Strings(validators)
	leaderIndex := int(c.currentView) % len(validators)
	expectedLeader := validators[leaderIndex]

	c.electedLeaderID = expectedLeader
	c.isLeader = (expectedLeader == c.nodeID)

	if c.isLeader {
		logger.Info("✅ Node %s elected as leader for view %d (index %d/%d)",
			c.nodeID, c.currentView, leaderIndex, len(validators))
	} else {
		logger.Debug("Node %s is NOT leader for view %d (leader: %s)",
			c.nodeID, c.currentView, expectedLeader)
	}
}

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

func (c *Consensus) getValidators() []string {
	peers := c.nodeManager.GetPeers()
	validatorSet := make(map[string]bool)
	validators := []string{}

	if c.isValidator() {
		validatorSet[c.nodeID] = true
		validators = append(validators, c.nodeID)
	}

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

	sort.Strings(validators)

	if len(validators) == 0 {
		logger.Error("CRITICAL: No validators found for consensus!")
		return []string{c.nodeID}
	}

	return validators
}

func (c *Consensus) isValidator() bool {
	self := c.nodeManager.GetNode(c.nodeID)
	return self != nil && self.GetRole() == RoleValidator
}

func (c *Consensus) SetLastBlockTime(blockTime time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastBlockTime = blockTime
}

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

	currentTime := common.GetTimeService().Now()
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

func (c *Consensus) broadcastProposal(proposal *Proposal) error {
	logger.Info("Broadcasting proposal for block %s at view %d", proposal.Block.GetHash(), proposal.View)
	return c.nodeManager.BroadcastMessage("proposal", proposal)
}

func (c *Consensus) broadcastVote(vote *Vote) error {
	logger.Info("Broadcasting commit vote for block %s at view %d", vote.BlockHash, vote.View)
	return c.nodeManager.BroadcastMessage("vote", vote)
}

func (c *Consensus) broadcastPrepareVote(vote *Vote) error {
	logger.Info("Broadcasting prepare vote for block %s at view %d", vote.BlockHash, vote.View)
	return c.nodeManager.BroadcastMessage("prepare", vote)
}

func (c *Consensus) broadcastTimeout(timeout *TimeoutMsg) error {
	logger.Info("Broadcasting timeout for view %d", timeout.View)
	return c.nodeManager.BroadcastMessage("timeout", timeout)
}

func (c *Consensus) SetLeader(isLeader bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isLeader = isLeader
	logger.Info("Node %s leader status set to %t", c.nodeID, isLeader)
}
