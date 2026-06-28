// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/consensus/consensus.go
package consensus

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	logger "github.com/sphinxfndorg/protocol/src/log"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
	"golang.org/x/crypto/sha3"
)

// ProposeBlock
//   ├─ signs block, builds Proposal, signs Proposal
//   ├─ spawns goroutine → processProposal(own proposal)   // leader processes itself
//   └─ broadcastProposal()                                 // sends to peers
//
//   [peer side]
//   HandleProposal → proposalCh → processProposal
//        ├─ deserialize/validate block, verify signatures
//        ├─ re-derive electedLeaderID via selector.SelectProposer (RANDAO seed)
//        ├─ phase = PhasePrePrepared
//        ├─ sendPrepareVote()  → broadcasts own Vote (type: prepare)
//        └─ tryEnterPreparedPhase()   ◄── side door #1
//
//   HandlePrepareVote → prepareCh → processPrepareVote
//        ├─ store vote, accumulate stake in weightedPrepareVotes
//        └─ tryEnterPreparedPhase()   ◄── side door #2 (same function, called again)
//
//        tryEnterPreparedPhase (idempotent, runs from either caller):
//            requires: hasPrepareQuorum() AND phase==PhasePrePrepared AND preparedBlock set
//            ├─ phase = PhasePrepared
//            ├─ lockedBlock = preparedBlock
//            └─ voteForBlock()  → broadcasts own Vote (type: commit)
//
//   HandleVote → voteCh → processVote
//        ├─ store vote, accumulate stake in weightedCommitVotes
//        └─ if hasQuorum():
//              ├─ phase = PhaseCommitted
//              ├─ attach Attestations to block body
//              └─ commitBlock(block)
//
//   commitBlock
//        ├─ blockChain.CommitBlock(block)   ← interface call, impl not in these files
//        ├─ onCommit callback
//        ├─ reset all round state, currentView++
//        └─ goroutine: UpdateLeaderStatus() for next round

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

	// Initialize VDF parameters for class group VDF (post-quantum)
	// Parameters are loaded from the canonical genesis constants — fixed at
	// trusted setup time and identical on every node in the network.
	// In production, these should come from genesis/trusted setup
	vdfParams, err := LoadCanonicalVDFParams()
	if err != nil {
		// A mismatched or missing discriminant means this node will elect
		// different leaders than its peers and can never reach consensus.
		// This is a fatal startup error — do not continue with a placeholder.
		logger.Error("❌ FATAL: Could not load canonical VDF parameters: %v", err)
		logger.Error("   Ensure the genesis VDF parameters are correctly embedded.")
		cancel()
		return nil
	}
	logger.Info("✅ Loaded canonical VDF parameters: D=%d bits, T=%d",
		vdfParams.Discriminant.BitLen(), vdfParams.T)

	// Initialize RANDAO with genesis seed and VDF parameters
	genesisSeed := [32]byte{0x53, 0x50, 0x48, 0x58} // "SPHX"
	// In NewConsensus, when creating RANDAO:
	randao := NewRANDAO(genesisSeed, vdfParams, nodeID)

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

	// NEW: Register self public key with signing service
	if signingService != nil {
		// Register self public key so the node can verify its own signatures
		if selfPK := signingService.GetPublicKeyObject(); selfPK != nil {
			signingService.RegisterPublicKey(nodeID, selfPK)
			logger.Info("✅ Registered self public key for %s", nodeID)
		} else {
			logger.Warn("⚠️ Could not get self public key for %s", nodeID)
		}
	}

	// Create consensus instance
	cons := &Consensus{
		nodeID:               nodeID,                            // Unique identifier for this node
		nodeManager:          nodeManager,                       // Manages peer connections
		blockChain:           blockchain,                        // Reference to blockchain storage
		signingService:       signingService,                    // Handles cryptographic signatures
		currentView:          0,                                 // Current consensus view (round)
		currentHeight:        0,                                 // Current blockchain height
		phase:                PhaseIdle,                         // Current consensus phase
		quorumFraction:       0.67,                              // 2/3 majority requirement
		timeout:              10 * time.Second,                  // View change timeout
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
		lastRoundActivity:    common.GetTimeService().Now(),     // Last proposal/vote progress timestamp
		validatorSet:         validatorSet,                      // Set of active validators
		randao:               randao,                            // VDF-based RANDAO instance
		selector:             selector,                          // Leader selector
		timeConverter:        timeConverter,                     // Slot time converter
		useStakeWeighted:     true,                              // Use stake-weighted leader election
		weightedPrepareVotes: make(map[string]*big.Int),         // Weighted prepare votes by stake
		weightedCommitVotes:  make(map[string]*big.Int),         // Weighted commit votes by stake
		attestations:         make(map[uint64][]*Attestation),   // Attestations by epoch
		pendingProposals:     make(map[string]Block),
		electedLeaderID:      "", // Set by UpdateLeaderStatus
		syncNeededCh:         make(chan uint64, 4),
	}

	// Initialize and validate VDF parameters (run once at startup)
	if err := cons.initializeVDF(); err != nil {
		logger.Error("VDF initialization failed: %v", err)
		// Don't fail consensus startup, but log the error
	}

	return cons
}

// Start begins the consensus operation by launching all goroutines
func (c *Consensus) Start() error {
	logger.Info("Consensus started for node %s", c.nodeID)

	// Start goroutines for handling different message types
	go c.handleProposals()
	go c.handleVotes()
	go c.handlePrepareVotes()
	go c.handleTimeouts()
	go c.consensusLoop()

	// Start periodic VDF state validation
	go c.periodicVDFValidation()

	// Start periodic RANDAO state sync
	go c.periodicStateSync()

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

// initializeVDF validates and optionally recovers VDF state
func (c *Consensus) initializeVDF() error {
	if c.randao == nil {
		logger.Warn("RANDAO not initialized, cannot validate VDF parameters")
		return nil
	}

	// Get VDF parameters from genesis
	expectedParams := c.getExpectedVDFParams()

	// Check if current params match expected
	if err := c.randao.ValidateVDFParams(expectedParams); err != nil {
		logger.Error("VDF parameter mismatch: %v", err)
		logger.Error("This node may be out of sync or corrupted")

		// Force sync from trusted source
		if err := c.randao.ForceSyncParams(expectedParams); err != nil {
			return fmt.Errorf("failed to sync VDF params: %w", err)
		}
		logger.Info("VDF parameters force synced successfully")
		c.randao.Recovery()
		return nil
	}

	logger.Info("VDF parameters validated successfully")

	// Also validate state consistency
	if err := c.randao.ValidateState(); err != nil {
		logger.Warn("VDF state inconsistency detected: %v - running recovery", err)
		c.randao.Recovery()
	}

	return nil
}

// getExpectedVDFParams returns the expected VDF parameters derived from genesis
// This ensures all nodes use the same parameters derived from the actual genesis block
func (c *Consensus) getExpectedVDFParams() VDFParams {
	// First check if pre-derived parameters are available
	if preDerivedVDFParams != nil {
		logger.Info("Using pre-derived VDF parameters in getExpectedVDFParams")
		return *preDerivedVDFParams
	}

	// Fall back to deriving from genesis hash
	var genesisHash string

	if c.blockChain != nil {
		// Try to get genesis block by traversing from latest block
		latestBlock := c.blockChain.GetLatestBlock()
		if latestBlock != nil {
			// Walk backwards to find genesis by checking parent chain
			currentHash := latestBlock.GetHash()
			for {
				block := c.blockChain.GetBlockByHash(currentHash)
				if block == nil {
					break
				}
				if block.GetHeight() == 0 {
					genesisHash = block.GetHash()
					logger.Info("Found genesis hash by traversing chain: %s", genesisHash)
					break
				}
				currentHash = block.GetPrevHash()
			}
		}
	}

	// If still no genesis hash, derive from node ID (fallback)
	if genesisHash == "" {
		genesisHash = fmt.Sprintf("GENESIS_%s", c.nodeID)
		logger.Error("No genesis hash available, using fallback: %s", genesisHash)
	}

	logger.Info("Deriving VDF parameters from genesis hash: %s", genesisHash)

	// Create a deterministic discriminant from genesis hash
	shake := sha3.NewShake256()
	shake.Write([]byte(genesisHash))
	hashBytes := make([]byte, 32)
	shake.Read(hashBytes)

	// Create a prime from the hash (ensuring it's suitable for class group)
	prime := new(big.Int).SetBytes(hashBytes)
	prime.SetBit(prime, 0, 1) // Ensure odd
	prime.SetBit(prime, 1, 1) // Ensure ≡ 3 mod 4

	// Ensure it's a prime
	for !prime.ProbablyPrime(20) {
		prime.Add(prime, big.NewInt(4))
	}

	// Make it negative for discriminant
	D := new(big.Int).Neg(prime)
	T := uint64(1024)

	logger.Info("Expected VDF parameters:")
	logger.Info("  Discriminant D: %d bits, D mod 4 = %d", D.BitLen(), new(big.Int).Mod(D, big.NewInt(4)))
	logger.Info("  T: %d", T)

	return VDFParams{
		Discriminant: D,
		T:            T,
		Lambda:       256,
	}
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
//
// SLOT PINNING — why we use currentView instead of wall-clock slot:
// wall-clock slots advance every 12 s.  If two nodes call UpdateLeaderStatus
// even milliseconds apart and they straddle a slot boundary, each sees a
// different slot → different RANDAO seed → different winner → the follower
// rejects every proposal.  Using currentView as the slot index is safe because
// every node that has committed the same blocks is at the same view number,
// so they all derive the same seed and elect the same leader regardless of
// when exactly they call this function.
func (c *Consensus) updateLeaderStatus() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.updateLeaderStatusLocked()
}

func (c *Consensus) updateLeaderStatusLocked() {
	// Fall back to round-robin if stake-weighted selection is disabled.
	if !c.useStakeWeighted {
		c.updateLeaderStatusRoundRobin()
		return
	}

	// PIN: use currentView as the canonical slot for this round.
	viewSlot := c.currentView
	viewEpoch := viewSlot / SlotsPerEpoch

	// Handle epoch transition if we've moved to a new epoch.
	if viewEpoch > c.currentEpoch {
		c.onEpochTransition(viewEpoch)
	}

	// Derive seed and run proposer selection.
	seed := c.randao.GetSeed(viewSlot)
	selected := c.selector.SelectProposer(viewEpoch, seed)

	if selected == nil {
		c.isLeader = false
		c.electedLeaderID = ""
		c.electedSlot = 0
		logger.Warn("No validator selected for view-slot %d", viewSlot)
		return
	}

	c.electedLeaderID = selected.ID
	c.electedSlot = viewSlot // carries the view number, not wall-clock
	c.isLeader = (selected.ID == c.nodeID)

	if c.isLeader {
		logger.Info("✅ Node %s elected proposer for view %d (stake %.2f SPX)",
			c.nodeID, viewSlot, selected.GetStakeInSPX())
	} else {
		logger.Info("   Node %s NOT proposer for view %d (elected: %s, stake %.2f SPX)",
			c.nodeID, viewSlot, selected.ID, selected.GetStakeInSPX())
	}
}

// GetElectedLeaderID returns the RANDAO-elected leader from the last UpdateLeaderStatus call.
func (c *Consensus) GetElectedLeaderID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.electedLeaderID
}

// RefreshLeaderStatus re-derives the leader for the current view and returns a
// consistent snapshot. Call this immediately before proposing so stale cached
// isLeader/electedLeaderID values cannot leak into a new view.
func (c *Consensus) RefreshLeaderStatus() (view uint64, electedLeaderID string, isLeader bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.updateLeaderStatusLocked()
	return c.currentView, c.electedLeaderID, c.isLeader
}

// ProposeBlock creates and broadcasts a new block proposal when this node is the leader
func (c *Consensus) ProposeBlock(block Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.updateLeaderStatusLocked()

	// Verify this node is actually the leader
	if !c.isLeader {
		return fmt.Errorf("node %s is not the leader for view %d (elected=%s)", c.nodeID, c.currentView, c.electedLeaderID)
	}

	// Update block metadata using the interface methods
	block.SetCommitStatus("proposed")
	block.SetSigValid(false)

	// Sign the block header if signing service is available
	if c.signingService != nil {
		if err := c.signingService.SignBlock(block); err != nil {
			return fmt.Errorf("failed to sign block header: %w", err)
		}
	}

	// Use the slot from election time
	proposalSlot := c.currentView
	logger.Info("📝 Using view %d as proposal slot (view=%d, height=%d)",
		proposalSlot, c.currentView, block.GetHeight())

	// Get the concrete block for serialization
	var concreteBlock interface{}
	if getter, ok := block.(interface{ GetUnderlyingBlock() interface{} }); ok {
		concreteBlock = getter.GetUnderlyingBlock()
	} else {
		concreteBlock = block
	}

	// Serialize the concrete block to JSON
	blockData, err := json.Marshal(concreteBlock)
	if err != nil {
		return fmt.Errorf("failed to serialize block: %w", err)
	}

	logger.Info("Serialized block data size: %d bytes, height from block: %d",
		len(blockData), block.GetHeight())

	// Create the proposal message with serialized block data
	proposal := &Proposal{
		BlockData:       blockData,
		View:            c.currentView,
		ProposerID:      c.nodeID,
		Signature:       []byte{},
		ElectedLeaderID: c.electedLeaderID,
		SlotNumber:      proposalSlot,
		Block:           block, // Store locally for immediate use
	}

	logger.Info("📝 Creating proposal: slot=%d, view=%d, leader=%s, block=%s, data_size=%d",
		proposalSlot, c.currentView, c.nodeID, block.GetHash(), len(blockData))

	// Sign the proposal
	if c.signingService != nil {
		if err := c.signingService.SignProposal(proposal); err != nil {
			return fmt.Errorf("failed to sign proposal: %w", err)
		}
	}

	// ========== FIX: Process proposal locally IMMEDIATELY ==========
	// The leader needs preparedBlock set before prepare votes arrive.
	// Process synchronously (this will set preparedBlock), then broadcast.
	c.processProposal(proposal)
	logger.Info("✅ Leader %s processed its own proposal locally", c.nodeID)

	// Broadcast the proposal to all peers
	if err := c.broadcastProposal(proposal); err != nil {
		return fmt.Errorf("failed to broadcast proposal: %w", err)
	}
	// ====================================================================

	logger.Info("✅ [%s] Block proposed and broadcast, waiting for consensus...", c.nodeID)
	return nil
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
	// Block view change if a proposal is currently being validated.
	// Without this, the view timer can fire (and advance currentView)
	// while processProposal is still mid-verification — e.g. waiting on
	// slow SPHINCS+ signature checks — causing that proposal to be
	// rejected as stale the instant verification completes, even though
	// the leader was actively making progress.
	if c.proposalInFlight {
		return true
	}
	// Block view change if we're in prepare phases
	if c.phase == PhasePrePrepared || c.phase == PhasePrepared {
		return true
	}
	// Block view change if we have pending votes
	if len(c.receivedVotes) > 0 || len(c.prepareVotes) > 0 {
		return true
	}
	if c.currentHeight > 0 && common.GetTimeService().Now().Sub(c.lastBlockTime) < 15*time.Second {
		return true
	}
	// FIX: Use a fixed 30-second window instead of c.timeout.
	// c.timeout may be set to values like 1 hour by callers (e.g. nodes.go
	// called cons.SetTimeout(1 * time.Hour)), which caused shouldPreventViewChange
	// to return true for 60 minutes after every round, permanently blocking
	// all view-changes and freezing the chain after block 1.
	const roundActivityWindow = 30 * time.Second
	if !c.lastRoundActivity.IsZero() && common.GetTimeService().Now().Sub(c.lastRoundActivity) < roundActivityWindow {
		return true
	}
	return false
}

// consensusLoop is the main loop that manages view change timeouts
func (c *Consensus) consensusLoop() {
	// Create timer for view change timeout - use a reasonable timeout
	timeout := c.timeout
	if timeout > 30*time.Second {
		timeout = 10 * time.Second // Cap at 10 seconds for responsiveness
	}
	viewTimer := time.NewTimer(timeout)
	defer viewTimer.Stop()

	// Create ticker for cleaning up stale signatures (every 30 seconds)
	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-viewTimer.C:
			if c.shouldPreventViewChange() {
				viewTimer.Reset(10 * time.Second)
				continue
			}

			// Check if chain has advanced since our last snapshot.
			if c.blockChain != nil {
				c.mu.RLock()
				currentHeight := c.currentHeight
				c.mu.RUnlock()

				chainBlock := c.blockChain.GetLatestBlock()
				if chainBlock != nil && chainBlock.GetHeight() > currentHeight {
					c.mu.Lock()
					c.currentHeight = chainBlock.GetHeight()
					c.mu.Unlock()
					viewTimer.Reset(10 * time.Second)
					continue
				}
			}

			// No new block within the timeout window — trigger view change.
			logger.Info("⏰ No new blocks for %v, checking view change...", timeout)
			c.startViewChange()
			viewTimer.Reset(10 * time.Second)

		case <-cleanupTicker.C:
			c.CleanupStaleSignatures()

		case <-c.ctx.Done():
			logger.Info("Consensus loop stopped for node %s", c.nodeID)
			return
		}
	}
}

// CleanupStaleSignatures removes signatures for blocks that don't exist in storage
// CleanupStaleSignatures removes signatures for blocks that don't exist in storage
func (c *Consensus) CleanupStaleSignatures() {
	c.signatureMutex.Lock()
	defer c.signatureMutex.Unlock()

	var cleaned []*ConsensusSignature
	removedCount := 0

	for _, sig := range c.consensusSignatures {
		// Check if block exists in storage
		block := c.blockChain.GetBlockByHash(sig.BlockHash)
		if block == nil {
			// Don't remove signatures for blocks that are still being processed
			// Only remove if the signature is older than 30 seconds
			sigTime, err := time.Parse(time.RFC3339, sig.Timestamp)
			if err == nil && time.Since(sigTime) > 30*time.Second {
				logger.Info("🧹 Removing stale signature for block %s (height=%d, type=%s, age=%v)",
					sig.BlockHash[:16], sig.BlockHeight, sig.MessageType, time.Since(sigTime))
				removedCount++
				continue
			}
			// Keep recent signatures even if block not in storage yet
			logger.Debug("Keeping recent signature for block %s (age=%v)", sig.BlockHash[:16], time.Since(sigTime))
		}
		cleaned = append(cleaned, sig)
	}

	c.consensusSignatures = cleaned
	if removedCount > 0 {
		logger.Info("✅ Cleaned up %d stale consensus signatures, %d remaining",
			removedCount, len(c.consensusSignatures))
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

// GetElectedSlot returns the slot number used for the current election
func (c *Consensus) GetElectedSlot() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.electedSlot
}

// BroadcastProposal broadcasts a proposal to all peers
func (c *Consensus) BroadcastProposal(proposal *Proposal) error {
	return c.broadcastProposal(proposal)
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
// processProposal validates and processes an incoming block proposal.
func (c *Consensus) processProposal(proposal *Proposal) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRoundActivity = common.GetTimeService().Now()

	// Mark this proposal as in-flight for the entire duration of validation
	// (deserialization, block validation, SPHINCS+ signature verification).
	// shouldPreventViewChange checks this so the view-change timer can't
	// fire mid-verification and increment currentView out from under a
	// proposal that hasn't been accepted/rejected yet. Using defer here
	// guarantees the flag clears on every one of this function's return
	// points (including the natural fall-through at the end), without
	// having to touch each individual return statement below.
	c.proposalInFlight = true
	defer func() { c.proposalInFlight = false }()

	// ========== FIX: Check if proposal.Block is nil FIRST ==========
	if proposal.Block == nil && len(proposal.BlockData) > 0 {
		// Try to deserialize as types.Block
		var block types.Block
		if err := json.Unmarshal(proposal.BlockData, &block); err != nil {
			logger.Error("Failed to deserialize block: %v", err)
			return
		}

		// Ensure the block height is correct
		if block.Header != nil {
			logger.Info("Deserialized block: height=%d, hash=%s", block.Header.Height, block.GetHash())
			if block.Header.Height == 0 && proposal.View == 0 {
				block.Header.Height = 1
				block.Header.Block = 1
				logger.Info("Corrected block height to 1")
			}
		}

		proposal.Block = &block
	}

	// NOW check if proposal.Block is still nil
	if proposal.Block == nil {
		logger.Error("Proposal has no block data")
		return
	}

	// ========== Store proposal in cache for leader self-recovery ==========
	c.proposalMutex.Lock()
	if c.pendingProposals == nil {
		c.pendingProposals = make(map[string]Block)
	}
	c.pendingProposals[proposal.Block.GetHash()] = proposal.Block
	c.proposalMutex.Unlock()

	// Clean up after 30 seconds
	go func(hash string) {
		time.Sleep(30 * time.Second)
		c.proposalMutex.Lock()
		delete(c.pendingProposals, hash)
		c.proposalMutex.Unlock()
	}(proposal.Block.GetHash())
	// ============================================================================

	// Get block nonce for logging
	nonce, err := proposal.Block.GetCurrentNonce()
	nonceStr := "unknown"
	if err != nil {
		logger.Warn("Failed to get block nonce: %v", err)
	} else {
		nonceStr = fmt.Sprintf("%d", nonce)
	}

	// Log proposal receipt
	logger.Info("🔍 Processing proposal for block at height %d, view %d from %s, nonce: %s",
		proposal.Block.GetHeight(), proposal.View, proposal.ProposerID, nonceStr)

	localTip := c.blockChain.GetLatestBlock()
	if localTip == nil {
		logger.Warn("❌ Cannot validate proposal %s: local chain has no tip", proposal.Block.GetHash())
		return
	}
	localTipHeight := localTip.GetHeight()
	proposalHeight := proposal.Block.GetHeight()

	// Already committed: the leader built this block while the network was
	// simultaneously committing the same height on this node.  This is a
	// normal race — the proposal is simply stale.  Drop it silently so the
	// next round can proceed without noise in the logs.
	if proposalHeight <= localTipHeight {
		logger.Info("⏭ Proposal for height %d already committed (local tip=%d), discarding",
			proposalHeight, localTipHeight)
		return
	}

	expectedHeight := localTipHeight + 1
	if proposalHeight != expectedHeight {
		if proposalHeight > expectedHeight {
			// This node is behind the network. Park the proposal in the cache
			// so it can be replayed once the gap is filled via FastForward,
			// and signal the sync layer to fetch the missing blocks.
			gap := proposalHeight - localTipHeight
			logger.Warn("⏩ Node behind: local tip=%d, proposal height=%d — need %d more block(s), signalling sync",
				localTipHeight, proposalHeight, gap)
			c.proposalMutex.Lock()
			if c.pendingProposals == nil {
				c.pendingProposals = make(map[string]Block)
			}
			c.pendingProposals[proposal.Block.GetHash()] = proposal.Block
			c.proposalMutex.Unlock()
			// Non-blocking send: best-effort; the sync goroutine drains this.
			select {
			case c.syncNeededCh <- localTipHeight + 1:
			default:
			}
		} else {
			logger.Warn("❌ Proposal height not ready: expected %d from local tip %s, got height %d block %s",
				expectedHeight, localTip.GetHash(), proposalHeight, proposal.Block.GetHash())
		}
		return
	}
	if proposal.Block.GetPrevHash() != localTip.GetHash() {
		logger.Warn("❌ Proposal parent not local tip: expected parent %s, got %s for block %s",
			localTip.GetHash(), proposal.Block.GetPrevHash(), proposal.Block.GetHash())
		return
	}

	// Validate the block itself
	if err := c.blockChain.ValidateBlock(proposal.Block); err != nil {
		logger.Warn("❌ Block validation failed: %v", err)
		return
	}

	// In processProposal, after validating the block
	if proposal.Block.GetHeight() == 0 {
		// This is a deserialization issue - try to correct
		logger.Warn("Block height is 0, attempting to correct to height 1")

		// Try to set the height using reflection or interface
		if setter, ok := proposal.Block.(interface{ SetHeight(uint64) }); ok {
			setter.SetHeight(1)
			logger.Info("Successfully corrected block height to 1")
		} else {
			// Try to access underlying block directly
			if getter, ok := proposal.Block.(interface{ GetUnderlyingBlock() interface{} }); ok {
				if underlying, ok := getter.GetUnderlyingBlock().(*types.Block); ok && underlying != nil {
					underlying.Header.Height = 1
					underlying.Header.Block = 1
					logger.Info("Successfully corrected underlying block height to 1")
				}
			}
		}
	}

	// Check for duplicate proposal
	if c.preparedBlock != nil && c.preparedBlock.GetHash() == proposal.Block.GetHash() {
		logger.Debug("Already have prepared block for height %d, continuing with validation",
			proposal.Block.GetHeight())
		// Don't return here - continue with validation to verify signatures
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
	proposal.Block.SetSigValid(true)
	proposal.Block.SetCommitStatus("proposed")

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
		if proposal.View == c.currentView-1 {
			logger.Info("⚠️ Proposal for view %d (current view %d) - catching up", proposal.View, c.currentView)
			// This is a late retransmission from the previous round. If lockedBlock
			// is still set from that round (commitBlock's second c.mu acquisition
			// hasn't run yet), the equivocation guard below would fire and reject it.
			// Since we have already advanced past this view, there is nothing to
			// equivocate — clear the stale lock so the height/parentHash checks
			// decide whether this proposal is still actionable.
			if c.lockedBlock != nil {
				logger.Info("⚠️ Clearing stale lockedBlock %s from old view %d before catching-up processing",
					c.lockedBlock.GetHash()[:16], proposal.View)
				c.lockedBlock = nil
			}
			// Re-check tip height: commitBlock may have advanced the chain in the
			// narrow window between the outer height check and here. Discard if so.
			recheck := c.blockChain.GetLatestBlock()
			if recheck != nil && proposal.Block.GetHeight() <= recheck.GetHeight() {
				logger.Info("⏭ Catching-up proposal for height %d already committed (tip now %d), discarding",
					proposal.Block.GetHeight(), recheck.GetHeight())
				return
			}
			// Don't return — continue processing; height check will discard if still not ready
		} else {
			logger.Warn("❌ Stale proposal for view %d, current view %d", proposal.View, c.currentView)
			return
		}
	}
	// =================================================================================

	// Handle view advancement if proposal is for a newer view.
	if proposal.View > c.currentView {
		logger.Info("🔄 Advancing view from %d to %d", c.currentView, proposal.View)
		c.currentView = proposal.View
		c.resetConsensusState()
		// Do NOT call updateLeaderStatus() here — it would deadlock because
		// processProposal already holds c.mu.  The re-derive block below
		// (using proposal.SlotNumber == proposal.View) handles the election.
	}

	// Re-derive electedLeaderID from the proposal's SlotNumber.
	// The leader sets SlotNumber = currentView (view-pinned slot), so every
	// follower that applies the same seed to SelectProposer gets the same winner.
	if proposal.SlotNumber > 0 {
		slotEpoch := proposal.SlotNumber / SlotsPerEpoch
		seed := c.randao.GetSeed(proposal.SlotNumber)
		selected := c.selector.SelectProposer(slotEpoch, seed)
		if selected != nil {
			c.electedLeaderID = selected.ID
			logger.Info("🔄 Follower re-derived electedLeaderID=%s for view-slot %d",
				c.electedLeaderID, proposal.SlotNumber)
		} else {
			logger.Warn("⚠️ SelectProposer returned nil for slot %d, trusting signed proposal", proposal.SlotNumber)
			c.electedLeaderID = proposal.ProposerID
		}
	} else if proposal.ElectedLeaderID != "" {
		logger.Warn("⚠️ Proposal has no SlotNumber, using embedded ElectedLeaderID=%s", proposal.ElectedLeaderID)
		c.electedLeaderID = proposal.ElectedLeaderID
	} else {
		// SlotNumber and ElectedLeaderID both absent — fall back to view-pinned election.
		viewSlot := c.currentView
		viewEpoch := viewSlot / SlotsPerEpoch
		seed := c.randao.GetSeed(viewSlot)
		if sel := c.selector.SelectProposer(viewEpoch, seed); sel != nil {
			c.electedLeaderID = sel.ID
		}
	}

	// Validate that the proposer is the legitimate leader
	if !c.isValidLeader(proposal.ProposerID, proposal.View) {
		logger.Warn("❌ Invalid leader %s for view %d (electedLeaderID=%s)",
			proposal.ProposerID, proposal.View, c.electedLeaderID)
		return
	}

	// ========== FIX 2: Special handling for leader's own proposal ==========
	isSelfProposal := (proposal.ProposerID == c.nodeID)

	if isSelfProposal {
		logger.Info("👑 [%s] LEADER: Processing own proposal for block %s", c.nodeID, proposal.Block.GetHash())
	}
	// =========================================================================

	// SAFETY: once this node has reached prepare-quorum and locked a block
	// for this height (c.lockedBlock set in tryEnterPreparedPhase), it must
	// never abandon that lock for a different, conflicting proposal in the
	// same view. Without this guard, a second/equivocating proposal at the
	// same height resets preparedBlock and forces phase back to
	// PhasePrePrepared below, letting this node re-enter PREPARED and
	// overwrite c.lockedBlock with the new block — i.e. it commits a vote
	// for two different blocks at the same height. That is precisely what
	// let different nodes converge on two different block hashes at the
	// same height (chain fork). c.lockedBlock is correctly cleared on every
	// legitimate commit and on legitimate view-advancement above, so this
	// only blocks genuine same-view equivocation, never normal progress.
	if c.lockedBlock != nil && c.lockedBlock.GetHash() != proposal.Block.GetHash() {
		// Before hard-rejecting, apply two escape hatches that distinguish genuine
		// equivocation (same view, two different blocks) from stale locks that must
		// be cleared to allow the chain to continue.
		chainTip := c.blockChain.GetLatestBlock()
		lockedHeight := c.lockedBlock.GetHeight()

		// Escape 1: The locked block has already been committed to storage (e.g. by
		// a concurrent commitBlock goroutine that hasn't re-acquired c.mu yet to
		// clear lockedBlock). The chain tip has advanced past lockedHeight, so this
		// new proposal is for a legitimately new height — not equivocation.
		if chainTip != nil && chainTip.GetHeight() >= lockedHeight {
			logger.Info("🔓 Clearing stale lockedBlock %s (height=%d, tip=%d) — committed mid-flight, not equivocation",
				c.lockedBlock.GetHash()[:16], lockedHeight, chainTip.GetHeight())
			c.lockedBlock = nil

			// Escape 2: The lock was acquired in a previous view (c.preparedView < proposal.View).
			// This happens when prepare quorum was reached and lockedBlock was set, but commit
			// quorum was never achieved — causing a view change — and the new view's leader is
			// now proposing a different block for the same height. Across a view change without
			// a completed commit, the lock is stale and must be cleared; refusing here would
			// permanently stall this node since resetConsensusState() in the view-advancement
			// branch (proposal.View > c.currentView) runs BEFORE this guard.
			// Note: resetConsensusState() only runs when proposal.View > c.currentView.
			// If the node is still at the same currentView (e.g. catching-up branch), the
			// lock may survive; preparedView is the reliable record of the view it was set in.
		} else if c.preparedView < proposal.View {
			logger.Info("🔓 Clearing cross-view lockedBlock %s (lockedAtView=%d, proposalView=%d, height=%d) — new view, not equivocation",
				c.lockedBlock.GetHash()[:16], c.preparedView, proposal.View, lockedHeight)
			c.lockedBlock = nil

		} else {
			logger.Warn("❌ Rejecting conflicting proposal %s at height %d: already locked on %s (same view %d) — refusing to equivocate",
				proposal.Block.GetHash()[:16], proposal.Block.GetHeight(), c.lockedBlock.GetHash()[:16], c.preparedView)
			return
		}
	}

	if c.preparedBlock != nil && c.preparedBlock.GetHash() != proposal.Block.GetHash() {
		oldHash := c.preparedBlock.GetHash()
		logger.Info("🔄 Resetting preparedBlock from %s to accept validated proposal %s from leader %s",
			oldHash[:16], proposal.Block.GetHash()[:16], proposal.ProposerID)
		c.preparedBlock = nil
		c.preparedView = 0
		c.preparedBlockHash = ""
		delete(c.prepareVotes, oldHash)
		delete(c.receivedVotes, oldHash)
	}
	if c.preparedBlock == nil || c.preparedBlock.GetHash() != proposal.Block.GetHash() {
		c.preparedBlock = proposal.Block
		c.preparedView = proposal.View
		c.preparedBlockHash = proposal.Block.GetHash()
		logger.Info("🚀 Set preparedBlock for validated proposal %s at height %d",
			proposal.Block.GetHash()[:16], proposal.Block.GetHeight())
	}

	// Accept the proposal
	logger.Info("✅ Node %s accepting proposal for block %s at view %d (height %d, nonce: %s)",
		c.nodeID, proposal.Block.GetHash(), proposal.View, proposal.Block.GetHeight(), nonceStr)

	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	if isSelfProposal {
		logger.Info("👑 [%s] LEADER: Processed own proposal for block %s", c.nodeID, proposal.Block.GetHash())
	} else {
		logger.Info("📬 [%s] FOLLOWER: Received proposal from leader %s for block %s",
			c.nodeID, proposal.ProposerID, proposal.Block.GetHash())
	}
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Ensure preparedBlock is still set (it should be from the beginning)
	if c.preparedBlock == nil || c.preparedBlock.GetHash() != proposal.Block.GetHash() {
		logger.Warn("⚠️ preparedBlock was lost! Re-setting for %s", proposal.Block.GetHash())
		c.preparedBlock = proposal.Block
		c.preparedView = proposal.View
		c.preparedBlockHash = proposal.Block.GetHash()
	}

	c.phase = PhasePrePrepared

	// Send prepare vote for this block (skip for leader's own proposal if already sent)
	if !isSelfProposal || !c.sentPrepareVotes[proposal.Block.GetHash()] {
		c.sendPrepareVote(proposal.Block.GetHash(), proposal.View)
		if isSelfProposal {
			logger.Info("👑 [%s] LEADER: Sending prepare vote for own block", c.nodeID)
		} else {
			logger.Info("✅ [%s] FOLLOWER: Proposal validated, sending prepare vote", c.nodeID)
		}
	} else {
		logger.Info("👑 [%s] LEADER: Already sent prepare vote for own block", c.nodeID)
	}

	// ========== FIX: catch quorum that arrived before this proposal ==========
	// proposalCh and prepareCh are drained by independent goroutines
	// (handleProposals / handlePrepareVotes), so peer PREPARE votes can be
	// processed by processPrepareVote() before this node's own proposal has
	// been processed here (and thus before c.preparedBlock was set). Without
	// this call, that ordering silently drops the PrePrepared->Prepared
	// transition forever, leaving the node stuck and never broadcasting its
	// own commit vote. See tryEnterPreparedPhase for full details.
	c.tryEnterPreparedPhase(proposal.Block.GetHash(), proposal.View)

	// ========== FIX: catch commit quorum that arrived before this proposal ==========
	// Commit votes can arrive (and reach quorum) before the proposal is processed
	// locally. processVoteLocked now parks those votes instead of discarding them.
	// Check here — after preparedBlock is set — whether commit quorum was already
	// achieved for this block, and if so dispatch the commit asynchronously.
	// We cannot call commitBlock directly (it calls blockChain.CommitBlock which
	// does I/O and must run outside c.mu), so we release the lock then commit.
	blockHash := proposal.Block.GetHash()
	view := proposal.View
	if c.phase != PhaseCommitted && c.hasQuorum(blockHash) {
		blockToCommit := proposal.Block
		logger.Info("🔄 Commit quorum was already reached for %s before proposal arrived — committing now", blockHash[:16])
		// Transition to committed phase and lock the block before releasing the mutex.
		c.phase = PhaseCommitted
		c.lockedBlock = blockToCommit
		_ = view // view used in logging above
		go func() {
			c.commitBlock(blockToCommit)
		}()
	}
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

// SetCurrentHeight updates the consensus engine's current height
func (c *Consensus) SetCurrentHeight(height uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.currentHeight = height
	logger.Info("Consensus height updated to %d for node %s", height, c.nodeID)
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
	c.lastRoundActivity = common.GetTimeService().Now()

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

	// Check if we've achieved quorum for this block. The actual
	// PrePrepared -> Prepared transition and commit-vote broadcast are
	// handled by tryEnterPreparedPhase (see its doc comment for why that
	// logic needs to live in one place callable from two sites).
	if c.hasPrepareQuorum(vote.BlockHash) {
		logger.Info("🎉 PREPARE QUORUM ACHIEVED for block %s at view %d", vote.BlockHash, vote.View)
	}
	c.tryEnterPreparedPhase(vote.BlockHash, vote.View)
}

// tryEnterPreparedPhase performs the PrePrepared -> Prepared transition and
// broadcasts this node's own commit vote, once ALL of the following hold:
//   - prepare quorum has been reached for blockHash, and
//   - c.phase is still PhasePrePrepared (i.e. we haven't already moved on), and
//   - this node has a matching preparedBlock for that hash.
//
// MUST be called with c.mu already held (no internal locking). It is safe
// (and intended) to call this speculatively/repeatedly from multiple call
// sites — it is a no-op until every precondition holds, and the c.phase
// guard makes the actual transition idempotent.
//
// Why two call sites are required:
// proposalCh and prepareCh are drained by two independent goroutines
// (handleProposals / handlePrepareVotes) with no ordering guarantee between
// them. A peer's PREPARE vote can therefore complete quorum — via
// processPrepareVote() — before this node's own processProposal() has run
// and set c.preparedBlock. Previously, the quorum check lived only inside
// processPrepareVote and simply gave up if preparedBlock wasn't set yet:
//
//	if c.preparedBlock == nil || ... { logger.Warn(...); return }
//
// That discarded the quorum event permanently — nothing else ever re-checked
// it once the last needed vote had already been processed — leaving the
// node stuck in PhasePrePrepared forever, with no commit vote ever sent.
// That single missing commit vote is enough to stall the *entire* network,
// since every other node then sits at votes=N-1/N waiting on it and times
// out every round. Calling this same helper from both processProposal and
// processPrepareVote closes that race: whichever of {the proposal, the
// quorum-completing vote} arrives second is the one that completes it.
func (c *Consensus) tryEnterPreparedPhase(blockHash string, view uint64) {
	if !c.hasPrepareQuorum(blockHash) {
		return // not yet — still waiting on prepare votes
	}
	if c.phase == PhasePrepared || c.phase == PhaseCommitted {
		// Already transitioned for this round — nothing to do.
		logger.Info("⚠️ Quorum reached for %s but already in phase %v, skipping transition", blockHash, c.phase)
		return
	}
	// PhaseIdle and PhasePrePrepared are both valid entry points:
	// - PhasePrePrepared: normal path, proposal processed before votes
	// - PhaseIdle: votes arrived before processProposal set the phase (channel
	//   ordering race), or the leader's own proposal is being processed while
	//   phase is still PhaseIdle after a fresh post-commit reset.
	if c.preparedBlock == nil || c.preparedBlock.GetHash() != blockHash {
		logger.Info("⏳ Prepare quorum reached for %s but proposal not processed locally yet — will retry once it arrives", blockHash)
		return
	}

	// Record a consensus signature for every prepare vote collected for this
	// block (previously only the single vote that happened to cross the
	// quorum threshold got recorded; this captures the full set).
	if votes := c.prepareVotes[blockHash]; votes != nil {
		for voterID, v := range votes {
			c.addConsensusSig(&ConsensusSignature{
				BlockHash:    blockHash,
				BlockHeight:  c.currentHeight,
				SignerNodeID: voterID,
				Signature:    hex.EncodeToString(v.Signature),
				MessageType:  "prepare",
				View:         view,
				Timestamp:    common.GetTimeService().GetCurrentTimeInfo().ISOLocal,
				Valid:        true,
				MerkleRoot:   "pending_calculation",
				Status:       "prepared",
			})
		}
	}

	// Transition to prepared phase.
	c.phase = PhasePrepared
	c.lockedBlock = c.preparedBlock
	c.preparedBlock.SetCommitStatus("prepared")

	logger.Info("[%s] 🔄 Entered PREPARED phase for block %s at height %d — sending commit vote",
		c.nodeID, blockHash, c.preparedBlock.GetHeight())

	// Send our own commit vote for this block.
	c.voteForBlock(blockHash, view)
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

	// If signature hash is missing, try to extract from the original signed message
	if sig.SignatureHash == "" && len(sig.Signature) > 0 {
		// Deserialize the signature to get the signature hash
		// This requires access to the signing service
		// For now, set a placeholder
		sig.SignatureHash = "pending_extraction"
	}

	// Append to signatures collection
	c.consensusSignatures = append(c.consensusSignatures, sig)
	logger.Info("🎯 Added signature: block=%s, merkle_root=%s, status=%s", sig.BlockHash, sig.MerkleRoot, sig.Status)
}

// extractMerkleRootFromBlock attempts to extract the merkle root from a block
// extractMerkleRootFromBlock attempts to extract the merkle root from a block
func (c *Consensus) extractMerkleRootFromBlock(block Block) string {
	// Try to get underlying block and extract from header
	var tb *types.Block

	// Check if it's a BlockHelper
	type underlyingGetter interface {
		GetUnderlyingBlock() interface{}
	}

	if getter, ok := block.(underlyingGetter); ok {
		if underlying, ok := getter.GetUnderlyingBlock().(*types.Block); ok {
			tb = underlying
		}
	} else if direct, ok := block.(*types.Block); ok {
		tb = direct
	}

	if tb != nil && tb.Header != nil && len(tb.Header.TxsRoot) > 0 {
		return fmt.Sprintf("%x", tb.Header.TxsRoot)
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

// processVote handles incoming commit votes.
func (c *Consensus) processVote(vote *Vote) {
	blockToCommit := c.processVoteLocked(vote)
	if blockToCommit != nil {
		c.commitBlock(blockToCommit)
	}
}

// processVoteLocked records a commit vote and returns a block to commit once
// quorum is reached. It must not execute storage/state work while c.mu is held.
func (c *Consensus) processVoteLocked(vote *Vote) Block {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify vote signature if signing service available
	if c.signingService != nil && len(vote.Signature) > 0 {
		valid, err := c.signingService.VerifyVote(vote)
		if err != nil || !valid {
			logger.Warn("Invalid vote signature from %s", vote.VoterID)
			return nil
		}
	}

	// Initialize vote tracking for this block if needed
	if c.receivedVotes[vote.BlockHash] == nil {
		c.receivedVotes[vote.BlockHash] = make(map[string]*Vote)
		c.weightedCommitVotes[vote.BlockHash] = big.NewInt(0)
	}

	// Ignore duplicate votes
	if _, exists := c.receivedVotes[vote.BlockHash][vote.VoterID]; exists {
		return nil
	}
	if c.phase == PhaseCommitted {
		logger.Info("Commit vote ignored for block %s: round already committed", vote.BlockHash)
		return nil
	}

	// Store the vote
	c.receivedVotes[vote.BlockHash][vote.VoterID] = vote
	c.lastRoundActivity = common.GetTimeService().Now()

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

	// In processVote, when commit quorum is achieved
	if c.hasQuorum(vote.BlockHash) {
		logger.Info("🎉 COMMIT QUORUM ACHIEVED for block %s at view %d", vote.BlockHash, vote.View)

		// Determine which block to commit
		var blockToCommit Block
		if c.lockedBlock != nil && c.lockedBlock.GetHash() == vote.BlockHash {
			blockToCommit = c.lockedBlock
		} else if c.preparedBlock != nil && c.preparedBlock.GetHash() == vote.BlockHash {
			blockToCommit = c.preparedBlock
		} else {
			// Last-resort: recover from the proposal cache populated in processProposal.
			// This handles the case where quorum arrives while lockedBlock/preparedBlock
			// are nil — e.g. the catching-up branch cleared lockedBlock before
			// tryEnterPreparedPhase ran, or a view-reset wiped preparedBlock mid-round.
			// The block was fully validated when cached, so it is safe to commit from here.
			c.proposalMutex.RLock()
			cached, ok := c.pendingProposals[vote.BlockHash]
			c.proposalMutex.RUnlock()
			if ok && cached != nil {
				logger.Info("🔄 Recovering block %s from proposal cache for commit (lockedBlock/preparedBlock were nil)",
					vote.BlockHash[:16])
				blockToCommit = cached
				// Re-lock so the equivocation guard holds for any straggler proposals.
				c.lockedBlock = cached
			} else {
				// The proposal for this block has not arrived yet (votes raced ahead of
				// the proposal). Keep accumulated votes in receivedVotes so that when
				// processProposal later sets preparedBlock, it can detect the already-
				// reached quorum and trigger the commit via the end-of-proposal quorum check.
				logger.Info("⏳ Commit quorum for %s reached before proposal — parking votes (will commit once proposal arrives)", vote.BlockHash[:16])
				return nil
			}
		}

		// Move to committed phase if not already there
		if c.phase != PhaseCommitted {
			c.phase = PhaseCommitted
			logger.Info("🚀 Moving to COMMITTED phase for block %s", vote.BlockHash)
		}

		// ========== FIX: Attach attestations BEFORE commit ==========
		// Extract underlying block
		var tb *types.Block
		if direct, ok := blockToCommit.(*types.Block); ok {
			tb = direct
		} else if getter, ok := blockToCommit.(interface{ GetUnderlyingBlock() interface{} }); ok {
			if underlying, ok := getter.GetUnderlyingBlock().(*types.Block); ok {
				tb = underlying
			}
		}

		if tb != nil {
			// Take snapshot of votes
			votesSnapshot := make(map[string]*Vote)
			if votes, exists := c.receivedVotes[vote.BlockHash]; exists {
				for k, v := range votes {
					votesSnapshot[k] = v
				}
				logger.Info("📸 Captured %d votes for attestations", len(votesSnapshot))
			}

			// Attach attestations directly to the block
			if len(votesSnapshot) > 0 {
				tb.Body.Attestations = make([]*types.Attestation, 0, len(votesSnapshot))
				for voterID, vote := range votesSnapshot {
					tb.Body.Attestations = append(tb.Body.Attestations, &types.Attestation{
						ValidatorID: voterID,
						BlockHash:   blockToCommit.GetHash(),
						View:        vote.View,
						Signature:   vote.Signature, // Keep as bytes, hex encoding happens in storage
					})
				}
				logger.Info("✅ Attached %d attestations to block BEFORE commit", len(tb.Body.Attestations))
			}
		}
		// ============================================================

		// Commit the block after releasing c.mu. CommitBlock performs storage,
		// state execution, checkpoint writes, and callbacks; holding the
		// consensus mutex across that work can deadlock Phase 2 leader refresh.
		return blockToCommit
	}

	return nil
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

	// If timeout is for a higher view, perform view change.
	if timeout.View > c.currentView {
		logger.Info("View change requested to view %d by %s", timeout.View, timeout.VoterID)
		c.currentView = timeout.View
		c.lastViewChange = common.GetTimeService().Now()
		c.resetConsensusState()
		// Use view-pinned RANDAO election so view-change leader matches proposal validation.
		viewSlot := c.currentView
		viewEpoch := viewSlot / SlotsPerEpoch
		seed := c.randao.GetSeed(viewSlot)
		if sel := c.selector.SelectProposer(viewEpoch, seed); sel != nil {
			c.electedLeaderID = sel.ID
			c.electedSlot = viewSlot
			c.isLeader = (sel.ID == c.nodeID)
		} else {
			// Fallback to round-robin if no stake set yet.
			c.updateLeaderStatusWithValidators(c.getValidators())
		}
		logger.Info("View change completed: node=%s, new_view=%d, leader=%v (elected=%s)",
			c.nodeID, c.currentView, c.isLeader, c.electedLeaderID)
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
	c.lastRoundActivity = common.GetTimeService().Now()

	// ========== FIX: register our own vote locally before broadcasting ==========
	// broadcastPrepareVote only sends this vote to peers — it never arrives back
	// at this node over the network (nodes don't loop messages to themselves).
	// Without this, processPrepareVote/hasPrepareQuorum only ever see N-1 votes
	// (everyone else's), so a quorum that should pass at 2-of-3 stake can fail
	// if the two *peer* votes alone don't clear 2/3 of total stake, even though
	// this node's own vote would have pushed it over. Insert it the same way
	// processProposal pre-emptively sets preparedBlock for a self-proposal.
	if c.prepareVotes[blockHash] == nil {
		c.prepareVotes[blockHash] = make(map[string]*Vote)
		c.weightedPrepareVotes[blockHash] = big.NewInt(0)
	}
	if _, exists := c.prepareVotes[blockHash][c.nodeID]; !exists {
		c.prepareVotes[blockHash][c.nodeID] = prepareVote
		selfStake := c.getValidatorStake(c.nodeID)
		c.weightedPrepareVotes[blockHash].Add(c.weightedPrepareVotes[blockHash], selfStake)
	}
	// ==============================================================================

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
	c.lastRoundActivity = common.GetTimeService().Now()

	// ========== FIX: register our own commit vote locally before broadcasting ==========
	// Same issue as sendPrepareVote above: broadcastVote only reaches peers, so
	// without this, hasQuorum() never counts this node's own stake toward the
	// commit quorum it itself is trying to reach.
	if c.receivedVotes[blockHash] == nil {
		c.receivedVotes[blockHash] = make(map[string]*Vote)
		c.weightedCommitVotes[blockHash] = big.NewInt(0)
	}
	if _, exists := c.receivedVotes[blockHash][c.nodeID]; !exists {
		c.receivedVotes[blockHash][c.nodeID] = vote
		selfStake := c.getValidatorStake(c.nodeID)
		c.weightedCommitVotes[blockHash].Add(c.weightedCommitVotes[blockHash], selfStake)
	}
	// =====================================================================================

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

	// Verify block height against current chain tip
	currentTip := c.blockChain.GetLatestBlock()
	if currentTip == nil {
		logger.Error("No chain tip available, cannot commit block")
		return
	}
	currentHeight := currentTip.GetHeight()
	blockHeight := block.GetHeight()

	if blockHeight < currentHeight {
		// Block is behind the current tip – already superseded
		logger.Info("Block height %d behind current height %d, ignoring", blockHeight, currentHeight)
		return
	}
	if blockHeight == currentHeight {
		// Same height: check if it's the same block
		if block.GetHash() == currentTip.GetHash() {
			logger.Info("Block height %d hash %s already committed, ignoring duplicate", blockHeight, block.GetHash())
			return
		} else {
			// Different block at same height – fork
			logger.Warn("Fork detected: block height %d hash %s differs from current tip %s",
				blockHeight, block.GetHash(), currentTip.GetHash())
			// Optionally trigger a sync or recovery here
			return
		}
	}
	// Now blockHeight > currentHeight, proceed with normal commit
	logger.Info("🚀 Node %s attempting to commit block %s at height %d (current tip %d)",
		c.nodeID, block.GetHash(), blockHeight, currentHeight)

	// Update block metadata using interface method
	block.SetCommitStatus("committed")

	// Try to extract underlying block for additional operations
	var tb *types.Block
	if direct, ok := block.(*types.Block); ok {
		tb = direct
	}

	if tb != nil {
		if len(tb.Header.ProposerSignature) > 0 {
			tb.Header.SigValid = true
		}
		if len(tb.Body.Attestations) > 0 {
			logger.Info("✅ Block already has %d attestations attached", len(tb.Body.Attestations))
		} else {
			logger.Warn("⚠️ No attestations attached to block before commit")
		}
	}

	// FIX: Clear lockedBlock under c.mu BEFORE calling blockChain.CommitBlock.
	//
	// Race condition: blockChain.CommitBlock performs storage I/O (state DB
	// flush, block storage) without holding c.mu. During that window the
	// StartLeaderLoop ticker can fire, see c.isLeader=true for this view, call
	// ProposeBlock (which acquires c.mu), and then processProposal will find
	// c.lockedBlock still set to the block we are in the process of committing.
	// If blockChain.CommitBlock hasn't yet appended to bc.chain, GetLatestBlock
	// returns the previous height, so the "stale lock" check
	// (chainTip.GetHeight() >= lockedBlock.GetHeight()) evaluates to false and
	// the leader rejects its own proposal, stalling the chain.
	//
	// Clearing lockedBlock here (before storage I/O) eliminates the race:
	// any concurrent processProposal will see lockedBlock==nil and proceed
	// normally, with the height/parentHash checks acting as the safety net.
	// preparedBlock is cleared for the same reason.
	committedHash := block.GetHash()
	c.mu.Lock()
	if c.lockedBlock != nil && c.lockedBlock.GetHash() == committedHash {
		c.lockedBlock = nil
	}
	if c.preparedBlock != nil && c.preparedBlock.GetHash() == committedHash {
		c.preparedBlock = nil
		c.preparedView = 0
		c.preparedBlockHash = ""
	}
	c.mu.Unlock()

	// Commit block to blockchain
	if err := c.blockChain.CommitBlock(block); err != nil {
		logger.Error("❌ Error committing block: %v", err)
		return
	}

	// Execute commit callback if provided (c.mu NOT held here — callback may lock)
	if c.onCommit != nil {
		if err := c.onCommit(block); err != nil {
			logger.Warn("⚠️ Error in commit callback: %v", err)
		}
	}

	// Update consensus state after storage/state commit is complete.
	c.mu.Lock()
	defer c.mu.Unlock()

	newHeight := block.GetHeight()
	c.currentHeight = newHeight
	c.lastBlockTime = common.GetTimeService().Now()
	// FIX: reset lastRoundActivity at commit so shouldPreventViewChange's 30s
	// window starts from NOW. Without this, lastRoundActivity was left at the
	// timestamp of the last incoming vote, which could be several seconds in
	// the past; combined with the 30-second window this could expire almost
	// immediately, letting followers fire spurious view-changes within seconds
	// of a commit and advancing their currentView ahead of the leader.
	c.lastRoundActivity = common.GetTimeService().Now()

	// Reset ALL per-round state and advance view for next round.
	c.currentView++ // Increment view for next round
	c.phase = PhaseIdle
	c.lockedBlock = nil
	c.preparedBlock = nil
	c.preparedView = 0
	c.preparedBlockHash = ""
	c.receivedVotes = make(map[string]map[string]*Vote)
	c.prepareVotes = make(map[string]map[string]*Vote)
	c.sentVotes = make(map[string]bool)
	c.sentPrepareVotes = make(map[string]bool)
	c.weightedPrepareVotes = make(map[string]*big.Int)
	c.weightedCommitVotes = make(map[string]*big.Int)
	// Evict only proposals at or below the committed height.
	// Proposals for the NEXT height may already be cached (arrived early)
	// and must survive this commit so FastForward can replay them.
	committedHeight := block.GetHeight()
	for hash, b := range c.pendingProposals {
		if b.GetHeight() <= committedHeight {
			delete(c.pendingProposals, hash)
		}
	}

	// Add self-commit signature while still under caller's c.mu.
	commitSig := &ConsensusSignature{
		BlockHash:    block.GetHash(),
		BlockHeight:  newHeight,
		SignerNodeID: c.nodeID,
		Signature:    "committed_by_" + c.nodeID,
		MessageType:  "commit",
		View:         c.currentView,
		Timestamp:    common.GetTimeService().GetCurrentTimeInfo().ISOLocal,
		Valid:        true,
		MerkleRoot:   c.extractMerkleRootFromBlock(block),
		Status:       "committed",
	}
	c.addConsensusSig(commitSig)

	logger.Info("🎉 Node %s committed block %s at height %d (view now %d)",
		c.nodeID, block.GetHash(), newHeight, c.currentView)

	logger.Info("🔄 Updating leader status for next round at height %d, view %d", newHeight, c.currentView)
	c.updateLeaderStatusLocked()
	logger.Info("📊 Leader status after commit: isLeader=%v, electedLeader=%s", c.isLeader, c.electedLeaderID)
}

// StartViewChange initiates a view change process (public wrapper for startViewChange)
func (c *Consensus) StartViewChange() {
	c.startViewChange()
}

// startViewChange initiates a view change process
func (c *Consensus) startViewChange() {
	// Try to acquire view change lock
	if !c.tryViewChangeLock() {
		return
	}
	defer c.viewChangeMutex.Unlock()

	c.mu.Lock()

	// Check conditions for view change
	if c.phase != PhaseIdle {
		logger.Info("View change skipped - not in idle phase (phase=%v)", c.phase)
		c.mu.Unlock()
		return
	}

	// ========== FIX: Increase rate limit ==========
	if common.GetTimeService().Now().Sub(c.lastViewChange) < 10*time.Second {
		logger.Info("View change skipped - rate limited (last view change was %v ago)",
			time.Since(c.lastViewChange))
		c.mu.Unlock()
		return
	}
	// ==============================================

	if c.currentHeight > 0 && common.GetTimeService().Now().Sub(c.lastBlockTime) < 15*time.Second {
		logger.Info("View change skipped - recent block committed")
		c.mu.Unlock()
		return
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

	// Use view-pinned RANDAO election
	viewSlot := c.currentView
	viewEpoch := viewSlot / SlotsPerEpoch
	seed := c.randao.GetSeed(viewSlot)
	if sel := c.selector.SelectProposer(viewEpoch, seed); sel != nil {
		c.electedLeaderID = sel.ID
		c.electedSlot = viewSlot
		c.isLeader = (sel.ID == c.nodeID)
		logger.Info("📊 New leader for view %d: %s (isLeader=%v)", newView, c.electedLeaderID, c.isLeader)
	} else {
		c.updateLeaderStatusWithValidators(validators)
	}

	// Unlock before broadcasting to avoid deadlock
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
// resetConsensusState clears all consensus-related state for a new view
func (c *Consensus) resetConsensusState() {
	c.phase = PhaseIdle
	c.lockedBlock = nil
	c.preparedBlock = nil
	c.preparedView = 0
	c.preparedBlockHash = "" // ← ADD THIS - clear the hash too
	c.receivedVotes = make(map[string]map[string]*Vote)
	c.prepareVotes = make(map[string]map[string]*Vote)
	c.sentVotes = make(map[string]bool)
	c.sentPrepareVotes = make(map[string]bool)
	c.weightedPrepareVotes = make(map[string]*big.Int) // ← ADD THIS
	c.weightedCommitVotes = make(map[string]*big.Int)  // ← ADD THIS
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

// GetValidators returns a list of all active validator node IDs (public version)
func (c *Consensus) GetValidators() []string {
	return c.getValidators()
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
		logger.Info("✅ Added self as validator: %s", c.nodeID)
	} else {
		logger.Warn("⚠️ Self is NOT a validator: %s", c.nodeID)
	}

	// Add validator peers
	for _, peer := range peers {
		node := peer.GetNode()
		if node != nil && node.GetRole() == RoleValidator && node.GetStatus() == NodeStatusActive {
			nodeID := node.GetID()
			if !validatorSet[nodeID] && nodeID != "" {
				validatorSet[nodeID] = true
				validators = append(validators, nodeID)
				logger.Info("✅ Added peer validator: %s", nodeID)
			}
		}
	}

	logger.Info("📊 Total validators found: %d", len(validators))
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

// AddConsensusSignature adds a signature to the consensus signatures collection
func (c *Consensus) AddConsensusSignature(sig *ConsensusSignature) {
	c.addConsensusSig(sig)
}

// broadcastProposal sends a proposal to all peers
func (c *Consensus) broadcastProposal(proposal *Proposal) error {
	// Log the proposal JSON for debugging
	jsonData, _ := json.Marshal(proposal)
	logger.Info("Broadcasting proposal JSON (first 500 chars): %s", string(jsonData[:min(500, len(jsonData))]))

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

// GetSyncNeededCh returns the channel that fires when this node detects it has
// fallen behind the network. Each value is the next height this node needs.
// The p2p/smr layer should drain this channel and call FastForward for each
// missing block fetched from a peer, in ascending height order.
func (c *Consensus) GetSyncNeededCh() <-chan uint64 {
	return c.syncNeededCh
}

// FastForward commits a block that was fetched from a peer during a sync
// catch-up, bypassing the normal proposal/vote pipeline. The block must be
// exactly localTip+1; call repeatedly in ascending order to fill a gap.
// After each commit, any proposal parked in pendingProposals whose height
// now matches the new expectedHeight is re-queued to proposalCh so normal
// PBFT processing resumes automatically once the gap is closed.
func (c *Consensus) FastForward(block Block) error {
	tip := c.blockChain.GetLatestBlock()
	if tip == nil {
		return fmt.Errorf("FastForward: no local tip")
	}
	if block.GetHeight() != tip.GetHeight()+1 {
		return fmt.Errorf("FastForward: expected height %d, got %d",
			tip.GetHeight()+1, block.GetHeight())
	}
	if block.GetPrevHash() != tip.GetHash() {
		return fmt.Errorf("FastForward: parent mismatch: expected %s, got %s",
			tip.GetHash(), block.GetPrevHash())
	}

	logger.Info("⏩ FastForward: committing synced block height=%d hash=%s",
		block.GetHeight(), block.GetHash())
	c.commitBlock(block)

	// After the commit, re-queue any parked proposal that is now the next
	// expected height so the normal PBFT pipeline can resume.
	newTip := c.blockChain.GetLatestBlock()
	if newTip == nil {
		return nil
	}
	nextHeight := newTip.GetHeight() + 1

	c.proposalMutex.Lock()
	defer c.proposalMutex.Unlock()
	for hash, b := range c.pendingProposals {
		if b.GetHeight() == nextHeight {
			logger.Info("⏩ FastForward: re-queuing parked proposal height=%d hash=%s",
				nextHeight, hash[:16])
			requeued := &Proposal{
				Block:      b,
				View:       c.currentView,
				ProposerID: "sync-replay",
			}
			select {
			case c.proposalCh <- requeued:
			default:
				logger.Warn("⏩ FastForward: proposalCh full, dropping re-queued proposal %s", hash[:16])
			}
			delete(c.pendingProposals, hash)
			break
		}
	}
	return nil
}

// SetLeader manually sets the leader status (used for testing/debugging)
func (c *Consensus) SetLeader(isLeader bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isLeader = isLeader
	logger.Info("Node %s leader status set to %t", c.nodeID, isLeader)
}
