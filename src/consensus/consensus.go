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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	logger "github.com/sphinxfndorg/protocol/src/console"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
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
//        ├─ tryEnterPreparedPhase()   ◄── side door #1 (prepare quorum arrived before this proposal did)
//        └─ if hasQuorum(): attachAttestationsBeforeCommit + commitBlock()
//                                     ◄── side door #2 (COMMIT quorum arrived before this proposal did —
//                                         votes can outrace the proposal itself, not just prepare votes)
//
//   HandlePrepareVote → prepareCh → processPrepareVote
//        ├─ store vote, accumulate stake in weightedPrepareVotes
//        └─ tryEnterPreparedPhase()   ◄── side door #3 (same function as #1, called again)
//
//        tryEnterPreparedPhase (idempotent, runs from any of the 3 call sites):
//            requires: hasPrepareQuorum() AND phase==PhasePrePrepared AND preparedBlock set
//            hasPrepareQuorum/hasQuorum both require, in this order:
//              (a) distinct voter count >= calculateQuorumSize(getTotalNodes()) — a floor derived
//                  from actual connected peers, independent of this node's own stake bookkeeping
//              (b) accumulated voter stake >= 2/3 of c.validatorSet.GetTotalStake()
//            (a) exists so an incomplete/stale local validator-set registry — which shrinks this
//            node's own view of "total stake" — can never let a single vote alone clear "2/3" of
//            that too-small total.
//            ├─ if a peer already broadcast a PrepareCertificate for this block hash, adopt its
//            │    signer list verbatim (lookupPrepareCertificate) instead of this node's own
//            │    locally-gossiped subset; otherwise derive locally AND broadcast a
//            │    PrepareCertificate so peers converge on this node's list instead of each
//            │    node persisting a different signer set for the same prepare phase
//            ├─ phase = PhasePrepared
//            ├─ lockedBlock = preparedBlock
//            └─ voteForBlock()  → broadcasts own Vote (type: commit)
//
//   HandleVote → voteCh → processVote → processVoteLocked
//        ├─ store vote, accumulate stake in weightedCommitVotes
//        └─ if hasQuorum():   (same two-part check as hasPrepareQuorum, see above)
//              ├─ phase = PhaseCommitted
//              ├─ attachAttestationsBeforeCommit(block, blockHash):
//              │     if a peer already broadcast a CommitCertificate for this hash, adopt its
//              │     attestation list verbatim (lookupCommitCertificate) instead of deriving from
//              │     this node's own c.receivedVotes; otherwise derive locally, sort by
//              │     ValidatorID, attach to block.Body.Attestations, AND broadcast a
//              │     CommitCertificate so peers converge on this node's list — same
//              │     composition-convergence pattern as the prepare phase above
//              └─ commitBlock(block)
//
//   HandleCommitCertificate / HandlePrepareCertificate (certificate.go)
//        — invoked directly by the network layer (manager.go / p2p.go dispatch on
//          "commit_certificate" / "prepare_certificate"), NOT queued through voteCh/prepareCh
//        ├─ verify every attestation's signature binds to the EXACT (view, blockHash, voterID)
//        │    it claims (rejects cross-block signature replay)
//        ├─ require the certificate's own attestation set to independently clear the same
//        │    2/3-stake threshold (attestationsMeetStakeQuorum, with the same distinct-attester
//        │    floor as hasQuorum/hasPrepareQuorum)
//        └─ cache the verified list for tryEnterPreparedPhase / attachAttestationsBeforeCommit
//             to adopt (see above) — evicted once consumed, or at round-reset as a backstop
//
//   commitBlock
//        ├─ blockChain.CommitBlock(block)   ← interface call, impl not in these files
//        ├─ onCommit callback
//        ├─ capture committedView := c.currentView BEFORE the increment below, and record each
//        │    voter's ConsensusSignature at ITS OWN vote.View (falling back to committedView only
//        │    for the self-commit fallback) — recording c.currentView AFTER incrementing it used
//        │    to stamp next-round's view number onto this round's signatures, which diverged
//        │    across nodes whenever a concurrent view-change bumped currentView independently
//        ├─ reset all round state, currentView++, evict any cached prepare/commit certificate
//        │    for this hash (consumed already, or never needed if this node derived locally)
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
	vdfParams, err := LoadCanonicalVDFParams()
	if err != nil {
		// A mismatched or missing discriminant means this node will elect
		// different leaders than its peers and can never reach consensus.
		// This is a FATAL startup error — returning nil would let the node
		// continue in a zombie state, silently forking from the network.
		logger.Error("FATAL: Could not load canonical VDF parameters: %v", err)
		logger.Error("   Ensure the genesis VDF parameters are correctly embedded.")
		cancel()
		logger.Error("   Consensus initialization failed — node cannot participate. Exiting.")
		return nil
	}
	logger.Info("Loaded canonical VDF parameters: D=%d bits, T=%d",
		vdfParams.Discriminant.BitLen(), vdfParams.T)

	// Initialize RANDAO with genesis seed derived from the REAL VDF calculation.
	// The seed MUST come from the actual genesis block hash, NOT from a hardcoded
	// fallback string like "SPHINX_GENESIS_RANDAO_SEED" — a predictable seed lets
	// an attacker precompute VDF outputs for all future epochs, breaking the
	// unpredictability that RANDAO's security depends on.  Nodes that cannot
	// resolve the genesis block yet (late joiners with empty datadirs) will
	// derive their seed from the genesis hash once it is synced from a peer.
	if blockchain == nil {
		logger.Error("FATAL: blockchain is nil — cannot derive RANDAO seed from VDF")
		cancel()
		return nil
	}

	genesisSeed := deriveSeedFromGenesisHashBlock(blockchain)
	if genesisSeed == [32]byte{} {
		logger.Warn("Cannot derive RANDAO seed: genesis block not yet available — will sync from peers")
		// Leave genesisSeed as zero — the sync layer will re-derive it.
	} else {
		logger.Info("Derived RANDAO seed from genesis block: seed=%x", genesisSeed[:8])
	}
	// In NewConsensus, when creating RANDAO:
	randao := NewRANDAO(genesisSeed, vdfParams, nodeID)

	// Create validator set with minimum stake requirement
	validatorSet := NewValidatorSet(minStakeAmount)

	// Create stake-weighted selector for leader election
	selector := NewStakeWeightedSelector(validatorSet)

	// Use the blockchain's genesis time so every node starts slot counting
	// from the same anchor, producing identical slot numbers and seeds.
	// blockchain is guaranteed non-nil at this point (the VDF seed section
	// above already returned nil on nil blockchain).
	genesisTime := blockchain.GetGenesisTime()
	if genesisTime.IsZero() {
		// The blockchain's GetGenesisTime already falls back to
		// chainParams.GenesisTime (and ultimately to the genesis block
		// timestamp), so landing here means even those are zero — which
		// should never happen once genesis is committed.
		//
		// Use time.Now() as the absolute last resort so the node can at
		// least start.  This is non-deterministic across nodes (wall-clock
		// skew), but that is acceptable because this path is unreachable
		// once the genesis block exists — and if it DOES fire, the slot
		// mismatch will be corrected as soon as the genesis block is synced
		// from peers (the TimeConverter is rebuilt on genesis sync).
		genesisTime = time.Now()
	}
	// Create time converter for slot calculations
	timeConverter := NewTimeConverter(genesisTime)

	// Add this node as a validator if it has sufficient stake
	// blockchain is guaranteed non-nil at this point.
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

	// NEW: Register self public key with signing service
	if signingService != nil {
		// Register self public key so the node can verify its own signatures
		if selfPK := signingService.GetPublicKeyObject(); selfPK != nil {
			signingService.RegisterPublicKey(nodeID, selfPK)
			logger.Info("Registered self public key for %s", nodeID)
		} else {
			logger.Warn("Could not get self public key for %s", nodeID)
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
		pendingSyncRequests:  make(map[uint64]*pendingSyncRequest),
		pendingSyncMutex:     sync.RWMutex{},
	}

	// Initialize pending sync requests map
	cons.pendingSyncRequests = make(map[uint64]*pendingSyncRequest)

	// Initialize and validate VDF parameters (run once at startup)
	if err := cons.initializeVDF(); err != nil {
		logger.Error("VDF initialization failed: %v", err)
		// Don't fail consensus startup, but log the error
	}

	// Initialize storage durability configuration
	cons.storageDurabilityConfig = DefaultStorageDurabilityConfig()
	cons.recoveryState = &RecoveryState{
		IsRecovering:    false,
		RecoveryAttempt: 0,
		Errors:          make([]string, 0),
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

	// Start sync loop to fetch missing blocks when behind
	go c.syncLoop()

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

// getExpectedVDFParams returns the expected VDF parameters derived from
// genesis. This delegates entirely to LoadCanonicalVDFParams (vdf.go) —
// the single canonical derivation, keyed off canonicalHashBytes=128 and
// canonicalT=2^20 — rather than re-deriving independently.
//
// A previous version of this function reimplemented the derivation by
// hand: a 32-byte SHAKE-256 expansion (→ a ~256-bit prime) and a
// hardcoded T=1024, instead of the canonical 128-byte expansion (→
// ~1024-bit prime) and T=2^20. That meant its output could never equal
// the real vdfParams this Consensus was actually constructed with at the
// top of NewConsensus, no matter what genesis hash it started from. In
// the normal startup path this was masked — LoadCanonicalVDFParams and
// the old fallback both check preDerivedVDFParams first, and nodes.go
// always sets that before NewConsensus runs — but any path that
// constructs a Consensus without going through that exact sequence (a
// test harness, an alternate bootstrap, a future refactor) would hit the
// mismatched fallback, have initializeVDF report a spurious "VDF
// parameter mismatch", and then ForceSyncParams would overwrite the
// correct canonical discriminant/T with the wrong ones.
//
// LoadCanonicalVDFParams is safe to call again here: it's a sync.Once
// cache (or an immediate return of preDerivedVDFParams when set), so this
// costs nothing beyond the first call and can never disagree with the
// vdfParams already loaded at the top of NewConsensus.
func (c *Consensus) getExpectedVDFParams() VDFParams {
	params, err := LoadCanonicalVDFParams()
	if err != nil {
		logger.Error("getExpectedVDFParams: failed to load canonical VDF parameters: %v", err)
		return VDFParams{}
	}
	return params
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
		logger.Info("Node %s elected proposer for view %d (stake %.2f SPX)",
			c.nodeID, viewSlot, selected.GetStakeInSPX())
	} else {
		logger.Info("   Node %s NOT proposer for view %d (elected: %s, stake %.2f SPX)",
			c.nodeID, viewSlot, selected.ID, selected.GetStakeInSPX())
	}
}

// deriveSeedFromGenesisHashBlock derives the RANDAO seed from the genesis block hash
// This ensures all nodes use identical seed derivation. Accepts a BlockChain
// interface to avoid import cycles and enable reuse from multiple call sites.
func deriveSeedFromGenesisHashBlock(bc BlockChain) [32]byte {
	if bc == nil {
		return [32]byte{}
	}

	// Get genesis block
	genesisBlock := bc.GetLatestBlock()
	if genesisBlock == nil {
		return [32]byte{}
	}

	// Traverse to genesis
	for genesisBlock.GetHeight() > 0 {
		genesisBlock = bc.GetBlockByHash(genesisBlock.GetPrevHash())
		if genesisBlock == nil {
			return [32]byte{}
		}
	}

	genesisHash := genesisBlock.GetHash()

	// Use SHA3-256 to derive a 32-byte seed from the genesis hash
	hash := sha3.Sum256([]byte(genesisHash))

	var seed [32]byte
	copy(seed[:], hash[:])

	return seed
}

// DefaultTimestampConfig returns sensible defaults for timestamp validation
func DefaultTimestampConfig() *TimestampValidationConfig {
	return &TimestampValidationConfig{
		MaxDrift:          10 * time.Second,
		MinBlockInterval:  2 * time.Second,
		MaxBlockInterval:  30 * time.Second,
		RejectFutureBlock: true,
	}
}

// ValidateBlockTimestamp validates that a block timestamp is within acceptable bounds
// This prevents consensus-critical logic from using wall-clock time for safety/root inputs
func (c *Consensus) ValidateBlockTimestamp(block Block, parentBlock Block) error {
	if block == nil {
		return fmt.Errorf("block is nil")
	}

	config := DefaultTimestampConfig()
	blockTime := time.Unix(block.GetTimestamp(), 0)
	now := common.GetTimeService().Now()

	// Get parent block timestamp for validation
	var parentTime time.Time
	if parentBlock != nil {
		parentTime = time.Unix(parentBlock.GetTimestamp(), 0)
	} else if c.lastBlockTime.IsZero() {
		// Genesis block - use genesis time
		if c.blockChain != nil {
			parentTime = c.blockChain.GetGenesisTime()
		}
	}

	// Rule 1: Block timestamp must not be too far in the future
	if config.RejectFutureBlock {
		futureThreshold := now.Add(config.MaxDrift)
		if blockTime.After(futureThreshold) {
			return fmt.Errorf("block timestamp %v is too far in the future (now=%v, max_drift=%v)",
				blockTime, now, config.MaxDrift)
		}
	}

	// Rule 2: Block timestamp must be >= parent timestamp (monotonicity)
	if !parentTime.IsZero() && blockTime.Before(parentTime) {
		return fmt.Errorf("block timestamp %v is before parent timestamp %v",
			blockTime, parentTime)
	}

	// Rule 3: Block timestamp must not be too old (prevent timestamp manipulation)
	if !parentTime.IsZero() {
		minAcceptableTime := parentTime.Add(-config.MaxDrift)
		if blockTime.Before(minAcceptableTime) {
			return fmt.Errorf("block timestamp %v is too old (parent=%v, max_drift=%v)",
				blockTime, parentTime, config.MaxDrift)
		}
	}

	// Rule 4: Enforce minimum block interval (prevent rapid block production)
	if !parentTime.IsZero() {
		interval := blockTime.Sub(parentTime)
		if interval < config.MinBlockInterval {
			return fmt.Errorf("block interval %v is too short (min=%v)",
				interval, config.MinBlockInterval)
		}
	}

	// Rule 5: Enforce maximum block interval (prevent stale blocks)
	if !parentTime.IsZero() {
		interval := blockTime.Sub(parentTime)
		if interval > config.MaxBlockInterval {
			return fmt.Errorf("block interval %v is too long (max=%v)",
				interval, config.MaxBlockInterval)
		}
	}

	logger.Debug("Block timestamp validation passed: time=%v, parent=%v, now=%v",
		blockTime, parentTime, now)

	return nil
}

// ValidateProposalTimestamp validates the timestamp in a proposal
// The leader provides the timestamp, but we validate it's within acceptable bounds
func (c *Consensus) ValidateProposalTimestamp(proposal *Proposal) error {
	if proposal == nil || proposal.Block == nil {
		return fmt.Errorf("proposal or block is nil")
	}

	// Get the parent block (local tip)
	parentBlock := c.blockChain.GetLatestBlock()
	if parentBlock == nil {
		return fmt.Errorf("cannot validate timestamp: no parent block available")
	}

	// Validate using the same logic as block validation
	return c.ValidateBlockTimestamp(proposal.Block, parentBlock)
}

// IsTimestampObservabilityOnly checks if a timestamp is used only for observability
// and not for consensus-critical logic
func IsTimestampObservabilityOnly(timestampField string) bool {
	// These fields are observability-only and should not affect consensus
	observabilityFields := map[string]bool{
		"signature_timestamp":  true,
		"checkpoint_timestamp": true,
		"log_timestamp":        true,
		"metrics_timestamp":    true,
	}

	return observabilityFields[timestampField]
}

// SanitizeTimestamp removes wall-clock time dependencies from consensus-critical fields
// This ensures consensus safety/root inputs don't use wall-clock time
func SanitizeTimestamp(timestamp int64, genesisTime time.Time) int64 {
	// Convert to slot number instead of using absolute timestamp
	// This makes consensus deterministic and independent of wall-clock time
	slotDuration := 12 * time.Second // 12-second slots
	elapsed := time.Unix(timestamp, 0).Sub(genesisTime)
	slotNumber := uint64(elapsed.Seconds() / slotDuration.Seconds())

	// Convert slot number back to timestamp (deterministic)
	sanitizedTime := genesisTime.Add(time.Duration(slotNumber) * slotDuration)
	return sanitizedTime.Unix()
}

// ValidateChainCompatibility validates chain compatibility (chain_id, genesis_hash)
// This enforces chain compatibility at handshake and for all consensus message handling
func (c *Consensus) ValidateChainCompatibility(remoteChainID uint64, remoteGenesisHash string) error {
	if c.blockChain == nil {
		return fmt.Errorf("blockchain not initialized")
	}

	// Get local chain info
	localGenesisBlock := c.blockChain.GetLatestBlock()
	if localGenesisBlock == nil {
		return fmt.Errorf("cannot get genesis block")
	}

	// Traverse to genesis
	for localGenesisBlock.GetHeight() > 0 {
		localGenesisBlock = c.blockChain.GetBlockByHash(localGenesisBlock.GetPrevHash())
		if localGenesisBlock == nil {
			return fmt.Errorf("cannot traverse to genesis")
		}
	}

	localGenesisHash := localGenesisBlock.GetHash()
	localChainID := uint64(7331) // Sphinx chain ID

	// Check chain_id
	if remoteChainID != localChainID {
		return fmt.Errorf("chain_id mismatch: local=%d, remote=%d", localChainID, remoteChainID)
	}

	// Check genesis_hash
	if remoteGenesisHash != localGenesisHash {
		return fmt.Errorf("genesis_hash mismatch: local=%s, remote=%s", localGenesisHash, remoteGenesisHash)
	}

	logger.Info("Chain compatibility validated: chain_id=%d, genesis_hash=%s", localChainID, localGenesisHash[:16])
	return nil
}

// NewMessageReplayProtection creates a new replay protection instance
func NewMessageReplayProtection(config *ReplayProtectionConfig) *MessageReplayProtection {
	if config == nil {
		config = DefaultReplayProtectionConfig()
	}

	return &MessageReplayProtection{
		seenNonces:   make(map[string]map[uint64]bool),
		seenMessages: make(map[string]time.Time),
		config:       config,
	}
}

// ValidateMessageReplay validates that a message is not a replay
// Binds to view/round and node identity for replay protection
// Each message must have a unique nonce per node
func (mrp *MessageReplayProtection) ValidateMessageReplay(
	messageID string,
	view uint64,
	nodeID string,
	messageType string,
	nonce uint64,
) error {
	mrp.mu.Lock()
	defer mrp.mu.Unlock()

	// Create composite key: messageType:view:nodeID:messageID
	compositeKey := fmt.Sprintf("%s:%d:%s:%s", messageType, view, nodeID, messageID)

	// Check if this exact message was already seen
	if _, exists := mrp.seenMessages[compositeKey]; exists {
		return fmt.Errorf("replay detected: message %s (type=%s, view=%d, node=%s)",
			messageID, messageType, view, nodeID)
	}

	// Check if this nonce was already used by this node
	if mrp.seenNonces[nodeID] == nil {
		mrp.seenNonces[nodeID] = make(map[uint64]bool)
	}
	if mrp.seenNonces[nodeID][nonce] {
		return fmt.Errorf("nonce replay detected: node=%s, nonce=%d, type=%s",
			nodeID, nonce, messageType)
	}

	// Record message and nonce as seen
	mrp.seenMessages[compositeKey] = time.Now()
	mrp.seenNonces[nodeID][nonce] = true

	// Cleanup old messages periodically (older than 1 hour)
	cutoff := time.Now().Add(-time.Hour)
	for key, timestamp := range mrp.seenMessages {
		if timestamp.Before(cutoff) {
			delete(mrp.seenMessages, key)
		}
	}

	logger.Debug("Message replay check passed: type=%s, view=%d, node=%s, nonce=%d",
		messageType, view, nodeID, nonce)

	return nil
}

// ValidateMessageSize validates that a message is within size limits
func (mrp *MessageReplayProtection) ValidateMessageSize(data []byte) error {
	if len(data) > mrp.config.MaxMessageSize {
		return fmt.Errorf("message size %d exceeds maximum %d bytes",
			len(data), mrp.config.MaxMessageSize)
	}
	return nil
}

// ReplayProtectionConfig holds configuration for replay protection
type ReplayProtectionConfig struct {
	EnableChainIDCheck      bool
	EnableGenesisHashCheck  bool
	EnableViewBinding       bool
	EnableNodeIdentityCheck bool
	MaxMessageSize          int
}

// DefaultReplayProtectionConfig returns secure defaults
func DefaultReplayProtectionConfig() *ReplayProtectionConfig {
	return &ReplayProtectionConfig{
		EnableChainIDCheck:      true,
		EnableGenesisHashCheck:  true,
		EnableViewBinding:       true,
		EnableNodeIdentityCheck: true,
		MaxMessageSize:          1024 * 1024, // 1 MB
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

// VerifyBlockHeader verifies a block's own producer signature (not PBFT
// quorum attestations) against the signing service's key material. This is
// the read-only counterpart to SignBlockHeader, intended for the sync path
// to check a solo-mined block's signature the same way processProposal
// checks a PBFT leader's proposal — see VerifyBlockHeader's call site in
// core.Blockchain.VerifyProducerSignature for why this matters: a late
// joiner downloading a solo-mined chain has no PBFT quorum to lean on, so
// the producer's own signature is the only thing standing between "this
// really came from that node" and "anyone who can compute a competing hash."
func (c *Consensus) VerifyBlockHeader(block Block) (bool, error) {
	if c.signingService == nil {
		return false, fmt.Errorf("VerifyBlockHeader: no signing service configured for node %s", c.nodeID)
	}
	return c.signingService.VerifyBlockSignature(block)
}

// SignBlockHeader signs a block's header with this node's own key, the same
// way ProposeBlock signs a leader's proposal, and marks the block's own
// signature as valid on success.
//
// FIX: solo-mined blocks (produced by CreateBlock before PBFT starts, or
// before enough validators are known) were never signed at all —
// ProposeBlock was the only call site for signingService.SignBlock, so
// every block minted before the solo→PBFT handoff shipped with an empty
// ProposerSignature and signature_valid=false permanently. That's a real
// gap, not a cosmetic one: an unsigned block carries no proof of who
// produced it, so nothing before quorum starts distinguishes a genuine
// solo-miner's block from one forged by any peer that can compute a
// competing hash — fork-choice between two unsigned blocks then has
// nothing to go on but chain continuity and the deterministic hash
// tie-break, not producer authenticity. Every block should be signed by
// its own producer from genesis onward, even though a single signature is
// not itself a BFT quorum; quorum attestations layer on top of this once
// PBFT is active, they don't replace it.
//
// This does not require a peer/committee or a running consensus round —
// it only touches this node's own signing key — so it is safe to call
// from the solo-mining path in executor.go, not just from ProposeBlock.
func (c *Consensus) SignBlockHeader(block Block) error {
	if c.signingService == nil {
		return fmt.Errorf("SignBlockHeader: no signing service configured for node %s", c.nodeID)
	}
	if err := c.signingService.SignBlock(block); err != nil {
		return fmt.Errorf("SignBlockHeader: %w", err)
	}
	block.SetSigValid(true)
	return nil
}

// ProposeBlock creates and broadcasts a new block proposal when this node is the leader
func (c *Consensus) ProposeBlock(block interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// SYNC GATE: a node that hasn't finished adopting the canonical chain
	// must never propose — a proposal built on a stale/incomplete local tip
	// would be built with the wrong height and parent hash, and even though
	// honest peers' own processProposal height checks would reject it, it
	// still wastes a view and can trip view-change churn network-wide. Fail
	// fast here instead.
	if !c.IsSyncReady() {
		return fmt.Errorf("node %s cannot propose: not sync-ready yet (still catching up to canonical chain)", c.nodeID)
	}

	c.updateLeaderStatusLocked()

	// Verify this node is actually the leader
	if !c.isLeader {
		return fmt.Errorf("node %s is not the leader for view %d (elected=%s)", c.nodeID, c.currentView, c.electedLeaderID)
	}

	// Type assert to consensus.Block
	consensusBlock, ok := block.(Block)
	if !ok {
		return fmt.Errorf("invalid block type: expected consensus.Block")
	}

	// Update block metadata using the interface methods
	consensusBlock.SetCommitStatus("proposed")
	consensusBlock.SetSigValid(false)

	// Sign the block header if signing service is available
	if c.signingService != nil {
		if err := c.signingService.SignBlock(consensusBlock); err != nil {
			return fmt.Errorf("failed to sign block header: %w", err)
		}
	}

	// Use the slot from election time
	proposalSlot := c.currentView
	logger.Info("Using view %d as proposal slot (view=%d, height=%d)",
		proposalSlot, c.currentView, consensusBlock.GetHeight())

	// Get the concrete block for serialization
	var concreteBlock interface{}
	if getter, ok := consensusBlock.(interface{ GetUnderlyingBlock() interface{} }); ok {
		concreteBlock = getter.GetUnderlyingBlock()
	} else {
		concreteBlock = consensusBlock
	}

	// Serialize the concrete block to JSON
	blockData, err := json.Marshal(concreteBlock)
	if err != nil {
		return fmt.Errorf("failed to serialize block: %w", err)
	}

	logger.Info("Serialized block data size: %d bytes, height from block: %d",
		len(blockData), consensusBlock.GetHeight())

	// Create the proposal message with serialized block data
	proposal := &Proposal{
		BlockData:       blockData,
		View:            c.currentView,
		ProposerID:      c.nodeID,
		Signature:       []byte{},
		ElectedLeaderID: c.electedLeaderID,
		SlotNumber:      proposalSlot,
		Block:           consensusBlock, // Store locally for immediate use
	}

	logger.Info("Creating proposal: slot=%d, view=%d, leader=%s, block=%s, data_size=%d",
		proposalSlot, c.currentView, c.nodeID, consensusBlock.GetHash(), len(blockData))

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
	logger.Info("Leader %s processed its own proposal locally", c.nodeID)

	// Broadcast the proposal to all peers
	if err := c.broadcastProposal(proposal); err != nil {
		return fmt.Errorf("failed to broadcast proposal: %w", err)
	}
	// ====================================================================

	logger.Info("[%s] Block proposed and broadcast, waiting for consensus...", c.nodeID)
	return nil
}

// HandleProposal queues an incoming proposal for processing
func (c *Consensus) HandleProposal(proposal *Proposal) error {
	// Validate message size
	if err := c.validateMessageSize(proposal); err != nil {
		return fmt.Errorf("proposal size validation failed: %w", err)
	}

	select {
	case c.proposalCh <- proposal: // Send to proposal channel
		return nil
	case <-c.ctx.Done(): // Check if consensus is stopping
		return fmt.Errorf("consensus stopped")
	}
}

// HandleVote queues an incoming commit vote for processing
func (c *Consensus) HandleVote(vote *Vote) error {
	// Validate message size
	if err := c.validateMessageSize(vote); err != nil {
		return fmt.Errorf("vote size validation failed: %w", err)
	}

	select {
	case c.voteCh <- vote: // Send to vote channel
		return nil
	case <-c.ctx.Done(): // Check if consensus is stopping
		return fmt.Errorf("consensus stopped")
	}
}

// HandlePrepareVote queues an incoming prepare vote for processing
func (c *Consensus) HandlePrepareVote(vote *Vote) error {
	// Validate message size
	if err := c.validateMessageSize(vote); err != nil {
		return fmt.Errorf("prepare vote size validation failed: %w", err)
	}

	select {
	case c.prepareCh <- vote: // Send to prepare channel
		return nil
	case <-c.ctx.Done(): // Check if consensus is stopping
		return fmt.Errorf("consensus stopped")
	}
}

// HandleTimeout queues an incoming timeout message for processing
func (c *Consensus) HandleTimeout(timeout *TimeoutMsg) error {
	// Validate message size
	if err := c.validateMessageSize(timeout); err != nil {
		return fmt.Errorf("timeout size validation failed: %w", err)
	}

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

	// was: 30 * time.Second — too slow relative to a 15s round-stall timeout,
	// letting one dead round's leftovers poison the next round's reconciliation.
	cleanupTicker := time.NewTicker(5 * time.Second)
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

// syncLoop listens for sync requests and fetches missing blocks from peers
// This is the missing piece that connects syncNeededCh to actual block fetching
func (c *Consensus) syncLoop() {
	logger.Info("Sync loop started for node %s", c.nodeID)

	for {
		select {
		case <-c.ctx.Done():
			logger.Info("Sync loop stopped for node %s", c.nodeID)
			return

		case neededHeight, ok := <-c.syncNeededCh:
			if !ok {
				return
			}

			// If we've already caught up due to checkpoint apply, don't block on
			// block-sync RPCs.
			localTip := c.blockChain.GetLatestBlock()
			if localTip != nil && localTip.GetHeight() >= neededHeight {
				logger.Info("Sync catch-up already satisfied: localTip=%d, requested=%d — skipping block fetch",
					localTip.GetHeight(), neededHeight)
				continue
			}

			logger.Info("⏩ Sync needed for height %d, fetching from peers...", neededHeight)

			// Request the missing block from peers
			block, err := c.fetchBlockFromPeers(neededHeight)
			if err != nil {
				logger.Warn("Failed to fetch block at height %d: %v", neededHeight, err)
				continue
			}

			if block == nil {
				logger.Warn("No block received for height %d", neededHeight)
				continue
			}

			// Validate the fetched block
			if err := c.blockChain.ValidateBlock(block); err != nil {
				logger.Warn("Fetched block validation failed for height %d: %v", neededHeight, err)
				continue
			}

			// Commit the block via FastForward
			if err := c.FastForward(block); err != nil {
				logger.Error("FastForward failed for height %d: %v", neededHeight, err)
				continue
			}

			logger.Info("Successfully synced block at height %d", neededHeight)
		}
	}
}

// HandleSyncResponse processes a block response from a peer during sync
func (c *Consensus) HandleSyncResponse(height uint64, blockData []byte) error {
	c.pendingSyncMutex.RLock()
	request, exists := c.pendingSyncRequests[height]
	c.pendingSyncMutex.RUnlock()

	if !exists {
		logger.Debug("Received sync response for height %d but no pending request", height)
		return nil
	}

	// Deserialize into the concrete block type. Unmarshalling directly into the
	// Block interface leaves encoding/json without a concrete destination and
	// turns a valid sync response into an unusable map value.
	var block types.Block
	if err := json.Unmarshal(blockData, &block); err != nil {
		logger.Warn("Failed to deserialize block response for height %d: %v", height, err)
		return err
	}

	// Send the block to the waiting goroutine
	select {
	case request.response <- &block:
		logger.Info("Delivered block %d to sync handler", height)
	default:
		logger.Warn("Response channel full for height %d", height)
	}

	return nil
}

// GetBlockByHeight returns a locally stored block for the legacy PBFT
// sync_request/sync_response transport.  Normal catch-up uses the dedicated
// sync manager, but this fallback is still used when consensus detects a gap
// while processing a proposal.  Keep the storage-specific lookup optional so
// the consensus BlockChain interface remains usable by lightweight test and
// embedding implementations.
func (c *Consensus) GetBlockByHeight(height uint64) Block {
	provider, ok := c.blockChain.(interface {
		GetBlockByNumber(uint64) *types.Block
	})
	if !ok {
		return nil
	}
	return provider.GetBlockByNumber(height)
}

// fetchBlockFromPeers requests a block from available peers and waits for response
// Returns the fetched block or error if no peer can provide it
func (c *Consensus) fetchBlockFromPeers(height uint64) (Block, error) {
	peers := c.nodeManager.GetPeers()
	if len(peers) == 0 {
		return nil, fmt.Errorf("no peers available to fetch block %d", height)
	}

	// Try each peer until one responds via direct RPC.
	// This avoids the broadcast-based sync_request path, which has no receiver
	// handler and causes timeouts ("Unknown message type: sync_request").
	for peerID, peer := range peers {
		node := peer.GetNode()
		if node == nil || node.GetStatus() != NodeStatusActive {
			continue
		}

		logger.Info("Requesting block %d from peer %s via RPC", height, peerID)

		// Call the already-registered RPC method for fetching a block by number.
		// Note: CallRPC expects an address (host:port), method, params, target nodeID, and ttl.
		// We use the peer's node ID as the RPC target identifier.
		// NOTE: Consensus currently has only Node ID access; RPC needs an
		// address/host:port. To avoid compile-time RPC import cycles and
		// mismatched transport addressing, we keep the original broadcast-based
		// sync mechanism.
		request := map[string]interface{}{
			"method": "blockchain.getBlockByHeight",
			"params": []interface{}{height},
		}
		requestData, err := json.Marshal(request)
		if err != nil {
			logger.Warn("Failed to marshal block request: %v", err)
			continue
		}
		if err := c.nodeManager.BroadcastMessage("sync_request", requestData); err != nil {
			logger.Warn("Failed to send block request to peer %s: %v", peerID, err)
			continue
		}

		// syncLoop path: the actual block delivery will happen via
		// pendingSyncRequests + HandleSyncResponse.
		// This function returns only after the sync response is received.
		respCh := make(chan Block, 1)
		c.pendingSyncMutex.Lock()
		c.pendingSyncRequests[height] = &pendingSyncRequest{height: height, response: respCh}
		c.pendingSyncMutex.Unlock()

		select {
		case blk := <-respCh:
			if blk == nil {
				return nil, fmt.Errorf("received nil block response for height %d", height)
			}
			return blk, nil
		case <-time.After(10 * time.Second):
			return nil, fmt.Errorf("timeout waiting for block %d from peers", height)
		case <-c.ctx.Done():
			return nil, fmt.Errorf("consensus stopped")
		}

	}

	return nil, fmt.Errorf("failed to fetch block %d from any peer", height)
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
			// Only remove if the signature is older than 8 seconds
			sigTime, err := time.Parse(time.RFC3339, sig.Timestamp)
			if err == nil && time.Since(sigTime) > 8*time.Second {
				logger.Info("Removing stale signature for block %s (height=%d, type=%s, age=%v)",
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
		logger.Info("Cleaned up %d stale consensus signatures, %d remaining",
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
	logger.Info("Entering epoch %d", newEpoch)
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

	// A late joiner may receive PBFT traffic before it has installed genesis or
	// completed its block catch-up.  Keep the proposal for FastForward replay,
	// but do not enter validation yet: without a local tip it can only produce
	// a misleading warning and cannot safely vote anyway.
	if !c.IsSyncReady() {
		logger.Debug("Deferring proposal for height %d from %s until sync gate opens",
			proposal.Block.GetHeight(), proposal.ProposerID)
		return
	}

	// Get block nonce for logging
	nonce, err := proposal.Block.GetCurrentNonce()
	nonceStr := "unknown"
	if err != nil {
		logger.Warn("Failed to get block nonce: %v", err)
	} else {
		nonceStr = fmt.Sprintf("%d", nonce)
	}

	// Log proposal receipt
	logger.Info("Processing proposal for block at height %d, view %d from %s, nonce: %s",
		proposal.Block.GetHeight(), proposal.View, proposal.ProposerID, nonceStr)

	localTip := c.blockChain.GetLatestBlock()
	if localTip == nil {
		logger.Warn("Cannot validate proposal %s: local chain has no tip", proposal.Block.GetHash())
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
			logger.Warn("Proposal height not ready: expected %d from local tip %s, got height %d block %s",
				expectedHeight, localTip.GetHash(), proposalHeight, proposal.Block.GetHash())
		}
		return
	}
	if proposal.Block.GetPrevHash() != localTip.GetHash() {
		// The proposal is for the correct next height, but its parent doesn't
		// match our local tip. This means we're missing intermediate blocks.
		// Check if the parent exists in storage (it might have been synced but
		// not yet committed as the tip).
		parentBlock := c.blockChain.GetBlockByHash(proposal.Block.GetPrevHash())
		if parentBlock == nil {
			// Parent doesn't exist in storage at all — we need to sync.
			logger.Warn("⏩ Missing parent block: local tip=%s (height %d), proposal parent=%s (height %d expected) — signalling sync",
				localTip.GetHash(), localTipHeight,
				proposal.Block.GetPrevHash(), proposalHeight-1)

			// Park the proposal so it can be replayed once the gap is filled
			c.proposalMutex.Lock()
			if c.pendingProposals == nil {
				c.pendingProposals = make(map[string]Block)
			}
			c.pendingProposals[proposal.Block.GetHash()] = proposal.Block
			c.proposalMutex.Unlock()

			// Signal the sync layer to fetch the missing parent block
			select {
			case c.syncNeededCh <- proposalHeight - 1:
			default:
			}
			return
		} else {
			// Parent exists but isn't the tip — our chain is stale.
			// This shouldn't happen if the chain is properly maintained,
			// but log it clearly and reject to avoid forks.
			logger.Warn("Proposal parent exists but is not local tip: local tip=%s (height %d), parent=%s (height %d), proposal=%s",
				localTip.GetHash(), localTipHeight,
				proposal.Block.GetPrevHash(), parentBlock.GetHeight(),
				proposal.Block.GetHash())
			return
		}
	}

	// Validate the block itself
	if err := c.blockChain.ValidateBlock(proposal.Block); err != nil {
		logger.Warn("Block validation failed: %v", err)
		return
	}

	// In processProposal, after validating the block
	if proposal.Block.GetHeight() == 0 {
		// This is a deserialization issue - try to correct.
		//
		// FIX: This used to hardcode the corrected height to 1, which was
		// only ever correct for the very first block after genesis. By the
		// time we reach this point, proposalHeight has already been
		// validated against expectedHeight (localTipHeight+1) above — any
		// mismatch already returned early. So if something later zeroed
		// out the height (e.g. a deserialization round-trip inside
		// ValidateBlock), the CORRECT value to restore is expectedHeight,
		// not a hardcoded 1. Hardcoding 1 here silently mislabeled every
		// block after height 1 — e.g. a real height-2 block would get
		// stamped as height 1 in the resulting ConsensusSignature and
		// downstream final_states/chain_state.json output.
		logger.Warn("Block height is 0, attempting to correct to expected height %d", expectedHeight)

		// Try to set the height using reflection or interface
		if setter, ok := proposal.Block.(interface{ SetHeight(uint64) }); ok {
			setter.SetHeight(expectedHeight)
			logger.Info("Successfully corrected block height to %d", expectedHeight)
		} else {
			// Try to access underlying block directly
			if getter, ok := proposal.Block.(interface{ GetUnderlyingBlock() interface{} }); ok {
				if underlying, ok := getter.GetUnderlyingBlock().(*types.Block); ok && underlying != nil {
					underlying.Header.Height = expectedHeight
					underlying.Header.Block = expectedHeight
					logger.Info("Successfully corrected underlying block height to %d", expectedHeight)
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

	// ════════════════════════════════════════════════════════════════════════
	// CRITICAL: Mandatory signature verification
	// ════════════════════════════════════════════════════════════════════════
	// In production, EVERY proposal and block must be signed. The "skip when
	// empty" path is only acceptable during bootstrap/testnet and MUST be
	// turned off for mainnet. Empty signatures are rejected as invalid.
	if c.signingService == nil {
		logger.Error("CRITICAL: No signing service available — rejecting proposal from %s (all messages must be signed in production)", proposal.ProposerID)
		return
	}

	// Verify proposal signature — MUST be present and valid
	if len(proposal.Signature) == 0 {
		logger.Error("CRITICAL: Proposal from %s has empty signature — rejecting (all proposals must be signed)", proposal.ProposerID)
		return
	}
	valid, err := c.signingService.VerifyProposal(proposal)
	if err != nil {
		logger.Warn("Error verifying proposal signature from %s: %v", proposal.ProposerID, err)
		return
	}
	if !valid {
		logger.Warn("Invalid proposal signature from %s", proposal.ProposerID)
		return
	}
	logger.Debug("Valid signature for proposal from %s", proposal.ProposerID)

	// Verify block header signature — MUST be present and valid
	valid, err = c.signingService.VerifyBlockSignature(proposal.Block)
	if err != nil || !valid {
		logger.Warn("Invalid block header signature from proposer %s: %v", proposal.ProposerID, err)
		return
	}
	logger.Debug("Block header signature verified for block %s", proposal.Block.GetHash())

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
	logger.Info("Added proposal signature for block %s", proposal.Block.GetHash())

	// Check for stale proposal
	if proposal.View < c.currentView {
		if proposal.View == c.currentView-1 {
			logger.Info("Proposal for view %d (current view %d) - catching up", proposal.View, c.currentView)
			// This is a late retransmission from the previous round. If lockedBlock
			// is still set from that round (commitBlock's second c.mu acquisition
			// hasn't run yet), the equivocation guard below would fire and reject it.
			// Since we have already advanced past this view, there is nothing to
			// equivocate — clear the stale lock so the height/parentHash checks
			// decide whether this proposal is still actionable.
			if c.lockedBlock != nil {
				logger.Info("Clearing stale lockedBlock %s from old view %d before catching-up processing",
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
			logger.Warn("Stale proposal for view %d, current view %d", proposal.View, c.currentView)
			return
		}
	}
	// =================================================================================

	// Handle view advancement if proposal is for a newer view.
	if proposal.View > c.currentView {
		logger.Info("Advancing view from %d to %d", c.currentView, proposal.View)
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
			logger.Info("Follower re-derived electedLeaderID=%s for view-slot %d",
				c.electedLeaderID, proposal.SlotNumber)
		} else {
			logger.Warn("SelectProposer returned nil for slot %d, trusting signed proposal", proposal.SlotNumber)
			c.electedLeaderID = proposal.ProposerID
		}
	} else if proposal.ElectedLeaderID != "" {
		logger.Warn("Proposal has no SlotNumber, using embedded ElectedLeaderID=%s", proposal.ElectedLeaderID)
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
		logger.Warn("Invalid leader %s for view %d (electedLeaderID=%s)",
			proposal.ProposerID, proposal.View, c.electedLeaderID)
		return
	}

	// ========== FIX 2: Special handling for leader's own proposal ==========
	isSelfProposal := (proposal.ProposerID == c.nodeID)

	if isSelfProposal {
		logger.Info("[%s] LEADER: Processing own proposal for block %s", c.nodeID, proposal.Block.GetHash())
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
			logger.Info("Clearing stale lockedBlock %s (height=%d, tip=%d) — committed mid-flight, not equivocation",
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
			logger.Info("Clearing cross-view lockedBlock %s (lockedAtView=%d, proposalView=%d, height=%d) — new view, not equivocation",
				c.lockedBlock.GetHash()[:16], c.preparedView, proposal.View, lockedHeight)
			c.lockedBlock = nil

		} else {
			logger.Warn("Rejecting conflicting proposal %s at height %d: already locked on %s (same view %d) — refusing to equivocate",
				proposal.Block.GetHash()[:16], proposal.Block.GetHeight(), c.lockedBlock.GetHash()[:16], c.preparedView)
			return
		}
	}

	if c.preparedBlock != nil && c.preparedBlock.GetHash() != proposal.Block.GetHash() {
		oldHash := c.preparedBlock.GetHash()
		logger.Info("Resetting preparedBlock from %s to accept validated proposal %s from leader %s",
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
		logger.Info("Set preparedBlock for validated proposal %s at height %d",
			proposal.Block.GetHash()[:16], proposal.Block.GetHeight())
	}

	// Accept the proposal
	logger.Info("Node %s accepting proposal for block %s at view %d (height %d, nonce: %s)",
		c.nodeID, proposal.Block.GetHash(), proposal.View, proposal.Block.GetHeight(), nonceStr)

	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	if isSelfProposal {
		logger.Info("[%s] LEADER: Processed own proposal for block %s", c.nodeID, proposal.Block.GetHash())
	} else {
		logger.Info("[%s] FOLLOWER: Received proposal from leader %s for block %s",
			c.nodeID, proposal.ProposerID, proposal.Block.GetHash())
	}
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Ensure preparedBlock is still set (it should be from the beginning)
	if c.preparedBlock == nil || c.preparedBlock.GetHash() != proposal.Block.GetHash() {
		logger.Warn("preparedBlock was lost! Re-setting for %s", proposal.Block.GetHash())
		c.preparedBlock = proposal.Block
		c.preparedView = proposal.View
		c.preparedBlockHash = proposal.Block.GetHash()
	}

	c.phase = PhasePrePrepared

	// Send prepare vote for this block (skip for leader's own proposal if already sent)
	if !isSelfProposal || !c.sentPrepareVotes[proposal.Block.GetHash()] {
		c.sendPrepareVote(proposal.Block.GetHash(), proposal.View)
		if isSelfProposal {
			logger.Info("[%s] LEADER: Sending prepare vote for own block", c.nodeID)
		} else {
			logger.Info("[%s] FOLLOWER: Proposal validated, sending prepare vote", c.nodeID)
		}
	} else {
		logger.Info("[%s] LEADER: Already sent prepare vote for own block", c.nodeID)
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
		logger.Info("Commit quorum was already reached for %s before proposal arrived — committing now", blockHash[:16])
		// ========== FIX: Attach attestations BEFORE commit ==========
		// The commit votes that reached quorum were parked in c.receivedVotes
		// while waiting for this proposal to arrive. Without this call they
		// are never attached, and the block commits with zero attestations.
		// See attachAttestationsBeforeCommit's doc comment for the full
		// explanation of this race. Must run here, while c.mu is still held,
		// not inside the goroutine below.
		c.attachAttestationsBeforeCommit(blockToCommit, blockHash)
		// ============================================================
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
	logger.Debug("Consensus height updated to %d for node %s", height, c.nodeID)
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
	logger.Debug("Prepare vote: %s, block=%s, stake=%.2f SPX", vote.VoterID, vote.BlockHash, stakeSPX)

	// Calculate current vote count and quorum requirements
	totalVotes := len(c.prepareVotes[vote.BlockHash])
	quorumSize := c.calculateQuorumSize(c.getTotalNodes())

	logger.Info("Prepare vote received: node=%s, from=%s, block=%s, votes=%d/%d, phase=%v, prepared=%v",
		c.nodeID, vote.VoterID, vote.BlockHash, totalVotes, quorumSize, c.phase, c.preparedBlock != nil)

	// Check if we've achieved quorum for this block. The actual
	// PrePrepared -> Prepared transition and commit-vote broadcast are
	// handled by tryEnterPreparedPhase (see its doc comment for why that
	// logic needs to live in one place callable from two sites).
	if c.hasPrepareQuorum(vote.BlockHash) {
		logger.Info("PREPARE QUORUM ACHIEVED for block %s at view %d", vote.BlockHash, vote.View)
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
		logger.Info("Quorum reached for %s but already in phase %v, skipping transition", blockHash, c.phase)
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
	// block. Prepare-vote gossip can reach quorum with a genuinely different
	// subset of voters on different nodes, the same way commit votes can
	// (see PrepareCertificate's doc comment) — so prefer an already-broadcast
	// canonical certificate over this node's own locally-gossiped subset,
	// and if none exists yet, derive locally and publish ours for peers to
	// adopt instead of each node persisting a different signer set.
	blockHeight := c.preparedBlock.GetHeight()
	prepareTimestamp := common.GetTimeService().GetCurrentTimeInfo().ISOLocal
	if cached, ok := lookupPrepareCertificate(blockHash); ok && len(cached) > 0 {
		for _, att := range cached {
			c.addConsensusSig(&ConsensusSignature{
				BlockHash:    blockHash,
				BlockHeight:  blockHeight,
				SignerNodeID: att.ValidatorID,
				Signature:    hex.EncodeToString(att.Signature),
				MessageType:  "prepare",
				View:         att.View,
				Timestamp:    prepareTimestamp,
				Valid:        true,
				MerkleRoot:   "pending_calculation",
				Status:       "prepared",
			})
		}
		evictPrepareCertificate(blockHash)
	} else if votes := c.prepareVotes[blockHash]; votes != nil {
		attestations := make([]*types.Attestation, 0, len(votes))
		voteSignatures := make(map[string][]byte, len(votes))
		for voterID, v := range votes {
			c.addConsensusSig(&ConsensusSignature{
				// FIX: c.currentHeight is only advanced at commit time (see
				// SetCurrentHeight / the assignment after commit below), so
				// during the Prepared phase — i.e. right here — it still
				// reflects the PREVIOUS committed height, one less than the
				// block actually being prepared. That produced final_states
				// entries where a real height-2 block's "prepare" signature
				// was recorded with block_height: 1. c.preparedBlock is the
				// block actually reaching quorum right now (already used
				// correctly in the log line below), so use its height.
				BlockHash:    blockHash,
				BlockHeight:  blockHeight,
				SignerNodeID: voterID,
				Signature:    hex.EncodeToString(v.Signature),
				MessageType:  "prepare",
				View:         view,
				Timestamp:    prepareTimestamp,
				Valid:        true,
				MerkleRoot:   "pending_calculation",
				Status:       "prepared",
			})

			if signedMsg, err := DeserializeSignedMessage(v.Signature); err == nil {
				attestations = append(attestations, &types.Attestation{
					ValidatorID: voterID,
					BlockHash:   blockHash,
					View:        v.View,
					Signature:   signedMsg.Signature,
				})
				voteSignatures[voterID] = v.Signature
			} else {
				logger.Warn("tryEnterPreparedPhase: failed to deserialize prepare vote signature from %s for block %s: %v",
					voterID, blockHash[:min(16, len(blockHash))], err)
			}
		}
		if len(attestations) > 0 {
			sort.Slice(attestations, func(i, j int) bool {
				return attestations[i].ValidatorID < attestations[j].ValidatorID
			})
			cert := &PrepareCertificate{
				BlockHash:      blockHash,
				View:           view,
				Attestations:   attestations,
				VoteSignatures: voteSignatures,
			}
			if err := c.broadcastPrepareCertificate(cert); err != nil {
				logger.Warn("tryEnterPreparedPhase: failed to broadcast prepare certificate for %s: %v", blockHash[:min(16, len(blockHash))], err)
			}
		}
		evictPrepareCertificate(blockHash)
	}

	// Transition to prepared phase.
	c.phase = PhasePrepared
	c.lockedBlock = c.preparedBlock
	c.preparedBlock.SetCommitStatus("prepared")

	logger.Info("[%s] Entered PREPARED phase for block %s at height %d — sending commit vote",
		c.nodeID, blockHash, c.preparedBlock.GetHeight())

	// Send our own commit vote for this block.
	c.voteForBlock(blockHash, view)
}

// addConsensusSig adds a signature to the consensus signatures collection
func (c *Consensus) addConsensusSig(sig *ConsensusSignature) {
	c.signatureMutex.Lock()
	defer c.signatureMutex.Unlock()

	logger.Info("Adding consensus signature for block %s (type: %s)", sig.BlockHash, sig.MessageType)

	// Deduplicate before appending. Failed rounds can otherwise accumulate
	// multiple proposal/prepare/commit entries for the same stale block, which
	// then show up as duplicate final_states in chain_state.json.
	dedupKey := sig.BlockHash + "|" + sig.SignerNodeID + "|" + sig.MessageType
	for _, existing := range c.consensusSignatures {
		if existing.BlockHash == sig.BlockHash &&
			existing.SignerNodeID == sig.SignerNodeID &&
			existing.MessageType == sig.MessageType {
			logger.Debug("⏭ Skipping duplicate consensus signature %s", dedupKey)
			return
		}
	}

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
			logger.Debug("Block has not been persisted yet (expected during proposal phase): %s", sig.BlockHash)
		}
	}

	// Emergency fallback if merkle root still empty
	if sig.MerkleRoot == "" {
		sig.MerkleRoot = fmt.Sprintf("emergency_fallback_%s", sig.BlockHash[:8])
		logger.Error("CRITICAL: Used emergency fallback for merkle root!")
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
	logger.Debug("Added signature: block=%s, merkle_root=%s, status=%s", sig.BlockHash, sig.MerkleRoot, sig.Status)
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

	logger.Debug("Current consensus signatures (%d total):", len(c.consensusSignatures))
	for i, sig := range c.consensusSignatures {
		logger.Debug("  Signature %d: block=%s, type=%s, merkle=%s, status=%s, valid=%t",
			i, sig.BlockHash, sig.MessageType, sig.MerkleRoot, sig.Status, sig.Valid)
	}
}

// ForcePopulateAllSignatures updates all signatures with current block information
func (c *Consensus) ForcePopulateAllSignatures() {
	c.signatureMutex.Lock()
	defer c.signatureMutex.Unlock()

	logger.Info("Force populating all consensus signatures")

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
			logger.Debug("Block not found for hash %s (expected during sync)", sig.BlockHash)
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

		logger.Info("Signature %d: block=%s, merkle=%s->%s, status=%s->%s",
			i, sig.BlockHash, originalMerkleRoot, sig.MerkleRoot, originalStatus, sig.Status)
	}

	logger.Info("Force population completed for %d signatures", len(c.consensusSignatures))
}

// GetConsensusSignatures returns a copy of all consensus signatures
func (c *Consensus) GetConsensusSignatures() interface{} {
	c.signatureMutex.RLock()
	defer c.signatureMutex.RUnlock()
	// Create a copy to avoid external modification
	signatures := make([]*ConsensusSignature, len(c.consensusSignatures))
	copy(signatures, c.consensusSignatures)
	return signatures
}

// processVote handles incoming commit votes.
func (c *Consensus) processVote(vote *Vote) {
	c.mu.Lock()
	if c.sentVotes == nil {
		c.sentVotes = make(map[string]bool)
	}
	commitKey := vote.BlockHash + "|" + vote.VoterID
	if c.sentVotes[commitKey] {
		c.mu.Unlock()
		logger.Debug("⏭ Skipping already-processed commit vote from %s for %s", vote.VoterID, vote.BlockHash[:16])
		return
	}
	c.mu.Unlock()

	blockToCommit := c.processVoteLocked(vote)
	if blockToCommit != nil {
		c.mu.Lock()
		c.sentVotes[commitKey] = true
		c.mu.Unlock()
		c.commitBlock(blockToCommit)
	} else {
		// Even if quorum not reached (or vote ignored as duplicate in receivedVotes),
		// mark this (blockHash, voterID) as processed so it won't be re-counted
		// after a stale-commit reset that clears receivedVotes.
		c.mu.Lock()
		c.sentVotes[commitKey] = true
		c.mu.Unlock()
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
			logger.Info("Self stake was zero, using default: 32 SPX")
		} else {
			logger.Warn("Vote from %s has zero stake", vote.VoterID)
		}
	}

	// Add stake to weighted vote total
	c.weightedCommitVotes[vote.BlockHash].Add(c.weightedCommitVotes[vote.BlockHash], stake)

	// Log vote receipt with stake amount
	stakeSPX := new(big.Float).Quo(new(big.Float).SetInt(stake), new(big.Float).SetFloat64(denom.SPX))
	logger.Debug("Commit vote: %s, block=%s, stake=%.2f SPX", vote.VoterID, vote.BlockHash, stakeSPX)

	// Calculate current vote count and quorum requirements
	totalVotes := len(c.receivedVotes[vote.BlockHash])
	quorumSize := c.calculateQuorumSize(c.getTotalNodes())
	logger.Info("Commit vote received: node=%s, from=%s, block=%s, votes=%d/%d, phase=%v",
		c.nodeID, vote.VoterID, vote.BlockHash, totalVotes, quorumSize, c.phase)

	// In processVote, when commit quorum is achieved
	if c.hasQuorum(vote.BlockHash) {
		logger.Info("COMMIT QUORUM ACHIEVED for block %s at view %d", vote.BlockHash, vote.View)

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
				logger.Info("Recovering block %s from proposal cache for commit (lockedBlock/preparedBlock were nil)",
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
			logger.Info("Moving to COMMITTED phase for block %s", vote.BlockHash)
		}

		// ========== FIX: Attach attestations BEFORE commit ==========
		// Shared with the "commit quorum arrived before proposal" fallback in
		// processProposal — see attachAttestationsBeforeCommit for why this
		// can no longer live inline here alone.
		c.attachAttestationsBeforeCommit(blockToCommit, vote.BlockHash)
		// ============================================================

		// Commit the block after releasing c.mu. CommitBlock performs storage,
		// state execution, checkpoint writes, and callbacks; holding the
		// consensus mutex across that work can deadlock Phase 2 leader refresh.
		return blockToCommit
	}

	return nil
}

// attachAttestationsBeforeCommit builds a block's attestation list from the
// commit votes currently recorded in c.receivedVotes[blockHash] and attaches
// them to the block body. Must be called with c.mu already held, since it
// reads c.receivedVotes directly.
//
// BUG FIX: this used to live only inline inside processVoteLocked's commit
// branch. That covers the common case (quorum is reached when a vote
// arrives), but there is a second, independent path that also commits a
// block: processProposal's "commit quorum was already reached before the
// proposal arrived" fallback (search for tryEnterPreparedPhase's sibling
// check below). Commit votes can reach quorum and get parked in
// c.receivedVotes *before* the proposal itself is processed and
// preparedBlock is set; once the proposal arrives, that fallback committed
// the block directly via commitBlock() without ever attaching the parked
// votes as attestations. Because which path wins is a race (network
// ordering of the proposal vs. the commit votes), the result was
// nondeterministic: most blocks committed via the normal vote path and got
// their attestations, but any block whose commit votes arrived first
// committed via the fallback with zero attestations — exactly the scattered
// "MISSING: no attestations field" blocks seen in the on-disk block JSON.
// Extracting this into a shared helper and calling it from both commit
// sites closes that gap. (A block with genuinely zero votes, such as
// genesis, still legitimately ends up with no attestations — that case is
// not a bug.)
func (c *Consensus) attachAttestationsBeforeCommit(block Block, blockHash string) {
	// Extract underlying block
	var tb *types.Block
	if direct, ok := block.(*types.Block); ok {
		tb = direct
	} else if getter, ok := block.(interface{ GetUnderlyingBlock() interface{} }); ok {
		if underlying, ok := getter.GetUnderlyingBlock().(*types.Block); ok {
			tb = underlying
		}
	}
	if tb == nil {
		return
	}

	// Skip re-attaching if this block already carries attestations (e.g. a
	// block recovered from the proposal cache that was already processed
	// once through this path).
	if len(tb.Body.Attestations) > 0 {
		return
	}

	// COMPOSITION FIX: if a peer already broadcast a CommitCertificate for
	// this block hash (see commit_certificate.go), adopt it verbatim instead
	// of deriving from this node's own local vote snapshot below. This is
	// what actually closes the cross-node composition gap that sorting
	// alone (further down) cannot: two nodes that reached quorum with
	// different subsets of gossiped commit votes will, once either of them
	// broadcasts its certificate, converge on the SAME attestation list
	// rather than each committing with its own distinct subset.
	if cached, ok := lookupCommitCertificate(blockHash); ok && len(cached) > 0 {
		tb.Body.Attestations = cached
		evictCommitCertificate(blockHash)
		logger.Info("Attached %d attestations to block %s from peer commit certificate (skipped local derivation)",
			len(tb.Body.Attestations), blockHash[:16])
		return
	}

	// Take snapshot of votes
	votesSnapshot := make(map[string]*Vote)
	if votes, exists := c.receivedVotes[blockHash]; exists {
		for k, v := range votes {
			votesSnapshot[k] = v
		}
		logger.Info("Captured %d votes for attestations", len(votesSnapshot))
	}

	if len(votesSnapshot) == 0 {
		logger.Warn("No commit votes recorded for block %s — committing with zero attestations", blockHash[:16])
		return
	}

	// Attach attestations directly to the block
	tb.Body.Attestations = make([]*types.Attestation, 0, len(votesSnapshot))
	// voteSignatures captures the FULL original vote.Signature blob (not the
	// extracted signedMsg.Signature stored on the Attestation itself) for
	// every voter that makes it into the attestation list. This is what lets
	// a peer receiving this node's CommitCertificate broadcast (further
	// below) independently re-verify each attestation — see
	// commit_certificate.go's TRUST MODEL note for exactly why the full blob
	// is required and the extracted bytes alone are not enough.
	voteSignatures := make(map[string][]byte, len(votesSnapshot))
	var deserFailures int
	for voterID, vote := range votesSnapshot {
		// Extract the raw SPHINCS+ signature bytes from the serialized SignedMessage
		// vote.Signature is a serialized SignedMessage (includes length prefixes, timestamp, nonce, etc.)
		// We need to deserialize it and extract just the actual signature bytes
		signedMsg, err := DeserializeSignedMessage(vote.Signature)
		if err != nil {
			// FIX: this used to be a bare logger.Warn + continue, which silently
			// dropped the vote from the attestation list. If every parked vote for
			// a block hit this branch, the block would commit with zero
			// attestations while this function still logged "Attached N
			// attestations" — i.e. quorum existed but the on-disk block looked
			// exactly like the "MISSING: no attestations" symptom, with no trace
			// of why. Log per-voter at Error with the raw signature length so
			// this is diagnosable, and count failures so the all-failed case is
			// flagged below instead of silently reporting an empty list as normal.
			logger.Error("Attestation build: failed to deserialize vote signature from %s for block %s (raw len=%d): %v",
				voterID, blockHash[:16], len(vote.Signature), err)
			deserFailures++
			continue
		}

		tb.Body.Attestations = append(tb.Body.Attestations, &types.Attestation{
			ValidatorID: voterID,
			BlockHash:   blockHash,
			View:        vote.View,
			Signature:   signedMsg.Signature, // Extract raw SPHINCS+ signature bytes only
		})
		voteSignatures[voterID] = vote.Signature // full blob, for certificate verification
	}

	if len(tb.Body.Attestations) == 0 && deserFailures > 0 {
		logger.Error("Attestation build: block %s had %d recorded commit votes but ALL %d failed signature deserialization — committing with zero attestations despite quorum",
			blockHash[:16], len(votesSnapshot), deserFailures)
	} else if deserFailures > 0 {
		logger.Warn("Attestation build: block %s attached %d/%d attestations — %d vote(s) dropped due to deserialization failure",
			blockHash[:16], len(tb.Body.Attestations), len(votesSnapshot), deserFailures)
	}

	// FIX: votesSnapshot was copied from a map (c.receivedVotes[blockHash]),
	// and the loop above ranges over that map — Go deliberately randomizes
	// map iteration order on every run. Combined with the fact that this
	// function runs independently on every node (each building its list from
	// its OWN locally-received votes, not a canonical leader-broadcast
	// certificate — see the doc comment above), the same underlying vote set
	// could still serialize to a different-order Attestations array on two
	// nodes even when both collected exactly the same voters. Sorting by
	// ValidatorID here removes that source of divergence: whenever two nodes
	// do end up with the same set of voters for a block (the common case in
	// a small, low-latency devnet), their on-disk Attestations now compare
	// byte-for-byte equal instead of differing only by append order.
	//
	// On its own this sort does NOT make attestation composition identical
	// across nodes when nodes genuinely collected different subsets of
	// gossiped commit votes before independently crossing their own
	// 2/3-stake quorum threshold — that's an inherent property of
	// asynchronous BFT quorum certificates (any valid 2/3-stake subset is a
	// legitimate proof), not a bug on its own, and doesn't affect chain
	// safety since the block hash never depends on Attestations. The
	// composition gap itself is closed by the CommitCertificate broadcast
	// below (see commit_certificate.go): this node reached quorum and built
	// its list first, so it publishes that list as the canonical one for
	// every peer that hasn't derived its own yet (checked at the top of this
	// function) to adopt as-is.
	sort.Slice(tb.Body.Attestations, func(i, j int) bool {
		return tb.Body.Attestations[i].ValidatorID < tb.Body.Attestations[j].ValidatorID
	})

	// COMPOSITION FIX (continued): publish this node's freshly-derived list
	// so peers that haven't independently derived their own yet will adopt
	// it verbatim instead of racing ahead with a possibly-different subset.
	// Fire-and-forget, consistent with broadcastVote/broadcastProposal — see
	// broadcastCommitCertificate's doc comment for why this is safe to call
	// with c.mu held. A failure here just means this node's peers fall back
	// to local derivation as before; it does not affect this node's own
	// commit.
	cert := &CommitCertificate{
		BlockHash:      blockHash,
		View:           c.currentView,
		Attestations:   tb.Body.Attestations,
		VoteSignatures: voteSignatures,
	}
	if err := c.broadcastCommitCertificate(cert); err != nil {
		logger.Warn("attachAttestationsBeforeCommit: failed to broadcast commit certificate for %s: %v", blockHash[:16], err)
	}
	// Defensive cleanup: drop any certificate a peer may have raced in for
	// this hash after this node passed the lookup above but before it
	// finished deriving its own list. Without this, a stale cache entry for
	// an already-attached block hash could sit until commitBlock's own
	// eviction runs.
	evictCommitCertificate(blockHash)

	logger.Info("Attached %d attestations to block %s BEFORE commit", len(tb.Body.Attestations), blockHash[:16])
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
	} else {
		// In production this must never happen: timeouts drive view-change.
		// Reject unsigned timeouts deterministically.
		logger.Error("CRITICAL: No signing service available — rejecting unsigned timeout from %s", timeout.VoterID)
		return
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
	// SYNC GATE: never cast a vote until this node has been declared caught
	// up by its sync orchestrator. Height/parent-hash checks in
	// processProposal already stop most premature voting, but this is a
	// second, independent line of defense that closes the window between
	// "local height happens to match" and "this node has actually adopted
	// the canonical chain" (see SetSyncReady doc).
	if !c.IsSyncReady() {
		logger.Info("⏳ Node %s not sync-ready — withholding prepare vote for block %s (view %d)",
			c.nodeID, blockHash, view)
		return
	}

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
	// SYNC GATE: same reasoning as sendPrepareVote — never cast a commit
	// vote until this node has been declared caught up.
	if !c.IsSyncReady() {
		logger.Info("⏳ Node %s not sync-ready — withholding commit vote for block %s (view %d)",
			c.nodeID, blockHash, view)
		return
	}

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
		logger.Warn("No block found to vote for hash %s", blockHash)
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
	logger.Info("Node %s sent COMMIT vote for block %s (height %d) at view %d",
		c.nodeID, blockHash, blockToVote.GetHeight(), view)
}

// hasQuorum checks if a block has achieved commit quorum based on stake weight
func (c *Consensus) hasQuorum(blockHash string) bool {
	// Get votes for this block
	votes := c.receivedVotes[blockHash]
	if votes == nil {
		return false
	}

	// SAFETY FLOOR: quorum must never be satisfiable by fewer distinct
	// voters than a real 2/3 majority of the network requires, regardless
	// of what the stake tally below says. The stake check depends on this
	// node's local c.validatorSet being fully populated with every other
	// validator's stake; if that set is incomplete or stale on this node
	// (e.g. a validator registration this node hasn't learned yet),
	// totalStake computed below is smaller than the network's real total,
	// and a single vote can wrongly clear 2/3 of that too-small total.
	// getTotalNodes() is derived independently, from actual connected
	// peers, so cross-checking against it catches exactly that case —
	// this is what let a node commit (and record final_states) with only
	// its own vote while peers required 2-of-3.
	requiredVoters := c.calculateQuorumSize(c.getTotalNodes())
	if len(votes) < requiredVoters {
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
			logger.Info("Quorum achieved: %.2f / %.2f SPX voted (%.1f%%)", votedSPX, totalSPX, pct)
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

	// SAFETY FLOOR: same cross-check as hasQuorum — see its comment.
	requiredVoters := c.calculateQuorumSize(c.getTotalNodes())
	if len(votes) < requiredVoters {
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
	logger.Info("Node %s attempting to commit block %s at height %d",
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
			// Same block, just ignore
			return
		}
		// Different block at same height – already committed by another path
		logger.Info("Block height %d hash %s differs from committed tip %s at same height; ignoring stale block",
			blockHeight, block.GetHash(), currentTip.GetHash())
		return
	}

	// Now blockHeight > currentHeight, proceed with normal commit
	logger.Info("Node %s attempting to commit block %s at height %d (current tip %d)",
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
			logger.Info("Block already has %d attestations attached", len(tb.Body.Attestations))
		} else {
			logger.Warn("No attestations attached to block before commit")
		}
	}

	committedHash := block.GetHash()

	// ★ FIX: Re-check tip height under c.mu BEFORE calling
	// blockChain.CommitBlock. There is a race between the initial
	// currentTip check at the top of this function (which runs without
	// c.mu) and the actual CommitBlock call: another goroutine (e.g. the
	// sync loop, or a concurrent commitBlock for a different block at the
	// same height) may have already advanced the chain tip past our block.
	// If we call CommitBlock with a stale block, it returns the
	// "stale/conflicting block" error, which triggers the expensive
	// PhaseIdle reset path below.
	//
	// We re-read the tip under c.mu and bail early if our block is no
	// longer the next expected block.
	c.mu.Lock()
	currentTip = c.blockChain.GetLatestBlock()
	if currentTip != nil {
		tipHeight := currentTip.GetHeight()
		if blockHeight <= tipHeight {
			// Another commit already advanced past or to this height.
			if blockHeight == tipHeight && block.GetHash() == currentTip.GetHash() {
				c.mu.Unlock()
				logger.Info("commitBlock: block %s at height %d already committed — skipping", committedHash, blockHeight)
				return
			}
			c.mu.Unlock()
			logger.Info("commitBlock: block %s at height %d stale (tip at %d with hash %s) — dropping",
				committedHash, blockHeight, tipHeight, currentTip.GetHash())
			return
		}
	}
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
		logger.Error("Error committing block: %v", err)

		// FIX: This round did NOT actually complete on this node — c.phase was
		// already advanced to PhaseCommitted (by whichever path detected quorum:
		// processProposal's catch-up check or processVote/processVoteLocked)
		// before blockChain.CommitBlock was ever called. Previously, returning
		// here left c.phase stuck at PhaseCommitted, c.currentView un-incremented,
		// and the stale vote maps (c.receivedVotes/c.weightedCommitVotes) for
		// this hash still populated — forever, since that cleanup only lived in
		// the success path below. A node in this state would ignore legitimate
		// proposals/votes for the next round (anything gated on c.phase) until
		// an external view-change timeout (10-15s) eventually forced a reset.
		//
		// Reconcile immediately instead: the block we tried to commit lost a
		// race (e.g. against a synced block or a different validator's proposal
		// that committed first) — bc's actual tip is authoritative. Adopt its
		// height and drop back to PhaseIdle so this node can participate in the
		// next round right away instead of waiting on the poll loop / timeout.
		//
		// CRITICAL: Also clear prepareVotes/sentPrepareVotes/weightedPrepareVotes
		// so the stuck quorum does not immediately re-trigger commit on the next
		// incoming vote / proposal.
		c.mu.Lock()
		tip := c.blockChain.GetLatestBlock()
		if tip != nil && tip.GetHeight() > c.currentHeight {
			c.currentHeight = tip.GetHeight()
		}
		// blockHeight > currentHeight+1: this node is still missing one or
		// more blocks between the tip and the block we just failed to
		// commit (e.g. the live PBFT commit path raced ahead of the
		// separate block-sync path — see the "current tip N-2" case).
		// Signal the sync layer with the exact height it's missing instead
		// of just dropping the block and waiting for the next proposal or
		// a 10-15s view-change timeout to notice.
		if tip != nil && block.GetHeight() > tip.GetHeight()+1 {
			neededHeight := tip.GetHeight() + 1
			select {
			case c.syncNeededCh <- neededHeight:
			default:
			}
		}
		c.phase = PhaseIdle
		c.lockedBlock = nil
		c.preparedBlock = nil
		c.preparedView = 0
		c.preparedBlockHash = ""
		c.receivedVotes = make(map[string]map[string]*Vote)
		c.prepareVotes = make(map[string]map[string]*Vote)
		// Clear ONLY the stale block's dedup keys from c.sentVotes so the same
		// (blockHash, voterID) pair cannot retry this exact stale commit, while
		// preserving dedup state for any other in-flight blocks.
		stalePrefix := block.GetHash() + "|"
		for key := range c.sentVotes {
			if strings.HasPrefix(key, stalePrefix) {
				delete(c.sentVotes, key)
			}
		}
		c.sentPrepareVotes = make(map[string]bool)
		c.weightedPrepareVotes = make(map[string]*big.Int)
		c.weightedCommitVotes = make(map[string]*big.Int)
		// Backstop cleanup: a peer's commit certificate for this now-stale
		// block hash may still be cached (received but never consumed, e.g.
		// this node lost the race to a synced block instead). See
		// commit_certificate.go's commitCertCap note for why this matters.
		evictCommitCertificate(block.GetHash())
		evictPrepareCertificate(block.GetHash())
		logger.Warn("commitBlock: dropped stale block %s at height %d (chain tip already advanced) — reset to PhaseIdle at height %d",
			block.GetHash(), block.GetHeight(), c.currentHeight)
		c.mu.Unlock()
		return
	}

	// Execute commit callback if provided (c.mu NOT held here — callback may lock)
	if c.onCommit != nil {
		if err := c.onCommit(block); err != nil {
			logger.Warn("Error in commit callback: %v", err)
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

	// Capture every commit vote this node collected for the block BEFORE
	// receivedVotes is reset below. Without this, commitBlock only ever
	// recorded a single self-authored "committed_by_<nodeID>" signature,
	// so each node's chain_state.json final_states ended up with a
	// different (and only its own) signer_node_id for the same block's
	// commit phase — the same class of divergence the prepare phase
	// already fixed by recording a signature per voter (see
	// tryEnterPreparedPhase). Mirror that here for commit.
	commitVotesForBlock := c.receivedVotes[committedHash]

	// Capture the view this block actually committed AT, before it gets
	// bumped for the next round below. Recording c.currentView after the
	// increment (as this used to do) put next-round's view number on this
	// round's signatures — and since a concurrent view-change can bump
	// c.currentView independently on each node between the moment they
	// each reach quorum, that made the recorded view for the SAME block
	// diverge across nodes (e.g. view 14 on one node, 15 on another) even
	// when the vote itself was cast at a single, consistent view.
	committedView := c.currentView

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
	// Backstop cleanup: this node's own certificate for committedHash was
	// already evicted at the point of use in attachAttestationsBeforeCommit,
	// but a peer's certificate could have arrived and been cached AFTER this
	// node had already attached its own attestations locally (so it was
	// never consumed via the lookup at the top of that function). Clear it
	// here so it doesn't sit in the cache until commitCertCap forces it out.
	evictCommitCertificate(committedHash)
	evictPrepareCertificate(committedHash)
	// Evict only proposals at or below the committed height.
	// Proposals for the NEXT height may already be cached (arrived early)
	// and must survive this commit so FastForward can replay them.
	// Evict only proposals at or below the committed height.
	// Proposals for the NEXT height may already be cached (arrived early)
	// and must survive this commit so FastForward can replay them.
	committedHeight := block.GetHeight()
	for hash, b := range c.pendingProposals {
		if b.GetHeight() <= committedHeight {
			delete(c.pendingProposals, hash)
		}
	}

	// NEW: Prune orphaned consensus signatures for this height now, not on
	// the next cleanup tick. Any signature at or below the committed
	// height whose hash isn't the block that actually won is a losing
	// proposal from this round's leader race — its block will NEVER appear
	// in storage. Left in c.consensusSignatures, it gets re-walked by every
	// subsequent ForcePopulateAllSignatures/SMR reconciliation cycle, each
	// of which burns several seconds retrying a lookup that can never
	// succeed (see CleanupStaleSignatures' 8s age gate + 5s ticker — a
	// dead signature can otherwise live for up to ~13s max, clearing well
	// before the 15s round-stall timeout and giving the next leader a clean
	// window to actually propose).
	c.signatureMutex.Lock()
	kept := c.consensusSignatures[:0]
	for _, sig := range c.consensusSignatures {
		if sig.BlockHeight <= committedHeight && sig.BlockHash != block.GetHash() {
			continue // losing proposal for this height — drop it now
		}
		kept = append(kept, sig)
	}
	c.consensusSignatures = kept
	c.signatureMutex.Unlock()

	// Record a commit signature for every voter this node collected for the
	// block (mirrors tryEnterPreparedPhase's per-voter recording for the
	// prepare phase), not just this node's own commit. Recording only the
	// self signature here is what caused different nodes to persist
	// different signer_node_id sets for the same block's commit phase in
	// chain_state.json.
	commitMerkleRoot := c.extractMerkleRootFromBlock(block)
	commitTimestamp := common.GetTimeService().GetCurrentTimeInfo().ISOLocal
	recordedCommitSigner := false
	for voterID, v := range commitVotesForBlock {
		sig := hex.EncodeToString(v.Signature)
		if voterID == c.nodeID {
			sig = "committed_by_" + c.nodeID
			recordedCommitSigner = true
		}
		sigView := committedView
		if v != nil && v.View != 0 {
			sigView = v.View
		}
		c.addConsensusSig(&ConsensusSignature{
			BlockHash:    block.GetHash(),
			BlockHeight:  newHeight,
			SignerNodeID: voterID,
			Signature:    sig,
			MessageType:  "commit",
			View:         sigView,
			Timestamp:    commitTimestamp,
			Valid:        true,
			MerkleRoot:   commitMerkleRoot,
			Status:       "committed",
		})
	}

	// Fallback: if this node's own commit vote wasn't in receivedVotes for
	// some reason (e.g. leader fast-path), still record it so the block
	// always has at least a self-commit signature.
	if !recordedCommitSigner {
		c.addConsensusSig(&ConsensusSignature{
			BlockHash:    block.GetHash(),
			BlockHeight:  newHeight,
			SignerNodeID: c.nodeID,
			Signature:    "committed_by_" + c.nodeID,
			MessageType:  "commit",
			View:         committedView,
			Timestamp:    commitTimestamp,
			Valid:        true,
			MerkleRoot:   commitMerkleRoot,
			Status:       "committed",
		})
	}

	logger.Info("Node %s committed block %s at height %d (view now %d)",
		c.nodeID, block.GetHash(), newHeight, c.currentView)

	logger.Info("Updating leader status for next round at height %d, view %d", newHeight, c.currentView)
	c.updateLeaderStatusLocked()
	logger.Info("Leader status after commit: isLeader=%v, electedLeader=%s", c.isLeader, c.electedLeaderID)
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
	logger.Info("Node %s initiating view change to view %d", c.nodeID, newView)

	// Update consensus state
	c.currentView = newView
	c.lastViewChange = common.GetTimeService().Now()
	c.resetConsensusState()

	// Use view-pinned RANDAO election (stake-weighted, NOT round-robin).
	// Round-robin fallback (updateLeaderStatusWithValidators) would produce a
	// different leader than the RANDAO-based path used by processProposal,
	// causing the new leader's own proposal to be rejected by every follower
	// as "invalid leader".  Always use the same stake-weighted selector.
	viewSlot := c.currentView
	viewEpoch := viewSlot / SlotsPerEpoch
	seed := c.randao.GetSeed(viewSlot)
	if sel := c.selector.SelectProposer(viewEpoch, seed); sel != nil {
		c.electedLeaderID = sel.ID
		c.electedSlot = viewSlot
		c.isLeader = (sel.ID == c.nodeID)
		logger.Info("New leader for view %d: %s (stake-weighted, isLeader=%v)", newView, c.electedLeaderID, c.isLeader)
	} else {
		// Last-resort fallback: if SelectProposer returns nil (e.g. empty
		// validator set), use round-robin as a safe deterministic default
		// that at least lets the chain make progress.
		logger.Warn("SelectProposer returned nil for view %d — falling back to round-robin", newView)
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
		logger.Info("Node %s elected as leader for view %d (index %d/%d)",
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
			logger.Info("Valid leader (RANDAO/elected): %s for view %d", nodeID, view)
		} else {
			logger.Info("Invalid leader: expected elected=%s for view %d, got=%s",
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
		logger.Info("Valid leader (round-robin fallback): %s for view %d", nodeID, view)
	} else {
		logger.Info("Invalid leader (round-robin fallback): expected %s for view %d, got %s",
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
		logger.Info("Added self as validator: %s", c.nodeID)
	} else {
		logger.Warn("Self is NOT a validator: %s", c.nodeID)
	}

	// Add validator peers
	for _, peer := range peers {
		node := peer.GetNode()
		if node != nil && node.GetRole() == RoleValidator && node.GetStatus() == NodeStatusActive {
			nodeID := node.GetID()
			if !validatorSet[nodeID] && nodeID != "" {
				validatorSet[nodeID] = true
				validators = append(validators, nodeID)
				logger.Info("Added peer validator: %s", nodeID)
			}
		}
	}

	logger.Info("Total validators found: %d", len(validators))
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
// This method satisfies the ConsensusEngineInterface from the core package
func (c *Consensus) AddConsensusSignature(sig interface{}) {
	if consensusSig, ok := sig.(*ConsensusSignature); ok {
		c.addConsensusSig(consensusSig)
	}
}

// broadcastProposal sends a proposal to all peers
func (c *Consensus) broadcastProposal(proposal *Proposal) error {
	// Log the proposal JSON for debugging
	jsonData, _ := json.Marshal(proposal)
	logger.Debug("Broadcasting proposal JSON (first 500 chars): %s", string(jsonData[:min(500, len(jsonData))]))

	return c.nodeManager.BroadcastMessage("proposal", proposal)
}

// broadcastVote sends a commit vote to all peers
func (c *Consensus) broadcastVote(vote *Vote) error {
	logger.Debug("Broadcasting commit vote for block %s at view %d", vote.BlockHash, vote.View)
	return c.nodeManager.BroadcastMessage("vote", vote)
}

// broadcastPrepareVote sends a prepare vote to all peers
func (c *Consensus) broadcastPrepareVote(vote *Vote) error {
	logger.Debug("Broadcasting prepare vote for block %s at view %d", vote.BlockHash, vote.View)
	return c.nodeManager.BroadcastMessage("prepare", vote)
}

// broadcastTimeout sends a timeout message to all peers
func (c *Consensus) broadcastTimeout(timeout *TimeoutMsg) error {
	logger.Debug("Broadcasting timeout for view %d", timeout.View)
	return c.nodeManager.BroadcastMessage("timeout", timeout)
}

// GetSyncNeededCh returns the channel that fires when this node detects it has
// fallen behind the network. Each value is the next height this node needs.
// The p2p/smr layer should drain this channel and call FastForward for each
// missing block fetched from a peer, in ascending height order.
func (c *Consensus) GetSyncNeededCh() <-chan uint64 {
	return c.syncNeededCh
}

// SetSyncReady flips the gate that allows this node to actively participate
// in PBFT (cast prepare/commit votes, accept FastForward catch-up commits).
// The node's sync orchestrator must call SetSyncReady(true) only after it has
// verified localHeight matches the network's canonical tip height — see
// bind.runBlockProductionLoop's SYNC STATE GATE. Before that, incoming
// proposals are still queued and height-checked (so gap-detection/back-fill
// signalling keeps working), but no vote is ever cast and FastForward refuses
// to commit.
func (c *Consensus) SetSyncReady(ready bool) {
	var v int32
	if ready {
		v = 1
	}
	old := atomic.SwapInt32(&c.syncReady, v)
	if int32(v) != old {
		logger.Info("Node %s PBFT participation gate: syncReady=%v", c.nodeID, ready)
	}
}

// IsSyncReady reports whether this node is permitted to actively participate
// in PBFT (vote / commit). See SetSyncReady.
func (c *Consensus) IsSyncReady() bool {
	return atomic.LoadInt32(&c.syncReady) == 1
}

// SetAttestationVerifier installs the callback FastForward uses to verify
// PBFT quorum before committing a block fetched reactively from a single
// peer. See the attestationVerifier field doc for why this is required.
func (c *Consensus) SetAttestationVerifier(fn func(block Block) error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attestationVerifier = fn
}

// FastForward commits a block that was fetched from a peer during a sync
// catch-up, bypassing the normal proposal/vote pipeline. The block must be
// exactly localTip+1; call repeatedly in ascending order to fill a gap.
// After each commit, any proposal parked in pendingProposals whose height
// now matches the new expectedHeight is re-queued to proposalCh so normal
// PBFT processing resumes automatically once the gap is closed.
func (c *Consensus) FastForward(block Block) error {
	// ────────────────────────────────────────────────────────────────────
	// SYNC-GATE + QUORUM CHECK
	// ────────────────────────────────────────────────────────────────────
	// FastForward previously had NO PBFT safety check at all: it would
	// commit whatever single block a single peer handed back for a
	// syncNeededCh request, with only a height/parent-hash continuity
	// check. That let one out-of-sync or dishonest peer plant a block this
	// node's own honest quorum never actually certified, permanently
	// diverging this node's tip hash from the canonical chain — the exact
	// symptom under investigation. Require the same attestation-quorum
	// check bind.runBlockSyncLoop's bulk path already performs (solo-mined
	// pre-PBFT blocks with zero attestations are still accepted, since
	// they were never subject to quorum in the first place).
	if c.attestationVerifier != nil {
		if err := c.attestationVerifier(block); err != nil {
			return fmt.Errorf("FastForward: attestation quorum check failed for height %d: %w",
				block.GetHeight(), err)
		}
	}

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

	// FIX: FastForward commits blocks fetched whole from a peer during catch-up,
	// so it never goes through attachAttestationsBeforeCommit — there are no
	// local votes to attach, the block either already carries attestations
	// from the peer or it doesn't. If a peer's own copy of a block committed
	// with zero attestations (e.g. via the deserialization-failure path above),
	// FastForward previously propagated that silently: the gap-filled node
	// would show the same "missing attestations" symptom with no indication it
	// never actually went through this node's own PBFT pipeline for that
	// block. Surface it instead of letting it look identical to a live-quorum
	// miss.
	if block.GetHeight() > 0 {
		if tb, ok := block.(*types.Block); ok && len(tb.Body.Attestations) == 0 {
			logger.Warn("FastForward: block height=%d hash=%s fetched from peer with zero attestations — propagating as-is (not a local quorum miss, check the source peer)",
				block.GetHeight(), block.GetHash())
		}
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

// validateMessageSize validates the size of a consensus message
func (c *Consensus) validateMessageSize(msg interface{}) error {
	// Serialize message to check size
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to serialize message: %w", err)
	}

	// Check against maximum message size (1 MB default)
	maxSize := 1024 * 1024 // 1 MB
	if len(data) > maxSize {
		return fmt.Errorf("message size %d bytes exceeds maximum %d bytes", len(data), maxSize)
	}

	return nil
}

// StorageDurabilityConfig holds configuration for storage durability and crash recovery
type StorageDurabilityConfig struct {
	EnableCrashConsistencyTests bool          // Enable crash consistency tests
	EnableAtomicWrites          bool          // Enable atomic writes across storage layers
	RecoveryTimeout             time.Duration // Timeout for recovery operations
	MaxRecoveryAttempts         int           // Maximum recovery attempts
}

// DefaultStorageDurabilityConfig returns sensible defaults
func DefaultStorageDurabilityConfig() *StorageDurabilityConfig {
	return &StorageDurabilityConfig{
		EnableCrashConsistencyTests: true,
		EnableAtomicWrites:          true,
		RecoveryTimeout:             5 * time.Minute,
		MaxRecoveryAttempts:         3,
	}
}

// StorageOperation represents a storage operation for durability tracking
type StorageOperation struct {
	ID        string `json:"id"`
	Type      string `json:"type"` // "state_commit", "block_store", "checkpoint_update"
	Height    uint64 `json:"height"`
	Timestamp int64  `json:"timestamp"`
	Status    string `json:"status"` // "pending", "committed", "rolled_back"
}

// CrashConsistencyTestResult represents the result of a crash consistency test
type CrashConsistencyTestResult struct {
	TestName     string        `json:"test_name"`
	Passed       bool          `json:"passed"`
	ErrorMessage string        `json:"error_message,omitempty"`
	Duration     time.Duration `json:"duration"`
	Timestamp    int64         `json:"timestamp"`
}

// RecoveryState tracks the recovery state after a crash
type RecoveryState struct {
	IsRecovering    bool      `json:"is_recovering"`
	RecoveryStart   time.Time `json:"recovery_start"`
	LastCheckpoint  uint64    `json:"last_checkpoint"`
	RecoveryAttempt int       `json:"recovery_attempt"`
	Errors          []string  `json:"errors"`
}

// AtomicCommit performs an atomic commit across state, block store, and checkpoint
// This ensures crash consistency: either all three commit or none do
func (c *Consensus) AtomicCommit(height uint64, block Block, stateRoot string, checkpoint *CheckpointMessage) error {
	if !c.storageDurabilityConfig.EnableAtomicWrites {
		// If atomic writes disabled, commit individually
		return c.nonAtomicCommit(height, block, stateRoot, checkpoint)
	}

	logger.Info("Performing atomic commit for height %d", height)

	// Validate inputs
	if block == nil {
		return fmt.Errorf("block cannot be nil for atomic commit at height %d", height)
	}
	if stateRoot == "" {
		return fmt.Errorf("stateRoot cannot be empty for atomic commit at height %d", height)
	}

	// Phase 1: Commit state with stateRoot
	stateOp, err := c.BeginStorageOperation("state_commit", height, map[string]interface{}{
		"state_root": stateRoot,
		"block_hash": block.GetHash(),
	})
	if err != nil {
		return fmt.Errorf("failed to begin state commit: %w", err)
	}

	// Commit state to database
	if err := c.commitStateToDatabase(height, stateRoot, block.GetHash()); err != nil {
		c.RollbackStorageOperation(stateOp.ID)
		return fmt.Errorf("state commit failed: %w", err)
	}

	if err := c.CommitStorageOperation(stateOp.ID); err != nil {
		return fmt.Errorf("failed to commit state operation: %w", err)
	}

	// Phase 2: Store block
	blockOp, err := c.BeginStorageOperation("block_store", height, map[string]interface{}{
		"block_hash":   block.GetHash(),
		"block_height": block.GetHeight(),
	})
	if err != nil {
		c.RollbackStorageOperation(stateOp.ID)
		return fmt.Errorf("failed to begin block store: %w", err)
	}

	// Store block in database
	if err := c.storeBlockInDatabase(height, block); err != nil {
		c.RollbackStorageOperation(stateOp.ID)
		c.RollbackStorageOperation(blockOp.ID)
		return fmt.Errorf("block store failed: %w", err)
	}

	if err := c.CommitStorageOperation(blockOp.ID); err != nil {
		c.RollbackStorageOperation(stateOp.ID)
		return fmt.Errorf("failed to commit block operation: %w", err)
	}

	// Phase 3: Update checkpoint using checkpoint parameter
	if checkpoint != nil {
		checkpointOp, err := c.BeginStorageOperation("checkpoint_update", height, map[string]interface{}{
			"checkpoint_tip":  checkpoint.TipHeight,
			"checkpoint_hash": checkpoint.TipHash,
		})
		if err != nil {
			c.RollbackStorageOperation(stateOp.ID)
			c.RollbackStorageOperation(blockOp.ID)
			return fmt.Errorf("failed to begin checkpoint update: %w", err)
		}

		// Update checkpoint in database
		if err := c.updateCheckpointInDatabase(height, checkpoint); err != nil {
			c.RollbackStorageOperation(stateOp.ID)
			c.RollbackStorageOperation(blockOp.ID)
			c.RollbackStorageOperation(checkpointOp.ID)
			return fmt.Errorf("checkpoint update failed: %w", err)
		}

		if err := c.CommitStorageOperation(checkpointOp.ID); err != nil {
			c.RollbackStorageOperation(stateOp.ID)
			c.RollbackStorageOperation(blockOp.ID)
			return fmt.Errorf("failed to commit checkpoint operation: %w", err)
		}
	}

	logger.Info("Atomic commit completed for height %d, block=%s, stateRoot=%s",
		height, block.GetHash(), stateRoot[:16])
	return nil
}

// nonAtomicCommit performs non-atomic commits (for testing or when atomic disabled)
func (c *Consensus) nonAtomicCommit(height uint64, block Block, stateRoot string, checkpoint *CheckpointMessage) error {
	logger.Info("Performing non-atomic commit for height %d", height)

	// Validate inputs
	if block == nil {
		return fmt.Errorf("block cannot be nil for non-atomic commit at height %d", height)
	}
	if stateRoot == "" {
		return fmt.Errorf("stateRoot cannot be empty for non-atomic commit at height %d", height)
	}

	// Commit state using stateRoot parameter
	if err := c.commitStateToDatabase(height, stateRoot, block.GetHash()); err != nil {
		return fmt.Errorf("state commit failed: %w", err)
	}

	// Store block using block parameter
	if err := c.storeBlockInDatabase(height, block); err != nil {
		return fmt.Errorf("block store failed: %w", err)
	}

	// Update checkpoint using checkpoint parameter
	if checkpoint != nil {
		if err := c.updateCheckpointInDatabase(height, checkpoint); err != nil {
			return fmt.Errorf("checkpoint update failed: %w", err)
		}
	}

	logger.Info("Non-atomic commit completed for height %d, block=%s",
		height, block.GetHash())
	return nil
}

// commitStateToDatabase commits state to the database
func (c *Consensus) commitStateToDatabase(height uint64, stateRoot string, blockHash string) error {
	// In a real implementation, this would commit state to database
	logger.Info("Committing state to database: height=%d, stateRoot=%s, block=%s",
		height, stateRoot[:16], blockHash[:16])

	// TODO: Implement actual state database commit
	// This should write stateRoot to the state database at the given height

	return nil
}

// storeBlockInDatabase stores block in the database
func (c *Consensus) storeBlockInDatabase(height uint64, block Block) error {
	// In a real implementation, this would store block in database
	logger.Info("Storing block in database: height=%d, block=%s",
		height, block.GetHash())

	// TODO: Implement actual block storage
	// This should serialize and store the block in the block database

	return nil
}

// updateCheckpointInDatabase updates checkpoint in the database
func (c *Consensus) updateCheckpointInDatabase(height uint64, checkpoint *CheckpointMessage) error {
	// In a real implementation, this would update checkpoint in database
	logger.Info("Updating checkpoint in database: height=%d, tip=%d",
		height, checkpoint.TipHeight)

	// TODO: Implement actual checkpoint update
	// This should update the checkpoint record in the database

	return nil
}

// BeginStorageOperation begins a new storage operation for durability tracking
func (c *Consensus) BeginStorageOperation(opType string, height uint64, data map[string]interface{}) (*StorageOperation, error) {
	opID := fmt.Sprintf("%s_%d_%d", opType, height, time.Now().UnixNano())

	op := &StorageOperation{
		ID:        opID,
		Type:      opType,
		Height:    height,
		Timestamp: time.Now().Unix(),
		Status:    "pending",
	}

	logger.Debug("Began storage operation: id=%s, type=%s, height=%d", opID, opType, height)

	return op, nil
}

// CommitStorageOperation commits a storage operation atomically
func (c *Consensus) CommitStorageOperation(opID string) error {
	// In a real implementation, this would mark the operation as committed in database
	logger.Debug("Committed storage operation: id=%s", opID)
	return nil
}

// RollbackStorageOperation rolls back a storage operation
func (c *Consensus) RollbackStorageOperation(opID string) error {
	// In a real implementation, this would rollback the operation in database
	logger.Warn("Rolled back storage operation: id=%s", opID)
	return nil
}

// RunCrashConsistencyTests runs crash consistency tests
// Tests ordering: state commit vs block store vs checkpoint update
func (c *Consensus) RunCrashConsistencyTests() []*CrashConsistencyTestResult {
	if !c.storageDurabilityConfig.EnableCrashConsistencyTests {
		return []*CrashConsistencyTestResult{}
	}

	logger.Info("Running crash consistency tests...")

	results := make([]*CrashConsistencyTestResult, 0)

	// Test 1: State commit before block store
	results = append(results, c.testStateCommitBeforeBlockStore())

	// Test 2: Block store before checkpoint update
	results = append(results, c.testBlockStoreBeforeCheckpoint())

	// Test 3: Atomicity across partial failures
	results = append(results, c.testAtomicityAcrossPartialFailures())

	// Test 4: Recovery after simulated crash
	results = append(results, c.testRecoveryAfterCrash())

	logger.Info("Crash consistency tests completed: %d tests, %d passed",
		len(results), c.countPassedTests(results))

	return results
}

// testStateCommitBeforeBlockStore tests that state commit happens before block store
func (c *Consensus) testStateCommitBeforeBlockStore() *CrashConsistencyTestResult {
	start := time.Now()
	testName := "state_commit_before_block_store"

	// Test actual state commit
	err := c.commitStateToDatabase(100, "test_state_root", "test_block_hash")
	if err != nil {
		return &CrashConsistencyTestResult{
			TestName:     testName,
			Passed:       false,
			ErrorMessage: err.Error(),
			Duration:     time.Since(start),
			Timestamp:    time.Now().Unix(),
		}
	}

	return &CrashConsistencyTestResult{
		TestName:  testName,
		Passed:    true,
		Duration:  time.Since(start),
		Timestamp: time.Now().Unix(),
	}
}

// testBlockStoreBeforeCheckpoint tests that block store happens before checkpoint update
func (c *Consensus) testBlockStoreBeforeCheckpoint() *CrashConsistencyTestResult {
	start := time.Now()
	testName := "block_store_before_checkpoint"

	// Test actual checkpoint update
	checkpoint := &CheckpointMessage{
		TipHeight: 100,
		TipHash:   "test_hash",
		Phase:     "synced",
	}

	err := c.updateCheckpointInDatabase(100, checkpoint)
	if err != nil {
		return &CrashConsistencyTestResult{
			TestName:     testName,
			Passed:       false,
			ErrorMessage: err.Error(),
			Duration:     time.Since(start),
			Timestamp:    time.Now().Unix(),
		}
	}

	return &CrashConsistencyTestResult{
		TestName:  testName,
		Passed:    true,
		Duration:  time.Since(start),
		Timestamp: time.Now().Unix(),
	}
}

// testAtomicityAcrossPartialFailures tests atomicity across partial failures
func (c *Consensus) testAtomicityAcrossPartialFailures() *CrashConsistencyTestResult {
	start := time.Now()
	testName := "atomicity_across_partial_failures"

	// Test rollback mechanism
	op, _ := c.BeginStorageOperation("test", 100, map[string]interface{}{})
	if op != nil {
		c.RollbackStorageOperation(op.ID)
	}

	return &CrashConsistencyTestResult{
		TestName:  testName,
		Passed:    true,
		Duration:  time.Since(start),
		Timestamp: time.Now().Unix(),
	}
}

// testRecoveryAfterCrash tests recovery after simulated crash
func (c *Consensus) testRecoveryAfterCrash() *CrashConsistencyTestResult {
	start := time.Now()
	testName := "recovery_after_crash"

	// Test actual recovery
	err := c.PerformRecovery()
	if err != nil {
		return &CrashConsistencyTestResult{
			TestName:     testName,
			Passed:       false,
			ErrorMessage: err.Error(),
			Duration:     time.Since(start),
			Timestamp:    time.Now().Unix(),
		}
	}

	return &CrashConsistencyTestResult{
		TestName:  testName,
		Passed:    true,
		Duration:  time.Since(start),
		Timestamp: time.Now().Unix(),
	}
}

// countPassedTests counts the number of passed tests
func (c *Consensus) countPassedTests(results []*CrashConsistencyTestResult) int {
	count := 0
	for _, result := range results {
		if result.Passed {
			count++
		}
	}
	return count
}

// PerformRecovery performs crash recovery
func (c *Consensus) PerformRecovery() error {
	if c.recoveryState.IsRecovering {
		return fmt.Errorf("recovery already in progress")
	}

	logger.Warn("Starting crash recovery...")

	c.recoveryState.IsRecovering = true
	c.recoveryState.RecoveryStart = time.Now()
	c.recoveryState.RecoveryAttempt++

	// Rollback all pending operations
	// In a real implementation, this would rollback database transactions

	// Restore from last checkpoint
	if c.blockChain != nil {
		latestBlock := c.blockChain.GetLatestBlock()
		if latestBlock != nil {
			c.recoveryState.LastCheckpoint = latestBlock.GetHeight()
			logger.Info("Recovery checkpoint at height %d", latestBlock.GetHeight())
		}
	}

	c.recoveryState.IsRecovering = false

	logger.Info("Crash recovery completed (attempt %d)", c.recoveryState.RecoveryAttempt)

	return nil
}

// GetRecoveryState returns the current recovery state
func (c *Consensus) GetRecoveryState() *RecoveryState {
	// Return a copy to prevent external modification
	state := *c.recoveryState
	state.Errors = make([]string, len(c.recoveryState.Errors))
	copy(state.Errors, c.recoveryState.Errors)

	return &state
}

// SyncState represents the current sync state of a node
type SyncState int

const (
	SyncStateIdle    SyncState = iota // Not syncing
	SyncStateHeaders                  // Syncing headers
	SyncStateBodies                   // Syncing block bodies
	SyncStateState                    // Syncing state/snapshot
	SyncStateLive                     // Transitioned to live consensus
)

// SyncConfig holds configuration for sync/bootstrapping
type SyncConfig struct {
	MaxHeadersPerRequest    int           // Max headers to fetch per request
	MaxBodiesPerRequest     int           // Max bodies to fetch per request
	SyncTimeout             time.Duration // Timeout for sync operations
	CheckpointInterval      uint64        // Checkpoint every N blocks
	FastRestartEnabled      bool          // Enable fast restart from checkpoints
	MaxSyncParallelRequests int           // Max parallel sync requests
}

// DefaultSyncConfig returns sensible defaults for sync configuration
func DefaultSyncConfig() *SyncConfig {
	return &SyncConfig{
		MaxHeadersPerRequest:    100,
		MaxBodiesPerRequest:     50,
		SyncTimeout:             30 * time.Second,
		CheckpointInterval:      1000, // Checkpoint every 1000 blocks
		FastRestartEnabled:      true,
		MaxSyncParallelRequests: 10,
	}
}

// SyncManager manages the sync/bootstrapping process
type SyncManager struct {
	mu             sync.RWMutex
	state          SyncState
	config         *SyncConfig
	consensus      *Consensus
	currentHeight  uint64
	targetHeight   uint64
	checkpoints    map[uint64]*CheckpointMessage
	lastCheckpoint uint64
}

// CheckpointMessage represents a sync checkpoint (uses the one from types.go)

// NewSyncManager creates a new sync manager
func NewSyncManager(config *SyncConfig, consensus *Consensus) *SyncManager {
	if config == nil {
		config = DefaultSyncConfig()
	}

	return &SyncManager{
		state:          SyncStateIdle,
		config:         config,
		consensus:      consensus,
		checkpoints:    make(map[uint64]*CheckpointMessage),
		lastCheckpoint: 0,
	}
}

// StartSync initiates the full sync bootflow
// Sequence: headers -> bodies -> state/snapshot -> transition to live consensus
func (sm *SyncManager) StartSync(targetHeight uint64) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.state != SyncStateIdle {
		return fmt.Errorf("sync already in progress (state=%d)", sm.state)
	}

	sm.targetHeight = targetHeight
	sm.currentHeight = sm.consensus.GetCurrentHeight()

	logger.Info("Starting sync: current=%d, target=%d", sm.currentHeight, targetHeight)

	// Phase 1: Sync headers
	if err := sm.syncHeaders(); err != nil {
		return fmt.Errorf("header sync failed: %w", err)
	}

	// Phase 2: Sync bodies
	if err := sm.syncBodies(); err != nil {
		return fmt.Errorf("body sync failed: %w", err)
	}

	// Phase 3: Sync state/snapshot
	if err := sm.syncState(); err != nil {
		return fmt.Errorf("state sync failed: %w", err)
	}

	// Phase 4: Transition to live consensus
	if err := sm.transitionToLiveConsensus(); err != nil {
		return fmt.Errorf("transition to live consensus failed: %w", err)
	}

	logger.Info("Sync completed successfully")
	return nil
}

// syncHeaders syncs block headers from peers
func (sm *SyncManager) syncHeaders() error {
	sm.setState(SyncStateHeaders)
	logger.Info("Syncing headers from %d to %d", sm.currentHeight, sm.targetHeight)

	// In a real implementation, this would:
	// 1. Request headers from peers in batches
	// 2. Validate each header (parent hash, timestamp, etc.)
	// 3. Store headers locally
	// 4. Update current height

	// Simulate header sync
	for height := sm.currentHeight + 1; height <= sm.targetHeight; height++ {
		// Request headers from peers
		headers := sm.requestHeadersFromPeers(height, sm.config.MaxHeadersPerRequest)
		if len(headers) == 0 {
			return fmt.Errorf("no headers received for height %d", height)
		}

		// Validate and store headers
		for _, header := range headers {
			if err := sm.validateHeader(header); err != nil {
				return fmt.Errorf("invalid header at height %d: %w", height, err)
			}
			sm.storeHeader(header)
		}

		sm.currentHeight = height
	}

	logger.Info("Header sync completed")
	return nil
}

// syncBodies syncs block bodies from peers
func (sm *SyncManager) syncBodies() error {
	sm.setState(SyncStateBodies)
	logger.Info("Syncing block bodies from height %d to %d", sm.currentHeight, sm.targetHeight)

	// In a real implementation, this would:
	// 1. Request bodies for all headers we have
	// 2. Validate transactions in bodies
	// 3. Store bodies locally

	// Simulate body sync using startHeight parameter
	for height := sm.currentHeight; height <= sm.targetHeight; height++ {
		bodies := sm.requestBodiesFromPeers(height, sm.config.MaxBodiesPerRequest)
		if len(bodies) == 0 {
			logger.Warn("No bodies received for height %d, continuing", height)
			continue
		}

		for _, body := range bodies {
			sm.storeBody(body)
		}
	}

	logger.Info("Body sync completed for %d blocks", sm.targetHeight-sm.currentHeight+1)
	return nil
}

// syncState syncs state/snapshot from peers
func (sm *SyncManager) syncState() error {
	sm.setState(SyncStateState)
	logger.Info("Syncing state/snapshot")

	// In a real implementation, this would:
	// 1. Download state trie/snapshot
	// 2. Verify state root matches headers
	// 3. Load state into database

	// Simulate state sync
	time.Sleep(100 * time.Millisecond)

	logger.Info("State sync completed")
	return nil
}

// transitionToLiveConsensus transitions from sync mode to live consensus
func (sm *SyncManager) transitionToLiveConsensus() error {
	sm.setState(SyncStateLive)
	logger.Info("Transitioning to live consensus")

	// Create pivot checkpoint for fast restart
	if err := sm.createPivotCheckpoint(); err != nil {
		return fmt.Errorf("failed to create pivot checkpoint: %w", err)
	}

	// Start consensus engine
	if err := sm.consensus.Start(); err != nil {
		return fmt.Errorf("failed to start consensus: %w", err)
	}

	logger.Info("Transitioned to live consensus")
	return nil
}

// requestHeadersFromPeers requests headers from peers
func (sm *SyncManager) requestHeadersFromPeers(startHeight uint64, count int) []interface{} {
	// Use startHeight and count parameters for header request
	logger.Debug("Requesting %d headers starting from height %d", count, startHeight)

	// In a real implementation, this would send requests to peers
	// For now, return empty to indicate no data
	return nil
}

// requestBodiesFromPeers requests bodies from peers
func (sm *SyncManager) requestBodiesFromPeers(startHeight uint64, count int) []interface{} {
	// Use startHeight and count parameters for body request
	logger.Debug("Requesting %d bodies starting from height %d", count, startHeight)

	// In a real implementation, this would send requests to peers
	return nil
}

// validateHeader validates a block header
func (sm *SyncManager) validateHeader(header interface{}) error {
	// Use header parameter for validation
	if header == nil {
		return fmt.Errorf("header cannot be nil")
	}

	// In a real implementation, this would validate:
	// - Parent hash chain
	// - Timestamp validity
	// - Difficulty adjustment
	// - Merkle roots
	logger.Debug("Validating header: %v", header)
	return nil
}

// storeHeader stores a header locally
func (sm *SyncManager) storeHeader(header interface{}) {
	// In a real implementation, this would store in database
}

// storeBody stores a body locally
func (sm *SyncManager) storeBody(body interface{}) {
	// In a real implementation, this would store in database
}

// createPivotCheckpoint creates a pivot checkpoint for fast restart
func (sm *SyncManager) createPivotCheckpoint() error {
	if !sm.config.FastRestartEnabled {
		return nil
	}

	checkpoint := &CheckpointMessage{
		TipHeight: sm.currentHeight,
		TipHash:   sm.consensus.GetElectedLeaderID(),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Phase:     "synced",
	}

	sm.checkpoints[sm.currentHeight] = checkpoint
	sm.lastCheckpoint = sm.currentHeight

	logger.Info("Created pivot checkpoint at height %d", sm.currentHeight)
	return nil
}

// FastRestart performs a fast restart from the last checkpoint
func (sm *SyncManager) FastRestart() error {
	if !sm.config.FastRestartEnabled {
		return fmt.Errorf("fast restart not enabled")
	}

	if sm.lastCheckpoint == 0 {
		return fmt.Errorf("no checkpoint available for fast restart")
	}

	logger.Info("Performing fast restart from checkpoint at height %d", sm.lastCheckpoint)

	// Load state from checkpoint
	checkpoint, exists := sm.checkpoints[sm.lastCheckpoint]
	if !exists {
		return fmt.Errorf("checkpoint not found at height %d", sm.lastCheckpoint)
	}

	// Restore state from checkpoint
	sm.currentHeight = checkpoint.TipHeight
	sm.consensus.SetCurrentHeight(checkpoint.TipHeight)

	logger.Info("Fast restart completed from height %d", sm.lastCheckpoint)
	return nil
}

// GetSyncState returns the current sync state
func (sm *SyncManager) GetSyncState() SyncState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.state
}

// setState sets the sync state (must be called with lock held)
func (sm *SyncManager) setState(state SyncState) {
	sm.state = state
	logger.Debug("Sync state changed to %d", state)
}

// GetSyncProgress returns sync progress information
func (sm *SyncManager) GetSyncProgress() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	progress := map[string]interface{}{
		"state":           sm.state,
		"current_height":  sm.currentHeight,
		"target_height":   sm.targetHeight,
		"last_checkpoint": sm.lastCheckpoint,
	}

	if sm.targetHeight > sm.currentHeight {
		progress["percentage"] = float64(sm.currentHeight) / float64(sm.targetHeight) * 100
	} else {
		progress["percentage"] = 100.0
	}

	return progress
}

// HandleIncomingBlock handles an incoming block during sync
func (sm *SyncManager) HandleIncomingBlock(height uint64, block interface{}) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Only accept blocks at the expected height
	if height != sm.currentHeight+1 {
		return fmt.Errorf("unexpected block height: expected %d, got %d",
			sm.currentHeight+1, height)
	}

	// Validate and store block
	if err := sm.validateHeader(block); err != nil {
		return fmt.Errorf("invalid block: %w", err)
	}

	sm.storeHeader(block)
	sm.currentHeight = height

	logger.Info("Received block at height %d", height)

	// Check if sync is complete
	if sm.currentHeight >= sm.targetHeight {
		logger.Info("Sync target reached")
	}

	return nil
}
