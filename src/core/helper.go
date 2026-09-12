// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/helper.go
package core

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/sphinxfndorg/protocol/src/consensus"
	logger "github.com/sphinxfndorg/protocol/src/console"
	"github.com/sphinxfndorg/protocol/src/contracts"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
	"github.com/sphinxfndorg/protocol/src/pool"
	storage "github.com/sphinxfndorg/protocol/src/state"
)

// NewBlockHelper creates a new adapter for types.Block
func NewBlockHelper(block *types.Block) consensus.Block {
	return &BlockHelper{block: block}
}

// GetHeight returns the block height
func (a *BlockHelper) GetHeight() uint64 {
	return a.block.GetHeight()
}

// GetHash returns the block hash
func (a *BlockHelper) GetHash() string {
	return a.block.GetHash()
}

// GetPrevHash returns the previous block hash
func (a *BlockHelper) GetPrevHash() string {
	return a.block.GetPrevHash()
}

// GetTimestamp returns the block timestamp
func (a *BlockHelper) GetTimestamp() int64 {
	return a.block.GetTimestamp()
}

// Validate validates the block
func (a *BlockHelper) Validate() error {
	return a.block.Validate()
}

// GetDifficulty returns the block difficulty
func (a *BlockHelper) GetDifficulty() *big.Int {
	if a.block.Header != nil {
		return a.block.Header.Difficulty
	}
	return big.NewInt(1)
}

// GetCurrentNonce returns the current nonce value - ADD THIS METHOD
func (a *BlockHelper) GetCurrentNonce() (uint64, error) {
	if a.block == nil {
		return 0, fmt.Errorf("block is nil")
	}
	return a.block.GetCurrentNonce()
}

// GetUnderlyingBlock returns the underlying types.Block
// GetUnderlyingBlock returns the underlying types.Block as interface{}
func (a *BlockHelper) GetUnderlyingBlock() interface{} {
	return a.block
}

// SetConsensus sets the consensus module for the state machine
func (bc *Blockchain) SetConsensus(consensus *consensus.Consensus) {
	bc.stateMachine.SetConsensus(consensus)
}

// IsGenesisHash checks if a hash is a valid genesis hash (starts with GENESIS_)
func (bc *Blockchain) IsGenesisHash(hash string) bool {
	return strings.HasPrefix(hash, "GENESIS_")
}

// IsValidChain checks the integrity of the full chain
func (bc *Blockchain) IsValidChain() error {
	return bc.storage.ValidateChain()
}

// Start TPS auto-save in blockchain initialization
func (bc *Blockchain) StartTPSAutoSave(ctx context.Context) {
	bc.storage.StartTPSAutoSave(ctx)
}

// VerifyMessage verifies a signed message (placeholder)
func (bc *Blockchain) VerifyMessage(address, signature, message string) bool {
	logger.Info("Message verification requested - address: %s, message: %s", address, message)
	return true
}

// ExplorerValidatorInfo holds validator data formatted for the block explorer.
type ExplorerValidatorInfo struct {
	ID              string  `json:"id"`
	StakeSPX        string  `json:"stake_spx"`
	StakeNSPX       string  `json:"stake_nspx"`
	RewardAddress   string  `json:"reward_address"`
	ActivationEpoch uint64  `json:"activation_epoch"`
	ExitEpoch       uint64  `json:"exit_epoch"`
	IsSlashed       bool    `json:"is_slashed"`
	LastAttested    uint64  `json:"last_attested"`
	Status          string  `json:"status"`
	StakePercent    float64 `json:"stake_percent"`
}

// ExplorerValidatorsResponse holds the full validator response for the explorer.
type ExplorerValidatorsResponse struct {
	TotalValidators   int                      `json:"total_validators"`
	ActiveValidators  int                      `json:"active_validators"`
	SlashedValidators int                      `json:"slashed_validators"`
	TotalStakeSPX     string                   `json:"total_stake_spx"`
	MinStakeSPX       uint64                   `json:"min_stake_spx"`
	Validators        []*ExplorerValidatorInfo `json:"validators"`
}

// GetExplorerValidators returns validator data formatted for the block explorer.
func (bc *Blockchain) GetExplorerValidators() *ExplorerValidatorsResponse {
	vs := bc.GetValidatorSet()
	if vs == nil {
		return &ExplorerValidatorsResponse{
			Validators: make([]*ExplorerValidatorInfo, 0),
		}
	}

	response := &ExplorerValidatorsResponse{
		Validators: make([]*ExplorerValidatorInfo, 0),
	}

	allVals := vs.GetValidators()
	totalStake := vs.GetTotalStake()

	if totalStake == nil || totalStake.Sign() == 0 {
		totalStake = big.NewInt(1) // avoid division by zero
	}

	for _, v := range allVals {
		if v == nil {
			continue
		}
		response.TotalValidators++

		if v.IsSlashed {
			response.SlashedValidators++
		}

		// Calculate stake percentage
		stakeFloat := new(big.Float).SetInt(v.StakeAmount)
		totalFloat := new(big.Float).SetInt(totalStake)
		stakePct, _ := new(big.Float).Quo(stakeFloat, totalFloat).Float64()
		stakePct *= 100

		// Convert to SPX
		stakeSPX := new(big.Float).Quo(
			new(big.Float).SetInt(v.StakeAmount),
			new(big.Float).SetFloat64(1e18),
		)

		status := "active"
		if v.IsSlashed {
			status = "slashed"
		} else if v.ExitEpoch > 0 {
			status = "exited"
		}

		response.Validators = append(response.Validators, &ExplorerValidatorInfo{
			ID:              v.ID,
			StakeSPX:        stakeSPX.Text('f', 2),
			StakeNSPX:       v.StakeAmount.String(),
			RewardAddress:   v.RewardAddress,
			ActivationEpoch: v.ActivationEpoch,
			ExitEpoch:       v.ExitEpoch,
			IsSlashed:       v.IsSlashed,
			LastAttested:    v.LastAttested,
			Status:          status,
			StakePercent:    stakePct,
		})

		if !v.IsSlashed {
			response.ActiveValidators++
		}
	}

	// Total stake in SPX
	if vs.totalStake != nil {
		totalSPX := new(big.Float).Quo(
			new(big.Float).SetInt(vs.totalStake),
			new(big.Float).SetFloat64(1e18),
		)
		response.TotalStakeSPX = totalSPX.Text('f', 2)
	}

	response.MinStakeSPX = vs.GetMinStakeSPX()

	return response
}

// HasPendingTx checks if a transaction is in the mempool
func (bc *Blockchain) HasPendingTx(hash string) bool {
	return bc.mempool.HasTransaction(hash)
}

// GetTPSMonitor returns the TPS monitor for debugging and metrics
func (bc *Blockchain) GetTPSMonitor() *types.TPSMonitor {
	return bc.tpsMonitor
}

// SetConsensusEngine sets the consensus engine
func (bc *Blockchain) SetConsensusEngine(engine *consensus.Consensus) {
	bc.consensusEngine = engine
}

// SetLateJoiner marks this node as a late joiner that should NOT create genesis
// locally. Instead, it will download the entire chain (including genesis) from
// peers via the sync loop. Call this before initializeChain().
func (bc *Blockchain) SetLateJoiner() {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	bc.lateJoiner = true
	logger.Info("📥 Late-joiner mode: genesis will be synced from peers, not created locally")
}

// IsLateJoiner returns whether this node is a late joiner.
func (bc *Blockchain) IsLateJoiner() bool {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.lateJoiner
}

// ReplaceGenesis replaces the local genesis block with one received from a peer.
// This is used by late-joining nodes that created a local genesis (with their own
// wall-clock timestamp) and need to adopt the network's canonical genesis block.
func (bc *Blockchain) ReplaceGenesis(block *types.Block) error {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	// Replace in storage
	if err := bc.storage.ReplaceGenesis(block); err != nil {
		return fmt.Errorf("ReplaceGenesis: storage: %w", err)
	}

	// Replace in-memory chain
	bc.chain = []*types.Block{block}

	logger.Info("SUCCESS ReplaceGenesis: local genesis replaced with peer's version — hash=%s", block.GetHash())
	return nil
}

// ClearChainAfter removes all blocks with height > keepAfter from the
// in-memory chain. This is used after ReplaceGenesis to clear locally-mined
// blocks that reference the old genesis, so the sync loop can re-download
// blocks from the peer against the canonical genesis without hitting
// "parent hash mismatch" errors.
//
// Storage blocks are intentionally NOT deleted here — they will be
// overwritten when the sync loop downloads fresh blocks from peers
// via StoreBlock. Clearing storage would also be risky if ReplaceGenesis
// ran mid-commit on a chain that already has validated blocks.
func (bc *Blockchain) ClearChainAfter(keepAfter uint64) {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	if len(bc.chain) == 0 {
		return
	}

	// Keep only up to keepAfter in memory
	kept := make([]*types.Block, 0)
	for _, blk := range bc.chain {
		if blk.GetHeight() <= keepAfter {
			kept = append(kept, blk)
		}
	}
	bc.chain = kept

	logger.Info("ClearChainAfter: cleared blocks after height %d (chain now has %d blocks)", keepAfter, len(bc.chain))
}

// ResetForResync wipes all blockchain state — account records, supply
// counters, validator stakes, stored blocks, and the in-memory chain — so the
// sync loop can re-download the entire chain from genesis. This is the recovery
// path when CommitBlock detects a state-root mismatch: the local state has
// diverged from the network and the only safe remedy is to throw everything
// away and resync from a trusted peer.
//
// It is safe to call from the sync goroutine: CommitBlock holds bc.commitMu for
// the duration of a commit, and the sync loop calls CommitBlock serially, so
// this can only run when no commit is in progress.
func (bc *Blockchain) ResetForResync() error {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	logger.Info("ResetForResync: wiping all blockchain state for resync from genesis")

	// 1. Wipe account state and supply counters from LevelDB.
	db, err := bc.storage.GetDB()
	if err != nil {
		return fmt.Errorf("ResetForResync: failed to get DB: %w", err)
	}

	keys, err := db.ListKeysWithPrefix(accountPrefix)
	if err != nil {
		return fmt.Errorf("ResetForResync: listing account keys: %w", err)
	}
	for _, k := range keys {
		if err := db.Delete(k); err != nil {
			return fmt.Errorf("ResetForResync: deleting %s: %w", k, err)
		}
	}

	// 2. Wipe supply / reward counters.
	_ = db.Delete(totalSupplyKey)
	_ = db.Delete(genesisSupplyKey)
	_ = db.Delete(rewardsMintedKey)

	// 3. Wipe ALL contract state (code, storage, validator stakes) so the
	//    replay starts from a clean slate.
	if contractKeys, err := db.ListKeysWithPrefix(contractPrefix); err == nil {
		for _, k := range contractKeys {
			_ = db.Delete(k)
		}
	}
	// Also use the StateDB helper to clear validator stakes (handles any
	// in-memory pending writes that wouldn't show up in ListKeysWithPrefix).
	if sdb, err := bc.newStateDB(); err == nil {
		if err := sdb.ClearValidatorStakes(); err != nil {
			logger.Warn("ResetForResync: could not clear validator stakes: %v", err)
		}
	}

	// 4. Delete all stored blocks from disk and reset the storage tip.
	//    ResetTip removes every block file (including genesis), clears the
	//    in-memory indices, and resets totalBlocks / bestBlockHash.
	if err := bc.storage.ResetTip(); err != nil {
		return fmt.Errorf("ResetForResync: ResetTip failed: %w", err)
	}

	// 5. Clear the in-memory chain entirely.
	bc.chain = nil

	logger.Info("ResetForResync: state wiped — node ready to resync from genesis")
	return nil
}

// GetStorage returns the storage instance for external access
func (bc *Blockchain) GetStorage() *storage.Storage {
	return bc.storage
}

// GetMempool returns the mempool instance
func (bc *Blockchain) GetMempool() *pool.Mempool {
	return bc.mempool
}

// SetMempool sets the mempool for the blockchain
func (bc *Blockchain) SetMempool(mempool *pool.Mempool) {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	bc.mempool = mempool
	// Also set on state machine if needed
	if bc.stateMachine != nil {
		bc.stateMachine.SetMempool(mempool)
	}
	// Keep admission-time (mempool) and commit-time (chain) auth consistent:
	// the mempool must observe the same STHINCS manager the chain uses.
	if mempool != nil {
		mempool.SetSTHINCSManager(bc.sphincsManager)
	}
}

// SyncSTHINCSManager re-applies bc.sphincsManager onto the mempool so both
// auth paths observe the same manager. Call after SetSTHINCSManager.
func (bc *Blockchain) SyncSTHINCSManager() {
	if bc.mempool != nil {
		bc.mempool.SetSTHINCSManager(bc.sphincsManager)
	}
}

// GetChainParams returns the Sphinx blockchain parameters for external recognition
func (bc *Blockchain) GetChainParams() *SphinxChainParameters {
	return bc.chainParams
}

// SaveBasicChainState saves a basic chain state
// Enhanced to preserve existing node information
func (bc *Blockchain) SaveBasicChainState() error {
	// Load existing chain state to preserve node information
	existingChainState, err := bc.storage.LoadCompleteChainState()
	if err != nil || existingChainState == nil {
		// No existing state, create with empty nodes array
		return bc.StoreChainState([]*storage.NodeInfo{})
	}

	// Preserve existing nodes array
	return bc.StoreChainState(existingChainState.Nodes)
}

// SetStorageDB injects a shared *database.DB into the blockchain's storage
// layer, enabling StateDB-backed block execution (ExecuteBlock / CommitBlock).
// Call this once after NewBlockchain and before any CommitBlock invocation.
func (bc *Blockchain) SetStorageDB(db *database.DB) {
	bc.storage.SetDB(db)
}

// SetStateDB injects a shared *database.DB into the blockchain's storage
// for consensus state management.
func (bc *Blockchain) SetStateDB(db *database.DB) {
	bc.storage.SetStateDB(db)
}

// RequiresDistributionBeforePromotion returns true for devnet — the network
// must drain the genesis vault before it can be promoted to testnet/mainnet.
func (p *SphinxChainParameters) RequiresDistributionBeforePromotion() bool {
	return p.IsDevnet()
}

// GetGovernancePolicy returns the governance policy parameters
func (p *SphinxChainParameters) GetGovernancePolicy() *policy.PolicyParameters {
	return policy.GetDefaultPolicyParams()
}

// CalculateTransactionFee calculates fee for a transaction based on governance policy
func (p *SphinxChainParameters) CalculateTransactionFee(bytes uint64, ops uint64, hashes uint64) *policy.FeeComponents {
	govPolicy := p.GetGovernancePolicy()
	return govPolicy.CalculateFees(bytes, ops, hashes)
}

// MinimumTransactionFee returns the governance-policy fee floor in nSPX.
func (bc *Blockchain) MinimumTransactionFee(bytes uint64, ops uint64, hashes uint64) *big.Int {
	if bc != nil && bc.chainParams != nil {
		return bc.chainParams.CalculateTransactionFee(bytes, ops, hashes).TotalFee
	}
	return policy.GetDefaultPolicyParams().CalculateMinimumFee(bytes, ops, hashes)
}

// EstimateTransactionPolicyCost estimates the policy dimensions used for a
// standard value-transfer transaction.
func (bc *Blockchain) EstimateTransactionPolicyCost(tx *types.Transaction) (uint64, uint64, uint64, *big.Int, error) {
	if tx == nil {
		return 0, 0, 0, nil, fmt.Errorf("nil transaction")
	}

	size, err := bc.calculateTxsSize(tx)
	if err != nil {
		return 0, 0, 0, nil, err
	}

	ops := uint64(1)
	if tx.HasReturnData() {
		ops++
	}
	if len(tx.Signature) > 0 {
		ops++
	}

	hashes := uint64(1)
	if len(tx.SignatureHash) == 32 {
		hashes++
	}
	if len(tx.MerkleRootHash) == 32 {
		hashes++
	}
	if len(tx.Commitment) == 32 {
		hashes++
	}
	if len(tx.Proof) == 32 {
		hashes++
	}

	fee := bc.MinimumTransactionFee(size, ops, hashes)
	return size, ops, hashes, fee, nil
}

// RequiredTransactionGas returns the policy-defined gas quote for tx. It is
// intentionally derived only from consensus transaction fields so every node
// reaches the same result; USI quotes this schedule only for user experience.
func (bc *Blockchain) RequiredTransactionGas(tx *types.Transaction) (*policy.GasQuote, error) {
	if tx == nil {
		return nil, fmt.Errorf("nil transaction")
	}
	quote := bc.ActivePolicy().QuoteTransactionGas(uint64(len(tx.ReturnData)))
	if len(tx.Code) == 0 && tx.ToContract == "" {
		return quote, nil
	}
	var operations, reads, writes, eventBytes, transfers uint64
	wasmExecution := false
	if len(tx.Code) > 0 && isSVMCode(tx.Code) {
		var err error
		operations, err = contracts.AnalyzeSVM(tx.Code)
		if err != nil {
			return nil, fmt.Errorf("invalid SVM contract: %w", err)
		}
	} else if len(tx.Code) > 0 && contracts.IsWASM(tx.Code) {
		analysis, err := contracts.AnalyzeWASM(tx.Code)
		if err != nil {
			return nil, fmt.Errorf("invalid WASM contract: %w", err)
		}
		wasmExecution = true
		operations, reads, writes, eventBytes, transfers = analysis.Operations, analysis.StorageReads, analysis.StorageWrites, analysis.EventBytes, analysis.Transfers
	} else if tx.ToContract != "" {
		// SVM call gas depends on the stored program. Read the committed
		// consensus state during admission; calls to contracts deployed earlier
		// in the same block are intentionally not supported in this first VM.
		state, err := bc.newStateDB()
		if err != nil {
			return nil, fmt.Errorf("load contract state for gas quote: %w", err)
		}
		code, err := newContractStore(state).GetContractCode(tx.ToContract)
		if err != nil {
			return nil, fmt.Errorf("unknown contract %q", tx.ToContract)
		}
		if isSVMCode(code) {
			operations, err = contracts.AnalyzeSVM(code)
			if err != nil {
				return nil, fmt.Errorf("invalid stored SVM contract: %w", err)
			}
		} else if contracts.IsWASM(code) {
			analysis, err := contracts.AnalyzeWASM(code)
			if err != nil {
				return nil, fmt.Errorf("invalid stored WASM contract: %w", err)
			}
			wasmExecution = true
			operations, reads, writes, eventBytes, transfers = analysis.Operations, analysis.StorageReads, analysis.StorageWrites, analysis.EventBytes, analysis.Transfers
		}
	}
	contractQuote := bc.ActivePolicy().QuoteContractGas(len(tx.Code) > 0, uint64(len(tx.Code)), uint64(len(tx.CallData)), operations)
	if wasmExecution {
		contractQuote = bc.ActivePolicy().QuoteWASMContractGas(len(tx.Code) > 0, uint64(len(tx.Code)), uint64(len(tx.CallData)), operations, reads, writes, eventBytes, transfers)
	}
	quote.GasLimit.Add(quote.GasLimit, contractQuote.GasLimit)
	quote.GasFee.Mul(quote.GasLimit, quote.GasPrice)
	return quote, nil
}

// ActivePolicy returns the consensus policy currently used by this chain.
// Keeping this fallback makes pure helpers and tests safe before chain
// parameters have been initialized.
func (bc *Blockchain) ActivePolicy() *policy.PolicyParameters {
	if bc != nil && bc.chainParams != nil {
		return bc.chainParams.GetGovernancePolicy()
	}
	return policy.GetDefaultPolicyParams()
}

// PolicyBlockReward returns the consensus block reward. Chain parameters may
// configure network mechanics, but monetary issuance is owned by policy.
func (bc *Blockchain) PolicyBlockReward() *big.Int {
	return bc.ActivePolicy().CalculateBlockReward()
}

// ValidateTransactionPolicy enforces governance policy for non-system txs.
func (bc *Blockchain) ValidateTransactionPolicy(tx *types.Transaction) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	if tx.IsSystemTransaction() {
		return nil
	}
	if len(tx.Code) > 0 && tx.ToContract != "" {
		return fmt.Errorf("contract transaction cannot deploy and call simultaneously")
	}
	if len(tx.Code) > 0 && len(tx.CallData) > 0 {
		return fmt.Errorf("contract deployment cannot contain call data")
	}
	if len(tx.Code) == 0 && tx.ToContract == "" && len(tx.CallData) > 0 {
		return fmt.Errorf("call data requires a contract target")
	}
	if tx.GasLimit == nil || tx.GasPrice == nil {
		return fmt.Errorf("missing gas fields")
	}

	quote, err := bc.RequiredTransactionGas(tx)
	if err != nil {
		return err
	}
	if tx.GasLimit.Cmp(quote.GasLimit) < 0 {
		return fmt.Errorf("gas limit below policy minimum: offered %s, required %s", tx.GasLimit.String(), quote.GasLimit.String())
	}
	if tx.GasPrice.Cmp(quote.GasPrice) < 0 {
		return fmt.Errorf("gas price below policy minimum: offered %s, required %s", tx.GasPrice.String(), quote.GasPrice.String())
	}

	_, _, _, requiredFee, err := bc.EstimateTransactionPolicyCost(tx)
	if err != nil {
		return err
	}
	offeredFee := tx.GetGasFee()
	if offeredFee.Cmp(requiredFee) < 0 {
		return fmt.Errorf("transaction fee below policy minimum: offered %s, required %s", offeredFee.String(), requiredFee.String())
	}

	// ── Node-side mint-anchor verification ────────────────────────────────
	// A mint-anchor transaction (USI "Mint Data", CLI mint) carries its entire
	// on-chain commitment in ReturnData as a mint_anchor AnchorTag. Every node
	// verifies that commitment here, twice:
	//
	//   - admission: the JSON-RPC handler's sendrawtransaction →
	//     AddTransaction path rejects un-verifiable anchors before they enter
	//     the mempool,
	//   - consensus: CommitBlock re-runs this policy per transaction for every
	//     proposed AND synced block, so a node can never commit (nor re-play
	//     from a peer) a block containing an anchor that does not verify.
	//
	// Verification enforces the commitment's internal consistency: CID present
	// and committed via cid_hash_hex, 32-byte receipt hash, valid minter key.
	// Full receipt binding (SPHINCS+ signature + payload hash vs ReceiptHash)
	// requires the original signed receipt and stays off-chain — see
	// usi/core/mint.VerifyAnchoredReceipt and the mint-anchor comment in mint_anchor.go.
	if tx.HasReturnData() && IsMintAnchor(tx.ReturnData) {
		if err := ValidateAnchorData(tx.ReturnData); err != nil {
			return fmt.Errorf("mint anchor verification failed: %w", err)
		}
	}
	return nil
}

// GetInflationRate returns the current inflation rate based on stake ratio
func (p *SphinxChainParameters) GetInflationRate(currentStakeRatio float64) float64 {
	govPolicy := p.GetGovernancePolicy()
	return govPolicy.CalculateAnnualInflation(uint64(currentStakeRatio * 10000))
}

// GetStorageCost calculates storage cost based on governance policy
func (p *SphinxChainParameters) GetStorageCost(bytes uint64, months float64) *policy.StoragePricing {
	govPolicy := p.GetGovernancePolicy()
	return govPolicy.CalculateStorageCost(bytes, months)
}

// GetMaxBlockSize returns the maximum block size in bytes
// Getter for maximum block size
func (p *SphinxChainParameters) GetMaxBlockSize() uint64 {
	return p.MaxBlockSize
}

// GetTargetBlockSize returns the target block size in bytes
// Getter for target block size (optimization target)
func (p *SphinxChainParameters) GetTargetBlockSize() uint64 {
	return p.TargetBlockSize
}

// GetMaxTransactionSize returns the maximum transaction size in bytes
// Getter for maximum transaction size
func (p *SphinxChainParameters) GetMaxTransactionSize() uint64 {
	return p.MaxTransactionSize
}

// IsBlockSizeValid checks if a block size is within acceptable limits
// Validates block size against chain parameters
func (p *SphinxChainParameters) IsBlockSizeValid(blockSize uint64) bool {
	// Block must not exceed maximum and must be positive
	return blockSize <= p.MaxBlockSize && blockSize > 0
}

// VerifyStateConsistency verifies that this node's state matches other nodes
// Parameters:
//   - otherState: State snapshot from another node
//
// Returns: true if states are consistent, error if verification fails
func (bc *Blockchain) VerifyStateConsistency(otherState *storage.StateSnapshot) (bool, error) {
	// Delegate to state machine for verification
	return bc.stateMachine.VerifyState(otherState)
}

// GetCurrentState returns the current state snapshot
// Returns: Current state snapshot
func (bc *Blockchain) GetCurrentState() *storage.StateSnapshot {
	// Get current state from state machine
	return bc.stateMachine.GetCurrentState()
}

// GetParentHash returns the parent block hash
func (a *BlockHelper) GetParentHash() string {
	return a.block.GetParentHash()
}

// GetCommitStatus returns the commit status
func (a *BlockHelper) GetCommitStatus() string {
	return a.block.GetCommitStatus()
}

// SetCommitStatus sets the commit status
func (a *BlockHelper) SetCommitStatus(status string) {
	a.block.SetCommitStatus(status)
}

// GetSigValid returns whether signature is valid
func (a *BlockHelper) GetSigValid() bool {
	return a.block.GetSigValid()
}

// SetSigValid sets the signature validity flag
func (a *BlockHelper) SetSigValid(valid bool) {
	a.block.SetSigValid(valid)
}

// GetTxsRoot returns the transaction root
func (a *BlockHelper) GetTxsRoot() []byte {
	return a.block.GetTxsRoot()
}
