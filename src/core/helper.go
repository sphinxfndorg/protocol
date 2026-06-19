// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/helper.go
package core

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/sphinxorg/protocol/src/common"
	"github.com/sphinxorg/protocol/src/consensus"
	database "github.com/sphinxorg/protocol/src/core/state"
	sign "github.com/sphinxorg/protocol/src/core/sthincs/sign/backend"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	logger "github.com/sphinxorg/protocol/src/log"
	"github.com/sphinxorg/protocol/src/policy"
	"github.com/sphinxorg/protocol/src/pool"
	storage "github.com/sphinxorg/protocol/src/state"
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

// calculateEmptyTransactionsRoot returns a standard Merkle root for empty transactions
func (bc *Blockchain) calculateEmptyTransactionsRoot() []byte {
	// Standard empty Merkle root (hash of empty string)
	emptyHash := common.SpxHash([]byte{})
	return emptyHash
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

// GetStorage returns the storage instance for external access
func (bc *Blockchain) GetStorage() *storage.Storage {
	return bc.storage
}

// GetMempool returns the mempool instance
func (bc *Blockchain) GetMempool() *pool.Mempool {
	return bc.mempool
}

// SetSTHINCSManager connects the chain mempool to the node's SPHINCS verifier.
// Call this during node startup after the per-node STHINCSManager is created.
func (bc *Blockchain) SetSTHINCSManager(manager *sign.STHINCSManager) {
	bc.sphincsManager = manager
	if bc.mempool != nil {
		bc.mempool.SetSTHINCSManager(manager)
	}
}

// GetChainParams returns the Sphinx blockchain parameters for external recognition
func (bc *Blockchain) GetChainParams() *SphinxChainParameters {
	return bc.chainParams
}

// SaveBasicChainState saves a basic chain state
// Simplified version of chain state saving without node information
func (bc *Blockchain) SaveBasicChainState() error {
	return bc.StoreChainState(nil) // Only one parameter now
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

// ValidateTransactionPolicy enforces governance policy for non-system txs.
func (bc *Blockchain) ValidateTransactionPolicy(tx *types.Transaction) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	if tx.IsSystemTransaction() {
		return nil
	}
	if tx.GasLimit == nil || tx.GasPrice == nil {
		return fmt.Errorf("missing gas fields")
	}

	_, _, _, requiredFee, err := bc.EstimateTransactionPolicyCost(tx)
	if err != nil {
		return err
	}
	offeredFee := tx.GetGasFee()
	if offeredFee.Cmp(requiredFee) < 0 {
		return fmt.Errorf("transaction fee below policy minimum: offered %s, required %s", offeredFee.String(), requiredFee.String())
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
