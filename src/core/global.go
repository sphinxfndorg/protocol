// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/global.go
// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/global.go
package core

import (
	"math/big"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/consensus"
	logger "github.com/sphinxfndorg/protocol/src/console"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
)

// genesisOnce ensures BuildBlock() runs exactly once per process.
// argon2 takes ~134s — running it 3 times (one per node) would hang for 400s+.
var (
	genesisOnce           sync.Once
	genesisHashValue      string
	genesisTimestampValue int64
	genesisCached         *types.Block
)

// genesisSignAttemptMu guards lazy re-signing of genesisCached in
// getCachedGenesisBlock. This is separate from genesisSignerMu (genesis.go),
// which only guards the registered signer pointer itself.
var genesisSignAttemptMu sync.Mutex

var genesisCommitmentMu sync.Mutex

// GetGenesisTime returns the genesis block timestamp
func (bc *Blockchain) GetGenesisTime() time.Time {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	if len(bc.chain) == 0 {
		// FIX: The old fallback returned a hardcoded Unix timestamp
		// (1732070400 = 2024-11-20), which is stale and completely
		// unrelated to whatever genesis time this deployment's chain
		// params actually define (e.g. 2026-07-07). Any caller that hit
		// this path — such as during startup before the genesis block is
		// appended to bc.chain, or a request racing block 0's commit —
		// would report a genesis year from over a year in the past
		// instead of the chain's real genesis time. Fall back to the
		// canonical genesis time already recorded in chainParams, which
		// is set before genesis block creation and does not depend on
		// bc.chain being populated.
		if bc.chainParams != nil && bc.chainParams.GenesisTime != 0 {
			logger.Warn("GetGenesisTime called with empty chain, falling back to chainParams.GenesisTime")
			return time.Unix(bc.chainParams.GenesisTime, 0)
		}
		logger.Warn("GetGenesisTime called with empty chain and no chainParams, returning current time")
		return time.Now()
	}

	// Genesis block is at height 0
	genesis := bc.chain[0]
	return time.Unix(genesis.GetTimestamp(), 0)
}

// GetValidatorStake returns the validator's recorded stake in nSPX.
func (bc *Blockchain) GetValidatorStake(validatorID string) *big.Int {
	if bc == nil || validatorID == "" {
		return nil
	}
	vs := bc.LiveValidatorSet()
	if vs == nil {
		return nil
	}
	validator, ok := vs.GetValidator(validatorID).(*consensus.StakedValidator)
	if !ok || validator == nil || validator.StakeAmount == nil {
		return nil
	}
	return new(big.Int).Set(validator.StakeAmount)
}

// GetTotalStaked returns active validator stake from the live chain state.
func (bc *Blockchain) GetTotalStaked() *big.Int {
	if bc == nil {
		return big.NewInt(0)
	}
	vs := bc.LiveValidatorSet()
	if vs == nil {
		return big.NewInt(0)
	}
	return vs.GetTotalStake()
}

// UpdateValidatorStake updates a validator's stake (for rewards/slashing)
func (bc *Blockchain) UpdateValidatorStake(validatorID string, delta *big.Int) error {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	// Placeholder - implement actual stake update logic
	logger.Info("Updating stake for validator %s by %s nSPX", validatorID, delta.String())
	return nil
}

// GetGenesisBlockDefinition returns the standardized genesis block definition
// DEPRECATED: Use GetCachedGenesisBlock() or DefaultGenesisState().BuildBlock() instead
func GetGenesisBlockDefinition() *types.BlockHeader {
	// Use the canonical genesis block from genesis.go
	canonicalGenesis := DefaultGenesisState().BuildBlock()

	// Return a copy of the header to prevent modification
	header := canonicalGenesis.Header
	return &types.BlockHeader{
		Version:    header.Version,
		Block:      header.Block, // FIX: GetHeight() reads Block, not Height — keep them in sync
		Height:     header.Height,
		Timestamp:  header.Timestamp,
		Difficulty: new(big.Int).Set(header.Difficulty),
		Nonce:      header.Nonce,
		TxsRoot:    append([]byte{}, header.TxsRoot...),
		StateRoot:  append([]byte{}, header.StateRoot...),
		GasLimit:   new(big.Int).Set(header.GasLimit),
		GasUsed:    new(big.Int).Set(header.GasUsed),
		ExtraData:  append([]byte{}, header.ExtraData...),
		Miner:      append([]byte{}, header.Miner...),
		ParentHash: append([]byte{}, header.ParentHash...),
		UnclesHash: append([]byte{}, header.UnclesHash...),
	}
}

// CreateStandardGenesisBlock creates a standardized genesis block that all nodes should use
// DEPRECATED: Use DefaultGenesisState().BuildBlock() instead
func CreateStandardGenesisBlock() *types.Block {
	// Delegate to the canonical genesis builder from genesis.go
	return DefaultGenesisState().BuildBlock()
}

// getCachedGenesisBlock builds the genesis block exactly once per process.
// It uses DefaultGenesisState() only for the cryptographic fields (timestamp,
// difficulty, gas limit, extra data) — the ChainName/ChainID in that state
// do NOT affect the block hash, so the same block is valid for all environments.
// The ChainName written to genesis_state.json is controlled by the gs passed
// to ApplyGenesisWithCachedBlock, NOT by this function.
//
// FIX: genesisOnce fires on the FIRST call from ANYWHERE in the process —
// and GetGenesisHash() (which triggers it) is called from many places that
// run well before bind.StartNode gets a chance to call core.SetGenesisSigner
// (chain-params construction in params.go, checkpoint continuity checks in
// chain_maker.go, VDF-parameter derivation, key-exchange with peers, etc).
// If any of those fire first, the ONE-TIME BuildBlock() call inside
// genesisOnce.Do happens before a signer is registered, and the resulting
// genesisCached block is permanently frozen unsigned — no later
// SetGenesisSigner call can retroactively fix it, since BuildBlock only
// signs at construction time.
//
// So signing can't safely live only inside genesisOnce.Do. Instead, every
// call to getCachedGenesisBlock() checks whether genesisCached still lacks
// a producer signature and a signer is now registered, and signs it in
// place if so. This is safe because BuildBlock signs strictly AFTER
// FinalizeHash — the signature never affects the hash, so mutating
// genesisCached's signature after the fact doesn't change its identity.
// This must happen before the caller persists the block (see
// createGenesisBlock in blockchain.go, which calls this function and then
// hands the result straight to ApplyGenesisWithCachedBlock/StoreBlock) —
// SetGenesisSigner must be called before NewBlockchain/FinishInit for that
// ordering to hold.
func getCachedGenesisBlock() *types.Block {
	genesisOnce.Do(func() {
		// DefaultGenesisState() provides the canonical cryptographic inputs.
		// ChainName here is irrelevant to the hash — only timestamp, difficulty,
		// gas limit, and extra data feed into BuildBlock() → FinalizeHash().
		gs := DefaultGenesisState()

		// A policy-owned vault MUST authorize its block-0 distributions by
		// M-of-N agreement (tx_auth.custodyPolicyOwns makes the unsigned
		// genesis exemption unavailable to such a vault). When an authorizer is
		// registered — devnet auto-custody, or a real ceremony's — build block 0
		// through the custody path so the witnesses are part of the body, hence
		// part of TxsRoot, hence part of the hash every node recomputes.
		auth, authChainID := getGenesisDistributionAuthorizer()
		if auth != nil {
			genesisCached = gs.BuildBlockWithCustody(auth, authChainID)
			logger.Info("Genesis block built WITH M-of-N custody witnesses (chainID=%d, vault=%s)",
				authChainID, GenesisVaultAddress)
		} else {
			genesisCached = gs.BuildBlock()

			// No authorizer, yet the vault resolves to a custody policy: this
			// block cannot authorize its own distributions, so surface that here
			// instead of letting it fail later as a confusing block-0 error.
			if custodyPolicyOwns(GenesisVaultAddress) {
				logger.Error("genesis vault %s is a custody policy but the genesis block was built UNSIGNED: block-0 distributions require M-of-N witnesses — build block 0 with GenesisState.BuildBlockWithCustody before starting this node", GenesisVaultAddress)
			}
		}

		genesisHashValue = genesisCached.GetHash()
		genesisTimestampValue = gs.Timestamp
		logger.Info("Genesis block computed once: %s at timestamp %d",
			genesisHashValue, genesisTimestampValue)

		// Let the producer persist the witness set, so peers that hold no
		// custodian keys can rebuild the identical block 0 (core/devnet_custody.go).
		if sink := getGenesisWitnessSink(); sink != nil {
			if err := sink(genesisCached); err != nil {
				logger.Error("genesis witness sink failed: %v", err)
			}
		}
	})
	ensureCachedGenesisCommitments(genesisCached)
	signGenesisIfPossible(genesisCached)
	return genesisCached
}

func ensureCachedGenesisCommitments(block *types.Block) {
	genesisCommitmentMu.Lock()
	defer genesisCommitmentMu.Unlock()
	if block == nil || block.Header == nil ||
		(block.Header.ActiveSnapshotHash != "" && block.Header.GenesisDocumentDigest != "") {
		return
	}
	digest, snapshotHash, err := genesisHeaderCommitments()
	if err != nil {
		logger.Error("genesis commitment refresh failed: %v", err)
		return
	}
	if digest == "" || snapshotHash == "" {
		return
	}
	block.Header.ActiveSnapshotHash = snapshotHash
	block.Header.GenesisDocumentDigest = digest
	block.Header.ProposerSignature = nil
	block.Header.SigValid = false
	block.FinalizeHash()
	genesisHashValue = block.GetHash()
	logger.Info("Genesis commitments attached: snapshot=%s document=%s",
		snapshotHash, digest)
}

// signGenesisIfPossible attaches a producer signature to the cached genesis
// block if it doesn't have one yet and a signer has since been registered
// via SetGenesisSigner. See the FIX comment on getCachedGenesisBlock for why
// this can't just happen once inside genesisOnce.Do.
func signGenesisIfPossible(block *types.Block) {
	if block == nil || block.Header == nil || len(block.Header.ProposerSignature) > 0 {
		return
	}
	signer, signerNodeID := getGenesisSigner()
	if signer == nil || signerNodeID == "" {
		return
	}

	genesisSignAttemptMu.Lock()
	defer genesisSignAttemptMu.Unlock()

	// Re-check under the lock — another goroutine may have signed it while
	// this one was waiting (e.g. concurrent key-exchange calls that both
	// call GetGenesisHash()).
	if len(block.Header.ProposerSignature) > 0 {
		return
	}

	block.Header.ProposerID = signerNodeID
	wrapped := NewBlockHelper(block)
	if err := signer.SignBlock(wrapped); err != nil {
		logger.Warn("getCachedGenesisBlock: failed to lazily sign genesis block: %v", err)
		return
	}
	wrapped.SetSigValid(true)
	logger.Info("SUCCESS Genesis block signed (lazily) by %s", signerNodeID)
}

// GetGenesisHash returns the computed genesis hash (computed once, cached forever).
func GetGenesisHash() string {
	getCachedGenesisBlock()
	return genesisHashValue
}

// GetGenesisTimestamp returns the frozen genesis timestamp (computed once, cached forever).
// This is the actual Unix timestamp used when building the genesis block, and is
// identical across all nodes in the network because it is captured at the same
// time as the genesis hash via sync.Once.
func GetGenesisTimestamp() int64 {
	getCachedGenesisBlock() // ensure computed
	return genesisTimestampValue
}

// LocalGenesisAnchor returns the genesis block THIS NODE has independently
// derived, for use as the trust anchor when a peer offers a genesis block.
//
// ★ WHY A LATE JOINER NEEDS THIS. A late joiner deliberately does not execute
// genesis: it skips ExecuteGenesisBlock and waits to sync block 0 from a peer
// (see the "Late-joiner mode" log line in bind.StartNodeWithOptions). That
// leaves bc.GetBlockByNumber(0) == nil, so the sync loop's guard
//
//	VerifyPeerGenesis(peerGenesis, bc.GetBlockByNumber(0))
//
// was handed a nil anchor and refused EVERY genesis with "no local genesis
// block to verify the peer's against" — the joiner could never adopt genesis,
// so it sat at height 0 forever even though it had peers.
//
// The anchor does not have to be a STORED block: a joiner has already built
// the identical block 0 in memory from its own genesis document — one it either
// authored itself or fetched and verified from the bootstrap node before
// startup (EnsureDevnetBundleFromSeeds). That derivation is independent of the
// peer now offering a genesis, which is exactly what the guard needs. Returning
// it restores the comparison without weakening any check: VerifyPeerGenesis
// still requires the document digest, the active-snapshot hash AND the full
// block hash to match, and the block hash covers the allocation list, so a peer
// cannot substitute its own distribution.
//
// Returns nil only if the genesis block could not be derived at all, in which
// case the caller must keep failing closed.
func LocalGenesisAnchor() *types.Block {
	return getCachedGenesisBlock()
}

// GenerateGenesisHash is deprecated - use GetGenesisHash instead for consistency
func GenerateGenesisHash() string {
	logger.Warn("GenerateGenesisHash is deprecated, using GetGenesisHash for consistency")
	return GetGenesisHash()
}

// ============================================================================
// SUPPLY STATUS HELPERS - Quick access to supply info
// ============================================================================

// GetMaxSupplySPX returns the maximum supply in whole SPX
func GetMaxSupplySPX() *big.Int {
	return new(big.Int).SetInt64(denom.MaxSupplySPX)
}

// GetMaxSupplyNSPX returns the maximum supply in nSPX
func GetMaxSupplyNSPX() *big.Int {
	return new(big.Int).Mul(
		big.NewInt(denom.MaxSupplySPX),
		big.NewInt(denom.SPX),
	)
}

// GetGenesisVaultAddress returns the genesis vault address constant
func GetGenesisVaultAddressLegacy() string {
	return GenesisVaultAddress
}
