// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/params.go
package core

import (
	"fmt"
	"math/big"
	"time"

	"github.com/sphinxfndorg/protocol/src/accounts/key"
	"github.com/sphinxfndorg/protocol/src/consensus"
	logger "github.com/sphinxfndorg/protocol/src/console"
	"github.com/sphinxfndorg/protocol/src/core/rawdb"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	"github.com/sphinxfndorg/protocol/src/params/commit"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
	"github.com/sphinxfndorg/protocol/src/policy"
	"github.com/sphinxfndorg/protocol/src/pool"
)

// GetChainParams returns the chain parameters from the mock provider
// This implements the ChainParamsProvider interface
func (m *MockChainParamsProvider) GetChainParams() *SphinxChainParameters {
	return m.params // Return the stored parameters
}

// NetworkNames provides a single source of truth for network display names
var NetworkNames = map[string]string{
	"devnet":  "Sphinx Devnet",
	"testnet": "Sphinx Testnet",
	"mainnet": "Sphinx Mainnet",
}

// Epoch-length defaults, in BLOCKS. These are chain parameters: consensus
// computes epoch(h) = h / EpochBlocks from them (or from the genesis file's
// value, which wins — see SetGenesisEpochBlocks). They are never read from a
// CLI flag.
//
// ★ DefaultEpochBlocks is an ALIAS of consensus.DefaultEpochBlocks, not a
// second copy. It used to be an independent `const ... = 1000` here, so a
// change to the epoch length in one package silently failed to apply in the
// other. The default and the genesis value now come from exactly one place:
// consensus.epochBlocksOverride, which consensus.SetEpochBlocks is the only
// writer of.
const (
	// DefaultEpochBlocks is the production epoch length: large, so epoch
	// boundaries (validator activations/exits, inflation) are rare events.
	DefaultEpochBlocks = consensus.DefaultEpochBlocks
	// DevnetEpochBlocks is the small devnet epoch length the devnet genesis
	// helper writes into the genesis file, so devnet tests see epoch
	// boundaries without producing thousands of blocks.
	DevnetEpochBlocks uint64 = 10
)

// SetGenesisEpochBlocks records the EpochBlocks value the genesis file
// carries. Must be called before chain params are first constructed (i.e.
// before core.NewBlockchain). Zero is a no-op.
//
// It no longer stores anything here: consensus owns the single epoch parameter,
// so forwarding to it is the whole job. There used to be a core-local
// `genesisEpochBlocksOvrd` as well, and the two could disagree.
func SetGenesisEpochBlocks(n uint64) {
	consensus.SetEpochBlocks(n)
}

// effectiveEpochBlocks returns the genesis-file value when one was supplied,
// else the per-network default, and reads the answer from consensus — the one
// place the epoch parameter lives.
func effectiveEpochBlocks(def uint64) uint64 {
	if n := consensus.EpochBlocksOverride(); n != 0 {
		return n
	}
	return def
}

// GetNetworkDisplayName returns the human-readable name for a network phase
func GetNetworkDisplayName(phase string) string {
	if name, ok := NetworkNames[phase]; ok {
		return name
	}
	return phase // fallback
}

// GetNetworkDisplayNameFromParams returns the display name from chain parameters
func (p *SphinxChainParameters) GetNetworkDisplayName() string {
	switch {
	case p.IsDevnet():
		return NetworkNames["devnet"]
	case p.IsTestnet():
		return NetworkNames["testnet"]
	default:
		return NetworkNames["mainnet"]
	}
}

// GetWalletDerivationPaths now delegates to the centralized keystore package
// Returns the appropriate BIP44 derivation paths for the current network
func (m *MockChainParamsProvider) GetWalletDerivationPaths() map[string]string {
	// Get the appropriate keystore config based on chain parameters
	var keystoreConfig *key.KeystoreConfig

	// Select the correct keystore configuration based on network type
	switch {
	case m.params.IsMainnet():
		keystoreConfig = key.GetMainnetKeystoreConfig()
	case m.params.IsTestnet():
		keystoreConfig = key.GetTestnetKeystoreConfig()
	case m.params.IsDevnet():
		keystoreConfig = key.GetDevnetKeystoreConfig()
	default:
		// Fallback to mainnet if network type cannot be determined
		keystoreConfig = key.GetMainnetKeystoreConfig()
	}

	// Return the wallet derivation paths from the selected keystore config
	return keystoreConfig.GetWalletDerivationPaths()
}

func getSphinxChainParams(includeGenesis bool) *SphinxChainParameters {
	genesisHash := ""
	genesisTime := CanonicalGenesisTimestamp
	if includeGenesis {
		// Use the STANDARDIZED genesis hash that all nodes will use.
		// This intentionally builds the cached genesis block, so callers that
		// may still need to author a devnet genesis document must opt out.
		genesisHash = GetGenesisHash()
		genesisTime = GetGenesisTimestamp()
	}

	// Use the canonical extra data from DefaultGenesisState() to ensure consistency
	// This guarantees the genesis extra data matches genesis.go
	canonicalExtraData := DefaultGenesisState().ExtraData

	// Get base chain parameters from commit package
	baseParams := commit.SphinxChainParams()

	// Return complete mainnet configuration with proper type conversions
	return &SphinxChainParameters{
		// Network Identification - unique identifiers for the blockchain
		ChainID:       baseParams.ChainID,               // uint64
		ChainName:     baseParams.ChainName,             // string
		Symbol:        baseParams.Symbol,                // string
		GenesisTime:   genesisTime,                      // int64 — frozen genesis timestamp (identical across all nodes)
		GenesisHash:   genesisHash,                      // Genesis block hash
		Version:       baseParams.Version,               // string
		MagicNumber:   baseParams.MagicNumber,           // uint32
		DefaultPort:   int(baseParams.DefaultPort),      // uint16 -> int
		BIP44CoinType: uint64(baseParams.BIP44CoinType), // uint32 -> uint64
		LedgerName:    baseParams.LedgerName,            // string

		// Denominations - unit conversions for the native token
		Denominations: map[string]*big.Int{
			"nSPX": big.NewInt(1),    // Base unit (nano SPX) - smallest unit
			"gSPX": big.NewInt(1e9),  // Giga SPX = 1,000,000,000 nSPX
			"SPX":  big.NewInt(1e18), // Main unit = 1,000,000,000,000,000,000 nSPX
		},

		// Block Configuration - size and gas limits
		MaxBlockSize:       2 * 1024 * 1024,      // 2MB - maximum block size
		MaxTransactionSize: 100 * 1024,           // 100KB - maximum transaction size
		TargetBlockSize:    1 * 1024 * 1024,      // 1MB - target block size for optimization
		BlockGasLimit:      big.NewInt(10000000), // 10 million gas - maximum gas per block

		// Genesis-specific configuration.
		// NOTE: The actual genesis block is always built from
		// DefaultGenesisState() via getCachedGenesisBlock(), so the fields
		// below MUST match DefaultGenesisState() or be left at their zero
		// values.  GenesisNonce is intentionally omitted (zero) because the
		// canonical genesis block always uses nonce=1
		// (common.FormatNonce(1) → "0000000000000001") and any override
		// here would be silently ignored by the cached-block path.
		GenesisConfig: &GenesisConfig{
			InitialDifficulty: big.NewInt(17179869184), // MUST match DefaultGenesisState()
			InitialGasLimit:   big.NewInt(5000),        // MUST match DefaultGenesisState()
			GenesisExtraData:  canonicalExtraData,      // Use canonical extra data from genesis.go
		},

		// Mempool Configuration - transaction pool settings
		MempoolConfig: GetDefaultMempoolConfig(),

		// Consensus Configuration - PBFT/RANDAO settings
		ConsensusConfig: GetDefaultConsensusConfig(),

		// Epoch length in blocks (chain parameter, never a flag).
		EpochBlocks: effectiveEpochBlocks(DefaultEpochBlocks),

		// Performance Configuration - node optimization settings
		PerformanceConfig: GetDefaultPerformanceConfig(),
	}
}

// GetSphinxChainParams returns the mainnet parameters.
// This is the primary function that defines all mainnet chain parameters.
func GetSphinxChainParams() *SphinxChainParameters {
	return getSphinxChainParams(true)
}

// GetSphinxChainHeader returns ONLY the header fields needed for Ledger headers and wallet operations.
// This does NOT initialize the blockchain/genesis block - it's lightweight and fast.
func GetSphinxChainHeader() *SphinxChainHeader {
	// Get base chain parameters from commit package (no blockchain init)
	baseParams := commit.SphinxChainParams()

	// Return only the fields needed for Ledger headers
	return &SphinxChainHeader{
		ChainID:       baseParams.ChainID,
		ChainName:     baseParams.ChainName,
		Symbol:        baseParams.Symbol,
		MagicNumber:   baseParams.MagicNumber,
		LedgerName:    baseParams.LedgerName,
		BIP44CoinType: uint64(baseParams.BIP44CoinType),
	}
}

// GetMainnetChainHeader returns mainnet header WITHOUT initializing genesis.
func GetMainnetChainHeader() *SphinxChainHeader {
	return GetSphinxChainHeader()
}

// GetDefaultMempoolConfig returns the default mempool configuration
// Defines how the transaction pool behaves
func GetDefaultMempoolConfig() *pool.MempoolConfig {
	return &pool.MempoolConfig{
		MaxSize:           10000,                // Maximum number of transactions in mempool
		MaxBytes:          100 * 1024 * 1024,    // 100MB - maximum mempool size in bytes
		MaxTxSize:         100 * 1024,           // 100KB - maximum transaction size
		BlockGasLimit:     big.NewInt(10000000), // 10 million gas - matches block gas limit
		ValidationTimeout: 30 * time.Second,     // Timeout for transaction validation
		ExpiryTime:        24 * time.Hour,       // How long transactions stay in mempool
		MaxBroadcastSize:  5000,                 // Maximum transactions to broadcast at once
		MaxPendingSize:    5000,                 // Maximum pending transactions
	}
}

// GetDefaultConsensusConfig returns the default consensus configuration
// Defines how the PBFT consensus with RANDAO operates
func GetDefaultConsensusConfig() *ConsensusConfig {
	// Minimum stake to become a validator. The "32 SPX" value is owned by the
	// shared denom package (MinValidatorStakeSPX) — core, consensus and policy
	// all derive from the same constant instead of re-declaring 32 × 1e18.
	minStakeNSPX := denom.MinValidatorStakeNSPX()

	return &ConsensusConfig{
		BlockTime:        10 * time.Second,               // Target time between blocks
		EpochLength:      100,                            // Number of slots per epoch
		ValidatorSetSize: 21,                             // Number of active validators
		MaxValidators:    100,                            // Maximum total validators
		MinStakeAmount:   minStakeNSPX,                   // Minimum stake to become validator (32 SPX)
		UnbondingPeriod:  7 * 24 * time.Hour,             // 7 days - time to unbond stake
		SlashingEnabled:  true,                           // Enable slashing for misbehavior
		DoubleSignSlash:  big.NewInt(500000000000000000), // 0.5 SPX penalty for double signing
	}
}

// GetDefaultPerformanceConfig returns the default performance configuration
// Defines node performance and optimization settings
func GetDefaultPerformanceConfig() *PerformanceConfig {
	return &PerformanceConfig{
		MaxConcurrentValidations: 100,              // Maximum parallel transaction validations
		ValidationTimeout:        30 * time.Second, // Timeout for validation operations
		CacheSize:                10000,            // Size of various caches
		PruningInterval:          5 * time.Minute,  // How often to prune old data
		MaxPeers:                 50,               // Maximum number of peer connections
		SyncBatchSize:            100,              // Blocks per sync batch
	}
}

// GetTestnetChainParams returns testnet parameters
// Testnet is used for testing before mainnet deployment
// Uses commit.TestnetChainParams() for base parameters
func GetTestnetChainParams() *SphinxChainParameters {
	params := GetSphinxChainParams()

	// Get testnet base parameters from commit package
	testnetBase := commit.TestnetChainParams()

	params.ChainID = testnetBase.ChainID                     // uint64
	params.ChainName = testnetBase.ChainName                 // string
	params.DefaultPort = int(testnetBase.DefaultPort)        // uint16 -> int
	params.BIP44CoinType = uint64(testnetBase.BIP44CoinType) // uint32 -> uint64
	params.LedgerName = testnetBase.LedgerName               // string
	params.MagicNumber = testnetBase.MagicNumber             // uint32
	params.Symbol = testnetBase.Symbol                       // string
	// GenesisTime must remain canonical — do NOT override from testnetBase
	// params.GenesisTime = testnetBase.GenesisTime // REMOVED — use canonical
	params.Version = testnetBase.Version // string

	// Inherit the devnet genesis hash — testnet continues from the same genesis
	// block, so nodes that started on devnet can verify the ancestry.
	params.GenesisHash = GetGenesisHash() // same hash, same block 0

	// Looser block limits for public testnet
	params.MaxBlockSize = 4 * 1024 * 1024
	params.BlockGasLimit = big.NewInt(20000000)

	params.ConsensusConfig.BlockTime = 5 * time.Second
	params.ConsensusConfig.EpochLength = 50

	return params
}

// GetMainnetChainParams inherits genesis from testnet/devnet lineage.
// The genesis block is identical across all environments; only operational
// parameters (ports, gas limits, block times) change per environment.
func GetMainnetChainParams() *SphinxChainParameters {
	// Get mainnet base parameters from commit package
	baseParams := commit.SphinxChainParams()
	params := GetSphinxChainParams()

	// Ensure mainnet parameters match commit package with proper type conversions
	params.ChainID = baseParams.ChainID     // uint64
	params.ChainName = baseParams.ChainName // string
	params.Symbol = baseParams.Symbol       // string
	// GenesisTime must remain canonical — do NOT override from baseParams
	// params.GenesisTime = baseParams.GenesisTime // REMOVED — use canonical
	params.Version = baseParams.Version                     // string
	params.MagicNumber = baseParams.MagicNumber             // uint32
	params.DefaultPort = int(baseParams.DefaultPort)        // uint16 -> int
	params.BIP44CoinType = uint64(baseParams.BIP44CoinType) // uint32 -> uint64
	params.LedgerName = baseParams.LedgerName               // string

	// GenesisHash is already set by GetSphinxChainParams → GetGenesisHash().
	// No override needed — mainnet shares the same genesis ancestry.
	return params
}

// GetDevnetChainParams returns development network parameters
// Devnet is used for local development and debugging
func GetDevnetChainParams() *SphinxChainParameters {
	params := getSphinxChainParams(false)

	// Devnet uses custom parameters (not defined in commit package)
	params.ChainName = NetworkNames["devnet"] // "Sphinx Devnet"
	params.ChainID = 73310
	params.DefaultPort = 32309
	params.BIP44CoinType = 1
	params.LedgerName = "Sphinx Devnet"

	// NOTE: The genesis hash MUST remain identical across all network phases
	// (devnet/testnet/mainnet) because:
	//   1. VDF discriminant → RANDAO seed → leader election must be identical
	//      on every node regardless of phase; a phase-specific hash would
	//      produce different VDF parameters and permanently fork the chain.
	//   2. Chain compatibility checks (ValidateChainCompatibility) compare
	//      genesis hashes — peers on different phases must still agree.
	//   3. All nodes share the same genesis block 0 regardless of phase.
	// Do NOT add a "DEVNET_" prefix here or anywhere else. Leave the hash empty
	// during cold devnet startup so parameter resolution cannot build block 0
	// before StartNode authors the validator set. FinishInit fills the actual
	// hash once the genesis block exists.

	params.MaxBlockSize = 8 * 1024 * 1024
	params.BlockGasLimit = big.NewInt(50000000)

	params.ConsensusConfig.BlockTime = 2 * time.Second
	params.ConsensusConfig.EpochLength = 10

	// Devnet uses a SMALL epoch length in blocks so tests observe epoch
	// boundaries quickly. A genesis file's epoch_blocks value still wins
	// (effectiveEpochBlocks), so the genesis document can override this.
	params.EpochBlocks = effectiveEpochBlocks(DevnetEpochBlocks)

	devnetMinStake := new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18))
	params.ConsensusConfig.MinStakeAmount = devnetMinStake

	return params
}

// GetMempoolConfigFromChainParams extracts mempool config from chain params
// Helper function to safely access mempool configuration
func GetMempoolConfigFromChainParams(chainParams *SphinxChainParameters) *pool.MempoolConfig {
	// Handle nil parameters or missing mempool config
	if chainParams == nil || chainParams.MempoolConfig == nil {
		return GetDefaultMempoolConfig() // Fallback to defaults
	}
	return chainParams.MempoolConfig
}

// ValidateChainParams validates the chain parameters
// Ensures all parameters are within acceptable ranges and consistent
func ValidateChainParams(params *SphinxChainParameters) error {
	// Check for nil parameters
	if params == nil {
		return fmt.Errorf("chain parameters cannot be nil")
	}

	// Chain ID must be non-zero (unique identifier)
	if params.ChainID == 0 {
		return fmt.Errorf("chain ID cannot be zero")
	}

	// Block size must be positive
	if params.MaxBlockSize == 0 {
		return fmt.Errorf("max block size cannot be zero")
	}

	// Transaction size cannot exceed block size
	if params.MaxTransactionSize > params.MaxBlockSize {
		return fmt.Errorf("max transaction size cannot exceed max block size")
	}

	// Gas limit must be positive
	if params.BlockGasLimit == nil || params.BlockGasLimit.Cmp(big.NewInt(0)) <= 0 {
		return fmt.Errorf("block gas limit must be positive")
	}

	// Mempool transaction size cannot exceed chain max transaction size
	if params.MempoolConfig != nil {
		if params.MempoolConfig.MaxTxSize > params.MaxTransactionSize {
			return fmt.Errorf("mempool max transaction size cannot exceed chain max transaction size")
		}
	}

	return nil
}

// GetNetworkName returns human-readable network name
// Delegates to commit package for consistent naming
func (p *SphinxChainParameters) GetNetworkName() string {
	// Use commit package's GetNetworkName for consistency
	switch p.ChainID {
	case 73310:
		return "Sphinx Devnet"
	case 7331:
		return "Sphinx Mainnet"
	case 17331:
		return "Sphinx Testnet"
	default:
		return "Sphinx Devnet"
	}
}

// IsDevnet no longer needs ChainName as tiebreaker
func (p *SphinxChainParameters) IsDevnet() bool {
	return p.ChainID == 73310
}

// IsMainnet is now unambiguous
func (p *SphinxChainParameters) IsMainnet() bool {
	return p.ChainID == 7331
}

// IsTestnet returns true if this is testnet configuration
// Identifies test network
func (p *SphinxChainParameters) IsTestnet() bool {
	return p.ChainID == 17331
}

// GetStakeDenomination returns the stake denomination
// Returns the human-readable unit for stake amounts
func (p *SphinxChainParameters) GetStakeDenomination() string {
	return "SPX"
}

// ConvertToBaseUnits converts amount to base units (nSPX)
// Converts from any denomination to the smallest unit
func (p *SphinxChainParameters) ConvertToBaseUnits(amount *big.Int, fromDenom string) (*big.Int, error) {
	// Look up the multiplier for the source denomination
	multiplier, exists := p.Denominations[fromDenom]
	if !exists {
		return nil, fmt.Errorf("unknown denomination: %s", fromDenom)
	}
	// Multiply amount by multiplier to get base units
	return new(big.Int).Mul(amount, multiplier), nil
}

// ConvertFromBaseUnits converts amount from base units to target denomination
// Converts from smallest unit to any other denomination
func (p *SphinxChainParameters) ConvertFromBaseUnits(amount *big.Int, toDenom string) (*big.Int, error) {
	// Look up the multiplier for the target denomination
	multiplier, exists := p.Denominations[toDenom]
	if !exists {
		return nil, fmt.Errorf("unknown denomination: %s", toDenom)
	}
	// Divide amount by multiplier to get target denomination
	return new(big.Int).Div(amount, multiplier), nil
}

// GetKeystoreConfig returns the appropriate keystore configuration for these chain parameters
// Provides the correct key management settings for the current network
func (p *SphinxChainParameters) GetKeystoreConfig() *key.KeystoreConfig {
	switch {
	case p.IsMainnet():
		return key.GetMainnetKeystoreConfig()
	case p.IsTestnet():
		return key.GetTestnetKeystoreConfig()
	case p.IsDevnet():
		return key.GetDevnetKeystoreConfig()
	default:
		// Default to mainnet for safety
		return key.GetMainnetKeystoreConfig()
	}
}

// GenerateLedgerHeaders generates headers specifically formatted for Ledger hardware
// This method now delegates to the commit package's header generator
func (p *SphinxChainParameters) GenerateLedgerHeaders(operation string, amount float64, address string, memo string) string {
	// Delegate to commit package's header generator
	return commit.GenerateLedgerHeaders(operation, amount, address, memo)
}

// GetRecommendedBlockSize returns a recommended block size (could be target or a percentage of max)
// Provides an optimal block size for miners/validators
func (p *SphinxChainParameters) GetRecommendedBlockSize() uint64 {
	// Use target size if set and valid, otherwise use 90% of max size
	if p.TargetBlockSize > 0 && p.TargetBlockSize < p.MaxBlockSize {
		return p.TargetBlockSize
	}
	// Default to 90% of maximum to leave room for growth
	return p.MaxBlockSize * 90 / 100
}

// NetworkPhase returns the ChainPhase constant matching this parameter set.
// Used by chain_phase.go to determine operational mode without importing
// the chain_phase package (avoids a circular dependency).
func (p *SphinxChainParameters) NetworkPhase() string {
	switch {
	case p.IsDevnet():
		return "devnet"
	case p.IsTestnet():
		return "testnet"
	default:
		return "mainnet"
	}
}

// GetEpochInflation calculates inflation for a specific epoch
func (p *SphinxChainParameters) GetEpochInflation(
	totalSupply *big.Int,
	year uint64,
	currentStakeRatio float64,
) *policy.InflationDistribution {
	govPolicy := p.GetGovernancePolicy()
	return govPolicy.CalculateEpochInflation(totalSupply, year, currentStakeRatio)
}

// GetAnnualMinting calculates total tokens minted in a specific year
func (p *SphinxChainParameters) GetAnnualMinting(
	totalSupply *big.Int,
	year uint64,
	currentStakeRatio float64,
) *big.Int {
	govPolicy := p.GetGovernancePolicy()
	return govPolicy.GetAnnualMinting(totalSupply, year, currentStakeRatio)
}

// rawdbSnapshotStore is the production SnapshotStore: it puts snapshots into
// rawdb under the vsnap: namespace and reads them all back on replay.
//
// It lives in core rather than consensus because rawdb is a core subpackage;
// consensus depends only on the SnapshotStore interface, so the storage layer
// does not leak into the epoch arithmetic.
type rawdbSnapshotStore struct{ db *database.DB }

func (s *rawdbSnapshotStore) PutSnapshot(epoch uint64, snap *consensus.ValidatorSnapshot) error {
	if snap == nil {
		return fmt.Errorf("nil snapshot for epoch %d", epoch)
	}
	row := &rawdb.ValidatorSnapshotRow{
		Epoch:      snap.Epoch,
		TotalStake: snap.TotalStake.String(),
		Validators: make(map[string]rawdb.VSRow, len(snap.Validators)),
	}
	for id, v := range snap.Validators {
		if v == nil {
			continue
		}
		stake := "0"
		if v.StakeAmount != nil {
			stake = v.StakeAmount.String()
		}
		row.Validators[id] = rawdb.VSRow{
			Stake:           stake,
			RewardAddress:   v.RewardAddress,
			ActivationEpoch: v.ActivationEpoch,
			ExitEpoch:       v.ExitEpoch,
			IsSlashed:       v.IsSlashed,
		}
	}
	return rawdb.WriteValidatorSnapshot(s.db, row)
}

func (s *rawdbSnapshotStore) AllSnapshots() ([]*consensus.ValidatorSnapshot, error) {
	rows, err := rawdb.ReadAllValidatorSnapshots(s.db)
	if err != nil {
		return nil, err
	}
	out := make([]*consensus.ValidatorSnapshot, 0, len(rows))
	for _, row := range rows {
		total, ok := new(big.Int).SetString(row.TotalStake, 10)
		if !ok {
			return nil, fmt.Errorf("rawdb: unparseable total %q in epoch %d", row.TotalStake, row.Epoch)
		}
		snap := &consensus.ValidatorSnapshot{
			Epoch:      row.Epoch,
			TotalStake: total,
			Validators: make(map[string]*consensus.StakedValidator, len(row.Validators)),
		}
		for id, v := range row.Validators {
			stake, ok := new(big.Int).SetString(v.Stake, 10)
			if !ok {
				return nil, fmt.Errorf("rawdb: unparseable stake %q for %s in epoch %d", v.Stake, id, row.Epoch)
			}
			snap.Validators[id] = &consensus.StakedValidator{
				ID:              id,
				StakeAmount:     stake,
				RewardAddress:   v.RewardAddress,
				ActivationEpoch: v.ActivationEpoch,
				ExitEpoch:       v.ExitEpoch,
				IsSlashed:       v.IsSlashed,
			}
		}
		out = append(out, snap)
	}
	return out, nil
}

// AttachSnapshotStore wires consensus's snapshot store to this node's rawdb and
// replays any snapshots already on disk into memory.
//
// It MUST be called during node startup, before the node verifies or accepts
// any block. Without the replay, a node restarting mid-epoch has no snapshot for
// the epoch it is currently serving, and VerifyBlockAttestations correctly — but
// uselessly — fails closed on every block until it re-crosses a boundary.
func (bc *Blockchain) AttachSnapshotStore() error {
	db, err := bc.storage.GetDB()
	if err != nil {
		return fmt.Errorf("core: attaching snapshot store: %w", err)
	}
	// ★★ CHECKPOINT 2 ITEM 0b — PARTICIPATION GATE FIRST.
	//
	// Set the flag BEFORE any rebuild attempt so that a failure to rebuild
	// leaves the node refusing to participate, rather than starting and
	// becoming the proposer the rest of the network is waiting on. It is
	// cleared only at the end, after every epoch up to the tip is proven to
	// have a snapshot.
	consensus.SetSnapshotRebuildPending(true)

	consensus.SetSnapshotStore(&rawdbSnapshotStore{db: db})

	// 1. Replay whatever reached disk. Missing entries are handled below.
	if n, err := consensus.ReplaySnapshotsFromStore(); err != nil {
		logger.Warn("Validator snapshot replay found nothing to restore: %v", err)
	} else {
		logger.Info("Validator snapshot store attached: %d snapshot(s) restored from disk", n)
	}

	// 2. Rebuild any epoch the chain says should exist but the store does not
	// have — the crash window between StoreBlock and the snapshot write.
	if err := bc.rebuildMissingSnapshots(); err != nil {
		// Leave the gate SET: a node that cannot rebuild its history must not
		// participate.
		logger.Error("FATAL snapshot rebuild failed: %v — this node will REFUSE to "+
			"participate in consensus until it is repaired", err)
		return err
	}

	consensus.SetSnapshotRebuildPending(false)
	return nil
}

// rebuildMissingSnapshots walks the epochs the chain has actually reached and
// rebuilds every snapshot the store is missing.
//
// ★ THE CRASH WINDOW THIS CLOSES. CommitBlock writes the BLOCK (line 2051)
// and the SNAPSHOT (now a few lines later) as two separate rawdb puts. A crash
// between them leaves a committed block at height h with no snapshot for the
// epoch that block opens. On restart the replay finds the gap and fails closed
// on that epoch's blocks forever — correct, but unusable.
//
// ★ WHY REPLAYING THE TRANSITION IS EXACT, NOT AN APPROXIMATION.
// ProcessEpochTransition(e) reads only per-validator ActivationEpoch, ExitEpoch
// and IsSlashed — all of which are set at admission/queue time and never
// mutated afterwards — and derives the total for epoch e from those. So
// replaying epochs in ascending order reproduces exactly the set that was in
// effect at epoch e, even though this node is now past it. The snapshots
// written this way are byte-for-byte what the original commit would have
// written.
//
// Note it runs ProcessEpochTransition for EVERY epoch up to the tip, not only
// the missing ones: the live set's currentEpoch must end at the tip, or
// GetTotalStake() would evaluate membership one epoch behind the chain.
func (bc *Blockchain) rebuildMissingSnapshots() error {
	vs := bc.liveValidatorSet()
	if vs == nil {
		// No validator set attached (e.g. a node that has not finished
		// seeding). There is nothing to rebuild and nothing to verify yet, so
		// this is not a failure.
		logger.Warn("No validator set attached; skipping snapshot rebuild")
		return nil
	}

	// The highest height this node has on disk is the chain it must be able to
	// verify. Genesis-only storage yields 0, so the loop still establishes the
	// epoch-0 snapshot.
	var tipHeight uint64
	if tip, err := bc.storage.GetLatestBlock(); err == nil && tip != nil {
		tipHeight = tip.GetHeight()
	}
	tipEpoch := consensus.EpochForHeight(tipHeight)

	rebuilt := 0
	for e := uint64(0); e <= tipEpoch; e++ {
		missing := consensus.SnapshotAtEpoch(e) == nil
		if e == 0 {
			// Genesis is authored: no transition, only the freeze. Taken
			// without mutation so a rebuild cannot alter the genesis set.
			if missing {
				vs.TakeSnapshot(0)
				rebuilt++
			}
			continue
		}
		vs.ProcessEpochTransition(e)
		if missing {
			vs.TakeSnapshot(e)
			rebuilt++
			logger.Info("Rebuilt missing snapshot for epoch %d from chain state", e)
		}
	}

	// Prove it: a gap that could not be repaired must not be papered over.
	for e := uint64(0); e <= tipEpoch; e++ {
		if consensus.SnapshotAtEpoch(e) == nil {
			return fmt.Errorf("epoch %d still has no snapshot after rebuild (tip height %d, tip epoch %d)",
				e, tipHeight, tipEpoch)
		}
	}

	if rebuilt > 0 {
		logger.Info("Snapshot rebuild complete: %d epoch(s) rebuilt, %d epoch(s) verified present "+
			"(tip height %d)", rebuilt, tipEpoch+1, tipHeight)
	} else {
		logger.Info("Snapshot history complete: %d epoch(s) present, nothing to rebuild (tip height %d)",
			tipEpoch+1, tipHeight)
	}
	return nil
}
