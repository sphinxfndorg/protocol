// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/types.go
package core

import (
	"math/big"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/consensus"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/pool"
	storage "github.com/sphinxfndorg/protocol/src/state"
)

// BlockchainStatus represents the current status of the blockchain
type BlockchainStatus int

// SyncMode represents different synchronization modes for the blockchain
type SyncMode int

// BlockImportResult represents the outcome of importing a new block
type BlockImportResult int

// CacheType represents different types of caches used in the blockchain
type CacheType int

// BlockInterface defines the interface for blocks (used by consensus)
type BlockInterface interface {
	GetHeight() uint64
	GetHash() string
	GetPrevHash() string
	GetParentHash() string
	GetTimestamp() int64
	Validate() error
	GetDifficulty() *big.Int
	GetCurrentNonce() (uint64, error)
	GetUnderlyingBlock() interface{}
	SetCommitStatus(status string)
	SetSigValid(valid bool)
	GetCommitStatus() string
	GetSigValid() bool
	GetTxsRoot() []byte
}

// BlockHelper wraps types.Block to implement consensus.Block interface
type BlockHelper struct {
	block *types.Block
}

// ChainParamsProvider defines an interface to get chain parameters without import cycle
type ChainParamsProvider interface {
	GetChainParams() *SphinxChainParameters
	GetWalletDerivationPaths() map[string]string
}

// Mock implementation for storage package to use
type MockChainParamsProvider struct {
	params *SphinxChainParameters
}

// ConsensusSignatureData defines the data structure for consensus signatures
// This is used by core package to interact with consensus without creating import cycle
type ConsensusSignatureData struct {
	BlockHash    string
	BlockHeight  uint64
	SignerNodeID string
	Signature    string
	MessageType  string
	View         uint64
	Timestamp    string
	Valid        bool
	MerkleRoot   string
	Status       string
}

// ConsensusEngineInterface defines the methods needed from consensus without importing the package
// This is used by core package to interact with consensus without creating import cycle
type ConsensusEngineInterface interface {
	GetNodeID() string
	ProposeBlock(block interface{}) error
	GetConsensusSignatures() interface{}
	RefreshLeaderStatus() (view uint64, electedLeaderID string, isLeader bool)
	GetCurrentView() uint64
	AddConsensusSignature(sig interface{})
	CacheMerkleRoot(blockHash, merkleRoot string)
}

// GenesisConfig defines genesis-specific parameters
type GenesisConfig struct {
	InitialDifficulty *big.Int
	InitialGasLimit   *big.Int
	GenesisNonce      uint64
	GenesisExtraData  []byte
}

// SphinxChainParameters defines the complete blockchain parameters
type SphinxChainParameters struct {
	// Network Identification
	ChainID       uint64
	ChainName     string
	Symbol        string
	GenesisTime   int64
	GenesisHash   string
	Version       string
	MagicNumber   uint32
	DefaultPort   int
	BIP44CoinType uint64
	LedgerName    string
	Denominations map[string]*big.Int

	// Block Configuration
	MaxBlockSize       uint64
	MaxTransactionSize uint64
	TargetBlockSize    uint64
	BlockGasLimit      *big.Int
	BaseBlockReward    *big.Int // Block reward in base units

	// Genesis-specific configuration
	GenesisConfig *GenesisConfig

	// Mempool Configuration
	MempoolConfig *pool.MempoolConfig

	// Consensus Configuration
	ConsensusConfig *ConsensusConfig

	// Performance Configuration
	PerformanceConfig *PerformanceConfig
}

// ConsensusConfig defines consensus-related parameters
type ConsensusConfig struct {
	BlockTime        time.Duration
	EpochLength      uint64
	ValidatorSetSize int
	MaxValidators    int
	MinStakeAmount   *big.Int
	UnbondingPeriod  time.Duration
	SlashingEnabled  bool
	DoubleSignSlash  *big.Int // Slashing amount for double signing
}

// PerformanceConfig defines performance-related parameters
type PerformanceConfig struct {
	MaxConcurrentValidations int
	ValidationTimeout        time.Duration
	CacheSize                int
	PruningInterval          time.Duration
	MaxPeers                 int
	SyncBatchSize            int
}

// Blockchain manages the chain of blocks with state machine replication
type Blockchain struct {
	// Node identifier
	nodeID string

	// lateJoiner indicates this node did NOT create genesis locally and
	// must download the entire chain (including genesis) from peers.
	// Set to true when --seeds is provided at startup.
	lateJoiner      bool
	storage         *storage.Storage
	stateMachine    *storage.StateMachine
	mempool         *pool.Mempool
	chain           []*types.Block
	txIndex         map[string]*types.Transaction
	pendingTx       []*types.Transaction
	lock            sync.RWMutex
	commitMu        sync.Mutex
	status          BlockchainStatus
	syncMode        SyncMode
	consensusEngine ConsensusEngineInterface
	sphincsManager  *sign.STHINCSManager
	chainParams     *SphinxChainParameters
	syncManager     *SyncManager

	merkleRootCache map[string]string

	// TPS Monitoring
	tpsMonitor *types.TPSMonitor // Add this line

	// SVM integration - ONE-WAY relationship: replication drives SVM execution
	svmMutex        sync.RWMutex             // Mutex for SVM data access
	returnDataStore map[string][]byte        // In-memory store for OP_RETURN data
	svmFailures     []map[string]interface{} // Tracks SVM failures for monitoring

	rpcCaller RPCCaller // Add this field

	// validatorRewardMap maps node IDs (e.g. "Node-127.0.0.1:30303") to their
	// SPIF reward addresses.  Block rewards and gas fees are credited to the
	// SPIF address so validators can actually spend them.
	validatorRewardMap map[string]string

	// orphanBlocks stores blocks whose parent is not yet committed.
	// Keyed by parent hash, each entry is a list of child blocks waiting
	// for their parent to arrive. When a block is committed, its children
	// are replayed automatically.
	orphanBlocks map[string][]*types.Block

	// orphanMu guards orphanBlocks access.
	orphanMu sync.Mutex

	// chainWeight is the cumulative PBFT attestation weight of the current
	// canonical chain. It is updated atomically whenever a block is committed.
	chainWeight *big.Int
}

// GenesisState holds the complete genesis configuration used to bootstrap a node.
// It is the single source of truth for all genesis-related data: chain identity,
// the block header template, pre-funded accounts, and initial validators.
// Every node in the network must produce an identical GenesisState to guarantee
// consensus on the first block.
type GenesisState struct {
	// ChainID uniquely identifies the network (mainnet = 7331, testnet = 17331).
	ChainID uint64 `json:"chain_id"`

	// ChainName is the human-readable network label shown in logs and wallets.
	ChainName string `json:"chain_name"`

	// Symbol is the native token ticker (e.g. "SPX").
	Symbol string `json:"symbol"`

	// Timestamp is the Unix epoch second at which the genesis block was anchored.
	// All nodes share this value so that slot / epoch calculations are identical.
	Timestamp int64 `json:"timestamp"`

	// ExtraData is an arbitrary byte payload embedded in the genesis block header.
	// It typically encodes the chain motto or a short ASCII description.
	ExtraData []byte `json:"extra_data"`

	// InitialDifficulty is the proof-of-work target used in the genesis header.
	// For PBFT networks this is cosmetic but must still be consistent.
	InitialDifficulty *big.Int `json:"initial_difficulty"`

	// InitialGasLimit caps the total gas that can be consumed in a single block
	// at genesis. Subsequent blocks may adjust this value through governance.
	InitialGasLimit *big.Int `json:"initial_gas_limit"`

	// Nonce is the genesis block nonce, formatted as a fixed-width hex string
	// via common.FormatNonce so every node produces the same value.
	Nonce string `json:"nonce"`

	// Allocations is the ordered list of pre-funded addresses at genesis.
	// The slice ordering is significant: it determines the TxsRoot Merkle root
	// embedded in the genesis block header AND the order of transactions in
	// txs_list inside the block body.  Every node must use the exact same list
	// in the same order.
	Allocations []*GenesisAllocation `json:"allocations"`

	// InitialValidators is the set of validators that are active from block 0.
	// Each entry carries the validator ID, its stake (in nSPX), and a public key.
	InitialValidators []*GenesisValidator `json:"initial_validators"`
}

// GenesisValidator describes a single validator that is active at genesis.
// These entries are consumed by the consensus layer during node initialisation
// to populate the initial ValidatorSet before any on-chain staking transactions
// have been processed.
type GenesisValidator struct {
	// NodeID is the unique string identifier used throughout the consensus layer
	// (e.g. "Node-127.0.0.1:32307").
	NodeID string `json:"node_id"`

	// Address is the hex-encoded 20-byte account address that will receive
	// block rewards earned by this validator.
	Address string `json:"address"`

	// StakeNSPX is the initial stake expressed in nSPX (the smallest unit).
	// Use NewGenesisValidatorStake() to create this value from whole SPX.
	StakeNSPX *big.Int `json:"stake_nspx"`

	// PublicKey is the hex-encoded SPHINCS+ public key associated with this
	// validator. It is stored for future signature verification but is not
	// required to be non-empty at genesis.
	PublicKey string `json:"public_key"`
}

// genesisAllocationEntry is the per-account row written to genesis_state.json.
// It converts *big.Int balance fields to human-readable strings so the file
// can be inspected without a Go runtime.
type genesisAllocationEntry struct {
	// Address is the hex-encoded 20-byte account address without a "0x" prefix.
	Address string `json:"address"`

	// BalanceNSPX is the initial balance expressed in nSPX (smallest unit).
	BalanceNSPX string `json:"balance_nspx"`

	// BalanceSPX is the initial balance expressed in whole SPX (truncated).
	BalanceSPX string `json:"balance_spx"`

	// Label is a human-readable tag (e.g. "Founders", "Reserve").
	Label string `json:"label"`
}

// genesisValidatorEntry is the per-validator row written to genesis_state.json.
// It mirrors GenesisValidator but expresses big.Int stake fields as strings.
type genesisValidatorEntry struct {
	// NodeID is the unique string identifier used throughout the consensus layer.
	NodeID string `json:"node_id"`

	// Address is the hex-encoded 20-byte reward address for this validator.
	Address string `json:"address"`

	// StakeNSPX is the initial stake expressed in nSPX.
	StakeNSPX string `json:"stake_nspx"`

	// StakeSPX is the initial stake expressed in whole SPX (truncated).
	StakeSPX string `json:"stake_spx"`

	// PublicKey is the hex-encoded SPHINCS+ public key (may be empty at genesis).
	PublicKey string `json:"public_key,omitempty"`
}

// genesisStateSnapshot is an intermediate representation used exclusively for
// JSON serialisation. It converts *big.Int fields to strings so that the file
// can be read by tools that do not understand Go's big.Int encoding.
// Now includes the full allocation and validator lists so genesis_state.json
// contains real data rather than blank arrays.
type genesisStateSnapshot struct {
	ChainID            uint64 `json:"chain_id"`
	ChainName          string `json:"chain_name"`
	Symbol             string `json:"symbol"`
	Timestamp          string `json:"timestamp"`
	ExtraData          string `json:"extra_data"`
	InitialDifficulty  string `json:"initial_difficulty"`
	InitialGasLimit    string `json:"initial_gas_limit"`
	Nonce              string `json:"nonce"`
	TotalAllocations   int    `json:"total_allocations"`
	TotalAllocatedNSPX string `json:"total_allocated_nspx"`
	// TotalAllocatedSPX is the same total expressed in whole SPX for readability.
	TotalAllocatedSPX string `json:"total_allocated_spx"`
	TotalValidators   int    `json:"total_validators"`
	// Allocations is the full ordered list of pre-funded accounts.
	// This was the field that caused genesis_state.json to appear blank.
	Allocations []genesisAllocationEntry `json:"allocations"`
	// InitialValidators is the full list of genesis validators.
	// omitempty keeps the file clean when the list is empty (most networks).
	InitialValidators []genesisValidatorEntry `json:"initial_validators,omitempty"`
}

// GenesisAllocation represents a single account that is funded at genesis.
// Each entry maps a hex-encoded 20-byte address to an initial balance expressed
// in nSPX (the smallest SPX denomination: 1 SPX = 10^18 nSPX).
//
// Allocations are stored in an ordered slice on GenesisState.Allocations.
// The ordering is significant because it determines the allocation Merkle root
// that is embedded in the genesis block header, so every node must use the
// exact same ordered list.
//
// Use one of the constructor functions (NewGenesisAllocation, NewFounderAlloc,
// NewReserveAlloc, etc.) rather than constructing the struct directly.
type GenesisAllocation struct {
	// Address is the hex-encoded 20-byte account address without a "0x" prefix.
	// Example: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	Address string `json:"address"`

	// BalanceNSPX is the initial balance in nSPX (1 SPX = 10^18 nSPX).
	// Use NewGenesisAllocationSPX() to specify the balance in whole SPX.
	BalanceNSPX *big.Int `json:"balance_nspx"`

	// Label is a human-readable tag (e.g. "Founders", "Reserve") used only
	// in log output and the genesis_state.json audit file. It has no effect
	// on consensus or block hash computation.
	Label string `json:"label"`
}

// AllocationSummary provides a breakdown of the genesis token distribution
// grouped by label. It is used for logging and the genesis_state.json audit file.
type AllocationSummary struct {
	// TotalNSPX is the sum of all allocation balances in nSPX.
	TotalNSPX *big.Int `json:"total_nspx"`

	// TotalSPX is TotalNSPX divided by 10^18 (whole SPX, truncated).
	TotalSPX *big.Int `json:"total_spx"`

	// Count is the total number of allocation entries.
	Count int `json:"count"`

	// ByLabel maps each label to the aggregate balance (in nSPX) across all
	// allocations sharing that label.
	ByLabel map[string]*big.Int `json:"by_label"`
}

// AllocationSet is an in-memory index of genesis allocations keyed by the
// normalised (lowercase) hex address. It is built once at startup and used
// for O(1) balance queries during state initialisation.
type AllocationSet struct {
	index map[string]*GenesisAllocation
	total *big.Int // cached total supply in nSPX
}

// ChainPhase identifies which operational phase a network is in.
type ChainPhase string

// types.go - Updated ChainCheckpoint struct with nested structure
// ChainCheckpoint captures the complete supply state including genesis vs rewards
type ChainCheckpoint struct {
	Phase       string `json:"phase"`        // "devnet", "testnet", "mainnet"
	ChainName   string `json:"chain_name"`   // "Sphinx Devnet", "Sphinx Testnet", "Sphinx Mainnet"
	GenesisHash string `json:"genesis_hash"` // canonical genesis hash
	Timestamp   string `json:"timestamp"`    // RFC3339 when checkpoint was taken

	// Supply breakdown with both nSPX and SPX representations
	Supply struct {
		Max struct {
			NSPX string `json:"nspx"` // maximum supply in nSPX (5B * 1e18)
			SPX  string `json:"spx"`  // maximum supply in whole SPX (5,000,000,000)
		} `json:"max"`
		Genesis struct {
			NSPX string `json:"nspx"` // genesis allocation in nSPX
			SPX  string `json:"spx"`  // genesis allocation in whole SPX
		} `json:"genesis"`
		Minted struct {
			NSPX string `json:"nspx"` // total minted so far in nSPX
			SPX  string `json:"spx"`  // total minted so far in whole SPX
		} `json:"minted"`
		Remaining struct {
			NSPX string `json:"nspx"` // remaining to be mined in nSPX
			SPX  string `json:"spx"`  // remaining to be mined in whole SPX
		} `json:"remaining"`
	} `json:"supply"`

	// Vault information - the genesis vault address and its balance
	Vault struct {
		Address     string `json:"address"`      // GenesisVaultAddress constant
		BalanceNSPX string `json:"balance_nspx"` // vault balance in nSPX
		BalanceSPX  string `json:"balance_spx"`  // vault balance in whole SPX
	} `json:"vault"`

	// Rewards tracking - block rewards minted separately from genesis
	Rewards struct {
		MintedNSPX string `json:"minted_nspx"` // rewards minted in nSPX
		MintedSPX  string `json:"minted_spx"`  // rewards minted in whole SPX
	} `json:"rewards"`

	// Distribution status - tracks whether genesis allocations have been distributed
	Distribution struct {
		Status            string `json:"status"`              // "pending" or "complete"
		TotalAllocations  int    `json:"total_allocations"`   // number of genesis allocations
		TotalAllocatedSPX string `json:"total_allocated_spx"` // total allocated in whole SPX
	} `json:"distribution"`

	// Chain tip information
	Tip struct {
		Height uint64 `json:"height"` // current block height
		Hash   string `json:"hash"`   // current block hash
	} `json:"tip"`
}

// accountRecord is the JSON shape stored in LevelDB for each address.
type accountRecord struct {
	Balance string `json:"balance"` // decimal string, nSPX
	Nonce   uint64 `json:"nonce"`
}

// accountEntry is the in-memory mutable form used inside StateDB.
type accountEntry struct {
	balance         *big.Int
	nonce           uint64
	lastTxTimestamp int64 // Last transaction timestamp for replay protection
}

// StateDB is an in-memory account-state cache backed by *database.DB.
type StateDB struct {
	mu          sync.RWMutex
	db          *database.DB
	pending     map[string]*accountEntry
	totalSupply *big.Int
	// NEW: Track genesis allocation separately from rewards
	genesisSupply *big.Int
	rewardsMinted *big.Int
	blockchain    *Blockchain
}

// StakedValidator represents a validator with SPX stake
// This type is used for validator set snapshots in sync verification
type StakedValidator struct {
	ID              string   `json:"id"`
	PublicKey       []byte   `json:"public_key,omitempty"`
	StakeAmount     *big.Int `json:"stake_amount"` // In nSPX (base units)
	ActivationEpoch uint64   `json:"activation_epoch"`
	ExitEpoch       uint64   `json:"exit_epoch"`
	IsSlashed       bool     `json:"is_slashed"`
	LastAttested    uint64   `json:"last_attested"`
	RewardAddress   string   `json:"reward_address"` // SPIF address that receives block rewards
}

// ValidatorSet manages staked validators
// This is a minimal implementation for sync verification purposes
type ValidatorSet struct {
	validators     map[string]*StakedValidator
	totalStake     *big.Int
	mu             sync.RWMutex
	minStakeAmount *big.Int
}

// GetTotalStake returns the total stake in nSPX (implements validatorSetProvider)
func (vs *ValidatorSet) GetTotalStake() *big.Int {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	if vs.totalStake == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(vs.totalStake)
}

// GetValidator returns a validator by ID (implements validatorSetProvider)
// Returns interface{} to avoid import cycles with consensus package
func (vs *ValidatorSet) GetValidator(id string) interface{} {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	v, exists := vs.validators[id]
	if !exists || v == nil {
		return nil
	}
	// Return a copy to prevent external modification
	return &StakedValidator{
		ID:              v.ID,
		StakeAmount:     new(big.Int).Set(v.StakeAmount),
		ActivationEpoch: v.ActivationEpoch,
		ExitEpoch:       v.ExitEpoch,
		IsSlashed:       v.IsSlashed,
		LastAttested:    v.LastAttested,
		RewardAddress:   v.RewardAddress,
	}
}

// validatorSetProvider is an interface for accessing validator set data
// This allows VerifyBlockAttestations to work with both consensus.ValidatorSet
// and core.ValidatorSet without creating circular dependencies
type validatorSetProvider interface {
	GetTotalStake() *big.Int
	// GetValidator returns a core-compatible view of a validator.
	// To avoid import cycles between core<->consensus, this method is
	// intentionally flexible: implementations may return either *StakedValidator
	// or a consensus.StakedValidator pointer that core can interpret.
	GetValidator(id string) interface{}
}

// ValidatorSetSnapshot stores a frozen copy of the validator set at a given
// epoch, so that blocks from that epoch can be verified even after the live
// validator set has changed (validators joined/left/slashed).
type ValidatorSetSnapshot struct {
	Epoch      uint64
	Validators map[string]*StakedValidator // copy of validators at this epoch
	TotalStake *big.Int
}

// StateDBInterface is a simplified interface for state DB operations
// used by the state snapshot system. It avoids exposing internal StateDB.
type StateDBInterface interface {
	IterateAccounts(fn func(addr string, balance *big.Int, nonce uint64))
	SetBalance(addr string, balance *big.Int)
	SetNonce(addr string, nonce uint64)
	GetBalance(addr string) *big.Int
	GetNonce(addr string) uint64
}

// NodeState represents the operational state of a node in the synchronization lifecycle
type NodeState int

// P2PServerInterface defines the interface needed from p2p.Server to avoid import cycle
type P2PServerInterface interface {
	GetNodeManager() NodeManagerInterface
	SendMessageToPeer(peerID string, messageType string, data []byte) error
}

// NodeManagerInterface defines the interface needed from network.NodeManager
type NodeManagerInterface interface {
	GetPeers() map[string]PeerInterface
}

// PeerInterface defines the interface needed from network.Peer
type PeerInterface interface {
	GetID() string
	GetStatus() string
	GetNodeID() string
}

// blockResult carries a downloaded block (or error) through the pipeline channel.
type blockResult struct {
	height uint64
	block  *types.Block
	err    error
}

// SyncManager coordinates all synchronization activities
type SyncManager struct {
	bc        *Blockchain
	p2pServer P2PServerInterface
	consensus *consensus.Consensus

	// Node lifecycle state
	mu          sync.RWMutex
	state       NodeState
	targetState NodeState

	// Peer management
	peers    map[string]PeerInterface
	peerInfo map[string]*PeerChainInfo // peerID -> chain info

	// Synchronization state
	syncHeight uint64        // Target height to sync to
	syncFrom   uint64        // Height to start syncing from
	syncHash   string        // Hash we're syncing to
	locator    *BlockLocator // Current block locator

	// Download coordination
	downloadQueue map[uint64]bool // Heights currently being downloaded
	downloaded    map[uint64]*types.Block
	downloadMutex sync.Mutex

	// Parallel download
	maxParallel int
	downloadWg  sync.WaitGroup

	// ========== PIPELINED BULK DOWNLOAD (Phase A) ==========
	// Pipeline depth: number of in-flight block requests per peer.
	// Higher values = more throughput at the cost of memory.
	// Default: 64 for bulk sync, 4 for tip chasing.
	pipelineDepth int

	// blockResultCh receives downloaded blocks from pipeline workers
	// in the order they were requested (not the order they arrive).
	blockResultCh chan *blockResult

	// pendingPipeline tracks which heights have been dispatched to the pipeline
	// but not yet collected. Key = height, value = true.
	pendingPipeline map[uint64]bool
	pipelineMu      sync.Mutex

	// bulkSyncMode is true when the node is far behind the network tip.
	// In this mode we use larger batches, pipelining, and sparse verification.
	bulkSyncMode bool

	// bulkSyncThreshold is the height at which we switch from bulk sync
	// (sparse verification) to tip chasing (full verification).
	// Calculated as: targetHeight - 10000 (last 10K blocks get full verification).
	bulkSyncThreshold uint64

	// =======================================================

	// State sync
	stateSyncMode bool
	stateSyncHash string

	// Reorganization tracking
	reorgDepth  uint64
	oldBestHash string

	// Control channels
	stopCh       chan struct{}
	syncCh       chan struct{}
	peerUpdateCh chan PeerInterface

	// Timing
	lastSyncTime time.Time
	syncTimeout  time.Duration

	// Late-joiner sync budget (to avoid blocking forever)
	lateJoinerSyncStartTime       time.Time
	lateJoinerMaxSyncDuration     time.Duration
	lateJoinerFallbackToStateSync bool

	// Metrics
	blocksDownloaded uint64
	bytesDownloaded  uint64

	// ========== FIX: Add production robustness features ==========
	// Continuous sync monitoring
	lastSyncCheck     time.Time
	syncCheckInterval time.Duration
	// Genesis verification
	genesisVerified bool
	// Reconnection tracking
	reconnectAttempts    map[string]int
	maxReconnectAttempts int
	reconnectBackoff     time.Duration

	// ========== FIX: Add pending request tracking for async block responses ==========
	pendingBlockRequests map[string]chan *types.Block
	pendingRequestMu     sync.Mutex
}

// PeerChainInfo contains chain information exchanged during handshake
type PeerChainInfo struct {
	// Chain Identity
	ChainID     uint64 `json:"chain_id"`
	GenesisHash string `json:"genesis_hash"`
	GenesisTime int64  `json:"genesis_time"`

	// Chain State
	Height          uint64 `json:"height"`
	BestHash        string `json:"best_hash"`
	FinalizedHeight uint64 `json:"finalized_height"`
	FinalizedHash   string `json:"finalized_hash"`

	// Consensus State
	ValidatorSetHash string `json:"validator_set_hash"`
	CurrentView      uint64 `json:"current_view"`
	CurrentEpoch     uint64 `json:"current_epoch"`
	LeaderID         string `json:"leader_id"`

	// Network Info
	ProtocolVersion string `json:"protocol_version"`
	Timestamp       int64  `json:"timestamp"`
}

// BlockLocator is used for efficient sync (similar to Bitcoin's getblocks)
// It identifies blocks at exponentially increasing distances from the tip
type BlockLocator struct {
	Hashes []string `json:"hashes"` // Block hashes at various heights
}

// SphinxChainHeader contains only the fields needed for Ledger headers and wallet operations.
// This lightweight struct does NOT require blockchain initialization.
type SphinxChainHeader struct {
	ChainID       uint64 `json:"chain_id"`
	ChainName     string `json:"chain_name"`
	Symbol        string `json:"symbol"`
	MagicNumber   uint32 `json:"magic_number"`
	LedgerName    string `json:"ledger_name"`
	BIP44CoinType uint64 `json:"bip44_coin_type"`
}

// StateSnapshotHeader contains metadata about a state snapshot.
type StateSnapshotHeader struct {
	Version         int    `json:"version"`
	BlockHeight     uint64 `json:"block_height"`
	BlockHash       string `json:"block_hash"`
	StateRoot       string `json:"state_root"`
	Epoch           uint64 `json:"epoch"`
	TotalAccounts   int    `json:"total_accounts"`
	TotalValidators int    `json:"total_validators"`
	TotalSupply     string `json:"total_supply"`
	Timestamp       string `json:"timestamp"`
	FileSize        int64  `json:"file_size"`
	SnapshotFile    string `json:"snapshot_file"`
}

// StateSnapshotData contains the full state at a checkpoint.
type StateSnapshotData struct {
	Version     int                           `json:"version"`
	BlockHeight uint64                        `json:"block_height"`
	BlockHash   string                        `json:"block_hash"`
	StateRoot   string                        `json:"state_root"`
	Accounts    map[string]*SnapshotAccount   `json:"accounts"`
	Validators  map[string]*SnapshotValidator `json:"validators"`
	TotalSupply string                        `json:"total_supply"`
	Timestamp   string                        `json:"timestamp"`
}

// SnapshotAccount represents a single account in a state snapshot.
type SnapshotAccount struct {
	BalanceNSPX string `json:"balance_nspx"`
	Nonce       uint64 `json:"nonce"`
}

// SnapshotValidator represents a validator in a state snapshot.
type SnapshotValidator struct {
	StakeNSPX       string `json:"stake_nspx"`
	RewardAddress   string `json:"reward_address,omitempty"`
	ActivationEpoch uint64 `json:"activation_epoch"`
	ExitEpoch       uint64 `json:"exit_epoch"`
	IsSlashed       bool   `json:"is_slashed"`
}

// CheckpointMessage is the message exchanged between peers to advertise
// available checkpoints.
type CheckpointMessage struct {
	BlockHeight uint64            `json:"block_height"`
	BlockHash   string            `json:"block_hash"`
	StateRoot   string            `json:"state_root"`
	Epoch       uint64            `json:"epoch"`
	Signatures  map[string]string `json:"signatures"`
	Timestamp   int64             `json:"timestamp"`
}

// ========== STATE SNAPSHOT MANAGER ==========

// StateSnapshotManager manages state snapshot generation, storage, and retrieval.
type StateSnapshotManager struct {
	bc *Blockchain

	mu sync.RWMutex

	snapshotsDir   string
	snapshotIndex  map[uint64]*StateSnapshotHeader
	latestSnapshot *StateSnapshotHeader
	checkpoints    map[uint64]*CheckpointMessage
}

// blockchainInitOptions controls how NewBlockchain finishes initialization.
type blockchainInitOptions struct {
	deferFinish bool
}

// BlockchainOption configures NewBlockchain's behavior. Zero options means
// exactly the original behavior: chain loading / genesis creation happens
// synchronously inside NewBlockchain, before it returns. Existing callers
// that pass no options (server.go, legacy.go) are unaffected.
type BlockchainOption func(*blockchainInitOptions)
