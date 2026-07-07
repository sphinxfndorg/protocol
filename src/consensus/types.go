// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/consensus/types.go
package consensus

import (
	"context"
	"math/big"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/core/hashtree"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
)

// Block interface that your existing types.Block will satisfy
type Block interface {
	GetHeight() uint64
	GetHash() string
	GetPrevHash() string
	GetParentHash() string
	GetTimestamp() int64
	Validate() error
	GetDifficulty() *big.Int
	GetCurrentNonce() (uint64, error)
	GetUnderlyingBlock() interface{}

	// Add these methods for metadata updates
	SetCommitStatus(status string)
	SetSigValid(valid bool)
	GetCommitStatus() string
	GetSigValid() bool
	GetTxsRoot() []byte // Add this method
}

// MerkleRootExtractor is a separate interface for blocks that can provide merkle roots
type MerkleRootExtractor interface {
	ExtractMerkleRoot() string
}

// BlockWithBody extends the basic Block interface for blocks that have bodies
type BlockWithBody interface {
	Block
	GetBody() interface{}
}

// Proposal represents a block proposal from a leader
type Proposal struct {
	BlockData       []byte `json:"block_data"`
	View            uint64 `json:"view"`
	ProposerID      string `json:"proposer_id"`
	Signature       []byte `json:"signature"`
	ElectedLeaderID string `json:"elected_leader_id"`
	SlotNumber      uint64 `json:"slot_number"`

	// Transient field - not serialized, used locally
	Block Block `json:"-"`
}

// Vote represents a vote from a validator
type Vote struct {
	BlockHash     string `json:"block_hash"`
	View          uint64 `json:"view"`
	VoterID       string `json:"voter_id"`
	Signature     []byte `json:"signature"`
	SignatureHash []byte `json:"signature_hash,omitempty"` // Optional: for debugging
}

// Attestation represents a validator's vote with epoch information
type Attestation struct {
	Slot        uint64
	Epoch       uint64
	BlockHash   string
	ValidatorID string
	SourceEpoch uint64
	TargetEpoch uint64
	Signature   []byte
}

// BlockChain interface for block storage and retrieval
// BlockChain interface for block storage and retrieval
type BlockChain interface {
	GetLatestBlock() Block
	ValidateBlock(block Block) error
	CommitBlock(block Block) error
	GetBlockByHash(hash string) Block
	GetValidatorStake(validatorID string) *big.Int
	GetTotalStaked() *big.Int
	UpdateValidatorStake(validatorID string, delta *big.Int) error
	GetGenesisTime() time.Time

	// ADD THESE METHODS:
	GetCheckpointMessage() (*CheckpointMessage, error)
	ApplyCheckpointFromPeer(cp *CheckpointMessage) error
}

// NodeManager interface to abstract network functionality
type NodeManager interface {
	GetPeers() map[string]Peer
	GetNode(nodeID string) Node
	BroadcastMessage(messageType string, data interface{}) error
	// BroadcastRANDAOState broadcasts RANDAO state to all peers
	BroadcastRANDAOState(mix [32]byte, submissions map[uint64]map[string]*VDFSubmission) error
}

// Node interface represents a participant in the network
type Node interface {
	GetID() string
	GetRole() NodeRole
	GetStatus() NodeStatus
}

// Peer interface represents a connection to another node
type Peer interface {
	GetNode() Node
}

// NodeRole represents the role of a node in the network
type NodeRole int

// NodeStatus represents the status of a node
type NodeStatus int

// ConsensusPhase represents the current phase of the consensus protocol
type ConsensusPhase int

// StakedValidator represents a validator with SPX stake
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
type ValidatorSet struct {
	validators     map[string]*StakedValidator
	totalStake     *big.Int
	mu             sync.RWMutex
	minStakeAmount *big.Int
}

// VDFParams holds the public parameters for the VDF evaluation and verification.
type VDFParams struct {
	Discriminant *big.Int // Class group discriminant (post-quantum)
	T            uint64   // sequential squarings = delay target
	Lambda       uint     // security parameter
}

// VDFSubmission is what a validator (or any node) broadcasts after computing
// the VDF output for an epoch.  Because the VDF input is public (the current
// RANDAO seed) any node can compute it; no secret key or commit-reveal is
// required.
type VDFSubmission struct {
	Epoch       uint64   `json:"epoch"`
	SlotInEpoch uint64   `json:"slot_in_epoch"`
	ValidatorID string   `json:"validator_id"` // submitter identity for slashing
	Input       [32]byte `json:"input"`        // seed fed into VDF (from GetSeed)
	Output      *big.Int `json:"output"`       // y = x^(2^T) mod N
	Proof       *big.Int `json:"proof"`        // Wesolowski π = x^(floor(2^T / l)) mod N
}

// RANDAO holds the running mix and all per-epoch VDF submission state.
//
// Design notes vs. the former VRF-based design:
//   - No commit/reveal phases.  The VDF input is public at slot 0; any node
//     may start computing immediately.  The sequential delay T ensures the
//     output is not known until roughly T squarings have elapsed, preventing
//     last-submitter grinding.
//   - submissions maps epoch → (validatorID → *VDFSubmission).  The first
//     valid submission per epoch is accepted and mixed in; duplicate submitters
//     are ignored (not slashed).
//   - missed maps epoch → set of validator IDs that were in the active set
//     for that epoch but did not submit before the window closed.  These are
//     returned by FinaliseEpoch for slashing by the caller.
//   - epochFinalized maps epoch → bool to prevent submissions after epoch finalization.
//   - impl can be swapped for a deterministic stub in unit tests.
type RANDAO struct {
	mu                  sync.RWMutex
	mix                 [32]byte
	reveals             map[uint64][][32]byte                // audit log of mixed-in outputs
	submissions         map[uint64]map[string]*VDFSubmission // submissions per epoch
	missed              map[uint64]map[string]bool           // validators that missed submission
	epochFinalized      map[uint64]bool                      // prevents submissions after finalization
	params              VDFParams
	impl                vdfProvider
	cache               *VDFCache
	consecutiveFailures map[string]int // Track consecutive failures per validator
	validatorID         string         // Store this node's validator ID
}

// StakeWeightedSelector selects proposers and committees based on stake
type StakeWeightedSelector struct {
	validatorSet *ValidatorSet
}

// TimeConverter converts between slots/epochs and time
type TimeConverter struct {
	genesisTime time.Time
}

// pendingSyncRequest tracks a block fetch request waiting for a peer response
type pendingSyncRequest struct {
	height   uint64
	response chan Block
}

// Consensus is the main PBFT + PoS consensus engine.
type Consensus struct {
	mu sync.RWMutex

	// Core fields
	nodeID         string
	nodeManager    NodeManager
	blockChain     BlockChain
	signingService *SigningService
	currentView    uint64
	currentHeight  uint64
	phase          ConsensusPhase
	lockedBlock    Block
	preparedBlock  Block
	preparedView   uint64
	quorumFraction float64
	timeout        time.Duration
	isLeader       bool

	// electedLeaderID stores the node ID selected by the most recent
	// UpdateLeaderStatus (RANDAO) or updateLeaderStatusWithValidators
	// (round-robin view-change) call.
	electedLeaderID string

	// Vote tracking
	receivedVotes    map[string]map[string]*Vote
	prepareVotes     map[string]map[string]*Vote
	sentVotes        map[string]bool
	sentPrepareVotes map[string]bool

	// Channels
	proposalCh chan *Proposal
	voteCh     chan *Vote
	timeoutCh  chan *TimeoutMsg
	prepareCh  chan *Vote

	// Callbacks
	onCommit func(Block) error

	// Context
	ctx               context.Context
	cancel            context.CancelFunc
	lastViewChange    time.Time
	viewChangeMutex   sync.Mutex
	lastBlockTime     time.Time
	lastRoundActivity time.Time

	// Cache fields
	merkleRootCache     map[string]string
	cacheMutex          sync.RWMutex
	signatureMutex      sync.RWMutex
	consensusSignatures []*ConsensusSignature

	// PoS fields
	validatorSet     *ValidatorSet
	randao           *RANDAO
	selector         *StakeWeightedSelector
	timeConverter    *TimeConverter
	useStakeWeighted bool
	currentEpoch     uint64
	justifiedEpoch   uint64
	finalizedEpoch   uint64

	// Stake-weighted vote tracking
	weightedPrepareVotes map[string]*big.Int // blockHash -> total stake for prepare
	weightedCommitVotes  map[string]*big.Int // blockHash -> total stake for commit

	// Attestations per epoch
	attestations map[uint64][]*Attestation

	pendingProposals map[string]Block // Cache of proposals by block hash for leader self-recovery
	proposalMutex    sync.RWMutex     // Mutex for proposal cache

	preparedBlockHash string // Track the hash of preparedBlock for cleanup

	electedSlot uint64 // slot number used when electedLeaderID was set

	// proposalInFlight is true while processProposal is actively validating
	// a just-received proposal (deserialization, block validation, SPHINCS+
	// signature checks, etc). These steps can take several seconds, and
	// during that window the proposal hasn't been rejected or accepted yet —
	// it's "in flight". shouldPreventViewChange checks this flag so the
	// view-change timer doesn't fire and advance currentView out from under
	// a proposal that is still being verified, which would otherwise cause
	// it to be discarded as stale the moment verification finishes.
	proposalInFlight bool

	// syncNeededCh receives the next height this node needs to sync from
	// when processProposal detects a gap (proposal height > localTip+1).
	// The p2p/smr layer drains this channel and calls FastForward with
	// each missing block fetched from a peer, in ascending height order.
	syncNeededCh chan uint64

	// pendingSyncRequests tracks block fetch requests waiting for peer responses
	pendingSyncRequests map[uint64]*pendingSyncRequest
	pendingSyncMutex    sync.RWMutex

	// Storage durability and crash recovery
	storageDurabilityConfig *StorageDurabilityConfig
	recoveryState           *RecoveryState
}

// SigningService handles cryptographic signing for consensus messages
// SigningService struct definition - FIXED: added missing struct with correct types
type SigningService struct {
	sphincsManager    *sign.STHINCSManager // FIXED: use STHINCSManager instead of SphincsManager
	keyManager        *key.KeyManager
	nodeID            string
	privateKey        *sthincs.SPHINCS_SK            // FIXED: use sthincs type
	publicKey         *sthincs.SPHINCS_PK            // FIXED: use sthincs type
	publicKeyRegistry map[string]*sthincs.SPHINCS_PK // FIXED: use sthincs type
	registryMutex     sync.RWMutex                   // FIXED: added mutex field
}

// SignedMessage represents a complete signed message with all components
type SignedMessage struct {
	Signature     []byte                 // Serialized SPHINCS+ signature bytes
	SignatureHash []byte                 // ← MISSING: 32-byte hash of signature for content replay detection
	Timestamp     []byte                 // 8-byte big-endian Unix timestamp (from SignMessage)
	Nonce         []byte                 // 16-byte random nonce (from SignMessage)
	MerkleRoot    *hashtree.HashTreeNode // Merkle root node built from sig chunks
	Commitment    []byte                 // H(sigBytes||pk||timestamp||nonce||data), 32 bytes
	Data          []byte                 // Original message data that was signed
}

// ConsensusSignature represents a captured signature from consensus messages
type ConsensusSignature struct {
	BlockHash     string `json:"block_hash"`
	BlockHeight   uint64 `json:"block_height"`
	SignerNodeID  string `json:"signer_node_id"`
	Signature     string `json:"signature"`
	SignatureHash string `json:"signature_hash"` // ← ADD THIS - for content replay detection
	MessageType   string `json:"message_type"`
	View          uint64 `json:"view"`
	Timestamp     string `json:"timestamp"`
	Valid         bool   `json:"valid"`
	MerkleRoot    string `json:"merkle_root"`
	Status        string `json:"status"`
}

// SignatureValidation contains statistics about signature validation
type SignatureValidation struct {
	TotalSignatures   int    `json:"total_signatures"`
	ValidSignatures   int    `json:"valid_signatures"`
	InvalidSignatures int    `json:"invalid_signatures"`
	ValidationTime    string `json:"validation_time"`
}

// BlockSizeMetrics contains block size statistics
type BlockSizeMetrics struct {
	TotalBlocks     int                      `json:"total_blocks"`
	AverageSize     uint64                   `json:"average_size_bytes"`
	MinSize         uint64                   `json:"min_size_bytes"`
	MaxSize         uint64                   `json:"max_size_bytes"`
	TotalSize       uint64                   `json:"total_size_bytes"`
	SizeStats       []map[string]interface{} `json:"size_stats"`
	CalculationTime string                   `json:"calculation_time"`
	AverageSizeMB   float64                  `json:"average_size_mb"`
	MinSizeMB       float64                  `json:"min_size_mb"`
	MaxSizeMB       float64                  `json:"max_size_mb"`
	TotalSizeMB     float64                  `json:"total_size_mb"`
}

// TimeoutMsg represents a view change timeout message
type TimeoutMsg struct {
	View      uint64 `json:"view"`
	VoterID   string `json:"voter_id"`
	Signature []byte `json:"signature"`
	Timestamp int64  `json:"timestamp"`
}

// QuorumVerifier provides mathematical guarantees for BFT safety
type QuorumVerifier struct {
	totalNodes     int
	faultyNodes    int
	quorumFraction float64
}

// QuorumCalculator implements the mathematical quorum guarantees
type QuorumCalculator struct {
	quorumFraction float64
}

// ConsensusState manages the state machine for consensus protocol
type ConsensusState struct {
	mu             sync.RWMutex
	currentView    uint64
	currentHeight  uint64
	phase          ConsensusPhase
	lockedBlock    Block
	preparedBlock  Block
	preparedView   uint64
	lastViewChange time.Time
}

// EpochInfo contains epoch state
type EpochInfo struct {
	Number    uint64
	StartTime time.Time
	EndTime   time.Time
	StartSlot uint64
	EndSlot   uint64
	Justified bool
	Finalized bool
}

// SlotInfo contains slot state
type SlotInfo struct {
	Number    uint64
	Epoch     uint64
	Proposer  *StakedValidator
	Committee []*StakedValidator
	Timestamp time.Time
}

// StateMachineInterface defines the methods needed for state transitions
type StateMachineInterface interface {
	ProposeStateTransition(transition *StateTransition) error
}

// StateTransition defines the structure for state changes
type StateTransition struct {
	TransitionType string      `json:"transition_type"`
	ValidatorID    string      `json:"validator_id,omitempty"`
	StakeAmount    *big.Int    `json:"stake_amount,omitempty"`
	ParamName      string      `json:"param_name,omitempty"`
	ParamValue     interface{} `json:"param_value,omitempty"`
	Timestamp      int64       `json:"timestamp,omitempty"`
}

// CheckpointMessage contains checkpoint data for peer synchronization
type CheckpointMessage struct {
	GenesisHash     string `json:"genesis_hash"`
	TipHeight       uint64 `json:"tip_height"`
	TipHash         string `json:"tip_hash"`
	TotalSupply     string `json:"total_supply"`
	GenesisSupply   string `json:"genesis_supply"`
	RewardsMinted   string `json:"rewards_minted"`
	RemainingSupply string `json:"remaining_supply"`
	VaultBalance    string `json:"vault_balance"`
	Timestamp       string `json:"timestamp"`
	Phase           string `json:"phase"`
	MintedSPX       string `json:"minted_spx"` // ADD THIS
}
