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

// go/src/consensus/types.go
package consensus

import (
	"context"
	"math/big"
	"sync"
	"time"

	"github.com/sphinxorg/protocol/src/core/hashtree"
	key "github.com/sphinxorg/protocol/src/core/sphincs/key/backend"
	sign "github.com/sphinxorg/protocol/src/core/sphincs/sign/backend"
	"github.com/sphinxorg/protocol/src/crypto/SPHINCSPLUS-golang/sphincs"
)

// Block interface that your existing types.Block will satisfy
type Block interface {
	GetHeight() uint64
	GetHash() string
	GetPrevHash() string
	GetTimestamp() int64
	Validate() error
	GetDifficulty() *big.Int
	GetCurrentNonce() (uint64, error)
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
// Proposal represents a block proposal from a leader
type Proposal struct {
	Block           Block  `json:"block"`
	View            uint64 `json:"view"`
	ProposerID      string `json:"proposer_id"`
	Signature       []byte `json:"signature"`
	ElectedLeaderID string `json:"elected_leader_id"` // ADD THIS
	SlotNumber      uint64 `json:"slot_number"`       // ADD THIS
}

// Vote represents a vote from a validator
type Vote struct {
	BlockHash string `json:"block_hash"`
	View      uint64 `json:"view"`
	VoterID   string `json:"voter_id"`
	Signature []byte `json:"signature"`
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
type BlockChain interface {
	GetLatestBlock() Block
	ValidateBlock(block Block) error
	CommitBlock(block Block) error
	GetBlockByHash(hash string) Block
	GetValidatorStake(validatorID string) *big.Int
	GetTotalStaked() *big.Int
	UpdateValidatorStake(validatorID string, delta *big.Int) error
	GetGenesisTime() time.Time
}

// NodeManager interface to abstract network functionality
type NodeManager interface {
	GetPeers() map[string]Peer
	GetNode(nodeID string) Node
	BroadcastMessage(messageType string, data interface{}) error
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
	ID              string
	PublicKey       []byte
	StakeAmount     *big.Int // In nSPX (base units)
	ActivationEpoch uint64
	ExitEpoch       uint64
	IsSlashed       bool
	LastAttested    uint64
	RewardAddress   string
}

// ValidatorSet manages staked validators
type ValidatorSet struct {
	validators     map[string]*StakedValidator
	totalStake     *big.Int
	mu             sync.RWMutex
	minStakeAmount *big.Int
}

// RANDAO provides verifiable randomness for leader selection
type RANDAO struct {
	mix     [32]byte
	reveals map[uint64][][32]byte
	mu      sync.RWMutex
}

// StakeWeightedSelector selects proposers and committees based on stake
type StakeWeightedSelector struct {
	validatorSet *ValidatorSet
}

// TimeConverter converts between slots/epochs and time
type TimeConverter struct {
	genesisTime time.Time
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
	// (round-robin view-change) call.  Every node that runs the same
	// deterministic selection arrives at the same value, so
	// isValidLeader can compare the proposer against it directly.
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
	ctx             context.Context
	cancel          context.CancelFunc
	lastViewChange  time.Time
	viewChangeMutex sync.Mutex
	lastBlockTime   time.Time

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

	electedSlot uint64 // slot number used when electedLeaderID was set
}

// SigningService handles cryptographic signing for consensus messages
type SigningService struct {
	sphincsManager    *sign.SphincsManager
	keyManager        *key.KeyManager
	nodeID            string
	privateKey        *sphincs.SPHINCS_SK
	publicKey         *sphincs.SPHINCS_PK
	publicKeyRegistry map[string]*sphincs.SPHINCS_PK
	registryMutex     sync.RWMutex
}

// SignedMessage represents a complete signed message with all components
type SignedMessage struct {
	Signature  []byte                 // Serialized SPHINCS+ signature bytes
	Timestamp  []byte                 // 8-byte big-endian Unix timestamp (from SignMessage)
	Nonce      []byte                 // 16-byte random nonce (from SignMessage)
	MerkleRoot *hashtree.HashTreeNode // Merkle root node built from sig chunks
	Commitment []byte                 // NEW: H(sigBytes||pk||timestamp||nonce||data), 32 bytes
	Data       []byte                 // Original message data that was signed
}

// ConsensusSignature represents a captured signature from consensus messages
type ConsensusSignature struct {
	BlockHash    string `json:"block_hash"`
	BlockHeight  uint64 `json:"block_height"`
	SignerNodeID string `json:"signer_node_id"`
	Signature    string `json:"signature"`
	MessageType  string `json:"message_type"`
	View         uint64 `json:"view"`
	Timestamp    string `json:"timestamp"`
	Valid        bool   `json:"valid"`
	MerkleRoot   string `json:"merkle_root"`
	Status       string `json:"status"`
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
