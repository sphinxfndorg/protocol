// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/transaction/types.go
package types

import (
	"math/big"
	"sync"
	"sync/atomic"
	"time"
)

// BlockHeader represents the metadata for a block in the blockchain.
type BlockHeader struct {
	Version    uint64   `json:"version"`     // Block version
	Block      uint64   `json:"nblock"`      // The position of the block in the blockchain (index)
	Height     uint64   `json:"height"`      // Block height (same as Block)
	Timestamp  int64    `json:"timestamp"`   // The timestamp when the block is mined
	ParentHash []byte   `json:"parent_hash"` // Hash of the previous block (main chain continuity)
	Hash       []byte   `json:"hash"`        // This block's hash
	Difficulty *big.Int `json:"difficulty"`  // Difficulty level of mining the block
	Nonce      string   `json:"nonce"`       // The nonce used in mining (CHANGED to string)
	TxsRoot    []byte   `json:"txs_root"`    // Merkle root of the transactions in the block
	StateRoot  []byte   `json:"state_root"`  // Merkle root of the state (EVM-like state)
	GasLimit   *big.Int `json:"gas_limit"`   // The maximum gas that can be used in the block
	GasUsed    *big.Int `json:"gas_used"`    // The actual gas used by the transactions
	UnclesHash []byte   `json:"uncles_hash"` // Hash of the uncles (references side blocks)
	ExtraData  []byte   `json:"extra_data"`  // Extra data field for additional information
	Miner      []byte   `json:"miner"`       // Miner address (20 bytes)
	// NEW: PoS signature fields
	ProposerSignature []byte `json:"proposer_signature"` // Signature by the block proposer
	ProposerID        string `json:"proposer_id"`        // Which validator proposed this block
	SigDataHash       []byte `json:"sig_data_hash"`      // Change from `json:"-"` to `json:"sig_data_hash"`

	// NEW: explicit status fields
	CommitStatus string `json:"commit_status"`   // "proposed" | "prepared" | "committed"
	SigValid     bool   `json:"signature_valid"` // true once verified by a peer
}

// BlockBody represents the transactions and uncle blocks.
type BlockBody struct {
	TxsList    []*Transaction `json:"txs_list"`    // A list of transactions in the block
	Uncles     []*BlockHeader `json:"uncles"`      // Actual uncle blocks (side chains)
	UnclesHash []byte         `json:"uncles_hash"` // Hash representing uncles (calculated from uncles)
	// NEW: Collected validator attestations (optional but recommended)
	Attestations []*Attestation `json:"attestations,omitempty"`
}

// NEW: Attestation struct
type Attestation struct {
	ValidatorID string `json:"validator_id"`
	Signature   []byte `json:"signature"`
	BlockHash   string `json:"block_hash"`
	View        uint64 `json:"view"`
}

// Block represents the entire block structure including the header and body.
type Block struct {
	Header *BlockHeader `json:"header"`
	Body   BlockBody    `json:"body"`
}

// Transaction represents a blockchain transaction
type Transaction struct {
	ID         string   `json:"id"`
	Sender     string   `json:"sender"`
	Receiver   string   `json:"receiver"`
	Amount     *big.Int `json:"amount"`
	GasLimit   *big.Int `json:"gas_limit"`
	GasPrice   *big.Int `json:"gas_price"`
	Nonce      uint64   `json:"nonce"`
	Timestamp  int64    `json:"timestamp"`
	Signature  []byte   `json:"signature"`
	ReturnData []byte   `json:"return_data,omitempty"` // OP_RETURN data (memos, proofs, metadata)
	// Optional data
	Data           []byte `json:"data,omitempty"`
	SignatureHash  []byte `json:"signature_hash"`             // ADD THIS - 32-byte hash of signature for replay detection
	PublicKey      []byte `json:"public_key"`                 // Serialized SPHINCS+ public key (NOT sender address string)
	AuthTimestamp  []byte `json:"auth_timestamp,omitempty"`   // 8-byte timestamp bound inside the SPHINCS signature
	AuthNonce      []byte `json:"auth_nonce,omitempty"`       // 16-byte random nonce bound inside the SPHINCS signature
	MerkleRootHash []byte `json:"merkle_root_hash,omitempty"` // SPHINCS+ receipt root derived from signature leaves
	Commitment     []byte `json:"commitment,omitempty"`       // Binding commitment over signature, key, timestamp, nonce, and tx ID
	Proof          []byte `json:"proof,omitempty"`            // Lightweight consistency proof for the receipt fields
}

const GenesisVaultAddress = "0000000000000000000000000000000000000001"

// IsSystemTransaction returns true for protocol-created transactions that are
// valid without an external SPHINCS+ signature.
func (tx *Transaction) IsSystemTransaction() bool {
	return tx != nil && (tx.Sender == "genesis" || tx.Sender == GenesisVaultAddress)
}

// HasFullAuthBundle returns true when all fields needed for real SPHINCS+
// transaction authentication are present.
func (tx *Transaction) HasFullAuthBundle() bool {
	return tx != nil &&
		len(tx.Signature) > 0 &&
		len(tx.SignatureHash) == 32 &&
		len(tx.PublicKey) > 0 &&
		len(tx.AuthTimestamp) == 8 &&
		len(tx.AuthNonce) == 16 &&
		len(tx.MerkleRootHash) == 32 &&
		len(tx.Commitment) == 32 &&
		len(tx.Proof) == 32
}

// Outpoint represents a specific transaction output.
type Outpoint struct {
	TxID  string `json:"txid"`  // Transaction ID
	Index int    `json:"index"` // Output index
}

// UTXO represents an unspent transaction output.
type UTXO struct {
	Outpoint Outpoint `json:"outpoint"`
	Value    uint64   `json:"value"`
	Address  string   `json:"address"`
	Coinbase bool     `json:"coinbase"`
	Spent    bool     `json:"spent"`
	Height   uint64   `json:"height"`
}

// UTXOSet manages unspent transaction outputs.
type UTXOSet struct {
	mu          sync.RWMutex
	utxos       map[Outpoint]*UTXO
	totalSupply *big.Int
}

// Output represents a transaction output.
type Output struct {
	Value   uint64 `json:"value"`
	Address string `json:"address"`
}

// Note represents a transaction receipt.
type Note struct {
	To        string  `json:"to"`
	From      string  `json:"from"`
	Fee       float64 `json:"fee"`
	Storage   string  `json:"storage"`
	Timestamp int64   `json:"timestamp"`
	MAC       string  `json:"mac"`
	Output    *Output `json:"output"`
	// AmountNSPX holds the exact nSPX amount when precision beyond float64 is needed.
	// If set, ToTxs uses this instead of converting Fee.
	AmountNSPX *big.Int `json:"amount_nspx,omitempty"`
	ReturnData []byte   `json:"return_data,omitempty"` // Add OP_RETURN data field
}

// Contract represents a transaction contract.
type Contract struct {
	Sender    string   `json:"sender"`
	Receiver  string   `json:"receiver"`
	Amount    *big.Int `json:"amount"`
	Fee       *big.Int `json:"fee"`
	Storage   string   `json:"storage"`
	Timestamp int64    `json:"timestamp"`
}

// Validator validates transaction notes.
type Validator struct {
	senderAddress    string
	recipientAddress string
}

// GetHash returns the transaction ID (hash)
func (tx *Transaction) GetHash() string {
	return tx.ID
}

// MerkleTree represents a Merkle tree structure for transactions
type MerkleTree struct {
	Root   *MerkleNode
	Leaves []*MerkleNode
}

// MerkleNode represents a node in the Merkle tree
type MerkleNode struct {
	Left   *MerkleNode
	Right  *MerkleNode
	Hash   []byte
	IsLeaf bool // Helper field to identify leaf nodes
}

// TPSMonitor tracks transactions per second metrics
type TPSMonitor struct {
	mu sync.RWMutex

	// Transaction counters
	totalTransactions  uint64
	currentWindowCount uint64
	windowStartTime    time.Time

	// TPS metrics
	currentTPS     float64
	averageTPS     float64
	peakTPS        float64
	windowDuration time.Duration

	// Historical data
	tpsHistory     []float64
	maxHistorySize int

	// Block-based metrics
	blocksProcessed uint64
	txsPerBlock     []uint64

	firstBlockRecorded atomic.Bool
}

// AccountState represents the state of a single account.
type AccountState struct {
	Address  string `json:"address"`
	Balance  uint64 `json:"balance"`  // Balance in nSPX
	Nonce    uint64 `json:"nonce"`    // Transaction counter for replay protection
	Coinbase bool   `json:"coinbase"` // Whether this is a coinbase account (mining rewards)
	Height   uint64 `json:"height"`   // Block height when this account was created/updated
	Spent    bool   `json:"spent"`    // Whether the account has been fully spent (for special accounts)
}

// AccountSet manages all accounts in the system.
type AccountSet struct {
	mu          sync.RWMutex
	accounts    map[string]*AccountState // address -> account state
	totalSupply *big.Int                 // circulating supply in nSPX
}
