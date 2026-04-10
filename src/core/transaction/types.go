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
