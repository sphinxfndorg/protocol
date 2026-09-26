// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/transaction/types.go
package types

import (
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
)

// BlockHeader represents the metadata for a block in the blockchain.
type BlockHeader struct {
	Version    uint64   `json:"version"`              // Block version
	Block      uint64   `json:"nblock"`               // The position of the block in the blockchain (index)
	Height     uint64   `json:"height"`               // Block height (same as Block)
	Timestamp  int64    `json:"timestamp"`            // The timestamp when the block is mined
	ParentHash []byte   `json:"parent_hash"`          // Hash of the previous block (main chain continuity)
	Hash       []byte   `json:"hash"`                 // This block's hash
	Difficulty *big.Int `json:"difficulty"`           // Difficulty level of mining the block
	Nonce      string   `json:"nonce"`                // The nonce used in mining (CHANGED to string)
	TxsRoot    []byte   `json:"txs_root"`             // Merkle root of the transactions in the block
	StateRoot  []byte   `json:"state_root"`           // Merkle root of the state (EVM-like state)
	GasLimit   *big.Int `json:"gas_limit"`            // The maximum gas that can be used in the block
	GasUsed    *big.Int `json:"gas_used"`             // The actual gas used by the transactions
	UnclesHash []byte   `json:"uncles_hash"`          // Hash of the uncles (references side blocks)
	ExtraData  []byte   `json:"extra_data"`           // Extra data field for additional information
	Miner      []byte   `json:"miner"`                // Miner address (20 bytes)
	LogsBloom  []byte   `json:"logs_bloom,omitempty"` // 256-byte Bloom filter over block addresses/tx IDs
	// NEW: PoS signature fields
	ProposerSignature []byte `json:"proposer_signature"` // Signature by the block proposer
	ProposerID        string `json:"proposer_id"`        // Which validator proposed this block
	SigDataHash       []byte `json:"sig_data_hash"`      // Change from `json:"-"` to `json:"sig_data_hash"`

	// NEW: explicit status fields
	CommitStatus string `json:"commit_status"`   // "proposed" | "prepared" | "committed"
	SigValid     bool   `json:"signature_valid"` // true once verified by a peer

	// ChainWeight is the cumulative PBFT attestation weight for this chain branch.
	// It is the sum of all validator stake that has signed attestations leading
	// to this block, starting from genesis. This is used for fork-choice:
	// the chain with the highest cumulative weight is the canonical chain.
	ChainWeight *big.Int `json:"chain_weight,omitempty"`
}

// BlockBody represents the transactions and uncle blocks.
type BlockBody struct {
	TxsList    []*Transaction `json:"txs_list"`    // A list of transactions in the block
	Uncles     []*BlockHeader `json:"uncles"`      // Actual uncle blocks (side chains)
	UnclesHash []byte         `json:"uncles_hash"` // Hash representing uncles (calculated from uncles)
	// NEW: Collected validator attestations (optional but recommended)
	Attestations []*Attestation `json:"attestations,omitempty"`
	// CGEWitnesses carries the M-of-N custodian witnesses this block consumed
	// for its CGE escrow releases (empty for every other block). Part of the
	// body so proposer and verifiers work from identical bytes.
	CGEWitnesses []*CGEReleaseWitness `json:"cge_witnesses,omitempty"`
}

// NEW: Attestation struct — each attestation represents a PBFT commit vote
// from a validator for a specific block. The cumulative weight of all
// attestations for a chain determines the canonical fork.
type Attestation struct {
	ValidatorID string `json:"validator_id"`
	Signature   []byte `json:"signature"`
	BlockHash   string `json:"block_hash"`
	View        uint64 `json:"view"`
	// Stake is the validator's stake at the time of attestation, cached here
	// so that chain weight calculation does NOT require live validator set
	// lookups that could change between epochs.
	Stake *big.Int `json:"stake,omitempty"`
}

// Block represents the entire block structure including the header and body.
type Block struct {
	Header *BlockHeader `json:"header"`
	Body   BlockBody    `json:"body"`

	// ChainWeight is cached cumulative weight for fast fork-choice decisions.
	// It is set once during chain processing and does not participate in
	// block hash computation.
	ChainWeight *big.Int `json:"-"`
}

// Transaction represents a blockchain transaction
type Transaction struct {
	ID         string   `json:"id"`
	ChainID    uint64   `json:"chain_id"` // EIP-155: Chain ID to prevent cross-chain replay attacks
	Sender     string   `json:"sender"`
	Receiver   string   `json:"receiver"`
	Amount     *big.Int `json:"amount"`
	GasLimit   *big.Int `json:"gas_limit"`
	GasPrice   *big.Int `json:"gas_price"`
	Nonce      uint64   `json:"nonce"`
	Timestamp  int64    `json:"timestamp"`
	Signature  []byte   `json:"signature"`
	ReturnData []byte   `json:"return_data"` // OP_RETURN data (memos, proofs, metadata)
	// Optional data
	Data           []byte `json:"data,omitempty"`
	Code           []byte `json:"code,omitempty"`             // Contract deployment bytecode
	CallData       []byte `json:"call_data,omitempty"`        // Contract call input data
	ToContract     string `json:"to_contract,omitempty"`      // Target contract address for calls
	SignatureHash  []byte `json:"signature_hash"`             // 32-byte hash of signature for replay detection
	PublicKey      []byte `json:"public_key"`                 // Serialized SPHINCS+ public key
	AuthTimestamp  []byte `json:"auth_timestamp,omitempty"`   // 8-byte timestamp bound inside the SPHINCS signature
	AuthNonce      []byte `json:"auth_nonce,omitempty"`       // 16-byte random nonce bound inside the SPHINCS signature
	MerkleRootHash []byte `json:"merkle_root_hash,omitempty"` // SPHINCS+ receipt root derived from signature leaves
	Commitment     []byte `json:"commitment,omitempty"`       // Binding commitment over signature, key, timestamp, nonce, and tx ID
	Proof          []byte `json:"proof,omitempty"`            // Lightweight consistency proof for the receipt fields

	// MultiSigWitness authorizes a spend from a custody policy address (the
	// genesis vault, the CGE escrow, or any future custody address). It is an
	// alternative to the single-key bundle above, not a replacement: a sender
	// that resolves to a registered policy is authorized by this witness and
	// only by this witness. Ordinary single-key transactions leave it nil, so
	// they serialize byte-for-byte as before.
	MultiSigWitness *multisig.MultiSigWitness `json:"multisig_witness,omitempty"`
}

// GenesisVaultAddress is the protocol-owned vault address. Genesis allocation
// transactions are sent from it, and those are the only transactions that are
// ever valid without an external SPHINCS+ signature. After block 0 the vault is
// an ordinary account (a multisig policy address) and its spends must be
// authorized through the normal transaction auth path.
var GenesisVaultAddress = "0000000000000000000000000000000000000001"

// legacyGenesisVaultAddress is the pre-multisig vault address. Kept so chains
// built before the vault became a multisig policy address still recognize
// their own block-0 funding transactions.
const legacyGenesisVaultAddress = "0000000000000000000000000000000000000001"

// CGEReleaseWitness pairs a CGE escrow-release recipient with the SPHINCS+
// M-of-N witness that authorizes that release. It travels inside the block
// body so a verifier can apply the release from the block's own bytes alone —
// no side channel, no local pool.
type CGEReleaseWitness struct {
	Recipient string                   `json:"recipient"`
	Witness   multisig.MultiSigWitness `json:"witness"`
}

// GenesisAllocationTxID returns the deterministic identifier of one genesis
// funding transaction: hex(SpxHash(receiver || amountBytes || index)). This is
// the single definition of the formula; GenesisState.buildBlock uses it too,
// so the shape check in IsSystemTransaction can never drift from the IDs the
// genesis builder actually emits.
func GenesisAllocationTxID(receiver string, amount *big.Int, index uint64) string {
	buf := []byte(receiver)
	if amount != nil {
		buf = append(buf, amount.Bytes()...)
	}
	var indexBytes [8]byte
	binary.BigEndian.PutUint64(indexBytes[:], index)
	buf = append(buf, indexBytes[:]...)
	return hex.EncodeToString(common.SpxHash(buf))
}

func isGenesisVaultSender(addr string) bool {
	return addr == GenesisVaultAddress || addr == legacyGenesisVaultAddress
}

// IsSystemTransaction reports whether tx has exactly the shape of a
// protocol-created genesis allocation transaction: sent from the genesis
// vault, carrying no SPHINCS authorization material and no gas, and carrying
// the deterministic genesis-funding ID of its own (receiver, amount, nonce).
//
// Sender identity alone is NOT enough — an ordinary vault spend is not a
// system transaction. This is only a *shape* test and is height-free, so it is
// informational (explorer badges, tooling). Every authorization or admission
// decision must use IsSystemTransactionAt(height), which additionally requires
// the transaction to be inside block 0.
func (tx *Transaction) IsSystemTransaction() bool {
	if tx == nil || !isGenesisVaultSender(tx.Sender) {
		return false
	}
	if tx.Amount == nil || tx.Amount.Sign() <= 0 {
		return false
	}
	// Genesis funding transactions are unsigned by construction; any auth
	// material means this is a real (authorized) transaction, not a
	// protocol-created distribution.
	if len(tx.Signature) != 0 || len(tx.PublicKey) != 0 || len(tx.Proof) != 0 ||
		len(tx.SignatureHash) != 0 || len(tx.Commitment) != 0 || len(tx.MerkleRootHash) != 0 ||
		len(tx.AuthTimestamp) != 0 || len(tx.AuthNonce) != 0 {
		return false
	}
	if tx.GasLimit != nil && tx.GasLimit.Sign() != 0 {
		return false
	}
	if tx.GasPrice != nil && tx.GasPrice.Sign() != 0 {
		return false
	}
	// A genesis funding transaction is a bare value transfer: no contract
	// payload, no memo, no OP_RETURN.
	if len(tx.Code) != 0 || len(tx.CallData) != 0 || len(tx.Data) != 0 ||
		len(tx.ReturnData) != 0 || tx.ToContract != "" {
		return false
	}
	return tx.ID != "" && tx.ID == GenesisAllocationTxID(tx.Receiver, tx.Amount, tx.Nonce)
}

// IsSystemTransactionAt is the authorization-relevant form of
// IsSystemTransaction: the unsigned genesis exemption applies only to block 0.
// A vault spend at any later height returns false, so it must satisfy the
// normal auth path (and, for the vault/escrow policy addresses, the M-of-N
// custody path) exactly like any other spend.
func (tx *Transaction) IsSystemTransactionAt(height uint64) bool {
	return height == 0 && tx.IsSystemTransaction()
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
	stopCh             chan struct{}
	stopOnce           sync.Once
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

// NFTAnchorPayload is the contract-like record committed in tx.ReturnData.
// It is the Sphinx equivalent of ERC-721 contract storage for tokenURI:
// the tx itself is permanent, and the payload binds mint_id to an IPFS CID.
type NFTAnchorPayload struct {
	Type       string `json:"type"` // always sphinx_nft_anchor
	Version    int    `json:"v"`
	MintID     string `json:"mid"`
	Subject    string `json:"sub,omitempty"`
	CID        string `json:"cid"`
	CIDHashHex string `json:"ch"` // sha256(CID) as hex
	Timestamp  int64  `json:"ts"`

	// RoyaltyBPS is the anchored asset's resale-royalty share in basis points
	// (0..10000) of the sale price carried by each transfer_from transaction.
	// 0 (unset) = no resale royalty. Deliberately a fraction of value, never a
	// flat fee, so it prices the liquid trade, not the mint.
	RoyaltyBPS uint64 `json:"rbps,omitempty"`

	// UsageFeeNSPX is the per licensed-access micro-fee in nSPX for this
	// anchored data (dataset pull, license exercise, training ingest). Decimal
	// string so arbitrary nSPX magnitudes survive JSON round-trips.
	UsageFeeNSPX string `json:"ufee,omitempty"`

	// RoyaltyRecipient overrides the default payout address (anchor sender).
	// Lets a collection route creator revenue elsewhere (treasury, joint
	// ownership) without changing ownership semantics.
	RoyaltyRecipient string `json:"rr,omitempty"`
}
