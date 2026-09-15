// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/pool/types.go
package pool

import (
	"math/big"
	"sync"
	"time"

	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend" // ADD THIS
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// TransactionStatus represents the state of a transaction in the pool
type TransactionStatus int

const (
	StatusBroadcast  TransactionStatus = iota // Newly broadcast, not yet validated
	StatusPending                             // Validated and waiting for block inclusion
	StatusValidating                          // Currently being validated
	StatusInvalid                             // Failed validation
	StatusExpired                             // Transaction expired
)

// PoolType distinguishes between different pool types
type PoolType int

const (
	PoolTypeBroadcast  PoolType = iota // For incoming broadcast transactions
	PoolTypePending                    // For validated transactions waiting for blocks
	PoolTypeValidation                 // For transactions undergoing validation
)

// MempoolConfig defines configuration for the mempool
type MempoolConfig struct {
	MaxSize           int
	MaxBytes          uint64
	MaxTxSize         uint64
	BlockGasLimit     *big.Int
	ValidationTimeout time.Duration
	ExpiryTime        time.Duration
	MaxBroadcastSize  int
	MaxPendingSize    int
}

// PooledTransaction wraps transaction with metadata
type PooledTransaction struct {
	Transaction *types.Transaction
	Status      TransactionStatus
	FirstSeen   time.Time
	LastUpdated time.Time
	RetryCount  int
	Error       string
	Priority    int // Higher priority transactions get included first

	// Validated is true only once performValidation has fully accepted the
	// transaction. It separates the two very different kinds of entry that
	// live in pendingPool:
	//
	//	StatusPending + Validated   → validated, ready for block inclusion
	//	StatusPending + !Validated  → parked because validationChan was full;
	//	                              still needs validating
	//
	// Only validated entries may be selected into a block, and only
	// un-validated ones may be re-queued for validation (see
	// drainPendingPool). Conflating the two is what made the block producer
	// see "0 pending tx" while a valid anchor sat in the pool: drainPendingPool
	// emptied the whole pendingPool every 500ms to re-validate it, so
	// already-validated transactions kept vanishing from the pool the producer
	// reads for the entire duration of each re-validation.
	Validated bool
}

// BalanceResult represents the balance information for an address
type BalanceResult struct {
	Confirmed *big.Int
	Pending   *big.Int
	Unlocked  *big.Int
}

// BlockchainStateProvider defines the interface that pool needs from blockchain
type BlockchainStateProvider interface {
	NewStateDB() (StateDB, error)
}

// StateDB defines the interface for state database operations
type StateDB interface {
	GetBalance(address string) (*big.Int, error)
	GetNonce(address string) (uint64, error)
	GetLastNonce(address string) (uint64, error)
	GetLastTransactionTimestamp(address string) (int64, error)
	GetBalanceResult(address string) (*BalanceResult, error)
	GetTransactionHistory(address string, limit int) ([]*types.Transaction, error)
	ContractExists(address string) bool
	Close() error
}

// Mempool manages all transaction pools (broadcast, pending, validation)
type Mempool struct {
	lock sync.RWMutex

	// Main pools
	broadcastPool   map[string]*PooledTransaction
	pendingPool     map[string]*PooledTransaction
	validationPool  map[string]*PooledTransaction
	invalidPool     map[string]*PooledTransaction
	allTransactions map[string]*PooledTransaction

	// accountNonceIndex maps "sender:nonce" -> the txID currently occupying
	// that account-nonce slot across broadcast/validation/pending. Ethereum-
	// style identity: an account can only have one live transaction per
	// nonce at a time. A new transaction for an occupied slot is only
	// admitted as a replace-by-fee (see isSufficientFeeBump in mempool.go);
	// otherwise it is rejected outright rather than left to sit alongside
	// the original and create an ambiguous choice at block-selection time.
	accountNonceIndex map[string]string

	// Configuration
	config *MempoolConfig

	// Memory tracking
	currentBytes uint64

	// SPHINCS+ manager
	sphincsManager *sign.STHINCSManager

	// CHANGE: Use interface instead of concrete type
	stateProvider BlockchainStateProvider

	publicKeyRegistry map[string][]byte

	// Statistics
	stats struct {
		totalAdded     uint64
		totalValidated uint64
		totalInvalid   uint64
		totalExpired   uint64
		totalBroadcast uint64
		validationTime time.Duration
	}

	// Channels for coordination
	broadcastChan  chan *types.Transaction
	validationChan chan *PooledTransaction
	cleanupChan    chan struct{}

	// Control
	stopChan chan struct{}
	running  bool
}
