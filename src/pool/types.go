// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/pool/types.go
package pool

import (
	"math/big"
	"sync"
	"time"

	sign "github.com/sphinxorg/protocol/src/core/sthincs/sign/backend" // ADD THIS
	types "github.com/sphinxorg/protocol/src/core/transaction"
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
}

// Mempool manages all transaction pools (broadcast, pending, validation)
type Mempool struct {
	lock sync.RWMutex

	// Main pools
	broadcastPool  map[string]*PooledTransaction // Newly broadcast transactions
	pendingPool    map[string]*PooledTransaction // Validated transactions waiting for blocks
	validationPool map[string]*PooledTransaction // Transactions being validated
	invalidPool    map[string]*PooledTransaction // Failed transactions (for monitoring)

	// Indexes for quick lookup
	allTransactions map[string]*PooledTransaction

	// Configuration
	config *MempoolConfig

	// Memory tracking
	currentBytes uint64 // tracks total bytes used by transactions

	// ADD THIS: SPHINCS+ manager for signature hash verification
	sphincsManager *sign.SphincsManager

	// ADD THIS FIELD:
	publicKeyRegistry map[string][]byte // Maps sender address -> serialized SPHINCS+ public key

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
