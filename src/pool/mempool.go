// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/pool/mempool.go
package pool

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/sphinxorg/protocol/src/common"
	sign "github.com/sphinxorg/protocol/src/core/sthincs/sign/backend"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	logger "github.com/sphinxorg/protocol/src/log"
)

// NewMempool creates a new comprehensive mempool instance
// CHANGE: Accept BlockchainStateProvider interface instead of *core.Blockchain
func NewMempool(config *MempoolConfig, stateProvider BlockchainStateProvider) *Mempool {
	if config == nil {
		config = &MempoolConfig{
			MaxSize:           10000,
			MaxBytes:          100 * 1024 * 1024,
			MaxTxSize:         100 * 1024,
			ValidationTimeout: 30 * time.Second,
			ExpiryTime:        24 * time.Hour,
			MaxBroadcastSize:  5000,
			MaxPendingSize:    5000,
		}
	}

	mp := &Mempool{
		broadcastPool:     make(map[string]*PooledTransaction),
		pendingPool:       make(map[string]*PooledTransaction),
		validationPool:    make(map[string]*PooledTransaction),
		invalidPool:       make(map[string]*PooledTransaction),
		allTransactions:   make(map[string]*PooledTransaction),
		config:            config,
		currentBytes:      0,
		stateProvider:     stateProvider, // Store interface reference
		broadcastChan:     make(chan *types.Transaction, 1000),
		validationChan:    make(chan *PooledTransaction, 1000),
		cleanupChan:       make(chan struct{}, 1),
		stopChan:          make(chan struct{}),
		running:           false,
		publicKeyRegistry: make(map[string][]byte),
	}

	mp.startWorkers()
	return mp
}

// SetSTHINCSManager configures the verifier used for full SPHINCS transaction
// authentication checks: signature hash, proof, commitment, and receipt root.
func (mp *Mempool) SetSTHINCSManager(manager *sign.STHINCSManager) {
	mp.lock.Lock()
	defer mp.lock.Unlock()
	mp.sphincsManager = manager
}

// AddPublicKeyToRegistry registers a public key for a sender address
func (mp *Mempool) AddPublicKeyToRegistry(senderAddress string, publicKey []byte) {
	mp.lock.Lock()
	defer mp.lock.Unlock()
	mp.publicKeyRegistry[senderAddress] = publicKey
	logger.Debug("Registered public key for sender: %s", senderAddress)
}

// GetPublicKeyFromRegistry retrieves a public key for a sender address
func (mp *Mempool) GetPublicKeyFromRegistry(senderAddress string) ([]byte, bool) {
	mp.lock.RLock()
	defer mp.lock.RUnlock()
	pk, ok := mp.publicKeyRegistry[senderAddress]
	return pk, ok
}

// Start background workers for processing
func (mp *Mempool) startWorkers() {
	mp.running = true

	// Broadcast processor
	go mp.broadcastProcessor()

	// Validation processor
	go mp.validationProcessor()

	// Cleanup worker
	go mp.cleanupWorker()
}

// Stop the mempool and all workers
func (mp *Mempool) Stop() {
	mp.lock.Lock()
	defer mp.lock.Unlock()

	if mp.running {
		close(mp.stopChan)
		mp.running = false
	}
}

// BroadcastTransaction adds a new transaction to the broadcast pool
// Now with SVM signature verification
func (mp *Mempool) BroadcastTransaction(tx *types.Transaction) error {
	mp.lock.Lock()
	defer mp.lock.Unlock()

	// Basic validation
	if err := mp.validateTransactionBasic(tx); err != nil {
		return fmt.Errorf("basic validation failed: %w", err)
	}

	// Ensure transaction has ID
	if tx.ID == "" {
		tx.ID = mp.generateTransactionID(tx)
	}

	// Check if transaction already exists in any pool
	if existing := mp.allTransactions[tx.ID]; existing != nil {
		return fmt.Errorf("transaction %s already exists with status %d", tx.ID, existing.Status)
	}

	// ========== SVM SIGNATURE VERIFICATION ==========
	// Verify transaction signature using SVM before adding to mempool
	// Skip genesis vault transactions (they are trusted)
	if tx.Sender != "0000000000000000000000000000000000000001" { // Genesis vault address
		if err := mp.verifyTransactionSignature(tx); err != nil {
			return fmt.Errorf("SVM signature verification failed: %w", err)
		}
		logger.Debug("SVM: Transaction signature verified for %s", tx.ID)
	}
	// =================================================

	// Check broadcast pool limits
	if len(mp.broadcastPool) >= mp.config.MaxBroadcastSize {
		return errors.New("broadcast pool is full")
	}

	// Check memory limits
	txSize := mp.CalculateTransactionSize(tx)
	if mp.currentBytes+txSize > mp.config.MaxBytes {
		return fmt.Errorf("mempool byte limit exceeded: current=%d, tx=%d, max=%d",
			mp.currentBytes, txSize, mp.config.MaxBytes)
	}

	// Create pooled transaction
	pooledTx := &PooledTransaction{
		Transaction: tx,
		Status:      StatusBroadcast,
		FirstSeen:   time.Now(),
		LastUpdated: time.Now(),
		Priority:    mp.calculatePriority(tx),
	}

	// Add to pools and update byte count
	mp.broadcastPool[tx.ID] = pooledTx
	mp.allTransactions[tx.ID] = pooledTx
	mp.currentBytes += txSize
	mp.stats.totalAdded++

	// Send to broadcast channel for processing
	select {
	case mp.broadcastChan <- tx:
		mp.stats.totalBroadcast++
		logger.Debug("Transaction broadcast: ID=%s, size=%d bytes, total_bytes=%d",
			tx.ID, txSize, mp.currentBytes)
	default:
		// Channel full, will be picked up by next processing cycle
		logger.Warn("Broadcast channel full, transaction %s queued", tx.ID)
	}

	return nil
}

// broadcastProcessor handles incoming broadcast transactions
func (mp *Mempool) broadcastProcessor() {
	for {
		select {
		case tx := <-mp.broadcastChan:
			mp.processBroadcastTransaction(tx)
		case <-mp.stopChan:
			return
		}
	}
}

// processBroadcastTransaction moves broadcast transactions to validation
func (mp *Mempool) processBroadcastTransaction(tx *types.Transaction) {
	mp.lock.Lock()
	defer mp.lock.Unlock()

	pooledTx, exists := mp.broadcastPool[tx.ID]
	if !exists {
		return
	}

	// Move to validation pool (no byte count change, just status change)
	pooledTx.Status = StatusValidating
	pooledTx.LastUpdated = time.Now()

	delete(mp.broadcastPool, tx.ID)
	mp.validationPool[tx.ID] = pooledTx

	// Send for validation
	select {
	case mp.validationChan <- pooledTx:
		logger.Debug("Transaction sent for validation: ID=%s", tx.ID)
	default:
		// If validation channel is full, mark as pending and validate later
		pooledTx.Status = StatusPending
		delete(mp.validationPool, tx.ID)
		mp.pendingPool[tx.ID] = pooledTx
		logger.Warn("Validation channel full, transaction %s moved to pending", tx.ID)
	}
}

// generateTransactionID creates a unique ID for the transaction
func (mp *Mempool) generateTransactionID(tx *types.Transaction) string {
	data := fmt.Sprintf("%s%s%s%s%s%v%d",
		tx.Sender, tx.Receiver, tx.Amount.String(),
		tx.GasLimit.String(), tx.GasPrice.String(), tx.Nonce, time.Now().UnixNano())
	return hex.EncodeToString(common.SpxHash([]byte(data)))
}

// calculatePriority calculates transaction priority for inclusion ordering
func (mp *Mempool) calculatePriority(tx *types.Transaction) int {
	priority := 0

	// Higher gas price = higher priority
	if tx.GasPrice != nil {
		// Convert gas price to priority points (simplified)
		gasPriority := new(big.Int).Div(tx.GasPrice, big.NewInt(1e9)).Int64()
		if gasPriority > 100 {
			gasPriority = 100
		}
		priority += int(gasPriority)
	}

	// Larger amounts = higher priority (simplified)
	if tx.Amount != nil {
		amountPriority := new(big.Int).Div(tx.Amount, big.NewInt(1e18)).Int64()
		if amountPriority > 50 {
			amountPriority = 50
		}
		priority += int(amountPriority)
	}

	return priority
}

// GetPendingTransactions returns validated transactions ready for block inclusion
func (mp *Mempool) GetPendingTransactions() []*types.Transaction {
	mp.lock.RLock()
	defer mp.lock.RUnlock()

	var txs []*types.Transaction
	for _, pooledTx := range mp.pendingPool {
		if pooledTx.Status == StatusPending {
			txs = append(txs, pooledTx.Transaction)
		}
	}

	return txs
}

// SelectTransactionsForBlock selects transactions for block inclusion with priority
func (mp *Mempool) SelectTransactionsForBlock(maxBlockSize, targetBlockSize uint64) ([]*types.Transaction, uint64) {
	mp.lock.RLock()
	defer mp.lock.RUnlock()

	// Get all pending transactions and sort by priority
	var pendingList []*PooledTransaction
	for _, pooledTx := range mp.pendingPool {
		if pooledTx.Status == StatusPending {
			pendingList = append(pendingList, pooledTx)
		}
	}

	// Sort by priority (descending) and then by timestamp (ascending)
	sort.Slice(pendingList, func(i, j int) bool {
		if pendingList[i].Priority != pendingList[j].Priority {
			return pendingList[i].Priority > pendingList[j].Priority
		}
		return pendingList[i].FirstSeen.Before(pendingList[j].FirstSeen)
	})

	var selected []*types.Transaction
	currentSize := uint64(0)

	// Select transactions in priority order
	for _, pooledTx := range pendingList {
		tx := pooledTx.Transaction
		txSize := mp.CalculateTransactionSize(tx)

		// Check if transaction fits
		if currentSize+txSize > maxBlockSize {
			continue
		}

		selected = append(selected, tx)
		currentSize += txSize

		// Optional: stop at target size for optimization
		if currentSize >= targetBlockSize && len(selected) > 0 {
			break
		}
	}

	return selected, currentSize
}

// PruneStaleNonces removes pendingPool transactions whose nonce is now
// behind the sender's current on-chain nonce. Call this after a block
// commits so any pendingPool entry that was bypassed — for example by a
// fee-bump replacement, or any other path that advances a sender's nonce
// without that exact transaction being the one committed — gets cleared out
// instead of sitting in pendingPool indefinitely and later being selected
// into a block with a nonce the chain has already passed.
func (mp *Mempool) PruneStaleNonces(senders map[string]bool) {
	if mp.stateProvider == nil || len(senders) == 0 {
		return
	}
	stateDB, err := mp.stateProvider.NewStateDB()
	if err != nil {
		logger.Warn("PruneStaleNonces: failed to open stateDB: %v", err)
		return
	}
	defer stateDB.Close()

	mp.lock.Lock()
	defer mp.lock.Unlock()

	var staleIDs []string
	for txID, pooledTx := range mp.pendingPool {
		tx := pooledTx.Transaction
		if tx == nil || !senders[tx.Sender] {
			continue
		}
		currentNonce, err := stateDB.GetNonce(tx.Sender)
		if err != nil {
			logger.Warn("PruneStaleNonces: failed to get nonce for %s: %v", tx.Sender, err)
			continue
		}
		if tx.Nonce < currentNonce {
			staleIDs = append(staleIDs, txID)
		}
	}

	for _, txID := range staleIDs {
		mp.removeTransactionFromAllPools(txID)
	}
	if len(staleIDs) > 0 {
		logger.Info("PruneStaleNonces: evicted %d stale-nonce transactions from pendingPool", len(staleIDs))
	}
}

// RemoveTransactions removes transactions from all pools (e.g., when included in block)
func (mp *Mempool) RemoveTransactions(txIDs []string) {
	mp.lock.Lock()
	defer mp.lock.Unlock()

	for _, txID := range txIDs {
		mp.removeTransactionFromAllPools(txID)
	}
}

// removeTransactionFromAllPools removes a transaction from all pools
func (mp *Mempool) removeTransactionFromAllPools(txID string) {
	pooledTx := mp.allTransactions[txID]
	if pooledTx == nil {
		return
	}

	txSize := mp.CalculateTransactionSize(pooledTx.Transaction)

	// Remove from specific pool based on status
	switch pooledTx.Status {
	case StatusBroadcast:
		delete(mp.broadcastPool, txID)
	case StatusPending:
		delete(mp.pendingPool, txID)
	case StatusValidating:
		delete(mp.validationPool, txID)
	case StatusInvalid:
		delete(mp.invalidPool, txID)
	}

	// Remove from main index
	delete(mp.allTransactions, txID)

	// Update byte count if it was in a counted pool
	if pooledTx.Status == StatusBroadcast || pooledTx.Status == StatusPending || pooledTx.Status == StatusValidating {
		if mp.currentBytes >= txSize {
			mp.currentBytes -= txSize
		} else {
			// Shouldn't happen, but reset to avoid underflow
			mp.currentBytes = 0
		}
	}

	logger.Debug("Transaction removed from all pools: ID=%s, size=%d bytes, remaining_bytes=%d",
		txID, txSize, mp.currentBytes)
}

// GetTransaction returns a transaction by ID from any pool
func (mp *Mempool) GetTransaction(txID string) (*types.Transaction, TransactionStatus) {
	mp.lock.RLock()
	defer mp.lock.RUnlock()

	pooledTx := mp.allTransactions[txID]
	if pooledTx == nil {
		return nil, StatusInvalid
	}

	return pooledTx.Transaction, pooledTx.Status
}

// HasTransaction checks if a transaction exists in any pool
func (mp *Mempool) HasTransaction(txID string) bool {
	mp.lock.RLock()
	defer mp.lock.RUnlock()
	_, exists := mp.allTransactions[txID]
	return exists
}

// GetTransactionCount returns total transaction count across all pools
func (mp *Mempool) GetTransactionCount() int {
	mp.lock.RLock()
	defer mp.lock.RUnlock()
	return len(mp.allTransactions)
}

// GetPoolStats returns detailed statistics for each pool
func (mp *Mempool) GetPoolStats() map[string]interface{} {
	mp.lock.RLock()
	defer mp.lock.RUnlock()

	broadcastSize := 0
	pendingSize := 0
	validationSize := 0
	invalidSize := 0

	for _, tx := range mp.allTransactions {
		switch tx.Status {
		case StatusBroadcast:
			broadcastSize++
		case StatusPending:
			pendingSize++
		case StatusValidating:
			validationSize++
		case StatusInvalid:
			invalidSize++
		}
	}

	avgValidationTime := time.Duration(0)
	if mp.stats.totalValidated > 0 {
		avgValidationTime = mp.stats.validationTime / time.Duration(mp.stats.totalValidated)
	}

	return map[string]interface{}{
		"total_transactions":       len(mp.allTransactions),
		"broadcast_pool_size":      broadcastSize,
		"pending_pool_size":        pendingSize,
		"validation_pool_size":     validationSize,
		"invalid_pool_size":        invalidSize,
		"total_broadcast":          mp.stats.totalBroadcast,
		"total_validated":          mp.stats.totalValidated,
		"total_invalid":            mp.stats.totalInvalid,
		"total_expired":            mp.stats.totalExpired,
		"average_validation_time":  avgValidationTime.String(),
		"current_bytes":            mp.currentBytes,
		"max_bytes":                mp.config.MaxBytes,
		"byte_utilization_percent": float64(mp.currentBytes) / float64(mp.config.MaxBytes) * 100,
	}
}

// cleanupWorker periodically cleans up expired transactions
func (mp *Mempool) cleanupWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mp.cleanupExpiredTransactions()
		case <-mp.cleanupChan:
			mp.cleanupExpiredTransactions()
		case <-mp.stopChan:
			return
		}
	}
}

// cleanupExpiredTransactions removes transactions that have expired
func (mp *Mempool) cleanupExpiredTransactions() {
	mp.lock.Lock()
	defer mp.lock.Unlock()

	now := time.Now()
	expiredCount := 0

	for txID, pooledTx := range mp.allTransactions {
		if now.Sub(pooledTx.FirstSeen) > mp.config.ExpiryTime {
			mp.removeTransactionFromAllPools(txID)
			expiredCount++
			mp.stats.totalExpired++
		}
	}

	if expiredCount > 0 {
		logger.Info("Cleaned up %d expired transactions, current_bytes=%d", expiredCount, mp.currentBytes)
	}
}

// RetryFailedTransactions moves some invalid transactions back to broadcast for retry
func (mp *Mempool) RetryFailedTransactions(maxRetries int) int {
	mp.lock.Lock()
	defer mp.lock.Unlock()

	retryCount := 0
	for txID, pooledTx := range mp.invalidPool {
		if pooledTx.RetryCount < maxRetries {
			// Move back to broadcast pool for retry
			pooledTx.Status = StatusBroadcast
			pooledTx.RetryCount++
			pooledTx.LastUpdated = time.Now()

			delete(mp.invalidPool, txID)
			mp.broadcastPool[txID] = pooledTx

			// Update byte count (transactions in invalid pool don't count toward currentBytes)
			txSize := mp.CalculateTransactionSize(pooledTx.Transaction)
			mp.currentBytes += txSize

			// Send to broadcast channel
			select {
			case mp.broadcastChan <- pooledTx.Transaction:
				retryCount++
			default:
				// If channel is full, leave in broadcast pool for next cycle
			}
		}
	}

	if retryCount > 0 {
		logger.Info("Retried %d failed transactions, current_bytes=%d", retryCount, mp.currentBytes)
	}

	return retryCount
}

// CalculateTransactionSize calculates the approximate size of a transaction
func (mp *Mempool) CalculateTransactionSize(tx *types.Transaction) uint64 {
	size := uint64(len(tx.Sender) + len(tx.Receiver))

	if tx.Amount != nil {
		size += uint64(len(tx.Amount.Bytes()))
	}

	if tx.GasLimit != nil {
		size += uint64(len(tx.GasLimit.Bytes()))
	}
	if tx.GasPrice != nil {
		size += uint64(len(tx.GasPrice.Bytes()))
	}

	size += 8 // for Nonce (uint64)
	size += 8 // for Timestamp (int64)
	size += uint64(len(tx.ID))

	if tx.Signature != nil {
		size += uint64(len(tx.Signature))
	}
	if tx.SignatureHash != nil {
		size += uint64(len(tx.SignatureHash))
	}
	if tx.PublicKey != nil {
		size += uint64(len(tx.PublicKey))
	}
	if tx.AuthTimestamp != nil {
		size += uint64(len(tx.AuthTimestamp))
	}
	if tx.AuthNonce != nil {
		size += uint64(len(tx.AuthNonce))
	}
	if tx.MerkleRootHash != nil {
		size += uint64(len(tx.MerkleRootHash))
	}
	if tx.Commitment != nil {
		size += uint64(len(tx.Commitment))
	}
	if tx.Proof != nil {
		size += uint64(len(tx.Proof))
	}

	// CRITICAL: Include OP_RETURN data size - this data occupies real block space
	if tx.HasReturnData() && len(tx.ReturnData) > 0 {
		size += uint64(len(tx.ReturnData))
		logger.Debug("CalculateTransactionSize: including OP_RETURN data size=%d bytes", len(tx.ReturnData))
	}

	return size
}

// Clear clears all transactions from all pools
func (mp *Mempool) Clear() {
	mp.lock.Lock()
	defer mp.lock.Unlock()

	mp.broadcastPool = make(map[string]*PooledTransaction)
	mp.pendingPool = make(map[string]*PooledTransaction)
	mp.validationPool = make(map[string]*PooledTransaction)
	mp.invalidPool = make(map[string]*PooledTransaction)
	mp.allTransactions = make(map[string]*PooledTransaction)
	mp.currentBytes = 0

	logger.Info("Mempool cleared")
}

// GetStats returns comprehensive mempool statistics
func (mp *Mempool) GetStats() map[string]interface{} {
	poolStats := mp.GetPoolStats()

	// Add additional stats
	poolStats["max_size"] = mp.config.MaxSize
	poolStats["max_tx_size"] = mp.config.MaxTxSize
	poolStats["validation_timeout"] = mp.config.ValidationTimeout.String()
	poolStats["expiry_time"] = mp.config.ExpiryTime.String()
	poolStats["is_running"] = mp.running

	return poolStats
}

// GetCurrentBytes returns the current memory usage in bytes
func (mp *Mempool) GetCurrentBytes() uint64 {
	mp.lock.RLock()
	defer mp.lock.RUnlock()
	return mp.currentBytes
}

// GetMemoryUsage returns memory usage statistics
func (mp *Mempool) GetMemoryUsage() map[string]interface{} {
	mp.lock.RLock()
	defer mp.lock.RUnlock()

	return map[string]interface{}{
		"current_bytes":       mp.currentBytes,
		"max_bytes":           mp.config.MaxBytes,
		"available_bytes":     mp.config.MaxBytes - mp.currentBytes,
		"utilization_percent": float64(mp.currentBytes) / float64(mp.config.MaxBytes) * 100,
		"average_tx_size":     mp.calculateAverageTxSize(),
		"estimated_max_txs":   mp.config.MaxBytes / mp.calculateAverageTxSize(),
	}
}

// calculateAverageTxSize calculates the average transaction size
func (mp *Mempool) calculateAverageTxSize() uint64 {
	if len(mp.allTransactions) == 0 {
		return 0
	}
	return mp.currentBytes / uint64(len(mp.allTransactions))
}
