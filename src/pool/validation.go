// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/pool/validation.go
package pool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	svm "github.com/sphinxfndorg/protocol/src/core/svm/opcodes"
	vmachine "github.com/sphinxfndorg/protocol/src/core/svm/vm"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	logger "github.com/sphinxfndorg/protocol/src/log"
)

// uint32ToBytesPool converts uint32 to big-endian 4 bytes for VM PUSH4 operands.
// This is used when pushing 32-bit values onto the SVM stack.
func uint32ToBytesPool(n uint32) []byte {
	// Shift and mask each byte to create big-endian representation
	return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// uint64ToBytesPool converts uint64 to big-endian 8 bytes for VM PUSH8 operands.
// This is used when pushing 64-bit values (timestamps, nonces, balances) onto the SVM stack.
func uint64ToBytesPool(n uint64) []byte {
	// Shift and mask each byte to create big-endian representation (most significant byte first)
	return []byte{
		byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
		byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
	}
}

// verifyTransactionSignature uses SVM to verify transaction signature.
//
// Memory layout:  [0 .. sigLen)             → signature bytes
//
//	[sigLen .. sigLen+pkLen)   → public key bytes (real SPHINCS+ key, NOT sender address)
//	[sigLen+pkLen .. end)      → full message bytes
//
// OP_CHECK_SPHINCS pop order: msgLen, msgPtr, pkLen, pkPtr, sigLen, sigPtr
// Push order (bottom→top):   sigPtr, sigLen, pkPtr, pkLen, msgPtr, msgLen
//
// IMPORTANT: tx.PublicKey must carry the sender's serialized SPHINCS+ public key.
// tx.Sender is a human-readable address string and must NOT be used as pkBytes —
// passing an address string to DeserializePublicKey causes "incorrect length" errors.
// go/src/pool/validation.go

func (mp *Mempool) verifyTransactionSignature(tx *types.Transaction) error {
	// Genesis vault transactions are TRUSTED protocol transactions
	// They don't have SPHINCS+ signatures - skip all cryptographic verification
	// The genesis vault address is a special system address used for initial coin distribution
	if tx.IsSystemTransaction() {
		logger.Debug("Genesis vault transaction %s is trusted, skipping signature verification", tx.ID)
		return nil
	}

	// For NON-genesis transactions, we REQUIRE full SPHINCS+ verification
	// Check if signature hash exists (32-byte hash used for replay protection)
	if len(tx.SignatureHash) == 0 {
		return fmt.Errorf("missing signature hash for transaction %s", tx.ID)
	}

	// Verify signature hash is exactly 32 bytes (standard hash length)
	if len(tx.SignatureHash) != 32 {
		return fmt.Errorf("invalid signature hash length: expected 32, got %d for tx %s",
			len(tx.SignatureHash), tx.ID)
	}

	// Check if signature data is present
	if len(tx.Signature) == 0 {
		return fmt.Errorf("missing signature for transaction %s", tx.ID)
	}

	// Check if public key is present (required for SPHINCS+ verification)
	if len(tx.PublicKey) == 0 {
		return fmt.Errorf("missing public key for transaction %s", tx.ID)
	}

	// Get the public key (already set in tx.PublicKey for non-genesis)
	pkBytes := tx.PublicKey

	tsBytes := tx.AuthTimestamp
	if len(tsBytes) == 0 {
		tsBytes = uint64ToBytesPool(uint64(tx.Timestamp))
	}

	nonceBytes := tx.AuthNonce
	if len(nonceBytes) == 0 {
		nonceBytes = make([]byte, 16)
		binary.BigEndian.PutUint64(nonceBytes[0:8], tx.Nonce)
	}

	if !tx.HasFullAuthBundle() {
		return fmt.Errorf("missing full SPHINCS transaction auth bundle")
	}

	// ========== 1. SPHINCS Manager Verification ==========
	if mp.sphincsManager != nil {
		if err := mp.sphincsManager.VerifyTransactionAuth(
			[]byte(tx.ID),
			tsBytes,
			nonceBytes,
			tx.Signature,
			pkBytes,
			tx.SignatureHash,
			tx.MerkleRootHash,
			tx.Commitment,
			tx.Proof,
			false,
		); err != nil {
			return fmt.Errorf("SPHINCS manager verification failed: %w", err)
		}
		logger.Debug("SPHINCS manager verification passed: %s", tx.ID)
	} else {
		logger.Warn("SPHINCS manager not available, falling back to SVM verification")
	}

	// ========== 2. SVM Verification ==========

	// Build the message that was signed
	// Format: timestamp(8) || nonce(16) || txID
	// This ensures each transaction has a unique signed message
	fullMsg := make([]byte, 0, 8+16+len(tx.ID))
	fullMsg = append(fullMsg, tsBytes...)
	fullMsg = append(fullMsg, nonceBytes...)

	// Append transaction ID as the final part of the message
	fullMsg = append(fullMsg, []byte(tx.ID)...)

	// Setup memory layout for SVM verification
	// Memory is organized as: [signature][signature_hash][public_key][message]
	sigLen := len(tx.Signature)
	pkLen := len(pkBytes)
	msgLen := len(fullMsg)

	// Calculate offsets for each section in memory
	hashOffset := sigLen          // Signature hash starts right after signature
	pkOffset := hashOffset + 32   // Public key starts after signature hash (32 bytes)
	msgOffset := pkOffset + pkLen // Message starts after public key

	// Allocate contiguous memory block for all data
	memoryLayout := make([]byte, sigLen+32+pkLen+msgLen)

	// Copy signature to memory at offset 0
	copy(memoryLayout[0:sigLen], tx.Signature)
	// Copy signature hash to memory right after signature
	copy(memoryLayout[hashOffset:hashOffset+32], tx.SignatureHash)
	// Copy public key to memory after signature hash
	copy(memoryLayout[pkOffset:pkOffset+pkLen], pkBytes)
	// Copy message to memory after public key
	copy(memoryLayout[msgOffset:msgOffset+msgLen], fullMsg)

	// Build bytecode for verification
	bc := []byte{}

	// OP_CHECK_SIGNATURE_HASH - Verifies the signature hash matches the transaction data
	// This prevents replay attacks by ensuring each signature is unique per transaction

	// Push 32 (hash length) onto the stack
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(32)...)

	// Push the memory offset where the signature hash is stored
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(hashOffset))...)

	// Push the signature length onto the stack
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(sigLen))...)

	// Push the signature offset (0, at the start of memory)
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(0)...)

	// Execute OP_CHECK_SIGNATURE_HASH opcode
	bc = append(bc, byte(svm.OP_CHECK_SIGNATURE_HASH))
	// OP_VERIFY ensures the result is true (non-zero)
	bc = append(bc, byte(svm.OP_VERIFY))

	// OP_CHECK_SPHINCS - Verifies the SPHINCS+ signature

	// Push message length onto stack
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(msgLen))...)

	// Push message offset (where message is stored in memory)
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(msgOffset))...)

	// Push public key length onto stack
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(pkLen))...)

	// Push public key offset onto stack
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(pkOffset))...)

	// Push signature length onto stack
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(sigLen))...)

	// Push signature offset (0, at the start of memory) onto stack
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(0)...)

	// Execute OP_CHECK_SPHINCS opcode to verify the signature
	bc = append(bc, byte(svm.OP_CHECK_SPHINCS))
	// OP_VERIFY ensures the verification succeeded
	bc = append(bc, byte(svm.OP_VERIFY))

	// Store the signature hash to prevent replay attacks
	// This records that this signature hash has been used
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(32)...)

	// Push the memory offset of the signature hash
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(hashOffset))...)

	// Store the signature hash in the VM's state
	bc = append(bc, byte(svm.OP_STORE_SIGNATURE_HASH))

	// Execute verification program with the prepared memory layout
	result, err := vmachine.RunProgramWithMemory(bc, memoryLayout)
	if err != nil {
		return fmt.Errorf("signature verification failed for tx %s: %w", tx.ID, err)
	}

	// Result is ignored as OP_VERIFY would have failed if verification failed
	_ = result

	logger.Debug("Transaction signature verified successfully: %s", tx.ID)
	return nil
}

// verifyTransactionNonce uses SVM to validate transaction nonce.
//
// The chain enforces strict account-nonce semantics: a transaction is only
// valid if its nonce exactly equals the sender's current state nonce (see
// executor.go's applyTransactions, which rejects with "bad nonce: got X want
// Y" on any mismatch, not just on nonces that are too low). This function
// previously required tx.Nonce > currentNonce (strictly greater), which is
// off by one against that contract: the correct next nonce for any sender
// IS the current nonce, not one past it. That mismatch let transactions with
// nonces ahead of the correct value sit in pendingPool, while the one
// transaction that would actually be accepted by applyTransactions failed
// mempool admission. Equality is expressed as (>= AND <=) using the same
// GT/LT/ISZERO idiom already used elsewhere in this file, since no EQ opcode
// is available.
func (mp *Mempool) verifyTransactionNonce(tx *types.Transaction, currentNonce uint64) error {
	// ---- Check tx.Nonce >= currentNonce, i.e. NOT(tx.Nonce < currentNonce) ----
	bcGTE := []byte{}
	bcGTE = append(bcGTE, byte(svm.PUSH8))
	bcGTE = append(bcGTE, uint64ToBytesPool(tx.Nonce)...)
	bcGTE = append(bcGTE, byte(svm.PUSH8))
	bcGTE = append(bcGTE, uint64ToBytesPool(currentNonce)...)
	bcGTE = append(bcGTE, byte(svm.LT))
	bcGTE = append(bcGTE, byte(svm.ISZERO))

	vmGTE := vmachine.NewVM(bcGTE)
	if err := vmGTE.Run(); err != nil {
		return fmt.Errorf("VM nonce validation failed: %w", err)
	}
	resultGTE, err := vmGTE.GetResult()
	if err != nil {
		return fmt.Errorf("VM result error: %w", err)
	}

	// ---- Check tx.Nonce <= currentNonce, i.e. NOT(tx.Nonce > currentNonce) ----
	bcLTE := []byte{}
	bcLTE = append(bcLTE, byte(svm.PUSH8))
	bcLTE = append(bcLTE, uint64ToBytesPool(tx.Nonce)...)
	bcLTE = append(bcLTE, byte(svm.PUSH8))
	bcLTE = append(bcLTE, uint64ToBytesPool(currentNonce)...)
	bcLTE = append(bcLTE, byte(svm.GT))
	bcLTE = append(bcLTE, byte(svm.ISZERO))

	vmLTE := vmachine.NewVM(bcLTE)
	if err := vmLTE.Run(); err != nil {
		return fmt.Errorf("VM nonce validation failed: %w", err)
	}
	resultLTE, err := vmLTE.GetResult()
	if err != nil {
		return fmt.Errorf("VM result error: %w", err)
	}

	// Nonce is valid only if both >= and <= hold, i.e. tx.Nonce == currentNonce.
	if resultGTE != 1 || resultLTE != 1 {
		return fmt.Errorf("invalid nonce: %d must equal %d", tx.Nonce, currentNonce)
	}
	return nil
}

// verifyTransactionBalance uses SVM to check sender has sufficient balance.
// Ensures the sender has enough funds to cover the transaction amount
func (mp *Mempool) verifyTransactionBalance(tx *types.Transaction, senderBalance *big.Int) error {
	// Quick check using big.Int comparison (more efficient for large numbers)
	if senderBalance.Cmp(tx.Amount) < 0 {
		return fmt.Errorf("insufficient balance: have %s, need %s",
			senderBalance.String(), tx.Amount.String())
	}

	// Only proceed with VM verification if values fit in uint64
	if !senderBalance.IsUint64() || !tx.Amount.IsUint64() {
		return nil
	}

	// Convert to uint64 for VM operations
	balanceUint := senderBalance.Uint64()
	amountUint := tx.Amount.Uint64()

	bc := []byte{}

	// Push sender's balance onto the stack
	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(balanceUint)...)

	// Push transaction amount onto the stack
	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(amountUint)...)

	// Check if balance is less than amount (LT pushes 1 if true, 0 otherwise)
	bc = append(bc, byte(svm.LT))
	// ISZERO inverts the result (1 if balance >= amount, 0 otherwise)
	bc = append(bc, byte(svm.ISZERO))

	// Create and run the VM
	vm := vmachine.NewVM(bc)
	if err := vm.Run(); err != nil {
		return fmt.Errorf("VM balance validation failed: %w", err)
	}

	// Get the verification result
	result, err := vm.GetResult()
	if err != nil {
		return fmt.Errorf("VM result error: %w", err)
	}

	// Verify balance is sufficient (result should be 1)
	if result != 1 {
		return fmt.Errorf("insufficient balance: have %d, need %d", balanceUint, amountUint)
	}
	return nil
}

// verifyTransactionGas uses SVM to validate gas parameters.
// Checks that gas limit is within acceptable bounds and gas price meets minimum requirement
func (mp *Mempool) verifyTransactionGas(tx *types.Transaction, minGasPrice *big.Int) error {
	const maxGasLimit = uint64(1_000_000) // Maximum allowed gas per transaction

	// Extract uint64 values for VM operations
	gasLimitUint := tx.GasLimit.Uint64()
	gasPriceUint := tx.GasPrice.Uint64()
	minGasPriceUint := minGasPrice.Uint64()

	bc := []byte{}

	// Check 1: Gas limit must not exceed maximum allowed

	// Push transaction gas limit onto stack
	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(gasLimitUint)...)

	// Push maximum gas limit onto stack
	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(maxGasLimit)...)

	// Check if gas limit exceeds maximum (GT pushes 1 if gasLimit > maxGasLimit)
	bc = append(bc, byte(svm.GT))
	// ISZERO makes it 1 if gasLimit <= maxGasLimit (valid)
	bc = append(bc, byte(svm.ISZERO))

	// Check 2: Gas price must meet or exceed minimum

	// Push transaction gas price onto stack
	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(gasPriceUint)...)

	// Push minimum gas price onto stack
	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(minGasPriceUint)...)

	// Check if gas price is below minimum (LT pushes 1 if gasPrice < minGasPrice)
	bc = append(bc, byte(svm.LT))
	// ISZERO makes it 1 if gasPrice >= minGasPrice (valid)
	bc = append(bc, byte(svm.ISZERO))

	// AND combines both checks - result is 1 only if BOTH conditions are true
	bc = append(bc, byte(svm.And))

	// Create and run the VM
	vm := vmachine.NewVM(bc)
	if err := vm.Run(); err != nil {
		return fmt.Errorf("VM gas validation failed: %w", err)
	}

	// Get the combined validation result
	result, err := vm.GetResult()
	if err != nil {
		return fmt.Errorf("VM result error: %w", err)
	}

	// Verify both conditions passed
	if result != 1 {
		return fmt.Errorf("gas validation failed: limit=%d (max=%d), price=%d (min=%d)",
			gasLimitUint, maxGasLimit, gasPriceUint, minGasPriceUint)
	}
	return nil
}

// verifyTransactionReplayProtection uses SVM to check tx.Timestamp > lastTimestamp.
// Prevents replay attacks by ensuring transaction timestamps are strictly increasing
func (mp *Mempool) verifyTransactionReplayProtection(tx *types.Transaction, lastTimestamp int64) error {
	// If no previous timestamp exists, skip validation (first transaction from this sender)
	if lastTimestamp == 0 {
		return nil
	}

	bc := []byte{}

	// Push transaction timestamp onto stack
	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(uint64(tx.Timestamp))...)

	// Push last recorded timestamp onto stack
	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(uint64(lastTimestamp))...)

	// Check if current timestamp is greater than last timestamp
	bc = append(bc, byte(svm.GT))

	// Create and run the VM
	vm := vmachine.NewVM(bc)
	if err := vm.Run(); err != nil {
		return fmt.Errorf("VM replay protection validation failed: %w", err)
	}

	// Get the comparison result
	result, err := vm.GetResult()
	if err != nil {
		return fmt.Errorf("VM result error: %w", err)
	}

	// Verify timestamp is newer (result should be 1)
	if result != 1 {
		return fmt.Errorf("replay protection failed: timestamp %d must be > last %d",
			tx.Timestamp, lastTimestamp)
	}
	return nil
}

// getLastTransactionTimestamp retrieves the timestamp of the last transaction from a sender
func (mp *Mempool) getLastTransactionTimestamp(sender string) int64 {
	if mp.stateProvider == nil {
		logger.Warn("StateProvider not set, returning default timestamp 0")
		return 0
	}

	stateDB, err := mp.stateProvider.NewStateDB()
	if err != nil {
		logger.Error("Failed to create StateDB for timestamp query: %v", err)
		return 0
	}
	defer stateDB.Close()

	timestamp, err := stateDB.GetLastTransactionTimestamp(sender)
	if err != nil {
		// If no previous transactions, return 0 (skip replay protection)
		return 0
	}

	return timestamp
}

// validationProcessor is a background goroutine that processes transactions for validation
// It reads from validationChan and validates each transaction asynchronously
func (mp *Mempool) validationProcessor() {
	for {
		select {
		case pooledTx := <-mp.validationChan:
			// Process a single transaction for validation
			mp.validateTransaction(pooledTx)
		case <-mp.stopChan:
			// Shutdown signal received - exit the goroutine
			return
		}
	}
}

// validateTransaction performs comprehensive validation on a pooled transaction
// Updates transaction status based on validation results
func (mp *Mempool) validateTransaction(pooledTx *PooledTransaction) {
	startTime := time.Now() // Track validation duration for metrics
	tx := pooledTx.Transaction

	// Check OP_RETURN data size limit (prevents memory exhaustion attacks)
	const maxReturnSize = 80
	if len(tx.ReturnData) > maxReturnSize {
		// Lock the mempool to safely update transaction state
		mp.lock.Lock()
		defer mp.lock.Unlock()

		// Mark transaction as invalid due to oversized return data
		pooledTx.Status = StatusInvalid
		pooledTx.Error = fmt.Sprintf("OP_RETURN data exceeds maximum size of %d bytes", maxReturnSize)
		pooledTx.LastUpdated = time.Now()

		// Move transaction from validation pool to invalid pool
		delete(mp.validationPool, tx.ID)
		mp.invalidPool[tx.ID] = pooledTx

		// Update statistics
		mp.stats.totalInvalid++
		logger.Warn("Transaction validation failed: ID=%s, OP_RETURN size exceeded", tx.ID)
		return
	}

	// Perform all validation checks (signature, nonce, balance, gas, replay protection)
	err := mp.performValidation(tx)

	// Lock to update mempool state with validation results
	mp.lock.Lock()
	defer mp.lock.Unlock()

	// Calculate and record validation duration for performance monitoring
	validationTime := time.Since(startTime)
	mp.stats.validationTime += validationTime

	if err != nil {
		// Validation failed - mark as invalid and move to invalid pool
		pooledTx.Status = StatusInvalid
		pooledTx.Error = err.Error()
		pooledTx.LastUpdated = time.Now()

		delete(mp.validationPool, tx.ID)
		mp.invalidPool[tx.ID] = pooledTx

		mp.stats.totalInvalid++
		logger.Warn("Transaction validation failed: ID=%s, error=%v", tx.ID, err)
	} else {
		// Validation succeeded - mark as pending and move to pending pool
		pooledTx.Status = StatusPending
		pooledTx.LastUpdated = time.Now()

		delete(mp.validationPool, tx.ID)
		mp.pendingPool[tx.ID] = pooledTx

		mp.stats.totalValidated++
		logger.Debug("Transaction validated: ID=%s, time=%v", tx.ID, validationTime)
	}
}

// performValidation executes all validation checks for a transaction
// Returns an error if any validation check fails
func (mp *Mempool) performValidation(tx *types.Transaction) error {
	// Genesis vault transactions are TRUSTED protocol transactions
	// They don't have SPHINCS+ signatures because they're system-level distributions.
	// IMPORTANT: "trusted" only ever meant "skip cryptographic signature
	// verification". Nonce and replay-protection checks still apply to system
	// transactions — a stale or duplicate nonce from the vault is exactly as
	// invalid as one from a regular sender, and skipping the check here was
	// the reason stale-nonce vault transactions could sit in pendingPool
	// forever and later get selected into a block with a nonce the chain had
	// already passed (e.g. "bad nonce: got 0 want 9").
	if tx.IsSystemTransaction() {
		logger.Debug("Genesis vault transaction %s is trusted, skipping cryptographic verification", tx.ID)

		// Still do basic sanity checks for safety
		if err := tx.SanityCheck(); err != nil {
			return fmt.Errorf("sanity check failed: %w", err)
		}

		// Validate sender and receiver addresses are not empty
		if tx.Sender == "" || tx.Receiver == "" {
			return errors.New("empty sender or receiver")
		}

		// Validate amount is positive
		if tx.Amount == nil || tx.Amount.Cmp(big.NewInt(0)) <= 0 {
			return errors.New("invalid amount")
		}

		// Verify nonce even for system transactions. No signature verification
		// needed for genesis vault, but nonce ordering must still hold or stale
		// vault transactions accumulate in pendingPool with no way to be
		// invalidated later.
		currentNonce := mp.getSenderNonce(tx.Sender)
		if err := mp.verifyTransactionNonce(tx, currentNonce); err != nil {
			return fmt.Errorf("nonce validation failed: %w", err)
		}

		return nil
	}

	// For NON-genesis transactions, ALL verifications must pass

	// Check transaction size against configured maximum
	txSize := mp.CalculateTransactionSize(tx)
	if txSize > mp.config.MaxTxSize {
		return fmt.Errorf("transaction size %d exceeds maximum %d bytes", txSize, mp.config.MaxTxSize)
	}

	// Perform basic sanity checks (valid fields, proper formatting)
	if err := tx.SanityCheck(); err != nil {
		return fmt.Errorf("sanity check failed: %w", err)
	}

	// Validate addresses are present
	if tx.Sender == "" || tx.Receiver == "" {
		return errors.New("empty sender or receiver")
	}

	// Validate amount is positive
	if tx.Amount == nil || tx.Amount.Cmp(big.NewInt(0)) <= 0 {
		return errors.New("invalid amount")
	}

	// Validate gas parameters exist
	if tx.GasLimit == nil || tx.GasPrice == nil {
		return errors.New("missing gas parameters")
	}

	// Verify cryptographic signature (this will fail if signature is invalid or public key missing)
	if err := mp.verifyTransactionSignature(tx); err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
	}

	// Verify nonce to prevent replay attacks
	currentNonce := mp.getSenderNonce(tx.Sender)
	if err := mp.verifyTransactionNonce(tx, currentNonce); err != nil {
		return fmt.Errorf("nonce validation failed: %w", err)
	}

	// Verify sender has sufficient balance for the transaction
	senderBalance := mp.getSenderBalance(tx.Sender)
	if err := mp.verifyTransactionBalance(tx, senderBalance); err != nil {
		return fmt.Errorf("balance validation failed: %w", err)
	}

	// Verify gas parameters meet minimum requirements
	minGasPrice := mp.getMinimumGasPrice()
	if err := mp.verifyTransactionGas(tx, minGasPrice); err != nil {
		return fmt.Errorf("gas validation failed: %w", err)
	}

	// Verify timestamp is newer than last transaction (replay protection)
	lastTimestamp := mp.getLastTransactionTimestamp(tx.Sender)
	if err := mp.verifyTransactionReplayProtection(tx, lastTimestamp); err != nil {
		return fmt.Errorf("replay protection failed: %w", err)
	}

	logger.Debug("All SVM validations passed for transaction %s", tx.ID)
	return nil
}

// getSenderNonce retrieves the current nonce for a given sender address
// This is a stub method that would query the blockchain state in production
// getSenderNonce retrieves the current nonce for a given sender address
// getSenderNonce retrieves the current nonce for a given sender address
func (mp *Mempool) getSenderNonce(sender string) uint64 {
	if mp.stateProvider == nil {
		logger.Warn("StateProvider not set, returning default nonce 0")
		return 0
	}

	stateDB, err := mp.stateProvider.NewStateDB()
	if err != nil {
		logger.Error("Failed to create StateDB for nonce query: %v", err)
		return 0
	}
	defer stateDB.Close()

	nonce, err := stateDB.GetNonce(sender)
	if err != nil {
		return 0 // ← Returns 0 for new accounts
	}
	return nonce
}

// getSenderBalance retrieves the current balance for a given sender address
func (mp *Mempool) getSenderBalance(sender string) *big.Int {
	if mp.stateProvider == nil {
		logger.Warn("StateProvider not set, returning default balance 0")
		return big.NewInt(0)
	}

	stateDB, err := mp.stateProvider.NewStateDB()
	if err != nil {
		logger.Error("Failed to create StateDB for balance query: %v", err)
		return big.NewInt(0)
	}
	defer stateDB.Close()

	balance, err := stateDB.GetBalance(sender)
	if err != nil {
		logger.Error("Failed to get balance for %s: %v", sender, err)
		return big.NewInt(0)
	}

	return balance
}

// getMinimumGasPrice returns the minimum acceptable gas price for transactions
// This is a stub method that would be configurable in production
func (mp *Mempool) getMinimumGasPrice() *big.Int {
	// Return 1 Gwei as minimum gas price (1,000,000,000 wei)
	return new(big.Int).SetUint64(1000000000)
}

// validateTransactionBasic performs minimal validation on a transaction
// This is a lightweight check for fundamental transaction properties
func (mp *Mempool) validateTransactionBasic(tx *types.Transaction) error {
	// Check for nil transaction pointer
	if tx == nil {
		return errors.New("nil transaction")
	}

	// Verify sender and receiver addresses are not empty
	if tx.Sender == "" || tx.Receiver == "" {
		return errors.New("empty sender or receiver")
	}

	// Verify amount exists and is positive
	if tx.Amount == nil || tx.Amount.Cmp(big.NewInt(0)) <= 0 {
		return errors.New("invalid amount")
	}

	return nil
}
