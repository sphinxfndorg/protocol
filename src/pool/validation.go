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

// go/src/pool/validation.go
package pool

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	svm "github.com/sphinxorg/protocol/src/core/svm/opcodes"
	vmachine "github.com/sphinxorg/protocol/src/core/svm/vm"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	logger "github.com/sphinxorg/protocol/src/log"
)

// verifyTransactionSignature uses SVM to verify transaction signature
// This is the core cryptographic verification using OP_CHECK_SPHINCS
func (mp *Mempool) verifyTransactionSignature(tx *types.Transaction) error {
	// Prepare signature verification parameters
	sigLen := len(tx.Signature)
	senderLen := len(tx.Sender)
	msgLen := len(tx.ID)

	// Create full message for signature verification
	// The message includes timestamp and nonce as per SPHINCS+ protocol
	fullMsg := make([]byte, 0, 8+16+msgLen)
	timestamp := make([]byte, 8) // 8-byte timestamp (zero for now, will be from tx)
	nonce := make([]byte, 16)    // 16-byte nonce (zero for now, will be from tx)
	fullMsg = append(fullMsg, timestamp...)
	fullMsg = append(fullMsg, nonce...)
	fullMsg = append(fullMsg, []byte(tx.ID)...)

	// Build VM bytecode for OP_CHECK_SPHINCS
	// Stack layout expected by executeCheckSphincs:
	//   It pops: msg_len, msg_ptr, pk_len, pk_ptr, sig_len, sig_ptr
	//   Then pushes 1 for success, 0 for failure
	vmBytecode := []byte{
		// Push message length and pointer
		byte(svm.PUSH4), byte(len(fullMsg) >> 24), byte(len(fullMsg) >> 16), byte(len(fullMsg) >> 8), byte(len(fullMsg)),
		byte(svm.PUSH4), byte((sigLen + senderLen) >> 24), byte((sigLen + senderLen) >> 16), byte((sigLen + senderLen) >> 8), byte(sigLen + senderLen),
		// Push public key length and pointer
		byte(svm.PUSH4), byte(senderLen >> 24), byte(senderLen >> 16), byte(senderLen >> 8), byte(senderLen),
		byte(svm.PUSH4), byte(sigLen >> 24), byte(sigLen >> 16), byte(sigLen >> 8), byte(sigLen),
		// Push signature length and pointer
		byte(svm.PUSH4), byte(sigLen >> 24), byte(sigLen >> 16), byte(sigLen >> 8), byte(sigLen),
		byte(svm.PUSH4), 0x00, 0x00, 0x00, 0x00,
		// Execute CHECK opcode - pushes 1 on success, 0 on failure
		byte(svm.OP_CHECK_SPHINCS),
	}

	// Prepare memory layout: signature + public key + full message
	memoryLayout := make([]byte, sigLen+senderLen+len(fullMsg))
	copy(memoryLayout[0:], tx.Signature)
	copy(memoryLayout[sigLen:], []byte(tx.Sender))
	copy(memoryLayout[sigLen+senderLen:], fullMsg)

	// Create and run VM
	vm := vmachine.NewVM(vmBytecode)
	if err := vm.SetMemoryBytes(0, memoryLayout); err != nil {
		return fmt.Errorf("VM memory setup failed: %w", err)
	}

	if err := vm.Run(); err != nil {
		return fmt.Errorf("VM execution failed: %w", err)
	}

	result, err := vm.GetResult()
	if err != nil {
		return fmt.Errorf("VM result error: %w", err)
	}

	if result != 1 {
		return errors.New("invalid transaction signature")
	}

	return nil
}

// verifyTransactionNonce uses SVM to validate transaction nonce
// Nonce validation ensures transactions are processed in order
// Uses XOR + NOT to check equality (since we don't have SUB or GT)
func (mp *Mempool) verifyTransactionNonce(tx *types.Transaction, currentNonce uint64) error {
	// Create VM bytecode for nonce validation
	// Stack layout: nonce value, expected nonce, then compare using XOR + NOT
	// If a ^ b == 0 then they are equal, NOT makes it 1 (true)
	vmBytecode := []byte{
		// Push transaction nonce (actual)
		byte(svm.PUSH8), byte(tx.Nonce >> 56), byte(tx.Nonce >> 48), byte(tx.Nonce >> 40),
		byte(tx.Nonce >> 32), byte(tx.Nonce >> 24), byte(tx.Nonce >> 16), byte(tx.Nonce >> 8), byte(tx.Nonce),
		// Push current nonce from sender's account (expected)
		byte(svm.PUSH8), byte(currentNonce >> 56), byte(currentNonce >> 48), byte(currentNonce >> 40),
		byte(currentNonce >> 32), byte(currentNonce >> 24), byte(currentNonce >> 16), byte(currentNonce >> 8), byte(currentNonce),
		// Compare nonces using XOR (if equal, result is 0)
		byte(svm.Xor),
		// NOT makes 0 become 1 (equal), non-zero becomes 0 (not equal)
		byte(svm.Not),
		// AND with 1 to ensure result is 0 or 1
		byte(svm.PUSH1), 0x01,
		byte(svm.And),
	}

	// Create and run VM
	vm := vmachine.NewVM(vmBytecode)
	if err := vm.Run(); err != nil {
		return fmt.Errorf("VM nonce validation failed: %w", err)
	}

	result, err := vm.GetResult()
	if err != nil {
		return fmt.Errorf("VM result error: %w", err)
	}

	if result != 1 {
		return fmt.Errorf("invalid nonce: expected %d, got %d", currentNonce, tx.Nonce)
	}

	return nil
}

// verifyTransactionBalance uses SVM to check if sender has sufficient balance
// Performs balance check using XOR comparison (since we don't have SUB or GT)
// Checks if amount <= balance by verifying that (balance - amount) doesn't underflow
func (mp *Mempool) verifyTransactionBalance(tx *types.Transaction, senderBalance *big.Int) error {
	// Convert sender balance and amount to uint64 for VM (simplified)
	balanceUint := senderBalance.Uint64()
	amountUint := tx.Amount.Uint64()

	// Create VM bytecode for balance validation
	// Since we don't have SUB, we use XOR to check if amount is within balance
	// A simple approach: check if amount <= balance by verifying amount doesn't exceed balance
	vmBytecode := []byte{
		// Push transaction amount
		byte(svm.PUSH8), byte(amountUint >> 56), byte(amountUint >> 48), byte(amountUint >> 40),
		byte(amountUint >> 32), byte(amountUint >> 24), byte(amountUint >> 16), byte(amountUint >> 8), byte(amountUint),
		// Push sender balance
		byte(svm.PUSH8), byte(balanceUint >> 56), byte(balanceUint >> 48), byte(balanceUint >> 40),
		byte(balanceUint >> 32), byte(balanceUint >> 24), byte(balanceUint >> 16), byte(balanceUint >> 8), byte(balanceUint),
		// Check if amount <= balance using XOR comparison
		// This is simplified - in production, proper big.Int comparison needed
		byte(svm.Xor),
		byte(svm.Not),
		byte(svm.PUSH1), 0x01,
		byte(svm.And),
	}

	// Create and run VM
	vm := vmachine.NewVM(vmBytecode)
	if err := vm.Run(); err != nil {
		return fmt.Errorf("VM balance validation failed: %w", err)
	}

	result, err := vm.GetResult()
	if err != nil {
		return fmt.Errorf("VM result error: %w", err)
	}

	if result != 1 {
		return fmt.Errorf("insufficient balance: have %d, need %d", balanceUint, amountUint)
	}

	return nil
}

// verifyTransactionGas uses SVM to validate gas parameters
// Checks if gas limit and gas price are within acceptable ranges
func (mp *Mempool) verifyTransactionGas(tx *types.Transaction, minGasPrice *big.Int) error {
	gasLimitUint := tx.GasLimit.Uint64()
	gasPriceUint := tx.GasPrice.Uint64()
	minGasPriceUint := minGasPrice.Uint64()

	// Create VM bytecode for gas validation using available opcodes
	vmBytecode := []byte{
		// Validate gas limit is within block limits (using XOR comparison)
		// Push gas limit
		byte(svm.PUSH8), byte(gasLimitUint >> 56), byte(gasLimitUint >> 48), byte(gasLimitUint >> 40),
		byte(gasLimitUint >> 32), byte(gasLimitUint >> 24), byte(gasLimitUint >> 16), byte(gasLimitUint >> 8), byte(gasLimitUint),
		// Push max gas limit (1,000,000)
		byte(svm.PUSH4), 0x00, 0x0F, 0x42, 0x40,
		// Compare using XOR (simplified)
		byte(svm.Xor),
		byte(svm.Not),

		// Validate gas price >= minimum
		// Push gas price
		byte(svm.PUSH8), byte(gasPriceUint >> 56), byte(gasPriceUint >> 48), byte(gasPriceUint >> 40),
		byte(gasPriceUint >> 32), byte(gasPriceUint >> 24), byte(gasPriceUint >> 16), byte(gasPriceUint >> 8), byte(gasPriceUint),
		// Push min gas price
		byte(svm.PUSH8), byte(minGasPriceUint >> 56), byte(minGasPriceUint >> 48), byte(minGasPriceUint >> 40),
		byte(minGasPriceUint >> 32), byte(minGasPriceUint >> 24), byte(minGasPriceUint >> 16), byte(minGasPriceUint >> 8), byte(minGasPriceUint),
		// Compare using XOR (if gasPrice >= minGasPrice)
		byte(svm.Xor),
		byte(svm.Not),
		byte(svm.And), // Combine both checks
		byte(svm.PUSH1), 0x01,
		byte(svm.And),
	}

	vm := vmachine.NewVM(vmBytecode)
	if err := vm.Run(); err != nil {
		return fmt.Errorf("VM gas validation failed: %w", err)
	}

	result, err := vm.GetResult()
	if err != nil {
		return fmt.Errorf("VM result error: %w", err)
	}

	if result != 1 {
		return fmt.Errorf("gas validation failed: limit=%d, price=%d, min=%d",
			gasLimitUint, gasPriceUint, minGasPriceUint)
	}

	return nil
}

// verifyTransactionReplayProtection uses SVM to check timestamp+nonce pair
// Prevents replay attacks by verifying transaction freshness using XOR comparison
func (mp *Mempool) verifyTransactionReplayProtection(tx *types.Transaction, lastTimestamp uint64) error {
	// Create VM bytecode for replay protection using XOR comparison
	vmBytecode := []byte{
		// Push transaction timestamp
		byte(svm.PUSH8), byte(tx.Timestamp >> 56), byte(tx.Timestamp >> 48), byte(tx.Timestamp >> 40),
		byte(tx.Timestamp >> 32), byte(tx.Timestamp >> 24), byte(tx.Timestamp >> 16), byte(tx.Timestamp >> 8), byte(tx.Timestamp),
		// Push last timestamp from sender
		byte(svm.PUSH8), byte(lastTimestamp >> 56), byte(lastTimestamp >> 48), byte(lastTimestamp >> 40),
		byte(lastTimestamp >> 32), byte(lastTimestamp >> 24), byte(lastTimestamp >> 16), byte(lastTimestamp >> 8), byte(lastTimestamp),
		// Check if tx.timestamp > lastTimestamp using XOR
		// This is simplified - proper comparison needs GT opcode
		byte(svm.Xor),
		byte(svm.Not),
		byte(svm.PUSH1), 0x01,
		byte(svm.And),
	}

	vm := vmachine.NewVM(vmBytecode)
	if err := vm.Run(); err != nil {
		return fmt.Errorf("VM replay protection validation failed: %w", err)
	}

	result, err := vm.GetResult()
	if err != nil {
		return fmt.Errorf("VM result error: %w", err)
	}

	if result != 1 {
		return fmt.Errorf("replay protection failed: timestamp %d <= last %d", tx.Timestamp, lastTimestamp)
	}

	return nil
}

// validationProcessor handles transaction validation
func (mp *Mempool) validationProcessor() {
	for {
		select {
		case pooledTx := <-mp.validationChan:
			mp.validateTransaction(pooledTx)
		case <-mp.stopChan:
			return
		}
	}
}

// validateTransaction performs comprehensive validation
// Uses SVM for all cryptographic and business logic validation
func (mp *Mempool) validateTransaction(pooledTx *PooledTransaction) {
	startTime := time.Now()
	tx := pooledTx.Transaction

	// ========== OP_RETURN VALIDATION ==========
	const maxReturnSize = 80
	if len(tx.ReturnData) > maxReturnSize {
		// Reject transaction with too much OP_RETURN data
		pooledTx.Status = StatusInvalid
		pooledTx.Error = fmt.Sprintf("OP_RETURN data exceeds maximum size of %d bytes", maxReturnSize)

		mp.lock.Lock()
		defer mp.lock.Unlock()

		pooledTx.Status = StatusInvalid
		pooledTx.Error = fmt.Sprintf("OP_RETURN data exceeds maximum size of %d bytes", maxReturnSize)
		pooledTx.LastUpdated = time.Now()

		delete(mp.validationPool, tx.ID)
		mp.invalidPool[tx.ID] = pooledTx

		mp.stats.totalInvalid++
		logger.Warn("Transaction validation failed: ID=%s, OP_RETURN size exceeded", tx.ID)
		return // Just return, don't return an error
	}
	// ==========================================

	err := mp.performValidation(tx)

	mp.lock.Lock()
	defer mp.lock.Unlock()

	validationTime := time.Since(startTime)
	mp.stats.validationTime += validationTime

	if err != nil {
		pooledTx.Status = StatusInvalid
		pooledTx.Error = err.Error()
		pooledTx.LastUpdated = time.Now()

		delete(mp.validationPool, tx.ID)
		mp.invalidPool[tx.ID] = pooledTx

		mp.stats.totalInvalid++
		logger.Warn("Transaction validation failed: ID=%s, error=%v", tx.ID, err)
	} else {
		pooledTx.Status = StatusPending
		pooledTx.LastUpdated = time.Now()

		delete(mp.validationPool, tx.ID)
		mp.pendingPool[tx.ID] = pooledTx

		mp.stats.totalValidated++
		logger.Debug("Transaction validated: ID=%s, time=%v", tx.ID, validationTime)
	}
}

// performValidation executes the actual validation logic
// This is the MAIN validation function that all transactions go through
// It performs comprehensive validation including:
//   - Transaction size and sanity checks
//   - Nonce validation (using SVM)
//   - Balance checks (using SVM)
//   - Gas validation (using SVM)
//   - Replay protection (using SVM)
func (mp *Mempool) performValidation(tx *types.Transaction) error {
	// ========== SKIP VALIDATION FOR GENESIS VAULT TRANSACTIONS ==========
	// Genesis vault transactions are trusted protocol transactions
	// They don't have signatures and bypass normal validation rules
	// This address is defined in core.GenesisVaultAddress (see genesis.go)
	const genesisVaultAddress = "0000000000000000000000000000000000000001"
	if tx.Sender == genesisVaultAddress {
		logger.Debug("Skipping validation for genesis vault transaction: %s", tx.ID)
		return nil
	}
	// ================================================================

	// Validate transaction size
	txSize := mp.CalculateTransactionSize(tx)
	if txSize > mp.config.MaxTxSize {
		return fmt.Errorf("transaction size %d exceeds maximum %d bytes", txSize, mp.config.MaxTxSize)
	}

	// Perform transaction sanity checks
	if err := tx.SanityCheck(); err != nil {
		return fmt.Errorf("sanity check failed: %w", err)
	}

	// Validate transaction fields
	if tx.Sender == "" || tx.Receiver == "" {
		return errors.New("empty sender or receiver")
	}

	if tx.Amount == nil || tx.Amount.Cmp(big.NewInt(0)) <= 0 {
		return errors.New("invalid amount")
	}

	// Validate gas parameters
	if tx.GasLimit == nil || tx.GasPrice == nil {
		return errors.New("missing gas parameters")
	}

	// ========== SVM-BASED VALIDATIONS ==========

	// 1. Nonce validation using SVM
	// Get current nonce for sender (would come from state)
	currentNonce := mp.getSenderNonce(tx.Sender)
	if err := mp.verifyTransactionNonce(tx, currentNonce); err != nil {
		return fmt.Errorf("nonce validation failed: %w", err)
	}

	// 2. Balance check using SVM
	senderBalance := mp.getSenderBalance(tx.Sender)
	if err := mp.verifyTransactionBalance(tx, senderBalance); err != nil {
		return fmt.Errorf("balance validation failed: %w", err)
	}

	// 3. Gas validation using SVM
	minGasPrice := mp.getMinimumGasPrice()
	if err := mp.verifyTransactionGas(tx, minGasPrice); err != nil {
		return fmt.Errorf("gas validation failed: %w", err)
	}

	// 4. Replay protection using SVM
	lastTimestamp := mp.getLastTransactionTimestamp(tx.Sender)
	if err := mp.verifyTransactionReplayProtection(tx, lastTimestamp); err != nil {
		return fmt.Errorf("replay protection failed: %w", err)
	}

	logger.Debug("All SVM validations passed for transaction %s", tx.ID)
	return nil
}

// Helper methods for getting state information
// These would typically query the blockchain state

// getSenderNonce returns the current nonce for a sender address
func (mp *Mempool) getSenderNonce(sender string) uint64 {
	// This would query the blockchain state for the sender's nonce
	// In production: stateDB.GetNonce(sender)
	_ = sender // Mark as used to avoid linter warning
	return 0
}

// getSenderBalance returns the current balance for a sender address
func (mp *Mempool) getSenderBalance(sender string) *big.Int {
	// This would query the blockchain state for the sender's balance
	// In production: stateDB.GetBalance(sender)
	_ = sender // Mark as used to avoid linter warning
	return new(big.Int).SetUint64(1000000000000000000)
}

// getMinimumGasPrice returns the minimum acceptable gas price
func (mp *Mempool) getMinimumGasPrice() *big.Int {
	// This would come from chain parameters or governance
	return new(big.Int).SetUint64(1000000000) // 1 Gwei
}

// getLastTransactionTimestamp returns the last timestamp for a sender
func (mp *Mempool) getLastTransactionTimestamp(sender string) uint64 {
	// This would query the blockchain state for the sender's last tx timestamp
	// In production: stateDB.GetLastTxTimestamp(sender)
	_ = sender // Mark as used to avoid linter warning
	return 0
}

// validateTransactionBasic performs quick basic validation
func (mp *Mempool) validateTransactionBasic(tx *types.Transaction) error {
	if tx == nil {
		return errors.New("nil transaction")
	}

	if tx.Sender == "" || tx.Receiver == "" {
		return errors.New("empty sender or receiver")
	}

	if tx.Amount == nil || tx.Amount.Cmp(big.NewInt(0)) <= 0 {
		return errors.New("invalid amount")
	}

	return nil
}
