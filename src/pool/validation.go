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
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	svm "github.com/sphinxorg/protocol/src/core/svm/opcodes"
	vmachine "github.com/sphinxorg/protocol/src/core/svm/vm"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	logger "github.com/sphinxorg/protocol/src/log"
)

// uint32ToBytesPool converts uint32 to big-endian 4 bytes for VM PUSH4 operands.
func uint32ToBytesPool(n uint32) []byte {
	return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// uint64ToBytesPool converts uint64 to big-endian 8 bytes for VM PUSH8 operands.
func uint64ToBytesPool(n uint64) []byte {
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
	if tx.Sender == "0000000000000000000000000000000000000001" {
		logger.Debug("Genesis vault transaction %s is trusted, skipping signature verification", tx.ID)
		return nil
	}

	// For NON-genesis transactions, we REQUIRE full SPHINCS+ verification
	if len(tx.SignatureHash) == 0 {
		return fmt.Errorf("missing signature hash for transaction %s", tx.ID)
	}

	if len(tx.SignatureHash) != 32 {
		return fmt.Errorf("invalid signature hash length: expected 32, got %d for tx %s",
			len(tx.SignatureHash), tx.ID)
	}

	if len(tx.Signature) == 0 {
		return fmt.Errorf("missing signature for transaction %s", tx.ID)
	}

	if len(tx.PublicKey) == 0 {
		return fmt.Errorf("missing public key for transaction %s", tx.ID)
	}

	// Get the public key (already set in tx.PublicKey for non-genesis)
	pkBytes := tx.PublicKey

	// Build the message that was signed
	// Format: timestamp(8) || nonce(16) || txID
	fullMsg := make([]byte, 0, 8+16+len(tx.ID))
	tsBytes := uint64ToBytesPool(uint64(tx.Timestamp))
	fullMsg = append(fullMsg, tsBytes...)

	nonceBytes := make([]byte, 16)
	binary.BigEndian.PutUint64(nonceBytes[0:8], tx.Nonce)
	fullMsg = append(fullMsg, nonceBytes...)
	fullMsg = append(fullMsg, []byte(tx.ID)...)

	// Setup memory layout for SVM verification
	sigLen := len(tx.Signature)
	pkLen := len(pkBytes)
	msgLen := len(fullMsg)

	hashOffset := sigLen
	pkOffset := hashOffset + 32
	msgOffset := pkOffset + pkLen

	memoryLayout := make([]byte, sigLen+32+pkLen+msgLen)
	copy(memoryLayout[0:sigLen], tx.Signature)
	copy(memoryLayout[hashOffset:hashOffset+32], tx.SignatureHash)
	copy(memoryLayout[pkOffset:pkOffset+pkLen], pkBytes)
	copy(memoryLayout[msgOffset:msgOffset+msgLen], fullMsg)

	// Build bytecode for verification
	bc := []byte{}

	// OP_CHECK_SIGNATURE_HASH
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(32)...)
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(hashOffset))...)
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(sigLen))...)
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(0)...)
	bc = append(bc, byte(svm.OP_CHECK_SIGNATURE_HASH))
	bc = append(bc, byte(svm.OP_VERIFY))

	// OP_CHECK_SPHINCS
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(msgLen))...)
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(msgOffset))...)
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(pkLen))...)
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(pkOffset))...)
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(sigLen))...)
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(0)...)
	bc = append(bc, byte(svm.OP_CHECK_SPHINCS))
	bc = append(bc, byte(svm.OP_VERIFY))

	// Store the signature hash to prevent replay attacks
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(32)...)
	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(hashOffset))...)
	bc = append(bc, byte(svm.OP_STORE_SIGNATURE_HASH))

	// Execute verification
	result, err := vmachine.RunProgramWithMemory(bc, memoryLayout)
	if err != nil {
		return fmt.Errorf("signature verification failed for tx %s: %w", tx.ID, err)
	}

	_ = result

	logger.Debug("Transaction signature verified successfully: %s", tx.ID)
	return nil
}

// verifyTransactionNonce uses SVM to validate transaction nonce.
func (mp *Mempool) verifyTransactionNonce(tx *types.Transaction, currentNonce uint64) error {
	bc := []byte{}

	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(currentNonce)...)

	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(tx.Nonce)...)

	bc = append(bc, byte(svm.EQ))

	vm := vmachine.NewVM(bc)
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

// verifyTransactionBalance uses SVM to check sender has sufficient balance.
func (mp *Mempool) verifyTransactionBalance(tx *types.Transaction, senderBalance *big.Int) error {
	if senderBalance.Cmp(tx.Amount) < 0 {
		return fmt.Errorf("insufficient balance: have %s, need %s",
			senderBalance.String(), tx.Amount.String())
	}

	if !senderBalance.IsUint64() || !tx.Amount.IsUint64() {
		return nil
	}

	balanceUint := senderBalance.Uint64()
	amountUint := tx.Amount.Uint64()

	bc := []byte{}

	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(balanceUint)...)

	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(amountUint)...)

	bc = append(bc, byte(svm.LT))
	bc = append(bc, byte(svm.ISZERO))

	vm := vmachine.NewVM(bc)
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

// verifyTransactionGas uses SVM to validate gas parameters.
func (mp *Mempool) verifyTransactionGas(tx *types.Transaction, minGasPrice *big.Int) error {
	const maxGasLimit = uint64(1_000_000)

	gasLimitUint := tx.GasLimit.Uint64()
	gasPriceUint := tx.GasPrice.Uint64()
	minGasPriceUint := minGasPrice.Uint64()

	bc := []byte{}

	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(gasLimitUint)...)

	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(maxGasLimit)...)

	bc = append(bc, byte(svm.GT))
	bc = append(bc, byte(svm.ISZERO))

	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(gasPriceUint)...)

	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(minGasPriceUint)...)

	bc = append(bc, byte(svm.LT))
	bc = append(bc, byte(svm.ISZERO))

	bc = append(bc, byte(svm.And))

	vm := vmachine.NewVM(bc)
	if err := vm.Run(); err != nil {
		return fmt.Errorf("VM gas validation failed: %w", err)
	}
	result, err := vm.GetResult()
	if err != nil {
		return fmt.Errorf("VM result error: %w", err)
	}
	if result != 1 {
		return fmt.Errorf("gas validation failed: limit=%d (max=%d), price=%d (min=%d)",
			gasLimitUint, maxGasLimit, gasPriceUint, minGasPriceUint)
	}
	return nil
}

// verifyTransactionReplayProtection uses SVM to check tx.Timestamp > lastTimestamp.
func (mp *Mempool) verifyTransactionReplayProtection(tx *types.Transaction, lastTimestamp int64) error {
	if lastTimestamp == 0 {
		return nil
	}

	bc := []byte{}

	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(uint64(tx.Timestamp))...)

	bc = append(bc, byte(svm.PUSH8))
	bc = append(bc, uint64ToBytesPool(uint64(lastTimestamp))...)

	bc = append(bc, byte(svm.GT))

	vm := vmachine.NewVM(bc)
	if err := vm.Run(); err != nil {
		return fmt.Errorf("VM replay protection validation failed: %w", err)
	}
	result, err := vm.GetResult()
	if err != nil {
		return fmt.Errorf("VM result error: %w", err)
	}
	if result != 1 {
		return fmt.Errorf("replay protection failed: timestamp %d must be > last %d",
			tx.Timestamp, lastTimestamp)
	}
	return nil
}

func (mp *Mempool) getLastTransactionTimestamp(sender string) int64 {
	_ = sender
	return 0
}

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

func (mp *Mempool) validateTransaction(pooledTx *PooledTransaction) {
	startTime := time.Now()
	tx := pooledTx.Transaction

	const maxReturnSize = 80
	if len(tx.ReturnData) > maxReturnSize {
		mp.lock.Lock()
		defer mp.lock.Unlock()

		pooledTx.Status = StatusInvalid
		pooledTx.Error = fmt.Sprintf("OP_RETURN data exceeds maximum size of %d bytes", maxReturnSize)
		pooledTx.LastUpdated = time.Now()

		delete(mp.validationPool, tx.ID)
		mp.invalidPool[tx.ID] = pooledTx

		mp.stats.totalInvalid++
		logger.Warn("Transaction validation failed: ID=%s, OP_RETURN size exceeded", tx.ID)
		return
	}

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

// go/src/pool/validation.go

func (mp *Mempool) performValidation(tx *types.Transaction) error {
	const genesisVaultAddress = "0000000000000000000000000000000000000001"

	// Genesis vault transactions are TRUSTED protocol transactions
	// They don't have SPHINCS+ signatures because they're system-level distributions
	if tx.Sender == genesisVaultAddress {
		logger.Debug("Genesis vault transaction %s is trusted, skipping cryptographic verification", tx.ID)

		// Still do basic sanity checks
		if err := tx.SanityCheck(); err != nil {
			return fmt.Errorf("sanity check failed: %w", err)
		}

		if tx.Sender == "" || tx.Receiver == "" {
			return errors.New("empty sender or receiver")
		}

		if tx.Amount == nil || tx.Amount.Cmp(big.NewInt(0)) <= 0 {
			return errors.New("invalid amount")
		}

		// No signature verification needed for genesis vault
		return nil
	}

	// For NON-genesis transactions, ALL verifications must pass
	txSize := mp.CalculateTransactionSize(tx)
	if txSize > mp.config.MaxTxSize {
		return fmt.Errorf("transaction size %d exceeds maximum %d bytes", txSize, mp.config.MaxTxSize)
	}

	if err := tx.SanityCheck(); err != nil {
		return fmt.Errorf("sanity check failed: %w", err)
	}

	if tx.Sender == "" || tx.Receiver == "" {
		return errors.New("empty sender or receiver")
	}

	if tx.Amount == nil || tx.Amount.Cmp(big.NewInt(0)) <= 0 {
		return errors.New("invalid amount")
	}

	if tx.GasLimit == nil || tx.GasPrice == nil {
		return errors.New("missing gas parameters")
	}

	// This will fail if signature is invalid or public key missing
	if err := mp.verifyTransactionSignature(tx); err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
	}

	currentNonce := mp.getSenderNonce(tx.Sender)
	if err := mp.verifyTransactionNonce(tx, currentNonce); err != nil {
		return fmt.Errorf("nonce validation failed: %w", err)
	}

	senderBalance := mp.getSenderBalance(tx.Sender)
	if err := mp.verifyTransactionBalance(tx, senderBalance); err != nil {
		return fmt.Errorf("balance validation failed: %w", err)
	}

	minGasPrice := mp.getMinimumGasPrice()
	if err := mp.verifyTransactionGas(tx, minGasPrice); err != nil {
		return fmt.Errorf("gas validation failed: %w", err)
	}

	lastTimestamp := mp.getLastTransactionTimestamp(tx.Sender)
	if err := mp.verifyTransactionReplayProtection(tx, lastTimestamp); err != nil {
		return fmt.Errorf("replay protection failed: %w", err)
	}

	logger.Debug("All SVM validations passed for transaction %s", tx.ID)
	return nil
}

func (mp *Mempool) getSenderNonce(sender string) uint64 {
	_ = sender
	return 0
}

func (mp *Mempool) getSenderBalance(sender string) *big.Int {
	_ = sender
	return new(big.Int).SetUint64(1000000000000000000)
}

func (mp *Mempool) getMinimumGasPrice() *big.Int {
	return new(big.Int).SetUint64(1000000000)
}

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
