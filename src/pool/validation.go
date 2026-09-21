// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/pool/validation.go
package pool

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	logger "github.com/sphinxfndorg/protocol/src/console"
	"github.com/sphinxfndorg/protocol/src/contracts"
	"github.com/sphinxfndorg/protocol/src/common"
	svm "github.com/sphinxfndorg/protocol/src/core/kernel/opcodes"
	vmachine "github.com/sphinxfndorg/protocol/src/core/kernel/vm"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// mintAnchorTagType mirrors core.AnchorTagType ("mint_anchor").
const mintAnchorTagType = "mint_anchor"

// isMintAnchorReturnData reports whether data is a self-send data/NFT anchor.
func isMintAnchorReturnData(data []byte) bool {
	var peek struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &peek); err == nil && peek.Type == mintAnchorTagType {
		return true
	}
	return types.IsNFTAnchorReturnData(data)
}

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
func (mp *Mempool) verifyTransactionSignature(tx *types.Transaction) error {
	if tx.IsSystemTransaction() {
		logger.Debug("Genesis vault transaction %s is trusted, skipping signature verification", tx.ID)
		return nil
	}

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

	if mp.sphincsManager == nil {
		return fmt.Errorf("SPHINCS manager is not configured, cannot verify transaction %s", tx.ID)
	}
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

	const maxMsgSize = 1 << 20
	if len(tx.ID) > maxMsgSize-24 {
		return fmt.Errorf("transaction ID too large: %d bytes (max: %d)", len(tx.ID), maxMsgSize-24)
	}
	fullMsg := make([]byte, 0, 8+16+len(tx.ID))
	fullMsg = append(fullMsg, tsBytes...)
	fullMsg = append(fullMsg, nonceBytes...)
	fullMsg = append(fullMsg, []byte(tx.ID)...)

	sigLen := len(tx.Signature)
	pkLen := len(pkBytes)
	msgLen := len(fullMsg)

	hashOffset := sigLen
	pkOffset := hashOffset + 32
	msgOffset := pkOffset + pkLen

	const maxMemoryLayoutSize = 1 << 20
	totalMemorySize := sigLen + 32 + pkLen + msgLen
	if totalMemorySize > maxMemoryLayoutSize {
		return fmt.Errorf("memory layout size %d exceeds maximum %d", totalMemorySize, maxMemoryLayoutSize)
	}
	memoryLayout := make([]byte, totalMemorySize)

	copy(memoryLayout[0:sigLen], tx.Signature)
	copy(memoryLayout[hashOffset:hashOffset+32], tx.SignatureHash)
	copy(memoryLayout[pkOffset:pkOffset+pkLen], pkBytes)
	copy(memoryLayout[msgOffset:msgOffset+msgLen], fullMsg)

	bc := []byte{}

	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(0)...)

	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(sigLen))...)

	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(hashOffset))...)

	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(32)...)

	bc = append(bc, byte(svm.OP_CHECK_SIGNATURE_HASH))
	bc = append(bc, byte(svm.OP_VERIFY))

	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(0)...)

	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(sigLen))...)

	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(pkOffset))...)

	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(pkLen))...)

	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(msgOffset))...)

	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(msgLen))...)

	bc = append(bc, byte(svm.OP_CHECK_SPHINCS))
	bc = append(bc, byte(svm.OP_VERIFY))

	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(uint32(hashOffset))...)

	bc = append(bc, byte(svm.PUSH4))
	bc = append(bc, uint32ToBytesPool(32)...)

	bc = append(bc, byte(svm.OP_STORE_SIGNATURE_HASH))

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

	if resultGTE != 1 || resultLTE != 1 {
		return fmt.Errorf("invalid nonce: %d must equal %d", tx.Nonce, currentNonce)
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
		return 0
	}

	return timestamp
}

// validationProcessor is a background goroutine that processes transactions for validation.
func (mp *Mempool) validationProcessor() {
	pendingTicker := time.NewTicker(500 * time.Millisecond)
	defer pendingTicker.Stop()
	for {
		select {
		case pooledTx := <-mp.validationChan:
			mp.validateTransaction(pooledTx)
		case <-pendingTicker.C:
			mp.drainPendingPool()
			mp.sweepStuck()
		case <-mp.stopChan:
			return
		}
	}
}

// drainPendingPool re-queues transactions that were PARKED in pendingPool.
func (mp *Mempool) drainPendingPool() {
	mp.lock.Lock()
	var toValidate []*PooledTransaction
	for _, pt := range mp.pendingPool {
		if pt.Validated || pt.Status != StatusPending {
			continue
		}
		toValidate = append(toValidate, pt)
		delete(mp.pendingPool, pt.Transaction.ID)
	}
	if len(toValidate) == 0 {
		mp.lock.Unlock()
		return
	}
	mp.lock.Unlock()

	for _, pt := range toValidate {
		select {
		case mp.validationChan <- pt:
			logger.Debug("drainPendingPool: re-queued unvalidated tx %s for validation", pt.Transaction.ID)
		default:
			mp.lock.Lock()
			pt.Status = StatusPending
			pt.Validated = false
			pt.LastUpdated = time.Now()
			mp.pendingPool[pt.Transaction.ID] = pt
			mp.lock.Unlock()
			logger.Warn("drainPendingPool: channel full, tx %s stays parked", pt.Transaction.ID)
		}
	}
}

// clearAccountNonceSlotIfOwner removes the (sender, nonce) entry from
// accountNonceIndex if — and only if — the current occupant is the given txID.
//
// ★ FIX: this is the companion helper to removeTransactionFromAllPools'
// existing index cleanup. Every path that parks a transaction in invalidPool
// MUST call this first, because parking directly into invalidPool bypasses
// removeTransactionFromAllPools (which is the only other place that clears
// the index). Leaving the entry behind means the invalid tx keeps "owning"
// its (sender, nonce) slot forever: the next valid tx from the same sender is
// either rejected as a replacement ("replacement transaction underpriced")
// or computed a nonce one past the phantom occupant by getSenderNonce —
// exactly how a rejected deploy blocked the next deploy attempt with
// "invalid nonce: 0 must equal 1".
//
// The guard `mp.accountNonceIndex[nonceKey] == txID` is essential: if a
// replacement already claimed the slot (BroadcastTransaction inserts under
// the same key when a fee-bump replaces an occupant), that entry belongs to
// the NEWER tx and must not be cleared by a stale rejection of the older one.
//
// Callers must hold mp.lock (validateTransaction already does, at every site
// this is called from).
func (mp *Mempool) clearAccountNonceSlotIfOwner(txID string, tx *types.Transaction) {
	if tx == nil {
		return
	}
	nonceKey := tx.Sender + ":" + strconv.FormatUint(tx.Nonce, 10)
	if mp.accountNonceIndex[nonceKey] == txID {
		delete(mp.accountNonceIndex, nonceKey)
	}
}

// validateTransaction performs comprehensive validation on a pooled transaction.
func (mp *Mempool) validateTransaction(pooledTx *PooledTransaction) {
	startTime := time.Now()
	tx := pooledTx.Transaction

	logger.Info("validateTransaction: ID=%s ReturnData=%d bytes", tx.ID, len(tx.ReturnData))

	const maxReturnSize = types.MaxReturnDataSize
	if len(tx.ReturnData) > maxReturnSize {
		mp.lock.Lock()
		defer mp.lock.Unlock()

		if !mp.stillOwnsSlot(tx.ID, pooledTx) {
			logger.Debug("validateTransaction: %s no longer tracked (evicted while validating), discarding OP_RETURN result", tx.ID)
			return
		}

		pooledTx.Status = StatusInvalid
		pooledTx.Error = fmt.Sprintf("OP_RETURN data exceeds maximum size of %d bytes", maxReturnSize)
		pooledTx.LastUpdated = time.Now()

		delete(mp.validationPool, tx.ID)
		// ★ FIX: release the (sender, nonce) slot before parking in
		// invalidPool. Without this the invalid tx keeps blocking the
		// sender's next tx on the same slot.
		mp.clearAccountNonceSlotIfOwner(tx.ID, tx)
		mp.invalidPool[tx.ID] = pooledTx

		mp.stats.totalInvalid++
		logger.Warn("Transaction validation failed: ID=%s, OP_RETURN size exceeded", tx.ID)
		return
	}

	txType := classifyTransaction(tx)
	if err := mp.validateTransactionByType(tx, txType); err != nil {
		mp.lock.Lock()
		defer mp.lock.Unlock()

		if !mp.stillOwnsSlot(tx.ID, pooledTx) {
			logger.Debug("validateTransaction: %s no longer tracked (evicted while classifying), discarding type check result", tx.ID)
			return
		}

		pooledTx.Status = StatusInvalid
		pooledTx.Error = err.Error()
		pooledTx.LastUpdated = time.Now()

		delete(mp.validationPool, tx.ID)
		// ★ FIX: same slot cleanup as above.
		mp.clearAccountNonceSlotIfOwner(tx.ID, tx)
		mp.invalidPool[tx.ID] = pooledTx

		mp.stats.totalInvalid++
		logger.Warn("Transaction validation failed: ID=%s, type check failed: %v", tx.ID, err)
		return
	}

	err := mp.performValidation(tx)

	mp.lock.Lock()
	defer mp.lock.Unlock()

	if !mp.stillOwnsSlot(tx.ID, pooledTx) {
		logger.Debug("validateTransaction: %s no longer tracked (evicted while validating), discarding validation result", tx.ID)
		return
	}

	validationTime := time.Since(startTime)
	mp.stats.validationTime += validationTime

	if err != nil {
		pooledTx.Status = StatusInvalid
		pooledTx.Validated = false
		pooledTx.Error = err.Error()
		pooledTx.LastUpdated = time.Now()

		delete(mp.validationPool, tx.ID)
		mp.clearAccountNonceSlotIfOwner(tx.ID, tx) // ★ FIX
		mp.invalidPool[tx.ID] = pooledTx

		mp.stats.totalInvalid++
		logger.Warn("Transaction validation failed: ID=%s, error=%v", tx.ID, err)
	} else {
		pooledTx.Status = StatusPending
		pooledTx.Validated = true
		pooledTx.LastUpdated = time.Now()

		delete(mp.validationPool, tx.ID)
		mp.pendingPool[tx.ID] = pooledTx

		mp.stats.totalValidated++
		logger.Info("Transaction validated OK: ID=%s type=%s time=%v — moved to PENDING pool",
			tx.ID, txType, validationTime)
	}
}

// classifyTransaction inspects a transaction's populated fields.
func classifyTransaction(tx *types.Transaction) TxType {
	switch {
	case len(tx.Code) > 0:
		return TxTypeDeployment
	case tx.ToContract != "":
		return TxTypeCall
	case len(tx.ReturnData) > 0 && (tx.Amount == nil || tx.Amount.Sign() == 0):
		return TxTypeNFTAnchor
	default:
		return TxTypeTransfer
	}
}

// TxType represents the classified purpose of a transaction.
type TxType int

const (
	TxTypeTransfer TxType = iota
	TxTypeDeployment
	TxTypeCall
	TxTypeNFTAnchor
)

func (t TxType) String() string {
	switch t {
	case TxTypeTransfer:
		return "transfer"
	case TxTypeDeployment:
		return "deployment"
	case TxTypeCall:
		return "call"
	case TxTypeNFTAnchor:
		return "nft_anchor"
	default:
		return "unknown"
	}
}

// validateTransactionByType runs type-specific validation checks.
func (mp *Mempool) validateTransactionByType(tx *types.Transaction, txType TxType) error {
	switch txType {
	case TxTypeDeployment:
		return mp.validateDeployment(tx)
	case TxTypeCall:
		return mp.validateCall(tx)
	case TxTypeNFTAnchor:
		return mp.validateNFTAnchor(tx)
	default:
		return nil
	}
}

// validateDeployment checks that the Code field parses as a valid DeploySpec.
func (mp *Mempool) validateDeployment(tx *types.Transaction) error {
	var spec contracts.DeploySpec
	if err := json.Unmarshal(tx.Code, &spec); err != nil {
		return fmt.Errorf("invalid deploy code: not a valid DeploySpec: %w", err)
	}
	if err := contracts.ValidateDeploySpec(&spec); err != nil {
		return fmt.Errorf("invalid deploy spec: %w", err)
	}
	return nil
}

// validateCall checks that the target contract already exists in state.
func (mp *Mempool) validateCall(tx *types.Transaction) error {
	if mp.stateProvider == nil {
		return nil
	}
	stateDB, err := mp.stateProvider.NewStateDB()
	if err != nil {
		return nil
	}
	defer stateDB.Close()

	contractAddr := tx.ToContract
	if !stateDB.ContractExists(contractAddr) {
		return fmt.Errorf("contract %s does not exist", contractAddr)
	}

	var call contracts.CallSpec
	if err := json.Unmarshal(tx.CallData, &call); err != nil {
		return fmt.Errorf("invalid call data: not a valid CallSpec: %w", err)
	}
	if call.Method == "" {
		return errors.New("invalid call data: missing method")
	}
	return nil
}

// validateNFTAnchor performs lightweight validation on NFT anchor transactions.
func (mp *Mempool) validateNFTAnchor(tx *types.Transaction) error {
	data := tx.ReturnData

	var jsonCheck interface{}
	if err := json.Unmarshal(data, &jsonCheck); err == nil {
		return nil
	}

	if len(data) > 6 && string(data[:7]) == "ipfs://" {
		return nil
	}

	if isHexString(string(data)) {
		return nil
	}

	return fmt.Errorf("invalid NFT anchor data: not valid JSON, IPFS URI, or hex")
}

// isHexString reports whether s consists entirely of hexadecimal characters.
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0 && len(s)%2 == 0
}

// performValidation executes all validation checks for a transaction.
func (mp *Mempool) performValidation(tx *types.Transaction) error {
	if tx.IsSystemTransaction() {
		logger.Debug("Genesis vault transaction %s is trusted, skipping cryptographic verification", tx.ID)

		if err := tx.SanityCheck(); err != nil {
			return fmt.Errorf("sanity check failed: %w", err)
		}

		if tx.Sender == "" || tx.Receiver == "" {
			return errors.New("empty sender or receiver")
		}

		if tx.Sender == tx.Receiver && !isMintAnchorReturnData(tx.ReturnData) {
			return fmt.Errorf("sender and receiver are the same (%s)", tx.Sender)
		}

		if tx.Amount == nil || tx.Amount.Cmp(big.NewInt(0)) <= 0 {
			return errors.New("invalid amount")
		}

		currentNonce := mp.getSenderNonceExcluding(tx.Sender, tx.ID) // ★ FIX
		if err := mp.verifyTransactionNonce(tx, currentNonce); err != nil {
			return fmt.Errorf("nonce validation failed: %w", err)
		}

		return nil
	}

	txSize := mp.CalculateTransactionSize(tx)
	if txSize > mp.config.MaxTxSize {
		return fmt.Errorf("transaction size %d exceeds maximum %d bytes", txSize, mp.config.MaxTxSize)
	}

	if err := tx.SanityCheck(); err != nil {
		return fmt.Errorf("sanity check failed: %w", err)
	}

	contractPayload := tx.HasContractPayload()
	if tx.Sender == "" || (tx.Receiver == "" && !contractPayload) {
		return errors.New("empty sender or receiver")
	}

	// Burn addresses are receive-only: anyone may send TO a DEAD address
	// (that is how coins are burned), but no transaction may spend FROM one —
	// the private key was destroyed in the burn ceremony, so a valid
	// signature from a DEAD address can never exist. Reject at admission so
	// burn funds can never move, even via a compromised signer path.
	if common.IsBurnAddress(tx.Sender) {
		return fmt.Errorf("burn address %s is receive-only and cannot send transactions", tx.Sender)
	}

	if tx.Sender == tx.Receiver && !isMintAnchorReturnData(tx.ReturnData) {
		return fmt.Errorf("sender and receiver are the same (%s)", tx.Sender)
	}

	if tx.Amount == nil || tx.Amount.Sign() < 0 {
		return errors.New("invalid amount")
	}
	if tx.Amount.Sign() == 0 && !contractPayload {
		return errors.New("invalid amount")
	}

	if tx.GasLimit == nil || tx.GasPrice == nil {
		return errors.New("missing gas parameters")
	}

	if err := mp.verifyTransactionSignature(tx); err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
	}

	currentNonce := mp.getSenderNonceExcluding(tx.Sender, tx.ID) // ★ FIX
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

// getSenderNonce retrieves the current nonce for a given sender address.
//
// The return value is the PENDING-AWARE next nonce: the committed state nonce
// is combined with the highest nonce this sender already has parked in the
// mempool's account-nonce index. That means a wallet which broadcasts two
// dependent transactions back-to-back (e.g. a deploy followed by a collection
// mint) has the second see nonce N+1 even though only nonce N has committed
// yet. A committed-only read would return N and produce a tx the validator
// here rejects with "invalid nonce: N must equal N+1".
//
// ★ FIX: excludeTxID lets a caller validating transaction X exclude X's own
// accountNonceIndex entry from this count. BroadcastTransaction registers a
// tx's (sender, nonce) slot in accountNonceIndex at ADMISSION time, before
// performValidation ever runs — so without this exclusion, every transaction
// counted its own slot while validating itself, inflating "highest" by one
// and rejecting every single transaction (including a brand-new account's
// very first, nonce 0) with "invalid nonce: 0 must equal 1". Pass "" to
// count every entry (used by the external GetSenderNonce, e.g. the RPC
// getnonce handler, where the caller's not-yet-broadcast tx has no entry to
// exclude in the first place).
func (mp *Mempool) getSenderNonce(sender string) uint64 {
	return mp.getSenderNonceExcluding(sender, "")
}

// getSenderNonceExcluding is getSenderNonce with one accountNonceIndex entry
// (identified by txID) skipped during the scan. See getSenderNonce's ★ FIX
// note for why this exists.
func (mp *Mempool) getSenderNonceExcluding(sender, excludeTxID string) uint64 {
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

	committed, err := stateDB.GetNonce(sender)
	if err != nil {
		committed = 0
	}

	mp.lock.RLock()
	highest := committed
	for key, occupantID := range mp.accountNonceIndex {
		if excludeTxID != "" && occupantID == excludeTxID {
			continue
		}
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 || parts[0] != sender {
			continue
		}
		n, perr := strconv.ParseUint(parts[1], 10, 64)
		if perr != nil {
			continue
		}
		if n >= highest {
			highest = n + 1
		}
	}
	mp.lock.RUnlock()

	return highest
}

// GetSenderNonce returns the next nonce this sender may use, accounting for
// both the committed state DB nonce AND any transactions already parked in
// the mempool for this sender.
//
// External callers (RPC handlers, wallet CLIs) must use this instead of
// reading stateDB.GetNonce directly, because a wallet that broadcasts two
// dependent transactions back-to-back expects the second tx to carry nonce
// N+1 even though only nonce N has committed to a block yet.
func (mp *Mempool) GetSenderNonce(sender string) uint64 {
	return mp.getSenderNonce(sender)
}

// getSenderBalance retrieves the current balance for a given sender address.
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

// getMinimumGasPrice returns the minimum acceptable gas price for transactions.
func (mp *Mempool) getMinimumGasPrice() *big.Int {
	return new(big.Int).SetUint64(1000000000)
}

// validateTransactionBasic performs minimal validation on a transaction.
func (mp *Mempool) validateTransactionBasic(tx *types.Transaction) error {
	if tx == nil {
		return errors.New("nil transaction")
	}

	contractPayload := tx.HasContractPayload()
	if tx.Sender == "" || (tx.Receiver == "" && !contractPayload) {
		return errors.New("empty sender or receiver")
	}

	if tx.Sender == tx.Receiver && !isMintAnchorReturnData(tx.ReturnData) {
		return fmt.Errorf("sender and receiver are the same (%s)", tx.Sender)
	}

	if tx.Amount == nil || tx.Amount.Sign() < 0 {
		return errors.New("invalid amount")
	}
	if tx.Amount.Sign() == 0 && !contractPayload {
		return errors.New("invalid amount")
	}

	return nil
}
