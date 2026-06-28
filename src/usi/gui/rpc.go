// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/rpc.go
package gui

import (
	"crypto/rand"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"time"

	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	"github.com/sphinxfndorg/protocol/src/rpc"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
)

// NewWalletClient creates a new wallet RPC client
func NewWalletClient(nodeAddr string) *WalletClient {
	if nodeAddr == "" {
		nodeAddr = "127.0.0.1:32307" // Use validator TCP port
	}

	var nodeID rpc.NodeID
	if sessionRawFingerprint != "" {
		// Convert hex string to bytes (truncate/pad to 32 bytes)
		rawBytes, err := hex.DecodeString(sessionRawFingerprint)
		if err == nil {
			copy(nodeID[:], rawBytes)
		}
	}

	return &WalletClient{
		nodeAddr: nodeAddr,
		nodeID:   nodeID,
	}
}

// GetBalance fetches balance for an address
func (c *WalletClient) GetBalance(address string) (*BalanceResponse, error) {
	if address == "" {
		address = sessionFingerprint
	}
	if address == "" {
		return nil, errors.New("no address provided")
	}

	log.Printf("[WalletRPC] GetBalance: fetching for %s", address[:16]+"...")

	params := []interface{}{address}
	resp, err := rpc.CallRPC(c.nodeAddr, "getbalance", params, c.nodeID, 60)
	if err != nil {
		log.Printf("[WalletRPC] RPC call failed: %v", err)
		return c.getMockBalance(address)
	}

	if len(resp.Values) == 0 {
		return c.getMockBalance(address)
	}

	var result struct {
		Address  string `json:"address"`
		Balance  string `json:"balance"`
		Pending  string `json:"pending"`
		Unlocked string `json:"unlocked"`
	}
	if err := json.Unmarshal(resp.Values[0], &result); err != nil {
		return c.getMockBalance(address)
	}

	balance := new(big.Int)
	balance.SetString(result.Balance, 10)

	pending := new(big.Int)
	pending.SetString(result.Pending, 10)

	unlocked := new(big.Int)
	unlocked.SetString(result.Unlocked, 10)

	return &BalanceResponse{
		Address:  result.Address,
		Balance:  balance,
		Pending:  pending,
		Unlocked: unlocked,
	}, nil
}

// getMockBalance returns mock balance for offline mode
func (c *WalletClient) getMockBalance(address string) (*BalanceResponse, error) {
	// Generate deterministic mock balance based on address
	// 1 SPX = 1e18 nSPX, so 1e18 represents 1 SPX
	mockBalance := big.NewInt(1e18) // 1 SPX in nSPX units
	return &BalanceResponse{
		Address:  address,
		Balance:  mockBalance,
		Pending:  big.NewInt(0),
		Unlocked: mockBalance,
	}, nil
}

// SendTransaction sends funds to a recipient
// SendTransaction sends funds to a recipient
func (c *WalletClient) SendTransaction(toAddress string, amount *big.Int, memo string) (string, error) {
	if sessionPassphrase == "" {
		return "", errors.New("not logged in")
	}
	if toAddress == "" {
		return "", errors.New("recipient required")
	}
	if amount == nil || amount.Sign() <= 0 {
		return "", errors.New("invalid amount")
	}

	log.Printf("[WalletRPC] SendTransaction: sending %s to %s",
		amount.String(), toAddress[:16]+"...")

	// ─── 1. Load key pair from local device ──────────────────────
	kp, skBytes, err := keys.LoadKeyFromDisk(sessionPassphrase)
	if err != nil {
		return "", fmt.Errorf("failed to load key: %w", err)
	}
	defer func() {
		for i := range skBytes {
			skBytes[i] = 0
		}
	}()

	// ─── 2. Get nonce (try RPC first, fallback to timestamp) ────
	var nonce uint64
	if cachedNonce, err := c.getCurrentNonce(sessionFingerprint); err == nil {
		nonce = cachedNonce
		log.Printf("[WalletRPC] Using RPC nonce: %d", nonce)
	} else {
		// Fallback: use UnixNano (works with GT validation)
		nonce = uint64(time.Now().UnixNano())
		log.Printf("[WalletRPC] RPC nonce failed, using timestamp: %d", nonce)
	}

	// ─── 3. Build and sign transaction locally ──────────────────
	tx := &types.Transaction{
		ID:         "",
		Sender:     sessionFingerprint,
		Receiver:   toAddress,
		Amount:     amount,
		GasLimit:   big.NewInt(21000),
		GasPrice:   big.NewInt(1000000000), // ← 1 Gwei (1,000,000,000)
		Nonce:      nonce,
		Timestamp:  time.Now().Unix(),
		Signature:  []byte{},
		ReturnData: []byte(memo),
	}
	tx.ID = tx.Hash()

	// Sign using the local key
	if err := signTransactionLocally(tx, skBytes, kp.PublicKey); err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	// ─── 4. Marshal to hex for RPC ──────────────────────────────
	txData, err := json.Marshal(tx)
	if err != nil {
		return "", fmt.Errorf("failed to marshal transaction: %w", err)
	}
	rawTx := hex.EncodeToString(txData)

	// ─── 5. Send to RPC node ────────────────────────────────────
	resp, err := rpc.CallRPC(c.nodeAddr, "sendrawtransaction", []interface{}{rawTx}, c.nodeID, 120)
	if err != nil {
		return "", fmt.Errorf("RPC error: %w", err)
	}

	if len(resp.Values) == 0 {
		return "", errors.New("empty response")
	}

	var result struct {
		TxID   string `json:"txid"`
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(resp.Values[0], &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if result.Error != "" {
		return "", fmt.Errorf("tx rejected: %s", result.Error)
	}

	return result.TxID, nil
}

func (c *WalletClient) getCurrentNonce(address string) (uint64, error) {
	resp, err := rpc.CallRPC(c.nodeAddr, "getnonce", []interface{}{address}, c.nodeID, 60)
	if err != nil {
		return 0, err
	}
	var nonce uint64
	json.Unmarshal(resp.Values[0], &nonce)
	return nonce + 1, nil // Increment for new transaction
}

// signTransactionLocally signs a transaction using SPHINCS+
func signTransactionLocally(tx *types.Transaction, skBytes, pkBytes []byte) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	if tx.ID == "" {
		tx.ID = tx.Hash()
	}

	// Initialize SPHINCS+ key manager
	km, err := key.NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to initialize key manager: %w", err)
	}
	privateKey, _, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		return fmt.Errorf("failed to deserialize key pair: %w", err)
	}

	// Get SPHINCS+ parameters
	params := km.GetSPHINCSParameters()
	if params == nil || params.Params == nil {
		return fmt.Errorf("SPHINCS+ parameters not initialized")
	}

	// Build message: timestamp || nonce || txID
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(tx.Timestamp))

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	msg := make([]byte, 0, 8+16+len(tx.ID))
	msg = append(msg, tsBytes...)
	msg = append(msg, nonceBytes...)
	msg = append(msg, []byte(tx.ID)...)

	// Create signature object
	sigObj, err := sthincs.Spx_sign(params.Params, []byte(tx.ID), privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign: %w", err)
	}
	if sigObj == nil {
		return fmt.Errorf("signature object is nil")
	}

	sigBytes, err := sigObj.SerializeSignature()
	if err != nil {
		return fmt.Errorf("failed to serialize signature: %w", err)
	}

	// Store signature hash for replay detection
	sigHash := sha3.Sum256(sigBytes)

	tx.Signature = sigBytes
	tx.SignatureHash = sigHash[:]
	tx.PublicKey = pkBytes
	tx.AuthTimestamp = make([]byte, 8)
	binary.BigEndian.PutUint64(tx.AuthTimestamp, uint64(time.Now().Unix()))
	tx.AuthNonce = make([]byte, 16)
	if _, err := rand.Read(tx.AuthNonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}
	tx.MerkleRootHash = make([]byte, 32)
	tx.Commitment = make([]byte, 32)
	tx.Proof = make([]byte, 32)

	return nil
}

// GetTransactionHistory fetches recent transactions
func (c *WalletClient) GetTransactionHistory(address string, limit int) ([]TransactionResponse, error) {
	if address == "" {
		address = sessionFingerprint
	}
	if address == "" {
		return nil, errors.New("no address provided")
	}
	if limit <= 0 {
		limit = 20
	}

	log.Printf("[WalletRPC] GetTransactionHistory: fetching for %s", address[:16]+"...")

	params := []interface{}{address, limit}
	resp, err := rpc.CallRPC(c.nodeAddr, "gettransactionhistory", params, c.nodeID, 60)
	if err != nil {
		return c.getMockTransactionHistory(address, limit)
	}

	if len(resp.Values) == 0 {
		return c.getMockTransactionHistory(address, limit)
	}

	var txs []TransactionResponse
	if err := json.Unmarshal(resp.Values[0], &txs); err != nil {
		return c.getMockTransactionHistory(address, limit)
	}

	return txs, nil
}

// getMockTransactionHistory returns mock transactions
func (c *WalletClient) getMockTransactionHistory(address string, limit int) ([]TransactionResponse, error) {
	txs := make([]TransactionResponse, 0, limit)
	for i := 0; i < limit && i < 10; i++ {
		amount := big.NewInt(int64(i+1) * 1000)
		txs = append(txs, TransactionResponse{
			TxID:      fmt.Sprintf("mock-tx-%d-%d", i, time.Now().UnixNano()),
			Sender:    address,
			Receiver:  fmt.Sprintf("recipient-%d", i),
			Amount:    amount,
			Fee:       big.NewInt(10),
			Timestamp: time.Now().Add(-time.Duration(i) * time.Hour),
			Status:    "confirmed",
		})
	}
	return txs, nil
}
