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
	"os"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	"github.com/sphinxfndorg/protocol/src/rpc"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
)

const (
	// GasPriceSPX defines the gas price in nSPX per gas unit.
	// 1 gSPX = 1,000,000,000 nSPX (same magnitude as 1 Gwei in Ethereum).
	// This is a reasonable default gas price for Sphinx transactions.
	GasPriceSPX = 1_000_000_000 // 1 gSPX in nSPX
)

// NewWalletClient creates a new wallet RPC client
func NewWalletClient(nodeAddr string) *WalletClient {
	if nodeAddr == "" {
		// Fallback to environment variable, then default
		if envAddr := os.Getenv("SPHINX_RPC_ADDR"); envAddr != "" {
			nodeAddr = envAddr
		} else {
			// Default to HTTP RPC port (8545), not TCP P2P port (30303)
			nodeAddr = "127.0.0.1:8545"
		}
	}
	// No scheme – just the raw host:port
	var nodeID rpc.NodeID
	if sessionRawFingerprint != "" {
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

// normaliseAddress converts a SPIF formatted address to raw hex.
func normaliseAddress(addr string) (string, error) {
	if addr == "" {
		return "", errors.New("empty address")
	}
	raw, err := common.NormalizeSPIFAddress(addr)
	if err != nil {
		return "", fmt.Errorf("invalid address format: %w", err)
	}
	return raw, nil
}

// GetBalance fetches balance for an address
func (c *WalletClient) GetBalance(address string) (*BalanceResponse, error) {
	if address == "" {
		address = sessionFingerprint
	}
	if address == "" {
		return nil, errors.New("no address provided")
	}

	// Normalise to raw hex
	rawAddress, err := normaliseAddress(address)
	if err != nil {
		return nil, err
	}

	log.Printf("[WalletRPC] GetBalance: fetching for %s", rawAddress[:16]+"...")

	params := []interface{}{rawAddress}
	resp, err := rpc.CallRPC(c.nodeAddr, "getbalance", params, c.nodeID, 60)
	if err != nil {
		log.Printf("[WalletRPC] RPC call failed: %v", err)
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}

	if len(resp.Values) == 0 {
		return nil, errors.New("empty response from RPC")
	}

	var result struct {
		Address  string `json:"address"`
		Balance  string `json:"balance"`
		Pending  string `json:"pending"`
		Unlocked string `json:"unlocked"`
	}
	if err := json.Unmarshal(resp.Values[0], &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
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

// getCurrentNonce uses raw hex address.
func (c *WalletClient) getCurrentNonce(address string) (uint64, error) {
	rawAddress, err := normaliseAddress(address)
	if err != nil {
		return 0, err
	}
	resp, err := rpc.CallRPC(c.nodeAddr, "getnonce", []interface{}{rawAddress}, c.nodeID, 60)
	if err != nil {
		return 0, err
	}
	var nonce uint64
	if err := json.Unmarshal(resp.Values[0], &nonce); err != nil {
		return 0, err
	}
	return nonce + 1, nil // Increment for new transaction
}

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

	// Normalise recipient address to raw hex
	rawTo, err := normaliseAddress(toAddress)
	if err != nil {
		return "", fmt.Errorf("invalid recipient address: %w", err)
	}

	// Normalise sender address (ours) – use sessionFingerprint
	rawSender, err := normaliseAddress(sessionFingerprint)
	if err != nil {
		return "", fmt.Errorf("invalid sender address: %w", err)
	}

	log.Printf("[WalletRPC] SendTransaction: sending %s to %s",
		amount.String(), rawTo[:16]+"...")

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
	// Gas price: 1 gSPX = 1,000,000,000 nSPX per gas unit
	gasPrice := big.NewInt(GasPriceSPX)

	tx := &types.Transaction{
		ID:         "",
		Sender:     rawSender,
		Receiver:   rawTo,
		Amount:     amount,
		GasLimit:   big.NewInt(21000), // Standard gas limit for a transfer
		GasPrice:   gasPrice,          // 1 gSPX per gas unit
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

// signTransactionLocally signs a transaction using SPHINCS+
func signTransactionLocally(tx *types.Transaction, skBytes, pkBytes []byte) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	if tx.ID == "" {
		tx.ID = tx.Hash()
	}

	km, err := key.NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to initialize key manager: %w", err)
	}
	privateKey, _, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		return fmt.Errorf("failed to deserialize key pair: %w", err)
	}

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

	rawAddress, err := normaliseAddress(address)
	if err != nil {
		return nil, err
	}

	log.Printf("[WalletRPC] GetTransactionHistory: fetching for %s", rawAddress[:16]+"...")

	params := []interface{}{rawAddress, limit}
	resp, err := rpc.CallRPC(c.nodeAddr, "gettransactionhistory", params, c.nodeID, 60)
	if err != nil {
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}

	if len(resp.Values) == 0 {
		return []TransactionResponse{}, nil
	}

	var txs []TransactionResponse
	if err := json.Unmarshal(resp.Values[0], &txs); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return txs, nil
}
