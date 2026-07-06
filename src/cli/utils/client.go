// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/client.go
package utils

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	logger "github.com/sphinxfndorg/protocol/src/log"
	"github.com/sphinxfndorg/protocol/src/policy"
)

// SendTransaction sends a transaction via JSON-RPC
func SendTransaction(opts SendTxOptions) error {
	logger.Infof("Sending transaction from %s to %s amount %s SPX", opts.From, opts.To, opts.Amount)

	// Convert amount to nSPX (assuming 1 SPX = 10^18 nSPX)
	amountBig, ok := new(big.Int).SetString(opts.Amount, 10)
	if !ok {
		return fmt.Errorf("invalid amount: %s", opts.Amount)
	}
	weiAmount := new(big.Int).Mul(amountBig, big.NewInt(1e18))

	// Get nonce if not provided
	nonce := opts.Nonce
	if nonce == 0 {
		var err error
		nonce, err = getNonce(opts.RPCURL, opts.From)
		if err != nil {
			logger.Warn("Failed to get nonce, using 0: %v", err)
			nonce = 0
		}
		logger.Debugf("Using nonce: %d", nonce)
	}

	if opts.KeyFile == "" {
		return fmt.Errorf("--key is required: transactions must be locally signed with a full SPHINCS auth bundle before broadcast")
	}

	tx, err := buildSignedTransaction(opts, weiAmount, nonce)
	if err != nil {
		return err
	}

	rawTx, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal signed transaction: %w", err)
	}

	var result map[string]string
	err = callRPC(opts.RPCURL, "sendrawtransaction", []interface{}{hex.EncodeToString(rawTx)}, &result)
	if err != nil {
		return fmt.Errorf("RPC call failed: %v", err)
	}

	txID := result["txid"]
	if txID == "" {
		txID = tx.ID
	}
	logger.Infof("Transaction sent! TX ID: %s", txID)

	// Wait for confirmation if requested
	if opts.Wait {
		logger.Info("Waiting for transaction confirmation...")
		return WatchTransaction(WatchTxOptions{
			RPCURL:      opts.RPCURL,
			TxID:        txID,
			TimeoutSecs: 120,
		})
	}

	return nil
}

func buildSignedTransaction(opts SendTxOptions, amount *big.Int, nonce uint64) (*types.Transaction, error) {
	gasLimit := big.NewInt(parseIntOrDefault(opts.GasLimit, 21000))
	gasPrice := big.NewInt(parseIntOrDefault(opts.GasPrice, 1))

	tx := &types.Transaction{
		Sender:    opts.From,
		Receiver:  opts.To,
		Amount:    new(big.Int).Set(amount),
		GasLimit:  gasLimit,
		GasPrice:  gasPrice,
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
		ChainID:   7331, // Sphinx Mainnet chain ID (EIP-155 replay protection)
	}
	tx.ID = tx.Hash()

	skBytes, pkBytes, err := loadSigningKeyFile(opts.KeyFile)
	if err != nil {
		return nil, err
	}

	km, err := key.NewKeyManager()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize key manager: %w", err)
	}
	privateKey, publicKey, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize key file: %w", err)
	}

	manager := sign.NewSTHINCSManager(nil, km, km.GetSPHINCSParameters())
	bundle, err := manager.SignTransactionAuth([]byte(tx.ID), privateKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	tx.Signature = bundle.Signature
	tx.SignatureHash = bundle.SignatureHash
	tx.PublicKey = bundle.PublicKey
	tx.AuthTimestamp = bundle.Timestamp
	tx.AuthNonce = bundle.Nonce
	tx.MerkleRootHash = bundle.MerkleRootHash
	tx.Commitment = bundle.Commitment
	tx.Proof = bundle.Proof

	ensurePolicyFee(tx)

	return tx, nil
}

func ensurePolicyFee(tx *types.Transaction) {
	estimatedSize := uint64(len(tx.ID) + len(tx.Sender) + len(tx.Receiver) + 16)
	if tx.Amount != nil {
		estimatedSize += uint64(len(tx.Amount.Bytes()))
	}
	if tx.GasLimit != nil {
		estimatedSize += uint64(len(tx.GasLimit.Bytes()))
	}
	if tx.GasPrice != nil {
		estimatedSize += uint64(len(tx.GasPrice.Bytes()))
	}
	estimatedSize += 16 // nonce + timestamp
	estimatedSize += uint64(len(tx.Signature) + len(tx.SignatureHash) + len(tx.PublicKey))
	estimatedSize += uint64(len(tx.AuthTimestamp) + len(tx.AuthNonce))
	estimatedSize += uint64(len(tx.MerkleRootHash) + len(tx.Commitment) + len(tx.Proof))
	estimatedSize += uint64(len(tx.ReturnData) + len(tx.Data))

	ops := uint64(2)
	if tx.HasReturnData() {
		ops++
	}
	hashes := uint64(5)
	requiredFee := policy.GetDefaultPolicyParams().CalculateMinimumFee(estimatedSize, ops, hashes)
	if tx.GetGasFee().Cmp(requiredFee) >= 0 {
		return
	}

	gasLimit := tx.GasLimit
	if gasLimit == nil || gasLimit.Sign() <= 0 {
		gasLimit = big.NewInt(21000)
		tx.GasLimit = gasLimit
	}
	tx.GasPrice = new(big.Int).Div(requiredFee, gasLimit)
	if new(big.Int).Mul(tx.GasPrice, gasLimit).Cmp(requiredFee) < 0 {
		tx.GasPrice.Add(tx.GasPrice, big.NewInt(1))
	}
}

func loadSigningKeyFile(path string) ([]byte, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key file: %w", err)
	}

	var keyFile struct {
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
		SK         string `json:"sk"`
		PK         string `json:"pk"`
	}
	if err := json.Unmarshal(data, &keyFile); err == nil {
		privateKey := firstNonEmpty(keyFile.PrivateKey, keyFile.SK)
		publicKey := firstNonEmpty(keyFile.PublicKey, keyFile.PK)
		if privateKey == "" || publicKey == "" {
			return nil, nil, fmt.Errorf("key file must contain private_key/public_key or sk/pk")
		}
		skBytes, err := decodeKeyBytes(privateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid private key encoding: %w", err)
		}
		pkBytes, err := decodeKeyBytes(publicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid public key encoding: %w", err)
		}
		return skBytes, pkBytes, nil
	}

	lines := strings.Fields(string(data))
	if len(lines) < 2 {
		return nil, nil, fmt.Errorf("key file must be JSON or contain private/public key hex on separate lines")
	}
	skBytes, err := decodeKeyBytes(lines[0])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid private key encoding: %w", err)
	}
	pkBytes, err := decodeKeyBytes(lines[1])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public key encoding: %w", err)
	}
	return skBytes, pkBytes, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func decodeKeyBytes(value string) ([]byte, error) {
	value = strings.TrimSpace(strings.TrimPrefix(value, "0x"))
	return hex.DecodeString(value)
}

// GetBalance queries the balance of an address
func GetBalance(opts GetBalanceOptions) error {
	logger.Infof("Querying balance for address: %s", opts.Address)

	var balanceHex string
	// Using spx_getBalance
	err := callRPC(opts.RPCURL, "spx_getBalance", []interface{}{opts.Address, "latest"}, &balanceHex)
	if err != nil {
		return fmt.Errorf("failed to get balance: %v", err)
	}

	// Convert from hex to decimal
	balanceHex = strings.TrimPrefix(balanceHex, "0x")
	if balanceHex == "" {
		balanceHex = "0"
	}
	balanceBig := new(big.Int)
	balanceBig, ok := balanceBig.SetString(balanceHex, 16)
	if !ok {
		return fmt.Errorf("failed to parse balance: %s", balanceHex)
	}

	// Convert from nSPX to SPX (1 SPX = 10^18 nSPX)
	spxBalance := new(big.Float).Quo(
		new(big.Float).SetInt(balanceBig),
		new(big.Float).SetFloat64(1e18),
	)

	logger.Infof("Balance for %s: %.6f SPX", opts.Address, spxBalance)
	return nil
}

// WatchTransaction polls until a transaction is confirmed
func WatchTransaction(opts WatchTxOptions) error {
	logger.Infof("Watching transaction: %s (timeout: %d seconds)", opts.TxID, opts.TimeoutSecs)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	timeout := time.After(time.Duration(opts.TimeoutSecs) * time.Second)

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for transaction %s after %d seconds", opts.TxID, opts.TimeoutSecs)
		case <-ticker.C:
			var receipt TransactionReceipt
			// Using spx_getTransactionReceipt
			err := callRPC(opts.RPCURL, "spx_getTransactionReceipt", []interface{}{opts.TxID}, &receipt)
			if err != nil {
				logger.Debugf("Transaction not yet confirmed: %v", err)
				continue
			}

			// Check if we got a valid receipt
			if receipt.TransactionHash != "" {
				// Parse status as hex string
				var status int64
				if receipt.Status != "" {
					status, err = strconv.ParseInt(strings.TrimPrefix(receipt.Status, "0x"), 16, 64)
					if err != nil {
						status = 0
					}
				}
				if status == 1 {
					blockNum, _ := strconv.ParseInt(strings.TrimPrefix(receipt.BlockNumber, "0x"), 16, 64)
					logger.Infof("✓ Transaction CONFIRMED in block %d! Hash: %s", blockNum, receipt.TransactionHash)
					return nil
				} else {
					return fmt.Errorf("transaction failed with status %d", status)
				}
			}
		}
	}
}

// getNonce retrieves the next nonce for an address
func getNonce(rpcURL, address string) (uint64, error) {
	var nonceHex string
	// Using spx_getTransactionCount
	err := callRPC(rpcURL, "spx_getTransactionCount", []interface{}{address, "pending"}, &nonceHex)
	if err != nil {
		return 0, err
	}

	nonceHex = strings.TrimPrefix(nonceHex, "0x")
	if nonceHex == "" {
		return 0, nil
	}
	nonce, err := strconv.ParseUint(nonceHex, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse nonce: %v", err)
	}

	return nonce, nil
}

// callRPC makes a JSON-RPC call to the specified endpoint
func callRPC(rpcURL, method string, params []interface{}, result interface{}) error {
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	logger.Debugf("RPC Request: %s", string(requestBody))

	resp, err := http.Post(rpcURL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	logger.Debugf("RPC Response: %s", string(body))

	var rpcResp JSONRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if rpcResp.Error != nil {
		return fmt.Errorf("RPC error (%d): %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	if result != nil {
		if err := json.Unmarshal(rpcResp.Result, result); err != nil {
			// Try to unmarshal as string if the target is string
			if strResult, ok := result.(*string); ok {
				var str string
				if err := json.Unmarshal(rpcResp.Result, &str); err != nil {
					return fmt.Errorf("failed to unmarshal result: %v", err)
				}
				*strResult = str
				return nil
			}
			return fmt.Errorf("failed to unmarshal result: %v", err)
		}
	}

	return nil
}

// parseIntOrDefault parses a string to int64 or returns a default value
func parseIntOrDefault(s string, defaultValue int64) int64 {
	if s == "" {
		return defaultValue
	}
	val, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return defaultValue
	}
	return val
}
