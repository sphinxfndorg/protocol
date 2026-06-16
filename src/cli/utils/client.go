// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/client.go
package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	logger "github.com/sphinxorg/protocol/src/log"
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

	// Prepare transaction parameters
	params := map[string]interface{}{
		"from":     opts.From,
		"to":       opts.To,
		"value":    "0x" + weiAmount.Text(16),
		"gas":      "0x" + strconv.FormatInt(parseIntOrDefault(opts.GasLimit, 21000), 16),
		"gasPrice": "0x" + strconv.FormatInt(parseIntOrDefault(opts.GasPrice, 1), 16),
		"nonce":    "0x" + strconv.FormatUint(nonce, 16),
	}

	// Make JSON-RPC call - Using spx_sendTransaction
	var result string
	err := callRPC(opts.RPCURL, "spx_sendTransaction", []interface{}{params}, &result)
	if err != nil {
		return fmt.Errorf("RPC call failed: %v", err)
	}

	logger.Infof("Transaction sent! TX ID: %s", result)

	// Wait for confirmation if requested
	if opts.Wait {
		logger.Info("Waiting for transaction confirmation...")
		return WatchTransaction(WatchTxOptions{
			RPCURL:      opts.RPCURL,
			TxID:        result,
			TimeoutSecs: 120,
		})
	}

	return nil
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
