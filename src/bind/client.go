// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/client.go
package bind

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

	"github.com/sphinxfndorg/protocol/src/rpc"
	"golang.org/x/crypto/sha3"
)

// ============================================================================
// P2P RPC Client (for node-to-node communication)
// ============================================================================

// CallNodeRPC sends an RPC request to a node identified by its name in the resources.
func CallNodeRPC(resources []NodeResources, nodeName, method string, params interface{}, ttl uint16) (interface{}, error) {
	var targetResource *NodeResources
	for _, resource := range resources {
		if resource.P2PServer.LocalNode().ID == nodeName {
			targetResource = &resource
			break
		}
	}
	if targetResource == nil {
		return nil, fmt.Errorf("node %s not found in resources", nodeName)
	}

	node := targetResource.P2PServer.LocalNode()
	udpAddr := node.UDPPort
	if udpAddr == "" {
		return nil, fmt.Errorf("no UDP address configured for node %s", nodeName)
	}

	var nodeID rpc.NodeID
	sh := sha3.NewShake256()
	sh.Write(node.PublicKey)
	sh.Read(nodeID[:])

	resp, err := rpc.CallRPC(udpAddr, method, params, nodeID, ttl)
	if err != nil {
		return nil, fmt.Errorf("RPC call to %s failed: %w", nodeName, err)
	}

	if len(resp.Values) == 0 {
		return nil, fmt.Errorf("no result data in RPC response from %s", nodeName)
	}

	var result interface{}
	if err := json.Unmarshal(resp.Values[0], &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal RPC result from %s: %w", nodeName, err)
	}

	return result, nil
}

// ============================================================================
// HTTP JSON-RPC Client (for external/client communication)
// ============================================================================

// JSONRPCRequest represents a standard JSON-RPC 2.0 request
type JSONRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

// JSONRPCResponse represents a standard JSON-RPC 2.0 response
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *JSONRPCError   `json:"error"`
	ID      int             `json:"id"`
}

// JSONRPCError represents a JSON-RPC error
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// SendTxOptions contains parameters for sending a transaction
type SendTxOptions struct {
	RPCURL   string
	From     string
	To       string
	Amount   string
	GasLimit string
	GasPrice string
	Nonce    uint64
	KeyFile  string
	Wait     bool
}

// GetBalanceOptions contains parameters for getting a balance
type GetBalanceOptions struct {
	RPCURL  string
	Address string
}

// WatchTxOptions contains parameters for watching a transaction
type WatchTxOptions struct {
	RPCURL      string
	TxID        string
	TimeoutSecs int
}

// TransactionReceipt represents the receipt of a transaction
type TransactionReceipt struct {
	TransactionHash   string `json:"transactionHash"`
	TransactionIndex  string `json:"transactionIndex"`
	BlockHash         string `json:"blockHash"`
	BlockNumber       string `json:"blockNumber"`
	CumulativeGasUsed string `json:"cumulativeGasUsed"`
	GasUsed           string `json:"gasUsed"`
	ContractAddress   string `json:"contractAddress"`
	Status            string `json:"status"`
}

// Logger interface for logging (to avoid import cycles)
type Logger interface {
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

var globalLogger Logger

// SetLogger sets the logger implementation to use
func SetLogger(logger Logger) {
	globalLogger = logger
}

func getLogger() Logger {
	if globalLogger == nil {
		return &noopLogger{}
	}
	return globalLogger
}

type noopLogger struct{}

func (l *noopLogger) Info(args ...interface{})                  {}
func (l *noopLogger) Infof(format string, args ...interface{})  {}
func (l *noopLogger) Debugf(format string, args ...interface{}) {}
func (l *noopLogger) Warnf(format string, args ...interface{})  {}
func (l *noopLogger) Errorf(format string, args ...interface{}) {}

// SendTransaction sends a transaction via HTTP JSON-RPC
func SendTransaction(opts SendTxOptions) error {
	logger := getLogger()
	logger.Infof("Sending transaction from %s to %s amount %s SPX", opts.From, opts.To, opts.Amount)

	amountBig, ok := new(big.Int).SetString(opts.Amount, 10)
	if !ok {
		return fmt.Errorf("invalid amount: %s", opts.Amount)
	}
	weiAmount := new(big.Int).Mul(amountBig, big.NewInt(1e18))

	nonce := opts.Nonce
	if nonce == 0 {
		var err error
		nonce, err = GetNonce(opts.RPCURL, opts.From)
		if err != nil {
			return fmt.Errorf("failed to get nonce: %v", err)
		}
		logger.Debugf("Using nonce: %d", nonce)
	}

	params := map[string]interface{}{
		"from":     opts.From,
		"to":       opts.To,
		"value":    "0x" + weiAmount.Text(16),
		"gas":      "0x" + strconv.FormatInt(parseIntOrDefault(opts.GasLimit, 21000), 16),
		"gasPrice": "0x" + strconv.FormatInt(parseIntOrDefault(opts.GasPrice, 1), 16),
		"nonce":    "0x" + strconv.FormatUint(nonce, 16),
	}

	var result string
	err := CallRPC(opts.RPCURL, "sphinx_sendTransaction", []interface{}{params}, &result)
	if err != nil {
		return fmt.Errorf("RPC call failed: %v", err)
	}

	logger.Infof("Transaction sent! TX ID: %s", result)

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

// GetBalance queries the balance of an address via HTTP JSON-RPC
func GetBalance(opts GetBalanceOptions) error {
	logger := getLogger()
	logger.Infof("Querying balance for address: %s", opts.Address)

	var balanceHex string
	err := CallRPC(opts.RPCURL, "sphinx_getBalance", []interface{}{opts.Address, "latest"}, &balanceHex)
	if err != nil {
		return fmt.Errorf("failed to get balance: %v", err)
	}

	balanceHex = strings.TrimPrefix(balanceHex, "0x")
	balanceBig := new(big.Int)
	balanceBig, ok := balanceBig.SetString(balanceHex, 16)
	if !ok {
		return fmt.Errorf("failed to parse balance: %s", balanceHex)
	}

	spxBalance := new(big.Float).Quo(
		new(big.Float).SetInt(balanceBig),
		new(big.Float).SetFloat64(1e18),
	)

	logger.Infof("Balance for %s: %.6f SPX", opts.Address, spxBalance)
	return nil
}

// WatchTransaction polls until a transaction is confirmed
func WatchTransaction(opts WatchTxOptions) error {
	logger := getLogger()
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
			err := CallRPC(opts.RPCURL, "sphinx_getTransactionReceipt", []interface{}{opts.TxID}, &receipt)
			if err != nil {
				logger.Debugf("Transaction not yet confirmed: %v", err)
				continue
			}

			if receipt.TransactionHash != "" {
				status, _ := strconv.ParseInt(receipt.Status, 16, 64)
				if status == 1 {
					blockNum, _ := strconv.ParseInt(receipt.BlockNumber, 16, 64)
					logger.Infof("✓ Transaction CONFIRMED in block %d! Hash: %s", blockNum, receipt.TransactionHash)
					return nil
				} else {
					return fmt.Errorf("transaction failed with status %s", receipt.Status)
				}
			}
		}
	}
}

// GetNonce retrieves the next nonce for an address
func GetNonce(rpcURL, address string) (uint64, error) {
	var nonceHex string
	err := CallRPC(rpcURL, "sphinx_getTransactionCount", []interface{}{address, "pending"}, &nonceHex)
	if err != nil {
		return 0, err
	}

	nonceHex = strings.TrimPrefix(nonceHex, "0x")
	nonce, err := strconv.ParseUint(nonceHex, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse nonce: %v", err)
	}

	return nonce, nil
}

// CallRPC makes a JSON-RPC call to the specified HTTP endpoint
func CallRPC(rpcURL, method string, params []interface{}, result interface{}) error {
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

	logger := getLogger()
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
