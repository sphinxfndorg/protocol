// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/client.go
package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/bind/abi"
	"github.com/sphinxfndorg/protocol/src/consensus"
	logger "github.com/sphinxfndorg/protocol/src/console"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
	"github.com/sphinxfndorg/protocol/src/rpc"
)

// abiRPC adapts this package's callRPC to abi.RPCClient, so the shared
// abi.Transact path can broadcast without abi importing the CLI transport. The
// TTL is unused here: callRPC has no timeout parameter.
type abiRPC struct{}

func (abiRPC) CallRPC(nodeAddr, method string, params interface{}, ttlSeconds uint16) (json.RawMessage, error) {
	list, ok := params.([]interface{})
	if !ok {
		return nil, fmt.Errorf("abi rpc: %s params must be a positional array", method)
	}
	var raw json.RawMessage
	if err := callRPC(nodeAddr, method, list, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// abiSigner implements abi.Signer with this package's canonical signing path
// (signTransactionCanonical), so key loading, the SPHINCS+ auth bundle and the
// policy fee floor stay exactly where they were.
type abiSigner struct{ keyFile string }

func (s abiSigner) SignTransaction(tx *types.Transaction) error {
	return signTransactionCanonical(tx, s.keyFile)
}

// SendTransaction sends a transaction via JSON-RPC
func SendTransaction(opts SendTxOptions) error {
	logger.Info("Sending transaction from %s to %s amount %s SPX", opts.From, opts.To, opts.Amount)

	// Convert amount to nSPX (assuming 1 SPX = 10^18 nSPX)
	amountBig, ok := new(big.Int).SetString(opts.Amount, 10)
	if !ok {
		return fmt.Errorf("invalid amount: %s", opts.Amount)
	}

	weiAmount := new(big.Int).Mul(amountBig, big.NewInt(1e18))

	// A caller-supplied --nonce wins. Otherwise leave it nil so abi.Transact
	// resolves it from the node's getnonce — the method the node registers.
	// This package used to pre-fill the nonce via spx_getTransactionCount,
	// which is not a registered method, so a run without --nonce silently fell
	// back to nonce 0 and was rejected by the exact-match mempool rule.
	var nonce *uint64
	if opts.Nonce != 0 {
		nonce = &opts.Nonce
	}

	if opts.KeyFile == "" {
		return fmt.Errorf("--key is required: transactions must be locally signed with a full SPHINCS auth bundle before broadcast")
	}

	tx, err := buildTransaction(opts, weiAmount, opts.Nonce)
	if err != nil {
		return err
	}

	txID, err := abi.Transact(&abi.TransactOpts{
		Client:   abiRPC{},
		Signer:   abiSigner{keyFile: opts.KeyFile},
		NodeAddr: opts.RPCURL,
		ChainID:  tx.ChainID,
		Nonce:    nonce,
	}, tx)
	if err != nil {
		return fmt.Errorf("broadcast signed transaction: %w", err)
	}
	logger.Info("Transaction sent! TX ID: %s", txID)

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

type StakeTxOptions struct {
	RPCURL           string
	Action           string
	From             string
	ValidatorID      string
	ValidatorKeyFile string
	Amount           string
	GasLimit         string
	GasPrice         string
	Nonce            uint64
	KeyFile          string
	Wait             bool
}

func SendStakeTransaction(opts StakeTxOptions) error {
	if opts.Action != "stake" && opts.Action != "unstake" {
		return fmt.Errorf("action must be stake or unstake")
	}
	if opts.From == "" || opts.ValidatorID == "" || opts.KeyFile == "" {
		return fmt.Errorf("--from, --validator-id, and --key are required")
	}
	amount := big.NewInt(0)
	if opts.Action == "stake" {
		spx, ok := new(big.Int).SetString(opts.Amount, 10)
		if !ok || spx.Sign() <= 0 {
			return fmt.Errorf("stake amount must be a positive whole-SPX integer")
		}
		amount.Mul(spx, big.NewInt(1e18))
	} else if opts.Amount != "" {
		return fmt.Errorf("--amount is only valid for --action=stake; unstake exits the full position")
	}
	receiver := opts.From
	if opts.Action == "stake" {
		receiver = types.StakingEscrowAddress
	}
	tx, err := buildTransaction(SendTxOptions{
		RPCURL:   opts.RPCURL,
		From:     opts.From,
		To:       receiver,
		GasLimit: opts.GasLimit,
		GasPrice: opts.GasPrice,
		KeyFile:  opts.KeyFile,
	}, amount, 0)
	if err != nil {
		return err
	}
	publicKey := ""
	var proof []byte
	if opts.Action == "stake" {
		if opts.ValidatorKeyFile == "" {
			return fmt.Errorf("--validator-key is required for stake")
		}
		proofMessage, err := types.StakeIdentityProofMessage(
			tx.ChainID, opts.Action, opts.ValidatorID, opts.From, tx.Amount,
		)
		if err != nil {
			return err
		}
		publicKey, proof, err = signStakeIdentityProof(opts.ValidatorID, opts.ValidatorKeyFile, proofMessage)
		if err != nil {
			return fmt.Errorf("sign validator identity proof: %w", err)
		}
	}
	data, err := types.BuildStakeActionData(opts.Action, opts.ValidatorID, publicKey, proof)
	if err != nil {
		return err
	}
	tx.ReturnData = data
	txID, err := abi.Transact(&abi.TransactOpts{
		Client:   abiRPC{},
		Signer:   abiSigner{keyFile: opts.KeyFile},
		NodeAddr: opts.RPCURL,
		ChainID:  tx.ChainID,
		Nonce:    optionalNonce(opts.Nonce),
	}, tx)
	if err != nil {
		return fmt.Errorf("broadcast signed %s transaction: %w", opts.Action, err)
	}
	logger.Info("%s transaction sent! TX ID: %s", opts.Action, txID)
	if opts.Wait {
		return WatchTransaction(WatchTxOptions{RPCURL: opts.RPCURL, TxID: txID, TimeoutSecs: 120})
	}
	return nil
}

func signStakeIdentityProof(validatorID, keyFile string, message []byte) (string, []byte, error) {
	skBytes, pkBytes, err := loadValidatorIdentityKeyFile(keyFile)
	if err != nil {
		return "", nil, err
	}
	keyManager, err := key.NewKeyManager()
	if err != nil {
		return "", nil, fmt.Errorf("initialize identity key manager: %w", err)
	}
	if _, _, err := keyManager.DeserializeKeyPair(skBytes, pkBytes); err != nil {
		return "", nil, fmt.Errorf("deserialize validator identity key: %w", err)
	}
	manager := sign.NewSTHINCSManager(nil, keyManager, keyManager.GetSPHINCSParameters())
	service, err := consensus.NewSigningService(manager, keyManager, validatorID, skBytes, pkBytes)
	if err != nil {
		return "", nil, fmt.Errorf("initialize validator identity signer: %w", err)
	}
	proof, err := service.SignMessage(message)
	if err != nil {
		return "", nil, fmt.Errorf("sign validator identity proof: %w", err)
	}
	return hex.EncodeToString(pkBytes), proof, nil
}

func loadValidatorIdentityKeyFile(path string) ([]byte, []byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("stat validator identity key path: %w", err)
	}
	if info.IsDir() || filepath.Base(path) == "private.key" {
		privatePath, publicPath := path, filepath.Join(path, "public.key")
		if !info.IsDir() {
			privatePath = path
			publicPath = filepath.Join(filepath.Dir(path), "public.key")
		} else {
			privatePath = filepath.Join(path, "private.key")
		}
		privateKey, err := readIdentityKeyFile(privatePath, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("read validator private key: %w", err)
		}
		publicKey, err := readIdentityKeyFile(publicPath, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("read validator public key: %w", err)
		}
		if len(privateKey) != 2*len(publicKey) {
			return nil, nil, fmt.Errorf("validator identity key lengths do not match")
		}
		return privateKey, publicKey, nil
	}
	return loadSigningKeyFile(path)
}

func readIdentityKeyFile(path string, expectedLength int) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == expectedLength {
		return data, nil
	}
	encoded := strings.TrimSpace(string(data))
	if len(encoded) == expectedLength*2 {
		decoded, err := hex.DecodeString(encoded)
		if err == nil && len(decoded) == expectedLength {
			return decoded, nil
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err == nil && len(decoded) == expectedLength {
		return decoded, nil
	}
	return nil, fmt.Errorf("key file %s has invalid encoding or length", path)
}

type SlashTxOptions struct {
	RPCURL       string
	From         string
	EvidenceFile string
	GasLimit     string
	GasPrice     string
	Nonce        uint64
	KeyFile      string
	Wait         bool
}

func SendDoubleSignEvidenceTransaction(opts SlashTxOptions) error {
	if opts.From == "" || opts.EvidenceFile == "" || opts.KeyFile == "" {
		return fmt.Errorf("--from, --evidence, and --key are required")
	}
	evidenceJSON, err := os.ReadFile(opts.EvidenceFile)
	if err != nil {
		return fmt.Errorf("read slashing evidence file: %w", err)
	}
	evidence, recognized, err := types.ParseDoubleSignEvidence(evidenceJSON)
	if err != nil {
		return fmt.Errorf("parse slashing evidence: %w", err)
	}
	if !recognized {
		return fmt.Errorf("evidence file does not contain %q", types.SlashEvidenceType)
	}
	data, err := types.BuildDoubleSignEvidenceData(evidence.First, evidence.Second)
	if err != nil {
		return fmt.Errorf("validate slashing evidence: %w", err)
	}
	tx, err := buildTransaction(SendTxOptions{
		RPCURL:   opts.RPCURL,
		From:     opts.From,
		To:       opts.From,
		GasLimit: opts.GasLimit,
		GasPrice: opts.GasPrice,
		KeyFile:  opts.KeyFile,
	}, big.NewInt(0), 0)
	if err != nil {
		return err
	}
	tx.ReturnData = data
	txID, err := abi.Transact(&abi.TransactOpts{
		Client:   abiRPC{},
		Signer:   abiSigner{keyFile: opts.KeyFile},
		NodeAddr: opts.RPCURL,
		ChainID:  tx.ChainID,
		Nonce:    optionalNonce(opts.Nonce),
	}, tx)
	if err != nil {
		return fmt.Errorf("broadcast double-sign evidence: %w", err)
	}
	logger.Info("Double-sign evidence submitted! TX ID: %s", txID)
	if opts.Wait {
		return WatchTransaction(WatchTxOptions{RPCURL: opts.RPCURL, TxID: txID, TimeoutSecs: 120})
	}
	return nil
}

func optionalNonce(nonce uint64) *uint64 {
	if nonce == 0 {
		return nil
	}
	return &nonce
}

// buildTransaction assembles the unsigned transfer; abi.Transact applies the
// nonce (nonce is the explicit override, 0 = let the node resolve it), derives
// the ID, signs (through abiSigner), encodes and broadcasts it.
func buildTransaction(opts SendTxOptions, amount *big.Int, nonce uint64) (*types.Transaction, error) {
	gasLimit := big.NewInt(parseIntOrDefault(opts.GasLimit, 21000))
	gasPrice := big.NewInt(parseIntOrDefault(opts.GasPrice, 1))

	return &types.Transaction{
		Sender:    opts.From,
		Receiver:  opts.To,
		Amount:    new(big.Int).Set(amount),
		GasLimit:  gasLimit,
		GasPrice:  gasPrice,
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
		ChainID:   7331, // Sphinx Mainnet chain ID (EIP-155 replay protection)
	}, nil
}

// signTransactionCanonical signs a transaction with the node's canonical
// SPHINCS+ transaction authentication path (mirrors the USI wallet's
// signTransactionLocally and core.SignTransaction).
//
// ★ HASH CONTRACT: tx.ID MUST be derived with types.Transaction.Hash() —
// which hashes the full transaction struct JSON with common.SpxHash — and
// the auth bundle MUST come from STHINCSManager.SignTransactionAuth over
// []byte(tx.ID), whose SignatureHash is common.SpxHash too. The node's SVM
// verifier (OP_CHECK_SIGNATURE_HASH → OP_VERIFY) re-derives the same SpxHash;
// any other hash construction (e.g. a bare sha256 over a partial struct, or
// an unsigned transaction) fails SVM signature verification with
// "error executing op code 0x69 at pc=21: VERIFY failed".
func signTransactionCanonical(tx *types.Transaction, keyFile string) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	if tx.ID == "" {
		tx.ID = tx.Hash()
	}

	skBytes, pkBytes, err := loadSigningKeyFile(keyFile)
	if err != nil {
		return err
	}

	km, err := key.NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to initialize key manager: %w", err)
	}
	privateKey, publicKey, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		return fmt.Errorf("failed to deserialize key file: %w", err)
	}

	manager := sign.NewSTHINCSManager(nil, km, km.GetSPHINCSParameters())
	bundle, err := manager.SignTransactionAuth([]byte(tx.ID), privateKey, publicKey)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
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
	return nil
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

// GetBalance queries the balance of an address over the wallet JSON-RPC
// transport. The REST/HTTP explorer does not serve JSON-RPC.
func GetBalance(opts GetBalanceOptions) error {
	logger.Info("Querying balance for address: %s", opts.Address)

	raw, err := rpc.CallRPC(opts.RPCURL, "getbalance", []interface{}{opts.Address}, 30)
	if err != nil {
		return fmt.Errorf("failed to get balance: %w", err)
	}

	var response struct {
		Address  string `json:"address"`
		Balance  string `json:"balance"`
		Pending  string `json:"pending"`
		Unlocked string `json:"unlocked"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return fmt.Errorf("failed to decode balance response: %w", err)
	}
	balanceText := strings.TrimSpace(response.Balance)
	if balanceText == "" {
		balanceText = "0"
	}
	balanceNSPX, ok := new(big.Int).SetString(balanceText, 10)
	if !ok {
		return fmt.Errorf("failed to parse balance: %s", balanceText)
	}
	spxBalance := new(big.Float).Quo(
		new(big.Float).SetInt(balanceNSPX),
		new(big.Float).SetFloat64(1e18),
	)

	logger.Info("Balance for %s: %.6f SPX (confirmed=%s nSPX, pending=%s nSPX, unlocked=%s nSPX)",
		opts.Address, spxBalance, balanceText, response.Pending, response.Unlocked)
	return nil
}

// WatchTransaction polls until a transaction is confirmed
func WatchTransaction(opts WatchTxOptions) error {
	logger.Info("Watching transaction: %s (timeout: %d seconds)", opts.TxID, opts.TimeoutSecs)

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
				logger.Debug("Transaction not yet confirmed: %v", err)
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
					logger.Info("Transaction CONFIRMED in block %d! Hash: %s", blockNum, receipt.TransactionHash)
					return nil
				} else {
					return fmt.Errorf("transaction failed with status %d", status)
				}
			}
		}
	}
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

	logger.Debug("RPC Request: %s", string(requestBody))

	resp, err := http.Post(rpcURL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	logger.Debug("RPC Response: %s", string(body))

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
