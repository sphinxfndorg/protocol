// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/rpc.go
package gui

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/core"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
	"github.com/sphinxfndorg/protocol/src/rpc"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
)

// NewWalletClient creates a new wallet RPC client.
//
// nodeAddr MUST be the node's dedicated wallet/JSON-RPC address — the
// nodeConfig.WSPort slot (see port.go's baseWSPort, default
// 127.0.0.1:8700), NOT the P2P gossip TCP address (baseTCPPort/32307) and
// NOT the HTTP/Gin address.
//
//   - The P2P gossip port (bind.StartNode's SECTION 11 listener) is served
//     by bind.handleIncomingConn, which speaks the unencrypted P2P wire
//     protocol (key_exchange, peer_exchange, checkpoint, get_blocks,
//     consensus messages) and has no "jsonrpc" case at all.
//   - The HTTP server (go/src/http) is a plain REST API
//     (/transaction, /blockcount, ...) with no JSON-RPC bridge.
//   - bind.StartNode's SECTION 11a starts a transport.TCPServer bound to
//     nodeConfig.WSPort specifically for this: transport.TCPServer.
//     handleConnection (tcp.go) is the only listener that performs the
//     handshake and forwards Type:"jsonrpc" requests into
//     rpc.Server.HandleRequest, and rpc.CallRPC (client.go) is written to
//     speak exactly its protocol (handshake + Type:"jsonrpc" + encrypted
//     framing).
func NewWalletClient(nodeAddr string) *WalletClient {
	if nodeAddr == "" {
		// Fallback to environment variable, then default
		if envAddr := os.Getenv("SPHINX_RPC_ADDR"); envAddr != "" {
			nodeAddr = envAddr
		} else {
			// Default to the dedicated wallet/JSON-RPC port (WSPort slot,
			// baseWSPort=8700), not the P2P gossip port (32307) and not the
			// HTTP port (8545/8645) — neither of those has a jsonrpc
			// handler, so pointing here previously guaranteed every wallet
			// RPC call would fail or be silently misrouted.
			nodeAddr = "127.0.0.1:8700"
		}
	}
	return &WalletClient{
		nodeAddr: nodeAddr,
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
	resultData, err := rpc.CallRPC(c.nodeAddr, "getbalance", params, 60)
	if err != nil {
		log.Printf("[WalletRPC] RPC call failed: %v", err)
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}

	if len(resultData) == 0 || string(resultData) == "null" {
		return nil, errors.New("empty response from RPC")
	}

	var result struct {
		Address  string `json:"address"`
		Balance  string `json:"balance"`
		Pending  string `json:"pending"`
		Unlocked string `json:"unlocked"`
	}
	if err := json.Unmarshal(resultData, &result); err != nil {
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

// ────────────────────────────────────────────────────────────────────────
// LIGHTWEIGHT (HEADER-ONLY) SYNC PATH
//
// ★ NODE-TYPE CONTRACT: USI is a LIGHTWEIGHT wallet, NOT a vault full node.
// Full nodes download and commit entire blocks (that is what
// src/core/sync.go's SyncManager does, running inside bind.StartNode).
// Lightweight wallets must NOT download block bodies — they download block
// headers only, and query all state (balance, history, nonce) from a full
// node's JSON-RPC. The three methods below are the wallet's entire chain
// footprint: they pull headers via the node's "getblockheader"/"getheaders"
// RPC, which deliberately return types.BlockHeader and never the full
// BlockBody (transactions, uncles, attestations).
// ────────────────────────────────────────────────────────────────────────

// GetChainTipHeader fetches ONLY the chain-tip block header from the node.
// Lightweight path: the wallet learns height/hash/proposer of the tip
// without ever requesting a full block.
func (c *WalletClient) GetChainTipHeader() (*types.BlockHeader, error) {
	resultData, err := rpc.CallRPC(c.nodeAddr, "getblockheader", []interface{}{"latest"}, 60)
	if err != nil {
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}
	if len(resultData) == 0 || string(resultData) == "null" {
		return nil, errors.New("empty response from RPC")
	}
	var hdr types.BlockHeader
	if err := json.Unmarshal(resultData, &hdr); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &hdr, nil
}

// GetBlockHeader fetches ONLY the header of the block at `height` (0 = genesis).
// Lightweight path: no block body is ever transferred.
func (c *WalletClient) GetBlockHeader(height uint64) (*types.BlockHeader, error) {
	resultData, err := rpc.CallRPC(c.nodeAddr, "getblockheader", []interface{}{height}, 60)
	if err != nil {
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}
	if len(resultData) == 0 || string(resultData) == "null" {
		return nil, errors.New("empty response from RPC")
	}
	var hdr types.BlockHeader
	if err := json.Unmarshal(resultData, &hdr); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &hdr, nil
}

// GetHeaders downloads a batch of block headers — headers only, never block
// bodies. A lightweight wallet can header-sync the whole chain (tip height,
// per-height hashes, difficulty, proposers) this way without holding a
// single full block.
func (c *WalletClient) GetHeaders(start uint64, count int) ([]types.BlockHeader, error) {
	resultData, err := rpc.CallRPC(c.nodeAddr, "getheaders", []interface{}{start, count}, 60)
	if err != nil {
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}
	if len(resultData) == 0 || string(resultData) == "null" {
		return []types.BlockHeader{}, nil
	}
	var hdrs []types.BlockHeader
	if err := json.Unmarshal(resultData, &hdrs); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return hdrs, nil
}

// getCurrentNonce gets the next nonce to use for `address` from the node.
//
// IMPORTANT: the node's getnonce RPC returns the account's CURRENT nonce (the
// next one that may be consumed). The mempool validates transactions with an
// EXACT match check ("invalid nonce: %d must equal %d"), so this value must be
// used verbatim — never incremented here, and never replaced with a timestamp.
func (c *WalletClient) getCurrentNonce(address string) (uint64, error) {
	rawAddress, err := normaliseAddress(address)
	if err != nil {
		return 0, err
	}
	resultData, err := rpc.CallRPC(c.nodeAddr, "getnonce", []interface{}{rawAddress}, 60)
	if err != nil {
		return 0, err
	}
	var nonce uint64
	if err := json.Unmarshal(resultData, &nonce); err != nil {
		return 0, err
	}
	return nonce, nil
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

	// ─── 2. Get next nonce from the node ────────────────────
	// The mempool enforces an EXACT nonce match ("invalid nonce: %d must
	// equal %d"), so the nonce must come from the node as-is. A timestamp
	// fallback can never pass that check — fail loudly instead of sending a
	// transaction that is guaranteed to be rejected.
	var nonce uint64
	if cachedNonce, err := c.getCurrentNonce(sessionFingerprint); err == nil {
		nonce = cachedNonce
		log.Printf("[WalletRPC] Using RPC nonce: %d", nonce)
	} else {
		return "", fmt.Errorf("failed to get account nonce from node: %w", err)
	}

	// ChainID for EIP-155 replay protection — must match the node's network.
	// Fall back to the Sphinx mainnet chain ID (7331) when the header is
	// unavailable.
	chainID := uint64(7331)
	if chainHdr := core.GetSphinxChainHeader(); chainHdr != nil && chainHdr.ChainID != 0 {
		chainID = chainHdr.ChainID
	}

	// ─── 3. Build and sign transaction locally ──────────────────
	// Mirror the policy quote for immediate UX. The node independently
	// recomputes and enforces this quote before accepting the transaction.
	gasQuote := policy.GetDefaultPolicyParams().QuoteTransactionGas(uint64(len(memo)))

	tx := &types.Transaction{
		ID:         "",
		ChainID:    chainID,
		Sender:     rawSender,
		Receiver:   rawTo,
		Amount:     amount,
		GasLimit:   gasQuote.GasLimit,
		GasPrice:   gasQuote.GasPrice,
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
	resultData, err := rpc.CallRPC(c.nodeAddr, "sendrawtransaction", []interface{}{rawTx}, 120)
	if err != nil {
		return "", fmt.Errorf("RPC error: %w", err)
	}

	if len(resultData) == 0 || string(resultData) == "null" {
		return "", errors.New("empty response")
	}

	var result struct {
		TxID   string `json:"txid"`
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(resultData, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if result.Error != "" {
		return "", fmt.Errorf("tx rejected: %s", result.Error)
	}

	return result.TxID, nil
}

// signTransactionLocally signs a transaction using the node's canonical
// SPHINCS+ transaction authentication path.
//
// ★ WHY THIS IS THE CANONICAL PATH: the node's mempool / RPC / block
// validators verify each transaction with STHINCSManager.VerifyTransactionAuth,
// which requires:
//   - signature over timestamp||nonce||txID  (NOT txID alone),
//   - SignatureHash == SpxHash(sigBytes)     (NOT plain sha3-256),
//   - a REAL SPHINCS receipt: MerkleRootHash built from the signature parts,
//     a real commitment, and a regenerable proof.
//
// The old hand-rolled implementation here signed only the bare txID with
// sha3-256 and left MerkleRootHash/Commitment/Proof as 32 zero bytes — the
// node rejected every one of those fields, so every wallet transfer failed
// with "signature verification failed" / "proof mismatch". Signing through
// STHINCSManager.SignTransactionAuth (the same call cli/utils/client.go and
// core.SignTransaction use) produces a bundle that passes all of them.
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
	privateKey, publicKey, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		return fmt.Errorf("failed to deserialize key pair: %w", err)
	}

	sphincsParams := km.GetSPHINCSParameters()
	if sphincsParams == nil || sphincsParams.Params == nil {
		return fmt.Errorf("SPHINCS+ parameters not initialized")
	}

	// Sign the canonical message (timestamp||nonce||txID) and build the full
	// auth bundle exactly as core/CLI nodes do. An in-memory manager (nil
	// LevelDB) is sufficient for signing — no replay evidence is consulted.
	signingMgr := sign.NewSTHINCSManager(nil, km, sphincsParams)
	bundle, err := signingMgr.SignTransactionAuth([]byte(tx.ID), privateKey, publicKey)
	if err != nil {
		return fmt.Errorf("failed to sign transaction auth bundle: %w", err)
	}

	tx.Signature = bundle.Signature
	tx.SignatureHash = bundle.SignatureHash
	tx.PublicKey = bundle.PublicKey
	tx.AuthTimestamp = bundle.Timestamp
	tx.AuthNonce = bundle.Nonce
	tx.MerkleRootHash = bundle.MerkleRootHash
	tx.Commitment = bundle.Commitment
	tx.Proof = bundle.Proof

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
	resultData, err := rpc.CallRPC(c.nodeAddr, "gettransactionhistory", params, 60)
	if err != nil {
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}

	if len(resultData) == 0 || string(resultData) == "null" {
		return []TransactionResponse{}, nil
	}

	var txs []TransactionResponse
	if err := json.Unmarshal(resultData, &txs); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return txs, nil
}
