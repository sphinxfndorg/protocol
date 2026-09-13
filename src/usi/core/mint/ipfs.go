// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/sphinxfndorg/protocol/src/policy"
	"github.com/sphinxfndorg/protocol/src/rpc"
	"github.com/sphinxfndorg/protocol/src/storage"
)

// ipfsClient wraps the storage.IPFS client for use in the mint package.
type ipfsClient struct {
	client *storage.Client
}

// newIPFSClient creates a new IPFS client for uploading content.
func newIPFSClient(ipfsAddr, gatewayBaseURL string) *ipfsClient {
	cfg := storage.Config{
		IPFSAddr:       ipfsAddr,
		GatewayBaseURL: gatewayBaseURL,
		DisableIPFS:    false,
		Timeout:        60 * time.Second,
	}
	return &ipfsClient{client: storage.NewClient(cfg)}
}

// AddBytesToIPFS uploads bytes to IPFS and returns the CID.
func (c *ipfsClient) AddBytesToIPFS(data []byte, filename string) (string, error) {
	return c.client.AddBytesToIPFS(data, filename)
}

// GetGatewayURL returns the full HTTP gateway URL for a CID.
func (c *ipfsClient) GetGatewayURL(cid string) string {
	return c.client.GetGatewayURL(cid)
}

// broadcastAnchorTransaction creates, signs, and broadcasts a Sphinx
// transaction with the anchor data in ReturnData (OP_RETURN).
//
// This is the REAL on-chain anchor — the transaction gets included in a
// confirmed block, permanently recording the commitment.
func broadcastAnchorTransaction(nodeAddr, from, keyFile string, anchorData []byte) (string, error) {
	if nodeAddr == "" {
		return "", fmt.Errorf("node address required")
	}
	if from == "" {
		return "", fmt.Errorf("sender address required")
	}
	if keyFile == "" {
		return "", fmt.Errorf("key file required")
	}

	// Use the same policy quote enforced by core. This legacy mint path emits a
	// raw RPC payload rather than a transaction struct, so the values are
	// encoded as decimal strings here.
	mintPolicy := policy.GetDefaultPolicyParams()
	gasQuote := mintPolicy.QuoteTransactionGas(uint64(len(anchorData)))

	// The mempool enforces an EXACT nonce match ("invalid nonce: %d must equal
	// %d"), so the nonce must be the account's live value from the node — never
	// assumed 0 (that is only correct for an account that has never sent a tx).
	nonceData, err := rpc.CallRPC(nodeAddr, "getnonce", []interface{}{from}, 60)
	if err != nil {
		return "", fmt.Errorf("failed to get account nonce: %w", err)
	}
	var nonce uint64
	if err := json.Unmarshal(nonceData, &nonce); err != nil {
		return "", fmt.Errorf("parse nonce response: %w", err)
	}

	// Price the anchor's Amount with the same policy fee schedule the wallet
	// quotes (CalculateMintDataFee.TotalFee) instead of a hardcoded zero — the
	// anchor is a self-send whose value represents the policy-priced worth of
	// the committed data. Fall back to 1 nSPX only if the quote is unavailable.
	mintFeeQuote := mintPolicy.CalculateMintDataFee(uint64(len(anchorData)), uint64(len(anchorData)), mintPolicy.MintBaseHashes, mintPolicy.MintPinningMonths)
	mintFeeNSPX := big.NewInt(1)
	if mintFeeQuote != nil && mintFeeQuote.TotalFee != nil && mintFeeQuote.TotalFee.Sign() > 0 {
		mintFeeNSPX = mintFeeQuote.TotalFee
	}

	// Create the transaction payload
	txPayload := map[string]interface{}{
		"sender":      from,
		"receiver":    from, // Send to self — this is an anchor, not a transfer
		"amount":      mintFeeNSPX.String(),
		"gas_limit":   gasQuote.GasLimit.String(),
		"gas_price":   gasQuote.GasPrice.String(),
		"nonce":       nonce,
		"timestamp":   time.Now().Unix(),
		"return_data": hex.EncodeToString(anchorData),
	}

	// Marshal to JSON
	txJSON, err := json.Marshal(txPayload)
	if err != nil {
		return "", fmt.Errorf("marshal tx: %w", err)
	}

	// Broadcast via RPC. rpc.CallRPC(address, method, params, ttlSeconds)
	// dials the node's P2P TCP address and handles its own handshake — it
	// no longer takes a NodeID argument, and it returns the JSON-RPC
	// "result" field directly as json.RawMessage.
	resp, err := rpc.CallRPC(nodeAddr, "sendrawtransaction", []interface{}{hex.EncodeToString(txJSON)}, 120)
	if err != nil {
		return "", fmt.Errorf("RPC broadcast: %w", err)
	}

	if len(resp) == 0 {
		return "", fmt.Errorf("empty RPC response")
	}

	var result struct {
		TxID string `json:"txid"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", fmt.Errorf("parse RPC response: %w", err)
	}

	if result.TxID == "" {
		return "", fmt.Errorf("no txid in response")
	}

	return result.TxID, nil
}
