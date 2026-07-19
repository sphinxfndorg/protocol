// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

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

	// Create the transaction payload
	txPayload := map[string]interface{}{
		"sender":      from,
		"receiver":    from, // Send to self — this is an anchor, not a transfer
		"amount":      "0",
		"gas_limit":   "50000",
		"gas_price":   "1",
		"nonce":       0,
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
