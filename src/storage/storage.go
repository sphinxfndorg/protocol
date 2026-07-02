// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sphinxfndorg/protocol/src/rpc"
)

// NOTE:
// This package is meant to support “off-chain storage + on-chain anchoring”
// for mint receipts / NFTs.
//
// ASSUMPTION — CONFIRM AGAINST YOUR NODE:
// The previous version of this file guessed at five different RPC method
// names and used whichever one didn't error. That's exactly backwards: a
// wrong guess can silently "succeed" against an unrelated handler. This
// version pins down ONE canonical method name for each operation below.
// If your node's actual RPC dispatcher uses different names, change these
// two constants — that's the only place the method name should live.
const (
	// RPCMethodStoreArtifact persists a StorageArtifact keyed by MintID.
	// Expected request:  params[0] = JSON-encoded StorageArtifact (string)
	// Expected response: JSON object with at least one of {txid, hash, status},
	//                    and optionally {error} to signal a node-side rejection.
	RPCMethodStoreArtifact = "storeartifact"

	// RPCMethodGetArtifact reads back a previously stored StorageArtifact.
	// Expected request:  params[0] = mint_id (string)
	// Expected response: JSON object matching StorageArtifact, OR
	//                    {"found": false} / a non-nil error if it doesn't exist.
	RPCMethodGetArtifact = "getartifact"
)

type StorageClient struct {
	NodeAddr string
	NodeID   rpc.NodeID
	HTTP     *http.Client
	Timeout  time.Duration
}

// StorageArtifact is the off-chain artifact we want to store/associate with an NFT.
type StorageArtifact struct {
	MintID        string `json:"mint_id"`
	Subject       string `json:"subject"`
	CID           string `json:"cid"`
	CIDHashHex    string `json:"cid_hash_hex"`
	PayloadHash   string `json:"payload_hash"`
	ReceiptHash   string `json:"receipt_hash"`
	AnchorTagType string `json:"anchor_tag_type"`
}

// DefaultStorageClient constructs a client with provided node addr.
func DefaultStorageClient(nodeAddr string) *StorageClient {
	return &StorageClient{
		NodeAddr: nodeAddr,
		Timeout:  30 * time.Second,
	}
}

// ErrArtifactConflict is returned when a MintID is already anchored on the
// node with a *different* CID/content than the one being submitted now.
// Callers should treat this as a hard failure, not something to retry —
// silently overwriting it would break the mint's content-binding guarantee.
var ErrArtifactConflict = errors.New("mint id already anchored with different content")

// StoreMintArtifact stores the artifact association on a node.
//
// This is idempotent: if the MintID is already stored with the same
// CIDHashHex, the existing status is returned instead of writing again
// (this is the equivalent of an ERC-721 contract refusing to mint a
// tokenId that already exists — Sphinx has no such enforcement on-chain
// yet, so it's enforced here at the client boundary instead).
func (c *StorageClient) StoreMintArtifact(artifact *StorageArtifact) (string, error) {
	if artifact == nil {
		return "", errors.New("nil artifact")
	}
	if c == nil {
		return "", errors.New("nil storage client")
	}
	if c.NodeAddr == "" {
		return "", errors.New("empty node addr")
	}
	if artifact.MintID == "" {
		return "", errors.New("empty mint id")
	}

	// Idempotency check: has this MintID already been stored?
	// NOTE: we can't yet distinguish "not found" from "node doesn't support
	// getartifact" from "transient RPC error" — GetMintArtifact returns a
	// plain error for all three. Until the node gives us a structured
	// not-found signal, we treat any error here as "proceed to store" and
	// only block on a *successful* lookup that shows a conflicting hash.
	if existing, err := c.GetMintArtifact(artifact.MintID); err == nil && existing != nil {
		if existing.CIDHashHex == artifact.CIDHashHex {
			return existing.CIDHashHex, nil // already anchored with identical content — no-op
		}
		return "", fmt.Errorf("%w: mint_id=%s existing_cid_hash=%s new_cid_hash=%s",
			ErrArtifactConflict, artifact.MintID, existing.CIDHashHex, artifact.CIDHashHex)
	}

	b, err := json.Marshal(artifact)
	if err != nil {
		return "", fmt.Errorf("marshal artifact: %w", err)
	}

	params := []interface{}{string(b)}
	resp, rpcErr := rpc.CallRPC(c.NodeAddr, RPCMethodStoreArtifact, params, c.NodeID, 120)
	if rpcErr != nil {
		return "", fmt.Errorf("%s: %w", RPCMethodStoreArtifact, rpcErr)
	}
	if len(resp.Values) == 0 {
		return "", fmt.Errorf("%s: empty response", RPCMethodStoreArtifact)
	}

	var r struct {
		TxID   string `json:"txid"`
		Hash   string `json:"hash"`
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(resp.Values[0], &r); err != nil {
		return "", fmt.Errorf("%s: parse response: %w", RPCMethodStoreArtifact, err)
	}
	if r.Error != "" {
		return "", fmt.Errorf("%s: %s", RPCMethodStoreArtifact, r.Error)
	}
	if r.TxID != "" {
		return r.TxID, nil
	}
	if r.Hash != "" {
		return r.Hash, nil
	}
	if r.Status != "" {
		return r.Status, nil
	}
	return "", fmt.Errorf("%s: response had none of txid/hash/status: %s", RPCMethodStoreArtifact, string(resp.Values[0]))
}

// GetMintArtifact reads back a stored artifact by MintID.
//
// This is the read-side "verify" primitive this package was missing: it's
// the closest equivalent to calling ownerOf()/tokenURI() on an ERC-721
// contract — a way for *anyone* holding a mint_id to ask the node what's
// actually anchored, rather than trusting a locally-supplied receipt file.
func (c *StorageClient) GetMintArtifact(mintID string) (*StorageArtifact, error) {
	if c == nil {
		return nil, errors.New("nil storage client")
	}
	if c.NodeAddr == "" {
		return nil, errors.New("empty node addr")
	}
	if mintID == "" {
		return nil, errors.New("empty mint id")
	}

	resp, err := rpc.CallRPC(c.NodeAddr, RPCMethodGetArtifact, []interface{}{mintID}, c.NodeID, 60)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", RPCMethodGetArtifact, err)
	}
	if len(resp.Values) == 0 {
		return nil, fmt.Errorf("%s: empty response", RPCMethodGetArtifact)
	}

	// Some nodes may signal "not found" as a structured field rather than
	// a transport error; handle that shape first.
	var probe struct {
		Found *bool  `json:"found"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(resp.Values[0], &probe)
	if probe.Found != nil && !*probe.Found {
		return nil, fmt.Errorf("%s: mint_id %s not found", RPCMethodGetArtifact, mintID)
	}
	if probe.Error != "" {
		return nil, fmt.Errorf("%s: %s", RPCMethodGetArtifact, probe.Error)
	}

	var artifact StorageArtifact
	if err := json.Unmarshal(resp.Values[0], &artifact); err != nil {
		return nil, fmt.Errorf("%s: parse response: %w", RPCMethodGetArtifact, err)
	}
	if artifact.MintID == "" {
		return nil, fmt.Errorf("%s: response missing mint_id (got: %s)", RPCMethodGetArtifact, string(resp.Values[0]))
	}
	return &artifact, nil
}

// Utility: build a deterministic “anchor payload” blob if needed elsewhere.
func BuildAnchorPayload(artifact *StorageArtifact) ([]byte, error) {
	if artifact == nil {
		return nil, errors.New("nil artifact")
	}
	// Deterministically marshal to JSON (encoding/json sorts map keys but struct field order is fixed).
	// For strict determinism, avoid random spacing.
	out := struct {
		MintID     string `json:"mint_id"`
		Subject    string `json:"subject"`
		CID        string `json:"cid"`
		CIDHashHex string `json:"cid_hash_hex"`
	}{
		MintID:     artifact.MintID,
		Subject:    artifact.Subject,
		CID:        artifact.CID,
		CIDHashHex: artifact.CIDHashHex,
	}

	b, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("marshal anchor payload: %w", err)
	}
	return bytes.Clone(b), nil
}
