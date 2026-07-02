// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package storage

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ContractPayload is what the chain stores to bind an NFT (mint receipt/artifact)
// to an off-chain content CID.
//
// NOTE: The project consensus/RPC "smart contract" mechanism is abstracted.
// This module only builds a deterministic payload blob suitable for tx.ReturnData
// (or any other on-chain data field).
type ContractPayload struct {
	Type       string `json:"type"` // always "nft_anchor"
	MintID     string `json:"mint_id"`
	Subject    string `json:"subject"`
	CID        string `json:"cid"`
	CIDHashHex string `json:"cid_hash_hex"` // deterministic binding: sha256(CID string) as hex
}

// CreateNftContractReturnData builds a JSON payload to anchor an NFT on-chain.
//
// The caller is responsible for signing/broadcasting the corresponding transaction.
func CreateNftContractReturnData(artifact *StorageArtifact) ([]byte, error) {
	if artifact == nil {
		return nil, errors.New("nil artifact")
	}
	if artifact.CIDHashHex == "" {
		return nil, errors.New("missing artifact.CIDHashHex")
	}
	if artifact.CID == "" {
		return nil, errors.New("missing artifact.CID")
	}
	if artifact.MintID == "" {
		return nil, errors.New("missing artifact.MintID")
	}

	p := ContractPayload{
		Type:       "nft_anchor",
		MintID:     artifact.MintID,
		Subject:    artifact.Subject,
		CID:        artifact.CID,
		CIDHashHex: artifact.CIDHashHex,
	}

	b, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal contract payload: %w", err)
	}
	// Return raw JSON bytes. Callers can hex-encode when needed.
	return b, nil
}
