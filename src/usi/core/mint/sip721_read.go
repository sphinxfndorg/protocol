// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sphinxfndorg/protocol/src/contracts"
	"github.com/sphinxfndorg/protocol/src/rpc"
	"github.com/sphinxfndorg/protocol/src/storage"
)

// ContractStorageReader performs global contract queries against a full node:
// getcontractstorage(contract, key) reads consensus storage (tokenURI[tokenId],
// ownerOf[tokenId], next_token_id) exactly as committed by block execution.
type ContractStorageReader struct {
	NodeAddr string
}

func NewContractStorageReader(nodeAddr string) *ContractStorageReader {
	return &ContractStorageReader{NodeAddr: nodeAddr}
}

func (r *ContractStorageReader) GetStorage(contract, key string) ([]byte, error) {
	if r == nil || strings.TrimSpace(r.NodeAddr) == "" {
		return nil, errors.New("node address required")
	}
	if strings.TrimSpace(contract) == "" || strings.TrimSpace(key) == "" {
		return nil, errors.New("contract address and storage key required")
	}
	raw, err := rpc.CallRPC(r.NodeAddr, "getcontractstorage", []interface{}{contract, key}, 60)
	if err != nil {
		return nil, fmt.Errorf("getcontractstorage: %w", err)
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fmt.Errorf("contract %s key %q not found", contract, key)
	}
	var hexStr string
	if err := json.Unmarshal(raw, &hexStr); err == nil {
		return storage.DecodeHexStorageValue(hexStr)
	}
	var asStr string
	if err := json.Unmarshal(raw, &asStr); err == nil {
		return []byte(asStr), nil
	}
	return []byte(strings.Trim(string(raw), "\"")), nil
}

// TokenOwnerOf reads ownerOf[tokenId] from the SIP-721 collection contract.
func (r *ContractStorageReader) TokenOwnerOf(contract string, tokenID uint64) (string, error) {
	v, err := r.GetStorage(contract, fmt.Sprintf("sip721:token:%d:owner", tokenID))
	if err != nil {
		return "", err
	}
	if len(v) == 0 {
		return "", fmt.Errorf("token %d does not exist on %s", tokenID, contract)
	}
	return string(v), nil
}

// TokenURIOf reads contract storage tokenURI[tokenId] (the on-chain
// ipfs://<metadataCID> pointer), the exact equivalent of ERC-721 tokenURI().
func (r *ContractStorageReader) TokenURIOf(contract string, tokenID uint64) (string, error) {
	v, err := r.GetStorage(contract, fmt.Sprintf("sip721:token:%d:uri", tokenID))
	if err != nil {
		return "", err
	}
	if len(v) == 0 {
		return "", fmt.Errorf("token %d does not exist on %s", tokenID, contract)
	}
	return string(v), nil
}

// TokenMetadataOf is tokenURI() + IPFS fetch: it resolves the on-chain
// tokenURI pointer and downloads the ERC-721 metadata JSON from the gateway.
func (r *ContractStorageReader) TokenMetadataOf(ipfsClient *storage.Client, contract string, tokenID uint64) (*NFTMetadata, string, error) {
	uri, err := r.TokenURIOf(contract, tokenID)
	if err != nil {
		return nil, "", err
	}
	cid := strings.TrimPrefix(strings.TrimSpace(uri), "ipfs://")
	if cid == "" {
		return nil, uri, fmt.Errorf("token %d has empty tokenURI", tokenID)
	}
	if ipfsClient == nil {
		return nil, uri, errors.New("ipfs client required")
	}
	data, err := ipfsClient.GetBytesFromIPFS(cid)
	if err != nil {
		return nil, uri, fmt.Errorf("fetch tokenURI %s: %w", uri, err)
	}
	var meta NFTMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, uri, fmt.Errorf("decode tokenURI %s: %w", uri, err)
	}
	return &meta, uri, nil
}

// NextTokenID reads the collection counter (the tokenId counter head).
func (r *ContractStorageReader) NextTokenID(contract string) (uint64, error) {
	v, err := r.GetStorage(contract, "sip721:info")
	if err != nil {
		return 0, err
	}
	var info contracts.SIP721Info
	if err := json.Unmarshal(v, &info); err != nil {
		return 0, fmt.Errorf("decode sip721 info: %w", err)
	}
	return info.NextTokenID, nil
}

// TokenIDOfMint resolves mintID -> tokenId via on-chain reverse index.
func (r *ContractStorageReader) TokenIDOfMint(contract, mintID string) (uint64, error) {
	v, err := r.GetStorage(contract, "sip721:mint:"+strings.TrimSpace(mintID))
	if err != nil {
		return 0, err
	}
	return parseUintStorage(v)
}

func parseUintStorage(v []byte) (uint64, error) {
	s := strings.TrimSpace(string(v))
	if s == "" {
		return 0, errors.New("empty storage value")
	}
	var n uint64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, fmt.Errorf("invalid uint storage %q", s)
	}
	return n, nil
}
