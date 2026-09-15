// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/types/types.go
package types

import (
	"encoding/hex"
	"time"
)

// Meta holds all cryptographic and descriptive metadata for a signed document.
// It is serialised to the .ecpmeta sidecar and embedded into format-specific
// metadata containers (PDF properties, XMP, Office custom properties, xattrs).
type Meta struct {
	// Cryptographic fields
	Signature         string `json:"signature"`
	PublicKey         string `json:"public_key"`
	FileHash          string `json:"file_hash"`
	FinalDocumentHash string `json:"final_document_hash"`
	DocumentSignature string `json:"document_signature"`

	// Organisation — carried with the file so any device can route the lookup
	OrgCode string `json:"org_code,omitempty"`

	// Timestamps
	Timestamp          int64 `json:"timestamp"`
	SignatureTimestamp int64 `json:"signature_timestamp"`

	// Entropy
	Nonce string `json:"nonce"`

	// Descriptive
	Signer        string `json:"signer,omitempty"`
	DocumentTitle string `json:"document_title,omitempty"`

	// On-chain / pinning context (set by the Mint Data flow). Both are
	// optional so legacy .usimeta sidecars without them still decode.
	IPFSCID     string `json:"ipfs_cid,omitempty"`     // IPFS CID the payload was pinned under
	BlockHeight uint64 `json:"block_height,omitempty"` // chain-tip height at mint time

	// ERC-721 NFT metadata context (set when minting NFTs with metadata JSON).
	// TokenURI points to the metadata JSON on IPFS (like Ethereum ERC-721).
	// NFTName/NFTDescription mirror the metadata JSON's name/description so
	// the on-chain provenance block shows what the token represents without
	// fetching the JSON from IPFS.
	TokenURI       string `json:"token_uri,omitempty"`       // ipfs://<metadataCID>
	MetadataCID    string `json:"metadata_cid,omitempty"`    // CID of the metadata JSON
	NFTName        string `json:"nft_name,omitempty"`        // ERC-721 metadata name (frozen at mint)
	NFTDescription string `json:"nft_description,omitempty"` // ERC-721 metadata description (frozen at mint)

	// On-chain anchor provenance (populated AFTER AnchorMintReceipt returns,
	// via RefreshOnChainProvenance — NEVER before signing, so the SPHINCS+
	// signature is never invalidated). All optional so legacy sidecars
	// without them still decode, and "unanchored"/"pending" sentinels mark
	// data that was signed but never anchored (or anchored but not yet
	// confirmed in a block). Verify screens render these verbatim, so an
	// empty value must never be mistaken for a confirmed one.
	MintID          string `json:"mint_id,omitempty"`          // deterministic mint identifier (receipt.MintID)
	AnchorTxID      string `json:"anchor_txid,omitempty"`      // sendrawtransaction result txid ("unanchored" if never anchored)
	AnchorPath      string `json:"anchor_path,omitempty"`      // local anchor_*.json sidecar path
	ConfirmedHeight uint64 `json:"confirmed_height,omitempty"` // block height that included the anchor tx (0 = pending/unconfirmed)
	BlockHash       string `json:"block_hash,omitempty"`       // hex hash of the confirming block ("pending" while unconfirmed)
	TokenID         uint64 `json:"token_id,omitempty"`         // SIP-721 tokenId (collection mints only)
	ContractAddress string `json:"contract_address,omitempty"` // SIP-721 collection contract (collection mints only)

	// Embedded economics frozen at SIP-721 mint time and enforced by the native
	// runtime on every transfer_from / purchase_license. They travel with the
	// signed document so any verifier can see what economics were attached to
	// this anchor without consulting the chain. Zero/empty = legacy no-terms
	// token (royalties and license fees do not apply).
	RoyaltyBPS       uint64 `json:"royalty_bps,omitempty"`       // 0..10000 basis points of sale value
	UsageFeeNSPX     string `json:"usage_fee_nspx,omitempty"`    // per licensed-access fee, decimal nSPX
	RoyaltyRecipient string `json:"royalty_recipient,omitempty"` // "" = the mint caller (creator)

	// MintFeeNSPX records the policy-priced mint fee the anchor transaction
	// carried as its Amount (CalculateMintDataFee.TotalFee, in nSPX). It is
	// set by the Mint Data flow after AnchorMintReceipt returns so the embedded
	// provenance shows the price charged when the data was minted on-chain.
	MintFeeNSPX string `json:"mint_fee,omitempty"`

	// AnchorNonce records the transaction account nonce used by the anchor tx —
	// the on-chain replay-protection counter (an account's first transaction is
	// 0). Kept as a string so an unset value ("") is distinguishable from a
	// legitimate nonce 0, and rendered in the on-chain provenance block so the
	// file shows the REAL on-chain nonce alongside the signature nonce.
	AnchorNonce string `json:"anchor_nonce,omitempty"`
}

// GetPublicKeyPreview returns a shortened preview of the public key
func (m *Meta) GetPublicKeyPreview() string {
	if len(m.PublicKey) > 12 {
		return m.PublicKey[:12] + "..."
	}
	return m.PublicKey
}

// IsExpired checks if the signature is older than maxAge
func (m *Meta) IsExpired(maxAge time.Duration) bool {
	ts := m.SignatureTimestamp
	if ts == 0 {
		ts = m.Timestamp
	}
	if ts == 0 {
		return false
	}
	sigTime := time.Unix(ts, 0)
	return time.Since(sigTime) > maxAge
}

// HasSignature returns true if the meta contains a signature
func (m *Meta) HasSignature() bool {
	return m.Signature != "" && m.PublicKey != ""
}

// Clone creates a deep copy of the Meta
func (m *Meta) Clone() *Meta {
	if m == nil {
		return nil
	}
	return &Meta{
		Signature:          m.Signature,
		PublicKey:          m.PublicKey,
		FileHash:           m.FileHash,
		FinalDocumentHash:  m.FinalDocumentHash,
		DocumentSignature:  m.DocumentSignature,
		Timestamp:          m.Timestamp,
		SignatureTimestamp: m.SignatureTimestamp,
		Nonce:              m.Nonce,
		Signer:             m.Signer,
		DocumentTitle:      m.DocumentTitle,
		IPFSCID:            m.IPFSCID,
		BlockHeight:        m.BlockHeight,
		TokenURI:           m.TokenURI,
		MetadataCID:        m.MetadataCID,
		NFTName:            m.NFTName,
		NFTDescription:     m.NFTDescription,
		MintID:             m.MintID,
		AnchorTxID:         m.AnchorTxID,
		AnchorPath:         m.AnchorPath,
		ConfirmedHeight:    m.ConfirmedHeight,
		BlockHash:          m.BlockHash,
		TokenID:            m.TokenID,
		ContractAddress:    m.ContractAddress,
		MintFeeNSPX:        m.MintFeeNSPX,
		AnchorNonce:        m.AnchorNonce,
		// Embedded economics frozen at mint.
		RoyaltyBPS:       m.RoyaltyBPS,
		UsageFeeNSPX:     m.UsageFeeNSPX,
		RoyaltyRecipient: m.RoyaltyRecipient,
	}
}

// ComputeFileHashFromBytes is a helper to compute hash from bytes
func ComputeFileHashFromBytes(data []byte) string {
	// This will be implemented by sign package or here with crypto
	// For now, just a placeholder - actual implementation should use SHAKE256
	return hex.EncodeToString(data[:32])
}
