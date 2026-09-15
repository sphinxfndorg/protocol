// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import "time"

// ReceiptVersion allows forward-compatible decoding.
const ReceiptVersion = 1

// MintReceipt is the on-disk representation of a "mint event".
// Anyone can verify it using the embedded public key.
//
// It mirrors Ethereum-style minting semantics:
// - the minter signs a canonical payload
// - the receipt is a self-contained proof
// - verifiers recompute the canonical payload and verify the signature
type MintReceipt struct {
	Version uint32 `json:"version"`

	// Deterministic identifier for the mint (SHA3-256 of subject+payloadHash+minterPK).
	MintID string `json:"mint_id"`

	// Asset/token identifier.
	Subject string `json:"subject"`

	// Hash of the minted payload bytes. SHAKE-256/32-bytes encoded as hex.
	PayloadHash string `json:"payload_hash"`

	// IPFS CID of the uploaded payload metadata.
	CID string `json:"cid,omitempty"`

	// ERC-721 style metadata URI (optional).
	// When set, this points to a JSON document conforming to the ERC-721
	// metadata schema (name, description, image, attributes, etc.).
	MetadataURI string `json:"metadata_uri,omitempty"`

	// TokenURI is the ERC-721 tokenURI — the canonical pointer to the NFT
	// metadata JSON document on IPFS. Set after the metadata JSON is uploaded.
	// Format: ipfs://<metadataCID>
	TokenURI string `json:"token_uri,omitempty"`

	// TokenID is the Ethereum-style numeric token id allocated by the
	// SIP-721 collection contract (contract storage tokenURI[tokenId]).
	// MintID remains the deterministic content-bound identifier; TokenID is
	// the per-collection counter value (starts at 1) for ERC-721 UX.
	TokenID uint64 `json:"token_id,omitempty"`

	// ContractAddress is the SIP-721 collection contract (sc...) that owns
	// tokenURI[tokenId] / ownerOf[tokenId] in consensus storage.
	ContractAddress string `json:"contract_address,omitempty"`

	// Embedded-economics terms set by the minter before anchoring. They travel
	// in the AnchorTag (and thus the signed receipt's own on-chain commitment)
	// and are enforced by the SIP-721 native runtime at consensus: RoyaltyBPS
	// is the resale-royalty share, UsageFeeNSPX the per licensed-access fee,
	// RoyaltyRecipient the optional payout override.
	RoyaltyBPS       uint64 `json:"royalty_bps,omitempty"`
	UsageFeeNSPX     string `json:"usage_fee_nspx,omitempty"`
	RoyaltyRecipient string `json:"royalty_recipient,omitempty"`

	// MetadataCID is the IPFS CID of the ERC-721 metadata JSON document.
	// This is the JSON that TokenURI points to.
	MetadataCID string `json:"metadata_cid,omitempty"`

	// MediaCID is the IPFS CID of the actual media/payload bytes.
	// This is what gets embedded in the NFT metadata's "image" field.
	// Same as CID, but explicitly named for the NFT flow.
	MediaCID string `json:"media_cid,omitempty"`

	// MediaGatewayURL is the HTTP gateway URL for the media CID. It is
	// transport metadata only (like MintResult.GatewayURL) and is excluded
	// from the canonical receipt bytes so gateway hostnames never affect the
	// SPHINCS+ signature.
	MediaGatewayURL string `json:"media_gateway_url,omitempty"`

	// Included for ecosystem routing / display.
	OrgCode string `json:"org_code,omitempty"` // e.g. "SPIF"

	// Timestamps
	Timestamp int64 `json:"timestamp"`

	// Embedded signer identity (so verifiers don't need trusted storage).
	MinterPublicKey   string `json:"minter_public_key"` // hex bytes
	MinterFingerprint string `json:"minter_fingerprint,omitempty"`

	// SPHINCS+ signature over canonical receipt bytes (excluding Signature field).
	SignatureHex string `json:"signature_hex"`

	// Arbitrary client-side metadata (optional)
	Metadata map[string]string `json:"metadata,omitempty"`

	// When true, receipt is intended to be verified only against an external payload.
	// Not a cryptographic flag.
	RequireExternalPayload bool `json:"require_external_payload,omitempty"`
}

// MintResult is returned by Mint().
type MintResult struct {
	Receipt *MintReceipt
	// TokenID is set by SIP-721 contract mints (0 for pure receipt mints).
	TokenID uint64 `json:"token_id,omitempty"`
	// ContractAddress is the SIP-721 collection that allocated TokenID.
	ContractAddress string `json:"contract_address,omitempty"`
	// Elapsed allows GUI to show progress if desired.
	Elapsed time.Duration
}

// NFTMetadata is the ERC-721 compatible metadata JSON document.
// When minting an NFT, this JSON is uploaded to IPFS and its CID becomes
// the tokenURI — exactly like Ethereum ERC-721 metadata standard.
//
// On Ethereum:
//
//	tokenURI → ipfs://<metadataCID>/metadata.json
//	metadata.json.image → ipfs://<mediaCID>
//
// On Sphinx:
//
//	TokenURI  → ipfs://<metadataCID>  (points to this JSON)
//	MediaCID  → ipfs://<mediaCID>     (points to actual payload/media)
type NFTMetadata struct {
	// ERC-721 standard fields
	Name         string `json:"name"`                    // NFT name/title
	Description  string `json:"description"`             // NFT description
	Image        string `json:"image"`                   // ipfs://<mediaCID> — the actual media
	AnimationURL string `json:"animation_url,omitempty"` // For video/audio NFTs

	// External link back to the minter's page
	ExternalURL string `json:"external_url,omitempty"`

	// ERC-721 attributes (displayed by marketplaces)
	Attributes []NFTAttribute `json:"attributes,omitempty"`

	// Sphinx-specific extensions (not part of ERC-721, but useful)
	MintID          string `json:"mint_id,omitempty"`           // Deterministic mint ID
	MinterPublicKey string `json:"minter_public_key,omitempty"` // Quantum-safe identity
	OrgCode         string `json:"org_code,omitempty"`          // e.g. "SPIF"
	Subject         string `json:"subject,omitempty"`           // Asset identifier
	BlockHeight     uint64 `json:"block_height,omitempty"`      // Chain height at mint
}

// NFTAttribute is a single ERC-721 attribute trait.
type NFTAttribute struct {
	TraitType   string      `json:"trait_type"`
	Value       interface{} `json:"value"`
	DisplayType string      `json:"display_type,omitempty"`
}
