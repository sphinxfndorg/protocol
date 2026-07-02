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
	// Elapsed allows GUI to show progress if desired.
	Elapsed time.Duration
}
