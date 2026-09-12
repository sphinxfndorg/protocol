// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/mint_anchor.go
//
// On-chain mint-anchor commitment. The node's transaction-policy validator
// (ValidateTransactionPolicy in helper.go) verifies anchors here, and the
// wallet (src/usi/core/mint's anchor builders) shares the same primitives
// so wallet-emitted anchors and node-side verification never drift.
package core

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sphinxfndorg/protocol/src/common"
)

// AnchorTag is the small payload placed into a Sphinx transaction's
// ReturnData field to anchor a MintReceipt on-chain. It carries no signature
// and no payload bytes — only commitment hashes — so anchoring stays cheap
// regardless of what was signed.
//
//   - CID + CIDHashHex bind the on-chain anchor to the exact IPFS object:
//     CIDHashHex = hex(sha256(CID string bytes)), byte-for-byte matching
//     storage.CIDHash so the transaction anchor and the node-side storage
//     artifact agree on the same commitment.
//   - ReceiptHash = hex(SHA3-256(full signed receipt)), the commitment
//     verifiers re-derive off-chain (usi/core/mint.VerifyAnchoredReceipt)
//     against the original signed receipt.
//   - MinterPublicKey lets verifiers confirm the anchoring transaction's
//     sender matches the receipt's minter without any trusted lookup.
type AnchorTag struct {
	Type            string `json:"type"` // always "mint_anchor"
	MintID          string `json:"mint_id"`
	Subject         string `json:"subject"`
	CID             string `json:"cid,omitempty"`               // IPFS content hash
	MinterPublicKey string `json:"minter_public_key,omitempty"` // hex-encoded
	ReceiptHash     string `json:"receipt_hash"`                // hex(SHA3-256(full signed receipt))
	CIDHashHex      string `json:"cid_hash_hex,omitempty"`      // hex(sha256(CID)) — the on-chain CID commitment
	TokenID         uint64 `json:"token_id,omitempty"`          // SIP-721 tokenId counter value (0 = legacy receipt anchor)
	TokenURI        string `json:"token_uri,omitempty"`         // ipfs://<metadataCID> bound to tokenID
	Contract        string `json:"contract,omitempty"`          // SIP-721 collection (sc...) owning tokenURI[tokenId]
}

// AnchorTagType is the type discriminator for mint-anchor tags.
const AnchorTagType = "mint_anchor"

// CIDHashHexFor returns hex(SphinxHash(cid string bytes)). Single source of
// truth for the on-chain CID commitment — matches storage.CIDHash so wallet
// anchors and node storage artifacts are computed identically.
//
// Both use common.SpxHash (NOT sha256/sha3): the SVM signature path already
// standardised on SpxHash (see sphincsSigHash in kernel/opcodes), and the
// anchor CID commitment travels inside the same signed transactions, so it
// must use the same hash family to avoid opcode-verification mismatches on
// NFT mint / SPX transfer flows that carry anchors.
func CIDHashHexFor(cid string) string {
	return hex.EncodeToString(common.SpxHash([]byte(cid)))
}

// IsMintAnchor reports whether data is a serialized AnchorTag. It is a cheap
// type peek so value-transfer memos, generic OP_RETURN messages, and the
// legacy CLI anchor payload (which uses "version" instead of "type") are left
// completely untouched by node-side mint verification.
func IsMintAnchor(data []byte) bool {
	var peek struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &peek); err != nil {
		return false
	}
	return peek.Type == AnchorTagType
}

// ParseTag decodes and type-checks a serialized AnchorTag.
func ParseTag(data []byte) (*AnchorTag, error) {
	var tag AnchorTag
	if err := json.Unmarshal(data, &tag); err != nil {
		return nil, fmt.Errorf("decode anchor tag: %w", err)
	}
	if tag.Type != AnchorTagType {
		return nil, fmt.Errorf("unexpected anchor type: %q", tag.Type)
	}
	return &tag, nil
}

// ValidateAnchorData performs the node-side verification of a mint-anchor
// commitment. The anchor transaction's ReturnData is the ONLY part of a mint
// that reaches the chain, so every node enforces the commitment's internal
// consistency here — the chain verifies the commitment, not the artifact:
//
//  1. the tag is a well-formed mint_anchor,
//  2. MintID / Subject / CID are all present — an anchor without a CID pins
//     nothing and cannot be verified by anyone, so it is not accepted,
//  3. when the tag claims a CID commitment (cid_hash_hex), it must equal
//     hex(sha256(CID)) — the tag can never claim a CID it does not commit to,
//  4. SIP-721 fields are all-or-nothing: token_id/token_uri/contract must be
//     set together or all be empty. A contract anchor with zero token_id or
//     an empty tokenURI/contract pins nothing verifiable and is rejected,
//  5. ReceiptHash is a real 32-byte SHA3-256 hex value,
//  6. MinterPublicKey, when present, is valid hex.
//
// Full receipt verification (SPHINCS+ signature + payload hash re-derived
// against ReceiptHash) requires the original signed receipt and stays
// off-chain via usi/core/mint.VerifyAnchoredReceipt.
func ValidateAnchorData(data []byte) error {
	tag, err := ParseTag(data)
	if err != nil {
		return err
	}
	if tag.MintID == "" {
		return errors.New("mint anchor missing mint_id")
	}
	if tag.Subject == "" {
		return errors.New("mint anchor missing subject")
	}
	if tag.CID == "" {
		return errors.New("mint anchor missing CID — anchor pins nothing and is unverifiable")
	}
	// Transitional leniency: anchors produced before the cid_hash_hex field
	// shipped carry a bare CID. When the commitment IS claimed, its binding
	// to the CID is strictly enforced; new wallet builders always emit it.
	if tag.CIDHashHex != "" && tag.CIDHashHex != CIDHashHexFor(tag.CID) {
		return fmt.Errorf("mint anchor cid_hash_hex does not commit to cid (cid=%s, claimed=%s, derived=%s)",
			shortStr(tag.CID), shortStr(tag.CIDHashHex), shortStr(CIDHashHexFor(tag.CID)))
	}
	// SIP-721 contract anchor: either a pure legacy receipt anchor (all three
	// empty) or a full contract binding (all three set). Partial bindings are
	// rejected so an index can never point at a token with no URI or owner.
	contractFields := 0
	if tag.TokenID != 0 {
		contractFields++
	}
	if strings.TrimSpace(tag.TokenURI) != "" {
		contractFields++
	}
	if strings.TrimSpace(tag.Contract) != "" {
		contractFields++
	}
	if contractFields != 0 && contractFields != 3 {
		return errors.New("mint anchor SIP-721 fields must be set together: token_id, token_uri, contract")
	}
	if tag.TokenURI != "" && !strings.HasPrefix(strings.TrimSpace(tag.TokenURI), "ipfs://") {
		return fmt.Errorf("mint anchor token_uri must be ipfs://<metadataCID>, got %q", tag.TokenURI)
	}
	if tag.ReceiptHash == "" {
		return errors.New("mint anchor missing receipt_hash")
	}
	receiptHash, err := hex.DecodeString(tag.ReceiptHash)
	if err != nil {
		return fmt.Errorf("mint anchor receipt_hash is not valid hex: %w", err)
	}
	if len(receiptHash) != 32 {
		return fmt.Errorf("mint anchor receipt_hash must be 32 bytes, got %d", len(receiptHash))
	}
	if tag.MinterPublicKey != "" {
		if _, err := hex.DecodeString(tag.MinterPublicKey); err != nil {
			return fmt.Errorf("mint anchor minter_public_key is not valid hex: %w", err)
		}
	}
	return nil
}

func shortStr(s string) string {
	if len(s) > 12 {
		return s[:12] + "..."
	}
	return s
}
