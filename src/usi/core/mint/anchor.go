// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// AnchorTag is the small payload placed into a Sphinx transaction's
// ReturnData field to anchor a MintReceipt on-chain. It carries no
// signature or payload bytes — only a commitment hash — so anchoring
// stays cheap regardless of what was signed.
//
// The CID and MinterPublicKey fields are included so that:
//   - anyone can fetch the content from IPFS using the CID
//   - verifiers can confirm the anchoring transaction sender matches minter
type AnchorTag struct {
	Type            string `json:"type"` // always "mint_anchor"
	MintID          string `json:"mint_id"`
	Subject         string `json:"subject"`
	CID             string `json:"cid,omitempty"`               // IPFS content hash
	MinterPublicKey string `json:"minter_public_key,omitempty"` // hex-encoded
	ReceiptHash     string `json:"receipt_hash"`                // hex(SHA3-256(full signed receipt))
}

const AnchorTagType = "mint_anchor"

// ReceiptCommitmentHash hashes the FULL signed receipt (SignatureHex
// included), so the on-chain commitment binds to one specific signed
// artifact rather than just its pre-signature content.
//
// Deliberately independent of canonicalReceiptBytesV2 — if that
// canonicalization ever changes/gets fixed, previously anchored hashes
// don't silently break.
func ReceiptCommitmentHash(r *MintReceipt) ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil receipt")
	}
	if r.SignatureHex == "" {
		return nil, errors.New("receipt is unsigned; sign before anchoring")
	}
	data, err := jsonMarshalReceipt(r) // encoding/json sorts map keys -> deterministic
	if err != nil {
		return nil, fmt.Errorf("marshal receipt: %w", err)
	}
	sum := sha3.Sum256(data)
	return sum[:], nil
}

// BuildAnchorData produces the bytes to place in a transaction's ReturnData.
func BuildAnchorData(r *MintReceipt) ([]byte, error) {
	h, err := ReceiptCommitmentHash(r)
	if err != nil {
		return nil, err
	}
	tag := AnchorTag{
		Type:        AnchorTagType,
		MintID:      r.MintID,
		Subject:     r.Subject,
		ReceiptHash: hex.EncodeToString(h),
	}
	out, err := json.Marshal(tag)
	if err != nil {
		return nil, fmt.Errorf("marshal anchor tag: %w", err)
	}
	return out, nil
}

// VerifyAnchor checks a receipt matches an on-chain anchor tag, without
// touching the signature itself.
func VerifyAnchor(r *MintReceipt, anchorData []byte) (bool, error) {
	var tag AnchorTag
	if err := json.Unmarshal(anchorData, &tag); err != nil {
		return false, fmt.Errorf("decode anchor tag: %w", err)
	}
	if tag.Type != AnchorTagType {
		return false, fmt.Errorf("unexpected anchor type: %q", tag.Type)
	}
	h, err := ReceiptCommitmentHash(r)
	if err != nil {
		return false, err
	}
	if hex.EncodeToString(h) != tag.ReceiptHash {
		return false, errors.New("receipt does not match on-chain commitment")
	}
	if tag.MintID != r.MintID {
		return false, errors.New("mint id mismatch")
	}
	return true, nil
}

// VerifyAnchoredReceipt does full verification: signature + payload hash
// (Verify) AND on-chain commitment binding (VerifyAnchor).
func VerifyAnchoredReceipt(r *MintReceipt, payload []byte, anchorData []byte) (bool, error) {
	if ok, err := Verify(r, payload); !ok {
		return false, fmt.Errorf("receipt signature invalid: %w", err)
	}
	return VerifyAnchor(r, anchorData)
}

// BuildAnchorTag returns the AnchorTag struct for a receipt without marshaling.
// BuildAnchorTag returns the AnchorTag struct for a receipt without marshaling.
func BuildAnchorTag(r *MintReceipt) (*AnchorTag, error) {
	if r == nil {
		return nil, errors.New("nil receipt")
	}
	if r.SignatureHex == "" {
		return nil, errors.New("receipt is unsigned; sign before anchoring")
	}
	h, err := ReceiptCommitmentHash(r)
	if err != nil {
		return nil, err
	}
	return &AnchorTag{
		Type:        AnchorTagType,
		MintID:      r.MintID,
		Subject:     r.Subject,
		ReceiptHash: hex.EncodeToString(h),
	}, nil
}

// SerializeAnchorTag returns JSON bytes of the AnchorTag.
func SerializeAnchorTag(tag *AnchorTag) ([]byte, error) {
	if tag == nil {
		return nil, errors.New("nil tag")
	}
	return json.Marshal(tag)
}

// DeserializeAnchorTag parses JSON bytes into an AnchorTag.
func DeserializeAnchorTag(data []byte) (*AnchorTag, error) {
	var tag AnchorTag
	if err := json.Unmarshal(data, &tag); err != nil {
		return nil, err
	}
	if tag.Type != AnchorTagType {
		return nil, fmt.Errorf("unexpected anchor type: %q", tag.Type)
	}
	return &tag, nil
}

// VerifyAnchorWithTag checks a receipt against an already-deserialized AnchorTag.
// Additionally verifies that the CID matches if the anchor includes one.
func VerifyAnchorWithTag(r *MintReceipt, tag *AnchorTag) (bool, error) {
	if r == nil || tag == nil {
		return false, errors.New("nil arguments")
	}
	if tag.Type != AnchorTagType {
		return false, fmt.Errorf("unexpected anchor type: %q", tag.Type)
	}
	h, err := ReceiptCommitmentHash(r)
	if err != nil {
		return false, err
	}
	if hex.EncodeToString(h) != tag.ReceiptHash {
		return false, errors.New("receipt does not match on-chain commitment")
	}
	if tag.MintID != r.MintID {
		return false, errors.New("mint id mismatch")
	}

	// If the anchor includes a CID, verify it matches the receipt
	if tag.CID != "" && tag.CID != r.CID {
		return false, errors.New("CID mismatch between anchor and receipt")
	}

	// If the anchor includes a MinterPublicKey, verify it matches the receipt
	if tag.MinterPublicKey != "" && tag.MinterPublicKey != r.MinterPublicKey {
		return false, errors.New("minter public key mismatch between anchor and receipt")
	}

	return true, nil
}

// VerifyAnchoredReceiptWithTag verifies signature, payload, and anchor tag.
func VerifyAnchoredReceiptWithTag(r *MintReceipt, payload []byte, tag *AnchorTag) (bool, error) {
	if ok, err := Verify(r, payload); !ok {
		return false, fmt.Errorf("receipt signature invalid: %w", err)
	}
	return VerifyAnchorWithTag(r, tag)
}
