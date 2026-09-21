// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/core"
)

// AnchorTag is re-exported from core (where the node's transaction-policy
// validator lives): the node's ValidateTransactionPolicy verifies anchors
// through core.IsMintAnchor / core.ValidateAnchorData, so the wallet and
// the node must share one struct definition.
type AnchorTag = core.AnchorTag

const AnchorTagType = core.AnchorTagType

// ReceiptCommitmentHash hashes the FULL signed receipt (SignatureHex
// included) with the protocol Sphinx hash — NOT SHA3-256 — so the on-chain
// commitment binds to one specific signed artifact in the same hash family
// the node verifies (core.ValidateAnchorData) and the SVM opcodes use.
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
	return common.SpxHash(data), nil
}

// validateSIP721AnchorFields enforces the all-or-nothing SIP-721 binding:
// token_id / token_uri / contract must be set together or all be empty, and a
// token_uri must use the ipfs:// scheme. Kept in sync with
// core.ValidateAnchorData so the wallet never builds an anchor the node would
// reject (partial bindings, tokenURI-less mint).
func validateSIP721AnchorFields(tokenID uint64, tokenURI, contract string) error {
	fields := 0
	if tokenID != 0 {
		fields++
	}
	if strings.TrimSpace(tokenURI) != "" {
		fields++
	}
	if strings.TrimSpace(contract) != "" {
		fields++
	}
	if fields != 0 && fields != 3 {
		return errors.New("SIP-721 anchor fields must be set together: token_id, token_uri, contract")
	}
	if strings.TrimSpace(tokenURI) != "" && !strings.HasPrefix(strings.TrimSpace(tokenURI), "ipfs://") {
		return fmt.Errorf("SIP-721 token_uri must be ipfs://<metadataCID>, got %q", tokenURI)
	}
	return nil
}

// spifAnchorAddress renders a SPIF address in the canonical grouped display
// form ("SPIF F6F6 66A0 …") for anchor output. Anchors are human-readable
// provenance artifacts (the anchor_<mintid>.json sidecar and the on-chain
// ReturnData) — every address in them must look like every other SPIF address
// on the protocol, not a bare 40/64-char hex blob. The receipt may carry any
// accepted rendering (raw hex from the mint broadcast path, the grouped form
// from a collection contract address); NormalizeSPIFAddress inside
// FormatSPIFAddress collapses them all into one grouped uppercase form.
// Non-address values (empty, system ids) pass through unchanged.
func spifAnchorAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if formatted, err := common.FormatSPIFAddress(addr); err == nil {
		return formatted
	}
	return addr
}

// sameSPIFAddress compares two address renderings for identity. Both sides are
// collapsed through common.NormalizeSPIFAddress, which accepts the grouped
// display form, bare raw hex, mixed case, and the legacy "SPIF"+lowercase form
// alike; when either side is not a parseable SPIF address it falls back to a
// trimmed, case-insensitive comparison so empty/system values still behave.
func sameSPIFAddress(a, b string) bool {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return strings.TrimSpace(a) == strings.TrimSpace(b)
	}
	rawA, errA := common.NormalizeSPIFAddress(a)
	rawB, errB := common.NormalizeSPIFAddress(b)
	if errA == nil && errB == nil {
		return rawA == rawB
	}
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// BuildAnchorData produces the bytes to place in a transaction's ReturnData.
// The tag includes the CID plus its sha256 commitment (cid_hash_hex) so the
// node can verify the anchor actually commits to the pinned content — see
// core.ValidateAnchorData, which every node runs on this ReturnData.
//
// The receipt's SIP-721 binding (TokenID/TokenURI/ContractAddress) travels in
// the tag when set, so a contract mint is verifiable as one atomic unit:
// the same ReturnData commits to both the media CID and the
// tokenURI[tokenId] pointer stored in contract storage.
func BuildAnchorData(r *MintReceipt) ([]byte, error) {
	h, err := ReceiptCommitmentHash(r)
	if err != nil {
		return nil, err
	}
	if err := validateSIP721AnchorFields(r.TokenID, r.TokenURI, r.ContractAddress); err != nil {
		return nil, err
	}
	tag := AnchorTag{
		Type:             AnchorTagType,
		MintID:           r.MintID,
		Subject:          r.Subject,
		CID:              r.CID,
		MinterPublicKey:  r.MinterPublicKey,
		ReceiptHash:      hex.EncodeToString(h),
		CIDHashHex:       core.CIDHashHexFor(r.CID),
		TokenID:          r.TokenID,
		TokenURI:         r.TokenURI,
		Contract:         spifAnchorAddress(r.ContractAddress),
		RoyaltyBPS:       r.RoyaltyBPS,
		UsageFeeNSPX:     r.UsageFeeNSPX,
		RoyaltyRecipient: spifAnchorAddress(r.RoyaltyRecipient),
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

	// SIP-721 binding: when the receipt carries a contract mint, the anchor
	// must carry the identical tokenURI[tokenId] pointer.
	if r.TokenID != 0 || r.TokenURI != "" || r.ContractAddress != "" {
		if tag.TokenID != r.TokenID {
			return false, errors.New("token_id mismatch between anchor and receipt")
		}
		if tag.TokenURI != r.TokenURI {
			return false, errors.New("token_uri mismatch between anchor and receipt")
		}
		if !sameSPIFAddress(tag.Contract, r.ContractAddress) {
			return false, errors.New("contract mismatch between anchor and receipt")
		}
	}
	if err := verifyAnchorTerms(r, &tag); err != nil {
		return false, err
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
// The disk sidecar (anchor_<mintid>.json) carries the same CID commitment as
// the on-chain tag produced by BuildAnchorData, so verifiers can re-check it
// with core.ValidateAnchorData.
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
	if err := validateSIP721AnchorFields(r.TokenID, r.TokenURI, r.ContractAddress); err != nil {
		return nil, err
	}
	return &AnchorTag{
		Type:             AnchorTagType,
		MintID:           r.MintID,
		Subject:          r.Subject,
		CID:              r.CID,
		MinterPublicKey:  r.MinterPublicKey,
		ReceiptHash:      hex.EncodeToString(h),
		CIDHashHex:       core.CIDHashHexFor(r.CID),
		TokenID:          r.TokenID,
		TokenURI:         r.TokenURI,
		Contract:         spifAnchorAddress(r.ContractAddress),
		RoyaltyBPS:       r.RoyaltyBPS,
		UsageFeeNSPX:     r.UsageFeeNSPX,
		RoyaltyRecipient: spifAnchorAddress(r.RoyaltyRecipient),
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

	// SIP-721 binding: same check as VerifyAnchor for already-deserialized tags.
	if r.TokenID != 0 || r.TokenURI != "" || r.ContractAddress != "" {
		if tag.TokenID != r.TokenID {
			return false, errors.New("token_id mismatch between anchor and receipt")
		}
		if tag.TokenURI != r.TokenURI {
			return false, errors.New("token_uri mismatch between anchor and receipt")
		}
		if !sameSPIFAddress(tag.Contract, r.ContractAddress) {
			return false, errors.New("contract mismatch between anchor and receipt")
		}
	}
	if err := verifyAnchorTerms(r, tag); err != nil {
		return false, err
	}

	return true, nil
}

// verifyAnchorTerms checks that the anchor's embedded economics match the
// receipt exactly. The terms are part of the receipt's on-chain commitment
// identity — a tampered royalty_bps / usage_fee / royalty_recipient must fail
// verification the same way a swapped CID or token_id does.
func verifyAnchorTerms(r *MintReceipt, tag *AnchorTag) error {
	if tag.RoyaltyBPS != r.RoyaltyBPS {
		return fmt.Errorf("royalty_bps mismatch between anchor and receipt: anchor=%d receipt=%d", tag.RoyaltyBPS, r.RoyaltyBPS)
	}
	if strings.TrimSpace(tag.UsageFeeNSPX) != strings.TrimSpace(r.UsageFeeNSPX) {
		return errors.New("usage_fee_nspx mismatch between anchor and receipt")
	}
	if !sameSPIFAddress(tag.RoyaltyRecipient, r.RoyaltyRecipient) {
		return errors.New("royalty_recipient mismatch between anchor and receipt")
	}
	return nil
}

// VerifyAnchoredReceiptWithTag verifies signature, payload, and anchor tag.
func VerifyAnchoredReceiptWithTag(r *MintReceipt, payload []byte, tag *AnchorTag) (bool, error) {
	if ok, err := Verify(r, payload); !ok {
		return false, fmt.Errorf("receipt signature invalid: %w", err)
	}
	return VerifyAnchorWithTag(r, tag)
}
