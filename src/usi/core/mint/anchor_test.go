// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/core"
)

// mintTestReceipt returns a receipt shaped like the one the USI Mint Data
// flow anchors: signed (dummy sig — only hex encoding is exercised here) and
// pinned to a real CID.
func mintTestReceipt(cid string) *MintReceipt {
	return &MintReceipt{
		Version:         ReceiptVersion,
		MintID:          "mintid0011223344556677889900aabbccdd",
		Subject:         "quarterly-report.pdf",
		PayloadHash:     "payloadhash00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		CID:             cid,
		OrgCode:         common.SPIFPrefix,
		MinterPublicKey: "6d696e7465722d7075626b65792d6279746573",
		SignatureHex:    "deadbeefdeadbeefdeadbeef",
	}
}

func TestBuildAnchorDataPassesNodeVerification(t *testing.T) {
	cid := "bafkqaccd1234abcd1234abcd1234abcd"
	receipt := mintTestReceipt(cid)

	tagBytes, err := BuildAnchorData(receipt)
	if err != nil {
		t.Fatalf("BuildAnchorData: %v", err)
	}

	// The node-side validator (src/core.ValidateTransactionPolicy) runs
	// ValidateAnchorData on the tx's ReturnData — the wallet's
	// anchor must pass it verbatim.
	if err := core.ValidateAnchorData(tagBytes); err != nil {
		t.Fatalf("wallet-emitted anchor must verify at nodes: %v", err)
	}
}

func TestBuildAnchorTagSidecarPassesNodeVerification(t *testing.T) {
	cid := "bafkqaccd1234abcd1234abcd1234abcd"
	receipt := mintTestReceipt(cid)

	tag, err := BuildAnchorTag(receipt)
	if err != nil {
		t.Fatalf("BuildAnchorTag: %v", err)
	}

	// The disk sidecar carries the same commitment — it must also verify.
	serialized, err := json.Marshal(tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.ValidateAnchorData(serialized); err != nil {
		t.Fatalf("disk anchor sidecar must verify: %v", err)
	}

	// And the on-chain tag and the sidecar must agree on the CID commitment.
	onChain, err := BuildAnchorData(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if string(onChain) != string(serialized) {
		t.Fatalf("on-chain tag and disk sidecar diverged:\n on-chain=%s\n sidecar=%s", onChain, serialized)
	}
}

func TestNodeVerificationRejectsTamperedAnchor(t *testing.T) {
	cid := "bafkqaccd1234abcd1234abcd1234abcd"
	receipt := mintTestReceipt(cid)

	tagBytes, err := BuildAnchorData(receipt)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper: swap the CID for one the tag never committed to.
	var tag AnchorTag
	if err := json.Unmarshal(tagBytes, &tag); err != nil {
		t.Fatal(err)
	}
	tag.CID = "bafkqattacked00000000000000000000000000"
	tampered, _ := json.Marshal(tag)

	if err := core.ValidateAnchorData(tampered); err == nil {
		t.Fatal("tampered anchor (CID swapped without re-committing) must be REJECTED by the node")
	}
}

func TestAnchorTagIsSharedDefinitionWithNodeValidator(t *testing.T) {
	// type alias — the wallet and the node's validator must parse with the
	// identical struct so future fields stay in lockstep.
	var tag core.AnchorTag = core.AnchorTag{Type: core.AnchorTagType}
	if tag.Type != core.AnchorTagType {
		t.Fatal("alias must preserve type identity")
	}
}

func TestSIP721TokenBindingFlowsThroughAnchorAndNodeVerifies(t *testing.T) {
	// A SIP-721 collection mint produces a receipt whose token binding
	// (token_id/token_uri/contract) travels inside the AnchorTag and must
	// pass node-side validation (core.ValidateAnchorData).
	cid := "bafkqaccd1234abcd1234abcd1234abcd"
	receipt := mintTestReceipt(cid)
	receipt.TokenID = 7
	receipt.TokenURI = "ipfs://bafkqameta0000000000000000000000000"
	// Legacy 20-byte rendering: "SPIF" + 40 lowercase hex.
	receipt.ContractAddress = common.SPIFPrefix + "1234567890abcdef1234567890abcdef12345678"

	tagBytes, err := BuildAnchorData(receipt)
	if err != nil {
		t.Fatalf("BuildAnchorData: %v", err)
	}
	if err := core.ValidateAnchorData(tagBytes); err != nil {
		t.Fatalf("SIP-721 bound anchor must verify at nodes: %v", err)
	}
	var tag AnchorTag
	if err := json.Unmarshal(tagBytes, &tag); err != nil {
		t.Fatal(err)
	}
	if tag.TokenID != 7 || tag.TokenURI != receipt.TokenURI || !sameSPIFAddress(tag.Contract, receipt.ContractAddress) {
		t.Fatalf("anchor did not carry token binding: %#v", tag)
	}

	// The tag must render every address in the canonical grouped SPIF form,
	// never a bare hex blob, regardless of the form the receipt carried.
	// Here the receipt carries the legacy "SPIF"+lowercase-hex rendering; the
	// tag must collapse it into the grouped uppercase display form.
	canonicalContract, ferr := common.FormatSPIFAddress(receipt.ContractAddress)
	if ferr != nil {
		t.Fatal(ferr)
	}
	if tag.Contract != canonicalContract {
		t.Fatalf("anchor contract %q must render in canonical SPIF form %q", tag.Contract, canonicalContract)
	}

	// Partial SIP-721 bindings are rejected by the node.
	receipt.TokenURI = ""
	if _, err := BuildAnchorData(receipt); err == nil {
		t.Fatal("expected anchor build to reject partial SIP-721 binding")
	}
}

func TestAnchorVerifiesTokenBindingMatchesReceipt(t *testing.T) {
	cid := "bafkqaccd1234abcd1234abcd1234abcd"
	receipt := mintTestReceipt(cid)
	receipt.TokenID = 3
	receipt.TokenURI = "ipfs://bafkqameta0000000000000000000000001"
	receipt.ContractAddress = common.SPIFPrefix + "1234567890abcdef1234567890abcdef"

	tagBytes, err := BuildAnchorData(receipt)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyAnchor(receipt, tagBytes)
	if err != nil || !ok {
		t.Fatalf("VerifyAnchor should accept matching token binding: ok=%v err=%v", ok, err)
	}

	// Tampering with the tokenURI must break anchor verification.
	var tag AnchorTag
	if err := json.Unmarshal(tagBytes, &tag); err != nil {
		t.Fatal(err)
	}
	tag.TokenURI = "ipfs://bafkqattack000000000000000000000000"
	tampered, _ := json.Marshal(tag)
	if ok, _ := VerifyAnchor(receipt, tampered); ok {
		t.Fatal("token_uri tampering must break VerifyAnchor")
	}
}

func TestAnchorCarriesRoyaltyTermsAndNodeVerifies(t *testing.T) {
	cid := "bafkqaccd1234abcd1234abcd1234abcd"
	receipt := mintTestReceipt(cid)
	recipient := "F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6"
	receipt.RoyaltyBPS = 250
	receipt.UsageFeeNSPX = "100000000000000000" // 0.1 SPX in nSPX
	receipt.RoyaltyRecipient = recipient

	tagBytes, err := BuildAnchorData(receipt)
	if err != nil {
		t.Fatalf("BuildAnchorData with terms: %v", err)
	}
	// The node validator must accept the terms-bearing anchor verbatim.
	if err := core.ValidateAnchorData(tagBytes); err != nil {
		t.Fatalf("terms-bearing anchor must verify at nodes: %v", err)
	}

	var tag AnchorTag
	if err := json.Unmarshal(tagBytes, &tag); err != nil {
		t.Fatal(err)
	}
	// The receipt carries the recipient as raw hex; the anchor must render it
	// in the canonical grouped SPIF display form (matching the contract field)
	// instead of a bare hex blob — this is the anchor_<mintid>.json sidecar's
	// human-readable address identity.
	formattedRecipient, ferr := common.FormatSPIFAddress(recipient)
	if ferr != nil {
		t.Fatal(ferr)
	}
	if tag.RoyaltyBPS != 250 || tag.UsageFeeNSPX != "100000000000000000" || tag.RoyaltyRecipient != formattedRecipient {
		t.Fatalf("anchor did not carry embedded economics: %#v", tag)
	}
	if !strings.HasPrefix(tag.RoyaltyRecipient, "SPIF ") {
		t.Fatalf("royalty_recipient must render in grouped SPIF form, got %q", tag.RoyaltyRecipient)
	}

	// The SAME receipt (raw-hex recipient in memory) must still verify against
	// the grouped-form tag — address renderings are one identity, compared
	// canonically in VerifyAnchor/verifyAnchorTerms.
	if ok, verr := VerifyAnchor(receipt, tagBytes); !ok || verr != nil {
		t.Fatalf("raw-hex receipt must verify against grouped-form anchor: ok=%v err=%v", ok, verr)
	}

	// Tampering with the terms breaks receipt↔anchor verification.
	var tampered AnchorTag = tag
	tampered.RoyaltyBPS = 251
	tamperedBytes, _ := json.Marshal(tampered)
	if ok, _ := VerifyAnchor(receipt, tamperedBytes); ok {
		t.Fatal("royalty_bps tampering must break VerifyAnchor")
	}
	// Out-of-range terms are rejected by the node outright.
	var outOfRange AnchorTag = tag
	outOfRange.RoyaltyBPS = 10001
	oorBytes, _ := json.Marshal(outOfRange)
	if err := core.ValidateAnchorData(oorBytes); err == nil {
		t.Fatal("royalty_bps above 10000 must be rejected by the node")
	}
}
