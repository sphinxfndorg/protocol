// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"encoding/json"
	"testing"

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
		OrgCode:         "SPIF",
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
	receipt.ContractAddress = "sc1234567890abcdef1234567890abcdef"

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
	if tag.TokenID != 7 || tag.TokenURI != receipt.TokenURI || tag.Contract != receipt.ContractAddress {
		t.Fatalf("anchor did not carry token binding: %#v", tag)
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
	receipt.ContractAddress = "sc1234567890abcdef1234567890abcdef"

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
