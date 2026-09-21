// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/http/explorer_test.go
package http

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/sphinxfndorg/protocol/src/core"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// newExplorerTestBlock builds the minimum block formatBlockDetail dereferences,
// so the assertions below are about the payload rather than about block
// construction. Every *big.Int the formatters call .String() on must be set.
func newExplorerTestBlock(txs ...*types.Transaction) *types.Block {
	return &types.Block{
		Header: &types.BlockHeader{
			Version:     1,
			Block:       42,
			Height:      42,
			Timestamp:   time.Now().Unix(),
			Hash:        []byte("block-hash"),
			Difficulty:  big.NewInt(1),
			GasLimit:    big.NewInt(1_000_000),
			GasUsed:     big.NewInt(21_000),
			ChainWeight: big.NewInt(7),
			ProposerID:  "validator-1",
		},
		Body: types.BlockBody{TxsList: txs},
	}
}

// TestFormatBlockDetailExposesReturnData locks in the field the anchor audit
// depends on.
//
// ReturnData is the ONLY on-chain record of what a mint pinned: the AnchorTag
// lives there, and its CID is what distinguishes a real IPFS pin from a
// local-only (spxhash-) commitment. Before this field was exposed, block detail
// listed txids but not the payload that classifies them, so answering "how many
// anchors recorded a local-only CID?" meant fetching every transaction
// individually — an O(blocks + txs) walk instead of O(blocks).
//
// The tag is marshalled with the REAL core.AnchorTag, so this proves the audit
// can parse exactly what the node writes, not a hand-rolled approximation.
func TestFormatBlockDetailExposesReturnData(t *testing.T) {
	const localOnlyCID = "spxhash-723a7f8b07b5907ccd8f7b81fee77c299a143756ae83d715482da722012a0299"

	tag := core.AnchorTag{
		Type:        core.AnchorTagType,
		MintID:      "554f471215ed560292c81f13f6cb3b56be373b906bcc06a843997922be07dbb2",
		Subject:     "freedom.pdf",
		CID:         localOnlyCID,
		CIDHashHex:  core.CIDHashHexFor(localOnlyCID),
		ReceiptHash: strings.Repeat("ab", 32),
	}
	anchorJSON, err := json.Marshal(tag)
	if err != nil {
		t.Fatalf("marshal anchor tag: %v", err)
	}

	anchorTx := &types.Transaction{
		ID: "anchor-tx", Sender: "SPIF A", Receiver: "SPIF A",
		Amount: big.NewInt(0), Nonce: 1, Timestamp: 1000, ReturnData: anchorJSON,
	}
	plainTx := &types.Transaction{
		ID: "plain-tx", Sender: "SPIF A", Receiver: "SPIF B",
		Amount: big.NewInt(5), Nonce: 2, Timestamp: 1001,
	}

	detail := formatBlockDetail(newExplorerTestBlock(anchorTx, plainTx, nil))

	// gin.H is a distinct named type, so assert it exactly rather than
	// converting through map[string]any.
	txs, ok := detail["transactions"].([]gin.H)
	if !ok {
		t.Fatalf("transactions missing or unexpected type: %T", detail["transactions"])
	}
	// The nil entry must be skipped, not rendered as an empty row.
	if len(txs) != 2 {
		t.Fatalf("expected 2 transactions (nil skipped), got %d", len(txs))
	}
	anchorRow, plainRow := txs[0], txs[1]

	// ── The audit path: hex-decode the payload back to the anchor tag ──
	if got := anchorRow["has_return_data"]; got != true {
		t.Fatalf("anchor tx must report has_return_data=true, got %v", got)
	}
	rawHex, ok := anchorRow["return_data"].(string)
	if !ok || rawHex == "" {
		t.Fatalf("anchor tx must expose return_data as a hex string, got %T", anchorRow["return_data"])
	}
	decoded, derr := hex.DecodeString(rawHex)
	if derr != nil {
		t.Fatalf("return_data must be valid hex: %v", derr)
	}
	var roundTripped core.AnchorTag
	if uerr := json.Unmarshal(decoded, &roundTripped); uerr != nil {
		t.Fatalf("the exposed payload must parse as an AnchorTag: %v", uerr)
	}
	if roundTripped.CID != localOnlyCID {
		t.Fatalf("CID must survive the round-trip verbatim: got %q", roundTripped.CID)
	}
	if !strings.HasPrefix(roundTripped.CID, "spxhash-") {
		t.Fatal("a local-only commitment must remain identifiable through the API")
	}

	// ── Additivity: the pre-existing fields must still be there ──
	for _, key := range []string{"txid", "sender", "receiver", "amount_spx", "nonce", "timestamp"} {
		if _, present := anchorRow[key]; !present {
			t.Fatalf("existing consumer field %q disappeared from the tx summary", key)
		}
	}

	// ── A transaction with no payload must not fabricate one ──
	if got := plainRow["has_return_data"]; got != false {
		t.Fatalf("plain tx must report has_return_data=false, got %v", got)
	}
	if _, present := plainRow["return_data"]; present {
		t.Fatal("an empty payload must be omitted, not emitted as an empty string")
	}
}
