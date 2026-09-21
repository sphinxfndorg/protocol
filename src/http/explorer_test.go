// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/http/explorer_test.go
package http

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
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

	detail := formatBlockDetail(nil, newExplorerTestBlock(anchorTx, plainTx, nil))

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

// TestConfirmationsForHeight pins the genesis-inclusive convention: a block's
// confirmation count is itself plus every block built on top of it, i.e.
// blockCount - height. Getting this off by one understates finality by a block,
// which is exactly the number the explorer badge renders.
func TestConfirmationsForHeight(t *testing.T) {
	cases := []struct {
		name       string
		blockCount uint64
		height     uint64
		want       uint64
	}{
		{"empty chain has nothing to confirm", 0, 0, 0},
		{"genesis of a one-block chain is confirmed once", 1, 0, 1},
		{"genesis carries the whole chain depth", 5, 0, 5},
		{"tip block is confirmed once", 5, 4, 1},
		{"height past the tip is not confirmable", 5, 5, 0},
	}
	for _, tc := range cases {
		if got := confirmationsForHeight(tc.blockCount, tc.height); got != tc.want {
			t.Errorf("%s: confirmationsForHeight(%d, %d) = %d, want %d",
				tc.name, tc.blockCount, tc.height, got, tc.want)
		}
	}
}

// TestFormatBlockDetailExposesFeeAndAuthFields locks in the per-transaction
// economic fields the explorer's "coins inside the block" view needs. Before
// these existed, a block listed who sent what but not what it cost, so fee
// totals could only be reconstructed by fetching every transaction by txid.
func TestFormatBlockDetailExposesFeeAndAuthFields(t *testing.T) {
	// 21,000 gas at 2 gSPX/gas = 42e9 nSPX = 4.2e-8 SPX.
	tx := &types.Transaction{
		ID: "paid-tx", Sender: "SPIF A", Receiver: "SPIF B",
		Amount:   big.NewInt(1_000_000_000_000_000_000), // 1 SPX
		GasLimit: big.NewInt(21_000),
		GasPrice: big.NewInt(2_000_000_000),
		Nonce:    7, Timestamp: 1_700_000_000,
	}

	detail := formatBlockDetail(nil, newExplorerTestBlock(tx))
	txs, ok := detail["transactions"].([]gin.H)
	if !ok || len(txs) != 1 {
		t.Fatalf("expected exactly one transaction row, got %T %d", detail["transactions"], len(txs))
	}
	row := txs[0]

	if got := row["amount_spx"]; got != "1.000000000000000000" {
		t.Errorf("amount_spx = %v, want 1.000000000000000000", got)
	}
	if got := row["fee_nspx"]; got != "42000000000000" {
		t.Errorf("fee_nspx = %v, want 42000000000000", got)
	}
	// The fee is rendered from the same nSPX figure, so the two must agree.
	if got := row["fee_spx"]; got != "0.000042000000000000" {
		t.Errorf("fee_spx = %v, want 0.000042000000000000", got)
	}
	if got := row["nonce"]; got != uint64(7) {
		t.Errorf("nonce = %v, want 7", got)
	}
	// A plain user transaction is neither a system mint nor a full SPHINCS+
	// auth bundle, and both flags must be explicit rather than absent.
	if got := row["is_system_tx"]; got != false {
		t.Errorf("is_system_tx = %v, want false", got)
	}
	if got := row["has_full_auth"]; got != false {
		t.Errorf("has_full_auth = %v, want false", got)
	}
}

// TestStampBlockConfirmationsStampsRows proves confirmation depth reaches both
// the block payload and every transaction row inside it, and that a block
// payload without a height is left untouched rather than stamped with a
// fabricated depth.
func TestStampBlockConfirmationsStampsRows(t *testing.T) {
	block := newExplorerTestBlock(&types.Transaction{
		ID: "tx-1", Sender: "SPIF A", Receiver: "SPIF B",
		Amount: big.NewInt(1), Nonce: 1, Timestamp: 1000,
	})
	block.Header.Height = 3
	block.Header.Block = 3

	detail := formatBlockDetail(nil, block)
	stampBlockConfirmations(detail, 10)

	if got := detail["confirmations"]; got != uint64(7) {
		t.Errorf("block confirmations = %v, want 7", got)
	}
	rows, ok := detail["transactions"].([]gin.H)
	if !ok || len(rows) != 1 {
		t.Fatalf("expected one transaction row, got %T", detail["transactions"])
	}
	if got := rows[0]["confirmations"]; got != uint64(7) {
		t.Errorf("row confirmations = %v, want 7", got)
	}
	if got := rows[0]["block_height"]; got != uint64(3) {
		t.Errorf("row block_height = %v, want 3", got)
	}

	// A payload with no height must not silently claim the tip's depth.
	unplaceable := gin.H{"tx_count": 0}
	stampBlockConfirmations(unplaceable, 10)
	if _, present := unplaceable["confirmations"]; present {
		t.Error("a heightless payload must not be stamped with confirmations")
	}
}

func TestFormatBlockDetailExposesCoinFields(t *testing.T) {
	// A 100,000-gas fee at 1 gSPX/gas = 1e14 nSPX = 1e-4 SPX.
	tx := &types.Transaction{
		ID: "coin-tx", Sender: "SPIF A", Receiver: "SPIF B",
		Amount:   big.NewInt(1_000_000_000_000_000_000), // 1 SPX
		GasLimit: big.NewInt(100_000),
		GasPrice: big.NewInt(1_000_000_000),
		Nonce:    3, Timestamp: 1_700_000_001,
	}

	detail := formatBlockDetail(nil, newExplorerTestBlock(tx))
	txs, ok := detail["transactions"].([]gin.H)
	if !ok || len(txs) != 1 {
		t.Fatalf("expected exactly one transaction row, got %T", detail["transactions"])
	}
	row := txs[0]
	if _, present := row["gas_used"]; !present {
		t.Error("row must carry gas_used (computed policy quote when no receipt exists)")
	}
	if _, present := row["burned_this_tx_nspx"]; !present {
		t.Error("row must carry burned_this_tx_nspx")
	}
	if _, present := row["burned_this_tx_spx"]; !present {
		t.Error("row must carry burned_this_tx_spx")
	}
	if _, present := detail["burned_this_block_nspx"]; !present {
		t.Error("detail must carry burned_this_block_nspx")
	}
	if _, present := detail["block_reward_nspx"]; !present {
		t.Error("detail must carry block_reward_nspx")
	}
}

// TestBlockBurnTotalsReadsJournal proves the per-block coin-burn count the
// explorer shows is read from the block's atomic-commit journal — the same
// record crash recovery uses — and that a block with no journal degrades to
// empty strings rather than an error or a fabricated zero.
func TestBlockBurnTotalsReadsJournal(t *testing.T) {
	dir := t.TempDir()
	if err := core.InitJournalManager(dir); err != nil {
		t.Fatalf("InitJournalManager: %v", err)
	}

	// Journal filename is keyed on the first 16 chars of the block hash.
	const blockHash = "abcdef0123456789" + "000000000000000000000000000000000000000000000000"
	journal := map[string]string{
		"block_hash":             blockHash,
		"burned_this_block_nspx": "250000000000000000",
		"burned_before_nspx":     "37500019956267073340",
	}
	data, err := json.Marshal(journal)
	if err != nil {
		t.Fatalf("marshal journal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "journals", "tx_abcdef0123456789.json"), data, 0o644); err != nil {
		t.Fatalf("write journal: %v", err)
	}

	burnedThis, burnedBefore := blockBurnTotals(blockHash)
	if burnedThis != "250000000000000000" {
		t.Errorf("burned_this_block_nspx = %q, want 250000000000000000", burnedThis)
	}
	if burnedBefore != "37500019956267073340" {
		t.Errorf("burned_before_nspx = %q, want 37500019956267073340", burnedBefore)
	}

	// No journal for this block: empty, not "0" — the UI distinguishes the
	// two so a missing audit record is never shown as "nothing burned".
	if got, _ := blockBurnTotals("ffffffffffffffff000000000000000000000000000000000000000000000000"); got != "" {
		t.Errorf("journal-less block must report empty burn total, got %q", got)
	}
}

// TestNspxToSPXStringUsesProtocolDenomination checks the display conversion is
// driven by denom.SPX (1e18) rather than a local literal, and that zero/nil
// amounts render as "0" instead of a padded decimal string.
func TestNspxToSPXStringUsesProtocolDenomination(t *testing.T) {
	cases := []struct {
		name   string
		amount *big.Int
		want   string
	}{
		{"nil is zero", nil, "0"},
		{"zero is zero", big.NewInt(0), "0"},
		{"one whole SPX", big.NewInt(1e18), "1.000000000000000000"},
		{"one nSPX keeps precision", big.NewInt(1), "0.000000000000000001"},
	}
	for _, tc := range cases {
		if got := nspxToSPXString(tc.amount); got != tc.want {
			t.Errorf("%s: nspxToSPXString = %q, want %q", tc.name, got, tc.want)
		}
	}
}
