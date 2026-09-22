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

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/contracts"
	"github.com/sphinxfndorg/protocol/src/core"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/pool"
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

// TestFormatBlockDetailExposesCreatedContract locks in the block-level contract
// provenance a deploy needs.
//
// A deployment carries NO ToContract — its destination is derived at execution
// time from (sender, nonce, code) — so before created_contract existed, the
// deploy that mints a dataset's SIP-721 collection appeared in the block view
// as a receiverless transaction with no contract address anywhere. The explorer
// must re-derive the address exactly the way block execution does; anything
// else (a locally invented hash, a zero address, a missing key) would display a
// collection the chain does not recognise.
//
// The mint-anchor half is asserted too: the collection a minted token was bound
// to lives in the AnchorTag inside ReturnData, not in ToContract, so it is the
// only place a block view can learn where minted data landed.
func TestFormatBlockDetailExposesCreatedContract(t *testing.T) {
	const (
		rawSender = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"
		rawTarget = "11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF"
	)
	codeBytes := []byte("sip721-collection-deploy-code")

	deployTx := &types.Transaction{
		ID: "deploy-tx", Sender: rawSender, Receiver: "",
		Amount: big.NewInt(0), Nonce: 3, Timestamp: 1002, Code: codeBytes,
	}
	callTx := &types.Transaction{
		ID: "call-tx", Sender: rawSender, Receiver: "",
		Amount: big.NewInt(0), Nonce: 4, Timestamp: 1003, ToContract: rawTarget,
	}
	anchorTag, err := json.Marshal(core.AnchorTag{
		Type:        core.AnchorTagType,
		MintID:      "554f471215ed560292c81f13f6cb3b56be373b906bcc06a843997922be07dbb2",
		Subject:     "collection_test.png",
		CID:         "bafybeigdyrzt",
		ReceiptHash: strings.Repeat("ab", 32),
		TokenID:     7,
		TokenURI:    "ipfs://bafybeimetadata",
		Contract:    "SPIF 0866 9081 D8AD 975F CB80 E52F 4F53 C31D 6AF4 A837 AAFF 1BEB 0940 D8D9 6E79 3B5E",
	})
	if err != nil {
		t.Fatalf("marshal anchor tag: %v", err)
	}
	anchorTx := &types.Transaction{
		ID: "anchor-tx", Sender: rawSender, Receiver: rawSender,
		Amount: big.NewInt(0), Nonce: 5, Timestamp: 1004, ReturnData: anchorTag,
	}
	plainTx := &types.Transaction{
		ID: "plain-tx", Sender: rawSender, Receiver: rawTarget,
		Amount: big.NewInt(5), Nonce: 6, Timestamp: 1005,
	}

	detail := formatBlockDetail(nil, newExplorerTestBlock(deployTx, callTx, anchorTx, plainTx))
	txs, ok := detail["transactions"].([]gin.H)
	if !ok || len(txs) != 4 {
		t.Fatalf("expected 4 tx summaries, got %T/%d", detail["transactions"], len(txs))
	}
	deployRow, callRow, anchorRow, plainRow := txs[0], txs[1], txs[2], txs[3]

	// ── The deploy: the address it CREATED ──────────────────────────────
	if got := deployRow["is_contract_deploy"]; got != true {
		t.Fatalf("deploy tx must report is_contract_deploy=true, got %v", got)
	}
	wantAddr := contracts.ContractAddress(rawSender, deployTx.Nonce, codeBytes)
	if got := deployRow["created_contract"]; got != wantAddr {
		t.Fatalf("created_contract = %v, want the address block execution derives (%s)", got, wantAddr)
	}
	if !strings.HasPrefix(wantAddr, common.SPIFPrefix+" ") {
		t.Fatalf("a derived contract address must carry the canonical SPIF prefix, got %q", wantAddr)
	}
	if groups := strings.Split(strings.TrimPrefix(wantAddr, common.SPIFPrefix+" "), " "); len(groups) != 16 {
		t.Fatalf("a derived contract address must be 16 groups of 4 hex, got %d groups in %q", len(groups), wantAddr)
	}
	if got := deployRow["to_contract"]; got != "" {
		t.Fatalf("a deployment must not claim a ToContract target, got %v", got)
	}

	// ── The call: its target, and no fabricated created address ─────────
	if got := callRow["is_contract_deploy"]; got != false {
		t.Fatalf("a plain contract call is not a deployment, got is_contract_deploy=%v", got)
	}
	if got := callRow["to_contract"]; got != rawTarget {
		t.Fatalf("call tx must keep its to_contract target, got %v", got)
	}
	if _, present := callRow["created_contract"]; present {
		t.Fatal("a call creates nothing, so created_contract must be omitted")
	}

	// ── The mint anchor: the collection/token it bound inside ReturnData ─
	if got := anchorRow["anchor_contract"]; got != "SPIF 0866 9081 D8AD 975F CB80 E52F 4F53 C31D 6AF4 A837 AAFF 1BEB 0940 D8D9 6E79 3B5E" {
		t.Fatalf("anchor tx must expose the collection it bound, got %v", got)
	}
	if got := anchorRow["anchor_token_id"]; got != uint64(7) {
		t.Fatalf("anchor tx must expose its token id, got %v", got)
	}
	if got := anchorRow["return_data_kind"]; got != "mint_anchor" {
		t.Fatalf("the anchor must still classify as a mint_anchor, got %v", got)
	}

	// ── A plain transfer fabricates nothing ─────────────────────────────
	if got := plainRow["is_contract_deploy"]; got != false {
		t.Fatalf("plain tx must report is_contract_deploy=false, got %v", got)
	}
	for _, key := range []string{"created_contract", "anchor_contract", "anchor_token_id"} {
		if _, present := plainRow[key]; present {
			t.Fatalf("a plain transfer must not carry %q", key)
		}
	}

	// ── Additivity: the pre-existing consumer fields survive ────────────
	for _, key := range []string{"txid", "sender", "receiver", "amount_spx", "nonce", "timestamp", "to_contract", "is_contract_tx"} {
		if _, present := deployRow[key]; !present {
			t.Fatalf("existing consumer field %q disappeared from the tx summary", key)
		}
	}
}

// TestAddContractFieldsNilSafety keeps the payload helper inert on a nil
// transaction or payload, since it runs inside handlers that also serve partial
// data (e.g. a block read while the DB is still warming).
func TestAddContractFieldsNilSafety(t *testing.T) {
	addContractFields(nil, gin.H{})
	addContractFields(&types.Transaction{ID: "x"}, nil)

	payload := gin.H{}
	addContractFields(&types.Transaction{ID: "y", Sender: "SPIF A", Receiver: "SPIF B"}, payload)
	if got := payload["is_contract_deploy"]; got != false {
		t.Fatalf("a plain tx must mark is_contract_deploy=false, got %v", got)
	}
	if _, present := payload["created_contract"]; present {
		t.Fatal("a plain tx must not gain a created_contract")
	}
	if _, present := payload["anchor_contract"]; present {
		t.Fatal("a tx with no ReturnData must not gain an anchor_contract")
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

// TestFormatBlockDetailExposesSignatureFields locks in the per-transaction and
// per-block signature material the explorer renders, because an explorer that
// shows a transaction without its signature makes the chain unverifiable to the
// people most likely to read it.
//
// Two distinct signatures exist and both must be present:
//   - the block's ProposerSignature (who sealed this block, and over what),
//   - each transaction's SPHINCS+ auth bundle (who authorised the transfer).
//
// The auth bundle is proof-carrying: HasFullAuthBundle() requires exact lengths
// (SignatureHash 32, AuthTimestamp 8, AuthNonce 16, MerkleRootHash 32,
// Commitment 32, Proof 32). Those lengths are asserted here, so a future change
// that truncates or reshapes the fields fails loudly instead of silently
// downgrading every transaction to "not fully authenticated".
func TestFormatBlockDetailExposesSignatureFields(t *testing.T) {
	tx := &types.Transaction{
		ID: "signed-tx", Sender: "SPIF A", Receiver: "SPIF B",
		Amount:   big.NewInt(1_000_000_000_000_000_000),
		GasLimit: big.NewInt(21_000),
		GasPrice: big.NewInt(2_000_000_000),
		Nonce:    3, Timestamp: 1_700_000_000,

		Signature:      []byte{0xAA, 0xBB},
		SignatureHash:  make([]byte, 32),
		PublicKey:      []byte{0xCC},
		AuthTimestamp:  make([]byte, 8),
		AuthNonce:      make([]byte, 16),
		MerkleRootHash: make([]byte, 32),
		Commitment:     make([]byte, 32),
		Proof:          make([]byte, 32),
	}

	block := newExplorerTestBlock(tx)
	block.Header.ProposerSignature = []byte{0xDE, 0xAD}
	block.Header.SigDataHash = []byte{0xBE, 0xEF}

	detail := formatBlockDetail(nil, block)

	// Block-level seal: the proposer's signature and the data it covers.
	header, ok := detail["header"].(gin.H)
	if !ok {
		t.Fatalf("detail[header] = %T, want gin.H", detail["header"])
	}
	if got := header["proposer_signature"]; got != "dead" {
		t.Errorf("header proposer_signature = %v, want dead", got)
	}
	if got := header["sig_data_hash"]; got != "beef" {
		t.Errorf("header sig_data_hash = %v, want beef", got)
	}
	if got := header["proposer_id"]; got != "validator-1" {
		t.Errorf("header proposer_id = %v, want validator-1", got)
	}

	// Transaction-level seal: every auth-bundle field must survive to the row.
	rows, ok := detail["transactions"].([]gin.H)
	if !ok || len(rows) != 1 {
		t.Fatalf("expected one transaction row, got %T %d", detail["transactions"], len(rows))
	}
	row := rows[0]
	if got := row["signature"]; got != "aabb" {
		t.Errorf("signature = %v, want aabb", got)
	}
	if got := row["signature_hash"]; got != strings.Repeat("00", 32) {
		t.Errorf("signature_hash = %v, want 32 zero bytes", got)
	}
	if got := row["auth_timestamp"]; got != strings.Repeat("00", 8) {
		t.Errorf("auth_timestamp = %v, want 8 zero bytes", got)
	}
	if got := row["auth_nonce"]; got != strings.Repeat("00", 16) {
		t.Errorf("auth_nonce = %v, want 16 zero bytes", got)
	}
	if got := row["commitment"]; got != strings.Repeat("00", 32) {
		t.Errorf("commitment = %v, want 32 zero bytes", got)
	}
	if got := row["proof"]; got != strings.Repeat("00", 32) {
		t.Errorf("proof = %v, want 32 zero bytes", got)
	}
	// has_full_auth is computed from the same fields just asserted, so a
	// complete bundle must report true — otherwise the UI would render a
	// fully-signed transaction as unauthenticated.
	if got := row["has_full_auth"]; got != true {
		t.Errorf("has_full_auth = %v, want true for a complete bundle", got)
	}
}

// TestMempoolResponseCarriesFullPoolPicture locks in the /mempool payload
// contract that ends the "0 pending forever" illusion.
//
// sendrawtransaction returns a txid BEFORE the pool validates the nonce, and
// the node validates asynchronously — so a wallet's send sits in the broadcast
// or validating pool first, and lands in the invalid pool if the nonce was
// wrong. GetPendingTransactions reports only the mineable (validated + pending)
// set, so a payload built on it alone reads a bare zero at exactly the moments
// an operator is watching: mid-send and after a rejection. The response must
// therefore carry the pool snapshot and BOTH non-mineable lists alongside the
// pending rows — and tx_count must stay the PENDING count existing consumers
// key off, not silently become the tracked total.
func TestMempoolResponseCarriesFullPoolPicture(t *testing.T) {
	pending := []gin.H{{"txid": "mineable-tx", "sender": "SPIF A"}}
	inFlight := []gin.H{mempoolEntryRow(pool.MempoolEntry{
		TxID: "broadcast-tx", Sender: "SPIF A", Nonce: 5, Status: "broadcast",
	}, false)}
	rejected := []gin.H{mempoolEntryRow(pool.MempoolEntry{
		TxID: "rejected-tx", Sender: "SPIF A", Nonce: 6, Status: "invalid",
		Reason: "nonce validation failed: invalid nonce: 5 must equal 2",
	}, true)}
	snapshot := [5]int{1 /*broadcast*/, 1 /*validating*/, 1 /*pending*/, 1 /*invalid*/, 4 /*tracked*/}

	resp := mempoolResponse(map[string]interface{}{"size": 4}, pending, inFlight, rejected, snapshot)

	// tx_count stays the pending count — existing consumers treat it as "how
	// many transactions could go into the next block".
	if got := resp["tx_count"]; got != 1 {
		t.Fatalf("tx_count = %v, want 1 (the pending count, not the tracked total)", got)
	}

	// The pool breakdown must be present and mapped 1:1 to the snapshot, so
	// zero pending is always accompanied by WHERE the transactions actually are.
	poolBreakdown, ok := resp["pool"].(gin.H)
	if !ok {
		t.Fatalf("pool = %T, want gin.H — the breakdown must ship with every response", resp["pool"])
	}
	for key, want := range map[string]int{
		"broadcast": 1, "validating": 1, "pending": 1, "invalid": 1, "total": 4,
	} {
		if got := poolBreakdown[key]; got != want {
			t.Errorf("pool.%s = %v, want %d", key, got, want)
		}
	}

	// Both non-mineable lists must ship alongside the pending rows.
	if rows, ok := resp["in_flight_txs"].([]gin.H); !ok || len(rows) != 1 {
		t.Fatalf("in_flight_txs = %T/%v, want one row", resp["in_flight_txs"], resp["in_flight_txs"])
	}
	rejectedRows, ok := resp["rejected_txs"].([]gin.H)
	if !ok || len(rejectedRows) != 1 {
		t.Fatalf("rejected_txs = %T/%v, want one row", resp["rejected_txs"], resp["rejected_txs"])
	}

	// The rejected row must carry the node's own reason verbatim — that string
	// is the entire point of listing it: the reader needs to know WHY the send
	// can never confirm.
	if got := rejectedRows[0]["reason"]; got != "nonce validation failed: invalid nonce: 5 must equal 2" {
		t.Errorf("rejected reason = %v, want the node's validation failure", got)
	}

	// An in-flight row has no failure to report; an empty string there would
	// read as one, so the key must be absent entirely.
	if _, present := inFlight[0]["reason"]; present {
		t.Error("an in-flight row must not carry a reason key")
	}
}

// TestMempoolResponseJSONShape keeps the exact wire keys the explorer frontend
// parses (fetchMempoolView reads pending_txs / pool / in_flight_txs /
// rejected_txs). A rename on either side would silently degrade the UI back to
// its old fallback — an empty pool rendered as a bare zero — with no compile
// error to catch it.
func TestMempoolResponseJSONShape(t *testing.T) {
	resp := mempoolResponse(nil, []gin.H{}, []gin.H{}, []gin.H{}, [5]int{})

	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal mempool response: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal mempool response: %v", err)
	}
	for _, key := range []string{"mempool", "pending_txs", "tx_count", "pool", "in_flight_txs", "rejected_txs"} {
		if _, present := decoded[key]; !present {
			t.Errorf("wire key %q missing from the mempool payload", key)
		}
	}

	// Empty lists must serialize as [], not null, so the frontend's
	// Array.isArray check always passes on an empty pool.
	for _, key := range []string{"pending_txs", "in_flight_txs", "rejected_txs"} {
		if got := string(decoded[key]); got != "[]" {
			t.Errorf("%s = %s, want [] (never null)", key, got)
		}
	}
}

// TestBlocksPageRangeCoversEveryHeightOnce locks the pagination contract the
// explorer's fetchAllBlocks now walks: pages 1..N of /blocks must partition
// the chain with no gap and no overlap. With the tip at #60 (61 blocks) and
// the default limit of 25, page 1 carries #60..#36 and pages 2-3 must still
// deliver #35..#0 — exactly the older heights a page-1-only fetch dropped
// from "All Mined Block States".
func TestBlocksPageRangeCoversEveryHeightOnce(t *testing.T) {
	const (
		blockCount = uint64(61)
		limit      = uint64(25)
	)

	seen := make(map[uint64]int)
	for page := uint64(1); page <= 3; page++ {
		startHeight, endHeight, clampedPage, totalPages := blocksPageRange(blockCount, page, limit)
		if totalPages != 3 {
			t.Fatalf("page %d: totalPages = %d, want 3", page, totalPages)
		}
		if clampedPage != page {
			t.Fatalf("page %d: clampedPage = %d, an in-range page must round-trip unchanged", page, clampedPage)
		}
		for h := startHeight; h > endHeight; h-- {
			seen[h-1]++
		}
	}

	if len(seen) != int(blockCount) {
		t.Fatalf("pages cover %d distinct heights, want %d (every mined block)", len(seen), blockCount)
	}
	for height := uint64(0); height < blockCount; height++ {
		if seen[height] != 1 {
			t.Errorf("height #%d visited %d times, want exactly once", height, seen[height])
		}
	}
}

// TestBlocksPageRangeWindowsAndClamping pins the exact window edges the
// frontend observes (page 1 starts at the tip, page 1's last row is the
// first block NOT on page 2) and the safety clamp: a page beyond the tip
// must land on the last page rather than underflowing the window math.
func TestBlocksPageRangeWindowsAndClamping(t *testing.T) {
	// Page 1: walks h=61..37 → serves heights #60..#36.
	start, end, _, totalPages := blocksPageRange(61, 1, 25)
	if start != 61 || end != 36 || totalPages != 3 {
		t.Fatalf("page 1 window = (start=%d, end=%d, pages=%d), want (61, 36, 3)", start, end, totalPages)
	}

	// Page 2 picks up exactly where page 1 stopped: walks h=36..12 → #35..#11.
	start, end, _, _ = blocksPageRange(61, 2, 25)
	if start != 36 || end != 11 {
		t.Fatalf("page 2 window = (start=%d, end=%d), want (36, 11)", start, end)
	}

	// Page 3 (partial last page): walks h=11..1 → #10..#0.
	start, end, _, _ = blocksPageRange(61, 3, 25)
	if start != 11 || end != 0 {
		t.Fatalf("page 3 window = (start=%d, end=%d), want (11, 0)", start, end)
	}

	// Out-of-range page clamps to the last page — never a negative window.
	start, end, clamped, _ := blocksPageRange(61, 99, 25)
	if clamped != 3 || start != 11 || end != 0 {
		t.Fatalf("page 99 clamps to (start=%d, end=%d, page=%d), want (11, 0, 3)", start, end, clamped)
	}

	// An empty chain yields an empty window, not a garbage one.
	if s, e, _, pages := blocksPageRange(0, 1, 25); s != 0 || e != 0 || pages != 0 {
		t.Fatalf("empty chain window = (%d, %d, pages=%d), want zeros", s, e, pages)
	}
}
