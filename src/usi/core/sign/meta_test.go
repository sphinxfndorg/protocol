// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/sign/meta_test.go
package sign

import (
	"math/big"
	"strings"
	"testing"
)

// anchoredMeta mirrors the provenance a completed Mint Data flow produces, so
// the renderers are pinned to the exact text a verify screen shows.
func anchoredMeta() *Meta {
	m := &Meta{}
	SetPinningContext(m,
		"spxhash-723a7f8b07b5907ccd8f7b81fee77c299a143756ae83d715482da722012a0299",
		13, "", "")
	StampAnchorProvenance(m,
		"41aa14f9ad3f125cd710e564b251ceddb59c7d7240c0d2ee98bd77a477a64acf",
		"/Users/x/anchors/anchor_41aa.json",
		"554f471215ed560292c81f13f6cb3b56be373b906bcc06a843997922be07dbb2",
		0, "",
		16, "c3bf4c47852733dd22269b7293f5f66685db7964320a9ca4e1006ad92dddc326")
	SetAnchorFee(m, big.NewInt(66196436288121), 0)
	return m
}

func TestOnChainBlockExactOutput(t *testing.T) {
	got := OnChainBlock(anchoredMeta())
	want := `--- On-Chain / Storage ---
MintPrice: 66196436288121 nSPX (~0.000066 SPX)
MintID: 554f471215ed560292c81f13f6cb3b56be373b906bcc06a843997922be07dbb2
CID: spxhash-723a7f8b07b5907ccd8f7b81fee77c299a143756ae83d715482da722012a0299
MintHeight: 13
AnchorTx: 41aa14f9ad3f125cd710e564b251ceddb59c7d7240c0d2ee98bd77a477a64acf
Confirmed: 16
BlockHash: c3bf4c47852733dd22269b7293f5f66685db7964320a9ca4e1006ad92dddc326
TxNonce: 0`
	if got != want {
		t.Fatalf("compact on-chain block mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestOnChainBlockSentinels locks in the "no data" contract: a signed-but-
// unanchored document must never render as if it were anchored.
func TestOnChainBlockSentinels(t *testing.T) {
	got := OnChainBlock(&Meta{})
	want := `--- On-Chain / Storage ---
MintPrice: n/a
MintID: unanchored
CID: unpinned
MintHeight: pending
AnchorTx: unanchored
Confirmed: pending
BlockHash: pending
TxNonce: n/a`
	if got != want {
		t.Fatalf("sentinel block mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	if strings.Contains(got, "TokenID") || strings.Contains(got, "Contract") ||
		strings.Contains(got, "Royalty") {
		t.Fatalf("zero-valued optional on-chain fields must be omitted, got:\n%s", got)
	}
}

func TestOnChainDetailBlockExactOutput(t *testing.T) {
	got := OnChainDetailBlock(anchoredMeta())
	want := `--- On-Chain / Storage Provenance ---
Mint Price: 66196436288121 nSPX (~0.000066 SPX)
Mint ID: 554f471215ed560292c81f13f6cb3b56be373b906bcc06a843997922be07dbb2
IPFS CID: spxhash-723a7f8b07b5907ccd8f7b81fee77c299a143756ae83d715482da722012a0299
Mint Block Height: 13
Anchor TxID: 41aa14f9ad3f125cd710e564b251ceddb59c7d7240c0d2ee98bd77a477a64acf
Anchor Path: /Users/x/anchors/anchor_41aa.json
Confirmed Height: 16
Block Hash: c3bf4c47852733dd22269b7293f5f66685db7964320a9ca4e1006ad92dddc326
Tx Nonce: 0
Token URI: n/a
Metadata CID: n/a
NFT Name: n/a
NFT Description: n/a
RoyaltyBPS: 0
UsageFeeNSPX: n/a
RoyaltyRecipient: n/a
Token ID: n/a (legacy receipt anchor — no collection)
Contract: n/a (no collection)`
	if got != want {
		t.Fatalf("detail on-chain block mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestSetAnchorFeeNeverDowngradesKnownPrice: a nil fee must not erase a price
// already recorded, and a legitimate nonce of 0 must survive as "0".
func TestSetAnchorFeeNeverDowngradesKnownPrice(t *testing.T) {
	m := &Meta{}
	SetAnchorFee(m, big.NewInt(66196436288121), 0)
	if m.MintFeeNSPX != "66196436288121" || m.AnchorNonce != "0" {
		t.Fatalf("first stamp wrong: fee=%q nonce=%q", m.MintFeeNSPX, m.AnchorNonce)
	}
	SetAnchorFee(m, nil, 7)
	if m.MintFeeNSPX != "66196436288121" {
		t.Fatalf("nil fee must not erase a known price, got %q", m.MintFeeNSPX)
	}
	if m.AnchorNonce != "7" {
		t.Fatalf("nonce must update, got %q", m.AnchorNonce)
	}
	SetAnchorFee(m, big.NewInt(0), 8)
	if m.MintFeeNSPX != "66196436288121" {
		t.Fatalf("non-positive fee must not erase a known price, got %q", m.MintFeeNSPX)
	}
}

// TestStampAnchorProvenanceRefusesUnanchored: stamping an empty anchor txid
// would render an anchor that never happened — must hard-fail.
func TestStampAnchorProvenanceRefusesUnanchored(t *testing.T) {
	m := &Meta{}
	if err := StampAnchorProvenance(m, "   ", "", "", 0, "", 0, ""); err == nil {
		t.Fatal("empty anchor txid must be refused")
	}
	if m.AnchorTxID != "" || m.BlockHash != "" {
		t.Fatal("refused stamp must leave Meta untouched")
	}
}

// TestStampAnchorProvenancePendingWhenUnconfirmed: an anchored-but-unconfirmed
// tx records height 0 and the explicit "pending" block-hash sentinel.
func TestStampAnchorProvenancePendingWhenUnconfirmed(t *testing.T) {
	m := &Meta{}
	if err := StampAnchorProvenance(m, "deadbeef", "/tmp/a.json", "mint-1", 0, "", 0, ""); err != nil {
		t.Fatalf("stamp failed: %v", err)
	}
	if m.ConfirmedHeight != 0 || m.BlockHash != "pending" {
		t.Fatalf("unconfirmed stamp wrong: height=%d hash=%q", m.ConfirmedHeight, m.BlockHash)
	}
	if m.MintID != "mint-1" || m.AnchorPath != "/tmp/a.json" {
		t.Fatalf("stamp dropped fields: mint=%q path=%q", m.MintID, m.AnchorPath)
	}
}

// TestApplyOnChainDataRoundTrip ensures the read/write views agree, so
// createUSIMetaFile can copy a caller's on-chain context wholesale.
func TestApplyOnChainDataRoundTrip(t *testing.T) {
	src := anchoredMeta()
	SetAnchorEconomics(src, 500, "1000", "SPIFABCD")
	SetNFTMetadata(src, "Freedom Document", "A signed declaration minted as an NFT")
	src.TokenID = 42
	src.ContractAddress = "SPIF00000000000000000000000000000000000000"
	src.TokenURI = "ipfs://bafkrei"
	src.MetadataCID = "bafkrei"

	dst := &Meta{}
	ApplyOnChainData(dst, OnChainData(src))
	if got, want := OnChainData(dst), OnChainData(src); got != want {
		t.Fatalf("round-trip mismatch\n got: %+v\nwant: %+v", got, want)
	}
	// Nil receiver must be inert, never panic.
	ApplyOnChainData(nil, OnChainData(src))
	if (OnChainData(nil)) != (OnChainProvenance{}) {
		t.Fatal("OnChainData(nil) must be the zero view")
	}
}

// TestOnChainBlockIncludesCollectionBinding: a SIP-721 collection mint adds
// token id, contract, and the embedded economics to the on-chain block.
func TestOnChainBlockIncludesCollectionBinding(t *testing.T) {
	m := anchoredMeta()
	m.TokenID = 42
	m.ContractAddress = "SPIF00000000000000000000000000000000000000"
	SetAnchorEconomics(m, 500, "1000", "SPIFABCD")

	got := OnChainBlock(m)
	for _, want := range []string{
		"TokenID: 42",
		"Contract: SPIF00000000000000000000000000000000000000",
		"RoyaltyBPS: 500",
		"UsageFeeNSPX: 1000 nSPX (~0.000000 SPX)",
		"RoyaltyRecipient: SPIFABCD",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("on-chain block missing %q:\n%s", want, got)
		}
	}
}

// TestSetNFTMetadataFlowsIntoProvenance: the name/description typed on the
// Mint Data screen must travel inside the signed document's on-chain block,
// not only in the pinned metadata JSON (which a bare/non-collection mint never
// uploads, and which an unreachable IPFS daemon can lose).
func TestSetNFTMetadataFlowsIntoProvenance(t *testing.T) {
	m := anchoredMeta()
	SetNFTMetadata(m, "Freedom Document", "A signed declaration minted as an NFT")

	if got := OnChainData(m).NFTName; got != "Freedom Document" {
		t.Fatalf("read view dropped NFT name, got %q", got)
	}
	if got := OnChainData(m).NFTDescription; got != "A signed declaration minted as an NFT" {
		t.Fatalf("read view dropped NFT description, got %q", got)
	}

	compact := OnChainBlock(m)
	for _, want := range []string{
		"NFTName: Freedom Document",
		"NFTDescription: A signed declaration minted as an NFT",
	} {
		if !strings.Contains(compact, want) {
			t.Fatalf("compact on-chain block missing %q:\n%s", want, compact)
		}
	}

	detail := OnChainDetailBlock(m)
	for _, want := range []string{
		"NFT Name: Freedom Document",
		"NFT Description: A signed declaration minted as an NFT",
	} {
		if !strings.Contains(detail, want) {
			t.Fatalf("detail on-chain block missing %q:\n%s", want, detail)
		}
	}

	// Nil receiver must be inert, never panic.
	SetNFTMetadata(nil, "ignored", "ignored")
}

func TestFormatMintFeeNSPX(t *testing.T) {
	if got := FormatMintFeeNSPX(""); got != "" {
		t.Fatalf("empty fee must render empty, got %q", got)
	}
	if got := FormatMintFeeNSPX("1000000000000000000"); got != "1000000000000000000 nSPX (~1.000000 SPX)" {
		t.Fatalf("1 SPX render wrong: %q", got)
	}
	if got := FormatMintFeeNSPX("not-a-number"); got != "not-a-number nSPX" {
		t.Fatalf("unparseable fee must fall back to raw nSPX, got %q", got)
	}
	if got := FormatMintFeeNSPX("-5"); got != "-5 nSPX" {
		t.Fatalf("negative fee must render raw, got %q", got)
	}
}

// TestIPFSPayloadHashIsDistinctFromFileHash locks in the canonical-artifact
// contract that the old pipeline left implicit (and therefore confusing):
//
//   - FileHash covers the SIGNED file, which cannot exist before the signature
//     is written, so it can never equal the hash of the pinned bytes;
//   - IPFSPayloadHash covers the EXACT bytes pinned to IPFS, and is the value
//     the mint receipt commits as PayloadHash.
//
// The test also proves the field survives every write path that carries
// provenance, because a value that only lives on the in-memory Meta would be
// silently dropped by the container writers (which rebuild the Meta from
// ApplyOnChainData).
func TestIPFSPayloadHashIsDistinctFromFileHash(t *testing.T) {
	const (
		fileHash    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		payloadHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	m := &Meta{FileHash: fileHash}
	SetIPFSPayloadHash(m, payloadHash)

	// The two hashes describe different artifacts and must not be conflated.
	if m.IPFSPayloadHash == m.FileHash {
		t.Fatal("IPFSPayloadHash must be independent of FileHash")
	}
	if m.IPFSPayloadHash != payloadHash || m.FileHash != fileHash {
		t.Fatalf("setter clobbered a hash: ipfs=%q file=%q", m.IPFSPayloadHash, m.FileHash)
	}

	// It must be part of the provenance view every renderer/container reads.
	if got := OnChainData(m).IPFSPayloadHash; got != payloadHash {
		t.Fatalf("OnChainData lost the payload hash: %q", got)
	}

	// And it must survive the ApplyOnChainData round-trip the container
	// writers use (createUSIMetaFile rebuilds the Meta this way).
	ApplyOnChainData(m, OnChainData(m))
	if m.IPFSPayloadHash != payloadHash {
		t.Fatalf("ApplyOnChainData round-trip dropped the payload hash: %q", m.IPFSPayloadHash)
	}
	if m.FileHash != fileHash {
		t.Fatalf("ApplyOnChainData round-trip clobbered FileHash: %q", m.FileHash)
	}

	// Clone is used before writing some containers; it must carry the field.
	if got := m.Clone().IPFSPayloadHash; got != payloadHash {
		t.Fatalf("Clone dropped the payload hash: %q", got)
	}

	// Nil receiver must be inert, never panic.
	SetIPFSPayloadHash(nil, payloadHash)
}
