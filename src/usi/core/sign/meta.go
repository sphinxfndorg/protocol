// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/sign/meta.go
//
// This file is the single source of truth for a signed document's ON-CHAIN
// data. Everything EmbedSignature writes into the "On-Chain / Storage" block
// of any container (PDF properties, XMP, PNG iTXt, JPEG APP1, Office
// custom.xml, xattrs, USIMETA footer) is defined, populated, and rendered
// here — embed.go only consumes the result via OnChainBlock(meta) /
// OnChainDetailBlock(meta).
//
// Meta is an alias for types.Meta, so the accessors are free functions rather
// than methods (Go forbids methods on a non-local type).
//
// Population order (mirrors the Mint Data flow in gui/helper.go):
//
//	NewMeta()                → crypto fields (signature, pubkey, nonce, hash)
//	SetAnchorEconomics()     → terms frozen from the mint form (pre-embed)
//	SetNFTMetadata()         → ERC-721 name/description from the mint form (pre-embed)
//	SetPinningContext()      → IPFS CID + chain-tip height + ERC-721 metadata
//	EmbedSignature()         → hashes/signs the file and writes the container
//	SetAnchorFee()           → policy mint fee + on-chain account nonce
//	SetIPFSPayloadHash()     → hash of the exact bytes pinned (receipt PayloadHash)
//	StampAnchorProvenance() / RefreshOnChainProvenance() → post-anchor txid,
//	                           mint id, confirming block + token binding
package sign

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// NewMeta creates a new Meta carrying the cryptographic core of a signature
// (signature bytes, public key, entropy nonce, timestamp, file hash). All
// on-chain fields start unset and are filled in through the setters below as
// the Mint Data flow progresses.
func NewMeta(sig *Signature, fileHash []byte) (*Meta, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &Meta{
		Signature: hex.EncodeToString(sig.Signature),
		PublicKey: hex.EncodeToString(sig.PublicKey),
		Nonce:     hex.EncodeToString(nonce),
		Timestamp: time.Now().Unix(),
		FileHash:  hex.EncodeToString(fileHash),
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// ON-CHAIN PROVENANCE — the data model
// ─────────────────────────────────────────────────────────────────────────────

// OnChainProvenance is the complete on-chain / storage context of a signed
// document: everything an IPFS pin, an anchor transaction, or a SIP-721 mint
// records about the file. It is a view over the on-chain subset of Meta — the
// values still travel inside Meta (and therefore inside every container's
// embedded metadata), but this type is what callers populate and read.
//
// Zero/empty values are meaningful: they mark data that was signed but never
// anchored ("unanchored"), pinned ("unpinned"), or confirmed ("pending"). The
// renderers below turn each of those into an explicit sentinel so a verify
// screen can never mistake "no data" for a confirmed anchor. All fields are
// optional so legacy sidecars without them still decode.
type OnChainProvenance struct {
	// Storage / pinning
	IPFSCID     string // IPFS CID the payload was pinned under
	BlockHeight uint64 // chain-tip height at mint time

	// IPFSPayloadHash is hex(SHAKE-256 with org) of the exact bytes pinned
	// under IPFSCID — equal to the mint receipt's PayloadHash, and NOT equal
	// to Meta.FileHash (which covers the signed on-disk file). See the field
	// docs on types.Meta for why the two must not be conflated.
	IPFSPayloadHash string

	// Anchor transaction
	MintID          string // deterministic mint identifier (receipt.MintID)
	AnchorTxID      string // sendrawtransaction result txid
	AnchorPath      string // local anchor_*.json sidecar path
	ConfirmedHeight uint64 // block height that included the anchor tx (0 = pending)
	BlockHash       string // hex hash of the confirming block ("pending" while unconfirmed)
	AnchorNonce     string // on-chain replay-protection counter the anchor tx consumed
	MintFeeNSPX     string // policy-priced mint fee charged as the tx Amount

	// ERC-721 metadata context (present when minting with metadata JSON)
	TokenURI    string // ipfs://<metadataCID>
	MetadataCID string // CID of the metadata JSON

	// NFT display metadata typed on the Mint Data screen before signing.
	// These are the same values baked into the ERC-721 metadata JSON
	// pinned to IPFS (see mint.BuildNFTMetadata) — recorded here too so
	// they travel with the signed document itself and render in every
	// on-chain provenance block, not just the pinned metadata file.
	NFTName        string
	NFTDescription string

	// SIP-721 token binding (collection mints only)
	TokenID         uint64
	ContractAddress string

	// Embedded economics frozen at mint time and enforced by the native
	// runtime on every transfer_from / purchase_license.
	RoyaltyBPS       uint64 // 0..10000 basis points of sale value
	UsageFeeNSPX     string // per licensed-access fee, decimal nSPX
	RoyaltyRecipient string // "" = the mint caller (creator)
}

// OnChainData returns the on-chain slice of the Meta. It is the read view used
// by every renderer and by callers that need to mirror provenance elsewhere.
// (Meta is an alias for types.Meta, so this is a free function — methods
// cannot be declared on a non-local type.)
func OnChainData(m *Meta) OnChainProvenance {
	if m == nil {
		return OnChainProvenance{}
	}
	return OnChainProvenance{
		IPFSCID:          m.IPFSCID,
		BlockHeight:      m.BlockHeight,
		IPFSPayloadHash:  m.IPFSPayloadHash,
		MintID:           m.MintID,
		AnchorTxID:       m.AnchorTxID,
		AnchorPath:       m.AnchorPath,
		ConfirmedHeight:  m.ConfirmedHeight,
		BlockHash:        m.BlockHash,
		AnchorNonce:      m.AnchorNonce,
		MintFeeNSPX:      m.MintFeeNSPX,
		TokenURI:         m.TokenURI,
		MetadataCID:      m.MetadataCID,
		NFTName:          m.NFTName,
		NFTDescription:   m.NFTDescription,
		TokenID:          m.TokenID,
		ContractAddress:  m.ContractAddress,
		RoyaltyBPS:       m.RoyaltyBPS,
		UsageFeeNSPX:     m.UsageFeeNSPX,
		RoyaltyRecipient: m.RoyaltyRecipient,
	}
}

// ApplyOnChainData writes an OnChainProvenance onto the Meta. This is the
// single write path for on-chain data; every other setter funnels through it
// so no container can ever disagree about which fields carry provenance.
func ApplyOnChainData(m *Meta, p OnChainProvenance) {
	if m == nil {
		return
	}
	m.IPFSCID = p.IPFSCID
	m.BlockHeight = p.BlockHeight
	m.IPFSPayloadHash = p.IPFSPayloadHash
	m.MintID = p.MintID
	m.AnchorTxID = p.AnchorTxID
	m.AnchorPath = p.AnchorPath
	m.ConfirmedHeight = p.ConfirmedHeight
	m.BlockHash = p.BlockHash
	m.AnchorNonce = p.AnchorNonce
	m.MintFeeNSPX = p.MintFeeNSPX
	m.TokenURI = p.TokenURI
	m.MetadataCID = p.MetadataCID
	m.NFTName = p.NFTName
	m.NFTDescription = p.NFTDescription
	m.TokenID = p.TokenID
	m.ContractAddress = p.ContractAddress
	m.RoyaltyBPS = p.RoyaltyBPS
	m.UsageFeeNSPX = p.UsageFeeNSPX
	m.RoyaltyRecipient = p.RoyaltyRecipient
}

// ─────────────────────────────────────────────────────────────────────────────
// ON-CHAIN POPULATION — called by the Mint Data flow at each stage
// ─────────────────────────────────────────────────────────────────────────────

// SetPinningContext records the storage context known BEFORE signing: the IPFS
// CID the payload was pinned under, the chain-tip block height at mint time,
// and (when minting with metadata JSON) the ERC-721 tokenURI + metadata CID.
// Best-effort by design — an offline node or unreachable IPFS daemon leaves the
// values empty and the renderers fall back to their "unpinned"/"pending"
// sentinels rather than blocking the mint.
func SetPinningContext(m *Meta, cid string, blockHeight uint64, tokenURI, metadataCID string) {
	if m == nil {
		return
	}
	m.IPFSCID = cid
	m.BlockHeight = blockHeight
	m.TokenURI = tokenURI
	m.MetadataCID = metadataCID
}

// SetIPFSPayloadHash records hex(SHAKE-256 with org) of the exact bytes pinned
// under IPFSCID — i.e. the mint receipt's PayloadHash.
//
// It is set AFTER mint.Mint() returns (the receipt is what defines the value),
// and lands on disk because RefreshOnChainProvenance rewrites every container
// once the anchor is resolved. Recording it makes the (expected) difference
// between IPFSPayloadHash and FileHash explicit, instead of leaving a verifier
// to wonder why a receipt's PayloadHash does not match the signed file's hash:
// the pinned bytes are the clean, pre-signature original, while FileHash covers
// the final signed file.
func SetIPFSPayloadHash(m *Meta, payloadHashHex string) {
	if m == nil {
		return
	}
	p := OnChainData(m)
	p.IPFSPayloadHash = payloadHashHex
	ApplyOnChainData(m, p)
}

// SetNFTMetadata records the NFT display name and description typed on the
// Mint Data screen before signing. Mirrors SetAnchorEconomics: known from
// the mint form up front, so it's populated before EmbedSignature writes
// the container rather than being reconstructed later from the pinned
// metadata JSON (which may be unreachable or, for a bare non-collection
// mint, never uploaded at all).
func SetNFTMetadata(m *Meta, name, description string) {
	if m == nil {
		return
	}
	m.NFTName = name
	m.NFTDescription = description
}

// SetAnchorEconomics records the embedded economics frozen at mint time
// (resale royalty in basis points, per-licensed-access fee in decimal nSPX,
// and an optional payout override). These travel with the signed document so
// a verifier can see what terms were attached to this anchor without
// consulting the chain. Zero/empty = legacy no-terms token.
func SetAnchorEconomics(m *Meta, royaltyBPS uint64, usageFeeNSPX, royaltyRecipient string) {
	if m == nil {
		return
	}
	m.RoyaltyBPS = royaltyBPS
	m.UsageFeeNSPX = usageFeeNSPX
	m.RoyaltyRecipient = royaltyRecipient
}

// SetAnchorFee records the policy-priced mint fee (in nSPX) the anchor
// transaction carried as its Amount, plus the on-chain account nonce that
// transaction consumed. A nil/non-positive fee leaves any already-recorded
// price untouched — provenance is never downgraded to "n/a" once known.
// The nonce is always recorded (including a legitimate nonce of 0) as a
// decimal string so an unset value ("") stays distinguishable from zero.
func SetAnchorFee(m *Meta, mintFeeNSPX *big.Int, anchorNonce uint64) {
	if m == nil {
		return
	}
	if mintFeeNSPX != nil && mintFeeNSPX.Sign() > 0 {
		m.MintFeeNSPX = mintFeeNSPX.String()
	}
	m.AnchorNonce = strconv.FormatUint(anchorNonce, 10)
}

// StampAnchorProvenance records the post-anchor provenance: the broadcast
// anchor txid, the local anchor sidecar path, the deterministic mint id, the
// SIP-721 token binding (0/"" for a plain receipt anchor), and the confirming
// block (height + hash; pass blockHash "" while unconfirmed to store the
// explicit "pending" sentinel).
//
// It REFUSES an empty anchorTxID: stamping "unanchored" data as if it were
// anchored would let a verify screen render an anchor that never happened.
func StampAnchorProvenance(m *Meta, anchorTxID, anchorPath, mintID string, tokenID uint64, contractAddress string, confirmedHeight uint64, blockHash string) error {
	if m == nil {
		return errors.New("nil meta")
	}
	if strings.TrimSpace(anchorTxID) == "" {
		return errors.New("empty anchor txid — refusing to stamp unanchored provenance")
	}
	m.MintID = mintID
	m.AnchorTxID = anchorTxID
	m.AnchorPath = anchorPath
	m.TokenID = tokenID
	m.ContractAddress = contractAddress
	m.ConfirmedHeight = confirmedHeight
	if h := strings.TrimSpace(blockHash); h != "" {
		m.BlockHash = h
	} else {
		m.BlockHash = "pending"
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// ON-CHAIN RENDERING — every container shows the same on-chain facts
// ─────────────────────────────────────────────────────────────────────────────

// provenanceLine renders a single field with an explicit sentinel when the
// value is missing/unset, so verify screens never mistake "no data" for a
// confirmed anchor.
func provenanceLine(label, value, emptySentinel string) string {
	if strings.TrimSpace(value) == "" {
		return fmt.Sprintf("%s: %s", label, emptySentinel)
	}
	return fmt.Sprintf("%s: %s", label, value)
}

// provenanceHeightLine renders a uint64 height with a "pending" sentinel for 0.
func provenanceHeightLine(label string, height uint64) string {
	if height == 0 {
		return fmt.Sprintf("%s: pending", label)
	}
	return fmt.Sprintf("%s: %d", label, height)
}

// FormatMintFeeNSPX renders a policy-priced fee recorded at mint time
// ("n/a" when unset). The exact nSPX amount is always shown; a human-readable
// SPX equivalent is appended when the value parses as a positive integer.
// The raw nSPX string is what travels in Meta, so the on-chain price is
// preserved at the exact precision the anchor transaction carried.
func FormatMintFeeNSPX(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	v, ok := new(big.Int).SetString(strings.TrimSpace(raw), 10)
	if !ok || v.Sign() <= 0 {
		return fmt.Sprintf("%s nSPX", strings.TrimSpace(raw))
	}
	spx := new(big.Float).SetPrec(200).Quo(
		new(big.Float).SetPrec(200).SetInt(v),
		big.NewFloat(1e18),
	)
	spxValue, _ := spx.Float64()
	return fmt.Sprintf("%s nSPX (~%.6f SPX)", strings.TrimSpace(raw), spxValue)
}

// Block renders the compact multi-line on-chain summary used by the
// human-readable verification block and by the XMP / Office container fields.
func (p OnChainProvenance) Block() string {
	lines := []string{
		"--- On-Chain / Storage ---",
		provenanceLine("MintPrice", FormatMintFeeNSPX(p.MintFeeNSPX), "n/a"),
		provenanceLine("MintID", p.MintID, "unanchored"),
		provenanceLine("CID", p.IPFSCID, "unpinned"),
		provenanceHeightLine("MintHeight", p.BlockHeight),
		provenanceLine("AnchorTx", p.AnchorTxID, "unanchored"),
		provenanceHeightLine("Confirmed", p.ConfirmedHeight),
		provenanceLine("BlockHash", p.BlockHash, "pending"),
		provenanceLine("TxNonce", p.AnchorNonce, "n/a"),
	}
	if p.TokenID != 0 {
		lines = append(lines, fmt.Sprintf("TokenID: %d", p.TokenID))
	}
	if p.ContractAddress != "" {
		lines = append(lines, provenanceLine("Contract", p.ContractAddress, "n/a"))
	}
	if p.TokenURI != "" {
		lines = append(lines, provenanceLine("TokenURI", p.TokenURI, "n/a"))
	}
	if p.NFTName != "" {
		lines = append(lines, provenanceLine("NFTName", p.NFTName, "n/a"))
	}
	if p.NFTDescription != "" {
		lines = append(lines, provenanceLine("NFTDescription", p.NFTDescription, "n/a"))
	}
	if p.RoyaltyBPS != 0 || p.UsageFeeNSPX != "" || p.RoyaltyRecipient != "" {
		lines = append(lines,
			provenanceLine("RoyaltyBPS", fmt.Sprintf("%d", p.RoyaltyBPS), "n/a"),
			provenanceLine("UsageFeeNSPX", FormatMintFeeNSPX(p.UsageFeeNSPX), "n/a"),
			provenanceLine("RoyaltyRecipient", p.RoyaltyRecipient, "n/a"),
		)
	}
	return strings.Join(lines, "\n")
}

// DetailBlock renders the full on-chain provenance block used in the PDF /
// Office cryptographic metadata (every on-chain field, always present, with
// an explicit sentinel when unset).
func (p OnChainProvenance) DetailBlock() string {
	tokenID := "Token ID: n/a (legacy receipt anchor — no collection)"
	if p.TokenID != 0 {
		tokenID = fmt.Sprintf("Token ID: %d", p.TokenID)
	}
	return strings.Join([]string{
		"--- On-Chain / Storage Provenance ---",
		provenanceLine("Mint Price", FormatMintFeeNSPX(p.MintFeeNSPX), "n/a"),
		provenanceLine("Mint ID", p.MintID, "unanchored"),
		provenanceLine("IPFS CID", p.IPFSCID, "unpinned"),
		provenanceHeightLine("Mint Block Height", p.BlockHeight),
		provenanceLine("Anchor TxID", p.AnchorTxID, "unanchored"),
		provenanceLine("Anchor Path", p.AnchorPath, "unanchored"),
		provenanceHeightLine("Confirmed Height", p.ConfirmedHeight),
		provenanceLine("Block Hash", p.BlockHash, "pending"),
		provenanceLine("Tx Nonce", p.AnchorNonce, "n/a"),
		provenanceLine("Token URI", p.TokenURI, "n/a"),
		provenanceLine("Metadata CID", p.MetadataCID, "n/a"),
		provenanceLine("NFT Name", p.NFTName, "n/a"),
		provenanceLine("NFT Description", p.NFTDescription, "n/a"),
		provenanceLine("RoyaltyBPS", fmt.Sprintf("%d", p.RoyaltyBPS), "n/a"),
		provenanceLine("UsageFeeNSPX", FormatMintFeeNSPX(p.UsageFeeNSPX), "n/a"),
		provenanceLine("RoyaltyRecipient", p.RoyaltyRecipient, "n/a"),
		tokenID,
		provenanceLine("Contract", p.ContractAddress, "n/a (no collection)"),
	}, "\n")
}

// OnChainBlock renders Meta's compact on-chain summary (see
// OnChainProvenance.Block).
func OnChainBlock(m *Meta) string { return OnChainData(m).Block() }

// OnChainDetailBlock renders Meta's full on-chain provenance block (see
// OnChainProvenance.DetailBlock).
func OnChainDetailBlock(m *Meta) string { return OnChainData(m).DetailBlock() }
