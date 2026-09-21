// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/provenance.go
//
// This file is the bridge between what the USI backend RECORDS and what the GUI
// SHOWS. Everything here is either a pure formatter over data the backend
// already produces, or a thin wrapper around a storage/sign helper — never a
// second implementation of a backend rule.
//
// Why this exists: the Verify Data screen used to report a single
// boolean-ish "SIGNATURE VALID", while the backend distinguishes
//
//   - signature ASSURANCE (tri-state: authenticated vs integrity-only), and
//   - payload RETRIEVABILITY (durable vs local-only vs never-uploaded),
//
// and records a full on-chain provenance block that every container writer
// embeds into the file. Collapsing those into one green checkmark presented
// weaker guarantees than the backend actually knew — the opposite of honest
// reporting, and precisely the class of bug the pin work removed.
package gui

import (
	"image/color"
	"strings"

	"github.com/sphinxfndorg/protocol/src/storage"
	"github.com/sphinxfndorg/protocol/src/usi/core/sign"
)

// ─────────────────────────────────────────────────────────────────────────────
// SIGNATURE ASSURANCE
// ─────────────────────────────────────────────────────────────────────────────

// assuranceLevel is how strong a verification result actually is — kept
// separate from "did it verify at all", because the two are different claims.
type assuranceLevel int

const (
	// assuranceInvalid: the signature does not verify, the file was tampered
	// with, or the signer's key is revoked/unknown. Do not trust the file.
	assuranceInvalid assuranceLevel = iota
	// assuranceIntegrityOnly: the signature is self-consistent against the
	// public key carried in the file, and the hash matches. That is
	// tamper-evidence against corruption — but NOT proof of who signed, since
	// nothing stops an attacker from replacing content, signature and key
	// together.
	assuranceIntegrityOnly
	// assuranceAuthenticated: the signature verifies AND the signer's key is
	// registered, active and org-bound in the directory. This is the only
	// result that proves who signed.
	assuranceAuthenticated
)

// assuranceFor maps the backend's tri-state onto display severity. The backend
// documents that consumers "can render the two cases differently"; this is that
// rendering, and it is deliberately NOT IsValid(), which returns true for both
// integrity-only and authenticated results.
func assuranceFor(r sign.VerificationResult) assuranceLevel {
	switch {
	case r.IsFullyVerified():
		return assuranceAuthenticated
	case r.IsValid():
		return assuranceIntegrityOnly
	default:
		return assuranceInvalid
	}
}

func assuranceTitle(l assuranceLevel) string {
	switch l {
	case assuranceAuthenticated:
		return "AUTHENTICATED"
	case assuranceIntegrityOnly:
		return "INTEGRITY ONLY"
	default:
		return "INVALID"
	}
}

// assuranceDetail states what the level does and does not prove, so the user is
// never left to infer it from a colour.
func assuranceDetail(l assuranceLevel) string {
	switch l {
	case assuranceAuthenticated:
		return "Signature is valid and the signer's key is registered and active. This proves who signed the file."
	case assuranceIntegrityOnly:
		return "Signature is self-consistent and the content is unchanged — but the signer's identity could NOT be confirmed against the key directory (offline, or not registered). This is tamper-evidence, not proof of authorship."
	default:
		return "Signature is invalid — the file may have been tampered with, or the signer's key is not accepted."
	}
}

func assuranceColor(l assuranceLevel) color.Color {
	switch l {
	case assuranceAuthenticated:
		return colAccent
	case assuranceIntegrityOnly:
		return colWarn
	default:
		return colDanger
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// PAYLOAD RETRIEVABILITY
// ─────────────────────────────────────────────────────────────────────────────

// pinStatusTitle names the retrievability verdict in the same vocabulary the
// CLI emits (storage.Durability.String), so a user reading either surface sees
// one answer rather than two spellings of the same state.
func pinStatusTitle(d storage.Durability) string {
	switch d {
	case storage.DurabilityRemotePinned:
		return "REPLICATED"
	case storage.DurabilityLocalOnly:
		return "LOCAL ONLY"
	case storage.DurabilityNotReachable:
		return "NOT REACHABLE"
	default:
		return "NEVER UPLOADED"
	}
}

// pinStatusDetail explains what the verdict means for the user, and what (if
// anything) they can do about it.
func pinStatusDetail(d storage.Durability) string {
	switch d {
	case storage.DurabilityRemotePinned:
		return "A public gateway served these bytes, so retrievability does not depend on this machine."
	case storage.DurabilityLocalOnly:
		return "Only local infrastructure could serve these bytes. They become unreachable once this machine's IPFS daemon or gateway goes offline. Configure SPHINX_IPFS_PINNING_SERVICE and SPHINX_IPFS_PINNING_TOKEN to pin new mints durably."
	case storage.DurabilityNotReachable:
		return "A real CID was recorded at mint, but nothing could serve the bytes just now. This may be temporary — a gateway or the pinning service may be offline. It is NOT the same as never having been uploaded."
	default:
		return "Nothing was ever uploaded for this mint: the recorded identifier is a local content hash (spxhash-…), not an IPFS CID, so no node can serve it. The original bytes can only be made retrievable by re-pinning them (sphinx ipfs repin), which refuses to proceed unless the file matches the anchor's commitment."
	}
}

func pinStatusColor(d storage.Durability) color.Color {
	switch d {
	case storage.DurabilityRemotePinned:
		return colAccent
	case storage.DurabilityLocalOnly, storage.DurabilityNotReachable:
		return colWarn
	default:
		return colDanger
	}
}

// pinStatusNeedsAttention reports whether the verdict warrants a warning box
// rather than a quiet info row — i.e. anything short of proven replication.
func pinStatusNeedsAttention(d storage.Durability) bool {
	return d != storage.DurabilityRemotePinned
}

// ─────────────────────────────────────────────────────────────────────────────
// PROVENANCE FIELD FORMATTING
// ─────────────────────────────────────────────────────────────────────────────

// valueOr renders v, or a sentinel when it is empty. Every provenance field is
// optional, so an empty value must never be mistaken for a real one; the
// sentinel says explicitly which kind of "nothing" it is (the sign package uses
// the same convention for the block it embeds into every container).
func valueOr(v, sentinel string) string {
	if strings.TrimSpace(v) == "" {
		return sentinel
	}
	return v
}

// heightOr renders a block height, distinguishing "pending" (the transaction
// exists but has not been mined yet) from a real height.
func heightOr(h uint64, sentinel string) string {
	if h == 0 {
		return sentinel
	}
	return formatUint(h)
}

// formatUint avoids pulling strconv in for display-only formatting.
func formatUint(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// describeMetaTerms renders a document's embedded economics (resale royalty,
// licence fee, payout override) the same way the mint dialog does, so identical
// terms read identically on both screens. Zero/empty terms mean a legacy
// no-terms mint.
func describeMetaTerms(meta *sign.Meta) string {
	if meta == nil {
		return "n/a"
	}
	if meta.RoyaltyBPS == 0 && strings.TrimSpace(meta.UsageFeeNSPX) == "" && strings.TrimSpace(meta.RoyaltyRecipient) == "" {
		return "none (legacy token — no resale royalty, no licensing)"
	}
	var parts []string
	if meta.RoyaltyBPS > 0 {
		parts = append(parts, percentageFromBPS(meta.RoyaltyBPS)+" resale royalty")
	}
	if strings.TrimSpace(meta.UsageFeeNSPX) != "" {
		parts = append(parts, sign.FormatMintFeeNSPX(meta.UsageFeeNSPX)+" per licence")
	}
	if strings.TrimSpace(meta.RoyaltyRecipient) != "" {
		parts = append(parts, "payout to "+truncMiddle(meta.RoyaltyRecipient, 10))
	}
	return strings.Join(parts, " · ")
}

// percentageFromBPS renders basis points as a percentage without float
// artefacts: 500 bps is exactly "5%", 125 bps is "1.25%".
func percentageFromBPS(bps uint64) string {
	if bps == 0 {
		return "0%"
	}
	whole := bps / 100
	frac := bps % 100
	if frac == 0 {
		return formatUint(whole) + "%"
	}
	fracStr := formatUint(frac)
	if len(fracStr) == 1 {
		fracStr = "0" + fracStr
	}
	fracStr = strings.TrimRight(fracStr, "0")
	return formatUint(whole) + "." + fracStr + "%"
}

// tokenBinding renders the SIP-721 binding, distinguishing a real collection
// token from a legacy receipt-only anchor — which is recorded and anchored but
// is NOT listable, buyable or rentable on the Marketplace.
func tokenBinding(meta *sign.Meta) string {
	if meta == nil {
		return "n/a"
	}
	if meta.TokenID == 0 || strings.TrimSpace(meta.ContractAddress) == "" {
		return "n/a (legacy receipt anchor — not listable/tradeable)"
	}
	return "#" + formatUint(meta.TokenID) + " in " + truncMiddle(meta.ContractAddress, 14)
}
