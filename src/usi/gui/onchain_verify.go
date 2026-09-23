// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/onchain_verify.go
//
// This file is the ON-CHAIN half of the Verify Data screen. The screen
// previously verified only offline data (the SPHINCS+ signature tri-state and
// the IPFS pin) and merely DISPLAYED the provenance recorded in the file —
// its own alert said re-checking those values against the chain was the CLI's
// job. That meant a user could never tell, from the GUI, whether the anchor
// tx / mint id / block / token / terms a file claims actually exist on the
// node the wallet is talking to.
//
// The design mirrors provenance.go: evidence gathering is a thin wrapper over
// the WalletClient's RPC methods, and the VERDICT comes from one pure
// function — evaluateOnChain(meta, evidence) — so every honesty rule is
// directly testable without a node:
//
//   - a transport failure (node down) is UNREACHABLE, never a pass;
//   - a reachable node that does not have the recorded tx is a MISMATCH
//     when the file claims a committed block, and an inconclusive PENDING
//     (not verified) when the file itself records the anchor as pending;
//   - the chain is authoritative when the two disagree about confirmation:
//     "chain confirmed, file still pending" passes (the file made no false
//     claim), "file claims a block, chain says uncommitted" fails;
//   - a terminally rejected anchor tx is always a mismatch — it can never
//     commit, so the file's anchor claim is permanently false.
package gui

import (
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
	"strings"

	"github.com/sphinxfndorg/protocol/src/core"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/rpc"
	"github.com/sphinxfndorg/protocol/src/usi/core/mint"
	"github.com/sphinxfndorg/protocol/src/usi/core/sign"
)

// ─────────────────────────────────────────────────────────────────────────────
// ON-CHAIN VERDICT — the penta-state of the chain check
// ─────────────────────────────────────────────────────────────────────────────

// onChainStatus is the outcome of re-checking a file's recorded provenance
// against the node. Kept separate from the offline assurance level: the two
// answer different questions ("is the signature sound?" vs "does the chain
// agree with what this file claims?") and the screen reports both.
type onChainStatus int

const (
	// onChainUnreachable: the node could not be reached at all. NOTHING was
	// verified on-chain — this must never be rendered as a pass.
	onChainUnreachable onChainStatus = iota
	// onChainMismatch: a reachable node's answer disagrees with the value
	// recorded in the file (missing tx, field mismatch, rejected anchor,
	// invalid anchor payload). The file's on-chain record cannot be trusted.
	onChainMismatch
	// onChainPending: the anchor could not be shown as committed yet —
	// either it is genuinely unconfirmed, the node cannot see it, or a
	// critical lookup failed mid-check. Explicitly NOT a verification pass.
	onChainPending
	// onChainVerified: the anchor tx exists, its payload passes the same
	// core.ValidateAnchorData rules every node runs, every provenance value
	// recorded in the file matches the chain, and the confirming block
	// agrees (or the file honestly records "pending" while the chain has
	// since confirmed).
	onChainVerified
	// onChainNotAnchored: the file carries no anchor txid at all — it was
	// signed offline only, so there is no on-chain data to verify. The
	// offline result stands on its own; this is not a chain pass.
	onChainNotAnchored
)

// onChainStatusTitle is the short label the panel row and detail box show.
// Titles are distinct so a weak state can never be confused with a pass at
// a glance (same rule as assuranceTitle).
func onChainStatusTitle(s onChainStatus) string {
	switch s {
	case onChainVerified:
		return "ANCHOR VERIFIED"
	case onChainPending:
		return "ANCHOR PENDING"
	case onChainMismatch:
		return "ANCHOR MISMATCH"
	case onChainNotAnchored:
		return "NOT ANCHORED — OFFLINE ONLY"
	default:
		return "NODE UNREACHABLE"
	}
}

// onChainStatusColor maps the verdict to the screen's palette.
func onChainStatusColor(s onChainStatus) color.Color {
	switch s {
	case onChainVerified:
		return colAccent
	case onChainMismatch:
		return colDanger
	case onChainPending, onChainUnreachable:
		return colWarn
	default:
		return colMuted
	}
}

// onChainStatusDetail explains what the verdict does and does not prove, so
// the user never has to infer it from a colour — and so UNREACHABLE
// explicitly says it is not a pass. inconclusive counts the non-critical
// checks that could not be completed (see finishOnChain).
func onChainStatusDetail(s onChainStatus, inconclusive int) string {
	base := ""
	switch s {
	case onChainVerified:
		base = "The anchor transaction, its payload commitments, and every provenance value recorded in this file match the node — including the confirming block."
	case onChainPending:
		base = "The anchor could not be shown as committed yet: the node reports it unconfirmed, cannot see it, or a critical lookup failed. Re-run Verify once the next block has been produced."
	case onChainMismatch:
		base = "At least one value recorded in this file disagrees with the node (see the failed checks below). Do not trust this file's on-chain record as-is."
	case onChainNotAnchored:
		base = "This file carries no anchor transaction — it was signed offline only. There is no on-chain data to verify; the offline signature result stands on its own."
	default:
		base = "The node could not be reached, so NOTHING was verified on-chain. This is NOT a pass — retry with the node running."
	}
	if inconclusive > 0 && (s == onChainVerified || s == onChainPending) {
		return fmt.Sprintf("%s %d check(s) were inconclusive — see below.", base, inconclusive)
	}
	return base
}

// ─────────────────────────────────────────────────────────────────────────────
// PER-CHECK RESULTS — what exactly agreed or disagreed
// ─────────────────────────────────────────────────────────────────────────────

// chainCheckStatus is one individual on-chain check's outcome.
type chainCheckStatus int

const (
	// checkPass: the node's answer agrees with the file (or the check is
	// vacuously true, e.g. both sides record legacy no-terms).
	checkPass chainCheckStatus = iota
	// checkFail: the node's answer contradicts the file. Forces the overall
	// verdict to onChainMismatch.
	checkFail
	// checkSkip: the check does not apply (field not recorded on one side,
	// no token binding, no anchor payload to inspect). Never a pass, never
	// a mismatch.
	checkSkip
	// checkUnknown: the check applies but could not be completed (transport
	// or transient node error on that one lookup). Blocks a clean pass only
	// when it is a CRITICAL check (anchor tx / payload / block); a
	// non-critical unknown (token existence) is counted as inconclusive and
	// named in the status detail instead of being silently dropped.
	checkUnknown
)

// chainCheck is one row of the screen's live on-chain verification list.
type chainCheck struct {
	Name   string
	Status chainCheckStatus
	Detail string
}

// chainCheckMark is the glyph shown in front of each check line.
func chainCheckMark(s chainCheckStatus) string {
	switch s {
	case checkPass:
		return "✓"
	case checkFail:
		return "✗"
	case checkSkip:
		return "–"
	default:
		return "?"
	}
}

// chainCheckLine renders one check as the single line the screen shows.
// The detail carries truncated hashes — rows must not be fed full 64-char
// strings (see truncMiddle's comment in theme.go). The line is rendered as a
// wrapping widget.Label (see the Verify screen), never a canvas.Text, so a
// long detail cannot stretch the window.
func chainCheckLine(c chainCheck) string {
	d := strings.TrimSpace(c.Detail)
	if d == "" {
		return chainCheckMark(c.Status) + " " + c.Name
	}
	return chainCheckMark(c.Status) + " " + c.Name + " — " + d
}

// inconclusiveChecks counts the non-critical checks that could not be
// completed, so the status detail can say how many rather than hiding them.
func inconclusiveChecks(checks []chainCheck) int {
	n := 0
	for _, c := range checks {
		if c.Status == checkUnknown {
			n++
		}
	}
	return n
}

// ─────────────────────────────────────────────────────────────────────────────
// EVIDENCE — what the node actually said (gathered off the UI thread)
// ─────────────────────────────────────────────────────────────────────────────

// anchorEvidence is everything the verify flow learned from the node about
// the anchor transaction a file records. Gathering is kept separate from
// evaluation so the verdict (the part that must never lie) is a pure
// function of (recorded file, node answers).
type anchorEvidence struct {
	// TipErr != nil: even a trivial getblockheader failed, so the node is
	// unreachable and no other field below means anything.
	TipErr error

	// LookupErr != nil: gettransaction failed or returned nothing — the
	// node does not have the recorded txid (or rejected the id as invalid).
	// After a successful tip probe this is the NODE's answer, not a
	// transport failure.
	LookupErr error

	// Found: the transaction exists on this node.
	Found bool
	// Tag is the decoded, node-rule-validated mint anchor (nil when the tx
	// is missing, carries no ReturnData, or its payload fails
	// core.ValidateAnchorData — TagErr then says why).
	Tag    *mint.AnchorTag
	TagErr error

	// RejectReason: the node terminally rejected this tx (it can never
	// commit). Takes precedence over everything below.
	RejectReason string
	// Conf is where the tx was committed (nil = not committed yet).
	// ConfErr is a receipt-lookup failure that is NOT a rejection.
	Conf    *TxConfirmation
	ConfErr error

	// Token existence was checked when the anchor binds a SIP-721 token.
	// TokenErr that is not a "does not exist" answer marks the check
	// inconclusive (non-critical) rather than failed.
	TokenChecked bool
	TokenOwner   string
	TokenErr     error
	TokenMissing bool // the contract says the token does not exist
}

// ReadAnchorTx fetches a transaction by id, returning the RAW error so the
// caller can tell "the node does not have it" from a transport failure.
// After gatherAnchorEvidence's tip probe succeeds, any error returned here is
// the node's own answer.
func (c *WalletClient) ReadAnchorTx(txID string) (*types.Transaction, error) {
	resultData, err := rpc.CallRPC(c.nodeAddr, "gettransaction", []interface{}{txID}, 60)
	if err != nil {
		return nil, fmt.Errorf("gettransaction rpc: %w", err)
	}
	if len(resultData) == 0 || string(resultData) == "null" {
		return nil, errors.New("transaction not found on this node")
	}
	var tx types.Transaction
	if err := json.Unmarshal(resultData, &tx); err != nil {
		return nil, fmt.Errorf("parse gettransaction: %w", err)
	}
	return &tx, nil
}

// gatherAnchorEvidence asks the node everything the on-chain check needs.
// It runs OFF the UI thread; every widget update happens later, in the
// caller. Order matters: the tip probe first turns every later transport
// failure into a distinguishable "node answer", and the receipt is queried
// BEFORE the tx body so a terminal rejection overrides whatever the body
// lookup finds (or fails to find).
func (c *WalletClient) gatherAnchorEvidence(meta *sign.Meta) anchorEvidence {
	var ev anchorEvidence

	txID := strings.TrimSpace(meta.AnchorTxID)

	// 1. Reachability probe. If the node will not even answer a header
	// read, everything downstream would be a transport error, and mixing
	// those with "tx not found" is exactly how a dead node gets rendered
	// as a mismatch.
	if hdr, err := c.GetChainTipHeader(); err != nil || hdr == nil {
		if err == nil {
			err = errors.New("empty chain tip header")
		}
		ev.TipErr = err
		return ev
	}

	// 2. Receipt: it answers confirmed / pending / REJECTED, and the
	// rejection reason must override every other observation.
	conf, _, invalidReason, recErr := c.getTxNodeState(txID)
	if recErr != nil {
		ev.ConfErr = recErr
	} else {
		ev.Conf = conf
		if strings.TrimSpace(invalidReason) != "" {
			ev.RejectReason = strings.TrimSpace(invalidReason)
		}
	}

	// 3. Transaction body + anchor payload.
	tx, err := c.ReadAnchorTx(txID)
	if err != nil {
		ev.LookupErr = err
		return ev
	}
	ev.Found = true
	if tx == nil || len(tx.ReturnData) == 0 {
		// The tx exists but carries no anchor payload — the file points at
		// a plain transfer or contract call, not a mint anchor.
		ev.TagErr = errors.New("transaction has no ReturnData — it is not a mint anchor")
		return ev
	}
	// Validate with the SAME rule every node runs at admission and at
	// consensus (core.ValidateAnchorData), then decode. A payload that
	// fails validation is a mismatch: it cannot be what a node committed.
	if verr := core.ValidateAnchorData(tx.ReturnData); verr != nil {
		ev.TagErr = fmt.Errorf("anchor payload rejected by node validation rules: %w", verr)
		return ev
	}
	tag, derr := mint.DeserializeAnchorTag(tx.ReturnData)
	if derr != nil {
		ev.TagErr = fmt.Errorf("decode mint anchor: %w", derr)
		return ev
	}
	ev.Tag = tag

	// 4. Token existence — only meaningful when the anchor binds a token.
	// Runs last because it is an extra storage round-trip.
	if tag.TokenID != 0 && strings.TrimSpace(tag.Contract) != "" {
		ev.TokenChecked = true
		owner, oerr := c.GetSIP721Owner(tag.Contract, fmt.Sprintf("%d", tag.TokenID))
		if oerr == nil {
			ev.TokenOwner = owner
		} else if strings.Contains(oerr.Error(), "does not exist") {
			ev.TokenMissing = true
			ev.TokenErr = oerr
		} else {
			// Transport/transient failure on this one lookup: inconclusive,
			// NOT a failure of the token check.
			ev.TokenErr = oerr
		}
	}
	return ev
}

// ─────────────────────────────────────────────────────────────────────────────
// THE VERDICT — pure, testable, no network
// ─────────────────────────────────────────────────────────────────────────────

// evaluateOnChain compares what the FILE records against what the NODE said
// and returns the overall status plus one row per check.
//
// Honesty rules (all locked in by onchain_verify_test.go):
//
//   - meta without an anchor txid → NOT ANCHORED, before any evidence is
//     considered: an offline-signed file must not be scored against a chain
//     it never touched.
//   - TipErr → UNREACHABLE with a single failed reachability row; no other
//     evidence is trusted.
//   - Any checkFail → MISMATCH, regardless of the other rows.
//   - Critical unknowns (anchor tx, payload, block) or an uncommitted tx →
//     PENDING — never VERIFIED.
//   - Only all-pass (plus at most non-critical unknowns) with a confirmed
//     block → VERIFIED.
func evaluateOnChain(meta *sign.Meta, ev anchorEvidence) (onChainStatus, []chainCheck) {
	// Offline-only file: nothing to check against the chain.
	if meta == nil || strings.TrimSpace(meta.AnchorTxID) == "" {
		return onChainNotAnchored, []chainCheck{{
			Name:   "Anchor transaction",
			Status: checkSkip,
			Detail: "no anchor txid recorded in this file",
		}}
	}

	// Node down: the tip probe failed, so no other field of ev is meaningful.
	if ev.TipErr != nil {
		return onChainUnreachable, []chainCheck{{
			Name:   "Node reachable",
			Status: checkFail,
			Detail: truncMiddle(ev.TipErr.Error(), 40),
		}}
	}

	metaTxID := truncMiddle(strings.TrimSpace(meta.AnchorTxID), 12)
	checks := make([]chainCheck, 0, 10)

	// ── Anchor transaction / payload ─────────────────────────────────────
	switch {
	case ev.RejectReason != "":
		// Terminal: the node refused this tx, so it can never commit. The
		// file's anchor claim is permanently false — mismatch even when the
		// file only records "pending".
		checks = append(checks, chainCheck{
			Name:   "Anchor transaction",
			Status: checkFail,
			Detail: "rejected by node: " + truncMiddle(ev.RejectReason, 60),
		})
	case ev.LookupErr != nil && meta.ConfirmedHeight > 0:
		// The file claims a committed block whose transaction this
		// reachable node does not have: the provenance is fabricated,
		// from another chain, or this node's state contradicts it.
		checks = append(checks, chainCheck{
			Name:   "Anchor transaction",
			Status: checkFail,
			Detail: "file claims block " + formatUint(meta.ConfirmedHeight) +
				" but " + metaTxID + " does not exist on this node",
		})
	case ev.LookupErr != nil:
		// The file itself records the anchor as not-yet-committed, and the
		// node cannot show it either. That agrees as "pending" — but it is
		// NOT a verification pass, so it is unknown (a critical check),
		// which pins the overall verdict to PENDING.
		checks = append(checks, chainCheck{
			Name:   "Anchor transaction",
			Status: checkUnknown,
			Detail: "not found on this node (" + truncMiddle(ev.LookupErr.Error(), 44) + "); file records anchor as pending",
		})
	case !ev.Found:
		// Defensive: lookup "succeeded" without producing a tx.
		checks = append(checks, chainCheck{
			Name:   "Anchor transaction",
			Status: checkUnknown,
			Detail: metaTxID + " not retrievable",
		})
	case ev.TagErr != nil:
		// The tx exists but is not a valid mint anchor under the rules the
		// node itself enforces — the file points at the wrong transaction.
		checks = append(checks, chainCheck{
			Name:   "Anchor payload",
			Status: checkFail,
			Detail: truncMiddle(ev.TagErr.Error(), 60),
		})
	default:
		checks = append(checks, chainCheck{
			Name:   "Anchor transaction",
			Status: checkPass,
			Detail: metaTxID + " found; payload passes node validation",
		})
	}

	// Field comparisons are only possible with a decoded payload.
	if ev.Tag == nil {
		return finishOnChain(ev, checks)
	}
	tag := ev.Tag

	// ── Mint ID ───────────────────────────────────────────────────────────
	switch {
	case strings.TrimSpace(meta.MintID) == "":
		checks = append(checks, chainCheck{Name: "Mint ID", Status: checkSkip, Detail: "file records no mint id"})
	case strings.TrimSpace(meta.MintID) != strings.TrimSpace(tag.MintID):
		checks = append(checks, chainCheck{
			Name:   "Mint ID",
			Status: checkFail,
			Detail: "file " + truncMiddle(meta.MintID, 10) + " ≠ anchor " + truncMiddle(tag.MintID, 10),
		})
	default:
		checks = append(checks, chainCheck{Name: "Mint ID", Status: checkPass, Detail: "matches anchor"})
	}

	// ── IPFS CID ──────────────────────────────────────────────────────────
	switch {
	case strings.TrimSpace(meta.IPFSCID) == "":
		checks = append(checks, chainCheck{Name: "IPFS CID", Status: checkSkip, Detail: "file records no CID"})
	case strings.TrimSpace(meta.IPFSCID) != strings.TrimSpace(tag.CID):
		checks = append(checks, chainCheck{
			Name:   "IPFS CID",
			Status: checkFail,
			Detail: "file " + truncMiddle(meta.IPFSCID, 10) + " ≠ anchor " + truncMiddle(tag.CID, 10),
		})
	default:
		checks = append(checks, chainCheck{Name: "IPFS CID", Status: checkPass, Detail: "matches anchor commitment"})
	}

	// ── SIP-721 token binding ────────────────────────────────────────────
	metaHasToken := meta.TokenID != 0 && strings.TrimSpace(meta.ContractAddress) != ""
	tagHasToken := tag.TokenID != 0 && strings.TrimSpace(tag.Contract) != ""
	switch {
	case !metaHasToken && !tagHasToken:
		checks = append(checks, chainCheck{Name: "Marketplace token", Status: checkSkip, Detail: "legacy receipt anchor — no token on either side"})
	case !metaHasToken || !tagHasToken:
		checks = append(checks, chainCheck{
			Name:   "Marketplace token",
			Status: checkFail,
			Detail: tokenBindingMismatchDetail(meta, tag),
		})
	case meta.TokenID != tag.TokenID || !sameIdentity(meta.ContractAddress, tag.Contract):
		checks = append(checks, chainCheck{
			Name:   "Marketplace token",
			Status: checkFail,
			Detail: fmt.Sprintf("file #%d in %s ≠ anchor #%d in %s",
				meta.TokenID, truncMiddle(meta.ContractAddress, 8),
				tag.TokenID, truncMiddle(tag.Contract, 8)),
		})
	default:
		checks = append(checks, chainCheck{
			Name:   "Marketplace token",
			Status: checkPass,
			Detail: fmt.Sprintf("#%d in %s", tag.TokenID, truncMiddle(tag.Contract, 10)),
		})
	}

	// ── Token existence (contract storage) ───────────────────────────────
	switch {
	case !tagHasToken:
		checks = append(checks, chainCheck{Name: "Token exists on-chain", Status: checkSkip, Detail: "anchor binds no token"})
	case !ev.TokenChecked:
		checks = append(checks, chainCheck{Name: "Token exists on-chain", Status: checkSkip, Detail: "not checked"})
	case ev.TokenMissing:
		checks = append(checks, chainCheck{
			Name:   "Token exists on-chain",
			Status: checkFail,
			Detail: fmt.Sprintf("token #%d does not exist in %s", tag.TokenID, truncMiddle(tag.Contract, 10)),
		})
	case ev.TokenErr != nil:
		// Non-critical: one storage lookup failed while the rest of the
		// node answered. Inconclusive, not a failure.
		checks = append(checks, chainCheck{
			Name:   "Token exists on-chain",
			Status: checkUnknown,
			Detail: truncMiddle(ev.TokenErr.Error(), 44),
		})
	default:
		checks = append(checks, chainCheck{
			Name:   "Token exists on-chain",
			Status: checkPass,
			Detail: "owner " + truncMiddle(ev.TokenOwner, 10),
		})
	}

	// ── Embedded terms, confirming block, minter key ─────────────────────
	checks = append(checks, termsCheck(meta, tag))
	checks = append(checks, blockCheck(meta, ev))
	checks = append(checks, minterKeyCheck(meta, tag))

	return finishOnChain(ev, checks)
}

// tokenBindingMismatchDetail names which side claims the token when only
// one does — "file says token, anchor says none" and its mirror are
// different lies and must read differently.
func tokenBindingMismatchDetail(meta *sign.Meta, tag *mint.AnchorTag) string {
	if meta.TokenID != 0 || strings.TrimSpace(meta.ContractAddress) != "" {
		return fmt.Sprintf("file claims #%d in %s but anchor binds no token",
			meta.TokenID, truncMiddle(meta.ContractAddress, 10))
	}
	return fmt.Sprintf("anchor binds #%d in %s but file records no token",
		tag.TokenID, truncMiddle(tag.Contract, 10))
}

// termsCheck compares the embedded economics the file records against the
// terms frozen into the on-chain anchor. Identical legacy no-terms on both
// sides is a SKIP (vacuously true, nothing to enforce); any disagreement —
// including one side carrying terms the other does not — is a FAIL, because
// the screen's "Embedded Terms" row would otherwise misrepresent what the
// contract enforces.
func termsCheck(meta *sign.Meta, tag *mint.AnchorTag) chainCheck {
	fileTerms := meta.RoyaltyBPS != 0 || strings.TrimSpace(meta.UsageFeeNSPX) != "" || strings.TrimSpace(meta.RoyaltyRecipient) != ""
	chainTerms := tag.RoyaltyBPS != 0 || strings.TrimSpace(tag.UsageFeeNSPX) != "" || strings.TrimSpace(tag.RoyaltyRecipient) != ""
	if !fileTerms && !chainTerms {
		return chainCheck{Name: "Embedded terms", Status: checkSkip, Detail: "none on either side (legacy token)"}
	}
	var mismatches []string
	if meta.RoyaltyBPS != tag.RoyaltyBPS {
		mismatches = append(mismatches, fmt.Sprintf("royalty %s vs %s",
			percentageFromBPS(meta.RoyaltyBPS), percentageFromBPS(tag.RoyaltyBPS)))
	}
	if strings.TrimSpace(meta.UsageFeeNSPX) != strings.TrimSpace(tag.UsageFeeNSPX) {
		mismatches = append(mismatches, "usage fee differs")
	}
	if !sameOrBothEmptyAddress(meta.RoyaltyRecipient, tag.RoyaltyRecipient) {
		mismatches = append(mismatches, "payout recipient differs")
	}
	if len(mismatches) > 0 {
		return chainCheck{Name: "Embedded terms", Status: checkFail, Detail: strings.Join(mismatches, "; ")}
	}
	return chainCheck{
		Name:   "Embedded terms",
		Status: checkPass,
		Detail: percentageFromBPS(tag.RoyaltyBPS) + " royalty, " + termsFeeDetail(tag) + " per licence",
	}
}

// termsFeeDetail renders the anchored licence fee for the pass line.
func termsFeeDetail(tag *mint.AnchorTag) string {
	if strings.TrimSpace(tag.UsageFeeNSPX) == "" {
		return "no fee"
	}
	return sign.FormatMintFeeNSPX(tag.UsageFeeNSPX)
}

// sameOrBothEmptyAddress compares two address renderings where empty == empty
// is a legitimate match (both sides opting out of a payout override), while
// empty vs set is a mismatch. sameIdentity alone would report empty-vs-empty
// as DIFFERENT (it bails on empty input), which would fail every legacy mint.
func sameOrBothEmptyAddress(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return a == b
	}
	return sameIdentity(a, b)
}

// blockCheck is the confirmation comparison, with the asymmetry that keeps
// the screen honest in both directions:
//
//   - chain confirmed + file confirmed  → heights/hashes must agree;
//   - chain confirmed + file pending    → PASS (the chain is authoritative
//     and the file made no false claim — the background provenance poller
//     simply never rewrote it);
//   - chain uncommitted + file claims a block → FAIL (the file claims a
//     confirmation the node does not have);
//   - chain uncommitted + file pending  → the check agrees as pending, but
//     is UNKNOWN (critical), pinning the overall verdict to PENDING;
//   - receipt lookup failed → UNKNOWN (critical): no clean pass without it.
func blockCheck(meta *sign.Meta, ev anchorEvidence) chainCheck {
	if ev.RejectReason != "" {
		return chainCheck{
			Name:   "Confirming block",
			Status: checkFail,
			Detail: "anchor can never commit — rejected: " + truncMiddle(ev.RejectReason, 44),
		}
	}
	if ev.ConfErr != nil {
		return chainCheck{
			Name:   "Confirming block",
			Status: checkUnknown,
			Detail: "receipt lookup failed: " + truncMiddle(ev.ConfErr.Error(), 44),
		}
	}
	if ev.Conf == nil {
		if meta.ConfirmedHeight > 0 {
			return chainCheck{
				Name:   "Confirming block",
				Status: checkFail,
				Detail: "file claims block " + formatUint(meta.ConfirmedHeight) +
					" but node reports the anchor uncommitted",
			}
		}
		return chainCheck{
			Name:   "Confirming block",
			Status: checkUnknown,
			Detail: "node reports the anchor not yet committed; file records pending",
		}
	}
	if meta.ConfirmedHeight == 0 {
		return chainCheck{
			Name:   "Confirming block",
			Status: checkPass,
			Detail: "chain confirmed at " + formatUint(ev.Conf.Height) + "; file still records pending",
		}
	}
	if meta.ConfirmedHeight != ev.Conf.Height {
		return chainCheck{
			Name:   "Confirming block",
			Status: checkFail,
			Detail: "file block " + formatUint(meta.ConfirmedHeight) + " ≠ chain block " + formatUint(ev.Conf.Height),
		}
	}
	if strings.TrimSpace(meta.BlockHash) != "" && meta.BlockHash != "pending" &&
		!strings.EqualFold(strings.TrimSpace(meta.BlockHash), strings.TrimSpace(ev.Conf.Hash)) {
		return chainCheck{
			Name:   "Confirming block",
			Status: checkFail,
			Detail: "file hash " + truncMiddle(meta.BlockHash, 8) + " ≠ chain " + truncMiddle(ev.Conf.Hash, 8),
		}
	}
	return chainCheck{
		Name:   "Confirming block",
		Status: checkPass,
		Detail: "block " + formatUint(ev.Conf.Height) + " matches",
	}
}

// minterKeyCheck compares the signer public key recorded in the file against
// the minter key committed by the on-chain anchor. The anchor's minter key is
// what every node validates at admission, so agreement ties the offline
// signer to the on-chain minter without a trusted lookup. Only checked when
// the anchor carries a key (older anchors may not).
func minterKeyCheck(meta *sign.Meta, tag *mint.AnchorTag) chainCheck {
	if strings.TrimSpace(tag.MinterPublicKey) == "" {
		return chainCheck{Name: "Minter key", Status: checkSkip, Detail: "anchor carries no minter key"}
	}
	if strings.TrimSpace(meta.PublicKey) == "" {
		return chainCheck{Name: "Minter key", Status: checkSkip, Detail: "file records no public key"}
	}
	if !strings.EqualFold(strings.TrimSpace(meta.PublicKey), strings.TrimSpace(tag.MinterPublicKey)) {
		return chainCheck{
			Name:   "Minter key",
			Status: checkFail,
			Detail: "file key " + truncMiddle(meta.PublicKey, 8) + " ≠ anchor minter " + truncMiddle(tag.MinterPublicKey, 8),
		}
	}
	return chainCheck{Name: "Minter key", Status: checkPass, Detail: "matches anchor minter"}
}

// finishOnChain folds the per-check rows into the overall verdict:
// any FAIL → mismatch; a critical UNKNOWN (anchor tx / payload / block, or
// an uncommitted anchor) → pending; otherwise verified. Non-critical
// unknowns are left in the row list (they are counted by
// inconclusiveChecks for the status detail, never silently dropped).
func finishOnChain(ev anchorEvidence, checks []chainCheck) (onChainStatus, []chainCheck) {
	isCritical := func(name string) bool {
		switch name {
		case "Anchor transaction", "Anchor payload", "Confirming block":
			return true
		}
		return false
	}
	for _, c := range checks {
		switch c.Status {
		case checkFail:
			return onChainMismatch, checks
		case checkUnknown:
			if isCritical(c.Name) {
				return onChainPending, checks
			}
		}
	}
	// A rejected tx was already a FAIL above; an anchor that is not shown as
	// committed is pending, not verified — even if every other row passed.
	if ev.RejectReason == "" && ev.Conf == nil {
		return onChainPending, checks
	}
	return onChainVerified, checks
}

// ─────────────────────────────────────────────────────────────────────────────
// COMBINED HEADLINE — offline assurance + on-chain verdict in one line
// ─────────────────────────────────────────────────────────────────────────────

// combinedVerifyHeadline renders the screen's big status line from BOTH
// verifications. Honesty constraints (tested in onchain_verify_test.go):
//
//   - an invalid signature always dominates: a matching anchor cannot
//     rescue a tampered file;
//   - INTEGRITY ONLY never appears beside "AUTHENTICATED" or any claim of
//     proving who signed — the chain agreeing with a file's provenance says
//     nothing about authorship the key directory could not confirm;
//   - UNREACHABLE never appears beside "VERIFIED" or "✓": an unchecked
//     chain is not a checked one, and the offline half is therefore phrased
//     "SIGNATURE VALID" (what was actually established) rather than
//     "OFFLINE VERIFIED" (which a reader could apply to the whole line);
//   - NOT ANCHORED states plainly that only the offline half ran.
//
// Lines are kept short: statusBig is a canvas.Text, which never wraps.
func combinedVerifyHeadline(a assuranceLevel, s onChainStatus) (string, color.Color) {
	if a == assuranceInvalid {
		return "✗  SIGNATURE INVALID", colDanger
	}
	integrity := a == assuranceIntegrityOnly

	switch s {
	case onChainVerified:
		if integrity {
			return "⚠  INTEGRITY ONLY · ANCHOR MATCHES", colWarn
		}
		return "✓  OFFLINE + ON-CHAIN VERIFIED", colAccent
	case onChainMismatch:
		if integrity {
			return "✗  INTEGRITY ONLY — ANCHOR MISMATCH", colDanger
		}
		return "✗  SIGNATURE VALID — ON-CHAIN MISMATCH", colDanger
	case onChainPending:
		if integrity {
			return "⚠  INTEGRITY ONLY — ANCHOR PENDING", colWarn
		}
		return "⚠  SIGNATURE VALID — ANCHOR PENDING", colWarn
	case onChainNotAnchored:
		if integrity {
			return "⚠  INTEGRITY ONLY — NOT ANCHORED", colWarn
		}
		return "✓  SIGNATURE VALID — NOT ANCHORED", colAccent
	default: // onChainUnreachable
		if integrity {
			return "⚠  INTEGRITY ONLY — NODE UNREACHABLE", colWarn
		}
		return "⚠  SIGNATURE VALID — NODE UNREACHABLE", colWarn
	}
}
