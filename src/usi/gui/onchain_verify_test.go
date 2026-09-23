// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/onchain_verify_test.go
package gui

import (
	"errors"
	"image/color"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/usi/core/mint"
	"github.com/sphinxfndorg/protocol/src/usi/core/sign"
)

const testAnchorTxID = "41aa14f9ad3f125cd710e564b251ceddb59c7d7240c0d2ee98bd77a477a64acf"

const testRawAddr = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"

const testSPIFAddr = "SPIF AABB CCDD EEFF 0011 2233 4455 6677 8899 AABB CCDD EEFF 0011 2233 4455 6677 8899"

// matchingMetaAndTag builds a file record and an on-chain anchor that agree
// on every field the screen compares, in the DIFFERENT renderings the two
// sources actually use (the file stores raw uppercase hex for addresses, the
// anchor stores the canonical grouped SPIF form).
func matchingMetaAndTag() (*sign.Meta, *mint.AnchorTag) {
	meta := &sign.Meta{
		Signature:        "aabb",
		PublicKey:        "AABB",
		MintID:           "mint-1",
		AnchorTxID:       testAnchorTxID,
		IPFSCID:          "bafy-media",
		ConfirmedHeight:  100,
		BlockHash:        "blockhash-100",
		TokenID:          7,
		ContractAddress:  testRawAddr,
		RoyaltyBPS:       500,
		UsageFeeNSPX:     "50000000000000000",
		RoyaltyRecipient: testRawAddr,
	}
	tag := &mint.AnchorTag{
		Type:             mint.AnchorTagType,
		MintID:           "mint-1",
		Subject:          "freedom.pdf",
		CID:              "bafy-media",
		MinterPublicKey:  "AABB",
		ReceiptHash:      strings.Repeat("11", 32),
		TokenID:          7,
		TokenURI:         "ipfs://bafy-meta",
		Contract:         testSPIFAddr,
		RoyaltyBPS:       500,
		UsageFeeNSPX:     "50000000000000000",
		RoyaltyRecipient: testSPIFAddr,
	}
	return meta, tag
}

// matchingEvidence is what a healthy node answers for that file.
func matchingEvidence(tag *mint.AnchorTag) anchorEvidence {
	return anchorEvidence{
		Found:        true,
		Tag:          tag,
		Conf:         &TxConfirmation{Height: 100, Hash: "blockhash-100"},
		TokenChecked: true,
		TokenOwner:   testRawAddr,
	}
}

// findCheck locates one named row, so a test can assert on that check alone.
func findCheck(t *testing.T, checks []chainCheck, name string) chainCheck {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q check in %+v", name, checks)
	return chainCheck{}
}

// TestEvaluateOnChainVerifiedWhenEverythingMatches is the happy path: the
// anchor exists, its payload passes the node's own validation rules, and
// every value the file records agrees with the chain — including a token
// binding whose address is rendered differently on the two sides.
func TestEvaluateOnChainVerifiedWhenEverythingMatches(t *testing.T) {
	meta, tag := matchingMetaAndTag()
	status, checks := evaluateOnChain(meta, matchingEvidence(tag))

	if status != onChainVerified {
		t.Fatalf("a fully matching anchor must verify, got %s (%+v)", onChainStatusTitle(status), checks)
	}
	for _, name := range []string{"Anchor transaction", "Mint ID", "IPFS CID", "Marketplace token", "Token exists on-chain", "Embedded terms", "Confirming block", "Minter key"} {
		c := findCheck(t, checks, name)
		if c.Status == checkFail || c.Status == checkUnknown {
			t.Fatalf("%s should pass on a matching anchor, got status=%d detail=%q", name, c.Status, c.Detail)
		}
	}
	if inconclusiveChecks(checks) != 0 {
		t.Fatalf("a matching anchor must have no inconclusive checks: %+v", checks)
	}
	if d := onChainStatusDetail(status, 0); !strings.Contains(d, "match") {
		t.Fatalf("verified detail must state the match, got %q", d)
	}
}

// TestEvaluateOnChainMismatches locks in that EVERY disagreement between the
// file's record and the chain is a hard mismatch — each case below changes
// exactly one recorded value (or one node answer).
func TestEvaluateOnChainMismatches(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*sign.Meta, *mint.AnchorTag, *anchorEvidence)
		wantCheck string
	}{
		{
			name:      "mint id",
			mutate:    func(m *sign.Meta, _ *mint.AnchorTag, _ *anchorEvidence) { m.MintID = "other-mint" },
			wantCheck: "Mint ID",
		},
		{
			name:      "ipfs cid",
			mutate:    func(m *sign.Meta, _ *mint.AnchorTag, _ *anchorEvidence) { m.IPFSCID = "bafy-other" },
			wantCheck: "IPFS CID",
		},
		{
			name:      "token id",
			mutate:    func(m *sign.Meta, _ *mint.AnchorTag, _ *anchorEvidence) { m.TokenID = 8 },
			wantCheck: "Marketplace token",
		},
		{
			name: "token contract",
			mutate: func(m *sign.Meta, _ *mint.AnchorTag, _ *anchorEvidence) {
				m.ContractAddress = strings.Repeat("CD", 32)
			},
			wantCheck: "Marketplace token",
		},
		{
			name:      "royalty",
			mutate:    func(m *sign.Meta, _ *mint.AnchorTag, _ *anchorEvidence) { m.RoyaltyBPS = 900 },
			wantCheck: "Embedded terms",
		},
		{
			name:      "usage fee",
			mutate:    func(m *sign.Meta, _ *mint.AnchorTag, _ *anchorEvidence) { m.UsageFeeNSPX = "1" },
			wantCheck: "Embedded terms",
		},
		{
			name: "royalty recipient",
			mutate: func(m *sign.Meta, _ *mint.AnchorTag, _ *anchorEvidence) {
				m.RoyaltyRecipient = strings.Repeat("EF", 32)
			},
			wantCheck: "Embedded terms",
		},
		{
			name:      "block height",
			mutate:    func(m *sign.Meta, _ *mint.AnchorTag, _ *anchorEvidence) { m.ConfirmedHeight = 99 },
			wantCheck: "Confirming block",
		},
		{
			name:      "block hash",
			mutate:    func(m *sign.Meta, _ *mint.AnchorTag, _ *anchorEvidence) { m.BlockHash = "other-block" },
			wantCheck: "Confirming block",
		},
		{
			name:      "minter key",
			mutate:    func(m *sign.Meta, _ *mint.AnchorTag, _ *anchorEvidence) { m.PublicKey = "CCDD" },
			wantCheck: "Minter key",
		},
		{
			name: "tx not found while file claims a block",
			mutate: func(_ *sign.Meta, _ *mint.AnchorTag, ev *anchorEvidence) {
				ev.Found, ev.Tag, ev.Conf = false, nil, nil
				ev.TokenChecked = false
				ev.LookupErr = errors.New("transaction not found on this node")
			},
			wantCheck: "Anchor transaction",
		},
		{
			name: "anchor payload invalid",
			mutate: func(_ *sign.Meta, _ *mint.AnchorTag, ev *anchorEvidence) {
				ev.Tag = nil
				ev.TagErr = errors.New("anchor payload rejected by node validation rules")
			},
			wantCheck: "Anchor payload",
		},
		{
			name: "anchor rejected by node",
			mutate: func(_ *sign.Meta, _ *mint.AnchorTag, ev *anchorEvidence) {
				ev.RejectReason = "invalid nonce: 5 must equal 2"
			},
			wantCheck: "Anchor transaction",
		},
		{
			name:      "token missing from collection",
			mutate:    func(_ *sign.Meta, _ *mint.AnchorTag, ev *anchorEvidence) { ev.TokenMissing = true },
			wantCheck: "Token exists on-chain",
		},
		{
			name: "file claims a token the anchor does not bind",
			mutate: func(_ *sign.Meta, tag *mint.AnchorTag, _ *anchorEvidence) {
				tag.TokenID, tag.TokenURI, tag.Contract = 0, "", ""
			},
			wantCheck: "Marketplace token",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			meta, tag := matchingMetaAndTag()
			ev := matchingEvidence(tag)
			tc.mutate(meta, tag, &ev)

			status, checks := evaluateOnChain(meta, ev)
			if status != onChainMismatch {
				t.Fatalf("a disagreement must be a mismatch, got %s (%+v)", onChainStatusTitle(status), checks)
			}
			if got := findCheck(t, checks, tc.wantCheck); got.Status != checkFail {
				t.Fatalf("%s must fail, got status=%d detail=%q", tc.wantCheck, got.Status, got.Detail)
			}
			// A mismatch is never announced as a pass of any kind.
			headline, _ := combinedVerifyHeadline(assuranceAuthenticated, status)
			if !strings.Contains(headline, "MISMATCH") {
				t.Fatalf("headline for a mismatch must say so, got %q", headline)
			}
			if d := onChainStatusDetail(status, inconclusiveChecks(checks)); !strings.Contains(d, "disagrees") {
				t.Fatalf("mismatch detail must say the chain disagrees, got %q", d)
			}
		})
	}
}

// TestEvaluateOnChainPendingIsNeverVerified covers the "not yet committed"
// states. An unconfirmed anchor that agrees with the file is PENDING — not a
// pass — and an anchor the node cannot see at all does not become a mismatch
// while the file itself only claims "pending" (there is nothing to contradict
// yet), but it still must not verify.
func TestEvaluateOnChainPendingIsNeverVerified(t *testing.T) {
	meta, tag := matchingMetaAndTag()
	meta.ConfirmedHeight, meta.BlockHash = 0, "pending"

	// Chain has not committed it either: both sides agree "pending".
	ev := matchingEvidence(tag)
	ev.Conf = nil
	status, _ := evaluateOnChain(meta, ev)
	if status != onChainPending {
		t.Fatalf("an uncommitted anchor must be pending, got %s", onChainStatusTitle(status))
	}
	if headline, _ := combinedVerifyHeadline(assuranceAuthenticated, status); !strings.Contains(headline, "PENDING") {
		t.Fatalf("pending headline must say so, got %q", headline)
	}
	if !strings.Contains(onChainStatusDetail(status, 0), "Re-run Verify") {
		t.Fatalf("pending detail must tell the user how to finish: %q", onChainStatusDetail(status, 0))
	}

	// The node cannot even see the anchor; the file records pending too.
	ev2 := anchorEvidence{LookupErr: errors.New("transaction not found on this node")}
	status2, checks2 := evaluateOnChain(meta, ev2)
	if status2 != onChainPending {
		t.Fatalf("an invisible anchor with a pending file must stay pending, got %s", onChainStatusTitle(status2))
	}
	if got := findCheck(t, checks2, "Anchor transaction"); got.Status != checkUnknown {
		t.Fatalf("invisible pending anchor must be an inconclusive check, got status=%d", got.Status)
	}
	headline2, _ := combinedVerifyHeadline(assuranceAuthenticated, status2)
	if strings.Contains(headline2, "VERIFIED") {
		t.Fatalf("a pending anchor must never render as VERIFIED: %q", headline2)
	}

	// The chain confirmed while the file still says pending: the chain is
	// authoritative and the file made no false claim, so this is a PASS —
	// with a detail that says the file is merely stale.
	ev3 := matchingEvidence(tag)
	status3, checks3 := evaluateOnChain(meta, ev3)
	if status3 != onChainVerified {
		t.Fatalf("chain-confirmed + file-pending must verify, got %s (%+v)", onChainStatusTitle(status3), checks3)
	}
	b := findCheck(t, checks3, "Confirming block")
	if b.Status != checkPass || !strings.Contains(b.Detail, "file still records pending") {
		t.Fatalf("stale-pending block check must pass and say so, got status=%d detail=%q", b.Status, b.Detail)
	}

	// And the mirror: the file claims a block the node reports uncommitted.
	ev4 := matchingEvidence(tag)
	ev4.Conf = nil
	meta.ConfirmedHeight, meta.BlockHash = 100, "blockhash-100"
	if status4, _ := evaluateOnChain(meta, ev4); status4 != onChainMismatch {
		t.Fatal("a file claiming a block the node reports uncommitted must be a mismatch")
	}
}

// TestEvaluateOnChainNotAnchoredSkipsTheChain: a file with no anchor txid is
// an offline-only artifact. It must be reported as such WITHOUT contacting the
// node and without any check failing — there is no chain claim to disprove.
func TestEvaluateOnChainNotAnchoredSkipsTheChain(t *testing.T) {
	status, checks := evaluateOnChain(&sign.Meta{AnchorTxID: "   "}, anchorEvidence{})
	if status != onChainNotAnchored {
		t.Fatalf("no anchor txid must be not-anchored, got %s", onChainStatusTitle(status))
	}
	if len(checks) != 1 || checks[0].Status != checkSkip {
		t.Fatalf("not-anchored must report a single skipped row, got %+v", checks)
	}
	// A nil meta (no signature metadata at all) behaves the same, never panics.
	if s, _ := evaluateOnChain(nil, anchorEvidence{}); s != onChainNotAnchored {
		t.Fatalf("nil meta must be not-anchored, got %s", onChainStatusTitle(s))
	}
	headline, _ := combinedVerifyHeadline(assuranceAuthenticated, status)
	if !strings.Contains(headline, "NOT ANCHORED") {
		t.Fatalf("not-anchored headline must be explicit, got %q", headline)
	}
}

// TestEvaluateOnChainUnreachableIsNotAPass is the honesty guard that matters
// most: when the node is down NOTHING was verified, so the verdict, the
// detail and the combined headline must all say so.
func TestEvaluateOnChainUnreachableIsNotAPass(t *testing.T) {
	meta, _ := matchingMetaAndTag()
	status, checks := evaluateOnChain(meta, anchorEvidence{TipErr: errors.New("dial 127.0.0.1:8700: connection refused")})

	if status != onChainUnreachable {
		t.Fatalf("a dead node must be unreachable, got %s", onChainStatusTitle(status))
	}
	if len(checks) != 1 || checks[0].Name != "Node reachable" || checks[0].Status != checkFail {
		t.Fatalf("unreachable must report the failed reachability probe, got %+v", checks)
	}
	if d := onChainStatusDetail(status, 0); !strings.Contains(d, "NOT a pass") {
		t.Fatalf("unreachable detail must state it is not a pass: %q", d)
	}
	for _, a := range []assuranceLevel{assuranceAuthenticated, assuranceIntegrityOnly} {
		headline, _ := combinedVerifyHeadline(a, status)
		if !strings.Contains(headline, "UNREACHABLE") {
			t.Fatalf("headline must name the unreachable node, got %q", headline)
		}
		if strings.Contains(headline, "VERIFIED") || strings.Contains(headline, "✓") {
			t.Fatalf("an unchecked chain must never read as verified: %q", headline)
		}
	}
}

// TestEvaluateOnChainNonCriticalUnknownIsInconclusive locks in the rule that a
// single transient storage lookup (token existence) does not sink an
// otherwise-matching anchor, but is still REPORTED as inconclusive rather than
// silently dropped.
func TestEvaluateOnChainNonCriticalUnknownIsInconclusive(t *testing.T) {
	meta, tag := matchingMetaAndTag()
	ev := matchingEvidence(tag)
	ev.TokenOwner = ""
	ev.TokenErr = errors.New("handshake with 127.0.0.1:8700 timed out")

	status, checks := evaluateOnChain(meta, ev)
	if status != onChainVerified {
		t.Fatalf("a transient token lookup must not fail the anchor, got %s (%+v)", onChainStatusTitle(status), checks)
	}
	if got := findCheck(t, checks, "Token exists on-chain"); got.Status != checkUnknown {
		t.Fatalf("token lookup failure must be inconclusive, got status=%d", got.Status)
	}
	if n := inconclusiveChecks(checks); n != 1 {
		t.Fatalf("expected exactly 1 inconclusive check, got %d", n)
	}
	if d := onChainStatusDetail(status, 1); !strings.Contains(d, "1 check(s) were inconclusive") {
		t.Fatalf("status detail must report the inconclusive check: %q", d)
	}
}

// TestOnChainStatusesAreDistinct keeps the five rendered verdicts, their
// explanations and their colours from collapsing into each other — a weak
// state must never look like a pass at a glance.
func TestOnChainStatusesAreDistinct(t *testing.T) {
	all := []onChainStatus{
		onChainVerified, onChainPending, onChainMismatch, onChainNotAnchored, onChainUnreachable,
	}
	seenTitle := map[string]bool{}
	for _, s := range all {
		title := onChainStatusTitle(s)
		if strings.TrimSpace(title) == "" {
			t.Fatal("every status needs a title")
		}
		if seenTitle[title] {
			t.Fatalf("status title %q is not distinct", title)
		}
		seenTitle[title] = true
		if strings.TrimSpace(onChainStatusDetail(s, 0)) == "" {
			t.Fatalf("status %q must explain itself", title)
		}
	}

	// The pass must never share a colour with any non-pass state.
	rgbaKey := func(c color.Color) [4]uint32 {
		r, g, b, a := c.RGBA()
		return [4]uint32{r, g, b, a}
	}
	verifiedKey := rgbaKey(onChainStatusColor(onChainVerified))
	for _, s := range []onChainStatus{onChainPending, onChainMismatch, onChainUnreachable, onChainNotAnchored} {
		if rgbaKey(onChainStatusColor(s)) == verifiedKey {
			t.Fatalf("non-pass state %q must not share the verified colour", onChainStatusTitle(s))
		}
	}
	if rgbaKey(onChainStatusColor(onChainMismatch)) == rgbaKey(onChainStatusColor(onChainPending)) {
		t.Fatal("mismatch (danger) and pending (warning) must not share a colour")
	}

	// The three "not a plain pass" explanations must be materially different:
	// unreachable (could not ask), pending (asked, not committed) and mismatch
	// (asked, contradicts) have different remedies.
	d := map[onChainStatus]string{}
	for _, s := range all {
		d[s] = onChainStatusDetail(s, 0)
	}
	if d[onChainUnreachable] == d[onChainPending] || d[onChainPending] == d[onChainMismatch] || d[onChainUnreachable] == d[onChainMismatch] {
		t.Fatal("unreachable / pending / mismatch must not share an explanation")
	}
	if !strings.Contains(d[onChainMismatch], "Do not trust") {
		t.Fatalf("mismatch detail must warn against trusting the record: %q", d[onChainMismatch])
	}
}

// TestCombinedVerifyHeadlineHonesty pins the one line the screen shows for the
// COMBINED offline + on-chain result.
func TestCombinedVerifyHeadlineHonesty(t *testing.T) {
	// Offline invalid dominates every chain state: a matching anchor cannot
	// authenticate a tampered file.
	for _, s := range []onChainStatus{onChainVerified, onChainPending, onChainMismatch, onChainNotAnchored, onChainUnreachable} {
		if got, _ := combinedVerifyHeadline(assuranceInvalid, s); !strings.Contains(got, "SIGNATURE INVALID") {
			t.Fatalf("invalid signature must dominate (chain=%s): %q", onChainStatusTitle(s), got)
		}
	}

	// The full "onchain + offline" pass is stated as exactly that.
	got, _ := combinedVerifyHeadline(assuranceAuthenticated, onChainVerified)
	if !strings.Contains(got, "OFFLINE + ON-CHAIN VERIFIED") {
		t.Fatalf("combined pass must name both halves, got %q", got)
	}

	// INTEGRITY ONLY must never be dressed up as authorship, whichever way the
	// chain answers.
	for _, s := range []onChainStatus{onChainVerified, onChainPending, onChainMismatch, onChainNotAnchored, onChainUnreachable} {
		got, _ := combinedVerifyHeadline(assuranceIntegrityOnly, s)
		if !strings.Contains(got, "INTEGRITY ONLY") {
			t.Fatalf("integrity-only must keep its label (chain=%s): %q", onChainStatusTitle(s), got)
		}
		if strings.Contains(got, "AUTHENTICATED") {
			t.Fatalf("integrity-only must never claim authentication: %q", got)
		}
	}
	// Chain agreeing with a file's provenance must not be sold as full
	// verification while the offline half is only integrity-level.
	integrityChainMatch, _ := combinedVerifyHeadline(assuranceIntegrityOnly, onChainVerified)
	if strings.Contains(integrityChainMatch, "ON-CHAIN VERIFIED") {
		t.Fatalf("integrity-only must not borrow the full pass wording: %q", integrityChainMatch)
	}
}

// TestChainCheckLineFormat keeps the per-check rows readable and honest: the
// mark is distinct per status, the row names the check, and a detail is never
// a full-length hash (rows are wrapped labels, but 64-char strings are noise).
func TestChainCheckLineFormat(t *testing.T) {
	statuses := []chainCheckStatus{checkPass, checkFail, checkSkip, checkUnknown}
	seen := map[string]bool{}
	for _, s := range statuses {
		mark := chainCheckMark(s)
		if strings.TrimSpace(mark) == "" || seen[mark] {
			t.Fatalf("check mark %q is empty or duplicated", mark)
		}
		seen[mark] = true
		line := chainCheckLine(chainCheck{Name: "Mint ID", Status: s, Detail: "file aabb ≠ anchor ccdd"})
		if !strings.HasPrefix(line, mark+" Mint ID") {
			t.Fatalf("line must lead with its mark and name, got %q", line)
		}
		if !strings.Contains(line, "file aabb ≠ anchor ccdd") {
			t.Fatalf("line must carry its detail, got %q", line)
		}
	}
	if got := chainCheckLine(chainCheck{Name: "IPFS CID", Status: checkPass}); got != "✓ IPFS CID" {
		t.Fatalf("a detail-less row renders as mark + name, got %q", got)
	}
}

// TestGatherAnchorEvidenceUnreachableNodeIsNotAMismatch is the live-feedback
// guard for the gathering layer: pointed at a closed port, the tip probe must
// fail and the verdict must be UNREACHABLE — never a mismatch, never a pass.
func TestGatherAnchorEvidenceUnreachableNodeIsNotAMismatch(t *testing.T) {
	client := NewWalletClient("127.0.0.1:9")
	meta, _ := matchingMetaAndTag()

	ev := client.gatherAnchorEvidence(meta)
	if ev.TipErr == nil {
		t.Fatal("a closed port must fail the reachability probe")
	}
	if ev.Found || ev.Tag != nil {
		t.Fatal("no chain data may be trusted when the node is unreachable")
	}
	status, checks := evaluateOnChain(meta, ev)
	if status != onChainUnreachable {
		t.Fatalf("unreachable node must yield UNREACHABLE, got %s", onChainStatusTitle(status))
	}
	if len(checks) != 1 {
		t.Fatalf("unreachable must be reported as a single failed probe, got %+v", checks)
	}
	headline, _ := combinedVerifyHeadline(assuranceAuthenticated, status)
	if strings.Contains(headline, "VERIFIED") {
		t.Fatalf("an unreachable node must not yield a verified headline: %q", headline)
	}
}
