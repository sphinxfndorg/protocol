// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/provenance_test.go
package gui

import (
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/storage"
	"github.com/sphinxfndorg/protocol/src/usi/core/sign"
)

// TestAssuranceForDoesNotCollapseIntegrityOnly is the core honesty guard for
// this screen. The backend distinguishes three states; the GUI used to render
// both valid states as one plain "SIGNATURE VALID". Mapping INTEGRITY_ONLY onto
// AUTHENTICATED would claim proof of authorship that verification never
// established, because that result only proves the file is self-consistent.
func TestAssuranceForDoesNotCollapseIntegrityOnly(t *testing.T) {
	cases := []struct {
		name string
		in   sign.VerificationResult
		want assuranceLevel
	}{
		{"invalid", sign.VerificationInvalid, assuranceInvalid},
		{"integrity only", sign.VerificationIntegrityOnly, assuranceIntegrityOnly},
		{"fully verified", sign.VerificationFullyVerified, assuranceAuthenticated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := assuranceFor(tc.in); got != tc.want {
				t.Fatalf("assuranceFor(%s) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}

	// The two valid states must remain distinguishable — that is the whole
	// point of not using IsValid() here.
	integrity := assuranceFor(sign.VerificationIntegrityOnly)
	authenticated := assuranceFor(sign.VerificationFullyVerified)
	if integrity == authenticated {
		t.Fatal("integrity-only and authenticated must not render identically")
	}
	// Only the authenticated level may claim it proves who signed.
	if strings.Contains(assuranceDetail(integrity), "proves who signed") {
		t.Fatalf("integrity-only must not claim to prove authorship: %q", assuranceDetail(integrity))
	}
	if !strings.Contains(assuranceDetail(authenticated), "proves who signed") {
		t.Fatalf("authenticated must state that it proves authorship: %q", assuranceDetail(authenticated))
	}
	if assuranceTitle(assuranceInvalid) == assuranceTitle(authenticated) {
		t.Fatal("invalid must not share the authenticated title")
	}
}

// TestAssuranceTitlesAreDistinct keeps the three rendered labels distinct, so a
// user cannot confuse a weak result with a strong one at a glance.
func TestAssuranceTitlesAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, l := range []assuranceLevel{assuranceInvalid, assuranceIntegrityOnly, assuranceAuthenticated} {
		title := assuranceTitle(l)
		if strings.TrimSpace(title) == "" {
			t.Fatal("assurance title must not be empty")
		}
		if seen[title] {
			t.Fatalf("assurance title %q is not distinct", title)
		}
		seen[title] = true
		if strings.TrimSpace(assuranceDetail(l)) == "" {
			t.Fatalf("assurance %q must explain itself", title)
		}
	}
}

// TestPercentageFromBPSIsExact pins the royalty rendering used for embedded
// terms: basis points must convert without float artefacts, since a royalty is
// money and "4.999999%" would misrepresent the frozen on-chain value.
func TestPercentageFromBPSIsExact(t *testing.T) {
	cases := map[uint64]string{
		0:     "0%",
		1:     "0.01%",
		5:     "0.05%",
		10:    "0.1%",
		20:    "0.2%",
		50:    "0.5%",
		125:   "1.25%",
		500:   "5%",
		1000:  "10%",
		10000: "100%",
	}
	for bps, want := range cases {
		if got := percentageFromBPS(bps); got != want {
			t.Fatalf("percentageFromBPS(%d) = %q, want %q", bps, got, want)
		}
	}
}

// TestDescribeMetaTerms covers the three states the backend records: no terms
// (a legacy mint), a full terms set, and a partial one.
func TestDescribeMetaTerms(t *testing.T) {
	// Nil meta is inert, never a panic.
	if got := describeMetaTerms(nil); got != "n/a" {
		t.Fatalf("nil meta must render n/a, got %q", got)
	}

	// Zero/empty terms are a legacy no-terms mint, and must SAY so rather than
	// rendering an empty string that reads as missing data.
	if got := describeMetaTerms(&sign.Meta{}); !strings.Contains(got, "legacy") {
		t.Fatalf("a no-terms mint must be labelled legacy, got %q", got)
	}

	full := &sign.Meta{
		RoyaltyBPS:       500,
		UsageFeeNSPX:     "50000000000000000",
		RoyaltyRecipient: "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
	}
	got := describeMetaTerms(full)
	for _, want := range []string{"5% resale royalty", "per licence", "payout to"} {
		if !strings.Contains(got, want) {
			t.Fatalf("full terms %q must mention %q", got, want)
		}
	}
	// The raw nSPX must survive at full precision — a rounded fee display would
	// misstate what the contract enforces.
	if !strings.Contains(got, "50000000000000000") {
		t.Fatalf("the exact nSPX fee must be shown, got %q", got)
	}

	// A royalty-only mint is still not "legacy".
	royaltyOnly := describeMetaTerms(&sign.Meta{RoyaltyBPS: 250})
	if strings.Contains(royaltyOnly, "legacy") {
		t.Fatalf("a royalty-only mint must not be labelled legacy, got %q", royaltyOnly)
	}
	if !strings.Contains(royaltyOnly, "2.5%") {
		t.Fatalf("expected a 2.5%% royalty, got %q", royaltyOnly)
	}
}

// TestTokenBindingDistinguishesLegacyFromTradeable keeps the marketplace
// consequence explicit: a receipt-only anchor is recorded and anchored, but it
// is NOT listable or tradeable — which is exactly what a bare mint produces.
func TestTokenBindingDistinguishesLegacyFromTradeable(t *testing.T) {
	if got := tokenBinding(nil); got != "n/a" {
		t.Fatalf("nil meta must render n/a, got %q", got)
	}

	// A token id without a contract, or a contract without a token id, is not
	// a real binding: a partial binding is never tradeable.
	if got := tokenBinding(&sign.Meta{}); !strings.Contains(got, "not listable/tradeable") {
		t.Fatalf("a receipt-only anchor must be flagged non-tradeable, got %q", got)
	}
	if got := tokenBinding(&sign.Meta{TokenID: 7}); !strings.Contains(got, "not listable/tradeable") {
		t.Fatalf("a token id without a contract is not tradeable, got %q", got)
	}

	full := tokenBinding(&sign.Meta{
		TokenID:         42,
		ContractAddress: "SPIF 0011 2233 4455 6677 8899 AABB CCDD EEFF 0011 2233 4455 6677 8899 AABB CCDD EEFF",
	})
	if !strings.Contains(full, "#42") || !strings.Contains(full, "in SPIF") {
		t.Fatalf("a collection token must render its id and collection, got %q", full)
	}
	if strings.Contains(full, "not listable") {
		t.Fatalf("a real binding must not be flagged non-tradeable, got %q", full)
	}
}

// TestPinStatusVocabularyMatchesStorage keeps the GUI's verdicts aligned with
// the strings the CLI emits (storage.Durability.String), so the same underlying
// state is never described two different ways depending on which surface the
// user is looking at.
func TestPinStatusVocabularyMatchesStorage(t *testing.T) {
	cases := []struct {
		d         storage.Durability
		title     string
		needsFlag bool
	}{
		{storage.DurabilityRemotePinned, "REPLICATED", false},
		{storage.DurabilityLocalOnly, "LOCAL ONLY", true},
		{storage.DurabilityNotReachable, "NOT REACHABLE", true},
		{storage.DurabilityNotUploaded, "NEVER UPLOADED", true},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		title := pinStatusTitle(tc.d)
		if title != tc.title {
			t.Fatalf("pinStatusTitle(%s) = %q, want %q", tc.d, title, tc.title)
		}
		if seen[title] {
			t.Fatalf("pin status %q is not distinct", title)
		}
		seen[title] = true

		if strings.TrimSpace(pinStatusDetail(tc.d)) == "" {
			t.Fatalf("%s must explain itself", title)
		}
		// ONLY proven replication may be presented without a warning.
		if got := pinStatusNeedsAttention(tc.d); got != tc.needsFlag {
			t.Fatalf("pinStatusNeedsAttention(%s) = %v, want %v", tc.d, got, tc.needsFlag)
		}
	}

	// "never uploaded" and "not reachable" are different problems with
	// different remedies, so their explanations must differ.
	if pinStatusDetail(storage.DurabilityNotUploaded) == pinStatusDetail(storage.DurabilityNotReachable) {
		t.Fatal("never-uploaded and not-reachable must not share an explanation")
	}
	// The never-uploaded explanation must name the only remedy that can fix it.
	if !strings.Contains(pinStatusDetail(storage.DurabilityNotUploaded), "repin") {
		t.Fatalf("the never-uploaded verdict must name the remedy: %q", pinStatusDetail(storage.DurabilityNotUploaded))
	}
}

// TestValueOrAndHeightOrSentinels covers the display rule that makes "no data"
// impossible to mistake for a real value.
func TestValueOrAndHeightOrSentinels(t *testing.T) {
	if got := valueOr("", "unanchored"); got != "unanchored" {
		t.Fatalf("empty value must render its sentinel, got %q", got)
	}
	if got := valueOr("   ", "unanchored"); got != "unanchored" {
		t.Fatalf("whitespace must count as empty, got %q", got)
	}
	if got := valueOr("41aa", "unanchored"); got != "41aa" {
		t.Fatalf("a real value must pass through, got %q", got)
	}

	// Height 0 means "not confirmed yet" and must never render as a real
	// height, while a genuine height must render exactly.
	if got := heightOr(0, "pending"); got != "pending" {
		t.Fatalf("height 0 must render as pending, got %q", got)
	}
	if got := heightOr(16, "pending"); got != "16" {
		t.Fatalf("a real height must render exactly, got %q", got)
	}
	// Large heights must not lose digits through a formatting shortcut.
	if got := heightOr(18446744073709551615, "pending"); got != "18446744073709551615" {
		t.Fatalf("a max height must render all digits, got %q", got)
	}
}
