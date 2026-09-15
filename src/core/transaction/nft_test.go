// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package types

import (
	"testing"
)

// The NFTAnchorPayload is the compact legacy ReturnData schema. Its
// embedded-economics fields (royalty_bps / usage_fee / royalty_recipient)
// must round-trip exactly and the bound checks must mirror the live AnchorTag
// checks in core.ValidateAnchorData so no path can announce unenforceable
// terms.
func TestNFTAnchorPayloadTermsRoundTrip(t *testing.T) {
	_, err := BuildNFTAnchorReturnDataWithTerms(
		"mint0001", "quarterly-report.pdf", "bafkqaccd1234abcd1234abcd1234abcd",
		"c0ffee", 500, "50000000000000000", "F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6", 12345)
	if err != nil {
		t.Fatalf("build anchored payload with terms: %v", err)
	}
	data, err := BuildNFTAnchorReturnDataWithTerms(
		"mint0001", "quarterly-report.pdf", "bafkqaccd1234abcd1234abcd1234abcd",
		"c0ffee", 500, "50000000000000000", "F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6", 12345)
	if err != nil {
		t.Fatalf("build anchored payload with terms: %v", err)
	}
	payload, err := ParseNFTAnchorReturnData(data)
	if err != nil {
		t.Fatalf("parse anchored payload: %v", err)
	}
	if payload.RoyaltyBPS != 500 || payload.UsageFeeNSPX != "50000000000000000" ||
		payload.RoyaltyRecipient != "F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6" {
		t.Fatalf("terms did not round-trip: %#v", payload)
	}
}

func TestNFTAnchorPayloadRejectsInvalidTerms(t *testing.T) {
	// royalty_bps above 10000.
	if _, err := BuildNFTAnchorReturnDataWithTerms("m", "s", "cid", "h", 10001, "", "", 0); err == nil {
		t.Fatal("royalty_bps 10001 must be rejected")
	}
	// usage_fee must be positive decimal nSPX.
	if _, err := BuildNFTAnchorReturnDataWithTerms("m", "s", "cid", "h", 100, "abc", "", 0); err == nil {
		t.Fatal("non-decimal usage_fee must be rejected")
	}
	if _, err := BuildNFTAnchorReturnDataWithTerms("m", "s", "cid", "h", 100, "0", "", 0); err == nil {
		t.Fatal("zero usage_fee must be rejected")
	}
	if _, err := BuildNFTAnchorReturnDataWithTerms("m", "s", "cid", "h", 100, "-5", "", 0); err == nil {
		t.Fatal("negative usage_fee must be rejected")
	}
	// royalty_recipient must be a real SPIF address.
	if _, err := BuildNFTAnchorReturnDataWithTerms("m", "s", "cid", "h", 100, "", "nope", 0); err == nil {
		t.Fatal("malformed royalty_recipient must be rejected")
	}
	// Valid zero-terms payload still builds and parses via the legacy path.
	data, err := BuildNFTAnchorReturnData("m", "s", "cid", "h", 0)
	if err != nil {
		t.Fatalf("legacy builder: %v", err)
	}
	if _, err := ParseNFTAnchorReturnData(data); err != nil {
		t.Fatalf("legacy parse: %v", err)
	}
}
