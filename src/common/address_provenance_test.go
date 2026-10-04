package common

import (
	"strings"
	"testing"
)

// TestFabricatedSPIFAddressIsAccepted documents a KNOWN GAP: src/common's
// validators are purely SYNTACTIC and cannot tell a real SPHINCS+-derived
// address from an invented one.
//
// This test pins the CURRENT (weak) behaviour so that anyone who later hardens
// ValidateAddress sees it flip. It is not an endorsement.
//
// What it shows: an address that was never derived from any key pair is
// accepted as a protocol address, and canonicalizes to itself.
func TestFabricatedSPIFAddressIsAccepted(t *testing.T) {
	// 64 hex characters that no SPHINCS+ key produced: it is the SPIF prefix
	// plus an all-1s body.
	fake := "1" + strings.Repeat("1", 63)
	spif := SPIFPrefix + " " + fake

	if !ValidateAddress(spif) {
		t.Fatalf("KNOWN GAP CHANGED: ValidateAddress(%q) now rejects a fabricated "+
			"address — good; update this test and re-audit callers", spif)
	}
	if !ValidateSPIFAddress(spif) {
		t.Fatalf("KNOWN GAP CHANGED: ValidateSPIFAddress(%q) now rejects a fabricated "+
			"address — good; update this test", spif)
	}
	if got := CanonicalAddress(spif); got != fake {
		t.Fatalf("canonical form = %q, want %q", got, fake)
	}
	if got := CanonicalSPIFAddress(spif); got != fake {
		t.Fatalf("canonical SPIF form = %q, want %q", got, fake)
	}
	if IsBurnAddress(spif) {
		t.Fatalf("a fabricated SPIF address must not be classified as burn")
	}
}

// TestDefaultBurnAddressIsShapeIdenticalToSPIF shows why shape validation
// cannot prove key provenance.
//
// DefaultBurnAddress and a fabricated SPIF address are indistinguishable by
// shape: same prefix width, same 64-hex body. The burn address's real
// provenance is only provable against its public key, which no address-shaped
// validator consults.
func TestDefaultBurnAddressIsShapeIdenticalToSPIF(t *testing.T) {
	_, rawBurn, err := SplitAddressPrefix(DefaultBurnAddress)
	if err != nil {
		t.Fatalf("SplitAddressPrefix(burn): %v", err)
	}
	prefix, rawFake, err := SplitAddressPrefix("SPIF " + strings.Repeat("A", 64))
	if err != nil {
		t.Fatalf("SplitAddressPrefix(fake SPIF): %v", err)
	}
	if prefix != SPIFPrefix {
		t.Fatalf("prefix = %q, want %q", prefix, SPIFPrefix)
	}
	if len(rawBurn) != len(rawFake) {
		t.Fatalf("body lengths differ: burn %d vs fake %d — shape check would be "+
			"able to distinguish them", len(rawBurn), len(rawFake))
	}
	// Same shape => any length/hex-based check accepts both.
	if !ValidateAddress("SPIF " + strings.Repeat("A", 64)) {
		t.Fatal("fabricated address should pass the same syntactic gate the burn " +
			"address passes; provenance is not part of that gate")
	}
}
