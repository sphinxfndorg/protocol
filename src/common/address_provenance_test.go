package common

import (
	"strings"
	"testing"
)

// TestSPHINCSShapeGateRejectsNonCryptographicAddresses covers the rejection half
// of the defense that src/common can provide on its own.
//
// These are bodies no SPHINCS+ key could have produced: the 40-hex legacy form,
// an odd-length body, a non-hex body, and an empty string. All pass the
// syntactic validators (that is what they are for) and MUST be refused by the
// strict cryptographic gate.
func TestSPHINCSShapeGateRejectsNonCryptographicAddresses(t *testing.T) {
	rejected := []struct {
		name string
		addr string
	}{
		{"40-hex legacy body", "0000000000000000000000000000000000000002"},
		{"40-hex system escrow", "system:staking-fee-pool"},
		{"odd-length body", "ABC"},
		{"non-hex body", strings.Repeat("Z", 64)},
		{"empty", ""},
		{"prefix only", "SPIF"},
		{"too long", strings.Repeat("A", 66)},
	}
	for _, c := range rejected {
		t.Run(c.name, func(t *testing.T) {
			if IsSPHINCSAddressShape(c.addr) {
				t.Fatalf("IsSPHINCSAddressShape(%q) = true; a SPHINCS+-derived body is "+
					"always %d hex characters, so this value cannot be key-derived",
					c.addr, SPHINCSAddressHexLen)
			}
			if err := ValidateSPHINCSAddressShape(c.addr); err == nil {
				t.Fatalf("ValidateSPHINCSAddressShape(%q) returned nil; want a rejection", c.addr)
			}
		})
	}
}

// TestValidateKeyDerivedAddressRejectsFabrication covers the provenance half.
//
// The `derived` value stands in for the address a real public key produces; the
// point is that anything else is refused, even though it is a perfectly
// well-shaped 64-hex SPIF address.
func TestValidateKeyDerivedAddressRejectsFabrication(t *testing.T) {
	derived := strings.Repeat("AB", 32) // 64 hex chars
	if err := ValidateKeyDerivedAddress(derived, derived); err != nil {
		t.Fatalf("the genuinely derived address must be accepted: %v", err)
	}

	// Same address in every spelling the project accepts.
	for _, spelling := range []string{
		derived,
		strings.ToLower(derived),
		SPIFPrefix + " " + derived[:4] + " " + derived[4:],
		"SPIF-" + derived[:4] + "-" + derived[4:8] + "-" + derived[8:],
	} {
		if err := ValidateKeyDerivedAddress(spelling, derived); err != nil {
			t.Fatalf("spelling %q of a genuine address was rejected: %v", spelling, err)
		}
	}

	// Fabricated: well-shaped, SPIF-prefixed, but not what the key derives to.
	for _, fake := range []string{
		strings.Repeat("11", 32),
		SPIFPrefix + " " + strings.Repeat("11", 32),
		DefaultBurnAddress, // real key, wrong org prefix
	} {
		if IsKeyDerivedAddress(fake, derived) {
			t.Fatalf("IsKeyDerivedAddress(%q, %q) = true; a fabricated address must be rejected", fake, derived)
		}
		if err := ValidateKeyDerivedAddress(fake, derived); err == nil {
			t.Fatalf("ValidateKeyDerivedAddress(%q, %q) returned nil; want rejection", fake, derived)
		}
	}
}

// TestFabricatedSPIFAddressIsAccepted documents the KNOWN GAP: src/common's
// validators are purely SYNTACTIC and cannot tell a real SPHINCS+-derived
// address from an invented one.
//
// This test pins the CURRENT (weak) behaviour so that anyone who later hardens
// ValidateAddress sees it flip. It is not an endorsement — the strict gate above
// (IsSPHINCSAddressShape / ValidateKeyDerivedAddress) and the vault's
// ValidateAndNormalizeRecipientsBoundToKeys are the actual defense.
//
// What it shows: an address that was never derived from any key pair is
// accepted by the shape-only validators, and canonicalizes to itself.
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
	// The strict gate is what the rest of the project now uses to refuse it:
	// it is well-shaped, yet it is not the value any given key derives to.
	if !IsSPHINCSAddressShape(spif) {
		t.Fatalf("this fabricated value is well-shaped by construction; the strict gate " +
			"must accept its shape and reject it only via ValidateKeyDerivedAddress")
	}
	if err := ValidateKeyDerivedAddress(spif, strings.Repeat("00", 32)); err == nil {
		t.Fatal("the strict gate accepted a fabricated address against an unrelated key")
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
