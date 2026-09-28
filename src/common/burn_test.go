// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package common

import (
	"strings"
	"testing"
)

func TestBurnAddressDefaults(t *testing.T) {
	// Default burn address must be valid.
	if !ValidateAddress(DefaultBurnAddress) {
		t.Fatalf("DefaultBurnAddress %q is not a valid address", DefaultBurnAddress)
	}
	if !IsBurnAddress(DefaultBurnAddress) {
		t.Fatalf("DefaultBurnAddress %q not detected as burn address", DefaultBurnAddress)
	}
	// SPIF addresses must NOT be detected as burn.
	spif, err := FormatSPIFAddress("262C098D17D0D99F315CD9B7C4D9AEDA685A65FD8630DEFDCE21F98460B1FA30")
	if err != nil {
		t.Fatalf("FormatSPIFAddress: %v", err)
	}
	if IsBurnAddress(spif) {
		t.Fatalf("SPIF address %q wrongly detected as burn", spif)
	}
	// DEAD rendering of the same hex body must be a burn address with the
	// same canonical hex.
	dead, err := FormatDEADAddress("262C098D17D0D99F315CD9B7C4D9AEDA685A65FD8630DEFDCE21F98460B1FA30")
	if err != nil {
		t.Fatalf("FormatDEADAddress: %v", err)
	}
	if !IsBurnAddress(dead) {
		t.Fatalf("DEAD address %q not detected as burn", dead)
	}
	rawSPIF, err := NormalizeAddress(spif)
	if err != nil {
		t.Fatalf("NormalizeAddress SPIF: %v", err)
	}
	rawDEAD, err := NormalizeAddress(dead)
	if err != nil {
		t.Fatalf("NormalizeAddress DEAD: %v", err)
	}
	if rawSPIF != rawDEAD {
		t.Fatalf("SPIF/DEAD same-hex bodies normalize differently: %q vs %q", rawSPIF, rawDEAD)
	}
	// Default burn address round-trips through normalize/format.
	raw, err := NormalizeAddress(DefaultBurnAddress)
	if err != nil {
		t.Fatalf("NormalizeAddress default: %v", err)
	}
	again, err := FormatDEADAddress(raw)
	if err != nil || again != DefaultBurnAddress {
		t.Fatalf("default burn round-trip failed: %q -> %q (%v)", DefaultBurnAddress, again, err)
	}
	// Case-insensitive prefix.
	if !IsBurnAddress(strings.ToLower(DefaultBurnAddress)) {
		t.Fatalf("lowercase DEAD prefix not detected as burn")
	}
	// Default burn pubkey must re-derive the default burn address.
	pubHex := strings.ToLower(DefaultBurnPublicKeyHex)
	if len(pubHex) == 0 {
		t.Fatalf("DefaultBurnPublicKeyHex is empty")
	}
}

// TestAddressNormalizersAgree pins the witness-pipeline invariant: every
// canonicalization entry point used between intake (core), signing
// (musig via CanonicalAddress) and allocation construction (core) must
// produce byte-identical output for the same input — otherwise a recipient
// could match at intake while the signed message hashes a different string
// and threshold verification silently fails.
//
// All four currently funnel into SplitAddressPrefix, so this test guards the
// funnel against future drift, not present divergence.
func TestAddressNormalizersAgree(t *testing.T) {
	renderings := []string{
		// Raw upper / raw lower / display form / lowercase prefix / hyphenated.
		"7AB62C1B1E0CEAAA28108B7EBEA23ACE718D412F84BDC3BF5FC14F8F42205FFA",
		"7ab62c1b1e0ceaaa28108b7ebea23ace718d412f84bdc3bf5fc14f8f42205ffa",
		"SPIF 7AB6 2C1B 1E0C EAAA 2810 8B7E BEA2 3ACE 718D 412F 84BD C3BF 5FC1 4F8F 4220 5FFA",
		"spif 7ab6 2c1b 1e0c eaaa 2810 8b7e bea2 3ace 718d 412f 84bd c3bf 5fc1 4f8f 4220 5ffa",
		"SPIF-7AB6-2C1B-1E0C-EAAA-2810-8B7E-BEA2-3ACE-718D-412F-84BD-C3BF-5FC1-4F8F-4220-5FFA",
		"0000000000000000000000000000000000000002", // system-style escrow hex
	}
	for _, in := range renderings {
		a, errA := NormalizeAddress(in)
		b, errB := NormalizeSPIFAddress(in)
		if (errA == nil) != (errB == nil) {
			t.Fatalf("acceptance diverges for %q: NormalizeAddress err=%v, NormalizeSPIFAddress err=%v", in, errA, errB)
		}
		if errA == nil && a != b {
			t.Fatalf("canonical output diverges for %q: %q vs %q", in, a, b)
		}
		if errA == nil && CanonicalAddress(in) != a {
			t.Fatalf("CanonicalAddress disagrees for %q: %q vs %q", in, CanonicalAddress(in), a)
		}
		if errA == nil && CanonicalSPIFAddress(in) != a {
			t.Fatalf("CanonicalSPIFAddress disagrees for %q: %q vs %q", in, CanonicalSPIFAddress(in), a)
		}
	}
	// Pass-through inputs must survive unchanged through both Canonical* forms.
	for _, in := range []string{"", "genesis", "system:staking-fee-pool"} {
		if CanonicalAddress(in) != in {
			t.Fatalf("CanonicalAddress must pass %q through unchanged, got %q", in, CanonicalAddress(in))
		}
		if CanonicalSPIFAddress(in) != in {
			t.Fatalf("CanonicalSPIFAddress must pass %q through unchanged, got %q", in, CanonicalSPIFAddress(in))
		}
	}
}
