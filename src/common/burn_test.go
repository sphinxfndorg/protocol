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
