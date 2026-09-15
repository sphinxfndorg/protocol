// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/deploy_address_test.go
package gui

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/contracts"
)

// TestDeploySpecDerivesCanonicalSPIFCollectionAddress locks in the corrected
// contract-address format for "Deploy New Collection": the deploy payload this
// GUI encodes (identical bytes to DeploySIP721Collection's sip721DeploySpec
// marshal) must derive a collection address in the canonical SPIF display form
// — "SPIF " followed by 16 space-separated groups of 4 UPPERCASE hex
// characters (64 hex total) — the same shape as every identity address.
//
// The node's deploycontract RPC predicts the address from exactly these bytes
// (contracts.ContractAddress(rawFrom, nonce, codeBytes)) and block execution
// derives the identical string, so whatever this returns is what the GUI
// saves, displays, and uses as the on-chain storage key. The previous
// derivation returned "SPIF" + 40 lowercase hex, which the Mint Data /
// Marketplace screens surfaced verbatim and which visibly disagreed with the
// protocol's address scheme.
func TestDeploySpecDerivesCanonicalSPIFCollectionAddress(t *testing.T) {
	const rawOwner = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"

	codeJSON, err := json.Marshal(sip721DeploySpec{
		Runtime:  "native",
		Standard: "sip721",
		Name:     "Datasets",
		Symbol:   "DSC",
		Owner:    rawOwner,
	})
	if err != nil {
		t.Fatalf("marshal deploy spec: %v", err)
	}

	// Every nonce the node could assign (0 = the handler's committed-nonce
	// query, higher = pending reservations) must yield a canonical address.
	for _, nonce := range []uint64{0, 1, 42} {
		addr := contracts.ContractAddress(rawOwner, nonce, codeJSON)

		if !strings.HasPrefix(addr, common.SPIFPrefix+" ") {
			t.Fatalf("deployed collection address must carry the canonical %q prefix followed by a space, got %q", common.SPIFPrefix, addr)
		}
		groups := strings.Split(strings.TrimPrefix(addr, common.SPIFPrefix+" "), " ")
		if len(groups) != 16 {
			t.Fatalf("collection address must be 16 groups of 4 hex characters (64 hex total, same width as identity fingerprints), got %d groups in %q", len(groups), addr)
		}
		for i, g := range groups {
			if len(g) != 4 {
				t.Fatalf("group %d must be exactly 4 hex characters, got %q", i, g)
			}
			if strings.ToUpper(g) != g {
				t.Fatalf("groups must be uppercase (SPIF canonical display form), got %q", g)
			}
		}

		// It must be a valid SPIF address under the canonical normalizer,
		// round-tripping to 64 uppercase hex characters.
		raw, nerr := common.NormalizeSPIFAddress(addr)
		if nerr != nil {
			t.Fatalf("deployed collection address must be a valid SPIF address: %v", nerr)
		}
		if len(raw) != 64 || raw != strings.ToUpper(raw) {
			t.Fatalf("normalized collection address must be 64 uppercase hex, got %q", raw)
		}

		// Canonical form is idempotent: re-rendering the normalized address
		// must produce the identical string, so the form the GUI saves and
		// displays can never drift from the form the node uses as the
		// contract's storage key.
		again, ferr := common.FormatSPIFAddress(raw)
		if ferr != nil || again != addr {
			t.Fatalf("canonical form must be idempotent: %q re-renders as %q (%v)", addr, again, ferr)
		}
	}
}

// TestDeploySIP721CollectionRejectsNonSPIFAddress covers the deploy flow's
// address guard inline through the same predicate it uses: an address that is
// not a valid SPIF address must be rejected rather than saved, and the legacy
// "SPIF"+40-hex form must still be recognized as a VALID (if non-canonical)
// address so contracts deployed by stale nodes remain usable.
func TestDeploySIP721CollectionRejectsNonSPIFAddress(t *testing.T) {
	cases := []struct {
		name string
		addr string
		ok   bool
	}{
		{"canonical grouped form", "SPIF 0866 9081 D8AD 975F CB80 E52F 4F53 C31D 6AF4 A837 AAFF 1BEB 0940 D8D9 6E79 3B5E", true},
		{"legacy prefixed 40-hex", "SPIFc5afe73e094471d6bb49fef65457e279ff47e46f", true},
		{"legacy grouped 40-hex", "SPIF C5AF E73E 0944 71D6 BB49 FEF6 5457 E279 FF47 E46F", true},
		{"raw 64-hex", "08669081D8AD975FCB80E52F4F53C31D6AF4A837AAFF1BEB0940D8D96E793B5E", true},
		{"empty", "", false},
		{"not hex", "SPIF ZZZZ 9081", false},
		{"garbage", "not-an-address", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := common.ValidateSPIFAddress(strings.TrimSpace(tc.addr)); got != tc.ok {
				t.Fatalf("ValidateSPIFAddress(%q) = %v, want %v", tc.addr, got, tc.ok)
			}
		})
	}
}
