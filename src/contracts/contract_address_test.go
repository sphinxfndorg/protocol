// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/contracts/contract_address_test.go
package contracts

import (
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
)

// TestContractAddressUsesCanonicalSPIFForm locks in the contract-address
// format: a generated contract address must be indistinguishable in shape
// from every other SPIF address on the protocol — "SPIF " followed by 16
// space-separated groups of 4 UPPERCASE hex characters (64 hex total), the
// same rendering identity addresses use (common.FormatSPIFAddress).
//
// The previous derivation returned "SPIF" + 40 lowercase hex (a 20-byte
// sha256 tail), which the Mint Data / Marketplace UI surfaced verbatim and
// which visibly disagreed with the protocol's address scheme.
func TestContractAddressUsesCanonicalSPIFForm(t *testing.T) {
	const sender = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"
	code := []byte(`{"runtime":"native","standard":"sip721","name":"Datasets","symbol":"DSC"}`)

	addr := ContractAddress(sender, 1, code)

	// Shape: "SPIF XXXX XXXX … XXXX" — 16 groups of 4 uppercase hex.
	if !strings.HasPrefix(addr, common.SPIFPrefix+" ") {
		t.Fatalf("contract address must carry the canonical %q prefix followed by a space, got %q", common.SPIFPrefix, addr)
	}
	body := strings.TrimPrefix(addr, common.SPIFPrefix+" ")
	groups := strings.Split(body, " ")
	if len(groups) != 16 {
		t.Fatalf("contract address must be 16 groups of 4 hex characters (64 hex total), got %d groups in %q", len(groups), addr)
	}
	for i, g := range groups {
		if len(g) != 4 {
			t.Fatalf("group %d must be exactly 4 hex characters, got %q", i, g)
		}
		if strings.ToLower(g) != g && strings.ToUpper(g) != g {
			t.Fatalf("group %d must be uniformly cased, got %q", i, g)
		}
		if strings.ToUpper(g) != g {
			t.Fatalf("groups must be uppercase (SPIF canonical display form), got %q", g)
		}
		for _, r := range g {
			if !strings.ContainsRune("0123456789ABCDEF", r) {
				t.Fatalf("group %d contains non-hex character %q", i, r)
			}
		}
	}

	// It must be a valid SPIF address under the canonical normalizer, and
	// normalizing it must round-trip to the same 64 uppercase hex characters
	// every consumer (state keys, ToContract, getcontractstorage) derives
	// from the address string.
	raw, err := common.NormalizeSPIFAddress(addr)
	if err != nil {
		t.Fatalf("generated contract address must be a valid SPIF address: %v", err)
	}
	if len(raw) != 64 {
		t.Fatalf("normalized contract address must be 64 hex characters (32 bytes, same as identity fingerprints), got %d", len(raw))
	}
	if raw != strings.ToUpper(raw) {
		t.Fatalf("normalized form must be uppercase, got %q", raw)
	}

	// Deterministic: prediction (deploycontract RPC) and execution (deploy at
	// block commit) must derive byte-identical addresses from the same inputs.
	if again := ContractAddress(sender, 1, code); again != addr {
		t.Fatalf("ContractAddress must be deterministic:\n got2: %q\n got1: %q", again, addr)
	}

	// Distinct inputs must yield distinct addresses (sender, nonce, code all
	// participate in the derivation).
	if other := ContractAddress(sender, 2, code); other == addr {
		t.Fatal("different nonce must yield a different contract address")
	}
	if other := ContractAddress("BBBCCC", 1, code); other == addr {
		t.Fatal("different sender must yield a different contract address")
	}
	if other := ContractAddress(sender, 1, []byte("different code")); other == addr {
		t.Fatal("different code must yield a different contract address")
	}
}
