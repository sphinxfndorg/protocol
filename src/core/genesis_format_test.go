// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/genesis_format_test.go
package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
)

// TestGenesisAllocationEntryJSONUsesSPIFPrefix — the allocation rows written to
// genesis_state.json must carry the canonical SPIF display form
// ("SPIF XXXX XXXX ...", per common.FormatSPIFAddress), not bare hex.
func TestGenesisAllocationEntryJSONUsesSPIFPrefix(t *testing.T) {
	rawAddrs := []string{
		"F6F666A0F07BB9F1B9C36C0BC497DEF789ACA6B4A7564F88A6277FCBBFD909F8",
		"5000000000000000000000000000000000000001",
	}
	for _, raw := range rawAddrs {
		e := genesisAllocationEntry{
			Address:     raw,
			BalanceNSPX: "10000000000000000000000000",
			BalanceSPX:  "10000000",
			Label:       "Test",
		}
		data, err := json.MarshalIndent(e, "", "  ")
		if err != nil {
			t.Fatalf("marshal %q: %v", raw, err)
		}
		s := string(data)

		want, err := common.FormatSPIFAddress(raw)
		if err != nil {
			t.Fatalf("FormatSPIFAddress(%q): %v", raw, err)
		}
		if !strings.Contains(s, want) {
			t.Errorf("genesis allocation JSON missing canonical SPIF form %q:\n%s", want, s)
		}
		// The contiguous bare hex must not appear (grouped form breaks it up).
		if strings.Contains(s, `"`+raw+`"`) {
			t.Errorf("genesis allocation JSON still contains bare hex %q:\n%s", raw, s)
		}

		// Round-trip: UnmarshalJSON must restore the canonical raw form.
		var decoded genesisAllocationEntry
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal %q: %v", raw, err)
		}
		if decoded.Address != raw {
			t.Errorf("round-trip canonical address mismatch: got %q, want %q", decoded.Address, raw)
		}
	}
}

// TestGenesisAllocationEntryJSONParsesLegacyBareHex — old genesis_state.json
// files with bare-hex addresses must still decode to the canonical raw form.
func TestGenesisAllocationEntryJSONParsesLegacyBareHex(t *testing.T) {
	raw := "F6F666A0F07BB9F1B9C36C0BC497DEF789ACA6B4A7564F88A6277FCBBFD909F8"
	legacy := `{"address":"` + raw + `","balance_nspx":"1","balance_spx":"0","label":"Legacy"}`
	var e genesisAllocationEntry
	if err := json.Unmarshal([]byte(legacy), &e); err != nil {
		t.Fatalf("unmarshal legacy bare hex: %v", err)
	}
	if e.Address != raw {
		t.Errorf("legacy bare hex mismatch: got %q, want %q", e.Address, raw)
	}
}

// TestGenesisValidatorEntryJSONUsesSPIFPrefix — the validator rows written to
// genesis_state.json must carry the canonical SPIF display form as well.
func TestGenesisValidatorEntryJSONUsesSPIFPrefix(t *testing.T) {
	e := genesisValidatorEntry{
		NodeID:    "Node-127.0.0.1:30303",
		Address:   "5000000000000000000000000000000000000001",
		StakeNSPX: "32000000000000000000",
		StakeSPX:  "32",
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want, err := common.FormatSPIFAddress(e.Address)
	if err != nil {
		t.Fatalf("FormatSPIFAddress: %v", err)
	}
	if !strings.Contains(string(data), want) {
		t.Errorf("genesis validator JSON missing canonical SPIF form %q:\n%s", want, data)
	}

	var decoded genesisValidatorEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Address != e.Address {
		t.Errorf("round-trip canonical address mismatch: got %q, want %q", decoded.Address, e.Address)
	}
}

// TestApplyGenesis_JSONAddressesCarrySPIFPrefix — end to end: the
// genesis_state.json file produced by ApplyGenesis records every allocation
// address in canonical SPIF display form, with no bare-hex addresses left.
func TestApplyGenesis_JSONAddressesCarrySPIFPrefix(t *testing.T) {
	bc := newMinimalBlockchain(t)
	gs := minimalGenesisState()

	if err := ApplyGenesis(bc, gs); err != nil {
		t.Fatalf("ApplyGenesis: %v", err)
	}

	jsonPath := filepath.Join(bc.storage.GetStateDir(), "genesis_state.json")
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(raw)

	for _, a := range gs.Allocations {
		want, err := common.FormatSPIFAddress(a.Address)
		if err != nil {
			t.Fatalf("FormatSPIFAddress(%q): %v", a.Address, err)
		}
		if !strings.Contains(content, want) {
			t.Errorf("genesis_state.json missing canonical SPIF address %q", want)
		}
		if strings.Contains(content, `"`+a.Address+`"`) {
			t.Errorf("genesis_state.json still contains bare hex %q", a.Address)
		}
	}
}
