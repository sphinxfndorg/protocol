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

// TestApplyGenesis_JSONReportsGrossSupply — the audit file must report the
// genesis supply block 0 actually mints (gross = sold + remainder), with sold
// and remainder broken out per allocation. Reporting only the remainder made
// genesis_state.json disagree with the chain by 130,000,000 SPX.
func TestApplyGenesis_JSONReportsGrossSupply(t *testing.T) {
	bc := newMinimalBlockchain(t)
	gs := DefaultGenesisState()

	if err := ApplyGenesis(bc, gs); err != nil {
		t.Fatalf("ApplyGenesis: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(bc.storage.GetStateDir(), "genesis_state.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var snap struct {
		TotalAllocatedSPX string `json:"total_allocated_spx"`
		TotalRemainderSPX string `json:"total_remainder_spx"`
		TotalSoldSPX      string `json:"total_sold_spx"`
		Allocations       []struct {
			Label      string `json:"label"`
			BalanceSPX string `json:"balance_spx"`
			SoldSPX    string `json:"sold_spx"`
			GrossSPX   string `json:"gross_spx"`
		} `json:"allocations"`
	}
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("unmarshal genesis_state.json: %v", err)
	}

	if snap.TotalAllocatedSPX != "1170000000" {
		t.Errorf("total_allocated_spx: want 1170000000 (gross minted), got %s", snap.TotalAllocatedSPX)
	}
	if snap.TotalSoldSPX != "130000000" {
		t.Errorf("total_sold_spx: want 130000000, got %s", snap.TotalSoldSPX)
	}
	if snap.TotalRemainderSPX != "1040000000" {
		t.Errorf("total_remainder_spx: want 1040000000, got %s", snap.TotalRemainderSPX)
	}

	byLabel := map[string][3]string{}
	for _, a := range snap.Allocations {
		byLabel[a.Label] = [3]string{a.BalanceSPX, a.SoldSPX, a.GrossSPX}
	}
	for _, tc := range []struct {
		label                  string
		remainder, sold, gross string
	}{
		{"Founder", "25000000", "5000000", "30000000"},
		{"PublicICOPool", "100000000", "90000000", "190000000"},
		{"Foundation", "300000000", "0", "300000000"},
		{"Airdrops", "90000000", "0", "90000000"},
	} {
		got, ok := byLabel[tc.label]
		if !ok {
			t.Errorf("%s: missing from genesis_state.json allocations", tc.label)
			continue
		}
		if got[0] != tc.remainder || got[1] != tc.sold || got[2] != tc.gross {
			t.Errorf("%s: remainder/sold/gross = %v, want [%s %s %s]",
				tc.label, got, tc.remainder, tc.sold, tc.gross)
		}
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
