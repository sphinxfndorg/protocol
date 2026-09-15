// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStateChangeJournalJSONUsesSPIFPrefix(t *testing.T) {
	j := StateChangeJournal{
		Address:         "F6F666A0F07BB9F1B9C36C0BC497DEF789ACA6B4A7564F88A6277FCBBFD909F8",
		PreviousBalance: "10000000000000000000",
		PreviousNonce:   0,
	}

	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// The address must carry the SPIF prefix and the grouped hex form in JSON output.
	s := string(data)
	if !strings.Contains(s, "SPIF") {
		t.Fatalf("journal address did not carry SPIF prefix:\n%s", s)
	}
	// FormatSPIFAddress groups hex into 4-char chunks, so the raw contiguous
	// hex won't appear; verify the grouped components are present instead.
	for _, chunk := range []string{"F6F6", "66A0", "F07B", "B9F1", "B9C3", "6C0B", "C497", "DEF7", "89AC", "A6B4", "A756", "4F88", "A627", "7FCB", "BFD9", "09F8"} {
		if !strings.Contains(s, chunk) {
			t.Fatalf("grouped hex chunk %q missing from SPIF address output:\n%s", chunk, s)
		}
	}

	// Round-trip: UnmarshalJSON must restore the canonical raw-uppercase-hex form.
	var decoded StateChangeJournal
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Address != "F6F666A0F07BB9F1B9C36C0BC497DEF789ACA6B4A7564F88A6277FCBBFD909F8" {
		t.Fatalf("round-trip canonical address mismatch: got %q", decoded.Address)
	}
	if decoded.PreviousBalance != "10000000000000000000" {
		t.Fatalf("round-trip balance mismatch: got %q", decoded.PreviousBalance)
	}
	if decoded.PreviousNonce != 0 {
		t.Fatalf("round-trip nonce mismatch: got %d", decoded.PreviousNonce)
	}
}

func TestStateChangeJournalJSONNonHexAddressPassesThrough(t *testing.T) {
	j := StateChangeJournal{
		Address:         "system:staking-fee-pool",
		PreviousBalance: "50000000000000000000",
		PreviousNonce:   0,
	}

	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "system:staking-fee-pool") {
		t.Fatalf("system address not present in output:\n%s", s)
	}
	if strings.Contains(s, "SPIF") {
		t.Fatalf("system address should not carry SPIF prefix:\n%s", s)
	}

	var decoded StateChangeJournal
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Address != "system:staking-fee-pool" {
		t.Fatalf("round-trip system address mismatch: got %q", decoded.Address)
	}
}

func TestAtomicCommitJournalStateChangesCarrySPIFPrefix(t *testing.T) {
	acj := AtomicCommitJournal{
		BlockHash:       "31666f5d2035546acbe431af99960850cf872465d857a5e9446435c45c348962",
		BlockHeight:     25,
		Phase:           "committed",
		StateChanged: []StateChangeJournal{
			{
				Address:         "F6F666A0F07BB9F1B9C36C0BC497DEF789ACA6B4A7564F88A6277FCBBFD909F8",
				PreviousBalance: "29999999999933803563669400",
				PreviousNonce:   1,
			},
			{
				Address:         "system:staking-fee-pool",
				PreviousBalance: "452968168226526800964",
				PreviousNonce:   0,
			},
		},
		Committed: true,
	}

	data, err := json.MarshalIndent(acj, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)

	// Each SPIF address in the state_changes array must carry the prefix.
	count := 0
	for strings.Contains(s, "SPIF") {
		count++
		s = s[strings.Index(s, "SPIF")+4:]
	}
	if count == 0 {
		t.Fatalf("no SPIF-prefixed address found in atomic commit journal output:\n%s", data)
	}

	// System address must not be prefixed.
	if strings.Contains(string(data), "SPIF system") || strings.Contains(string(data), "system:SPIF") {
		t.Fatalf("system address should not be SPIF-prefixed")
	}
}