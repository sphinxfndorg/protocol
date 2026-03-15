// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/core/allocation_test.go
package core

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// ============================================================================
// 1. Constructor helpers
// ============================================================================

func TestNewGenesisAllocation_CopiesBalance(t *testing.T) {
	original := big.NewInt(12345)
	a := NewGenesisAllocation("1000000000000000000000000000000000000001", original, "Test")

	// Mutate the original; the allocation must not reflect the change.
	original.SetInt64(999)

	if a.BalanceNSPX.Int64() == 999 {
		t.Error("NewGenesisAllocation did not copy the balance (aliased big.Int)")
	}
	if a.BalanceNSPX.Int64() != 12345 {
		t.Errorf("BalanceNSPX: want 12345, got %d", a.BalanceNSPX.Int64())
	}
}

func TestNewGenesisAllocationSPX_Conversion(t *testing.T) {
	cases := []struct {
		spx      int64
		wantNSPX string
	}{
		{1, "1000000000000000000"},
		{32, "32000000000000000000"},
		{1_000_000, "1000000000000000000000000"},
	}
	for _, tc := range cases {
		a := NewGenesisAllocationSPX("1000000000000000000000000000000000000001", tc.spx, "T")
		if a.BalanceNSPX.String() != tc.wantNSPX {
			t.Errorf("NewGenesisAllocationSPX(%d): want %s nSPX, got %s",
				tc.spx, tc.wantNSPX, a.BalanceNSPX.String())
		}
	}
}

func TestDomainConstructors_Labels(t *testing.T) {
	addr := "1000000000000000000000000000000000000001"
	cases := []struct {
		alloc *GenesisAllocation
		label string
	}{
		{NewFounderAlloc(addr, 1), "Founders"},
		{NewReserveAlloc(addr, 1), "Reserve"},
		{NewTreasuryAlloc(addr, 1), "Treasury"},
		{NewCommunityAlloc(addr, 1), "Community"},
		{NewValidatorAlloc(addr, 1), "Validator"},
	}
	for _, tc := range cases {
		if tc.alloc.Label != tc.label {
			t.Errorf("Label: want %q, got %q", tc.label, tc.alloc.Label)
		}
		if tc.alloc.Address != addr {
			t.Errorf("Address: want %q, got %q", addr, tc.alloc.Address)
		}
	}
}

// ============================================================================
// 2. DefaultGenesisAllocations
// ============================================================================

func TestDefaultGenesisAllocations_Count(t *testing.T) {
	allocs := DefaultGenesisAllocations()
	// The default distribution has 14 entries (3 founders + 2 reserve +
	// 2 treasury + 2 community + 5 validators).
	const want = 14 // ← correct
	if len(allocs) != want {
		t.Errorf("DefaultGenesisAllocations: want %d entries, got %d", want, len(allocs))
	}
}

func TestDefaultGenesisAllocations_TotalSupply(t *testing.T) {
	allocs := DefaultGenesisAllocations()
	total := new(big.Int)
	for _, a := range allocs {
		total.Add(total, a.BalanceNSPX)
	}

	// 1,000,000,000 SPX × 10^18 nSPX/SPX
	wantNSPX := new(big.Int).Mul(big.NewInt(1_000_000_000), big.NewInt(1e18))
	if total.Cmp(wantNSPX) != 0 {
		t.Errorf("total supply: want %s nSPX, got %s nSPX", wantNSPX.String(), total.String())
	}
}

func TestDefaultGenesisAllocations_NoNilBalances(t *testing.T) {
	for i, a := range DefaultGenesisAllocations() {
		if a.BalanceNSPX == nil {
			t.Errorf("allocation[%d] (%s): BalanceNSPX is nil", i, a.Address)
		}
	}
}

func TestDefaultGenesisAllocations_ValidAddresses(t *testing.T) {
	for i, a := range DefaultGenesisAllocations() {
		if len(a.Address) != 40 {
			t.Errorf("allocation[%d]: address length want 40, got %d (%q)",
				i, len(a.Address), a.Address)
		}
		if _, err := hex.DecodeString(a.Address); err != nil {
			t.Errorf("allocation[%d]: address %q is not valid hex: %v", i, a.Address, err)
		}
	}
}

func TestDefaultGenesisAllocations_NoDuplicateAddresses(t *testing.T) {
	seen := make(map[string]bool)
	for i, a := range DefaultGenesisAllocations() {
		key := toLower(a.Address)
		if seen[key] {
			t.Errorf("allocation[%d]: duplicate address %s", i, a.Address)
		}
		seen[key] = true
	}
}

// ============================================================================
// 3. AllocationSummary
// ============================================================================

func TestSummariseAllocations_Empty(t *testing.T) {
	s := SummariseAllocations(nil)
	if s.Count != 0 {
		t.Errorf("Count: want 0, got %d", s.Count)
	}
	if s.TotalNSPX.Sign() != 0 {
		t.Errorf("TotalNSPX: want 0, got %s", s.TotalNSPX.String())
	}
}

func TestSummariseAllocations_ByLabel(t *testing.T) {
	allocs := []*GenesisAllocation{
		NewFounderAlloc("1000000000000000000000000000000000000001", 100),
		NewFounderAlloc("2000000000000000000000000000000000000002", 200),
		NewReserveAlloc("3000000000000000000000000000000000000003", 50),
	}
	s := SummariseAllocations(allocs)

	wantFounders := new(big.Int).Mul(big.NewInt(300), big.NewInt(1e18))
	if s.ByLabel["Founders"].Cmp(wantFounders) != 0 {
		t.Errorf("ByLabel[Founders]: want %s, got %s",
			wantFounders.String(), s.ByLabel["Founders"].String())
	}

	wantReserve := new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18))
	if s.ByLabel["Reserve"].Cmp(wantReserve) != 0 {
		t.Errorf("ByLabel[Reserve]: want %s, got %s",
			wantReserve.String(), s.ByLabel["Reserve"].String())
	}

	wantTotal := new(big.Int).Add(wantFounders, wantReserve)
	if s.TotalNSPX.Cmp(wantTotal) != 0 {
		t.Errorf("TotalNSPX: want %s, got %s", wantTotal.String(), s.TotalNSPX.String())
	}
}

func TestSummariseAllocations_TotalSPX(t *testing.T) {
	allocs := []*GenesisAllocation{
		NewTreasuryAlloc("1000000000000000000000000000000000000001", 1_000_000),
	}
	s := SummariseAllocations(allocs)
	want := big.NewInt(1_000_000)
	if s.TotalSPX.Cmp(want) != 0 {
		t.Errorf("TotalSPX: want %s, got %s", want.String(), s.TotalSPX.String())
	}
}

// ============================================================================
// 4. validate() — internal allocation validator
// ============================================================================

func TestAllocationValidate_Valid(t *testing.T) {
	a := NewGenesisAllocationSPX("abcdef1234567890abcdef1234567890abcdef12", 42, "OK")
	if err := a.validate(); err != nil {
		t.Errorf("valid allocation failed validation: %v", err)
	}
}

func TestAllocationValidate_NilAllocation(t *testing.T) {
	var a *GenesisAllocation
	if err := a.validate(); err == nil {
		t.Error("expected error for nil allocation")
	}
}

func TestAllocationValidate_ShortAddress(t *testing.T) {
	a := NewGenesisAllocationSPX("tooshort", 1, "X")
	if err := a.validate(); err == nil {
		t.Error("expected error for address shorter than 40 chars")
	}
}

func TestAllocationValidate_OddLengthAddress(t *testing.T) {
	// 41 characters — invalid hex length
	a := NewGenesisAllocationSPX("100000000000000000000000000000000000000A1", 1, "X")
	if err := a.validate(); err == nil {
		t.Error("expected error for 41-char address")
	}
}

func TestAllocationValidate_NonHexAddress(t *testing.T) {
	a := NewGenesisAllocationSPX("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", 1, "X")
	if err := a.validate(); err == nil {
		t.Error("expected error for non-hex address")
	}
}

func TestAllocationValidate_NilBalance(t *testing.T) {
	a := &GenesisAllocation{
		Address:     "1000000000000000000000000000000000000001",
		BalanceNSPX: nil,
		Label:       "X",
	}
	if err := a.validate(); err == nil {
		t.Error("expected error for nil BalanceNSPX")
	}
}

func TestAllocationValidate_NegativeBalance(t *testing.T) {
	a := NewGenesisAllocation(
		"1000000000000000000000000000000000000001",
		big.NewInt(-1),
		"X",
	)
	if err := a.validate(); err == nil {
		t.Error("expected error for negative balance")
	}
}

func TestAllocationValidate_ZeroBalanceAllowed(t *testing.T) {
	// Zero balance is technically valid (reserved address with no initial funds).
	a := NewGenesisAllocation(
		"1000000000000000000000000000000000000001",
		big.NewInt(0),
		"Placeholder",
	)
	if err := a.validate(); err != nil {
		t.Errorf("zero-balance allocation should be valid, got: %v", err)
	}
}

// ============================================================================
// 5. deterministicBytes
// ============================================================================

func TestDeterministicBytes_Length(t *testing.T) {
	a := NewGenesisAllocationSPX("abcdef1234567890abcdef1234567890abcdef12", 100, "T")
	b := a.deterministicBytes()
	// Expect exactly 20 (address) + 32 (balance) = 52 bytes.
	const wantLen = 52
	if len(b) != wantLen {
		t.Errorf("deterministicBytes length: want %d, got %d", wantLen, len(b))
	}
}

func TestDeterministicBytes_Deterministic(t *testing.T) {
	a := NewGenesisAllocationSPX("abcdef1234567890abcdef1234567890abcdef12", 100, "T")
	b1 := a.deterministicBytes()
	b2 := a.deterministicBytes()
	if hex.EncodeToString(b1) != hex.EncodeToString(b2) {
		t.Error("deterministicBytes is not deterministic")
	}
}

func TestDeterministicBytes_DifferentAddresses(t *testing.T) {
	a1 := NewGenesisAllocationSPX("1000000000000000000000000000000000000001", 100, "T")
	a2 := NewGenesisAllocationSPX("2000000000000000000000000000000000000002", 100, "T")
	if hex.EncodeToString(a1.deterministicBytes()) == hex.EncodeToString(a2.deterministicBytes()) {
		t.Error("different addresses produced identical deterministicBytes")
	}
}

func TestDeterministicBytes_DifferentBalances(t *testing.T) {
	addr := "1000000000000000000000000000000000000001"
	a1 := NewGenesisAllocationSPX(addr, 100, "T")
	a2 := NewGenesisAllocationSPX(addr, 200, "T")
	if hex.EncodeToString(a1.deterministicBytes()) == hex.EncodeToString(a2.deterministicBytes()) {
		t.Error("different balances produced identical deterministicBytes")
	}
}

// TestDeterministicBytes_LabelIgnored confirms that the Label field has no
// effect on the byte encoding (it is metadata only).
func TestDeterministicBytes_LabelIgnored(t *testing.T) {
	addr := "abcdef1234567890abcdef1234567890abcdef12"
	a1 := NewGenesisAllocationSPX(addr, 100, "Founders")
	a2 := NewGenesisAllocationSPX(addr, 100, "COMPLETELY_DIFFERENT_LABEL")
	if hex.EncodeToString(a1.deterministicBytes()) != hex.EncodeToString(a2.deterministicBytes()) {
		t.Error("Label should not affect deterministicBytes encoding")
	}
}

// ============================================================================
// 6. AllocationSet
// ============================================================================

func TestNewAllocationSet_Valid(t *testing.T) {
	allocs := DefaultGenesisAllocations()
	s, err := NewAllocationSet(allocs)
	if err != nil {
		t.Fatalf("NewAllocationSet: %v", err)
	}
	if s.Len() != len(allocs) {
		t.Errorf("Len: want %d, got %d", len(allocs), s.Len())
	}
}

func TestNewAllocationSet_DuplicateAddress(t *testing.T) {
	addr := "1000000000000000000000000000000000000001"
	_, err := NewAllocationSet([]*GenesisAllocation{
		NewFounderAlloc(addr, 100),
		NewFounderAlloc(addr, 200),
	})
	if err == nil {
		t.Error("expected error for duplicate address in AllocationSet")
	}
}

func TestAllocationSet_Get_CaseInsensitive(t *testing.T) {
	allocs := []*GenesisAllocation{
		NewFounderAlloc("abcdef1234567890abcdef1234567890abcdef12", 100),
	}
	s, err := NewAllocationSet(allocs)
	if err != nil {
		t.Fatalf("NewAllocationSet: %v", err)
	}

	upper := "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
	a, ok := s.Get(upper)
	if !ok {
		t.Error("Get with uppercase address returned ok=false")
	}
	if a == nil {
		t.Fatal("Get returned nil allocation")
	}
	if a.BalanceNSPX.Cmp(new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))) != 0 {
		t.Errorf("balance mismatch: %s", a.BalanceNSPX.String())
	}
}

func TestAllocationSet_Contains(t *testing.T) {
	addr := "1000000000000000000000000000000000000001"
	s, _ := NewAllocationSet([]*GenesisAllocation{NewFounderAlloc(addr, 1)})

	if !s.Contains(addr) {
		t.Errorf("Contains(%q): want true, got false", addr)
	}
	if s.Contains("ffffffffffffffffffffffffffffffffffffffff") {
		t.Error("Contains with unknown address: want false, got true")
	}
}

func TestAllocationSet_TotalSupply(t *testing.T) {
	allocs := []*GenesisAllocation{
		NewFounderAlloc("1000000000000000000000000000000000000001", 100),
		NewReserveAlloc("2000000000000000000000000000000000000002", 400),
	}
	s, _ := NewAllocationSet(allocs)

	wantNSPX := new(big.Int).Mul(big.NewInt(500), big.NewInt(1e18))
	if s.TotalSupplyNSPX().Cmp(wantNSPX) != 0 {
		t.Errorf("TotalSupplyNSPX: want %s, got %s",
			wantNSPX.String(), s.TotalSupplyNSPX().String())
	}

	wantSPX := big.NewInt(500)
	if s.TotalSupplySPX().Cmp(wantSPX) != 0 {
		t.Errorf("TotalSupplySPX: want %s, got %s",
			wantSPX.String(), s.TotalSupplySPX().String())
	}
}

func TestAllocationSet_All_Length(t *testing.T) {
	allocs := DefaultGenesisAllocations()
	s, _ := NewAllocationSet(allocs)
	if len(s.All()) != len(allocs) {
		t.Errorf("All() length: want %d, got %d", len(allocs), len(s.All()))
	}
}

// TestAllocationSet_TotalSupplyMatchesDefaultAllocations is an end-to-end
// check that AllocationSet correctly totals the full genesis distribution.
func TestAllocationSet_TotalSupplyMatchesDefaultAllocations(t *testing.T) {
	allocs := DefaultGenesisAllocations()
	s, err := NewAllocationSet(allocs)
	if err != nil {
		t.Fatalf("NewAllocationSet: %v", err)
	}

	want := new(big.Int).Mul(big.NewInt(1_000_000_000), big.NewInt(1e18))
	if s.TotalSupplyNSPX().Cmp(want) != 0 {
		t.Errorf("TotalSupplyNSPX mismatch: want %s, got %s",
			want.String(), s.TotalSupplyNSPX().String())
	}
}

// ============================================================================
// 7. uint64ToBytes
// ============================================================================

func TestUint64ToBytes(t *testing.T) {
	cases := []struct {
		n    uint64
		want string // big-endian hex
	}{
		{0, "0000000000000000"},
		{1, "0000000000000001"},
		{255, "00000000000000ff"},
		{^uint64(0), "ffffffffffffffff"},
	}
	for _, tc := range cases {
		got := hex.EncodeToString(uint64ToBytes(tc.n))
		if got != tc.want {
			t.Errorf("uint64ToBytes(%d): want %q, got %q", tc.n, tc.want, got)
		}
	}
}
