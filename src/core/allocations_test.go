// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/allocation_test.go
package core

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/sphinxfndorg/protocol/src/policy"
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
		{NewFounderAlloc(addr, 1), "Founder"},
		{NewCoFounderAlloc(addr, 1), "CoFounder"},
		{NewDevelopmentAlloc(addr, 1), "Development"},
		{NewContributorAlloc(addr, 1), "Contributors"},
		{NewFoundationAlloc(addr, 1), "Foundation"},
		{NewCampaignAlloc(addr, 1), "Campaigns"},
		{NewAirdropAlloc(addr, 1), "Airdrops"},
		{NewPublicICOPoolAlloc(addr, 1), "PublicICOPool"},
		{NewReserveAlloc(addr, 1), "Reserve"},
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
	// 9 entries: Founder + CoFounder + Development + Contributors +
	// Foundation + Campaigns + Airdrops + PublicICOPool + Reserve.
	const want = 9
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

	// 1,040,000,000 SPX × 10^18 nSPX/SPX
	wantNSPX := new(big.Int).Mul(big.NewInt(1_040_000_000), big.NewInt(1e18))
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
		// Addresses are normalized (SPIF prefix/spaces stripped) at
		// construction time, and are valid at either 40 hex chars (20-byte
		// legacy/placeholder addresses) or 64 hex chars (32-byte real
		// SPHINCS+ derived addresses).
		if len(a.Address) != 40 && len(a.Address) != 64 {
			t.Errorf("allocation[%d]: address length want 40 or 64, got %d (%q)",
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

// TestDefaultGenesisAllocations_RealRecipientAddresses pins the exact mainnet
// recipient address of every pre-funded account, in order. Addresses are given
// in canonical raw hex (SPIF prefix/spaces stripped, as stored after
// construction-time normalisation). Changing any of these changes the
// allocation Merkle root and therefore the genesis hash — this test guards
// against accidental drift.
func TestDefaultGenesisAllocations_RealRecipientAddresses(t *testing.T) {
	want := []string{
		"7AB62C1B1E0CEAAA28108B7EBEA23ACE718D412F84BDC3BF5FC14F8F42205FFA", // Founder
		"991175EA129E8680A36B1A343103E0C3D66F6333973120BA7E7E5FACC45FB3C0", // CoFounder
		"6AC57C53E6287C19AE5865BC958DCDFC5AAF982689590D117379B2CBD4A85156", // Development
		"064C84E204356BA407C40825AE2F47807E19DA9600A91111C22BDC615680C7EF", // Contributors
		"AD198DF96B76F9F72E2DB336AFB46424C4BE01BF45BB8145151A9F249F461890", // Foundation
		"B7CABAC653D2D7B0D01C189DE6128C6311EBC93B70381E9AC14B57A269BDDB9F", // Campaigns
		"34062BDA5176B81697193077F7DC1694069D2C6A88A4B7349A98821D0AD952AF", // Airdrops
		"780D0EFDC57862F180986F02F25CCEA1430CFB7C9460F6C6DE92C34AC3D3591B", // PublicICOPool
		"171FBCCB61C8B697DAA7FC77088196ED387ED81BCC2FA8EECA413E0FE08D60F0", // Reserve
	}

	allocs := DefaultGenesisAllocations()
	if len(allocs) != len(want) {
		t.Fatalf("DefaultGenesisAllocations: want %d entries, got %d", len(want), len(allocs))
	}
	for i, a := range allocs {
		if a.Address != want[i] {
			t.Errorf("allocation[%d] (%s): want address %s, got %s",
				i, a.Label, want[i], a.Address)
		}
	}
}

// TestDefaultGenesisAllocations_CategoryTotals verifies each category carries
// exactly the SPX amount specified in the tokenomics table.
func TestDefaultGenesisAllocations_CategoryTotals(t *testing.T) {
	allocs := DefaultGenesisAllocations()
	s := SummariseAllocations(allocs)

	nspx := func(spx int64) *big.Int {
		return new(big.Int).Mul(big.NewInt(spx), big.NewInt(1e18))
	}

	cases := []struct {
		label   string
		wantSPX int64
	}{
		{"Founder", policy.CGEFounderSPX},
		{"CoFounder", policy.CGECoFounderSPX},
		{"Development", policy.CGEDevelopmentSPX},
		{"Contributors", policy.CGEContributorsSPX},
		{"Foundation", policy.CGEFoundationSPX},
		{"Campaigns", policy.CGECampaignsSPX},
		{"Airdrops", policy.CGEAirdropsSPX},
		{"PublicICOPool", policy.CGEPublicICOPoolSPX},
		{"Reserve", policy.CGEReserveSPX},
	}

	for _, tc := range cases {
		got, ok := s.ByLabel[tc.label]
		if !ok {
			t.Errorf("label %q not found in summary", tc.label)
			continue
		}
		want := nspx(tc.wantSPX)
		if got.Cmp(want) != 0 {
			t.Errorf("ByLabel[%q]: want %s nSPX, got %s", tc.label, want.String(), got.String())
		}
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
		NewDevelopmentAlloc("3000000000000000000000000000000000000003", 50),
	}
	s := SummariseAllocations(allocs)

	wantFounder := new(big.Int).Mul(big.NewInt(300), big.NewInt(1e18))
	if s.ByLabel["Founder"].Cmp(wantFounder) != 0 {
		t.Errorf("ByLabel[Founder]: want %s, got %s",
			wantFounder.String(), s.ByLabel["Founder"].String())
	}

	wantDev := new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18))
	if s.ByLabel["Development"].Cmp(wantDev) != 0 {
		t.Errorf("ByLabel[Development]: want %s, got %s",
			wantDev.String(), s.ByLabel["Development"].String())
	}

	wantTotal := new(big.Int).Add(wantFounder, wantDev)
	if s.TotalNSPX.Cmp(wantTotal) != 0 {
		t.Errorf("TotalNSPX: want %s, got %s", wantTotal.String(), s.TotalNSPX.String())
	}
}

func TestSummariseAllocations_TotalSPX(t *testing.T) {
	allocs := []*GenesisAllocation{
		NewFoundationAlloc("1000000000000000000000000000000000000001", 1_000_000),
	}
	s := SummariseAllocations(allocs)
	want := big.NewInt(1_000_000)
	if s.TotalSPX.Cmp(want) != 0 {
		t.Errorf("TotalSPX: want %s, got %s", want.String(), s.TotalSPX.String())
	}
}

// TestSummariseAllocations_GrossIncludesSold pins the audit split: the summary
// exposes sold/remainder/gross, and gross (not the remainder) is what block 0
// mints — reporting the remainder alone understates supply by the sold amount.
func TestSummariseAllocations_GrossIncludesSold(t *testing.T) {
	s := SummariseAllocations(DefaultGenesisAllocations())
	nspx := func(spx int64) *big.Int {
		return new(big.Int).Mul(big.NewInt(spx), big.NewInt(1e18))
	}

	if s.TotalNSPX.Cmp(nspx(1_040_000_000)) != 0 {
		t.Errorf("TotalNSPX (remainder): want 1040000000 SPX, got %s", s.TotalNSPX.String())
	}
	if s.TotalSoldNSPX.Cmp(nspx(130_000_000)) != 0 {
		t.Errorf("TotalSoldNSPX: want 130000000 SPX, got %s", s.TotalSoldNSPX.String())
	}
	if s.TotalGrossNSPX.Cmp(nspx(1_170_000_000)) != 0 {
		t.Errorf("TotalGrossNSPX: want 1170000000 SPX, got %s", s.TotalGrossNSPX.String())
	}

	for _, tc := range []struct {
		label                  string
		remainder, sold, gross int64
	}{
		{"Founder", 25_000_000, 5_000_000, 30_000_000},
		{"CoFounder", 85_000_000, 10_000_000, 95_000_000},
		{"Development", 150_000_000, 20_000_000, 170_000_000},
		{"Contributors", 75_000_000, 5_000_000, 80_000_000},
		{"PublicICOPool", 100_000_000, 90_000_000, 190_000_000},
		{"Foundation", 300_000_000, 0, 300_000_000},
	} {
		if got := s.ByLabel[tc.label]; got == nil || got.Cmp(nspx(tc.remainder)) != 0 {
			t.Errorf("%s remainder = %v, want %d SPX", tc.label, got, tc.remainder)
		}
		if got := s.SoldByLabel[tc.label]; got == nil || got.Cmp(nspx(tc.sold)) != 0 {
			t.Errorf("%s sold = %v, want %d SPX", tc.label, got, tc.sold)
		}
		if got := s.GrossByLabel[tc.label]; got == nil || got.Cmp(nspx(tc.gross)) != 0 {
			t.Errorf("%s gross = %v, want %d SPX", tc.label, got, tc.gross)
		}
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
	a1 := NewGenesisAllocationSPX(addr, 100, "Founder")
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
		NewDevelopmentAlloc("2000000000000000000000000000000000000002", 400),
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

	// Total genesis supply: 1,040,000,000 SPX
	want := new(big.Int).Mul(big.NewInt(1_040_000_000), big.NewInt(1e18))
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
