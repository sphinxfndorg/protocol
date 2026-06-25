// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/allocation.go
package core

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/sphinxorg/protocol/src/common"
	logger "github.com/sphinxorg/protocol/src/log"
)

// ----------------------------------------------------------------------------
// Constructors
// ----------------------------------------------------------------------------

// NewGenesisAllocation creates a GenesisAllocation whose balance is already
// expressed in nSPX. Use this when you have a raw big.Int amount.
//
//	alloc := NewGenesisAllocation("a1b2...e5f6", big.NewInt(1e18), "Treasury")
func NewGenesisAllocation(address string, balanceNSPX *big.Int, label string) *GenesisAllocation {
	return &GenesisAllocation{
		Address:     address,
		BalanceNSPX: new(big.Int).Set(balanceNSPX),
		Label:       label,
	}
}

// NewGenesisAllocationSPX creates a GenesisAllocation where the balance is
// specified in whole SPX units. The value is converted to nSPX internally.
//
//	alloc := NewGenesisAllocationSPX("a1b2...e5f6", 1_000_000, "Founders")
//	// → 1,000,000 × 10^18 nSPX
func NewGenesisAllocationSPX(address string, spx int64, label string) *GenesisAllocation {
	nspx := new(big.Int).Mul(big.NewInt(spx), big.NewInt(1e18))
	return NewGenesisAllocation(address, nspx, label)
}

// NewFounderAlloc is a domain-specific shorthand for the primary founder account.
// Allocation: 30,000,000 SPX total, with 5,000,000 SPX sold in Angel Round.
// 25,000,000 SPX remaining — 4-year vesting with 12-month cliff.
// Includes planned charity allocation.
// It calls NewGenesisAllocationSPX with the label "Founder".
func NewFounderAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "Founder")
}

// NewCoFounderAlloc is a domain-specific shorthand for the co-founder accounts.
// Allocation: 95,000,000 SPX total (4 co-founders), with 10,000,000 SPX sold in Angel Round.
// 85,000,000 SPX remaining — 4-year vesting with 12-month cliff.
// Includes planned charity allocation.
// It calls NewGenesisAllocationSPX with the label "CoFounder".
func NewCoFounderAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "CoFounder")
}

// NewDevelopmentAlloc is a domain-specific shorthand for the Development Fund.
// Allocation: 200,000,000 SPX total, with 50,000,000 SPX sold (25%):
//   - 10,000,000 in Angel Round
//   - 30,000,000 in Private Sale
//   - 10,000,000 in Public ICO
//
// 150,000,000 SPX remaining — module-based development fund.
// Paid per completed module (10,000 SPX/module). First 2,000 modules targeted
// for completion over approximately 2 years.
// It calls NewGenesisAllocationSPX with the label "Development".
func NewDevelopmentAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "Development")
}

// NewContributorAlloc is a domain-specific shorthand for contributor accounts.
// Allocation: 90,000,000 SPX total, with 15,000,000 SPX sold (16.7%):
//   - 5,000,000 in Angel Round
//   - 10,000,000 in Private Sale
//
// 75,000,000 SPX remaining — milestone-based vesting.
// Covers: Legal (10M, 2yr), Advisors (15M, 2yr), CSO (15M, 3yr),
// Partners (25M, milestone), Managers (25M, 2yr).
// It calls NewGenesisAllocationSPX with the label "Contributors".
func NewContributorAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "Contributors")
}

// NewFoundationAlloc is a domain-specific shorthand for the SPHINX Foundation.
// Allocation: 300,000,000 SPX — 0% sold, fully kept for ecosystem.
// Distribution:
//   - Ecosystem Grants: 120,000,000 SPX
//   - Liquidity Provision: 60,000,000 SPX
//   - R&D: 50,000,000 SPX
//   - Strategic Partnerships: 30,000,000 SPX
//   - Emergency Reserve: 20,000,000 SPX
//   - Buybacks (optional): 20,000,000 SPX
//
// Governance: Multi-sig wallet (5-of-9), quarterly transparency reports,
// community oversight committee.
// It calls NewGenesisAllocationSPX with the label "Foundation".
func NewFoundationAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "Foundation")
}

// NewCampaignAlloc is a domain-specific shorthand for campaigns and outreach.
// Allocation: 35,000,000 SPX total, with 20,000,000 SPX sold (57%):
//   - 20,000,000 in Private Sale
//
// 15,000,000 SPX remaining — future marketing and partnerships.
// It calls NewGenesisAllocationSPX with the label "Campaigns".
func NewCampaignAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "Campaigns")
}

// NewAirdropAlloc is a domain-specific shorthand for community airdrop pools.
// Allocation: 90,000,000 SPX — 0% sold, fully kept for community.
// Distribution:
//   - Phase 1: Genesis — 20,000,000 SPX (Early testnet users)
//   - Phase 2: Adoption — 20,000,000 SPX (Wallet creation & usage)
//   - Phase 3: Staking — 25,000,000 SPX (First 10,000 stakers)
//   - Phase 4: Engagement — 25,000,000 SPX (Governance & referrals)
//
// Rules: No vesting, sybil resistance, proof-of-humanity verification,
// gradual release over 12 months.
// It calls NewGenesisAllocationSPX with the label "Airdrops".
func NewAirdropAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "Airdrops")
}

// NewPublicICOPoolAlloc is a domain-specific shorthand for the Public ICO Pool.
// Allocation: 200,000,000 SPX total, with 100,000,000 SPX sold (50%):
//   - 10,000,000 in Private Sale
//   - 90,000,000 in Public ICO
//
// 100,000,000 SPX remaining — future public sales.
// It calls NewGenesisAllocationSPX with the label "PublicICOPool".
func NewPublicICOPoolAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "PublicICOPool")
}

// NewReserveAlloc is a domain-specific shorthand for the Reserve / Unsold pool.
// Allocation: 200,000,000 SPX — 0% sold.
// Reserved for future ecosystem needs, emergencies, and strategic initiatives.
// It calls NewGenesisAllocationSPX with the label "Reserve".
func NewReserveAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "Reserve")
}

// ------------------------------------------------------------------------------
// DefaultGenesisAllocations — the canonical mainnet pre-funded accounts
// ------------------------------------------------------------------------------

// DefaultGenesisAllocations returns the ordered list of pre-funded accounts
// that are embedded in the Sphinx Mainnet genesis block. The ordering of
// entries in this slice is part of the consensus specification: changing the
// order would produce a different allocation Merkle root and therefore a
// different genesis hash, forking the network.
//
// Total genesis supply  : 1,240,000,000 SPX (24.8% of 5B max supply)
//
// Distribution:
//
//	Category                    Original      Sold      Remaining    % of Max  Notes
//	─────────────────────────────────────────────────────────────────────────────────────
//	Founder (Lead)             30,000,000    5,000,000  25,000,000    0.6%     4yr vesting, 12mo cliff
//	Co-founders (4)            95,000,000   10,000,000  85,000,000    1.9%     4yr vesting, 12mo cliff
//	Development Fund          200,000,000   50,000,000 150,000,000    4.0%     Module-based (10k/module)
//	Contributors               90,000,000   15,000,000  75,000,000    1.8%     Milestone-based vesting
//	SPHINX Foundation         300,000,000          0   300,000,000    6.0%     Ecosystem grants, liquidity
//	Campaigns                  35,000,000   20,000,000  15,000,000    0.7%     Marketing & partnerships
//	Community Airdrops         90,000,000          0    90,000,000    1.8%     Free distribution, 4 phases
//	Public ICO Pool           200,000,000  100,000,000 100,000,000    4.0%     Future public sales
//	Reserve / Unsold          200,000,000          0   200,000,000    4.0%     Ecosystem reserve
//	─────────────────────────────────────────────────────────────────────────────────────
//	Total                    1,240,000,000  200,000,000 1,040,000,000  24.8%
//
// Funding Rounds Sold:
//   - Angel Round: 30,000,000 SPX @ $0.06 = $1,800,000
//     Source: Founder (5M) + Co-founders (10M) + Dev Fund (10M) + Contributors (5M)
//   - Private Sale: 70,000,000 SPX @ $0.24 = $16,800,000
//     Source: Dev Fund (30M) + Contributors (10M) + Campaigns (20M) + Public ICO Pool (10M)
//   - Public ICO: 100,000,000 SPX @ $0.36 = $36,000,000
//     Source: Public ICO Pool (90M) + Dev Fund (10M)
//
// Total Raised: $54,600,000
//
// Vesting Schedules:
//   - Founders (Lead + 4): 4-year vesting, 12-month cliff
//     Month 12: 25% | Month 24: 25% | Month 36: 25% | Month 48: 25%
//   - Development Fund: Module-based (10,000 SPX/module, 3,000 modules total)
//   - Contributors: Role-based vesting (Legal 2yr, Advisors 2yr, CSO 3yr,
//     Partners milestone, Managers 2yr)
//   - SPHINX Foundation: Multi-sig wallet (5-of-9), quarterly transparency reports
//   - Community Airdrops: No vesting, 12-month gradual release
//
// These addresses are placeholder hex strings. Replace them with the actual
// multisig or keystore addresses before mainnet launch.
func DefaultGenesisAllocations() []*GenesisAllocation {
	return []*GenesisAllocation{
		// ── Founder (Lead) ─────────────────────────────────────────────────
		// 30,000,000 SPX total · 5,000,000 sold in Angel Round.
		// 25,000,000 SPX remaining — 4-year vesting, 12-month cliff.
		NewFounderAlloc("1000000000000000000000000000000000000001", 30_000_000),

		// ── Co-founders (4) ───────────────────────────────────────────────
		// 95,000,000 SPX total · 10,000,000 sold in Angel Round.
		// 85,000,000 SPX remaining — 4-year vesting, 12-month cliff.
		NewCoFounderAlloc("2000000000000000000000000000000000000001", 95_000_000),

		// ── Development Fund ───────────────────────────────────────────────
		// 200,000,000 SPX total · 50,000,000 sold (25%):
		//   Angel: 10M · Private: 30M · Public ICO: 10M.
		// 150,000,000 SPX remaining — module-based (10,000/module).
		NewDevelopmentAlloc("3000000000000000000000000000000000000001", 200_000_000),

		// ── Contributors ───────────────────────────────────────────────────
		// 90,000,000 SPX total · 15,000,000 sold (16.7%):
		//   Angel: 5M · Private: 10M.
		// 75,000,000 SPX remaining — milestone-based vesting.
		// Roles: Legal (10M/2yr) · Advisors (15M/2yr) · CSO (15M/3yr)
		//        Partners (25M/milestone) · Managers (25M/2yr)
		NewContributorAlloc("4000000000000000000000000000000000000001", 90_000_000),

		// ── SPHINX Foundation ──────────────────────────────────────────────
		// 300,000,000 SPX · 0% sold — fully kept for ecosystem.
		// Grants: 120M · Liquidity: 60M · R&D: 50M
		// Partnerships: 30M · Emergency: 20M · Buybacks: 20M (optional)
		NewFoundationAlloc("5000000000000000000000000000000000000001", 300_000_000),

		// ── Campaigns ──────────────────────────────────────────────────────
		// 35,000,000 SPX total · 20,000,000 sold in Private Sale (57%).
		// 15,000,000 SPX remaining — future marketing and partnerships.
		NewCampaignAlloc("6000000000000000000000000000000000000001", 35_000_000),

		// ── Community Airdrops ─────────────────────────────────────────────
		// 90,000,000 SPX · 0% sold — fully kept.
		// Phases: Genesis (20M) · Adoption (20M) · Staking (25M) · Engagement (25M)
		// No vesting · Sybil resistance · 12-month release.
		NewAirdropAlloc("7000000000000000000000000000000000000001", 90_000_000),

		// ── Public ICO Pool ───────────────────────────────────────────────
		// 200,000,000 SPX total · 100,000,000 sold (50%):
		//   Private: 10M · Public ICO: 90M.
		// 100,000,000 SPX remaining — future public sales.
		NewPublicICOPoolAlloc("8000000000000000000000000000000000000001", 200_000_000),

		// ── Reserve / Unsold ───────────────────────────────────────────────
		// 200,000,000 SPX · 0% sold.
		// Reserved for future ecosystem needs, emergencies, and strategic initiatives.
		NewReserveAlloc("9000000000000000000000000000000000000001", 200_000_000),
	}
}

// SummariseAllocations iterates over allocs and returns an AllocationSummary.
// It does not modify the input slice.
func SummariseAllocations(allocs []*GenesisAllocation) *AllocationSummary {
	summary := &AllocationSummary{
		TotalNSPX: new(big.Int),
		TotalSPX:  new(big.Int),
		Count:     len(allocs),
		ByLabel:   make(map[string]*big.Int),
	}

	for _, a := range allocs {
		if a.BalanceNSPX == nil {
			continue
		}
		summary.TotalNSPX.Add(summary.TotalNSPX, a.BalanceNSPX)

		if _, ok := summary.ByLabel[a.Label]; !ok {
			summary.ByLabel[a.Label] = new(big.Int)
		}
		summary.ByLabel[a.Label].Add(summary.ByLabel[a.Label], a.BalanceNSPX)
	}

	// Convert total to whole SPX (truncating any fractional part).
	summary.TotalSPX.Div(summary.TotalNSPX, big.NewInt(1e18))
	return summary
}

// LogAllocationSummary prints a formatted summary of the genesis allocations
// to the logger. It is called automatically by ApplyGenesis.
func LogAllocationSummary(allocs []*GenesisAllocation) {
	s := SummariseAllocations(allocs)
	logger.Info("=== GENESIS ALLOCATION SUMMARY ===")
	logger.Info("Total accounts : %d", s.Count)
	logger.Info("Total supply   : %s SPX  (%s nSPX)", s.TotalSPX.String(), s.TotalNSPX.String())
	logger.Info("Distribution by label:")
	for label, amountNSPX := range s.ByLabel {
		amountSPX := new(big.Int).Div(amountNSPX, big.NewInt(1e18))
		pct := new(big.Float).Quo(
			new(big.Float).SetInt(amountSPX),
			new(big.Float).SetInt(s.TotalSPX),
		)
		pct.Mul(pct, big.NewFloat(100))
		pctF, _ := pct.Float64()
		logger.Info("  %-20s %15s SPX  (%.2f%%)", label, amountSPX.String(), pctF)
	}
	logger.Info("==================================")
}

// ----------------------------------------------------------------------------
// Validation
// ----------------------------------------------------------------------------

// validate checks that an individual GenesisAllocation is internally consistent.
// It is called by ValidateGenesisState for every entry in the Allocations slice.
func (a *GenesisAllocation) validate() error {
	if a == nil {
		return fmt.Errorf("allocation is nil")
	}
	if len(a.Address) != 40 {
		return fmt.Errorf("address must be 40 hex characters, got %d", len(a.Address))
	}
	addrBytes, err := hex.DecodeString(a.Address)
	if err != nil {
		return fmt.Errorf("address is not valid hex: %w", err)
	}
	if len(addrBytes) != 20 {
		return fmt.Errorf("address decodes to %d bytes, want 20", len(addrBytes))
	}
	if a.BalanceNSPX == nil {
		return fmt.Errorf("balance_nspx is nil")
	}
	if a.BalanceNSPX.Sign() < 0 {
		return fmt.Errorf("balance_nspx must be non-negative")
	}
	return nil
}

// ----------------------------------------------------------------------------
// Merkle root contribution
// ----------------------------------------------------------------------------

// deterministicBytes serialises the allocation to a canonical byte slice for
// Merkle tree leaf computation. The encoding is:
//
//	[20 bytes: address] || [32 bytes: balance big-endian, zero-padded]
//
// This fixed-width encoding avoids ambiguity: a variable-length encoding could
// allow two different (address, balance) pairs to produce the same byte string.
func (a *GenesisAllocation) deterministicBytes() []byte {
	addrBytes, err := hex.DecodeString(a.Address)
	if err != nil || len(addrBytes) != 20 {
		// Fall back to hashing the address string if it cannot be decoded.
		// This should never happen in a validated GenesisState.
		addrBytes = common.SpxHash([]byte(a.Address))[:20]
	}

	// Encode balance as a 32-byte big-endian integer (same as EVM convention).
	balBytes := make([]byte, 32)
	if a.BalanceNSPX != nil {
		raw := a.BalanceNSPX.Bytes() // big-endian, no leading zeros
		if len(raw) > 32 {
			raw = raw[len(raw)-32:] // truncate if somehow >256 bits
		}
		copy(balBytes[32-len(raw):], raw) // right-align in 32-byte buffer
	}

	result := make([]byte, 0, 20+32)
	result = append(result, addrBytes...)
	result = append(result, balBytes...)
	return result
}

// ----------------------------------------------------------------------------
// AllocationSet — fast lookup helpers used during block/tx processing
// ----------------------------------------------------------------------------

// NewAllocationSet builds an AllocationSet from an ordered allocation slice.
// Duplicate addresses cause an error so callers receive early feedback before
// the genesis block is applied.
func NewAllocationSet(allocs []*GenesisAllocation) (*AllocationSet, error) {
	s := &AllocationSet{
		index: make(map[string]*GenesisAllocation, len(allocs)),
		total: new(big.Int),
	}

	for i, a := range allocs {
		if err := a.validate(); err != nil {
			return nil, fmt.Errorf("allocation[%d]: %w", i, err)
		}
		key := toLower(a.Address)
		if _, exists := s.index[key]; exists {
			return nil, fmt.Errorf("duplicate genesis allocation for address %s", a.Address)
		}
		s.index[key] = a
		s.total.Add(s.total, a.BalanceNSPX)
	}

	return s, nil
}

// Get returns the GenesisAllocation for address (case-insensitive) and a bool
// indicating whether the address was found.
func (s *AllocationSet) Get(address string) (*GenesisAllocation, bool) {
	a, ok := s.index[toLower(address)]
	return a, ok
}

// TotalSupplyNSPX returns the total genesis supply across all allocations,
// expressed in nSPX.
func (s *AllocationSet) TotalSupplyNSPX() *big.Int {
	return new(big.Int).Set(s.total)
}

// TotalSupplySPX returns the total genesis supply in whole SPX (truncated).
func (s *AllocationSet) TotalSupplySPX() *big.Int {
	return new(big.Int).Div(s.total, big.NewInt(1e18))
}

// Len returns the number of entries in the set.
func (s *AllocationSet) Len() int {
	return len(s.index)
}

// Contains reports whether address (case-insensitive) has a genesis allocation.
func (s *AllocationSet) Contains(address string) bool {
	_, ok := s.index[toLower(address)]
	return ok
}

// All returns every allocation in an unspecified order. Use this only for
// iteration where order does not matter (e.g. logging); for Merkle root
// computation always use the original ordered slice from GenesisState.
func (s *AllocationSet) All() []*GenesisAllocation {
	out := make([]*GenesisAllocation, 0, len(s.index))
	for _, a := range s.index {
		out = append(out, a)
	}
	return out
}

// ----------------------------------------------------------------------------
// Encoding helpers used by snapshot/restore paths
// ----------------------------------------------------------------------------

// uint64ToBytes encodes a uint64 to an 8-byte big-endian slice.
// Used when serialising slot / epoch numbers into Merkle leaf data.
func uint64ToBytes(n uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, n)
	return b
}
