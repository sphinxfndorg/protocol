// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/allocation.go
package core

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"

	"github.com/sphinxfndorg/protocol/src/common"
	logger "github.com/sphinxfndorg/protocol/src/console"
	"github.com/sphinxfndorg/protocol/src/policy"
)

// ----------------------------------------------------------------------------
// Constructors
// ----------------------------------------------------------------------------

// NewGenesisAllocation creates a GenesisAllocation whose balance is already
// expressed in nSPX. Use this when you have a raw big.Int amount.
//
//	alloc := NewGenesisAllocation("a1b2...e5f6", big.NewInt(1e18), "Treasury")
func NewGenesisAllocation(address string, balanceNSPX *big.Int, label string) *GenesisAllocation {
	// Accept addresses either as raw hex or in "SPIF XXXX XXXX ..." display
	// format. NormalizeSPIFAddress strips the "SPIF" prefix, spaces, and
	// hyphens, and validates the result is 40/64-char hex. If normalization
	// fails (e.g. malformed/short address), keep the original string as-is so
	// that validate() can surface a proper error later instead of silently
	// swallowing it here.
	addr := address
	if normalized, err := common.NormalizeSPIFAddress(address); err == nil {
		addr = normalized
	}
	return &GenesisAllocation{
		Address:     addr,
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
// BalanceNSPX here is the 25,000,000 SPX unsold remainder, escrowed at CGE
// and released 25% at months 12/24/36/48 (4-year vesting, 12-month cliff).
// The sold 5,000,000 SPX is paid to the same address as an always-liquid
// top-up in block 0 (see allocationsToTxList) — it is never escrowed.
// Includes planned charity allocation.
// It calls NewGenesisAllocationSPX with the label "Founder".
func NewFounderAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "Founder")
}

// NewCoFounderAlloc is a domain-specific shorthand for the co-founder accounts.
// Allocation: 95,000,000 SPX total (4 co-founders), with 10,000,000 SPX sold in Angel Round.
// BalanceNSPX here is the 85,000,000 SPX unsold remainder, escrowed at CGE
// and released 25% at months 12/24/36/48. The sold 10,000,000 SPX is paid to
// the same address as an always-liquid top-up in block 0, never escrowed.
// Includes planned charity allocation.
// It calls NewGenesisAllocationSPX with the label "CoFounder".
func NewCoFounderAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "CoFounder")
}

// NewDevelopmentAlloc is a domain-specific shorthand for the Development Fund.
// Allocation: 170,000,000 SPX total, with 20,000,000 SPX sold (10M Angel
// Round + 10M Public ICO). BalanceNSPX here is the 150,000,000 SPX unsold
// remainder — fully escrowed at CGE, released ONLY via module completion
// (50,000 SPX/module × 3,000 modules; see ReleaseDevelopmentModule). The
// sold 20,000,000 SPX is paid to the same address as an always-liquid
// top-up in block 0, never escrowed and never module-gated.
// It calls NewGenesisAllocationSPX with the label "Development".
func NewDevelopmentAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "Development")
}

// NewContributorAlloc is a domain-specific shorthand for contributor accounts.
// Allocation: 80,000,000 SPX total, with 5,000,000 SPX sold in Angel Round.
// BalanceNSPX here is the 75,000,000 SPX unsold remainder, escrowed at CGE
// and released linearly over 36 months with no cliff. The sold 5,000,000 SPX
// is paid to the same address as an always-liquid top-up in block 0, never
// escrowed.
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
// Allocation: 15,000,000 SPX — 0% sold (the Private Sale tier that once sold
// 20,000,000 SPX from a 35,000,000 SPX total has been removed entirely).
// Liquid at CGE.
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
// Escrowed at CGE and released linearly over 12 months (no cliff). Sybil
// resistance and proof-of-humanity verification are application-layer rules,
// not part of the CGE release.
// It calls NewGenesisAllocationSPX with the label "Airdrops".
func NewAirdropAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "Airdrops")
}

// NewPublicICOPoolAlloc is a domain-specific shorthand for the Public ICO Pool.
// Allocation: 200,000,000 SPX total, with 100,000,000 SPX sold in the public
// ICO. BalanceNSPX here is the 100,000,000 SPX unsold remainder — genesis
// pays the sold 100,000,000 SPX back in as an always-liquid top-up (see
// allocationsToTxList), so the address receives all 200,000,000 SPX in block
// 0 (no cliff, no vesting for either portion).
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
// Each BalanceNSPX below is the UNSOLD remainder of its category — the same
// figures as before. What changed is how genesis pays them out:
// allocationsToTxList (genesis.go) now adds each category's sold amount
// (policy.CGESoldAmountSPX) back in as an always-liquid top-up on top of
// whatever the remainder's own CGE schedule unlocks, so the sold portion is
// minted directly to the category's own address in block 0 instead of being
// delivered by some separate, out-of-band process. The remainder keeps its
// existing schedule untouched.
//
//	Category              Remainder (escrow input)  Sold (always liquid)  Gross
//	──────────────────────────────────────────────────────────────────────────
//	Founder (Lead)             25,000,000                 5,000,000     30,000,000
//	Co-founders (4)            85,000,000                10,000,000     95,000,000
//	Development Fund          150,000,000                20,000,000    170,000,000
//	Contributors               75,000,000                 5,000,000     80,000,000
//	SPHINX Foundation         300,000,000                         0    300,000,000
//	Campaigns                  15,000,000                         0     15,000,000
//	Community Airdrops         90,000,000                         0     90,000,000
//	Public ICO Pool           100,000,000                90,000,000    190,000,000
//	Reserve / Unsold          200,000,000                         0    200,000,000
//	──────────────────────────────────────────────────────────────────────────
//	Total                   1,040,000,000               130,000,000  1,170,000,000
//
// Sold total = Angel Round (30,000,000) + Public ICO (100,000,000).
//
// CGE — coins event generation (see src/policy/cge.go):
//   - Every schedule counts from the genesis block timestamp —
//     CanonicalGenesisTimestamp (2026-07-15 19:33:18 UTC) — never from
//     wall-clock time. Releases are triggered by sealed block timestamps.
//   - Locked tokens sit at policy.CGEEscrowAddress and stream to the
//     recipient as chain time passes; liquid categories (and every sold
//     amount) are paid in full in block 0.
//   - Development Fund's remainder never releases on time: a future module
//     registry calls policy.ReleaseDevelopmentModule (50,000 SPX × 3,000
//     modules = 150M). Its sold 20,000,000 SPX is liquid at genesis same as
//     any other sold amount.
//   - No private-sale tier exists: with it removed there is no intermediate
//     cliff between angel investors and public investors (public buyers
//     receive at CGE).
//
// Release Schedules (CGE), applied to each category's remainder only —
// every category's sold amount is always liquid at genesis, regardless of
// the remainder's schedule:
//   - Founders (Lead + 4): 4-year vesting, 12-month cliff
//     Month 12: 25% | Month 24: 25% | Month 36: 25% | Month 48: 25%
//   - Development Fund: Module-based (50,000 SPX/module, 3,000 modules)
//   - Contributors: Linear over 36 months, no cliff
//   - SPHINX Foundation: Multi-sig wallet (5-of-9), quarterly transparency reports
//   - Community Airdrops: Linear over 12 months, no cliff (sybil resistance
//     and proof-of-humanity checks are application-layer, not vesting)
//   - Public ICO Pool: CGE (no cliff, no vesting)
func DefaultGenesisAllocations() []*GenesisAllocation {
	return []*GenesisAllocation{
		// ── Founder (Lead) ─────────────────────────────────────────────────
		// 25,000,000 SPX funded at genesis (unsold remainder of 30,000,000).
		// Escrowed at CGE — released 25% at months 12/24/36/48.
		// Amount: policy.CGEFounderSPX. Address below is the canonical
		// recipient (REAL ADDRESS #1) and stays in core.
		NewFounderAlloc("SPIF F471 9CBD E8EE 7766 2B76 7F59 7039 94EF A5D2 D9F4 597C 3C2B D1E2 861E AEB1 3159", policy.CGEFounderSPX),

		// ── Co-founders (4) ───────────────────────────────────────────────
		// 85,000,000 SPX funded at genesis (unsold remainder of 95,000,000).
		// Escrowed at CGE — released 25% at months 12/24/36/48.
		// Amount: policy.CGECoFounderSPX. Address below is the canonical
		// recipient (REAL ADDRESS #2) and stays in core.
		NewCoFounderAlloc("SPIF BD4D 2032 DDEC 0060 E94D 6A3E F866 A278 F47B 0A2C FB2A E2DC 301A C261 953C C106", policy.CGECoFounderSPX),

		// ── Development Fund ───────────────────────────────────────────────
		// 150,000,000 SPX funded at genesis — module rewards
		// (50,000 SPX × 3,000 modules = 150,000,000 exactly).
		// Fully escrowed; NEVER released by time — only via a future
		// ReleaseDevelopmentModule call from the module registry.
		// Amount: policy.CGEDevelopmentSPX. Address below is the canonical
		// recipient (REAL ADDRESS #3) and stays in core.
		NewDevelopmentAlloc("SPIF 7C25 F767 770D 2C7E 242C 55C4 A129 82FC 73A7 E03D 410E 66B2 CDF3 E6F0 6B40 3411", policy.CGEDevelopmentSPX),

		// ── Contributors ───────────────────────────────────────────────────
		// 75,000,000 SPX funded at genesis (unsold remainder of 90,000,000).
		// Escrowed at CGE — released linearly over 36 months, no cliff.
		// Amount: policy.CGEContributorsSPX. Address below is the canonical
		// recipient (REAL ADDRESS #4) and stays in core.
		NewContributorAlloc("SPIF 4E4F 7B3B 2FF1 5795 5379 A8A4 DAE2 6D36 1480 EE27 132C AE92 C7DE B523 7F27 8E01", policy.CGEContributorsSPX),

		// ── SPHINX Foundation ──────────────────────────────────────────────
		// 300,000,000 SPX · 0% sold — fully kept for ecosystem.
		// Grants: 120M · Liquidity: 60M · R&D: 50M
		// Partnerships: 30M · Emergency: 20M · Buybacks: 20M (optional)
		// Liquid at CGE — governed by a 5-of-9 multisig treasury.
		// Amount: policy.CGEFoundationSPX. Address below is the canonical
		// treasury (REAL ADDRESS #5) and stays in core.
		NewFoundationAlloc("SPIF 35E8 224A 7F71 ED86 28FD BFD5 ED60 6CF3 5B97 32F2 3E77 A83C 7286 2B92 B2FF D5F6", policy.CGEFoundationSPX),

		// ── Campaigns ──────────────────────────────────────────────────────
		// 15,000,000 SPX funded at genesis (unsold remainder of 35,000,000).
		// Liquid at CGE — future marketing and partnerships.
		// Amount: policy.CGECampaignsSPX. Address below is the canonical
		// recipient (REAL ADDRESS #6) and stays in core.
		NewCampaignAlloc("SPIF 3FC4 E475 5A11 8E66 34F4 B689 FE13 288B DF64 95A9 5465 B692 9AFB 858F 6DF1 6E71", policy.CGECampaignsSPX),

		// ── Community Airdrops ─────────────────────────────────────────────
		// 90,000,000 SPX · 0% sold — fully kept.
		// Escrowed at CGE — released linearly over 12 months, no cliff.
		// Sybil resistance / proof-of-humanity gating is application-layer.
		// Amount: policy.CGEAirdropsSPX. Address below is the canonical
		// recipient (REAL ADDRESS #7) and stays in core.
		NewAirdropAlloc("SPIF 7ED7 AFC5 AF4E 9ECC 29B0 04C5 E687 ABB4 2EE2 6EA9 5A05 68A3 F40B DE98 12D7 84C6", policy.CGEAirdropsSPX),

		// ── Public ICO Pool ───────────────────────────────────────────────
		// 100,000,000 SPX funded at genesis (unsold remainder of 200,000,000;
		// 100,000,000 sold in the public ICO, delivered outside genesis).
		// Liquid at CGE — public investors have no cliff, no vesting.
		// Amount: policy.CGEPublicICOPoolSPX. Address below is the canonical
		// recipient (REAL ADDRESS #8) and stays in core.
		NewPublicICOPoolAlloc("SPIF 8F34 52C1 2382 AA9E 6280 8B75 409D A5CD FD96 3C57 6367 31E3 4728 DCA2 3319 A7FF", policy.CGEPublicICOPoolSPX),

		// ── Reserve / Unsold ───────────────────────────────────────────────
		// 200,000,000 SPX · 0% sold.
		// Liquid at CGE — future ecosystem needs, emergencies, strategic initiatives.
		// Amount: policy.CGEReserveSPX. Address below is the canonical
		// recipient (REAL ADDRESS #9) and stays in core.
		NewReserveAlloc("SPIF 029C 1D9F 37BA 57FE 6B9A 53FE A58D A27A 4B24 F008 9F0C AC75 6E42 2DDC A8B9 22C8", policy.CGEReserveSPX),
	}
}

// SummariseAllocations iterates over allocs and returns an AllocationSummary.
// It does not modify the input slice.
//
// BalanceNSPX is the post-sale REMAINDER, so TotalNSPX/ByLabel are the schedule
// input. This also sums each category's sold-at-genesis amount (always liquid)
// into TotalSoldNSPX/SoldByLabel and the two into TotalGrossNSPX/GrossByLabel —
// gross is what block 0 actually mints, so audit output must report that.
func SummariseAllocations(allocs []*GenesisAllocation) *AllocationSummary {
	summary := &AllocationSummary{
		TotalNSPX:      new(big.Int),
		TotalSPX:       new(big.Int),
		TotalSoldNSPX:  new(big.Int),
		TotalGrossNSPX: new(big.Int),
		Count:          len(allocs),
		ByLabel:        make(map[string]*big.Int),
		SoldByLabel:    make(map[string]*big.Int),
		GrossByLabel:   make(map[string]*big.Int),
	}

	for _, a := range allocs {
		if a.BalanceNSPX == nil {
			continue
		}
		sold := cgeSoldNSPX(a.Label)
		gross := new(big.Int).Add(a.BalanceNSPX, sold)

		summary.TotalNSPX.Add(summary.TotalNSPX, a.BalanceNSPX)
		summary.TotalSoldNSPX.Add(summary.TotalSoldNSPX, sold)
		summary.TotalGrossNSPX.Add(summary.TotalGrossNSPX, gross)

		accumulateByLabel(summary.ByLabel, a.Label, a.BalanceNSPX)
		accumulateByLabel(summary.SoldByLabel, a.Label, sold)
		accumulateByLabel(summary.GrossByLabel, a.Label, gross)
	}

	// Convert total to whole SPX (truncating any fractional part).
	summary.TotalSPX.Div(summary.TotalNSPX, big.NewInt(1e18))
	return summary
}

// cgeSoldNSPX returns label's sold-at-genesis amount in nSPX (0 if none).
func cgeSoldNSPX(label string) *big.Int {
	return new(big.Int).Mul(big.NewInt(policy.CGESoldAmountSPX(label)), big.NewInt(1e18))
}

// accumulateByLabel adds amount into m[label], creating the entry on first use.
func accumulateByLabel(m map[string]*big.Int, label string, amount *big.Int) {
	if _, ok := m[label]; !ok {
		m[label] = new(big.Int)
	}
	m[label].Add(m[label], amount)
}

// LogAllocationSummary prints a formatted summary of the genesis allocations
// to the logger. It is called automatically by ApplyGenesis.
//
// It reports the GROSS genesis supply (what block 0 mints), with the sold and
// remainder components broken out per label — reporting the remainder alone
// would understate the minted supply by the sold amount (130,000,000 SPX) and
// make the log disagree with the chain.
func LogAllocationSummary(allocs []*GenesisAllocation) {
	s := SummariseAllocations(allocs)
	oneSPX := big.NewInt(1e18)
	grossSPX := new(big.Int).Div(s.TotalGrossNSPX, oneSPX)
	logger.Info("=== GENESIS ALLOCATION SUMMARY ===")
	logger.Info("Total accounts     : %d", s.Count)
	logger.Info("Genesis supply     : %s SPX  (%s nSPX)  [what block 0 mints]",
		grossSPX.String(), s.TotalGrossNSPX.String())
	logger.Info("  sold (liquid)    : %s SPX", new(big.Int).Div(s.TotalSoldNSPX, oneSPX).String())
	logger.Info("  remainder (CGE)  : %s SPX", new(big.Int).Div(s.TotalNSPX, oneSPX).String())
	logger.Info("Distribution by label (remainder + sold = gross):")
	for _, label := range sortedLabels(s.GrossByLabel) {
		gross := new(big.Int).Div(s.GrossByLabel[label], oneSPX)
		remainder := new(big.Int).Div(s.ByLabel[label], oneSPX)
		sold := new(big.Int).Div(s.SoldByLabel[label], oneSPX)
		pctF := 0.0
		if grossSPX.Sign() != 0 {
			pct := new(big.Float).Quo(new(big.Float).SetInt(gross), new(big.Float).SetInt(grossSPX))
			pct.Mul(pct, big.NewFloat(100))
			pctF, _ = pct.Float64()
		}
		logger.Info("  %-20s %15s SPX  (remainder %s + sold %s)  (%.2f%%)",
			label, gross.String(), remainder.String(), sold.String(), pctF)
	}
	logger.Info("==================================")
}

// sortedLabels returns the keys of m in lexicographic order so log output is
// deterministic (Go map iteration is randomised).
func sortedLabels(m map[string]*big.Int) []string {
	labels := make([]string, 0, len(m))
	for l := range m {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	return labels
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

	// Normalise the address using the common SPIF utility
	normalized, err := common.NormalizeSPIFAddress(a.Address)
	if err != nil {
		return err
	}
	// Store the cleaned hex (without "SPIF")
	a.Address = normalized

	if a.BalanceNSPX == nil || a.BalanceNSPX.Sign() < 0 {
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
//	[20 or 32 bytes: address] || [32 bytes: balance big-endian, zero-padded]
//
// Addresses come in two valid widths: 20 bytes (legacy/placeholder,
// Ethereum-style) and 32 bytes (real SPHINCS+ derived "SPIF" addresses).
// Both are fixed-width per-address so there's no ambiguity within a single
// address's own encoding.
func (a *GenesisAllocation) deterministicBytes() []byte {
	addrBytes, err := hex.DecodeString(a.Address)
	if err != nil || (len(addrBytes) != 20 && len(addrBytes) != 32) {
		// Fall back to hashing the address string if it cannot be decoded,
		// or isn't one of the two recognised widths. This should never
		// happen in a validated GenesisState.
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

	result := make([]byte, 0, len(addrBytes)+32)
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
