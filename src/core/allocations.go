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

// NewFounderAlloc is a domain-specific shorthand for founder/team allocations.
// It calls NewGenesisAllocationSPX with the label "Founders".
func NewFounderAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "Founders")
}

// NewReserveAlloc is a domain-specific shorthand for ecosystem reserve accounts.
// It calls NewGenesisAllocationSPX with the label "Reserve".
func NewReserveAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "Reserve")
}

// NewTreasuryAlloc is a domain-specific shorthand for protocol treasury accounts.
// It calls NewGenesisAllocationSPX with the label "Treasury".
func NewTreasuryAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "Treasury")
}

// NewCommunityAlloc is a domain-specific shorthand for community / airdrop pools.
// It calls NewGenesisAllocationSPX with the label "Community".
func NewCommunityAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "Community")
}

// NewValidatorAlloc is a domain-specific shorthand for initial validator bonded
// accounts. It calls NewGenesisAllocationSPX with the label "Validator".
func NewValidatorAlloc(address string, spx int64) *GenesisAllocation {
	return NewGenesisAllocationSPX(address, spx, "Validator")
}

// ------------------------------------------------------------------------------
// Example; DefaultGenesisAllocations — the canonical mainnet pre-funded accounts
// ------------------------------------------------------------------------------

// DefaultGenesisAllocations returns the ordered list of pre-funded accounts
// that are embedded in the Sphinx Mainnet genesis block. The ordering of
// entries in this slice is part of the consensus specification: changing the
// order would produce a different allocation Merkle root and therefore a
// different genesis hash, forking the network.
//
// Total genesis supply  :  1,000,000,000 SPX  (10^9 SPX = 10^27 nSPX)
//
// Distribution:
//   - Founders & Team    :   150,000,000 SPX  (15%)
//   - Ecosystem Reserve  :   300,000,000 SPX  (30%)
//   - Protocol Treasury  :   200,000,000 SPX  (20%)
//   - Community & Grants :   200,000,000 SPX  (20%)
//   - Validator Bonds    :   150,000,000 SPX  (15%)
//
// These addresses are placeholder hex strings. Replace them with the actual
// multisig or keystore addresses before mainnet launch.
func DefaultGenesisAllocations() []*GenesisAllocation {
	return []*GenesisAllocation{
		// ── Founders & Team (15%) ────────────────────────────────────────────
		NewFounderAlloc(
			"1000000000000000000000000000000000000001",
			50_000_000, // 50 M SPX — Core protocol team
		),
		NewFounderAlloc(
			"1000000000000000000000000000000000000002",
			50_000_000, // 50 M SPX — Early contributors
		),
		NewFounderAlloc(
			"1000000000000000000000000000000000000003",
			50_000_000, // 50 M SPX — Advisors & partners
		),

		// ── Ecosystem Reserve (30%) ──────────────────────────────────────────
		NewReserveAlloc(
			"2000000000000000000000000000000000000001",
			150_000_000, // 150 M SPX — Long-term ecosystem fund
		),
		NewReserveAlloc(
			"2000000000000000000000000000000000000002",
			150_000_000, // 150 M SPX — Strategic reserve
		),

		// ── Protocol Treasury (20%) ──────────────────────────────────────────
		NewTreasuryAlloc(
			"3000000000000000000000000000000000000001",
			100_000_000, // 100 M SPX — On-chain governance treasury
		),
		NewTreasuryAlloc(
			"3000000000000000000000000000000000000002",
			100_000_000, // 100 M SPX — Protocol development fund
		),

		// ── Community & Grants (20%) ─────────────────────────────────────────
		NewCommunityAlloc(
			"4000000000000000000000000000000000000001",
			100_000_000, // 100 M SPX — Community incentives & airdrops
		),
		NewCommunityAlloc(
			"4000000000000000000000000000000000000002",
			100_000_000, // 100 M SPX — Developer grants programme
		),

		// ── Validator Bonds (15%) ────────────────────────────────────────────
		// These accounts represent the initial bonded stake for the first
		// set of genesis validators. Each holds 30 M SPX to cover the
		// 32-SPX minimum stake and leave room for delegation.
		NewValidatorAlloc(
			"5000000000000000000000000000000000000001",
			30_000_000, // 30 M SPX — Genesis validator pool 1
		),
		NewValidatorAlloc(
			"5000000000000000000000000000000000000002",
			30_000_000, // 30 M SPX — Genesis validator pool 2
		),
		NewValidatorAlloc(
			"5000000000000000000000000000000000000003",
			30_000_000, // 30 M SPX — Genesis validator pool 3
		),
		NewValidatorAlloc(
			"5000000000000000000000000000000000000004",
			30_000_000, // 30 M SPX — Genesis validator pool 4
		),
		NewValidatorAlloc(
			"5000000000000000000000000000000000000005",
			30_000_000, // 30 M SPX — Genesis validator pool 5
		),
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

	// Address must be a 40-character hex string (20 bytes).
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

	// Balance must be present and non-negative.
	if a.BalanceNSPX == nil {
		return fmt.Errorf("balance_nspx is nil")
	}
	if a.BalanceNSPX.Sign() < 0 {
		return fmt.Errorf("balance_nspx must be non-negative, got %s", a.BalanceNSPX.String())
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
