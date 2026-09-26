// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/policy/cge.go
//
// CGE — Coins Event Generation.
//
// CGE owns the deterministic release schedule of the genesis distributions:
// when each pre-funded account's coins become spendable, counted from the
// genesis block's timestamp (persisted in deterministic state at block 0 —
// see core.applyCGEReleases), never from wall-clock time. Releases are
// computed inside core's applyBlockTransitions from the sealed block header
// timestamp, so the proposer, every verifier, and every late joiner replaying
// the chain compute byte-identical results.
//
// The mechanism is escrow-based:
//
//	Genesis (block 0)   vault ── CGE-unlocked portion ──▶ recipient
//	                    vault ── locked remainder    ──▶ CGEEscrowAddress
//	Block N (timestamp) CGEEscrowAddress ── newly released delta ──▶ recipient
//
// Because locked tokens physically live at CGEEscrowAddress, a recipient's
// balance IS its spendable balance everywhere (RPC, explorer, contracts,
// staking) — no balance-validation path needs to know CGE exists. The
// cumulative-delta release is idempotent: re-executing a block (replay,
// previewStateRoot) computes delta 0 after the first application.
//
// This file is deliberately policy-owned and core-independent: it deals only
// in labels, amounts and second counts — never in core types such as
// GenesisAllocation or StateDB — so the schedule lives in exactly one place,
// the same way fees, inflation and slashing do.
package policy

import (
	"fmt"
	"math/big"
	"strconv"
)

// CGEEscrowAddress is the protocol system address that holds every genesis
// token which is not yet unlocked by its CGE schedule.
//
// It is a 20-byte legacy-style system address (like core's GenesisVault
// address ...0001), chosen so it is valid under the same 40-hex validation
// rules. The escrow never sends signed transactions: releases are state-level
// transfers performed deterministically by core.applyCGEReleases.
const CGEEscrowAddress = "0000000000000000000000000000000000000002"

// CGEMonthSeconds is the canonical month length used by every CGE schedule:
// 30 days. Using a fixed second count (instead of calendar months) keeps
// every computation a pure integer function of elapsed seconds, so all nodes
// agree byte-for-byte. A "year" in annual-tranche schedules is therefore
// 12 × 30d = 360d = 31,104,000s.
const CGEMonthSeconds int64 = 30 * 24 * 3600

// ----------------------------------------------------------------------------
// Canonical genesis allocation amounts (whole SPX).
//
// Single source of truth for every genesis amount funded at CGE. Core builds
// the ordered DefaultGenesisAllocations list from these values plus the
// canonical recipient addresses (which stay in core — addresses are identity,
// amounts are monetary policy). Importing core from policy would create an
// import cycle (core already imports policy for schedules/escrow), so the
// numbers live here and core references them as policy.CGE*SPX.
//
// Conservation (all in whole SPX):
//
//	Founder 25,000,000 + CoFounder 85,000,000 + Development 150,000,000 +
//	Contributors 75,000,000 + Foundation 300,000,000 + Campaigns 15,000,000 +
//	Airdrops 90,000,000 + PublicICOPool 100,000,000 + Reserve 200,000,000
//	= 1,040,000,000 SPX post-sale remainder.
//
// Escrowed at CGE (time/module-gated): 25M + 85M + 150M + 75M + 90M = 425M.
// Liquid at CGE: 300M + 15M + 100M + 200M = 615M.
//
// The 1,040,000,000 above is what's LEFT after the funding rounds. The full
// gross genesis allocation also includes what was sold — 130,000,000 SPX,
// minted directly to each category's own recipient at genesis (see the
// sold-amount constants below) — for a gross total of 1,170,000,000 SPX.
// remainder (1,040M) + sold (130M) = gross (1,170M).
// ----------------------------------------------------------------------------
const (
	// CGEFounderSPX is the Founder (Lead) genesis remainder: 25,000,000 SPX
	// (unsold remainder of 30,000,000; 5,000,000 sold in Angel Round).
	CGEFounderSPX int64 = 25_000_000
	// CGECoFounderSPX is the Co-founders (4) genesis remainder: 85,000,000 SPX
	// (unsold remainder of 95,000,000; 10,000,000 sold in Angel Round).
	CGECoFounderSPX int64 = 85_000_000
	// CGEDevelopmentSPX is the Development Fund genesis amount: 150,000,000 SPX
	// (50,000 SPX/module × 3,000 modules — fully escrowed, module-gated only).
	CGEDevelopmentSPX int64 = 150_000_000
	// CGEContributorsSPX is the Contributors genesis remainder: 75,000,000 SPX
	// (unsold remainder of 80,000,000; 5,000,000 sold in Angel Round).
	CGEContributorsSPX int64 = 75_000_000
	// CGEFoundationSPX is the SPHINX Foundation genesis amount: 300,000,000 SPX
	// (0% sold — liquid at CGE, 5-of-9 multisig treasury).
	CGEFoundationSPX int64 = 300_000_000
	// CGECampaignsSPX is the Campaigns genesis amount: 15,000,000 SPX
	// (0% sold — the Private Sale tier that once sold 20,000,000 SPX from a
	// 35,000,000 SPX total has been removed entirely).
	CGECampaignsSPX int64 = 15_000_000
	// CGEAirdropsSPX is the Community Airdrops genesis amount: 90,000,000 SPX
	// (0% sold — escrowed, linear over 12 months).
	CGEAirdropsSPX int64 = 90_000_000
	// CGEPublicICOPoolSPX is the Public ICO Pool genesis remainder: 100,000,000 SPX
	// (unsold remainder of 190,000,000; 90,000,000 sold in the public ICO).
	CGEPublicICOPoolSPX int64 = 100_000_000
	// CGEReserveSPX is the Reserve / Unsold genesis amount: 200,000,000 SPX
	// (0% sold — liquid at CGE).
	CGEReserveSPX int64 = 200_000_000

	// CGEGenesisTotalSPX is the total genesis supply: 1,040,000,000 SPX
	// (20.8% of 5B max supply).
	CGEGenesisTotalSPX int64 = 1_040_000_000
	// CGEGenesisEscrowedSPX is the total locked at CGE: 425,000,000 SPX
	// (25M + 85M + 150M + 75M + 90M).
	CGEGenesisEscrowedSPX int64 = 425_000_000
	// CGEGenesisLiquidSPX is the total liquid at CGE: 615,000,000 SPX
	// (300M + 15M + 100M + 200M).
	CGEGenesisLiquidSPX int64 = 615_000_000
)

// ----------------------------------------------------------------------------
// Sold-at-genesis amounts (whole SPX).
//
// "Sold" = minted directly to the category's own recipient address in the
// genesis block, fully liquid, no escrow — the coinomics v3.2 Funding
// Sources. The remainder of each category (the CGE*SPX constants above) is
// unaffected and keeps its existing schedule.
//
// Angel Round (30M):  Founder 5M + CoFounder 10M + Development 10M + Contributors 5M.
// Public ICO (100M):  Development 10M + PublicICOPool 90M.
// ----------------------------------------------------------------------------
const (
	CGEFounderSoldSPX       int64 = 5_000_000
	CGECoFounderSoldSPX     int64 = 10_000_000
	CGEDevelopmentSoldSPX   int64 = 20_000_000 // 10M Angel Round + 10M Public ICO
	CGEContributorsSoldSPX  int64 = 5_000_000
	CGEPublicICOPoolSoldSPX int64 = 90_000_000

	// CGEGenesisSoldSPX is the total sold across both rounds: 130,000,000 SPX
	// (Angel Round 30M + Public ICO 100M).
	CGEGenesisSoldSPX int64 = 130_000_000
	// CGEGenesisGrossSPX is the full genesis allocation before any sale:
	// 1,170,000,000 SPX = CGEGenesisTotalSPX + CGEGenesisSoldSPX.
	CGEGenesisGrossSPX int64 = 1_170_000_000
)

// CGESoldAmountSPX returns the portion of label's gross genesis allocation
// that was sold in a funding round: minted straight to the recipient at
// genesis, fully liquid, never escrowed. 0 for labels with no sale.
func CGESoldAmountSPX(label string) int64 {
	switch label {
	case "Founder":
		return CGEFounderSoldSPX
	case "CoFounder":
		return CGECoFounderSoldSPX
	case "Development":
		return CGEDevelopmentSoldSPX
	case "Contributors":
		return CGEContributorsSoldSPX
	case "PublicICOPool":
		return CGEPublicICOPoolSoldSPX
	default:
		return 0
	}
}

// CGEGrossGenesisAmountSPX returns label's full genesis allocation before
// sale: CGEGenesisAmountSPX(label) + CGESoldAmountSPX(label).
func CGEGrossGenesisAmountSPX(label string) int64 {
	return CGEGenesisAmountSPX(label) + CGESoldAmountSPX(label)
}

// CGEGenesisAmountSPX returns the canonical genesis amount (whole SPX) for a
// genesis allocation label, or 0 for unknown labels. The mapping mirrors
// core.DefaultGenesisAllocations: changing a value here changes genesis.
func CGEGenesisAmountSPX(label string) int64 {
	switch label {
	case "Founder":
		return CGEFounderSPX
	case "CoFounder":
		return CGECoFounderSPX
	case "Development":
		return CGEDevelopmentSPX
	case "Contributors":
		return CGEContributorsSPX
	case "Foundation":
		return CGEFoundationSPX
	case "Campaigns":
		return CGECampaignsSPX
	case "Airdrops":
		return CGEAirdropsSPX
	case "PublicICOPool":
		return CGEPublicICOPoolSPX
	case "Reserve":
		return CGEReserveSPX
	default:
		return 0
	}
}

// CGEKind enumerates the release mechanisms a genesis allocation can use.
type CGEKind int

const (
	// CGELiquid releases 100% of the allocation at CGE — the genesis
	// funding transaction pays the recipient directly; no escrow entry.
	CGELiquid CGEKind = iota

	// CGEAnnualTranches releases in four equal tranches of 25% each at
	// months 12, 24, 36 and 48 counted from the genesis timestamp
	// (0% at CGE, 0% before month 12 — the classic 12-month cliff).
	CGEAnnualTranches

	// CGELinear releases the full allocation in equal proportion over
	// DurationSec, no cliff, 0% at CGE. released(t) = total * t / duration.
	CGELinear

	// CGEModuleGated never releases on time. The allocation sits fully
	// in CGEEscrowAddress until a future module registry calls
	// ReleaseDevelopmentModule. The generic per-block CGE loop skips
	// this kind entirely.
	CGEModuleGated
)

// CGESchedule describes when an allocation's coins are generated
// (released) as chain time advances. All fields are code constants — part
// of the consensus specification.
type CGESchedule struct {
	Kind CGEKind

	// DurationSec is the linear-release window (CGELinear only).
	DurationSec int64
}

// IsTimeBased reports whether the schedule releases coins automatically as
// chain time advances. Liquid allocations release at CGE (no escrow) and
// module-gated allocations release only via ReleaseDevelopmentModule, so
// neither is time-based.
func (s CGESchedule) IsTimeBased() bool {
	return s.Kind == CGEAnnualTranches || s.Kind == CGELinear
}

// String returns a compact human-readable description used in logs and the
// genesis_state.json audit output.
func (s CGESchedule) String() string {
	switch s.Kind {
	case CGEAnnualTranches:
		return "25% at months 12/24/36/48"
	case CGELinear:
		months := s.DurationSec / CGEMonthSeconds
		return fmt.Sprintf("linear over %d months", months)
	case CGEModuleGated:
		return "module-gated (no time release)"
	default:
		return "liquid at CGE"
	}
}

// UnlockedAt returns the cumulative amount of total unlocked after elapsedSec
// seconds from the genesis timestamp. The result is always in [0, total] and
// is a pure integer function — no floating point, no calendar dependency.
func (s CGESchedule) UnlockedAt(elapsedSec int64, total *big.Int) *big.Int {
	if total == nil {
		return big.NewInt(0)
	}
	if elapsedSec < 0 {
		elapsedSec = 0
	}

	switch s.Kind {
	case CGELiquid:
		return new(big.Int).Set(total)

	case CGEAnnualTranches:
		// n = whole years elapsed (12-month units), capped at 4 tranches.
		const trancheCount = int64(4)
		years := elapsedSec / (12 * CGEMonthSeconds)
		if years > trancheCount {
			years = trancheCount
		}
		// total * years / 4 — integer division on big.Int.
		return new(big.Int).Div(
			new(big.Int).Mul(total, big.NewInt(years)),
			big.NewInt(trancheCount),
		)

	case CGELinear:
		if s.DurationSec <= 0 {
			return new(big.Int).Set(total)
		}
		if elapsedSec == 0 {
			return big.NewInt(0)
		}
		if elapsedSec >= s.DurationSec {
			return new(big.Int).Set(total)
		}
		// total * elapsed / duration — integer division truncates down.
		return new(big.Int).Div(
			new(big.Int).Mul(total, big.NewInt(elapsedSec)),
			big.NewInt(s.DurationSec),
		)

	case CGEModuleGated:
		return big.NewInt(0)

	default:
		return big.NewInt(0)
	}
}

// CGEScheduleForLabel returns the CGE schedule for a genesis allocation
// label. Labels without an explicit schedule (Foundation, Campaigns,
// PublicICOPool, Reserve, and any ad-hoc test label) are liquid at CGE —
// the same behaviour as before CGE existed.
//
// The mapping is part of the consensus specification:
//
//	Founder, CoFounder    25% at months 12/24/36/48 (from genesis timestamp)
//	Development           module-gated — escrowed, never released by time
//	Contributors          linear over 36 months, no cliff
//	Airdrops              linear over 12 months, no cliff
//	(all others)          100% liquid at CGE
func CGEScheduleForLabel(label string) CGESchedule {
	switch label {
	case "Founder", "CoFounder":
		return CGESchedule{Kind: CGEAnnualTranches}
	case "Development":
		return CGESchedule{Kind: CGEModuleGated}
	case "Contributors":
		return CGESchedule{Kind: CGELinear, DurationSec: 36 * CGEMonthSeconds}
	case "Airdrops":
		return CGESchedule{Kind: CGELinear, DurationSec: 12 * CGEMonthSeconds}
	default:
		return CGESchedule{Kind: CGELiquid}
	}
}

// CGEUnlockedAmount returns the portion of an allocation of total nSPX under
// label's schedule that is paid directly to the recipient in the genesis
// block (elapsed = 0).
func CGEUnlockedAmount(label string, total *big.Int) *big.Int {
	if total == nil {
		return big.NewInt(0)
	}
	return CGEScheduleForLabel(label).UnlockedAt(0, total)
}

// CGELockedAmount returns the portion of an allocation of total nSPX under
// label's schedule that must be routed to CGEEscrowAddress in the genesis
// block.
func CGELockedAmount(label string, total *big.Int) *big.Int {
	if total == nil {
		return big.NewInt(0)
	}
	locked := new(big.Int).Sub(total, CGEUnlockedAmount(label, total))
	if locked.Sign() < 0 {
		return big.NewInt(0)
	}
	return locked
}

// CGEGenesisDirectAmount returns the nSPX paid straight to label's recipient
// in the genesis block: the sold amount (always liquid) plus whatever
// label's own schedule releases at CGE. remainderTotal is the nSPX value of
// CGEGenesisAmountSPX(label) — the post-sale remainder that the schedule
// applies to; the sold amount is computed internally and must not be added
// into remainderTotal by the caller.
func CGEGenesisDirectAmount(label string, remainderTotal *big.Int) *big.Int {
	sold := new(big.Int).Mul(big.NewInt(CGESoldAmountSPX(label)), big.NewInt(1e18))
	return new(big.Int).Add(sold, CGEUnlockedAmount(label, remainderTotal))
}

// CGEGenesisEscrowAmount returns the nSPX routed to CGEEscrowAddress in the
// genesis block for label: the locked portion of the post-sale remainder.
// The sold amount is never escrowed.
func CGEGenesisEscrowAmount(label string, remainderTotal *big.Int) *big.Int {
	return CGELockedAmount(label, remainderTotal)
}

// ----------------------------------------------------------------------------
// Development module releases
//
// CGEMaxModules is 3,000 modules at 50,000 SPX each
// (3,000 × 50,000 SPX = 150,000,000 SPX exactly —
// exactly the amount escrowed at genesis for the Development allocation).
// IDs are validated against 1..3000 and every release pays 50,000 SPX.
// ----------------------------------------------------------------------------
const (
	// CGEModuleRewardSPX is the reward paid per completed development
	// module: 50,000 SPX.
	CGEModuleRewardSPX int64 = 50_000

	// CGEMaxModules is the total number of development modules the
	// Development Fund schedules: 3,000 × 50,000 SPX = 150,000,000 SPX —
	// exactly the amount escrowed at genesis for the Development allocation.
	CGEMaxModules uint64 = 3_000

	// cgeStateModulesReleasedKey persists the highest development module ID
	// released so far (decimal string). Because IDs are released strictly
	// sequentially from 1, this doubles as the count of released modules.
	cgeStateModulesReleasedKey = "cge:modules_released"
)

// CGEState is the minimal deterministic state interface required by CGE
// module release operations. It is satisfied by *core.StateDB and test fakes.
type CGEState interface {
	GetBalance(address string) (*big.Int, error)
	Transfer(from, to string, amount *big.Int) error
	GetContractValue(key string) ([]byte, error)
	SetContractValue(key string, value []byte)
}

// CGEModuleRewardNSPX returns the per-module reward in nSPX (50,000 × 10^18).
func CGEModuleRewardNSPX() *big.Int {
	return new(big.Int).Mul(big.NewInt(CGEModuleRewardSPX), big.NewInt(1e18))
}

// CGEDevModulesReleased returns the highest development module ID released so far
// from the persistent contract store (0 if none released yet).
func CGEDevModulesReleased(state CGEState) uint64 {
	if state == nil {
		return 0
	}
	value, err := state.GetContractValue(cgeStateModulesReleasedKey)
	if err != nil || len(value) == 0 {
		return 0
	}
	id, err := strconv.ParseUint(string(value), 10, 64)
	if err != nil {
		return 0
	}
	return id
}

// ReleaseDevelopmentModule releases the module reward for one completed
// development module out of CGEEscrowAddress to the canonical Development
// allocation recipient address (50,000 SPX per module, up to 3,000 modules = 150,000,000 SPX).
//
// Requirements & guarantees:
//   - moduleID must be in range [1, CGEMaxModules]
//   - releases must be strictly sequential (moduleID == alreadyReleased + 1),
//     preventing re-releases, double-spend, and skipped milestones
//   - transfers 50,000 SPX (in nSPX) from CGEEscrowAddress to recipient
//   - updates cge:modules_released in state contract storage, making progress
//     deterministic and cryptographically anchored in the state root
func ReleaseDevelopmentModule(state CGEState, recipient string, moduleID uint64) error {
	if state == nil {
		return fmt.Errorf("ReleaseDevelopmentModule: nil state")
	}
	if recipient == "" {
		return fmt.Errorf("ReleaseDevelopmentModule: empty recipient")
	}
	if moduleID == 0 || moduleID > CGEMaxModules {
		return fmt.Errorf("ReleaseDevelopmentModule: module %d out of range [1, %d]", moduleID, CGEMaxModules)
	}

	released := CGEDevModulesReleased(state)
	if moduleID <= released {
		return fmt.Errorf("ReleaseDevelopmentModule: module %d already released (released=%d)", moduleID, released)
	}
	if moduleID != released+1 {
		return fmt.Errorf("ReleaseDevelopmentModule: out of order — next releasable module is %d, got %d", released+1, moduleID)
	}

	reward := CGEModuleRewardNSPX()
	bal, err := state.GetBalance(CGEEscrowAddress)
	if err != nil {
		return fmt.Errorf("ReleaseDevelopmentModule: escrow balance unreadable: %w", err)
	}
	if bal.Cmp(reward) < 0 {
		return fmt.Errorf("ReleaseDevelopmentModule: escrow holds %s nSPX, need %s nSPX for module %d", bal, reward, moduleID)
	}

	if err := state.Transfer(CGEEscrowAddress, recipient, reward); err != nil {
		return fmt.Errorf("ReleaseDevelopmentModule: transfer module %d reward: %w", moduleID, err)
	}

	state.SetContractValue(cgeStateModulesReleasedKey, []byte(strconv.FormatUint(moduleID, 10)))
	return nil
}
