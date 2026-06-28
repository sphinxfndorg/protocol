// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/consensus/selection.go
package consensus

import (
	"encoding/binary"
	"math/big"
	"sort"

	logger "github.com/sphinxfndorg/protocol/src/log"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
)

// sips0014 https://github.com/sphinxorg/SIPS/blob/main/.github/workflows/sips0014/sips0014.md

// NewStakeWeightedSelector constructs a selector that uses the provided
// ValidatorSet for all proposer and committee selection calls.
func NewStakeWeightedSelector(vs *ValidatorSet) *StakeWeightedSelector {
	return &StakeWeightedSelector{
		validatorSet: vs, // live registry — mutations are visible immediately
	}
}

// SelectProposer deterministically selects exactly one block proposer for the
// given epoch using stake-weighted random selection seeded by the RANDAO output.
//
// Algorithm:
//  1. Collect active validators and sort them by ID (canonical order).
//  2. Convert the 32-byte seed to a big.Int.
//  3. Compute target = seed mod totalStake — a random point in stake-space.
//  4. Walk the sorted slice accumulating stake until cumulative > target.
//     The validator whose stake "covers" the target is the elected proposer.
//
// Because steps 1-4 are fully deterministic given the same inputs, every node
// that calls SelectProposer with the same epoch and seed returns the same winner.
// SelectProposer deterministically selects exactly one block proposer for the
// given epoch using stake-weighted random selection seeded by the RANDAO output.
func (s *StakeWeightedSelector) SelectProposer(epoch uint64, seed [32]byte) *StakedValidator {
	// Gather all validators that are active in the given epoch.
	active := s.validatorSet.GetActiveValidators(epoch)
	if len(active) == 0 {
		return nil // no validators registered — cannot elect a leader
	}

	// ── SORT — the critical fix ───────────────────────────────────────────────
	// GetActiveValidators iterates a map, so the returned slice order is random.
	// Sorting by ID gives every node the exact same iteration order, ensuring
	// that the cumulative-stake walk below produces the same winner everywhere.
	sort.Slice(active, func(i, j int) bool {
		return active[i].ID < active[j].ID // lexicographic by node ID string
	})
	// ─────────────────────────────────────────────────────────────────────────

	// Sum the stake of all active validators to define the full stake-space range.
	totalStake := s.validatorSet.GetTotalStake()

	// ========== DEBUG: Log all validator stakes ==========
	logger.Info("🔍 SelectProposer: epoch=%d, totalStake=%s SPX, validators=%d",
		epoch,
		new(big.Int).Div(totalStake, big.NewInt(denom.SPX)).String(),
		len(active))
	for _, v := range active {
		stakeSPX := new(big.Int).Div(v.StakeAmount, big.NewInt(denom.SPX))
		logger.Info("  Validator %s: stake=%d SPX", v.ID, stakeSPX.Uint64())
	}
	// =============================================

	// Check if total stake is zero or nil - SINGLE CHECK
	if totalStake == nil || totalStake.Sign() == 0 {
		// No stake recorded — fall back to the first validator in sorted order.
		logger.Warn("⚠️ Total stake is zero! Using round-robin fallback to first validator: %s", active[0].ID)
		return active[0]
	}

	// Interpret the 32-byte RANDAO seed as a big-endian unsigned integer.
	seedNum := new(big.Int).SetBytes(seed[:])

	// Map the seed into [0, totalStake) so it identifies a point in stake-space.
	target := new(big.Int).Mod(seedNum, totalStake)

	// Walk the sorted validator list, accumulating stake.  The first validator
	// whose cumulative stake exceeds the target wins the election.
	cumulative := big.NewInt(0)
	for _, v := range active {
		cumulative.Add(cumulative, v.StakeAmount) // add this validator's stake
		if target.Cmp(cumulative) < 0 {           // target is now covered
			return v // this validator is the elected proposer
		}
	}

	// Fallback (should only be reached due to rounding in integer division):
	// return the last validator in sorted order so the result is still deterministic.
	return active[len(active)-1]
}

// SelectCommittee selects a committee of up to `size` validators for attestation
// during the given epoch.  A different seed byte is used to avoid the committee
// overlapping with the proposer selection.
func (s *StakeWeightedSelector) SelectCommittee(epoch uint64, seed [32]byte, size int) []*StakedValidator {
	active := s.validatorSet.GetActiveValidators(epoch)
	if len(active) == 0 {
		return nil
	}

	// Sort for determinism before shuffling, same reason as SelectProposer.
	sort.Slice(active, func(i, j int) bool {
		return active[i].ID < active[j].ID
	})

	// Flip the first seed byte so committee selection uses a different random
	// sequence than proposer selection even for the same slot.
	seed[0] ^= 0xFF

	// Shuffle the sorted slice using the modified seed.
	shuffled := s.shuffleValidators(active, seed)

	// Return the first `size` validators from the shuffled slice.
	if len(shuffled) > size {
		return shuffled[:size]
	}
	return shuffled
}

// shuffleValidators performs a deterministic Fisher-Yates shuffle of the
// validator slice using a 32-byte seed as the source of pseudo-randomness.
// The same seed always produces the same permutation.
func (s *StakeWeightedSelector) shuffleValidators(validators []*StakedValidator, seed [32]byte) []*StakedValidator {
	// Work on a copy so the original slice is not mutated.
	result := make([]*StakedValidator, len(validators))
	copy(result, validators)

	// Derive two independent 64-bit random streams from the seed.
	r1 := binary.LittleEndian.Uint64(seed[:8])   // first 8 bytes
	r2 := binary.LittleEndian.Uint64(seed[8:16]) // next 8 bytes

	// Standard Fisher-Yates shuffle (Knuth shuffle), iterating backwards.
	for i := len(result) - 1; i > 0; i-- {
		// Advance both LCG streams to generate the next pseudo-random value.
		r1 = r1*1103515245 + 12345 // LCG parameters from glibc rand()
		r2 = r2*1103515245 + 12345
		// XOR the two streams and reduce modulo (i+1) to get a swap index.
		j := int((r1 ^ r2) % uint64(i+1))
		result[i], result[j] = result[j], result[i] // swap
	}
	return result
}
