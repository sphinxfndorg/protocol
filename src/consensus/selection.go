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

// consensus/selection.go
package consensus

import (
	"encoding/binary"
	"math/big"
)

func NewStakeWeightedSelector(vs *ValidatorSet) *StakeWeightedSelector {
	return &StakeWeightedSelector{
		validatorSet: vs,
	}
}

// SelectProposer selects a block proposer using stake-weighted random selection
func (s *StakeWeightedSelector) SelectProposer(epoch uint64, seed [32]byte) *StakedValidator {
	active := s.validatorSet.GetActiveValidators(epoch)
	if len(active) == 0 {
		return nil
	}

	totalStake := s.validatorSet.GetTotalStake()

	// Convert seed to number
	seedNum := new(big.Int).SetBytes(seed[:])

	// Select random point in [0, totalStake)
	target := new(big.Int).Mod(seedNum, totalStake)

	// Find validator by cumulative stake
	cumulative := big.NewInt(0)
	for _, v := range active {
		cumulative.Add(cumulative, v.StakeAmount)
		if target.Cmp(cumulative) < 0 {
			return v
		}
	}

	return active[0] // Fallback
}

// SelectCommittee selects a committee of validators for attestation
func (s *StakeWeightedSelector) SelectCommittee(epoch uint64, seed [32]byte, size int) []*StakedValidator {
	active := s.validatorSet.GetActiveValidators(epoch)
	if len(active) == 0 {
		return nil
	}

	// Use different seed for committee selection
	seed[0] ^= 0xFF

	// Shuffle validators using seed
	shuffled := s.shuffleValidators(active, seed)

	// Take first 'size' validators
	if len(shuffled) > size {
		return shuffled[:size]
	}
	return shuffled
}

// Fisher-Yates shuffle with seed
func (s *StakeWeightedSelector) shuffleValidators(validators []*StakedValidator, seed [32]byte) []*StakedValidator {
	result := make([]*StakedValidator, len(validators))
	copy(result, validators)

	// Convert seed to 64-bit numbers
	r1 := binary.LittleEndian.Uint64(seed[:8])
	r2 := binary.LittleEndian.Uint64(seed[8:16])

	for i := len(result) - 1; i > 0; i-- {
		// Generate pseudo-random index
		r1 = r1*1103515245 + 12345
		r2 = r2*1103515245 + 12345
		j := int((r1 ^ r2) % uint64(i+1))

		result[i], result[j] = result[j], result[i]
	}

	return result
}
