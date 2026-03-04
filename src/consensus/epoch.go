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

// consensus/epoch.go
package consensus

import (
	"math/big"
	"time"

	logger "github.com/sphinxorg/protocol/src/log"
	denom "github.com/sphinxorg/protocol/src/params/denom"
)

const (
	// SlotDuration is the time for one block (12 seconds like Ethereum)
	SlotDuration = 12 * time.Second

	// SlotsPerEpoch is number of slots in one epoch
	SlotsPerEpoch = 32

	// EpochDuration is time for one full epoch
	EpochDuration = SlotDuration * SlotsPerEpoch // 6.4 minutes
)

func NewTimeConverter(genesisTime time.Time) *TimeConverter {
	return &TimeConverter{
		genesisTime: genesisTime,
	}
}

// SlotToTime converts slot number to actual time
func (tc *TimeConverter) SlotToTime(slot uint64) time.Time {
	return tc.genesisTime.Add(time.Duration(slot) * SlotDuration)
}

// CurrentSlot returns current slot number
func (tc *TimeConverter) CurrentSlot() uint64 {
	elapsed := time.Since(tc.genesisTime)
	return uint64(elapsed / SlotDuration)
}

// CurrentEpoch returns current epoch number
func (tc *TimeConverter) CurrentEpoch() uint64 {
	return tc.CurrentSlot() / SlotsPerEpoch
}

// IsNewEpoch checks if we've entered a new epoch
func (tc *TimeConverter) IsNewEpoch(lastEpoch uint64) bool {
	currentEpoch := tc.CurrentEpoch()
	return currentEpoch > lastEpoch
}

// ProcessEpochAttestations processes attestations for finality
// ProcessEpochAttestations processes attestations for finality
func (c *Consensus) processEpochAttestations(epoch uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	attestations := c.attestations[epoch]
	if len(attestations) == 0 {
		logger.Info("No attestations for epoch %d", epoch)
		return
	}

	// Group by target block
	blockVotes := make(map[string]*big.Int)
	for _, att := range attestations {
		stake := c.getValidatorStake(att.ValidatorID) // This returns nSPX
		if blockVotes[att.BlockHash] == nil {
			blockVotes[att.BlockHash] = big.NewInt(0)
		}
		blockVotes[att.BlockHash].Add(blockVotes[att.BlockHash], stake)
	}

	// Check for 2/3 majority
	totalStake := c.validatorSet.GetTotalStake() // This returns nSPX
	required := new(big.Int).Mul(totalStake, big.NewInt(2))
	required.Div(required, big.NewInt(3))

	for blockHash, votedStake := range blockVotes {
		if votedStake.Cmp(required) >= 0 {
			// Convert to SPX for human-readable logging
			votedSPX := new(big.Float).Quo(
				new(big.Float).SetInt(votedStake),
				new(big.Float).SetFloat64(denom.SPX))

			logger.Info("🎯 Epoch %d justified for block %s with %v SPX stake",
				epoch, blockHash, votedSPX)

			// Casper FFG finality rule
			if c.justifiedEpoch == epoch-1 {
				c.finalizedEpoch = epoch - 1
				logger.Info("🔒 Epoch %d FINALIZED!", epoch-1)
			}
			c.justifiedEpoch = epoch
		}
	}
}

// ProcessEpochTransition handles validator activations/exits at epoch boundaries
func (vs *ValidatorSet) ProcessEpochTransition(epoch uint64) {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	// Process pending activations
	for _, v := range vs.validators {
		if v.ActivationEpoch == epoch {
			logger.Info("✨ Validator %s activated at epoch %d with %v SPX",
				v.ID, epoch, v.GetStakeInSPX())
		}
		if v.ExitEpoch == epoch {
			logger.Info("👋 Validator %s exited at epoch %d", v.ID, epoch)
			// Remove from total stake calculation? Or keep for history?
		}
	}
}

// GetEpochStakeDistribution returns stake distribution for an epoch
func (vs *ValidatorSet) GetEpochStakeDistribution(epoch uint64) map[string]float64 {
	distribution := make(map[string]float64)
	active := vs.GetActiveValidators(epoch)

	for _, v := range active {
		distribution[v.ID] = v.GetStakeInSPX()
	}
	return distribution
}
