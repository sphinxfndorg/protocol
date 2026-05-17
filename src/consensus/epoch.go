// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// consensus/epoch.go
package consensus

import (
	"math/big"
	"time"

	logger "github.com/sphinxorg/protocol/src/log"
	denom "github.com/sphinxorg/protocol/src/params/denom"
)

// sips0013 https://github.com/sphinxorg/SIPS/blob/main/.github/workflows/sips0013/sips0013.md

const (
	// SlotDuration is the time for one block (12 seconds like Ethereum)
	// This defines the block production interval - each slot can produce one block
	SlotDuration = 12 * time.Second

	// SlotsPerEpoch is number of slots in one epoch
	// Each epoch contains 32 slots for processing attestations and finality
	SlotsPerEpoch = 32

	// EpochDuration is time for one full epoch
	// Calculated as slot duration multiplied by slots per epoch = 6.4 minutes
	EpochDuration = SlotDuration * SlotsPerEpoch // 6.4 minutes
)

// NewTimeConverter creates a new TimeConverter instance
// The time converter maps slot numbers to actual timestamps based on genesis time
func NewTimeConverter(genesisTime time.Time) *TimeConverter {
	return &TimeConverter{
		genesisTime: genesisTime, // Store genesis time as reference point
	}
}

// SlotToTime converts slot number to actual time
// This allows calculating when a specific slot should occur based on genesis
func (tc *TimeConverter) SlotToTime(slot uint64) time.Time {
	// Add slot duration multiplied by slot number to genesis time
	return tc.genesisTime.Add(time.Duration(slot) * SlotDuration)
}

// CurrentSlot returns current slot number
// Calculates how many slots have passed since genesis
func (tc *TimeConverter) CurrentSlot() uint64 {
	elapsed := time.Since(tc.genesisTime) // Time elapsed since genesis
	return uint64(elapsed / SlotDuration) // Number of complete slots
}

// CurrentEpoch returns current epoch number
// Calculates current epoch based on current slot
func (tc *TimeConverter) CurrentEpoch() uint64 {
	return tc.CurrentSlot() / SlotsPerEpoch // Integer division gives epoch
}

// IsNewEpoch checks if we've entered a new epoch
// Compares current epoch with last known epoch to detect transition
func (tc *TimeConverter) IsNewEpoch(lastEpoch uint64) bool {
	currentEpoch := tc.CurrentEpoch() // Get current epoch
	return currentEpoch > lastEpoch   // True if we've advanced
}

// processEpochAttestations processes attestations for finality.
// This function determines which blocks become justified and finalized
// based on attestations collected during an epoch.
// MUST be called with c.mu already held (no internal locking).
func (c *Consensus) processEpochAttestations(epoch uint64) {
	// NOTE: c.mu is already held by the caller — do NOT lock here.

	// Retrieve attestations for this epoch from the attestations map
	attestations := c.attestations[epoch]

	// If no attestations, nothing to process
	if len(attestations) == 0 {
		logger.Info("No attestations for epoch %d", epoch)
		return
	}

	// Map to aggregate stake votes per block hash
	blockVotes := make(map[string]*big.Int)

	// Aggregate stake for each block based on attestations
	for _, att := range attestations {
		// Get the stake of the validator who made this attestation
		stake := c.getValidatorStake(att.ValidatorID)

		// Initialize vote tally for this block if not already present
		if blockVotes[att.BlockHash] == nil {
			blockVotes[att.BlockHash] = big.NewInt(0)
		}
		// Add this validator's stake to the block's vote total
		blockVotes[att.BlockHash].Add(blockVotes[att.BlockHash], stake)
	}

	// Calculate required stake for justification (2/3 of total stake)
	totalStake := c.validatorSet.GetTotalStake()
	required := new(big.Int).Mul(totalStake, big.NewInt(2))
	required.Div(required, big.NewInt(3))

	// Check each block to see if it achieved 2/3 majority
	for blockHash, votedStake := range blockVotes {
		// If block has sufficient stake votes, it becomes justified
		if votedStake.Cmp(required) >= 0 {
			// Convert to SPX for readable logging
			votedSPX := new(big.Float).Quo(
				new(big.Float).SetInt(votedStake),
				new(big.Float).SetFloat64(denom.SPX))

			logger.Info("🎯 Epoch %d justified for block %s with %v SPX stake",
				epoch, blockHash, votedSPX)

			// Check if we can finalize the previous epoch
			// In Casper FFG, when epoch N is justified and epoch N-1 was justified,
			// epoch N-1 becomes finalized
			if c.justifiedEpoch == epoch-1 {
				c.finalizedEpoch = epoch - 1
				logger.Info("🔒 Epoch %d FINALIZED!", epoch-1)
			}

			// Update justified epoch
			c.justifiedEpoch = epoch
		}
	}
}

// ProcessEpochTransition handles validator activations/exits at epoch boundaries
// This manages the validator lifecycle - new validators become active,
// exiting validators are removed from the active set
func (vs *ValidatorSet) ProcessEpochTransition(epoch uint64) {
	vs.mu.Lock()         // Lock for thread safety
	defer vs.mu.Unlock() // Ensure unlock on return

	// Process all validators for activation or exit
	for _, v := range vs.validators {
		// Check if this validator is scheduled to activate in this epoch
		if v.ActivationEpoch == epoch {
			logger.Info("✨ Validator %s activated at epoch %d with %v SPX",
				v.ID, epoch, v.GetStakeInSPX())
			// Note: Activation status is tracked elsewhere - this just logs
		}

		// Check if this validator is scheduled to exit in this epoch
		if v.ExitEpoch == epoch {
			logger.Info("👋 Validator %s exited at epoch %d", v.ID, epoch)
			// Remove from total stake calculation? Or keep for history?
			// Currently just logs, actual removal would happen elsewhere
		}
	}
}

// GetEpochStakeDistribution returns stake distribution for an epoch
// This provides a snapshot of validator stakes at a specific epoch
// Useful for historical analysis and debugging
func (vs *ValidatorSet) GetEpochStakeDistribution(epoch uint64) map[string]float64 {
	// Create map to hold stake distribution
	distribution := make(map[string]float64)

	// Get active validators for this epoch
	active := vs.GetActiveValidators(epoch)

	// Populate distribution map with each validator's stake in SPX
	for _, v := range active {
		distribution[v.ID] = v.GetStakeInSPX()
	}

	return distribution
}
