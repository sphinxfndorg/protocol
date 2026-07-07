// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/sync.go
//
// Quorum certificate verification for block sync. These functions verify that
// blocks received from peers carry valid commit attestations (≥2/3+ stake)
// before they are committed during catch-up sync.

package core

import (
	"fmt"
	"math/big"
	"sync"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	logger "github.com/sphinxfndorg/protocol/src/log"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
)

// validatorSetProvider is an interface for accessing validator set data
// This allows VerifyBlockAttestations to work with both consensus.ValidatorSet
// and core.ValidatorSet without creating circular dependencies
type validatorSetProvider interface {
	GetTotalStake() *big.Int
	// GetValidator returns a core-compatible view of a validator.
	// To avoid import cycles between core<->consensus, this method is
	// intentionally flexible: implementations may return either *StakedValidator
	// or a consensus.StakedValidator pointer that core can interpret.
	GetValidator(id string) interface{}
}

// ValidatorSetSnapshot stores a frozen copy of the validator set at a given
// epoch, so that blocks from that epoch can be verified even after the live
// validator set has changed (validators joined/left/slashed).
type ValidatorSetSnapshot struct {
	Epoch      uint64
	Validators map[string]*StakedValidator // copy of validators at this epoch
	TotalStake *big.Int
}

// validatorSetHistory stores per-epoch snapshots of the validator set.
// It is populated at each epoch transition and queried by
// VerifyBlockAttestations to find the correct set for a block's epoch.
var (
	validatorSetHistory   map[uint64]*ValidatorSetSnapshot
	validatorSetHistoryMu sync.RWMutex
)

func init() {
	validatorSetHistory = make(map[uint64]*ValidatorSetSnapshot)
}

// SnapshotValidatorSet creates a frozen copy of the current validator set
// for the given epoch and stores it in the history. Call this at each epoch
// transition (slot 0 of each new epoch) so that historical blocks can be
// verified against the correct validator set.
//
// NOTE: validator snapshots are taken from core.ValidatorSet.
func SnapshotValidatorSet(epoch uint64, vs *ValidatorSet) {
	if vs == nil {
		return
	}

	vs.mu.RLock()
	defer vs.mu.RUnlock()

	snapshot := &ValidatorSetSnapshot{
		Epoch:      epoch,
		Validators: make(map[string]*StakedValidator),
		TotalStake: new(big.Int).Set(vs.totalStake),
	}

	for id, v := range vs.validators {
		// Deep copy the StakedValidator
		copy := &StakedValidator{
			ID:              v.ID,
			StakeAmount:     new(big.Int).Set(v.StakeAmount),
			ActivationEpoch: v.ActivationEpoch,
			ExitEpoch:       v.ExitEpoch,
			IsSlashed:       v.IsSlashed,
			LastAttested:    v.LastAttested,
			RewardAddress:   v.RewardAddress,
		}
		snapshot.Validators[id] = copy
	}

	validatorSetHistoryMu.Lock()
	validatorSetHistory[epoch] = snapshot
	validatorSetHistoryMu.Unlock()

	logger.Info("📸 Snapshot validator set for epoch %d: %d validators, %s SPX total",
		epoch, len(snapshot.Validators),
		new(big.Float).Quo(new(big.Float).SetInt(snapshot.TotalStake), new(big.Float).SetFloat64(denom.SPX)))
}

// GetValidatorSetAtEpoch retrieves the validator set snapshot for a given
// epoch. Returns nil if no snapshot exists for that epoch (falls back to
// the current live set).
func GetValidatorSetAtEpoch(epoch uint64) *ValidatorSetSnapshot {
	validatorSetHistoryMu.RLock()
	defer validatorSetHistoryMu.RUnlock()
	snap, exists := validatorSetHistory[epoch]
	if !exists {
		return nil
	}
	return snap
}

// VerifyBlockAttestations checks that a block carries valid commit attestations
// representing ≥2/3+ of total validator stake. This is the sync-time equivalent
// of the PBFT commit quorum check.
//
// It looks up the validator set that was active at the block's epoch (via
// per-epoch snapshots), falling back to the current live set if no snapshot
// exists. This ensures correct verification even when validators rotate.
//
// Genesis block (height 0) is exempted from attestation verification — it
// has no attestations and is verified by hash/config match instead.
//
// Parameters:
//   - block: the block whose Body.Attestations should be verified
//   - vs: the current ValidatorSet (used as fallback if no epoch snapshot)
//   - epoch: the epoch in which this block was committed (0 for genesis)
//
// Returns nil if attestations are valid and meet quorum, or an error describing
// the failure.
func VerifyBlockAttestations(block *types.Block, vs validatorSetProvider, epoch uint64) error {
	if block == nil {
		return fmt.Errorf("block is nil")
	}

	// ── Genesis block exemption ──
	// The genesis block (height 0) has no attestations because it is created
	// by configuration, not by PBFT consensus. It is verified by hash/config
	// match instead of attestation quorum.
	if block.GetHeight() == 0 {
		logger.Info("✅ Genesis block (height 0) — skipping attestation verification (verified by config/hash)")
		return nil
	}

	if vs == nil {
		return fmt.Errorf("validator set is nil")
	}

	attestations := block.Body.Attestations
	if len(attestations) == 0 {
		return fmt.Errorf("block height %d has zero attestations — no quorum certificate", block.GetHeight())
	}

	// ── Determine which validator set to use ──
	// Try to find a snapshot for the block's epoch. If none exists, fall back
	// to the current live validator set. This handles the common case where
	// the validator set hasn't changed since the block was committed.
	var totalStake *big.Int
	var validatorLookup func(id string) *StakedValidator

	snap := GetValidatorSetAtEpoch(epoch)
	if snap != nil {
		totalStake = snap.TotalStake
		validatorLookup = func(id string) *StakedValidator {
			v, exists := snap.Validators[id]
			if !exists {
				return nil
			}
			return v
		}
		logger.Info("📋 Using epoch %d validator set snapshot (%d validators) for block %d verification",
			epoch, len(snap.Validators), block.GetHeight())
	} else {
		// Fall back to current live set via the interface
		totalStake = vs.GetTotalStake()
		validatorLookup = func(id string) *StakedValidator {
			vAny := vs.GetValidator(id)
			if vAny == nil {
				return nil
			}
			if v, ok := vAny.(*StakedValidator); ok {
				return v
			}
			// If a consensus.StakedValidator is returned, core can't type-assert
			// without importing consensus. Treat as unknown.
			return nil
		}

		logger.Info("📋 Using current validator set (no epoch %d snapshot) for block %d verification",
			epoch, block.GetHeight())
	}

	if totalStake == nil || totalStake.Sign() == 0 {
		return fmt.Errorf("total stake is zero — cannot verify quorum")
	}

	// Collect unique validators that attested
	attestedStake := big.NewInt(0)
	seen := make(map[string]bool)

	for _, att := range attestations {
		if att == nil {
			continue
		}
		if att.ValidatorID == "" {
			continue
		}
		if seen[att.ValidatorID] {
			continue // duplicate
		}
		seen[att.ValidatorID] = true

		// Look up the validator's stake from the appropriate set
		val := validatorLookup(att.ValidatorID)
		if val == nil {
			logger.Debug("VerifyBlockAttestations: validator %s not in active set for epoch %d", att.ValidatorID, epoch)
			continue
		}
		attestedStake.Add(attestedStake, val.StakeAmount)
	}

	// Calculate required stake: 2/3 of total
	requiredStake := new(big.Int).Mul(totalStake, big.NewInt(2))
	requiredStake.Div(requiredStake, big.NewInt(3))

	// Check quorum
	if attestedStake.Cmp(requiredStake) < 0 {
		attestedSPX := new(big.Float).Quo(new(big.Float).SetInt(attestedStake), new(big.Float).SetFloat64(denom.SPX))
		totalSPX := new(big.Float).Quo(new(big.Float).SetInt(totalStake), new(big.Float).SetFloat64(denom.SPX))
		requiredSPX := new(big.Float).Quo(new(big.Float).SetInt(requiredStake), new(big.Float).SetFloat64(denom.SPX))
		return fmt.Errorf("block %d attestation quorum not met: %.2f / %.2f SPX attested (need ≥ %.2f) from %d unique validators (epoch %d)",
			block.GetHeight(), attestedSPX, totalSPX, requiredSPX, len(seen), epoch)
	}

	attestedSPX := new(big.Float).Quo(new(big.Float).SetInt(attestedStake), new(big.Float).SetFloat64(denom.SPX))
	totalSPX := new(big.Float).Quo(new(big.Float).SetInt(totalStake), new(big.Float).SetFloat64(denom.SPX))
	pct := new(big.Float).Quo(attestedSPX, totalSPX)
	pct.Mul(pct, big.NewFloat(100))
	logger.Info("✅ Block %d attestation quorum verified: %.2f / %.2f SPX (%.1f%%) from %d validators (epoch %d)",
		block.GetHeight(), attestedSPX, totalSPX, pct, len(seen), epoch)

	return nil
}
