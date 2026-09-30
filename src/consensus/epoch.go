// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// consensus/epoch.go
package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"sync"

	logger "github.com/sphinxfndorg/protocol/src/console"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
)

// sips0013 https://github.com/sphinxorg/SIPS/blob/main/.github/workflows/sips0013/sips0013.md

// ============================================================================
// DELETED: wall-clock epoch arithmetic
// ============================================================================
//
// Removed: SlotDuration, SlotsPerEpoch, EpochDuration, TimeConverter and its
// methods (NewTimeConverter, SlotToTime, CurrentSlot, CurrentEpoch, IsNewEpoch).
//
// Two distinct notions of "epoch" were tangled together here, and neither
// belonged:
//
//  1. TimeConverter.CurrentEpoch() = wall-clock elapsed / SlotDuration / 32.
//     Two nodes with a one-second clock skew disagree about the current epoch,
//     so any decision keyed on it is unreproducible. Chain state cannot depend
//     on a local clock.
//
//  2. view / SlotsPerEpoch, used at five proposer-selection sites. A view is a
//     local round counter, so two nodes at the SAME HEIGHT in different views
//     elected different leaders from different membership — and then rejected
//     each other's proposals as "invalid leader".
//
// Both are replaced by a single rule: the epoch is ALWAYS
// EpochForHeight(height) = height / EpochBlocks, where EpochBlocks is a chain
// parameter. Height is chain state that every node agrees on by construction.
//
// The view still feeds the RANDAO seed. That is fine and intentional: a seed
// only has to be unpredictable, not identical across nodes, so it does not need
// to be a deterministic function of chain state. What must not be view-derived
// is MEMBERSHIP.
//
// Do not reintroduce a time- or view-derived epoch. If something needs "the
// epoch now", call EpochForHeight with the chain height.

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
				logger.Info(" Epoch %d FINALIZED!", epoch-1)
			}

			// Update justified epoch
			c.justifiedEpoch = epoch
		}
	}
}

// ProcessEpochTransition activates validators whose ActivationEpoch has arrived,
// retires those whose ExitEpoch has, and REBUILDS totalStake from the set that
// can actually vote. Returns the IDs activated and retired.
//
// totalStake is REBUILT, not incremented. That is the single invariant that
// keeps quorum honest: a pending validator contributes zero, a slashed or
// retired validator contributes zero, and every node that processes the same
// blocks reaches the same total. Incremental updates are how a pending
// validator ends up in the denominator before it is allowed to vote, which
// stalls the chain instead of admitting it.
//
// This is the ONLY place the live set membership is meant to change.
func (vs *ValidatorSet) ProcessEpochTransition(epoch uint64) (activated, retired []string) {
	if vs == nil {
		return nil, nil
	}
	vs.mu.Lock()
	defer vs.mu.Unlock()

	// Process all validators for activation or exit
	for id, v := range vs.validators {
		if v == nil {
			continue
		}
		if v.ExitEpoch != 0 && v.ExitEpoch <= epoch {
			// Retired: the record is kept (so history and snapshots stay
			// meaningful) but it contributes no stake from here on.
			retired = append(retired, id)
			continue
		}
		if v.ActivationEpoch != 0 && v.ActivationEpoch <= epoch {
			activated = append(activated, id)
		}
	}
	sort.Strings(activated)
	sort.Strings(retired)

	// The total is REBUILT from membership by the single shared helper, so the
	// boundary and the live-read path cannot compute it differently.
	vs.rebuildTotalLocked(epoch)
	total := vs.totalStake

	if len(activated) > 0 || len(retired) > 0 {
		logger.Info("Epoch %d transition: %d activated, %d retired, active stake now %s SPX",
			epoch, len(activated), len(retired),
			new(big.Int).Div(total, new(big.Int).SetUint64(denom.SPX)).String())
		for _, id := range activated {
			logger.Info("  Validator %s is now ACTIVE (epoch %d)", id, epoch)
		}
		for _, id := range retired {
			logger.Info("  Validator %s RETIRED (epoch %d)", id, epoch)
		}
	}
	return activated, retired
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

// ============================================================================
// Epoch arithmetic and validator snapshots (Checkpoint 1)
//
// ★ THE EPOCH IS A FUNCTION OF HEIGHT, NOT OF VIEW AND NOT OF THE CLOCK.
//
//	epoch(h) = h / EpochBlocks
//
// EpochBlocks is a CHAIN PARAMETER, read from the genesis document (the only
// place it comes from — see SetEpochBlocks, called by core.SetGenesisEpochBlocks).
// View and slot numbers still drive leader rotation and timeouts, but they must
// never decide membership: two nodes at the same height in different views have
// to compute the same validator set, or they compute different quorums for the
// same block.
//
// This replaces the wall-clock TimeConverter and the view-derived
// viewSlot/SlotsPerEpoch epoch that used to feed SelectProposer and
// onEpochTransition.
// ============================================================================

var (
	epochBlocksMu       sync.RWMutex
	epochBlocksOverride uint64
)

// DefaultEpochBlocks is the production epoch length. Large, so epoch boundaries
// (activations, exits, inflation) are rare events.
const DefaultEpochBlocks uint64 = 1000

// SetEpochBlocks records the chain's EpochBlocks parameter. Called once, from
// core.SetGenesisEpochBlocks, which reads it from genesis_state.json. Zero is a
// no-op so an absent override falls back to DefaultEpochBlocks.
func SetEpochBlocks(n uint64) {
	if n == 0 {
		return
	}
	epochBlocksMu.Lock()
	epochBlocksOverride = n
	epochBlocksMu.Unlock()
}

// EpochBlocks returns the chain's epoch length in blocks.
func EpochBlocks() uint64 {
	epochBlocksMu.RLock()
	n := epochBlocksOverride
	epochBlocksMu.RUnlock()
	if n == 0 {
		return DefaultEpochBlocks
	}
	return n
}

// EpochBlocksOverride returns the RAW override, without the default applied, so
// a caller can tell "genesis said 10" from "nothing was set and 1000 is the
// default". Zero means unset.
//
// It also exists so a test can save and restore the exact prior value instead of
// guessing at it: SetEpochBlocks treats zero as "no change", so a test that
// restored 0 would silently leave the override installed for every later test
// in the package.
func EpochBlocksOverride() uint64 {
	epochBlocksMu.RLock()
	defer epochBlocksMu.RUnlock()
	return epochBlocksOverride
}

// EpochForHeight derives the epoch that a height belongs to.
func EpochForHeight(height uint64) uint64 {
	eb := EpochBlocks()
	if eb == 0 {
		return 0
	}
	return height / eb
}

// IsEpochBoundary reports whether `height` starts a new epoch.
//
// ★ Height 0 IS arithmetically a boundary (0 % n == 0) but is NOT a
// transition: genesis is the authored set, not the result of one. The single
// caller skips height 0 explicitly, so this stays a pure modulus function.
func IsEpochBoundary(height uint64) bool {
	eb := EpochBlocks()
	if eb == 0 {
		return false
	}
	return height%eb == 0
}

// ActivationEpochForStake returns the epoch at which a validator staking NOW
// activates: nextEpochStart + 1 epoch.
//
// ★ The one-epoch delay is the whole point. A stake submitted during epoch e is
// recorded immediately but gains weight only at the start of epoch e+2. That
// delay guarantees a validator is not added while it is still syncing: it has a
// full epoch to catch up before it can hold vote weight or stall the chain it
// is behind.
//
// Genesis validators use activation epoch 0, meaning "active from epoch 0".
func ActivationEpochForStake(currentHeight uint64) uint64 {
	eb := EpochBlocks()
	if eb == 0 {
		return 0
	}
	return currentHeight/eb + 2
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

// ValidatorSnapshot is an immutable, deep-copied record of the validator set
// that governs one epoch.
//
// ★ IMMUTABLE BY CONSTRUCTION. Every field is copied on the way in, including
// the big.Int stakes, so nothing a later epoch transition does to the live set
// can reach back and change a snapshot that has already been taken. A snapshot
// that aliased the live set would let a node verify an old block against a
// membership that did not exist when the block was made.
type ValidatorSnapshot struct {
	Epoch      uint64
	Validators map[string]*StakedValidator
	TotalStake *big.Int
}

// Hash returns a deterministic digest of the snapshot, so it can be committed to
// in a block header. Validators are sorted by ID, so the digest does not depend
// on map iteration order.
func (s *ValidatorSnapshot) Hash() string {
	if s == nil {
		return ""
	}
	ids := make([]string, 0, len(s.Validators))
	for id := range s.Validators {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	h := sha256.New()
	fmt.Fprintf(h, "epoch=%d;total=%s;", s.Epoch, s.TotalStake.String())
	for _, id := range ids {
		fmt.Fprintf(h, "%s=%s;", id, s.Validators[id].StakeAmount.String())
	}
	return hex.EncodeToString(h.Sum(nil))
}

var (
	snapshotMu      sync.RWMutex
	snapshotByEpoch = make(map[uint64]*ValidatorSnapshot)
)

// TakeSnapshot freezes the set that GOVERNS `epoch` and stores it.
//
// Epoch filtering is the point: a validator whose ActivationEpoch is still in
// the future is PENDING and must NOT appear in the set governing this epoch,
// and TotalStake is summed from the snapshot's OWN rows rather than read from
// the live field — otherwise the denominator could contain stake that no voter
// in the snapshot could account for, and quorum could never be met.
func (vs *ValidatorSet) TakeSnapshot(epoch uint64) *ValidatorSnapshot {
	if vs == nil {
		return nil
	}
	snap := &ValidatorSnapshot{
		Epoch:      epoch,
		Validators: make(map[string]*StakedValidator),
		TotalStake: big.NewInt(0),
	}
	for _, v := range vs.GetActiveValidators(epoch) {
		if v == nil {
			continue
		}
		stake := big.NewInt(0)
		if v.StakeAmount != nil {
			stake = new(big.Int).Set(v.StakeAmount)
		}
		// Deep copy: this row must never alias the live validator.
		snap.Validators[v.ID] = &StakedValidator{
			ID:              v.ID,
			StakeAmount:     new(big.Int).Set(stake),
			ActivationEpoch: v.ActivationEpoch,
			ExitEpoch:       v.ExitEpoch,
			IsSlashed:       v.IsSlashed,
			LastAttested:    v.LastAttested,
			RewardAddress:   v.RewardAddress,
		}
		snap.TotalStake.Add(snap.TotalStake, stake)
	}
	snapshotMu.Lock()
	snapshotByEpoch[epoch] = snap
	snapshotMu.Unlock()

	// Persist at the moment of taking, so a crash before the next boundary does
	// not lose the set governing the epoch this node is currently serving.
	persistSnapshot(snap)

	logger.Info("Validator snapshot for epoch %d: %d validator(s), %s SPX, hash %s",
		epoch, len(snap.Validators),
		new(big.Float).Quo(new(big.Float).SetInt(snap.TotalStake), new(big.Float).SetFloat64(denom.SPX)),
		snap.Hash()[:16])
	return snap
}

// ValidatorSetAt returns the snapshot that governs `height`.
//
// ★ THIS IS THE AUTHORITATIVE LOOKUP, and it is HEIGHT-keyed on purpose. The
// epoch is derived internally, so a caller can never pair a height with an
// epoch number computed under a different EpochBlocks, and there is
// deliberately no exported epoch-keyed getter to misuse.
func ValidatorSetAt(height uint64) *ValidatorSnapshot {
	return SnapshotAtEpoch(EpochForHeight(height))
}

// SnapshotAtEpoch returns the snapshot for an epoch. Callers should prefer
// ValidatorSetAt, which derives the epoch from a height.
func SnapshotAtEpoch(epoch uint64) *ValidatorSnapshot {
	snapshotMu.RLock()
	defer snapshotMu.RUnlock()
	return snapshotByEpoch[epoch]
}

// ResetSnapshots clears the snapshot store. A fresh chain must not inherit a
// previous one's snapshots; also used by tests.
func ResetSnapshots() {
	snapshotMu.Lock()
	snapshotByEpoch = make(map[uint64]*ValidatorSnapshot)
	snapshotMu.Unlock()
}

// ---------------------------------------------------------------------------
// Test support
// ---------------------------------------------------------------------------

// StoreSnapshotForTest installs a hand-built snapshot into the store, without
// requiring a live ValidatorSet to produce it.
//
// It exists for the block-verification tests in package core, which need to
// place a specific epoch's set in place and then assert how verification
// behaves. It deliberately bypasses TakeSnapshot so a test can construct a
// snapshot that no transition would ever produce — for example an epoch-2 set
// installed while no epoch-0 snapshot exists.
//
// It is a test-only export, so it cannot be reached from production code.
func StoreSnapshotForTest(snap ValidatorSnapshot) {
	clone := snap.Clone()
	snapshotMu.Lock()
	snapshotByEpoch[clone.Epoch] = clone
	snapshotMu.Unlock()
}

// RestoreEpochBlocks puts the epoch parameter back to an exact prior value,
// including zero ("unset"), which SetEpochBlocks cannot express because it
// treats zero as "no change". Without it, a test that shrinks EpochBlocks
// would leak the override into every later test in the package.
func RestoreEpochBlocks(prev uint64) {
	epochBlocksMu.Lock()
	epochBlocksOverride = prev
	epochBlocksMu.Unlock()
}

// Clone returns a deep copy of the snapshot, so a caller cannot mutate a stored
// snapshot by holding on to a row it passed in.
func (s ValidatorSnapshot) Clone() *ValidatorSnapshot {
	out := &ValidatorSnapshot{
		Epoch:      s.Epoch,
		TotalStake: big.NewInt(0),
		Validators: make(map[string]*StakedValidator, len(s.Validators)),
	}
	if s.TotalStake != nil {
		out.TotalStake = new(big.Int).Set(s.TotalStake)
	}
	for id, v := range s.Validators {
		if v == nil {
			continue
		}
		row := *v
		if v.StakeAmount != nil {
			row.StakeAmount = new(big.Int).Set(v.StakeAmount)
		}
		out.Validators[id] = &row
	}
	return out
}

// SnapshotStore is the persistence seam for validator snapshots. It is an
// interface rather than a direct rawdb dependency so consensus does not import
// the storage layer, which imports consensus.
//
// ★ FAIL CLOSED IS THE WHOLE POINT. A node whose store is unavailable must not
// quietly serve in-memory snapshots as if they were durable, because a
// restart would then lose exactly the epochs it still needs to verify.
type SnapshotStore interface {
	// PutSnapshot persists one epoch's snapshot. It is called at the moment the
	// snapshot is taken, not at shutdown.
	PutSnapshot(epoch uint64, snap *ValidatorSnapshot) error
	// AllSnapshots returns every persisted snapshot, for replay on startup.
	AllSnapshots() ([]*ValidatorSnapshot, error)
}

// snapshotStoreMu guards snapshotStore, which is attached once at startup and
// read from the epoch-boundary path.
var (
	snapshotStoreMu sync.RWMutex
	snapshotStore   SnapshotStore
)

// SetSnapshotStore attaches the durable store. Passing nil detaches it, which
// puts the node back into fail-closed mode: a snapshot that is not in memory
// cannot be recovered, so blocks in that epoch are rejected.
func SetSnapshotStore(s SnapshotStore) {
	snapshotStoreMu.Lock()
	snapshotStore = s
	snapshotStoreMu.Unlock()
}

// CurrentSnapshotStore returns the attached store, or nil.
func CurrentSnapshotStore() SnapshotStore {
	snapshotStoreMu.RLock()
	defer snapshotStoreMu.RUnlock()
	return snapshotStore
}

// persistSnapshot writes snap through the attached store. A store failure is
// logged and the in-memory snapshot is left in place, but the epoch is
// REMEMBERED as unpersisted so a later read can fail closed rather than serve
// a snapshot that a restart would lose.
func persistSnapshot(snap *ValidatorSnapshot) {
	st := CurrentSnapshotStore()
	if st == nil || snap == nil {
		return
	}
	if err := st.PutSnapshot(snap.Epoch, snap); err != nil {
		logger.Error("FATAL Validator snapshot for epoch %d could NOT be persisted: %v — "+
			"a restart will lose it and verification of this epoch will fail closed", snap.Epoch, err)
	}
}

// ReplaySnapshotsFromStore rebuilds the in-memory snapshot store from durable
// storage, and returns how many epochs were recovered.
//
// It is called on startup, BEFORE the node accepts or verifies any block: a
// node that skipped a boundary while down must still be able to verify the
// epoch it is currently serving, and the only record of that set is the stored
// snapshot. Without this, every restart mid-epoch would fail closed on its own
// current epoch and stall.
func ReplaySnapshotsFromStore() (int, error) {
	st := CurrentSnapshotStore()
	if st == nil {
		return 0, fmt.Errorf("consensus: no snapshot store attached; cannot replay snapshots")
	}
	rows, err := st.AllSnapshots()
	if err != nil {
		return 0, fmt.Errorf("consensus: replaying validator snapshots: %w", err)
	}
	restored := make(map[uint64]*ValidatorSnapshot, len(rows))
	for _, snap := range rows {
		if snap == nil {
			continue
		}
		restored[snap.Epoch] = snap
	}
	snapshotMu.Lock()
	for epoch, snap := range restored {
		// Never overwrite a live in-memory snapshot: if this node took it
		// itself in this process, that copy is authoritative.
		if _, exists := snapshotByEpoch[epoch]; !exists {
			snapshotByEpoch[epoch] = snap
		}
	}
	total := len(snapshotByEpoch)
	snapshotMu.Unlock()
	logger.Info("Validator snapshots replayed from store: %d recovered, %d total known", len(restored), total)
	return len(restored), nil
}

// TotalStake returns the live set's total active stake in nSPX. Read-only: the
// only writer is ProcessEpochTransition, which rebuilds it from membership.
func (vs *ValidatorSet) TotalStake() *big.Int {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	if vs.totalStake == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(vs.totalStake)
}

// ReplaceAll atomically replaces the whole set. It exists for exactly one
// caller — restoring a state snapshot — and it goes through a single lock so a
// restore can never be observed half-applied.
func (vs *ValidatorSet) ReplaceAll(rows map[string]*StakedValidator) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	vs.validators = make(map[string]*StakedValidator, len(rows))
	for id, v := range rows {
		if v == nil {
			continue
		}
		vs.validators[id] = v
	}
}
