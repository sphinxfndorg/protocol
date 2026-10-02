package consensus

import (
	"math/big"
	"testing"
)

// TestProposerRotationOverManySlots answers, with data, the question "is
// block production a fixed node?".
//
// SelectProposer is stake-weighted RANDOM selection: target = seed mod
// totalStake, then a cumulative walk over validators sorted by ID. The seed
// changes per slot, so with more than one active validator the winner must
// change too.
//
// This builds a 3-validator set and runs 300 distinct slots. If the winner
// never changed, selection would be STATIC and the whole claim would be false.
func TestProposerRotationOverManySlots(t *testing.T) {
	ResetSnapshots()
	t.Cleanup(ResetSnapshots)
	unit := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
	vs := NewValidatorSet(unit)
	for _, id := range []string{"Node-a", "Node-b", "Node-c"} {
		if err := vs.AddGenesisValidator(id, unit); err != nil {
			t.Fatalf("AddGenesisValidator(%s): %v", id, err)
		}
	}
	vs.ProcessEpochTransition(0)
	snapshot := vs.TakeSnapshot(0)
	StoreSnapshotForTest(*snapshot)
	sel := NewStakeWeightedSelector(vs)

	counts := map[string]int{}
	const slots = 300
	for slot := uint64(1); slot <= slots; slot++ {
		var seed [32]byte
		// A distinct pseudo-random RANDAO-ish seed per slot.
		copy(seed[:], big.NewInt(int64(slot)*2654435761).Bytes())
		w := sel.SelectProposer(0, seed)
		if w != nil {
			counts[w.ID]++
		}
	}

	t.Logf("%d active validators over %d slots:", len(vs.GetValidators()), slots)
	for _, id := range []string{"Node-a", "Node-b", "Node-c"} {
		n := counts[id]
		t.Logf("  %s won %3d/%d (%.1f%%)", id, n, slots, 100*float64(n)/float64(slots))
	}
	if len(counts) < 2 {
		t.Errorf("★ only %d validator(s) ever selected across %d slots — "+
			"selection is STATIC, not random", len(counts), slots)
	}
}

func TestProposerSelectionUsesHeightSnapshotNotLiveSet(t *testing.T) {
	ResetSnapshots()
	t.Cleanup(ResetSnapshots)

	unit := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
	vs := NewValidatorSet(unit)
	for _, id := range []string{"Node-a", "Node-b"} {
		if err := vs.AddGenesisValidator(id, unit); err != nil {
			t.Fatalf("AddGenesisValidator(%s): %v", id, err)
		}
	}
	vs.ProcessEpochTransition(0)
	snapshot := vs.TakeSnapshot(0)
	StoreSnapshotForTest(*snapshot)

	selector := NewStakeWeightedSelector(vs)
	var seed [32]byte
	seed[31] = 1
	before := selector.SelectProposer(1, seed)
	if before == nil {
		t.Fatal("expected proposer from height-1 snapshot")
	}

	if err := vs.QueueValidator("Node-c", new(big.Int).Mul(unit, big.NewInt(100)), 0); err != nil {
		t.Fatalf("QueueValidator: %v", err)
	}
	after := selector.SelectProposer(1, seed)
	if after == nil || after.ID != before.ID {
		t.Fatalf("live set mutation changed election for same height snapshot: before=%v after=%v",
			before, after)
	}
	if got := len(ValidatorSetAt(1).Validators); got != 2 {
		t.Fatalf("height snapshot includes unstaked/new peer: got %d validators, want 2", got)
	}
}
