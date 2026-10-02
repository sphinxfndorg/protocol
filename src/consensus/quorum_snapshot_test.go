// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/consensus/quorum_snapshot_test.go
//
// CHECKPOINT 2 ITEM 1 — snapshot-based quorum, and the removal of the float
// quorum paths.
package consensus

import (
	"math/big"
	"testing"
)

// snapOfN builds an epoch-0 snapshot of n equal 32 SPX validators.
func snapOfN(n int) *ValidatorSnapshot {
	unit := spx32()
	s := &ValidatorSnapshot{
		Epoch:      0,
		TotalStake: new(big.Int).Mul(unit, big.NewInt(int64(n))),
		Validators: make(map[string]*StakedValidator, n),
	}
	for i := 0; i < n; i++ {
		id := "Node-" + string(rune('a'+i))
		s.Validators[id] = &StakedValidator{ID: id, StakeAmount: new(big.Int).Set(unit)}
	}
	return s
}

// TestQuorumFromSnapshot_FailsClosedAndUsesTheSnapshot is item 1's core claim.
//
//  1. A nil snapshot cannot reach quorum. This is what replaces getTotalNodes()
//     reading the LIVE set: with no chain-state record there is no denominator.
//  2. A vote from outside the governing snapshot is worth nothing.
//  3. The LIVE set is not consulted — shown by adding a whale to it after the
//     snapshot was taken and observing the verdict does not change.
func TestQuorumFromSnapshot_FailsClosedAndUsesTheSnapshot(t *testing.T) {
	snap := snapOfN(4)
	unit := spx32()

	// 1. Fail closed, at every vote weight that would otherwise pass.
	for _, v := range []*big.Int{big.NewInt(0), unit, new(big.Int).Mul(unit, big.NewInt(3))} {
		if quorumFromSnapshot(nil, v, 4) {
			t.Error("quorum granted with NO snapshot; that must fail closed")
		}
	}
	zero := &ValidatorSnapshot{Epoch: 0, TotalStake: big.NewInt(0), Validators: snap.Validators}
	if quorumFromSnapshot(zero, unit, 1) {
		t.Error("quorum granted against a zero-total snapshot")
	}

	// 2. In-set vote counts.
	if quorumFromSnapshot(snap, new(big.Int).Mul(unit, big.NewInt(2)), 2) {
		t.Error("2 of 4 equal-stake validators reached quorum (2/4 is not > 2/3)")
	}
	if !quorumFromSnapshot(snap, new(big.Int).Mul(unit, big.NewInt(3)), 3) {
		t.Error("3 of 4 equal-stake validators must reach strict >2/3")
	}

	// 3. The live set must not matter.
	live := NewValidatorSet(spx32())
	if err := live.AddGenesisValidator("Node-a", spx32()); err != nil {
		t.Fatalf("live: %v", err)
	}
	if err := live.AddGenesisValidator("Node-intruder", new(big.Int).Mul(unit, big.NewInt(100))); err != nil {
		t.Fatalf("live: %v", err)
	}
	if !quorumFromSnapshot(snap, new(big.Int).Mul(unit, big.NewInt(3)), 3) {
		t.Error("adding a whale to the LIVE set changed the verdict; quorum must " +
			"come from the snapshot alone")
	}
	if quorumFromSnapshot(snap, new(big.Int).Mul(unit, big.NewInt(100)), 1) {
		t.Error("a validator absent from the governing snapshot reached quorum alone")
	}
}

// TestVerifySafety_ThreeFPlusOne pins the corrected fault-tolerance bound. The
// old expression was `faultyNodes < setSize/3`, which depends on integer
// division flooring; the N=7,f=2 case separates the two.
func TestVerifySafety_ThreeFPlusOne(t *testing.T) {
	cases := []struct {
		n, f int
		want bool
		why  string
	}{
		{1, 0, true, "N=1,f=0: 1 >= 1"},
		{3, 0, true, "N=3,f=0: 3 >= 1"},
		{3, 1, false, "N=3,f=1: 3 >= 4 is false"},
		{4, 1, true, "N=4,f=1: 4 >= 4"},
		{4, 2, false, "N=4,f=2: 4 >= 7 is false"},
		{7, 2, true, "N=7,f=2: 7 >= 7 — f < N/3 gave false here (7/3=2, so f<2 allows only 1)"},
		{7, 3, false, "N=7,f=3: 7 >= 10 is false"},
		{100, 33, true, "N=100,f=33: 100 >= 100"},
		{100, 34, false, "N=100,f=34: 100 >= 103 is false"},
	}
	for _, c := range cases {
		qv := &QuorumVerifier{setSize: c.n, faultyNodes: c.f, quorumFraction: 0.67}
		if got := qv.VerifySafety(); got != c.want {
			t.Errorf("VerifySafety(N=%d,f=%d) = %v, want %v — %s", c.n, c.f, got, c.want, c.why)
		}
	}
}

// TestCalculateMinQuorumSize_IntegerMatchesEngine is the no-float pin.
//
// At N=100 the two forms happen to agree (ceil(67)=67 and (200)/3+1=67), so the
// argument for integer math is not a specific disagreement — it is that the
// float form's ANSWER DEPENDS ON A CONFIGURABLE FRACTION. Set quorumFraction to
// 0.5 and ceil(N*0.5) silently becomes a different rule than the protocol's,
// with nothing tying the two together. The integer form is invariant, because
// there is no fraction to configure.
func TestCalculateMinQuorumSize_IntegerMatchesEngine(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 4, 5, 6, 7, 10, 99, 100, 1000} {
		for _, frac := range []float64{0.5, 0.67, 2.0 / 3.0, 0.9} {
			qv := &QuorumVerifier{setSize: n, quorumFraction: frac}
			if got, want := qv.CalculateMinQuorumSize(), StrictTwoThirdsCount(n); got != want {
				t.Errorf("CalculateMinQuorumSize(%d) with fraction %v = %d, want %d "+
					"(the answer must not depend on a configurable fraction)", n, frac, got, want)
			}
		}
	}
	// The concrete way the float form could have gone wrong: at fraction 0.5
	// and N=4 the float form answers 2, where the protocol's rule is 3.
	loose := &QuorumVerifier{setSize: 4, quorumFraction: 0.5}
	if got := loose.CalculateMinQuorumSize(); got != StrictTwoThirdsCount(4) {
		t.Errorf("CalculateMinQuorumSize(4) at fraction 0.5 = %d, want %d",
			got, StrictTwoThirdsCount(4))
	}
}
