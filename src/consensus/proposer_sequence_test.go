package consensus

import (
	"math/big"
	"testing"
)

// installTestSnapshot registers a four-validator epoch-0 snapshot for tests.
func installTestSnapshot(t *testing.T, ids ...string) {
	t.Helper()
	total := big.NewInt(0)
	vals := make(map[string]*StakedValidator, len(ids))
	for i, id := range ids {
		stake := big.NewInt(3200000000000000000) // equal stake, as localnet seeds it
		vals[id] = &StakedValidator{
			ID:              id,
			StakeAmount:     stake,
			ActivationEpoch: 0,
			ExitEpoch:       0,
			IsSlashed:       false,
		}
		total.Add(total, stake)
		_ = i
	}
	snapshotMu.Lock()
	defer snapshotMu.Unlock()
	epoch := EpochForHeight(1)
	snapshotByEpoch[epoch] = &ValidatorSnapshot{
		Epoch:      epoch,
		Validators: vals,
		TotalStake: total,
	}
}

// TestSelectProposerSequenceOverViews prints and checks which validator
// SelectProposer elects for each view slot 1..20 at one fixed height.
//
// This is the diagnostic for "leader kill stalls the chain": if the elected
// proposer were a function of the view slot only, and some slots always elect
// the same (possibly dead) validator, the chain could never escape. The test
// asserts the two properties recovery depends on:
//
//  1. the elected proposer VARIES across views (so a dead leader is not sticky), and
//  2. every slot elects SOMEONE (no view index is permanently unreachable).
func TestSelectProposerSequenceOverViews(t *testing.T) {
	ids := []string{
		"Node-127.0.0.1:30303",
		"Node-127.0.0.1:30304",
		"Node-127.0.0.1:30305",
		"Node-127.0.0.1:30306",
	}
	installTestSnapshot(t, ids...)

	// GetSeed only reads r.mix and the slot, so any RANDAO with a fixed mix is
	// enough here; the production VDF constructor is irrelevant to selection.
	r := NewRANDAO([32]byte{}, VDFParams{}, "Node-127.0.0.1:30303")
	sel := &StakeWeightedSelector{}

	elected := make([]string, 0, 20)
	counts := map[string]int{}
	for view := uint64(1); view <= 20; view++ {
		seed := r.GetSeed(view)
		p := sel.SelectProposer(1, seed)
		if p == nil {
			t.Fatalf("view %d elected NO proposer; that view index is unreachable "+
				"and would stall the chain forever", view)
		}
		elected = append(elected, p.ID)
		counts[p.ID]++
	}

	t.Logf("elected proposer by view (height 1, equal stake):")
	for i, id := range elected {
		t.Logf("  view %2d -> %s", i+1, id)
	}
	t.Logf("distinct proposers across 20 views: %d %v", len(counts), counts)

	// (2) covered above: a nil proposer fails the loop.
	// (1) the sequence must vary, otherwise one validator is stuck as leader.
	if len(counts) < 2 {
		t.Fatalf("every view 1..20 elected the same validator %v; a dead leader "+
			"would then be re-elected forever", elected)
	}

	// Specifically: can a live validator ever displace a given dead one?
	// For each validator, count the slots where it was NOT elected; there must
	// be a slot that elects a different validator, or recovery is impossible.
	for _, dead := range ids {
		others := 0
		for _, id := range elected {
			if id != dead {
				others++
			}
		}
		if others == 0 {
			t.Errorf("%s was elected for all 20 views; killing it would stall "+
				"the chain permanently with no reachable view that elects a survivor", dead)
		}
	}
}
