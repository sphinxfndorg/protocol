package consensus

import (
	"math/big"
	"testing"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
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

// TestCommitCertCache_RejectsUnderQuorumBeforeCaching pins the invariant the
// block-hash-keyed cache relies on: the ONLY path that populates it verifies
// strict 2/3 against the height's snapshot first.
//
// The adopt path in attachAttestationsBeforeCommit does a bare lookup and
// re-attaches without re-checking quorum, so an under-quorum certificate
// reaching the cache would be adopted as a sub-quorum attestation set.
func TestCommitCertCache_RejectsUnderQuorumBeforeCaching(t *testing.T) {
	ResetSnapshots()
	t.Cleanup(ResetSnapshots)

	ids := []string{"Node-a", "Node-b", "Node-c", "Node-d"}
	unit := big.NewInt(3200000000000000000)
	snapshot := &ValidatorSnapshot{Epoch: 0, TotalStake: new(big.Int).Mul(unit, big.NewInt(4)),
		Validators: make(map[string]*StakedValidator, len(ids))}
	for _, id := range ids {
		snapshot.Validators[id] = &StakedValidator{ID: id, StakeAmount: new(big.Int).Set(unit)}
	}
	StoreSnapshotForTest(*snapshot)

	// signingService nil: HandleCommitCertificate then accepts on the
	// stake-quorum check alone, which is exactly the gate under test.
	c := &Consensus{chainID: 7331, currentHeight: 0}

	atts := func(n int, hash string) []*types.Attestation {
		out := make([]*types.Attestation, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, &types.Attestation{
				ValidatorID: ids[i],
				BlockHash:   hash,
				ChainID:     7331,
				Height:      1,
				Phase:       VotePhaseCommit,
				View:        1,
			})
		}
		return out
	}

	// 2 of 4 is exactly 2/3, which is NOT enough: the rule is strict.
	const hash = "under-quorum-block"
	if err := c.HandleCommitCertificate(&CommitCertificate{
		BlockHash:    hash,
		View:         1,
		Attestations: atts(2, hash),
	}); err == nil {
		t.Fatal("a 2-of-4 certificate was accepted; strict 2/3 must reject it")
	}
	if _, cached := lookupCommitCertificate(hash); cached {
		t.Fatal("an under-quorum certificate reached the cache; the adopt path " +
			"would then re-attach a sub-quorum attestation set")
	}

	const okHash = "quorum-block"
	if err := c.HandleCommitCertificate(&CommitCertificate{
		BlockHash:    okHash,
		View:         1,
		Attestations: atts(3, okHash),
	}); err != nil {
		t.Fatalf("a 3-of-4 certificate was rejected: %v", err)
	}
	cached, ok := lookupCommitCertificate(okHash)
	if !ok || len(cached) != 3 {
		t.Fatalf("verified certificate not cached: ok=%v len=%d", ok, len(cached))
	}
	evictCommitCertificate(okHash)
}

// TestCommitCertCache_IsKeyedByBlockNotView pins the scoping the cache relies
// on: a certificate is reachable ONLY under its own block hash. That is what
// stops a view-N certificate being adopted for a DIFFERENT block proposed at the
// same height after a view change, which would be the route to two blocks
// committing at one height.
func TestCommitCertCache_IsKeyedByBlockNotView(t *testing.T) {
	ResetSnapshots()
	t.Cleanup(ResetSnapshots)

	ids := []string{"Node-a", "Node-b", "Node-c", "Node-d"}
	unit := big.NewInt(3200000000000000000)
	snapshot := &ValidatorSnapshot{Epoch: 0, TotalStake: new(big.Int).Mul(unit, big.NewInt(4)),
		Validators: make(map[string]*StakedValidator, len(ids))}
	for _, id := range ids {
		snapshot.Validators[id] = &StakedValidator{ID: id, StakeAmount: new(big.Int).Set(unit)}
	}
	StoreSnapshotForTest(*snapshot)

	c := &Consensus{chainID: 7331, currentHeight: 0}

	const blockX = "block-X-at-height-1"
	atts := make([]*types.Attestation, 0, 3)
	for i := 0; i < 3; i++ {
		atts = append(atts, &types.Attestation{
			ValidatorID: ids[i],
			BlockHash:   blockX,
			ChainID:     7331,
			Height:      1,
			Phase:       VotePhaseCommit,
			View:        4, // produced in view 4
		})
	}
	if err := c.HandleCommitCertificate(&CommitCertificate{
		BlockHash: blockX, View: 4, Attestations: atts,
	}); err != nil {
		t.Fatalf("cache setup: %v", err)
	}

	// A competing block Y at the SAME height, proposed by the view-5 leader,
	// must not see X's certificate.
	const blockY = "block-Y-at-height-1"
	if _, ok := lookupCommitCertificate(blockY); ok {
		t.Fatal("block Y's lookup returned block X's certificate; the cache is " +
			"not scoped to the block hash, so a view change could adopt the old " +
			"block's attestations for a competing block at the same height")
	}

	got, ok := lookupCommitCertificate(blockX)
	if !ok || len(got) != 3 {
		t.Fatalf("block X certificate lost: ok=%v len=%d", ok, len(got))
	}
	for _, a := range got {
		if a.BlockHash != blockX {
			t.Fatalf("cached attestation claims block %q, want %q", a.BlockHash, blockX)
		}
	}
	evictCommitCertificate(blockX)
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
