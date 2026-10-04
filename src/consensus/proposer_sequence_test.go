package consensus

import (
	"math/big"
	"sync"
	"testing"
	"time"

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

// TestLeaderDeath_ViewChangeNotBlockedBySelfVoteRefresh is the regression test
// for the measured 204s stall.
//
// After the leader dies the survivors keep sending their OWN prepare and commit
// votes in a dead round. That is not progress. When it refreshed
// lastRoundActivity, the 45s stalledRoundThreshold and the 90s
// roundActivityWindow never expired, so shouldPreventViewChange stayed true and
// no further view change could ever start.
func TestLeaderDeath_ViewChangeNotBlockedBySelfVoteRefresh(t *testing.T) {
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

	clock := newTestClock()
	survivor := newGateNode(t, "Node-b", ids, clock)

	// Post-leader-death state: committed long ago, nothing advancing since.
	survivor.currentHeight = 1
	survivor.lastBlockTime = clock.now().Add(-10 * time.Minute)
	survivor.lastViewChange = clock.now().Add(-10 * time.Minute)
	survivor.lastRoundActivity = clock.now().Add(-10 * time.Minute)

	if survivor.shouldPreventViewChange() {
		t.Fatal("with a 10-minute-old stall the gate is shut; no view change could start")
	}

	// Advance past the 90s window. Each step models one more view: resetConsensusState
	// clears the per-block sent-vote maps, so the survivor legitimately re-sends its
	// own prepare and commit votes for the same dead round. That is not progress.
	// If it refreshed the round clock the gate would shut again and never reopen.
	for elapsed := time.Duration(0); elapsed < 4*time.Minute; elapsed += 5 * time.Second {
		survivor.sentPrepareVotes = map[string]bool{}
		survivor.sentVotes = map[string]bool{}
		survivor.sendPrepareVote("dead-round-block", 1, 2)
		survivor.voteForBlock("dead-round-block", 1, 2)
		clock.advance(5 * time.Second)

		if survivor.shouldPreventViewChange() {
			t.Fatalf("view change was suppressed %v into a dead round that made "+
				"no progress; re-sending its own votes must not refresh the "+
				"round-activity clock", elapsed+5*time.Second)
		}
	}

	if got := clock.now().Sub(survivor.lastBlockTime); got <= roundActivityWindow {
		t.Fatalf("test did not advance past the window (lastBlockTime age %v)", got)
	}
}

// TestLeaderDeath_LegitimateSlowRoundStillSuppressesViewChange is the regression
// guard: real progress MUST keep refreshing the clock, so a slow but healthy
// round is never abandoned early.
func TestLeaderDeath_LegitimateSlowRoundStillSuppressesViewChange(t *testing.T) {
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

	clock := newTestClock()
	c := newGateNode(t, "Node-b", ids, clock)
	c.currentHeight = 1
	c.lastBlockTime = clock.now().Add(-10 * time.Minute)
	c.lastViewChange = clock.now().Add(-10 * time.Minute)
	c.lastRoundActivity = clock.now().Add(-10 * time.Minute)

	// A real proposal is accepted, then the round makes progress every 30s for
	// five minutes of injected time. Each progress event refreshes the clock,
	// so the gate must stay shut throughout.
	for elapsed := time.Duration(0); elapsed < 5*time.Minute; elapsed += 30 * time.Second {
		clock.advance(30 * time.Second)
		c.markRoundProgress()

		if !c.shouldPreventViewChange() {
			t.Fatalf("a round making real progress was abandoned %v in; the gate "+
				"must stay shut while progress continues", elapsed+30*time.Second)
		}
	}
}

// testClock is a manually advanced clock for the view-change timeout windows.
type testClock struct {
	mu sync.Mutex
	at time.Time
}

func newTestClock() *testClock {
	return &testClock{at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// newGateNode returns a Consensus wired only far enough to exercise the
// view-change gates: no goroutines, an injected clock, sync gate open.
// stubNodeManager swallows broadcasts: the gate tests need the vote-send paths
// to run for their side effects, not to reach a network.
type stubNodeManager struct{ sent int }

func (s *stubNodeManager) GetPeers() map[string]Peer { return nil }
func (s *stubNodeManager) GetNode(string) Node       { return nil }
func (s *stubNodeManager) BroadcastMessage(string, interface{}) error {
	s.sent++
	return nil
}
func (s *stubNodeManager) BroadcastRANDAOState([32]byte, map[uint64]map[string]*VDFSubmission) error {
	return nil
}

func newGateNode(t *testing.T, id string, allIDs []string, clock *testClock) *Consensus {
	t.Helper()
	unit := big.NewInt(3200000000000000000)
	vs := NewValidatorSet(unit)
	if err := vs.AddGenesisValidator(id, unit); err != nil {
		t.Fatalf("AddGenesisValidator: %v", err)
	}
	for _, other := range allIDs {
		if other == id {
			continue
		}
		if err := vs.AddGenesisValidator(other, unit); err != nil {
			t.Fatalf("AddGenesisValidator(%s): %v", other, err)
		}
	}
	vs.ProcessEpochTransition(0)
	vs.SealGenesis()

	c := &Consensus{
		nodeID:               id,
		chainID:              7331,
		nowFn:                clock.now,
		phase:                PhaseIdle,
		validatorSet:         vs,
		nodeManager:          &stubNodeManager{},
		receivedVotes:        map[string]map[string]*Vote{},
		prepareVotes:         map[string]map[string]*Vote{},
		sentVotes:            map[string]bool{},
		sentPrepareVotes:     map[string]bool{},
		timeoutVotes:         map[uint64]map[string]*TimeoutMsg{},
		weightedPrepareVotes: map[string]*big.Int{},
		weightedCommitVotes:  map[string]*big.Int{},
	}
	c.SetSyncReady(true)
	return c
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
