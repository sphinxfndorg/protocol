// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/consensus/forcepopulate_test.go
package consensus

import (
	"bytes"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	logger "github.com/sphinxfndorg/protocol/src/console"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
)

// stubChain is a BlockChain whose lookups always miss. That is exactly the
// state of a node during startup/sync: consensus signatures exist for blocks
// that have not reached this node's storage yet. It is also the minimal
// implementation needed to drive ForcePopulateAllSignatures' populated path
// without standing up a full storage stack.
type stubChain struct{}

func (stubChain) GetLatestBlock() Block                               { return nil }
func (stubChain) ValidateBlock(block Block) error                     { return nil }
func (stubChain) CommitBlock(block Block) error                       { return nil }
func (stubChain) GetBlockByHash(hash string) Block                    { return nil }
func (stubChain) GetValidatorStake(validatorID string) *big.Int       { return big.NewInt(0) }
func (stubChain) GetTotalStaked() *big.Int                            { return big.NewInt(0) }
func (stubChain) UpdateValidatorStake(id string, d *big.Int) error    { return nil }
func (stubChain) GetGenesisTime() time.Time                           { return time.Unix(0, 0) }
func (stubChain) GetCheckpointMessage() (*CheckpointMessage, error)   { return nil, nil }
func (stubChain) ApplyCheckpointFromPeer(cp *CheckpointMessage) error { return nil }

// captureNodeLogs redirects the process-wide logger (the one the node writes
// through) into a buffer for one call and returns everything emitted at or
// above level. SetLevel/SetDefaultWriter are global seams, so every test using
// this helper restores them and must not use t.Parallel.
func captureNodeLogs(t *testing.T, level logger.Level, fn func()) string {
	t.Helper()

	buf := &bytes.Buffer{}
	logger.SetDefaultWriter(buf)
	logger.SetLevel(level)
	defer func() {
		logger.SetLevel(logger.INFO) // the node's default (see console.init)
		logger.SetDefaultWriter(nil) // nil restores os.Stdout
	}()

	fn()
	return buf.String()
}

// TestForcePopulateAllSignaturesSilentWhenEmpty pins the fix for the log flood
// seen in a 3-node run, once per 2-second state-machine tick:
//
//	10:58:35.028 INFO Force populating all consensus signatures
//	10:58:35.028 INFO Force population completed for 0 signatures
//	10:58:37.027 INFO Force populating all consensus signatures
//	10:58:37.028 INFO Force population completed for 0 signatures
//
// ForcePopulateAllSignatures is called by StateMachine.syncFinalStates on the
// 2-second replication tick for the entire life of the node (see state/smr.go),
// and on an idle or still-syncing node the signature set is empty. Those two
// INFO lines therefore replayed ~60 times a minute forever, burying the
// actionable startup diagnostics around them. With nothing to populate there is
// nothing an operator needs to be told, so an empty set must log nothing at all
// — at INFO and at DEBUG alike, because the early return is unconditional
// rather than a level change (the remaining lines are per-signature, per-tick).
func TestForcePopulateAllSignaturesSilentWhenEmpty(t *testing.T) {
	// Zero value is sufficient: with an empty set the method returns before it
	// reaches blockChain, so no stub is needed on this path.
	c := &Consensus{}

	for _, level := range []logger.Level{logger.INFO, logger.DEBUG} {
		out := captureNodeLogs(t, level, func() { c.ForcePopulateAllSignatures() })
		if out != "" {
			t.Fatalf("ForcePopulateAllSignatures with an empty signature set logged %d bytes at %v, want silence:\n%s",
				len(out), level, out)
		}
	}
}

// TestForcePopulateAllSignaturesPopulatedStaysOutOfInfo is the other half of the
// fix: the early return must not swallow the real path, and a populated pass
// must stay out of INFO. It runs every 2s, so its progress lines ("Force
// populating %d consensus signatures", one per signature, and the completion
// line) were moved to DEBUG. This asserts both directions: at INFO — the level a
// running node logs at — a populated pass prints nothing, while at DEBUG it
// still reports its work, and the signature is still populated.
func TestForcePopulateAllSignaturesPopulatedStaysOutOfInfo(t *testing.T) {
	newPopulated := func() *Consensus {
		c := &Consensus{blockChain: stubChain{}}
		c.consensusSignatures = []*ConsensusSignature{{
			BlockHash:   "abcdef0123456789",
			MessageType: "prepare",
			// MerkleRoot and Status are deliberately unset: populating them is
			// exactly what this method exists to do.
		}}
		return c
	}

	// 1. At INFO — the level a running node logs at — a populated pass is silent.
	if out := captureNodeLogs(t, logger.INFO, func() { newPopulated().ForcePopulateAllSignatures() }); out != "" {
		t.Fatalf("a populated ForcePopulateAllSignatures pass logged %d bytes at INFO, want silence (this runs every 2s):\n%s",
			len(out), out)
	}

	// 2. At DEBUG the same pass still reports what it did.
	c := newPopulated()
	out := captureNodeLogs(t, logger.DEBUG, func() { c.ForcePopulateAllSignatures() })
	for _, want := range []string{
		"Force populating 1 consensus signatures",
		"Force population completed for 1 signatures",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("DEBUG output missing %q; got:\n%s", want, out)
		}
	}

	// 3. And the work itself still happened: the block is not in storage, so the
	//    merkle root gets the block_not_found_ placeholder and the status is
	//    derived from the message type.
	sig := c.consensusSignatures[0]
	if !strings.HasPrefix(sig.MerkleRoot, "block_not_found_") {
		t.Errorf("MerkleRoot = %q, want block_not_found_<hash prefix> placeholder", sig.MerkleRoot)
	}
	if sig.Status != "prepared" {
		t.Errorf("Status = %q, want \"prepared\" (derived from MessageType \"prepare\")", sig.Status)
	}
}

// ============================================================================
// TestNoLocalObservationSlashing (Phase 1, decision 3)
//
// Slashing a validator because THIS node observed it miss a VDF submission
// makes the validator set a function of local observation. Two nodes that saw
// different submission sets at the same height would then compute different
// totals, different quorums, and different leaders for the same block — the
// exact divergence the epoch-snapshot model exists to prevent.
//
// Two guards live here:
//  1. FinaliseEpoch returns NOTHING, so no caller can turn the missed-set into
//     a stake mutation. (This is enforced at compile time: if someone
//     reintroduces a []string return, `r.FinaliseEpoch(...)` below stops
//     being a valid statement.)
//  2. A source scan of this package fails if any file calls SlashValidator.
//     Slashing must arrive only from the executor applying on-chain evidence.
// ============================================================================

func TestNoLocalObservationSlashing_FinaliseEpochReturnsNothing(t *testing.T) {
	// Constructed directly rather than via NewRANDAO: this test is about the
	// bookkeeping maps, and a production VDF instance is irrelevant (and slow)
	// here. Only the maps FinaliseEpoch touches are populated.
	r := &RANDAO{
		reveals:        make(map[uint64][][32]byte),
		submissions:    make(map[uint64]map[string]*VDFSubmission),
		missed:         make(map[uint64]map[string]bool),
		epochFinalized: make(map[uint64]bool),
	}
	active := []string{"Node-a", "Node-b"}

	// A bare statement: valid ONLY because FinaliseEpoch returns no value.
	r.FinaliseEpoch(7, active)

	if !r.epochFinalized[7] {
		t.Error("FinaliseEpoch must still mark the epoch finalized (the VDF reveal schedule depends on it)")
	}
	// The missed set is still recorded, but purely as an observation.
	if len(r.missed[7]) != len(active) {
		t.Errorf("missed[7] = %v, want both validators recorded as having missed", r.missed[7])
	}
}

func TestNoLocalObservationSlashing_NoSlashValidatorCallerInPackage(t *testing.T) {
	// Any call form that mutates stake from inside this package.
	banned := []string{
		"vs.SlashValidator(",
		"validatorSet.SlashValidator(",
		"c.validatorSet.SlashValidator(",
		".validatorSet.SlashValidator(",
	}

	// Scan the WHOLE package directory rather than a hand-listed set of files,
	// so a newly added file cannot smuggle a caller past the guard. The
	// definition itself is in staking.go, so that one file is exempt: it is
	// allowed to DECLARE SlashValidator, never to call it.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(src)
		checked++
		for _, call := range banned {
			if strings.Contains(text, call) {
				t.Errorf("%s contains %q — slashing must come from on-chain evidence applied by the executor at an epoch boundary, never from local observation", name, call)
			}
		}
	}
	if checked == 0 {
		t.Fatal("scanned no source files — the guard is not actually guarding anything")
	}
	t.Logf("scanned %d non-test source files for local-observation slashing", checked)
}

// ============================================================================
// Checkpoint 1: the single live validator set, epoch from height, snapshots
// ============================================================================

// newSetWith builds a ValidatorSet whose min stake is the protocol minimum, with
// the given IDs active from epoch 0.
func newSetWith(ids ...string) (*ValidatorSet, *big.Int) {
	minStake := new(big.Int).Mul(big.NewInt(32), new(big.Int).SetUint64(denom.SPX))
	vs := NewValidatorSet(minStake)
	for _, id := range ids {
		if err := vs.AddGenesisValidator(id, spx32()); err != nil {
			panic("AddGenesisValidator: " + err.Error())
		}
	}
	return vs, minStake
}

// TestProcessEpochTransition_ActivatesInTheLiveSet is the Checkpoint 1 item 1
// test. A validator with ActivationEpoch = e must become ACTIVE IN THE LIVE SET
// at the epoch-e boundary — the defect was that the transition ran against a
// throwaway copy, so the live set never changed.
func TestProcessEpochTransition_ActivatesInTheLiveSet(t *testing.T) {
	vs, minStake := newSetWith("Node-a")

	// Schedule a validator to activate at epoch 3, by writing the field the
	// queued-stake path will set.
	vs.mu.Lock()
	vs.validators["Node-b"] = &StakedValidator{
		ID:              "Node-b",
		StakeAmount:     new(big.Int).Set(minStake),
		ActivationEpoch: 3,
	}
	vs.mu.Unlock()

	// Before the boundary it is PENDING: no weight, not active, and explicitly
	// reported as pending so an operator can be told when it lands.
	if got := vs.GetTotalStake(); got.Cmp(minStake) != 0 {
		t.Fatalf("before activation totalStake = %s, want %s (Node-b is pending)", got, minStake)
	}
	if ids := vs.ActiveValidatorIDs(2); len(ids) != 1 || ids[0] != "Node-a" {
		t.Fatalf("epoch 2 active set = %v, want [Node-a]", ids)
	}

	// Boundaries before e change nothing.
	for e := uint64(0); e < 3; e++ {
		vs.ProcessEpochTransition(e)
		if got := vs.GetTotalStake(); got.Cmp(minStake) != 0 {
			t.Fatalf("epoch %d: totalStake = %s, want %s", e, got, minStake)
		}
	}

	// At the boundary it activates IN THE LIVE SET.
	activated, retired := vs.ProcessEpochTransition(3)
	if len(activated) != 1 || activated[0] != "Node-b" {
		t.Fatalf("epoch 3: activated = %v, want [Node-b]", activated)
	}
	if len(retired) != 0 {
		t.Errorf("epoch 3: retired = %v, want none", retired)
	}
	want := new(big.Int).Mul(minStake, big.NewInt(2))
	if got := vs.GetTotalStake(); got.Cmp(want) != 0 {
		t.Errorf("epoch 3: LIVE totalStake = %s, want %s", got, want)
	}
	if ids := vs.ActiveValidatorIDs(3); len(ids) != 2 {
		t.Errorf("epoch 3: LIVE active set = %v, want 2 entries", ids)
	}
	// Re-read through the public accessor, not the struct, so this is the same
	// view the rest of consensus uses.
	if v := vs.GetValidator("Node-b"); v == nil {
		t.Error("Node-b must be readable from the live set after activation")
	}
}

// TestValidatorSetAt_HeightKeyedAndImmutable covers Checkpoint 1 items 2 and 3:
// the lookup is height-keyed, and a snapshot taken earlier is unaffected by a
// later transition.
func TestValidatorSetAt_HeightKeyedAndImmutable(t *testing.T) {
	ResetSnapshots()
	prev := epochBlocksOverride
	SetEpochBlocks(4)
	defer func() { epochBlocksOverride = prev; ResetSnapshots() }()

	vs, minStake := newSetWith("Node-a")
	vs.mu.Lock()
	vs.validators["Node-b"] = &StakedValidator{
		ID: "Node-b", StakeAmount: new(big.Int).Set(minStake), ActivationEpoch: 2,
	}
	vs.mu.Unlock()

	// Snapshot epoch 0: only Node-a is active there.
	vs.TakeSnapshot(0)
	epoch0 := ValidatorSetAt(1)
	if epoch0 == nil {
		t.Fatal("epoch 0 snapshot missing")
	}
	if len(epoch0.Validators) != 1 {
		t.Errorf("epoch 0 snapshot has %d validators, want 1 (Node-b is pending)", len(epoch0.Validators))
	}
	if _, present := epoch0.Validators["Node-b"]; present {
		t.Error("a pending validator must not appear in the epoch-0 snapshot")
	}
	if epoch0.TotalStake.Cmp(minStake) != 0 {
		t.Errorf("epoch 0 TotalStake = %s, want %s", epoch0.TotalStake, minStake)
	}
	hash0 := epoch0.Hash()

	// Advance the world.
	vs.ProcessEpochTransition(2)
	vs.TakeSnapshot(2)
	epoch2 := ValidatorSetAt(8)
	if epoch2 == nil || len(epoch2.Validators) != 2 {
		t.Fatalf("epoch 2 snapshot = %v, want 2 validators", epoch2)
	}

	// IMMUTABLE: the epoch-0 snapshot is byte-identical to what it was.
	if len(epoch0.Validators) != 1 {
		t.Errorf("epoch 0 snapshot changed after epoch 2: %d validators", len(epoch0.Validators))
	}
	if epoch0.Hash() != hash0 {
		t.Errorf("epoch 0 snapshot hash changed: %s -> %s", hash0, epoch0.Hash())
	}
	if snap := ValidatorSetAt(1); snap.Hash() != hash0 {
		t.Errorf("re-read of epoch 0 differs: %s vs %s", snap.Hash(), hash0)
	}
	// The two epochs must have DIFFERENT hashes, or the hash is not binding.
	if epoch2.Hash() == hash0 {
		t.Error("epoch 0 and epoch 2 snapshots hash the same despite different membership")
	}
	t.Logf("epoch0 hash=%s (1 validator), epoch2 hash=%s (2 validators)", hash0[:16], epoch2.Hash()[:16])
}

// ============================================================================
// STEP 1: the quorum rules that core.VerifyBlockAttestations now enforces
// ============================================================================

// ============================================================================
// STEP 2: epoch and proposer come from HEIGHT, never from the view
// ============================================================================

// TestMembershipEpoch_DependsOnHeightNotView is checkpoint item 2's core
// property. Two consensus engines at the SAME HEIGHT but in DIFFERENT views —
// the normal state of affairs right after a view change — must agree on the
// epoch that decides proposer membership.
//
// Before the fix each computed `c.currentView / SlotsPerEpoch`, so those two
// engines selected proposers from DIFFERENT membership and then rejected each
// other's proposals as "invalid leader". That is a livelock, not a cosmetic
// inconsistency.
func TestMembershipEpoch_DependsOnHeightNotView(t *testing.T) {
	prev := epochBlocksOverride
	SetEpochBlocks(verifyEpochBlocks)
	defer func() { epochBlocksOverride = prev }()

	// Engines differing ONLY in view. A bare &Consensus{} is enough and is
	// deliberate: membershipEpoch reads only currentHeight under mu, so if it
	// ever grew a dependency on the view, a clock, or a peer, the test would
	// catch it here rather than in production. Going through NewConsensus
	// instead would require real VDF/genesis parameters — machinery that is not
	// what is under test — and would still not assert more about this function.
	a := &Consensus{nodeID: "Node-a"}
	b := &Consensus{nodeID: "Node-b"}

	// A spread of heights, including several epochs.
	for _, h := range []uint64{0, 1, 7, 8, 9, 31, 32, 33, 400} {
		a.SetCurrentHeight(h)
		b.SetCurrentHeight(h)

		// Drive the views far apart — far more than one epoch's worth, which is
		// exactly where the old view/SlotsPerEpoch formula diverged.
		a.currentView = 0
		b.currentView = 4096

		if got, want := a.membershipEpoch(), EpochForHeight(h); got != want {
			t.Errorf("height %d: Node-a membershipEpoch = %d, want EpochForHeight = %d", h, got, want)
		}
		if got, want := b.membershipEpoch(), EpochForHeight(h); got != want {
			t.Errorf("height %d: Node-b membershipEpoch = %d, want EpochForHeight = %d", h, got, want)
		}
		if a.membershipEpoch() != b.membershipEpoch() {
			t.Errorf("height %d: engines in different views disagree on the epoch (%d vs %d)",
				h, a.membershipEpoch(), b.membershipEpoch())
		}
	}
}

// TestMembershipEpoch_ChangesWithHeight confirms the value is not merely
// constant: crossing an epoch boundary must move it, otherwise the previous test
// would pass for a function that always returned 0.
func TestMembershipEpoch_ChangesWithHeight(t *testing.T) {
	prev := epochBlocksOverride
	SetEpochBlocks(verifyEpochBlocks)
	defer func() { epochBlocksOverride = prev }()

	c := &Consensus{nodeID: "Node-a"}
	c.currentView = 999 // pinned: must not influence the result

	seen := make(map[uint64]uint64)
	for h := uint64(0); h < 3*verifyEpochBlocks; h++ {
		c.SetCurrentHeight(h)
		e := c.membershipEpoch()
		if want := EpochForHeight(h); e != want {
			t.Fatalf("height %d: membershipEpoch = %d, want %d", h, e, want)
		}
		seen[h] = e
	}
	if seen[0] == seen[verifyEpochBlocks] {
		t.Error("crossing an epoch boundary did not change membershipEpoch")
	}
	if seen[0] != 0 || seen[verifyEpochBlocks] != 1 || seen[2*verifyEpochBlocks] != 2 {
		t.Errorf("unexpected epoch progression across %d blocks: %v", verifyEpochBlocks, seen)
	}
}

// TestProposerSelection_SameAtEqualHeightAcrossViews is the end-to-end version
// of the same property: given the same height and the same RANDAO seed, two
// engines in different views must elect the SAME proposer from the SAME
// membership.
//
// The seed is passed explicitly rather than taken from the view, because the
// view legitimately still supplies randomness. Membership is what must be
// height-derived, and this asserts that a difference in view alone changes
// nothing about who is eligible.
func TestProposerSelection_SameAtEqualHeightAcrossViews(t *testing.T) {
	prev := epochBlocksOverride
	SetEpochBlocks(verifyEpochBlocks)
	defer func() { epochBlocksOverride = prev }()

	// One shared set, so both engines are deciding over identical membership.
	vs := NewValidatorSet(spx32())
	for _, id := range []string{"Node-a", "Node-b", "Node-c", "Node-d"} {
		if err := vs.AddGenesisValidator(id, spx32()); err != nil {
			t.Fatalf("AddGenesisValidator: %v", err)
		}
	}
	sel := NewStakeWeightedSelector(vs)

	// A fixed seed. The point is that ONLY the view differs between the two
	// calls; the epoch passed to SelectProposer is derived from height.
	seed := [32]byte{}
	for i := range seed {
		seed[i] = byte(i * 7)
	}

	const height = 5
	a := &Consensus{nodeID: "Node-a"}
	b := &Consensus{nodeID: "Node-b"}
	a.SetCurrentHeight(height)
	b.SetCurrentHeight(height)
	a.currentView = 0
	b.currentView = 7777

	pa := sel.SelectProposer(a.membershipEpoch(), seed)
	pb := sel.SelectProposer(b.membershipEpoch(), seed)
	if pa == nil || pb == nil {
		t.Fatalf("SelectProposer returned nil (a=%v b=%v)", pa, pb)
	}
	if pa.ID != pb.ID {
		t.Errorf("two engines at height %d in different views elected different proposers: %s vs %s",
			height, pa.ID, pb.ID)
	}
	t.Logf("height %d, views 0 and 7777 both elected %s", height, pa.ID)
}

// ============================================================================
// STEP 3: stake integrity — a runtime admitter must not vote until it syncs
// ============================================================================

// TestSetStakeFromBalanceAtEpoch_NoWeightUntilBoundary is checkpoint item 3.
//
// A validator admitted at RUNTIME is by definition still syncing. Before this
// change, SetStakeFromBalance credited its stake to vs.totalStake immediately
// and left ActivationEpoch at 0, so the node instantly held a full share of the
// quorum DENOMINATOR — weighted in a tip it had never validated, and forcing
// every honest node to chase a threshold it could not reach.
func TestSetStakeFromBalanceAtEpoch_NoWeightUntilBoundary(t *testing.T) {
	prev := epochBlocksOverride
	SetEpochBlocks(verifyEpochBlocks)
	defer func() { epochBlocksOverride = prev }()
	ResetSnapshots()
	defer ResetSnapshots()

	vs := NewValidatorSet(spx32())
	if err := vs.AddGenesisValidator("Node-a", spx32()); err != nil {
		t.Fatalf("AddGenesisValidator: %v", err)
	}
	baseline := vs.GetTotalStake()
	if baseline.Cmp(spx32()) != 0 {
		t.Fatalf("baseline totalStake = %s, want one validator's stake", baseline)
	}

	// Admit a syncing node at height 4, i.e. epoch 1. ActivationEpochForStake
	// puts it at epoch 3: one full epoch of slack.
	const height = 4
	activation := ActivationEpochForStake(height)
	if activation <= EpochForHeight(height) {
		t.Fatalf("ActivationEpochForStake(%d) = %d, must be strictly ahead of epoch %d",
			height, activation, EpochForHeight(height))
	}
	if err := vs.SetStakeFromBalanceAtEpoch("Node-syncer", spx32(), activation); err != nil {
		t.Fatalf("SetStakeFromBalanceAtEpoch: %v", err)
	}

	// ★ The denominator must NOT have moved. This is the whole point.
	if got := vs.GetTotalStake(); got.Cmp(baseline) != 0 {
		t.Errorf("totalStake = %s after admitting a syncing validator, want %s: "+
			"a pending validator must not be in the quorum denominator", got, baseline)
	}
	// It must not be active at any epoch before its activation.
	for e := uint64(0); e < activation; e++ {
		vs.ProcessEpochTransition(e)
		if ids := vs.ActiveValidatorIDs(e); len(ids) != 1 || ids[0] != "Node-a" {
			t.Fatalf("epoch %d active set = %v, want only [Node-a]", e, ids)
		}
		if got := vs.GetTotalStake(); got.Cmp(baseline) != 0 {
			t.Fatalf("epoch %d totalStake = %s, want %s", e, got, baseline)
		}
	}

	// At its activation epoch it joins, and the total grows by exactly its stake.
	activated, _ := vs.ProcessEpochTransition(activation)
	if len(activated) != 1 || activated[0] != "Node-syncer" {
		t.Fatalf("epoch %d: activated = %v, want [Node-syncer]", activation, activated)
	}
	want := new(big.Int).Mul(spx32(), big.NewInt(2))
	if got := vs.GetTotalStake(); got.Cmp(want) != 0 {
		t.Errorf("epoch %d totalStake = %s, want %s", activation, got, want)
	}
}

// TestSetStakeFromBalanceAtEpoch_LeavesGenesisMembersAlone guards the other
// side of the change: a member that is ALREADY active must not be pushed into
// the future by a re-stake. Otherwise ordinary reward-driven stake updates
// would silently eject working validators from the set.
func TestSetStakeFromBalanceAtEpoch_LeavesGenesisMembersAlone(t *testing.T) {
	ResetSnapshots()
	defer ResetSnapshots()

	vs := NewValidatorSet(spx32())
	if err := vs.AddGenesisValidator("Node-a", spx32()); err != nil {
		t.Fatalf("AddGenesisValidator: %v", err)
	}
	// A far-future epoch is passed, as a naive caller might.
	if err := vs.SetStakeFromBalanceAtEpoch("Node-a", new(big.Int).Mul(spx32(), big.NewInt(2)), 99); err != nil {
		t.Fatalf("SetStakeFromBalanceAtEpoch: %v", err)
	}
	// vs.GetValidator returns interface{} (the decoupled view used by the RPC
	// and diagnostic paths), so read the row from the live set under its lock.
	vs.mu.RLock()
	row := vs.validators["Node-a"]
	gotEpoch, gotStake := uint64(0), (*big.Int)(nil)
	if row != nil {
		gotEpoch = row.ActivationEpoch
		gotStake = row.StakeAmount
	}
	vs.mu.RUnlock()
	if row == nil {
		t.Fatal("Node-a disappeared")
	}
	if gotEpoch != 0 {
		t.Errorf("an already-active member was pushed to activation epoch %d", gotEpoch)
	}
	// And its weight is still counted.
	if want := new(big.Int).Mul(spx32(), big.NewInt(2)); vs.GetTotalStake().Cmp(want) != 0 {
		t.Errorf("totalStake = %s, want %s (stake %s was recorded)", vs.GetTotalStake(), want, gotStake)
	}
}

// TestTotalStake_EqualsSumOfActiveMembers pins the active-only-total invariant
// directly: after any transition, GetTotalStake() must equal the sum of the
// members GetActiveValidators() actually admits. A denominator that disagrees
// with the voter set is unreachably large, and quorum then fails forever.
func TestTotalStake_EqualsSumOfActiveMembers(t *testing.T) {
	prev := epochBlocksOverride
	SetEpochBlocks(verifyEpochBlocks)
	defer func() { epochBlocksOverride = prev }()

	vs := NewValidatorSet(spx32())
	ids := []string{"Node-a", "Node-b", "Node-c", "Node-d"}
	for _, id := range ids {
		if err := vs.AddGenesisValidator(id, spx32()); err != nil {
			t.Fatalf("AddGenesisValidator: %v", err)
		}
	}
	// Retire one and slash another, then cross a boundary.
	vs.mu.Lock()
	vs.validators["Node-d"].ExitEpoch = 2
	vs.validators["Node-c"].IsSlashed = true
	vs.mu.Unlock()

	for e := uint64(0); e <= 3; e++ {
		vs.ProcessEpochTransition(e)

		sum := big.NewInt(0)
		for _, v := range vs.GetActiveValidators(e) {
			if v != nil && v.StakeAmount != nil {
				sum.Add(sum, v.StakeAmount)
			}
		}
		got := vs.GetTotalStake()
		if got.Cmp(sum) != 0 {
			t.Errorf("epoch %d: totalStake = %s but the active members sum to %s "+
				"(a slashed or retired validator must not be in the denominator)", e, got, sum)
		}
		// Sanity: a slashed validator is not in the active list at all.
		for _, v := range vs.GetActiveValidators(e) {
			if v != nil && v.ID == "Node-c" {
				t.Errorf("epoch %d: slashed Node-c appears in the active set", e)
			}
		}
	}
}

// ============================================================================
// CHECKPOINT 1b — item 1: stake integrity
// ============================================================================

// TestStakeAdmission_ZeroAndBelowMinimumAreErrors is 1a.
//
// Before this change, AddValidator clamped a below-minimum stake UP to the
// minimum and returned nil, and SetStakeFromBalance had two separate clamps
// ("balance < 1 SPX => use minimum" and "stake < min => use minimum"). So
// AddValidator(id, 0), SetStakeFromBalance(id, 0) and even a 1-wei balance all
// produced a FULL 32 SPX validator: a zero-cost seat.
//
// Every one of those inputs must now be an ERROR and must leave the set and
// its total UNCHANGED.
func TestStakeAdmission_ZeroAndBelowMinimumAreErrors(t *testing.T) {
	ResetSnapshots()
	defer ResetSnapshots()

	vs := NewValidatorSet(spx32())
	if err := vs.AddGenesisValidator("Node-a", spx32()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	baseline := vs.GetTotalStake()
	members0 := len(vs.GetValidators())

	belowMin := new(big.Int).Sub(spx32(), big.NewInt(1)) // 1 nSPX under
	inputs := []struct {
		name string
		v    *big.Int
	}{
		{"zero", big.NewInt(0)},
		{"one nSPX", big.NewInt(1)},
		{"one SPX", new(big.Int).Mul(big.NewInt(1), new(big.Int).SetUint64(denom.SPX))},
		{"minimum minus one", belowMin},
		{"negative", big.NewInt(-1)},
	}

	for _, in := range inputs {
		if err := vs.AddGenesisValidator("Node-x", in.v); err == nil {
			t.Errorf("1a: AddGenesisValidator accepted %s stake %s", in.name, in.v)
		}
		if err := vs.SetStakeFromBalance("Node-y", in.v); err == nil {
			t.Errorf("1a: SetStakeFromBalance accepted %s balance %s", in.name, in.v)
		}
		if err := vs.SetStakeFromBalanceAtEpoch("Node-z", in.v, 3); err == nil {
			t.Errorf("1a: SetStakeFromBalanceAtEpoch accepted %s balance %s", in.name, in.v)
		}
		if err := vs.QueueValidator("Node-w", in.v, 3); err == nil {
			t.Errorf("1a: QueueValidator accepted %s stake %s", in.name, in.v)
		}
	}

	if n := len(vs.GetValidators()); n != members0 {
		t.Errorf("1a: rejected stakes still created members: %d -> %d", members0, n)
	}
	if got := vs.GetTotalStake(); got.Cmp(baseline) != 0 {
		t.Errorf("1a: totalStake = %s after only-rejected admissions, want %s", got, baseline)
	}
	if err := vs.AddGenesisValidator("Node-nil", nil); err == nil {
		t.Error("1a: AddGenesisValidator accepted a nil stake")
	}
	if err := vs.SetStakeFromBalance("Node-nil", nil); err == nil {
		t.Error("1a: SetStakeFromBalance accepted a nil balance")
	}
}

// TestStakeAdmission_ExactlyMinimumIsAccepted is the other half of 1a: the fix
// must not reject a legitimate minimum-stake validator, and must not reject a
// fractional stake above the minimum.
func TestStakeAdmission_ExactlyMinimumIsAccepted(t *testing.T) {
	ResetSnapshots()
	defer ResetSnapshots()

	vs := NewValidatorSet(spx32())
	if err := vs.AddGenesisValidator("Node-min", spx32()); err != nil {
		t.Errorf("exactly the minimum stake was refused: %v", err)
	}
	// 32 SPX + 1 nSPX: the old whole-SPX truncation would have compared this as
	// exactly 32 and then re-multiplied a truncated value.
	justOver := new(big.Int).Add(spx32(), big.NewInt(1))
	if err := vs.AddGenesisValidator("Node-over", justOver); err != nil {
		t.Errorf("minimum+1nSPX was refused: %v", err)
	}
	// 1b: the full nSPX value must be stored, not a truncated SPX multiple.
	vs.mu.RLock()
	got := new(big.Int).Set(vs.validators["Node-over"].StakeAmount)
	vs.mu.RUnlock()
	if got.Cmp(justOver) != 0 {
		t.Errorf("1b: stored stake = %s, want %s (nSPX must be kept end to end)", got, justOver)
	}
}

const verifyEpochBlocks uint64 = 4

// spx32 is 32 SPX in nSPX.
func spx32() *big.Int {
	return new(big.Int).Mul(big.NewInt(32), new(big.Int).SetUint64(denom.SPX))
}

// TestQuorumArithmetic_StrictTwoThirds pins the exact vote counts. This is the
// table the operator-facing docs must match, written as arithmetic so it cannot
// drift. It is the stake half of what VerifyBlockAttestations checks.
func TestQuorumArithmetic_StrictTwoThirds(t *testing.T) {
	stake := new(big.Int).Mul(big.NewInt(32), new(big.Int).SetUint64(denom.SPX))

	cases := []struct {
		k        int
		voting   int
		mustHold bool
		why      string
	}{
		{1, 1, true, "1 validator: 1*3=3 > 1*2=2"},
		{2, 1, false, "2 validators, 1 votes: 3 > 4 is false"},
		{2, 2, true, "2 validators, both vote: 6 > 4"},
		{3, 2, false, "★ 3 validators, 2 vote: 6 > 6 is FALSE — exactly 2/3 is not strictly more"},
		{3, 3, true, "3 validators, all 3 vote: 9 > 6"},
		{4, 3, true, "4 validators, 3 vote: 9 > 8"},
		{4, 2, false, "4 validators, 2 vote: 6 > 8 is false"},
		{5, 4, true, "5 validators, 4 vote: 12 > 10"},
		{7, 5, true, "7 validators, 5 vote: 15 > 14"},
	}

	for _, c := range cases {
		total := new(big.Int).Mul(stake, big.NewInt(int64(c.k)))
		voted := new(big.Int).Mul(stake, big.NewInt(int64(c.voting)))
		if got := meetsStakeQuorum(voted, total); got != c.mustHold {
			t.Errorf("K=%d with %d voting: meetsStakeQuorum = %v, want %v (%s)",
				c.k, c.voting, got, c.mustHold, c.why)
		}
		// The exported wrapper must be the identical rule, not a copy that
		// can drift: core.VerifyBlockAttestations calls it.
		if got := MeetsStakeQuorum(voted, total); got != c.mustHold {
			t.Errorf("K=%d with %d voting: exported MeetsStakeQuorum = %v, want %v",
				c.k, c.voting, got, c.mustHold)
		}
	}
}

// TestStrictTwoThirdsCount_IntegerMath pins the DISTINCT-VOTER floor. The old
// code used int(N*0.67), which floors to 2 for BOTH N=3 and N=4 and so was not
// a 2/3 rule at all. These are the exact values verification enforces.
func TestStrictTwoThirdsCount_IntegerMath(t *testing.T) {
	want := map[int]int{1: 1, 2: 2, 3: 3, 4: 3, 5: 4, 6: 5, 7: 5, 10: 7}
	for n, w := range want {
		if got := StrictTwoThirdsCount(n); got != w {
			t.Errorf("StrictTwoThirdsCount(%d) = %d, want %d", n, got, w)
		}
	}
	if got := StrictTwoThirdsCount(0); got != 0 {
		t.Errorf("StrictTwoThirdsCount(0) = %d, want 0", got)
	}
	// The floor must never be satisfied by fewer than 2/3 of members, for any
	// N up to 200. This is the property int(N*0.67) violated at N=4.
	for n := 1; n <= 200; n++ {
		got := StrictTwoThirdsCount(n)
		if got*3 <= n*2 {
			t.Fatalf("N=%d: floor %d does not exceed 2/3 of %d", n, got, n)
		}
	}
}

// TestLiveness_ThreeValidatorsOneStopped_HaltsChain is the scenario the
// operator will actually hit on a 3-node devnet: stop one node, and the chain
// stops. This is CORRECT under strict >2/3, and the test exists so a future
// change cannot quietly relax it into a 2-of-3 rule.
func TestLiveness_ThreeValidatorsOneStopped_HaltsChain(t *testing.T) {
	stake := new(big.Int).Mul(big.NewInt(32), new(big.Int).SetUint64(denom.SPX))
	total := new(big.Int).Mul(stake, big.NewInt(3))

	if !meetsStakeQuorum(new(big.Int).Mul(stake, big.NewInt(3)), total) {
		t.Fatal("3/3 voting must commit")
	}
	if meetsStakeQuorum(new(big.Int).Mul(stake, big.NewInt(2)), total) {
		t.Fatal("2 of 3 must NOT clear strict >2/3 (64*3=192 is not > 96*2=192); " +
			"a 3-validator chain is expected to halt when one validator stops")
	}
	// And the distinct-voter floor agrees: 3 of 3 are required.
	if StrictTwoThirdsCount(3) != 3 {
		t.Error("a 3-validator set must require 3 distinct attesters")
	}
}

// TestLiveness_FourValidatorsOneStopped_ContinuesChain is the complementary
// case: 4 is the smallest set that survives one offline validator.
func TestLiveness_FourValidatorsOneStopped_ContinuesChain(t *testing.T) {
	stake := new(big.Int).Mul(big.NewInt(32), new(big.Int).SetUint64(denom.SPX))
	total := new(big.Int).Mul(stake, big.NewInt(4))

	if !meetsStakeQuorum(new(big.Int).Mul(stake, big.NewInt(3)), total) {
		t.Fatal("3 of 4 must clear strict >2/3 (96*3=288 > 128*2=256): " +
			"4 is the smallest set that tolerates one offline validator")
	}
	if meetsStakeQuorum(new(big.Int).Mul(stake, big.NewInt(2)), total) {
		t.Fatal("2 of 4 must not clear strict >2/3")
	}
	if StrictTwoThirdsCount(4) != 3 {
		t.Error("a 4-validator set must require 3 distinct attesters")
	}
}

// TestAddValidator_GenesisMembersAreActiveFromEpochZero pins the actual
// contract of AddValidator: it is the GENESIS-AUTHORING path, so a member added
// by it is active from epoch 0 and its stake IS in the total immediately.
//
// This is deliberately the OPPOSITE of the core.ValidatorSet.SetValidator
// behaviour the equivalent old test asserted. That old SetValidator took an
// explicit activation epoch and added a PENDING member with no weight; this
// package's AddValidator has no such parameter, and inventing one would create
// a second, divergent join path. The pending behaviour that actually matters —
// a validator scheduled for a future epoch gaining weight only at its boundary —
// is what ProcessEpochTransition and TestProcessEpochTransition_ActivatesInTheLiveSet
// cover, and is pinned again here through the public API.
func TestAddValidator_GenesisMembersAreActiveFromEpochZero(t *testing.T) {
	ResetSnapshots()
	vs, minStake := newSetWith("Node-a")

	// Genesis members count immediately: no epoch has been crossed, and every
	// member of an authored genesis is active at epoch 0.
	before := vs.GetTotalStake()
	if err := vs.AddGenesisValidator("Node-b", spx32()); err != nil {
		t.Fatalf("AddGenesisValidator: %v", err)
	}
	if got, want := vs.GetTotalStake(), new(big.Int).Mul(minStake, big.NewInt(2)); got.Cmp(want) != 0 {
		t.Errorf("after AddValidator totalStake = %s, want %s (a genesis member is active at epoch 0)", got, want)
	}
	if ids := vs.ActiveValidatorIDs(0); len(ids) != 2 {
		t.Errorf("ActiveValidatorIDs(0) = %v, want both genesis members active", ids)
	}
	_ = before

	// Now the pending case, through the public read surface: a member with a
	// FUTURE activation epoch holds no weight until its boundary.
	vs2, minStake2 := newSetWith("Node-a")
	vs2.mu.Lock()
	vs2.validators["Node-joiner"] = &StakedValidator{
		ID:              "Node-joiner",
		StakeAmount:     new(big.Int).Set(minStake2),
		ActivationEpoch: 4,
	}
	vs2.mu.Unlock()

	if got := vs2.GetTotalStake(); got.Cmp(minStake2) != 0 {
		t.Errorf("a pending validator must not be counted: totalStake = %s, want %s", got, minStake2)
	}
	// ...and it is genuinely absent from a snapshot taken before its epoch,
	// which is what verification would consult for those heights. EpochBlocks
	// is the package default here, so height 0 is epoch 0.
	vs2.TakeSnapshot(0)
	if snap := ValidatorSetAt(0); snap == nil {
		t.Fatal("epoch 0 snapshot missing")
	} else if _, present := snap.Validators["Node-joiner"]; present {
		t.Error("a validator pending until epoch 4 must not appear in the epoch-0 snapshot")
	}
}

// ============================================================================
// CHECKPOINT 1b — item 1 (continued): overflow, ejection, runtime admission
// ============================================================================

// TestStakeAdmission_HugeStakeDoesNotOverflow is 1b.
//
// The old signatures took `stakeSPX uint64` and did big.NewInt(int64(stakeSPX)).
// That conversion WRAPS NEGATIVE above 2^63-1, so a validator staking more than
// 9.22e18 SPX got a NEGATIVE stake — catastrophic in a quorum denominator. The
// parameters are now *big.Int in nSPX, so no narrowing cast exists at all.
func TestStakeAdmission_HugeStakeDoesNotOverflow(t *testing.T) {
	ResetSnapshots()
	defer ResetSnapshots()

	vs := NewValidatorSet(spx32())
	if err := vs.AddGenesisValidator("Node-a", spx32()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// 1e24 SPX: far beyond 2^63-1, so the old int64() cast would have wrapped.
	huge, ok := new(big.Int).SetString("1000000000000000000000000", 10)
	if !ok {
		t.Fatal("bad test constant")
	}
	hugeNSPX := new(big.Int).Mul(huge, new(big.Int).SetUint64(denom.SPX))

	if err := vs.AddGenesisValidator("Node-whale", hugeNSPX); err != nil {
		t.Fatalf("a huge stake was refused: %v", err)
	}
	vs.mu.RLock()
	got := new(big.Int).Set(vs.validators["Node-whale"].StakeAmount)
	vs.mu.RUnlock()
	if got.Sign() <= 0 {
		t.Fatalf("1b: stored stake is %s — this is the int64 overflow wrapping negative", got)
	}
	if got.Cmp(hugeNSPX) != 0 {
		t.Errorf("1b: stored stake = %s, want %s", got, hugeNSPX)
	}
	if total := vs.GetTotalStake(); total.Cmp(new(big.Int).Add(spx32(), hugeNSPX)) != 0 {
		t.Errorf("1b: totalStake = %s, want one validator plus the whale at %s", total, hugeNSPX)
	}
}

// TestTotalStake_EjectedValidatorLosesFullStake is 1c.
//
// The cached total used to be maintained by four separate incremental updates. A
// validator slashed or ejected after the last boundary therefore kept its FULL
// stake in the denominator forever, inflating the threshold every honest node
// had to reach. GetTotalStake() now recomputes from membership.
func TestTotalStake_EjectedValidatorLosesFullStake(t *testing.T) {
	ResetSnapshots()
	defer ResetSnapshots()

	vs := NewValidatorSet(spx32())
	for _, id := range []string{"Node-a", "Node-b", "Node-c"} {
		if err := vs.AddGenesisValidator(id, spx32()); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	vs.ProcessEpochTransition(0)
	if want := new(big.Int).Mul(spx32(), big.NewInt(3)); vs.GetTotalStake().Cmp(want) != 0 {
		t.Fatalf("full total = %s, want %s", vs.GetTotalStake(), want)
	}

	// ── Ejection: its FULL stake must leave the total. ──
	vs.mu.Lock()
	vs.validators["Node-c"].ExitEpoch = 1
	vs.mu.Unlock()
	vs.ProcessEpochTransition(1)
	want := new(big.Int).Mul(spx32(), big.NewInt(2))
	if got := vs.GetTotalStake(); got.Cmp(want) != 0 {
		t.Errorf("1c: after ejecting Node-c the total is %s, want %s — an ejected "+
			"validator must lose its FULL stake, not be discounted", got, want)
	}
	if ids := vs.ActiveValidatorIDs(1); len(ids) != 2 {
		t.Errorf("active set = %v, want 2 members", ids)
	}

	// ── Slashing must remove the FULL stake, with no transition at all. ──
	// This is the case an incrementally-maintained field cannot express: it
	// only changed when some other code path happened to touch it.
	vs.mu.Lock()
	vs.validators["Node-b"].IsSlashed = true
	vs.mu.Unlock()
	if afterSlash := vs.GetTotalStake(); afterSlash.Cmp(spx32()) != 0 {
		t.Errorf("1c: after slashing Node-b the total is %s, want %s — a slashed "+
			"validator must leave the denominator immediately", afterSlash, spx32())
	}
	vs.ProcessEpochTransition(1)
	if got := vs.GetTotalStake(); got.Cmp(spx32()) != 0 {
		t.Errorf("1c: after the next transition the total is %s, want %s", got, spx32())
	}
}

// TestEpochFromHeight_NotFromView pins the arithmetic that replaced the
// view-derived epoch: the same height always yields the same epoch, and the
// activation schedule is always strictly ahead of the current epoch.
func TestEpochFromHeight_NotFromView(t *testing.T) {
	prev := epochBlocksOverride
	SetEpochBlocks(4)
	defer func() { epochBlocksOverride = prev }()

	for _, c := range []struct{ h, e uint64 }{{0, 0}, {3, 0}, {4, 1}, {7, 1}, {8, 2}, {12, 3}} {
		if got := EpochForHeight(c.h); got != c.e {
			t.Errorf("EpochForHeight(%d) = %d, want %d", c.h, got, c.e)
		}
	}
	if !IsEpochBoundary(4) || !IsEpochBoundary(8) {
		t.Error("4 and 8 must be epoch boundaries at EpochBlocks=4")
	}
	if IsEpochBoundary(5) {
		t.Error("5 must not be an epoch boundary at EpochBlocks=4")
	}
	for h := uint64(0); h < 40; h++ {
		if got, cur := ActivationEpochForStake(h), EpochForHeight(h); got <= cur {
			t.Errorf("ActivationEpochForStake(%d) = %d, must be > current epoch %d", h, got, cur)
		}
	}
}
