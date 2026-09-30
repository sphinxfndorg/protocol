// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/verify_attestations_test.go
//
// STEP 1 of the duplicate-layer deletion: VerifyBlockAttestations is now
// height-keyed, snapshot-only, and fails closed.
package core

import (
	"math/big"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/consensus"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"

	denom "github.com/sphinxfndorg/protocol/src/params/denom"
)

const verifyTestEpochBlocks = 4

// spx32 is 32 SPX in nSPX, the protocol minimum stake and the unit used
// throughout these tests.
func spx32() *big.Int { return new(big.Int).Mul(big.NewInt(32), new(big.Int).SetUint64(denom.SPX)) }

// blockAttestedBy builds a block at `height` attested by exactly `attesters`.
func blockAttestedBy(height uint64, attesters ...string) *types.Block {
	atts := make([]*types.Attestation, 0, len(attesters))
	for _, a := range attesters {
		atts = append(atts, &types.Attestation{ValidatorID: a, View: 0})
	}
	return &types.Block{
		// ★ Header.Block, not Header.Height. GetHeight() reads Header.Block,
		// and that is the field consensus and the sync path key on. The two
		// fields are documented as equal, so setting only Height would build a
		// block that reads as height 0 — i.e. genesis — and every assertion
		// below would be testing the genesis exemption instead.
		Header: &types.BlockHeader{Block: height, Height: height},
		Body:   types.BlockBody{Attestations: atts},
	}
}

// snapOf builds a snapshot row for `ids`, each holding 32 SPX.
func snapOf(epoch uint64, ids ...string) consensus.ValidatorSnapshot {
	s := consensus.ValidatorSnapshot{
		Epoch:      epoch,
		TotalStake: new(big.Int).Mul(spx32(), big.NewInt(int64(len(ids)))),
		Validators: make(map[string]*consensus.StakedValidator, len(ids)),
	}
	for _, id := range ids {
		s.Validators[id] = &consensus.StakedValidator{ID: id, StakeAmount: spx32()}
	}
	return s
}

// withEpochBlocks installs a small epoch length for the duration of a test and
// restores the previous override afterwards.
func withEpochBlocks(t *testing.T, n uint64) {
	t.Helper()
	prev := consensus.EpochBlocksOverride()
	consensus.SetEpochBlocks(n)
	t.Cleanup(func() { consensus.RestoreEpochBlocks(prev) })
	consensus.ResetSnapshots()
	t.Cleanup(consensus.ResetSnapshots)
}

// ---------------------------------------------------------------------------
// (a) FAIL CLOSED
// ---------------------------------------------------------------------------

// TestVerifyBlockAttestations_FailsClosedOnMissingSnapshot is requirement (a).
// With no snapshot for the block's height, the block is REJECTED.
//
// The old code had a `block.Height < EpochBlocks` branch that fell back to the
// LIVE set across the whole genesis epoch, so a node that had taken no snapshot
// at all verified blocks against whatever its local set happened to be. That
// fallback is gone; this test pins the absence of any such escape hatch,
// including at a height INSIDE the genesis epoch, which is exactly the range
// the old branch covered.
func TestVerifyBlockAttestations_FailsClosedOnMissingSnapshot(t *testing.T) {
	withEpochBlocks(t, verifyTestEpochBlocks)

	// A block perfectly well attested by the single genesis validator.
	blk := blockAttestedBy(1, "Node-a")

	err := VerifyBlockAttestations(blk)
	if err == nil {
		t.Fatal("VerifyBlockAttestations accepted a block with no snapshot; it must fail closed")
	}
	if !strings.Contains(err.Error(), "no validator set snapshot") {
		t.Errorf("the error should name the missing snapshot, got: %v", err)
	}

	// A height past the first boundary must be rejected too, so a missing
	// snapshot is never survivable in ANY epoch.
	if err := VerifyBlockAttestations(blockAttestedBy(9, "Node-a", "Node-b", "Node-c")); err == nil {
		t.Error("height 9 past the first boundary with no snapshot must be rejected too")
	}

	// Once the snapshot EXISTS, the very same block verifies. This proves the
	// rejection was about the missing snapshot, not about the attestation set.
	consensus.StoreSnapshotForTest(snapOf(0, "Node-a"))
	if err := VerifyBlockAttestations(blk); err != nil {
		t.Errorf("with the epoch-0 snapshot present the block must verify: %v", err)
	}
}

// ---------------------------------------------------------------------------
// (b) STRICT quorum against the SNAPSHOT's own stake and membership
// ---------------------------------------------------------------------------

// TestVerifyBlockAttestations_StrictTwoThirdsAgainstSnapshot is requirement
// (b): quorum is voted*3 > total*2 against the snapshot's OWN TotalStake, with
// a distinct-voter floor from the snapshot's own size.
//
// The regression this pins: the old check computed required = total*2/3 with
// integer truncation and compared with >=. For three equal validators, 2 of 3 is
// exactly 2/3, and that old arithmetic ACCEPTED it. Under the protocol rule —
// strictly MORE than two thirds — 2 of 3 must be rejected.
func TestVerifyBlockAttestations_StrictTwoThirdsAgainstSnapshot(t *testing.T) {
	withEpochBlocks(t, verifyTestEpochBlocks)
	consensus.StoreSnapshotForTest(snapOf(0, "Node-a", "Node-b", "Node-c"))

	// 2 of 3 is exactly 2/3 — not strictly more. MUST be rejected.
	if err := VerifyBlockAttestations(blockAttestedBy(1, "Node-a", "Node-b")); err == nil {
		t.Error("2 of 3 validators must NOT satisfy strict >2/3 (it is exactly 2/3)")
	}

	// All 3 of 3 must be accepted.
	if err := VerifyBlockAttestations(blockAttestedBy(1, "Node-a", "Node-b", "Node-c")); err != nil {
		t.Errorf("3 of 3 must verify: %v", err)
	}

	// Duplicates add no weight: one validator attesting 50 times is one vote.
	dupes := make([]*types.Attestation, 0, 50)
	for i := 0; i < 50; i++ {
		dupes = append(dupes, &types.Attestation{ValidatorID: "Node-a"})
	}
	if err := VerifyBlockAttestations(&types.Block{
		Header: &types.BlockHeader{Block: 1, Height: 1},
		Body:   types.BlockBody{Attestations: dupes},
	}); err == nil {
		t.Error("50 duplicate attestations from one validator must not reach quorum")
	}

	// An attester outside the snapshot contributes NOTHING, so Node-z's vote
	// leaves the total at 2 of 3 and the block is still rejected.
	if err := VerifyBlockAttestations(blockAttestedBy(1, "Node-a", "Node-b", "Node-z")); err == nil {
		t.Error("a vote from outside the snapshot must not count toward quorum")
	}
}

// TestVerifyBlockAttestations_WhaleCannotCommitAlone pins the distinct-voter
// floor where it bites. A single validator holding 10 of 13 units clears the
// STAKE rule by itself (10*3=30 > 13*2=26) but must not be able to commit,
// because 4 members require (2*4)/3+1 = 3 distinct attesters.
//
// This is the property the old int(N*0.67) floor lost: 0.67*4 floors to 2, so
// the old check would have let the whale commit alone.
func TestVerifyBlockAttestations_WhaleCannotCommitAlone(t *testing.T) {
	withEpochBlocks(t, verifyTestEpochBlocks)

	unit := spx32()
	snap := consensus.ValidatorSnapshot{
		Epoch:      0,
		TotalStake: new(big.Int).Mul(unit, big.NewInt(13)),
		Validators: map[string]*consensus.StakedValidator{
			"Node-whale": {ID: "Node-whale", StakeAmount: new(big.Int).Mul(unit, big.NewInt(10))},
			"Node-f1":    {ID: "Node-f1", StakeAmount: new(big.Int).Set(unit)},
			"Node-f2":    {ID: "Node-f2", StakeAmount: new(big.Int).Set(unit)},
			"Node-f3":    {ID: "Node-f3", StakeAmount: new(big.Int).Set(unit)},
		},
	}
	consensus.StoreSnapshotForTest(snap)

	// The stake rule alone is satisfied by the whale alone. That is what makes
	// the distinct-voter floor load-bearing rather than decorative.
	if !consensus.MeetsStakeQuorum(new(big.Int).Mul(unit, big.NewInt(10)), snap.TotalStake) {
		t.Fatal("test setup wrong: 10 of 13 should clear the stake rule on its own")
	}
	if err := VerifyBlockAttestations(blockAttestedBy(1, "Node-whale")); err == nil {
		t.Error("a single validator holding 10 of 13 must not commit: 4 members need 3 distinct attesters")
	}
	// Two of four is not enough either.
	if err := VerifyBlockAttestations(blockAttestedBy(1, "Node-whale", "Node-f1")); err == nil {
		t.Error("2 distinct attesters of 4 must not commit")
	}
	// Three does.
	if err := VerifyBlockAttestations(blockAttestedBy(1, "Node-whale", "Node-f1", "Node-f2")); err != nil {
		t.Errorf("3 distinct attesters of 4 must commit: %v", err)
	}
}

// ---------------------------------------------------------------------------
// (c) LATE-NODE REPLAY: the set changes in epoch 2
// ---------------------------------------------------------------------------

// TestVerifyBlockAttestations_LateNodeReplayAcrossEpochChange is requirement
// (c). A late node replaying history must verify an epoch-0 block against the
// epoch-0 set EVEN THOUGH the set has since changed, and must reject a later
// block signed only by a validator absent from the set governing that height.
func TestVerifyBlockAttestations_LateNodeReplayAcrossEpochChange(t *testing.T) {
	withEpochBlocks(t, verifyTestEpochBlocks) // epoch 0 = h 0..3, epoch 2 = h 8..11

	_ = spx32()
	epoch0 := snapOf(0, "Node-a") // Node-a alone
	consensus.StoreSnapshotForTest(epoch0)

	// ── The epoch-0 block, verified against the epoch-0 snapshot. ──
	oldBlock := blockAttestedBy(1, "Node-a")
	if err := VerifyBlockAttestations(oldBlock); err != nil {
		t.Fatalf("an epoch-0 block signed by the epoch-0 set must verify: %v", err)
	}

	// The world advances: Node-b joins, so the set governing epoch 2 has two
	// members. This is what a late node observes when it syncs past the
	// boundary: the LIVE set and the epoch-0 snapshot now disagree, and only
	// the latter may be used for height 1.
	epoch2 := snapOf(2, "Node-a", "Node-b")
	consensus.StoreSnapshotForTest(epoch2)

	// The old block STILL verifies: a later epoch cannot retroactively
	// invalidate it. This is the property a late node depends on.
	if err := VerifyBlockAttestations(oldBlock); err != nil {
		t.Errorf("an epoch-0 block must still verify after the set changed in epoch 2: %v", err)
	}
	if len(epoch0.Validators) != 1 {
		t.Errorf("the epoch-0 snapshot was mutated by the later epoch: %d validators, want 1", len(epoch0.Validators))
	}

	// ── A LATER block signed only by a validator that left / never joined. ──
	// Node-c is not in the epoch-2 snapshot, so its lone vote is worth nothing
	// and quorum fails.
	if err := VerifyBlockAttestations(blockAttestedBy(9, "Node-c")); err == nil {
		t.Error("a height-9 block signed only by a validator absent from the epoch-2 set must be rejected")
	}
	// Re-signed by the epoch-2 set, the same height verifies. So the rejection
	// above was about the attester set, not the block.
	if err := VerifyBlockAttestations(blockAttestedBy(9, "Node-a", "Node-b")); err != nil {
		t.Errorf("a height-9 block signed by both epoch-2 validators must verify: %v", err)
	}
	// A height-9 block carrying ONLY the old epoch-0 signer's vote: Node-a alone
	// is 32 of 64 = exactly 2/3, which is not strictly more, so it is refused.
	if err := VerifyBlockAttestations(blockAttestedBy(9, "Node-a")); err == nil {
		t.Error("a lone vote that is exactly 2/3 of the epoch-2 stake must be rejected")
	}
}

// ---------------------------------------------------------------------------
// (d) NO EPOCH OR SET PARAMETER ANYWHERE
// ---------------------------------------------------------------------------

// TestVerifyBlockAttestations_SignatureTakesOnlyABlock is requirement (d),
// enforced at COMPILE time by the assignment below.
//
// The old signature was
//
//	func VerifyBlockAttestations(block *Block, vs validatorSetProvider) error
//
// which let each caller supply a different set — and the two production callers
// did disagree (one used height/100, the other height/SlotsPerEpoch(32)). The
// new signature takes only the block, so a caller cannot supply an epoch or a
// set at all: the epoch is derived from the block's own height inside the
// function. If the parameter ever comes back, this line stops compiling.
func TestVerifyBlockAttestations_SignatureTakesOnlyABlock(t *testing.T) {
	var fn func(*types.Block) error = VerifyBlockAttestations

	withEpochBlocks(t, verifyTestEpochBlocks)
	consensus.StoreSnapshotForTest(snapOf(0, "Node-a"))
	if err := fn(blockAttestedBy(1, "Node-a")); err != nil {
		t.Errorf("the block-only signature must verify against the epoch-0 snapshot: %v", err)
	}
}

// TestVerifyBlockAttestations_EpochComesFromHeightNotCaller is requirement (d)
// at runtime: the epoch a block is judged by is a function of its HEIGHT, so
// the identical attestation verifies at one height and is refused at another.
func TestVerifyBlockAttestations_EpochComesFromHeightNotCaller(t *testing.T) {
	withEpochBlocks(t, verifyTestEpochBlocks)
	// ONLY epoch 2 has a snapshot; heights 8..11 resolve to it.
	consensus.StoreSnapshotForTest(snapOf(2, "Node-a"))

	if err := VerifyBlockAttestations(blockAttestedBy(9, "Node-a")); err != nil {
		t.Errorf("height 9 resolves to epoch 2, which has a snapshot, so it must verify: %v", err)
	}
	if err := VerifyBlockAttestations(blockAttestedBy(1, "Node-a")); err == nil {
		t.Error("height 1 resolves to epoch 0, which has NO snapshot, so the same attestation must be rejected")
	}
	// A zero-attestation block is refused independently of snapshots.
	if err := VerifyBlockAttestations(&types.Block{
		Header: &types.BlockHeader{Block: 9, Height: 9},
		Body:   types.BlockBody{},
	}); err == nil {
		t.Error("a block with zero attestations must be rejected even with a valid snapshot")
	}
	// Genesis (height 0) is exempt: it is verified by config/hash, not quorum.
	if err := VerifyBlockAttestations(blockAttestedBy(0)); err != nil {
		t.Errorf("the genesis block must be exempt from attestation verification: %v", err)
	}
	// A nil block is an error, not a panic.
	if err := VerifyBlockAttestations(nil); err == nil {
		t.Error("a nil block must be rejected")
	}
}
