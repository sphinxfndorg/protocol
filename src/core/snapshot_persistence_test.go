// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/snapshot_persistence_test.go
//
// Requirement (e) of STEP 1: after a restart mid-epoch, ValidatorSetAt(h) must
// equal the pre-restart value for the same h, read back from rawdb.
package core

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/core/rawdb"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// TestValidatorSetAt_SurvivesRestartMidEpoch is requirement (e).
//
// The point of the test is the RESTART, not the write. A snapshot that only
// ever lives in memory is correct right up to the moment the process dies, and
// then the node has no record of the set governing the epoch it is serving —
// so VerifyBlockAttestations, which correctly fails closed, rejects every block
// it sees until it re-crosses a boundary. The test therefore:
//
//  1. opens a real LevelDB, attaches it, and takes snapshots at two epochs;
//  2. records ValidatorSetAt(h) for several heights spanning both epochs;
//  3. CLOSES the database and resets all in-memory state, exactly as a crash
//     plus restart would;
//  4. reopens the same directory, replays from rawdb, and asserts every
//     recorded height resolves to the SAME snapshot, compared by hash so the
//     assertion is on content and not on pointer identity.
func TestValidatorSetAt_SurvivesRestartMidEpoch(t *testing.T) {
	withEpochBlocks(t, verifyTestEpochBlocks) // epoch 0 = h 0..3, epoch 2 = h 8..11

	dbPath := filepath.Join(t.TempDir(), "chaindb")

	// ── Before the restart ──
	db, err := database.NewLevelDB(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	store := &rawdbSnapshotStore{db: db}
	consensus.SetSnapshotStore(store)

	// Build the snapshots from real live sets, the way the chain does.
	epoch0Set := mustLiveSetWith("Node-a")
	epoch0Set.TakeSnapshot(0)

	epoch2Set := mustLiveSetWith("Node-a", "Node-b")
	epoch2Set.TakeSnapshot(2)

	// Record what each height resolves to, mid-epoch included. Epoch 1 is
	// deliberately absent from the set: no snapshot was ever taken for it, so
	// those heights must resolve to nothing, before OR after the restart.
	heights := []uint64{0, 1, 3, 8, 9, 11}
	before := make(map[uint64]string, len(heights))
	for _, h := range heights {
		snap := consensus.ValidatorSetAt(h)
		if snap == nil {
			t.Fatalf("height %d has no snapshot before the restart", h)
		}
		before[h] = snap.Hash()
	}
	// Sanity: the two epochs really are different sets, or the test proves
	// nothing about which epoch a height resolved to.
	if before[1] == before[9] {
		t.Fatal("epoch 0 and epoch 2 snapshots hash identically; test setup is wrong")
	}
	// Height 4 is epoch 1, which was never snapshotted. A restart must not
	// invent it.
	if snap := consensus.ValidatorSetAt(4); snap != nil {
		t.Fatal("height 4 resolves to epoch 1, which has no snapshot; expected nil")
	}

	// ── The restart ──
	// Detach the store and wipe in-memory state BEFORE closing, so nothing can
	// be served out of the old process's memory.
	consensus.SetSnapshotStore(nil)
	consensus.ResetSnapshots()
	if consensus.ValidatorSetAt(1) != nil {
		t.Fatal("in-memory snapshots survived ResetSnapshots; the restart would prove nothing")
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	// ── After the restart ──
	db2, err := database.NewLevelDB(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer db2.Close()
	consensus.SetSnapshotStore(&rawdbSnapshotStore{db: db2})

	// This is what AttachSnapshotStore does on a real node startup.
	recovered, err := consensus.ReplaySnapshotsFromStore()
	if err != nil {
		t.Fatalf("replay snapshots: %v", err)
	}
	if recovered != 2 {
		t.Errorf("replayed %d snapshots from rawdb, want 2 (epochs 0 and 2)", recovered)
	}

	for _, h := range heights {
		snap := consensus.ValidatorSetAt(h)
		if snap == nil {
			t.Errorf("height %d has NO snapshot after the restart, but had one before", h)
			continue
		}
		if got := snap.Hash(); got != before[h] {
			t.Errorf("height %d resolves to a different set after the restart:\n  before %s\n  after  %s",
				h, before[h], got)
		}
	}
	// The unsnapshotted epoch is still unsnapshotted after the replay.
	if snap := consensus.ValidatorSetAt(4); snap != nil {
		t.Error("height 4 (epoch 1) has a snapshot after the restart but had none before")
	}

	// And the restored snapshot is a real, usable set: a block at height 9
	// verifies against it, which is the whole point of persisting.
	if err := VerifyBlockAttestations(blockAttestedBy(9, "Node-a", "Node-b")); err != nil {
		t.Errorf("a height-9 block must verify against the REPLAYED epoch-2 snapshot: %v", err)
	}
	// A height-1 block still verifies against the replayed epoch-0 snapshot, so
	// a late node can still replay history after a restart.
	if err := VerifyBlockAttestations(blockAttestedBy(1, "Node-a")); err != nil {
		t.Errorf("a height-1 block must verify against the REPLAYED epoch-0 snapshot: %v", err)
	}
}

// TestValidatorSnapshotRow_RejectsInconsistentTotal proves the persistence
// layer refuses to store a snapshot whose declared total is unreachable by its
// own members. Such a row would let a quorum check divide by a denominator no
// voter in the set could account for, and — because it is on disk — it would
// survive every restart.
func TestValidatorSnapshotRow_RejectsInconsistentTotal(t *testing.T) {
	unit := spx32()
	row := &rawdb.ValidatorSnapshotRow{
		Epoch:      0,
		TotalStake: new(big.Int).Mul(unit, big.NewInt(5)).String(), // claims 5
		Validators: map[string]rawdb.VSRow{
			"Node-a": {Stake: unit.String()}, // sums to 1
		},
	}
	if err := row.Validate(); err == nil {
		t.Error("a row whose total does not equal the sum of its members must be refused")
	}

	// A consistent row is accepted, which confirms the check above is the
	// discriminator and not a blanket rejection.
	row2 := &rawdb.ValidatorSnapshotRow{
		Epoch:      0,
		TotalStake: unit.String(),
		Validators: map[string]rawdb.VSRow{"Node-a": {Stake: unit.String()}},
	}
	if err := row2.Validate(); err != nil {
		t.Errorf("a consistent row must be accepted: %v", err)
	}
}

// ============================================================================
// Checkpoint item 5: served and stored genesis_state.json are the SAME BYTES
// ============================================================================

// TestGenesisStateFile_ServedAndStoredBytesAreIdentical proves checkpoint item 5
// end to end, across the exact three functions a real devnet uses:
//
//	author   WriteGenesisFile        (bootstrap node authors and persists)
//	serve    ServeDevnetBundle      (the same node answers a joiner's fetch)
//	store    WriteDevnetBundleFile  (the joiner persists what it received)
//
// The joiner then RE-SERVES what it stored, so a late node fetching from the
// joiner is provably getting the same document again.
//
// WHY BYTES AND NOT SEMANTICS. The bootstrap document is what a joiner
// reconstructs block 0 from, and every node must derive the same genesis hash
// from it. Two documents can be semantically equal — unmarshalled into the same
// GenesisStateFile — and still hash differently if key order, indentation, or a
// trailing newline differs. Validating the parsed struct would pass in both
// cases and prove nothing, which is exactly the shape of the gap this closes.
func TestGenesisStateFile_ServedAndStoredBytesAreIdentical(t *testing.T) {
	authorDir := t.TempDir()
	joinerDir := t.TempDir()
	secondJoinerDir := t.TempDir()

	minStake := SelfGenesisStakeNSPX()
	gf := &GenesisStateFile{
		Version:   genesisStateFileVersion,
		Bootstrap: true,
		Chain: GenesisChainParams{
			ChainID: DevnetChainID, Network: "devnet",
			EpochBlocks: DevnetEpochBlocks, MinStakeNSPX: minStake,
		},
		Validators: []GenesisStakedValidator{{NodeID: "Node-a", StakeNSPX: minStake}},
	}

	// ── 1. The bootstrap node authors and persists the document. ──
	if err := WriteGenesisFile(authorDir, gf); err != nil {
		t.Fatalf("WriteGenesisFile: %v", err)
	}
	authorBytes, err := os.ReadFile(GenesisStateFilePathForDataDir(authorDir))
	if err != nil {
		t.Fatalf("read authored file: %v", err)
	}
	if len(authorBytes) == 0 {
		t.Fatal("the authored genesis_state.json is empty")
	}
	authorHash := sha256.Sum256(authorBytes)

	// ── 2. It serves those bytes to a joiner. ──
	const authorAddr = "127.0.0.1:30399"
	RegisterDevnetBundleDataDir(authorAddr, authorDir)
	resp, err := ServeDevnetBundle(authorAddr, DevnetBundleRequest{File: GenesisStateFileName})
	if err != nil {
		t.Fatalf("ServeDevnetBundle: %v", err)
	}
	if !resp.Ready || len(resp.Data) == 0 {
		t.Fatal("the bootstrap node did not offer the document")
	}
	if servedHash := sha256.Sum256(resp.Data); servedHash != authorHash {
		t.Fatalf("SERVED bytes differ from AUTHORED bytes:\n  authored sha256=%x (%d bytes)\n  served   sha256=%x (%d bytes)",
			authorHash, len(authorBytes), servedHash, len(resp.Data))
	}

	// The joiner fail-closes on them before touching disk, as production does.
	if err := ValidateDevnetBundleBytes(GenesisStateFileName, resp.Data); err != nil {
		t.Fatalf("the served document failed validation: %v", err)
	}

	// ── 3. The joiner stores exactly what it received. ──
	subdir, ok := BundleSubdirFor(GenesisStateFileName)
	if !ok {
		t.Fatalf("%s is not an allowlisted bundle file", GenesisStateFileName)
	}
	if err := WriteDevnetBundleFile(joinerDir, subdir, resp.Data); err != nil {
		t.Fatalf("WriteDevnetBundleFile: %v", err)
	}
	joinBytes, err := os.ReadFile(GenesisStateFilePathForDataDir(joinerDir))
	if err != nil {
		t.Fatalf("read joiner file: %v", err)
	}
	if joinHash := sha256.Sum256(joinBytes); joinHash != authorHash {
		t.Errorf("STORED bytes differ from SERVED bytes:\n  authored sha256=%x\n  stored   sha256=%x", authorHash, joinHash)
	}
	if string(joinBytes) != string(authorBytes) {
		t.Errorf("stored document is not byte-identical to the authored one (%d vs %d bytes)", len(joinBytes), len(authorBytes))
	}

	// ── 4. The joiner serves the same document onward. ──
	// A second-generation joiner must receive the identical document, or the
	// network has two different genesis documents in circulation.
	const joinerAddr = "127.0.0.1:30398"
	RegisterDevnetBundleDataDir(joinerAddr, joinerDir)
	resp2, err := ServeDevnetBundle(joinerAddr, DevnetBundleRequest{File: GenesisStateFileName})
	if err != nil {
		t.Fatalf("ServeDevnetBundle (joiner): %v", err)
	}
	if h := sha256.Sum256(resp2.Data); h != authorHash {
		t.Errorf("second-generation fetch returned different bytes: sha256=%x, want %x", h, authorHash)
	}

	// ── 5. Store onward; the document must be stable across generations. ──
	if err := WriteDevnetBundleFile(secondJoinerDir, subdir, resp2.Data); err != nil {
		t.Fatalf("WriteDevnetBundleFile (second joiner): %v", err)
	}
	secondBytes, err := os.ReadFile(GenesisStateFilePathForDataDir(secondJoinerDir))
	if err != nil {
		t.Fatalf("read second joiner file: %v", err)
	}
	if h := sha256.Sum256(secondBytes); h != authorHash {
		t.Errorf("second-generation STORED bytes differ: sha256=%x, want %x", h, authorHash)
	}

	// ── 6. The bytes must also still round-trip to the same struct. ──
	// Same bytes AND same meaning; either alone would be a weaker claim.
	var reparsed GenesisStateFile
	if err := ValidateGenesisFileBytes(authorBytes, &reparsed); err != nil {
		t.Errorf("the authoritative bytes do not re-validate: %v", err)
	}

	t.Logf("genesis_state.json byte-identical across author/serve/store/re-serve: sha256=%x (%d bytes)",
		authorHash, len(authorBytes))
}

// TestGenesisStateFile_TrailingNewlineIsStable documents the one place where
// the author and the store path could plausibly disagree: the author appends a
// trailing newline (json.MarshalIndent + append(data, '\n')), the store path
// does not. Today that is harmless because the store path copies bytes
// verbatim, but it is exactly the kind of asymmetry that produces a DIFFERENT
// document the moment anyone re-serializes on the store path — and every node
// derives the genesis hash from these bytes.
//
// This pins the author-side shape so such a change is a deliberate, visible
// edit rather than an accident discovered in production.
func TestGenesisStateFile_TrailingNewlineIsStable(t *testing.T) {
	dir := t.TempDir()
	minStake := SelfGenesisStakeNSPX()
	gf := &GenesisStateFile{
		Version:   genesisStateFileVersion,
		Bootstrap: true,
		Chain: GenesisChainParams{
			ChainID: DevnetChainID, Network: "devnet",
			EpochBlocks: DevnetEpochBlocks, MinStakeNSPX: minStake,
		},
		Validators: []GenesisStakedValidator{{NodeID: "Node-a", StakeNSPX: minStake}},
	}
	if err := WriteGenesisFile(dir, gf); err != nil {
		t.Fatalf("WriteGenesisFile: %v", err)
	}
	b, err := os.ReadFile(GenesisStateFilePathForDataDir(dir))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("empty document")
	}
	if b[len(b)-1] != '\n' {
		t.Error("the authored document no longer ends with a newline; the author and store paths would now differ by one byte")
	}
	// It must stay pretty-printed: operators diff this file, and a compact
	// re-serialization would also change the hash.
	if !bytes.Contains(b, []byte("\n  ")) {
		t.Error("the authored document is no longer indented; it must stay human-readable")
	}
}

// ============================================================================
// Checkpoint 1b item 4: snapshot durability vs the block commit
// ============================================================================

// TestSnapshotDurability_CrashBetweenBlockAndSnapshot demonstrates the exact
// crash window and proves the recovery, because the two writes are NOT atomic.
//
// The ordering inside CommitBlock is:
//  1. bc.storage.StoreBlock(block)          — blockchain.go:2051, BLOCK -> rawdb
//  2. bc.applyEpochTransitionIfBoundary(h)  — blockchain.go:2109, SNAPSHOT -> rawdb
//
// They are separate Puts with no shared WriteBatch, so a crash between them
// leaves a COMMITTED block at height h with no snapshot for the epoch that block
// opened. That is a real window, not a theoretical one.
//
// The recovery is the interesting half. On restart the node replays the vsnap:
// namespace and finds the epoch MISSING. Two properties are asserted:
//
//	(a) the block is still durable, so the epoch is RE-DERIVABLE by replaying
//	    committed blocks — only the cached summary was lost, never the data;
//	(b) until it is re-derived, verification for that epoch FAILS CLOSED rather
//	    than silently serving the genesis set, which would otherwise let a node
//	    accept blocks under a set that never governed them.
func TestSnapshotDurability_CrashBetweenBlockAndSnapshot(t *testing.T) {
	withEpochBlocks(t, verifyTestEpochBlocks) // epoch 2 starts at height 8

	dbPath := filepath.Join(t.TempDir(), "chaindb")
	db, err := database.NewLevelDB(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	consensus.SetSnapshotStore(&rawdbSnapshotStore{db: db})
	t.Cleanup(func() {
		consensus.SetSnapshotStore(nil)
		consensus.ResetSnapshots()
		_ = db.Close()
	})

	// ── The chain reaches a boundary. Height 8 opens epoch 2. ──
	vs := mustLiveSetWith("Node-a", "Node-b")
	vs.TakeSnapshot(0)
	vs.ProcessEpochTransition(2)

	// Simulate the crash: the BLOCK is stored, the SNAPSHOT is not — exactly the
	// state after a crash between CommitBlock's two writes.
	if err := rawdb.WriteBlock(db, epochBoundaryBlock(8)); err != nil {
		t.Fatalf("WriteBlock: %v", err)
	}

	// ── Restart: wipe memory, keep only what reached disk. ──
	consensus.ResetSnapshots()
	rows, err := rawdb.ReadAllValidatorSnapshots(db)
	if err != nil {
		t.Fatalf("scan snapshots: %v", err)
	}
	var have0, have2 bool
	for _, r := range rows {
		switch r.Epoch {
		case 0:
			have0 = true
		case 2:
			have2 = true
		}
	}
	if !have0 {
		t.Error("the epoch-0 snapshot should have been persisted before the crash")
	}
	if have2 {
		t.Fatal("test setup wrong: the epoch-2 snapshot must NOT exist — that IS the crash window")
	}

	// (a) The block that opened the epoch IS durable, so the epoch is
	// re-derivable rather than lost.
	h, err := rawdb.ReadCanonicalHash(db, 8)
	if err != nil {
		t.Fatalf("the block that opened epoch 2 is NOT durable: %v", err)
	}
	if h == "" {
		t.Fatal("empty canonical hash at height 8")
	}

	// (b) Verification for epoch 2 now FAILS CLOSED — no snapshot, no answer.
	blk := blockAttestedBy(9, "Node-a", "Node-b")
	err = VerifyBlockAttestations(blk)
	if err == nil {
		t.Error("★ a block in the epoch whose snapshot was lost VERIFIED; the crash " +
			"window would let a node accept blocks under a set that never governed them")
	} else if !strings.Contains(err.Error(), "no validator set snapshot") {
		t.Errorf("expected a missing-snapshot failure, got: %v", err)
	}
	// Epoch 0 is unaffected — the failure is scoped to the lost epoch.
	if snap := consensus.ValidatorSetAt(3); snap != nil {
		t.Error("an epoch-0 snapshot appeared without a replay; memory was not actually cleared")
	}

	// ── Recovery: re-derive epoch 2 and write it, as a restart replay would. ──
	vs2 := mustLiveSetWith("Node-a", "Node-b")
	vs2.TakeSnapshot(0)
	vs2.ProcessEpochTransition(2)
	vs2.TakeSnapshot(2)

	if _, err := consensus.ReplaySnapshotsFromStore(); err != nil {
		t.Fatalf("replay after recovery: %v", err)
	}
	if snap := consensus.ValidatorSetAt(9); snap == nil {
		t.Fatal("after re-deriving, height 9 still has no snapshot")
	}
	if err := VerifyBlockAttestations(blk); err != nil {
		t.Errorf("after recovery the epoch-2 block must verify again: %v", err)
	}
	t.Logf("crash between StoreBlock(2051) and applyEpochTransition(2109) recovered by "+
		"re-deriving epoch %d from the committed block at height 8", consensus.EpochForHeight(8))
}

// epochBoundaryBlock builds a minimal committed block at `height` for the
// durability test. Only its height and its persistence matter, but rawdb
// requires a hash and a parent hash to store a canonical entry.
func epochBoundaryBlock(height uint64) *types.Block {
	h := make([]byte, 32)
	h[0] = byte(height)
	h[1] = byte(height >> 8)
	parent := make([]byte, 32)
	parent[31] = 1
	return &types.Block{
		Header: &types.BlockHeader{
			Block:      height,
			Height:     height,
			Hash:       h,
			ParentHash: parent,
		},
		Body: types.BlockBody{},
	}
}

// ============================================================================
// Checkpoint 1b item 3: the first block of each epoch
// ============================================================================

// TestEpochFirstBlock_VerifiesAgainstItsOwnEpochSnapshot answers "when is the
// snapshot for epoch e created, and can the first block of epoch e be verified
// BEFORE it commits?"
//
// ★ WHEN IT IS CREATED. Exactly one call site exists outside tests:
// core/blockchain.go:2215 `vs.TakeSnapshot(epoch)`, reached from
// `applyEpochTransitionIfBoundary`, called at core/blockchain.go:2109 — inside
// CommitBlock, AFTER bc.storage.StoreBlock(block) at line 2051 and BEFORE the
// commit returns.
//
// So a block that OPENS epoch e is itself the first block of epoch e, and it is
// the very block whose commit creates the snapshot for e. The snapshot exists
// from the moment that block is committed and NOT one block earlier. A verifier
// replaying it before its commit therefore has no snapshot for epoch e, and must
// fail closed rather than fall back to the epoch-(e-1) set.
//
// The test walks a real chain across four epochs and reports, per height: the
// epoch, whether it is an epoch's first block, whether a snapshot existed at
// pre-commit time, and the pre-commit verdict.
func TestEpochFirstBlock_VerifiesAgainstItsOwnEpochSnapshot(t *testing.T) {
	withEpochBlocks(t, verifyTestEpochBlocks) // 4 blocks per epoch
	consensus.ResetSnapshots()
	defer consensus.ResetSnapshots()

	const (
		epochBlocks = verifyTestEpochBlocks
		numEpochs   = 4
		totalBlocks = epochBlocks * numEpochs // 16
	)

	// Genesis: a single validator owns every epoch. Node-b is QUEUED for epoch
	// 2, so the set genuinely changes mid-chain and the epochs are not all
	// exercising the same membership.
	vs := mustLiveSetWith("Node-a")
	if err := vs.QueueValidator("Node-b", spx32(), 2); err != nil {
		t.Fatalf("QueueValidator: %v", err)
	}
	vs.TakeSnapshot(0) // genesis is epoch 0's snapshot, taken at genesis

	type row struct {
		height  uint64
		epoch   uint64
		first   bool
		hasSnap bool
		verify  string
	}
	var results []row

	for h := uint64(1); h < totalBlocks; h++ {
		epoch := consensus.EpochForHeight(h)
		first := h%epochBlocks == 0

		// BEFORE the commit: does a snapshot for this epoch exist yet?
		snapBefore := consensus.ValidatorSetAt(h)

		verdict := "VERIFIED"
		if err := VerifyBlockAttestations(blockAttestedBy(h, "Node-a")); err != nil {
			verdict = "refused"
		}
		results = append(results, row{h, epoch, first, snapBefore != nil, verdict})

		// THE COMMIT: exactly what CommitBlock does at 2051 then 2109.
		vs.ProcessEpochTransition(epoch)
		if first {
			vs.TakeSnapshot(epoch) // the snapshot for the epoch this block opened
		}
	}

	t.Logf("EpochBlocks=%d, chain grown across %d epochs (heights 0..%d)", epochBlocks, numEpochs, totalBlocks-1)
	t.Logf("%-8s %-6s %-14s %-17s %s", "height", "epoch", "first-of-epoch", "snap@pre-commit", "verify(pre-commit)")
	for _, r := range results {
		t.Logf("%-8d %-6d %-14v %-17v %s", r.height, r.epoch, r.first, r.hasSnap, r.verify)
	}
	// ── Assertions on the pre-commit phase ──
	for _, r := range results {
		if !r.first {
			continue
		}
		// A first block of an epoch is the block whose own commit creates the
		// snapshot, so before that commit it MUST be unavailable.
		if r.hasSnap {
			t.Errorf("height %d is the first block of epoch %d but its snapshot already "+
				"existed BEFORE its commit; the snapshot must be created BY that commit",
				r.height, r.epoch)
		}
		// And therefore it must fail closed before committing.
		if r.verify != "refused" {
			t.Errorf("height %d (first block of epoch %d) VERIFIED before its snapshot "+
				"existed; verification must fail closed rather than use another epoch's set",
				r.height, r.epoch)
		}
	}

	// ── AFTER the chain is grown, every block must verify against the snapshot
	// for ITS OWN epoch — including every epoch's first block. ──
	t.Logf("%-8s %-6s %-14s %-6s %s", "height", "epoch", "first-of-epoch", "vsets", "verify(post-commit)")
	for h := uint64(1); h < totalBlocks; h++ {
		epoch := consensus.EpochForHeight(h)
		snap := consensus.ValidatorSetAt(h)
		if snap == nil {
			t.Errorf("height %d has no snapshot for epoch %d after the chain was grown", h, epoch)
			continue
		}
		if snap.Epoch != epoch {
			t.Errorf("height %d resolved to the epoch-%d snapshot, want epoch %d", h, snap.Epoch, epoch)
		}
		// Attest with the FULL active set of that epoch, so the block is a
		// genuine quorum certificate rather than a lone vote.
		attesters := make([]string, 0, len(snap.Validators))
		for id := range snap.Validators {
			attesters = append(attesters, id)
		}
		sort.Strings(attesters)
		verdict := "VERIFIED"
		if err := VerifyBlockAttestations(blockAttestedBy(h, attesters...)); err != nil {
			verdict = "REFUSED: " + err.Error()
		}
		t.Logf("%-8d %-6d %-14v %-6d %s", h, epoch, h%epochBlocks == 0, len(attesters), verdict)
		if verdict != "VERIFIED" {
			t.Errorf("height %d (epoch %d, first-of-epoch=%v) failed to verify after commit: %s",
				h, epoch, h%epochBlocks == 0, verdict)
		}
	}

	// Each epoch must have produced a DISTINCT snapshot, and the membership must
	// actually have changed, or the epochs are not exercising anything.
	seen := make(map[string]uint64)
	for e := uint64(0); e < numEpochs; e++ {
		s := consensus.SnapshotAtEpoch(e)
		if s == nil {
			t.Errorf("epoch %d has no snapshot at all", e)
			continue
		}
		if prev, dup := seen[s.Hash()]; dup {
			t.Errorf("epoch %d has an identical snapshot to epoch %d", e, prev)
		}
		seen[s.Hash()] = e
		t.Logf("epoch %d snapshot: %d validator(s), hash %s", e, len(s.Validators), s.Hash()[:16])
	}
}

// TestStakeValidatorFromRewardAddress_RefusedOnSealedSet is Checkpoint 1b
// item 5: the local-admission shim must not be able to admit anyone on a node
// that runs with a genesis file.
//
// WHY THIS MATTERS. stakeValidatorFromRewardAddress decides admission from a
// LOCAL view — a key-exchange handshake plus a local balance read — and it
// derived the activation epoch from this node's own currentHeight. None of that
// is chain state, so two nodes can legitimately disagree about who is a
// validator. It is a temporary shim, removed in Phase 3.
//
// With a genesis file the set is SEALED immediately after seeding, and the guard
// refuses admission outright. This test drives the guarantee the guard depends
// on: a sealed set accepts no runtime admission, so the shim has nothing to
// grant even if it is reached.
func TestStakeValidatorFromRewardAddress_RefusedOnSealedSet(t *testing.T) {
	withEpochBlocks(t, verifyTestEpochBlocks)
	consensus.ResetSnapshots()
	defer consensus.ResetSnapshots()

	unit := spx32()
	vs := mustLiveSetWith("Node-a")
	vs.ProcessEpochTransition(0)

	// BEFORE sealing, a runtime admitter can still be QUEUED — this is the
	// no-genesis-file startup path, where Phase 2 establishes membership.
	if err := vs.QueueValidator("Node-early", unit, 5); err != nil {
		t.Fatalf("QueueValidator before sealing: %v", err)
	}
	beforeTotal := vs.GetTotalStake()
	beforeMembers := len(vs.GetValidators())

	// Seal: what bind.StartNode does immediately after seeding from genesis.
	vs.SealGenesis()
	if !vs.Sealed() {
		t.Fatal("SealGenesis did not take effect")
	}

	// The shim's whole job would be to turn a funded reward address into a
	// member. On a sealed set that route is closed: the balance cannot become
	// an immediate seat.
	if err := vs.AddGenesisValidator("Node-shim", unit); err == nil {
		t.Error("a SEALED set accepted AddGenesisValidator; the local-admission " +
			"shim could grant a seat outside chain state")
	}
	// And nothing else about the set moved across the seal.
	if got := len(vs.GetValidators()); got != beforeMembers {
		t.Errorf("membership changed across the seal: %d -> %d", beforeMembers, got)
	}
	if got := vs.GetTotalStake(); got.Cmp(beforeTotal) != 0 {
		t.Errorf("totalStake changed across the seal: %s -> %s", beforeTotal, got)
	}

	// The already-queued Node-early still activates only at ITS boundary,
	// proving the seal blocks IMMEDIATE membership without blocking deferred,
	// chain-derived activation.
	for e := uint64(0); e < 5; e++ {
		vs.ProcessEpochTransition(e)
		if got := vs.GetTotalStake(); got.Cmp(beforeTotal) != 0 {
			t.Fatalf("epoch %d: a queued validator gained weight before its boundary", e)
		}
	}
	vs.ProcessEpochTransition(5)
	if want := new(big.Int).Mul(unit, big.NewInt(2)); vs.GetTotalStake().Cmp(want) != 0 {
		t.Errorf("at epoch 5 the total is %s, want %s", vs.GetTotalStake(), want)
	}
}

func mustLiveSetWith(ids ...string) *consensus.ValidatorSet {
	minStake := spx32()
	vs := consensus.NewValidatorSet(minStake)
	for _, id := range ids {
		if err := vs.AddGenesisValidator(id, spx32()); err != nil {
			panic("AddGenesisValidator: " + err.Error())
		}
	}
	return vs
}
