// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/sync_apply_safety_test.go
//
// Safety of the SYNC path specifically. A block that arrives from a peer during
// catch-up is untrusted input: any peer can serve whatever it likes. These
// tests assert that the verification the sync loop performs —
// core.VerifyBlockAuthority, the same call the consensus commit path relies on
// — refuses a block that consensus would also refuse, so applying a peer-served
// block cannot grant a weaker standard than proposing one.
package bind

import (
	"testing"

	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/core"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// newFourValidatorSyncFixture builds four real SPHINCS+ validators and the
// epoch-0 snapshot that governs height 1, matching a real 4-node localnet.
func newFourValidatorSyncFixture(t *testing.T) []*harnessValidator {
	t.Helper()
	prev := consensus.EpochBlocksOverride()
	consensus.SetEpochBlocks(harnessEpochBlocks)
	t.Cleanup(func() { consensus.RestoreEpochBlocks(prev) })

	consensus.ResetSnapshots()
	t.Cleanup(consensus.ResetSnapshots)

	vals := make([]*harnessValidator, 0, 4)
	for i := 0; i < 4; i++ {
		vals = append(vals, newHarnessValidator(t, harnessNodeID(i)))
	}
	snap, _ := buildSnapshotFor(vals)
	consensus.StoreSnapshotForTest(*snap)
	return vals
}

// attest returns signed attestations from the first k validators.
func attest(t *testing.T, vals []*harnessValidator, height uint64, k int) []*types.Attestation {
	t.Helper()
	out := make([]*types.Attestation, 0, k)
	for i := 0; i < k; i++ {
		out = append(out, vals[i].signBlockAttestation(t, height))
	}
	return out
}

// TestSyncApply_QuorumCertificateIsEnforced is the core safety assertion: a
// peer-served block carrying a real but UNDER-quorum certificate is refused,
// exactly as it would be if this node had proposed it.
func TestSyncApply_QuorumCertificateIsEnforced(t *testing.T) {
	vals := newFourValidatorSyncFixture(t)
	need := consensus.StrictTwoThirdsCount(4)

	t.Run("quorum verifies", func(t *testing.T) {
		blk := harnessBlock(1, attest(t, vals, 1, need))
		if err := core.VerifyBlockAttestations(blk, harnessKeyResolver(vals), harnessVerifyFn(vals)); err != nil {
			t.Fatalf("a peer-served block with a real %d-of-4 certificate must verify: %v", need, err)
		}
	})

	t.Run("under-quorum refused", func(t *testing.T) {
		blk := harnessBlock(1, attest(t, vals, 1, need-1))
		if err := core.VerifyBlockAttestations(blk, harnessKeyResolver(vals), harnessVerifyFn(vals)); err == nil {
			t.Fatalf("a peer-served block with only %d of 4 attestations was ACCEPTED; "+
				"sync must apply no weaker a standard than consensus", need-1)
		}
	})

	t.Run("zero attestations refused", func(t *testing.T) {
		blk := harnessBlock(1, nil)
		if err := core.VerifyBlockAttestations(blk, harnessKeyResolver(vals), harnessVerifyFn(vals)); err == nil {
			t.Fatal("a peer-served block with no attestations was ACCEPTED")
		}
	})
}

// TestSyncApply_ForgedAndAlienSignaturesRefused covers a peer that does not
// merely under-sign but actively forges.
func TestSyncApply_ForgedAndAlienSignaturesRefused(t *testing.T) {
	vals := newFourValidatorSyncFixture(t)
	need := consensus.StrictTwoThirdsCount(4)

	t.Run("all attestations from one signer", func(t *testing.T) {
		// A single validator's signature copied across several validator IDs:
		// the vote count looks like quorum but no other key ever signed.
		one := vals[0].signBlockAttestation(t, 1)
		forged := make([]*types.Attestation, 0, need)
		for i := 0; i < need; i++ {
			forged = append(forged, &types.Attestation{
				ValidatorID: vals[i].id,
				Signature:   one.Signature,
				Height:      1,
				View:        1,
			})
		}
		blk := harnessBlock(1, forged)
		if err := core.VerifyBlockAttestations(blk, harnessKeyResolver(vals), harnessVerifyFn(vals)); err == nil {
			t.Fatal("a block whose attestations are all one validator's signature was ACCEPTED")
		}
	})

	t.Run("garbage signature", func(t *testing.T) {
		bad := make([]*types.Attestation, 0, need)
		for i := 0; i < need; i++ {
			bad = append(bad, &types.Attestation{
				ValidatorID: vals[i].id,
				Signature:   []byte("not-a-signature"),
				Height:      1,
				View:        1,
			})
		}
		if err := core.VerifyBlockAttestations(harnessBlock(1, bad), harnessKeyResolver(vals), harnessVerifyFn(vals)); err == nil {
			t.Fatal("a block with malformed signatures was ACCEPTED")
		}
	})

	t.Run("non-member signer", func(t *testing.T) {
		// A real signature from a key that is not in the epoch-0 snapshot.
		outsider := newHarnessValidator(t, "Node-outsider")
		att := outsider.signBlockAttestation(t, 1)
		if err := core.VerifyBlockAttestations(harnessBlock(1, []*types.Attestation{att}),
			harnessKeyResolver(vals), harnessVerifyFn(vals)); err == nil {
			t.Fatal("a block attested by a non-member was ACCEPTED")
		}
	})
}

// TestSyncApply_AuthorityRefusesUnattestedMultiValidatorBlock pins the branch
// a forked peer would most plausibly take: omit the certificate entirely and
// hope the "no attestations" path is treated as permission.
func TestSyncApply_AuthorityRefusesUnattestedMultiValidatorBlock(t *testing.T) {
	vals := newFourValidatorSyncFixture(t)
	err := core.VerifyBlockAuthority(harnessBlock(1, nil),
		harnessKeyResolver(vals), harnessVerifyFn(vals), nil)
	if err == nil {
		t.Fatal("an unattested block was ACCEPTED on a 4-validator snapshot; " +
			"the single-validator exemption must not extend to a real set")
	}
}
