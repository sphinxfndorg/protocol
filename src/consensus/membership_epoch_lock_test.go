// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/consensus/membership_epoch_lock_test.go
//
// Regression tests for a SELF-DEADLOCK that froze every late-joining node at
// height 0.
//
// `sync.RWMutex` is not reentrant. `membershipEpoch()` takes `c.mu.RLock()`,
// but its callers inside updateLeaderStatusLocked / processProposal /
// processTimeout already hold `c.mu.Lock()`. RLock cannot proceed while a writer
// holds the same mutex, and the writer cannot release until the RLock returns,
// so the first such call wedged the engine permanently:
//
//	runBlockSyncLoop -> ResetRANDAO -> UpdateLeaderStatus
//	  -> updateLeaderStatus [c.mu.Lock] -> membershipEpoch [c.mu.RLock] DEADLOCK
//
// It reproduced only on nodes that SYNC genesis, which is why every
// genesis-authoring test passed while every joiner hung. These tests call the
// previously-deadlocking paths directly and require them to RETURN.
package consensus

import (
	"math/big"
	"testing"
	"time"
)

// emptyNodeManager is a NodeManager with no peers. updateLeaderStatus's
// round-robin fallback reads it via getValidators(); the deadlock being pinned
// is about lock ordering, not about peer membership, so an empty manager is
// sufficient — and keeps the test free of any network dependency.
type emptyNodeManager struct{}

func (emptyNodeManager) GetPeers() map[string]Peer                  { return nil }
func (emptyNodeManager) GetNode(string) Node                        { return nil }
func (emptyNodeManager) BroadcastMessage(string, interface{}) error { return nil }
func (emptyNodeManager) BroadcastRANDAOState([32]byte, map[uint64]map[string]*VDFSubmission) error {
	return nil
}

// lockTestEngine builds a real engine with canonical VDF parameters so the
// height- and leader-selection paths are live.
func lockTestEngine(t *testing.T) *Consensus {
	t.Helper()
	// -(2^255 - 1) is a valid class-group discriminant: negative, and
	// = 1 mod 4 because 2^255 - 1 = 3 (mod 4).
	disc := new(big.Int).Neg(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1)))
	if err := SetCanonicalVDFParameters(&VDFParams{Discriminant: disc, T: 100, Lambda: 128}); err != nil {
		t.Fatalf("SetCanonicalVDFParameters: %v", err)
	}
	ResetSnapshots()
	t.Cleanup(ResetSnapshots)

	eng := &Consensus{
		nodeID:               "Node-a",
		nodeManager:          emptyNodeManager{},
		useStakeWeighted:     true,
		validatorSet:         NewValidatorSet(engineUnit()),
		currentHeight:        7,
		phase:                PhasePrePrepared,
		receivedVotes:        make(map[string]map[string]*Vote),
		prepareVotes:         make(map[string]map[string]*Vote),
		weightedCommitVotes:  make(map[string]*big.Int),
		weightedPrepareVotes: make(map[string]*big.Int),
	}
	if err := eng.validatorSet.AddGenesisValidator("Node-a", engineUnit()); err != nil {
		t.Fatalf("AddGenesisValidator: %v", err)
	}
	eng.validatorSet.ProcessEpochTransition(0)
	eng.validatorSet.SealGenesis()
	snap := eng.validatorSet.TakeSnapshot(0)
	StoreSnapshotForTest(*snap)
	eng.selector = NewStakeWeightedSelector(eng.validatorSet)
	// updateLeaderStatusLocked derives its RANDAO seed from c.randao.
	var seed [32]byte
	eng.randao = NewRANDAO(seed, VDFParams{Discriminant: disc, T: 100, Lambda: 128}, "Node-a")
	return eng
}

// TestUpdateLeaderStatus_DoesNotDeadlockOnItsOwnMutex is the direct regression.
//
// Before the fix this HANGS FOREVER rather than failing, so the call runs on a
// goroutine under a timeout.
func TestUpdateLeaderStatus_DoesNotDeadlockOnItsOwnMutex(t *testing.T) {
	eng := lockTestEngine(t)
	done := make(chan struct{})
	go func() {
		eng.UpdateLeaderStatus() // -> updateLeaderStatusLocked -> membershipEpochLocked
		close(done)
	}()
	select {
	case <-done:
		// Returning is the entire point.
	case <-time.After(20 * time.Second):
		t.Fatal("★ UpdateLeaderStatus deadlocked on c.mu: it holds the write lock and " +
			"membershipEpoch() tried to take a read lock on the same non-reentrant RWMutex")
	}
}

// TestProcessProposal_DoesNotDeadlockOnItsOwnMutex covers the second held-lock
// caller: processProposal defers Unlock, so both membershipEpoch() calls inside
// it ran with c.mu held.
func TestProcessProposal_DoesNotDeadlockOnItsOwnMutex(t *testing.T) {
	eng := lockTestEngine(t)
	done := make(chan struct{})
	go func() {
		// A minimal proposal. processProposal must RETURN, whatever it decides.
		eng.processProposal(&Proposal{View: 0, ProposerID: "Node-a", ElectedLeaderID: "Node-a"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("★ processProposal deadlocked on c.mu via membershipEpoch()")
	}
}

// TestProcessTimeout_DoesNotDeadlockOnItsOwnMutex covers the third.
func TestProcessTimeout_DoesNotDeadlockOnItsOwnMutex(t *testing.T) {
	eng := lockTestEngine(t)
	done := make(chan struct{})
	go func() {
		eng.processTimeout(&TimeoutMsg{View: 0, VoterID: "Node-a"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("★ processTimeout deadlocked on c.mu via membershipEpoch()")
	}
}

// TestMembershipEpochVariantsAgree keeps the locked and unlocked variants in
// lockstep. They must differ ONLY in locking; if they diverge, one is deriving
// membership from a different rule than the other.
func TestMembershipEpochVariantsAgree(t *testing.T) {
	eng := lockTestEngine(t)
	for _, h := range []uint64{0, 1, 7, 9, 10, 11, 40, 41} {
		eng.mu.Lock()
		eng.currentHeight = h
		locked := eng.membershipEpochLocked()
		eng.mu.Unlock()

		got := eng.membershipEpoch()
		if locked != got {
			t.Errorf("height %d: membershipEpochLocked()=%d but membershipEpoch()=%d; "+
				"they must be the same rule", h, locked, got)
		}
		if want := EpochForHeight(h); got != want {
			t.Errorf("height %d: membershipEpoch()=%d, want EpochForHeight=%d", h, got, want)
		}
	}
}
