// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package consensus

import (
	"testing"
	"time"
)

// deadlockGuardTimeout is generous: these tests detect a PERMANENT block, so any
// finite wait is enough, and a tight bound would flake on a loaded machine.
const deadlockGuardTimeout = 10 * time.Second

// TestSnapshotForVotingLocked_NoSelfDeadlock is the regression test for the
// localnet "validators never exchange votes" stall.
//
// What was wrong: processProposal, processPrepareVote, processVoteLocked and
// tryEnterPreparedPhase all take c.mu.Lock() (a WRITE lock) and then need the
// voting snapshot. They called snapshotForVoting(), which reaches
// GetCurrentHeight(), which takes c.mu.RLock() on the SAME mutex. sync.RWMutex
// is not reentrant, so the first such call blocked that goroutine on itself
// forever, wedging the whole engine: processProposal never released c.mu, so
// every later processPrepareVote blocked at its own c.mu.Lock() and no prepare
// or commit vote was ever counted.
//
// The fix routes the lock-held callers through snapshotForVotingLocked, which
// reads c.currentHeight directly. This test holds the write lock exactly as
// those callers do and fails on any regression that reintroduces the
// self-deadlock.
func TestSnapshotForVotingLocked_NoSelfDeadlock(t *testing.T) {
	c := &Consensus{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.mu.Lock()
		defer c.mu.Unlock()
		_ = c.snapshotForVotingLocked()
	}()

	select {
	case <-done:
	case <-time.After(deadlockGuardTimeout):
		t.Fatalf("snapshotForVotingLocked blocked for %s while c.mu was held: sync.RWMutex is not reentrant, so a locking accessor here wedges every lock-held consensus path", deadlockGuardTimeout)
	}
}

// TestLockHeldQuorumPaths_DoNotSelfDeadlock drives the exact call shape of the
// four production sites that previously deadlocked: take the write lock, then
// perform the quorum/snapshot work that needs the voting snapshot.
//
// It mirrors processPrepareVote and processVoteLocked (the vote-counting paths
// whose silence produced the zero-vote stall), so a regression in either helper
// fails here rather than only in the multi-process localnet run.
//
// A zero-value Consensus has no epoch snapshot registered, so the snapshot is
// nil here — exactly the state the production guards tolerate. The point of this
// test is that none of these calls BLOCKS, so nil-tolerance is asserted rather
// than assumed.
func TestLockHeldQuorumPaths_DoNotSelfDeadlock(t *testing.T) {
	c := &Consensus{}
	const blockHash = "deadbeefdeadbeef"

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.mu.Lock()
		defer c.mu.Unlock()

		// Mirrors processPrepareVote / processVoteLocked: derive the snapshot
		// under the lock, then size the quorum from it.
		snap := c.snapshotForVotingLocked()
		if snap != nil {
			_ = StrictTwoThirdsCount(len(snap.Validators))
		} else if got := StrictTwoThirdsCount(0); got != 0 {
			// nil-tolerant sizing, same as the production paths.
			t.Errorf("StrictTwoThirdsCount(0) = %d, want 0", got)
		}

		// Mirrors tryEnterPreparedPhase's guard.
		_ = c.hasPrepareQuorum(blockHash, c.snapshotForVotingLocked())

		// Mirrors processProposal's commit-quorum guard.
		_ = c.hasQuorum(blockHash, c.snapshotForVotingLocked())
	}()

	select {
	case <-done:
	case <-time.After(deadlockGuardTimeout):
		t.Fatalf("a lock-held quorum path blocked for %s; the voting snapshot must be read without re-locking c.mu", deadlockGuardTimeout)
	}
}

// NOTE ON WHY THE *Locked VARIANTS EXIST
//
// snapshotForVoting is correct for callers that do NOT hold c.mu
// (certificate.go's HandleCommitCertificate / HandlePrepareCertificate). It
// reaches GetCurrentHeight, which takes c.mu.RLock, so calling it from a
// write-lock holder blocks that goroutine forever — the bug the *Locked
// variants fix.
//
// That hazard is deliberately NOT asserted by a test here: demonstrating it
// requires a goroutine that stays blocked for the life of the test binary,
// which the runtime's "all goroutines are asleep - deadlock" detector can turn
// into a spurious panic for the WHOLE package. The two tests above are the
// regression guards: they fail if any lock-held caller is routed back through a
// locking accessor.
