// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package consensus

import (
	"math/big"
	"sync/atomic"
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

// TestProposeBlock_DoesNotSelfDeadlockOnProcessProposal is the regression test
// for a SECOND, previously unfixed instance of the same re-lock pattern, on the
// leader proposal path rather than the vote-counting paths.
//
// ProposeBlock takes c.mu.Lock() (with a deferred unlock) to evaluate its
// guards, then calls c.processProposal(proposal). processProposal takes
// c.mu.Lock() on its own first line, and sync.RWMutex is not reentrant, so the
// leader goroutine blocked on itself forever.
//
// Unlike the snapshotForVoting wedge, this one never showed up in a localnet
// run: localnet leaders go through bind.runBlockProductionLoop, which calls
// HandleProposal/BroadcastProposal directly (src/bind/helpers.go). The only
// production caller of ProposeBlock is core.Blockchain's leader loop
// (src/core/blockchain.go), so the path was latent, not dead.
//
// The fix releases c.mu immediately before the processProposal call while
// keeping every guard under the lock.
func TestProposeBlock_DoesNotSelfDeadlockOnProcessProposal(t *testing.T) {
	c := &Consensus{
		nodeID:      "Node-127.0.0.1:30303",
		nodeManager: selfValidatorNodeManager{nodeID: "Node-127.0.0.1:30303"},
	}
	// Pass the sync gate and be the sole validator, so updateLeaderStatusRoundRobin
	// elects this node leader and ProposeBlock actually reaches processProposal
	// rather than returning early at a guard.
	atomic.StoreInt32(&c.syncReady, 1)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// processProposal needs a real blockChain, key manager and signing
		// service, none of which exist on a bare Consensus, so it panics a few
		// lines in. That is irrelevant here and is recovered: this test is
		// about LOCKING, and it only needs to prove the call gets past the
		// processProposal call site instead of wedging on c.mu. Whether the
		// proposal is then accepted is processProposal's business, tested
		// elsewhere. What must NOT happen is a hang.
		defer func() { _ = recover() }()
		_ = c.ProposeBlock(stubBlock{})
	}()

	select {
	case <-done:
	case <-time.After(deadlockGuardTimeout):
		t.Fatalf("ProposeBlock blocked for %s: it holds c.mu and calls processProposal, "+
			"which takes c.mu itself, and sync.RWMutex is not reentrant",
			deadlockGuardTimeout)
	}

	// The early-release path must not leave the mutex locked, and must not
	// double-unlock it (which would panic on any later Lock/Unlock pair).
	acquired := make(chan struct{})
	go func() {
		c.mu.Lock()
		c.mu.Unlock()
		close(acquired)
	}()
	select {
	case <-acquired:
	case <-time.After(deadlockGuardTimeout):
		t.Fatalf("c.mu was still held after ProposeBlock returned; the guard read lock is never released")
	}
}

// selfValidatorNodeManager reports the node itself as an active validator and
// no peers, which makes getValidators return exactly [nodeID].
type selfValidatorNodeManager struct{ nodeID string }

func (m selfValidatorNodeManager) GetPeers() map[string]Peer { return map[string]Peer{} }
func (m selfValidatorNodeManager) GetNode(id string) Node {
	if id != m.nodeID {
		return nil
	}
	return selfValidatorNode{id: id}
}
func (m selfValidatorNodeManager) BroadcastMessage(string, interface{}) error { return nil }
func (m selfValidatorNodeManager) BroadcastRANDAOState([32]byte, map[uint64]map[string]*VDFSubmission) error {
	return nil
}

type selfValidatorNode struct{ id string }

func (n selfValidatorNode) GetID() string         { return n.id }
func (n selfValidatorNode) GetRole() NodeRole     { return RoleValidator }
func (n selfValidatorNode) GetStatus() NodeStatus { return NodeStatusActive }

// stubBlock is the minimum Block needed to get ProposeBlock past its type
// assertion. processProposal rejects it on validation; that is fine, the test
// only asserts the call returns.
type stubBlock struct{}

func (stubBlock) GetHeight() uint64                { return 1 }
func (stubBlock) GetHash() string                  { return "aa11" }
func (stubBlock) GetPrevHash() string              { return "" }
func (stubBlock) GetParentHash() string            { return "" }
func (stubBlock) GetTimestamp() int64              { return 0 }
func (stubBlock) Validate() error                  { return nil }
func (stubBlock) GetDifficulty() *big.Int          { return big.NewInt(0) }
func (stubBlock) GetCurrentNonce() (uint64, error) { return 0, nil }
func (stubBlock) GetUnderlyingBlock() interface{}  { return nil }
func (stubBlock) SetCommitStatus(string)           {}
func (stubBlock) SetSigValid(bool)                 {}
func (stubBlock) GetCommitStatus() string          { return "" }
func (stubBlock) GetSigValid() bool                { return false }
func (stubBlock) GetTxsRoot() []byte               { return nil }
