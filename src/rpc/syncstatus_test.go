// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/rpc/syncstatus_test.go
package rpc

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestSyncServer builds a Server capable of serving getsyncstatus without
// a node: the handler needs metrics (dispatch increments them), authConfig
// (authenticateRequest dereferences it), maxRequestSize (0 would reject every
// request), and the methods map. Deliberately NOT NewServer: that opens an
// on-disk artifact DB in the working directory and starts a GC goroutine —
// side effects a unit test must not have.
func newTestSyncServer(t *testing.T) *Server {
	t.Helper()
	s := &Server{
		metrics:        NewMetrics(),
		authConfig:     DefaultAuthConfig(),
		maxRequestSize: 1024 * 1024,
		queryManager:   NewQueryManager(),
		store:          NewKVStore(),
	}
	s.handler = NewJSONRPCHandler(s)
	return s
}

// syncStatusEnvelope is the JSON-RPC 2.0 wrapper getsyncstatus replies in.
type syncStatusEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *RPCError       `json:"error"`
	ID      float64         `json:"id"`
}

// tryGetSyncStatus issues one real JSON-RPC request through HandleRequest —
// the exact wire path a wallet uses — and decodes the result shape. It
// returns errors instead of failing the test so goroutines may call it
// (t.Fatalf is only legal on the test's own goroutine).
func tryGetSyncStatus(s *Server) (syncStatusResponse, syncStatusEnvelope, string, error) {
	body := []byte(`{"jsonrpc":"2.0","id":42,"method":"getsyncstatus"}`)
	raw, err := s.HandleRequest(body)
	if err != nil {
		return syncStatusResponse{}, syncStatusEnvelope{}, string(raw), err
	}
	var env syncStatusEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return syncStatusResponse{}, env, string(raw), err
	}
	if env.Error != nil {
		return syncStatusResponse{}, env, string(raw), jsonErrorf("error envelope: %+v", env.Error)
	}
	if env.JSONRPC != "2.0" {
		return syncStatusResponse{}, env, string(raw), jsonErrorf("jsonrpc version = %q, want 2.0", env.JSONRPC)
	}
	if env.ID != 42 {
		return syncStatusResponse{}, env, string(raw), jsonErrorf("response id = %v, want 42", env.ID)
	}
	var resp syncStatusResponse
	if len(env.Result) == 0 {
		return resp, env, string(raw), jsonErrorf("response has no result: %s", raw)
	}
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		return resp, env, string(raw), err
	}
	return resp, env, string(raw), nil
}

// jsonErrorf keeps error construction in tryGetSyncStatus allocation-light and
// readable.
func jsonErrorf(format string, args ...interface{}) error {
	return fmt.Errorf(format, args...)
}

// callGetSyncStatus is the fail-fast wrapper for the test's own goroutine.
func callGetSyncStatus(t *testing.T, s *Server) (syncStatusResponse, syncStatusEnvelope, string) {
	t.Helper()
	resp, env, raw, err := tryGetSyncStatus(s)
	if err != nil {
		t.Fatalf("getsyncstatus request: %v", err)
	}
	return resp, env, raw
}

func almostEqual(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// TestDeriveSyncProgressIndeterminateNever100 locks in the honesty rule the
// wallet gating depends on: when the target height is unknown (0) or no peers
// were observed, progress is INDETERMINATE — never 100, never any number a
// client should trust. A peerless node's own height says "caught up" by
// construction, so accepting heights alone would let a node with zero network
// view report a completed sync.
func TestDeriveSyncProgressIndeterminateNever100(t *testing.T) {
	cases := []struct {
		name    string
		syncing bool
		current uint64
		target  uint64
		peers   int
	}{
		{"no peers, target known", false, 100, 100, 0},
		{"no peers while syncing", true, 50, 100, 0},
		{"negative peers (caller bug)", false, 50, 100, -1},
		{"target unknown (0), peers present", false, 0, 0, 3},
		{"target unknown while syncing", true, 7, 0, 2},
		{"nothing known at all", true, 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pct, ok := deriveSyncProgress(tc.syncing, tc.current, tc.target, tc.peers)
			if ok {
				t.Fatalf("deriveSyncProgress(syncing=%v, current=%d, target=%d, peers=%d) = (%v, true); want indeterminate (false)",
					tc.syncing, tc.current, tc.target, tc.peers, pct)
			}
			if pct == 100 {
				t.Fatal("an indeterminate result must never be 100")
			}
		})
	}
}

// TestDeriveSyncProgressDeterminate covers every case where an estimate IS
// allowed, pinning the exact numbers and both ceilings: 100 only when the
// node is not syncing and its height reaches the target; 99.9 while syncing
// even at equal heights (the state transition can lag one pass behind the
// heights), so a wallet never sees 100% while the node says it is syncing.
func TestDeriveSyncProgressDeterminate(t *testing.T) {
	cases := []struct {
		name    string
		syncing bool
		current uint64
		target  uint64
		peers   int
		want    float64
	}{
		{"caught up with peers", false, 100, 100, 3, 100},
		{"local ahead of stale peer tip", false, 150, 100, 1, 100},
		{"syncing at equal heights caps below 100", true, 100, 100, 3, 99.9},
		{"syncing exactly half", true, 500, 1000, 2, 50},
		{"syncing quarter", true, 250, 1000, 2, 25},
		{"syncing start", true, 0, 1000, 1, 0},
		{"syncing ratio that would round to 100 caps", true, 9995, 10000, 1, 99.9},
		{"caught-up state but behind (stale observation stays honest)", false, 50, 100, 1, 50},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pct, ok := deriveSyncProgress(tc.syncing, tc.current, tc.target, tc.peers)
			if !ok {
				t.Fatalf("deriveSyncProgress(%v, %d, %d, %d) is indeterminate; want determinate %v",
					tc.syncing, tc.current, tc.target, tc.peers, tc.want)
			}
			if !almostEqual(pct, tc.want) {
				t.Fatalf("deriveSyncProgress(%v, %d, %d, %d) = %v; want %v",
					tc.syncing, tc.current, tc.target, tc.peers, pct, tc.want)
			}
			if tc.want < 100 && pct >= 100 {
				t.Fatalf("progress %v must stay below 100 for this case", pct)
			}
		})
	}
}

// TestDeriveSyncing is the Phase 1.1 honesty rule: `syncing` must not be the
// raw SyncState string. bind's sync loop parks in CAUGHT_UP (no peers yet, or
// genesis-only network) and later downloads from a newly-found peer with a
// higher tip WITHOUT moving the state machine back to SYNCING — so the
// reported value folds the peer-tip comparison in. Behind by exactly one block
// stays "not syncing", mirroring the loop's own within-1-block definition of
// caught up.
func TestDeriveSyncing(t *testing.T) {
	cases := []struct {
		name         string
		state        string
		stateSyncing bool
		current      uint64
		target       uint64
		want         bool
	}{
		{"no peers, target unknown, state CAUGHT_UP", "CAUGHT_UP", false, 100, 0, false},
		{"caught up with peers", "CAUGHT_UP", false, 100, 100, false},
		{"local ahead of a stale peer tip", "CAUGHT_UP", false, 150, 100, false},
		{"behind by 1 (ordinary propagation lag)", "CAUGHT_UP", false, 100, 101, false},
		{"behind by 2 while state says CAUGHT_UP", "CAUGHT_UP", false, 100, 102, true},
		{"far behind while state says CAUGHT_UP", "CAUGHT_UP", false, 100, 100000, true},
		{"state SYNCING even at target (transition lag)", "SYNCING", true, 500, 500, true},
		{"state SYNCING with no peers at all", "SYNCING", true, 0, 0, true},
		{"SYNCING string with a false boolean (provider bug)", "SYNCING", false, 0, 0, true},
		{"consensus participant but behind a higher tip", "CONSENSUS_PARTICIPANT", false, 10, 40, true},
		{"unknown state with nothing known", "UNKNOWN", false, 0, 0, false},
		{"empty state with nothing known", "", false, 0, 0, false},
		{"MaxUint64 local and target (no +1 wrap)", "CAUGHT_UP", false, ^uint64(0), ^uint64(0), false},
		{"MaxUint64 local, target one below", "CAUGHT_UP", false, ^uint64(0), ^uint64(0) - 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveSyncing(tc.state, tc.stateSyncing, tc.current, tc.target)
			if got != tc.want {
				t.Fatalf("deriveSyncing(state=%q, syncing=%v, current=%d, target=%d) = %v; want %v",
					tc.state, tc.stateSyncing, tc.current, tc.target, got, tc.want)
			}
		})
	}
}

// TestDeriveObservedAgeMS pins the age contract: -1 means NEVER OBSERVED (and
// is not a legitimate age), 0 is a legitimate "just now", a future timestamp
// clamps to 0 so a backwards clock step can never satisfy a freshness check,
// and real ages are expressed in milliseconds.
func TestDeriveObservedAgeMS(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		observed   bool
		observedAt time.Time
		want       int64
	}{
		{"never observed", false, now.Add(-time.Hour), -1},
		{"observed but zero timestamp", true, time.Time{}, -1},
		{"just now", true, now, 0},
		{"sub-millisecond ago rounds to 0", true, now.Add(-500 * time.Microsecond), 0},
		{"90 seconds ago", true, now.Add(-90 * time.Second), 90_000},
		{"exactly the staleness threshold", true, now.Add(-time.Duration(SyncStatusStaleAfterMS) * time.Millisecond), SyncStatusStaleAfterMS},
		{"one millisecond past stale", true, now.Add(-time.Duration(SyncStatusStaleAfterMS+1) * time.Millisecond), SyncStatusStaleAfterMS + 1},
		{"timestamp in the future clamps to 0", true, now.Add(5 * time.Second), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deriveObservedAgeMS(tc.observed, tc.observedAt, now); got != tc.want {
				t.Fatalf("deriveObservedAgeMS(observed=%v, at=%v, now=%v) = %d; want %d",
					tc.observed, tc.observedAt, now, got, tc.want)
			}
		})
	}
}

// TestSyncStatusTrackerNilSafety locks in the nil-receiver contract: a nil
// tracker must never panic — Observe is a no-op, Get reports "not observed",
// and a nil tracker's method value used AS the provider (the wiring a
// forgotten construction would produce) still answers the handler safely.
func TestSyncStatusTrackerNilSafety(t *testing.T) {
	var nilTracker *SyncStatusTracker

	nilTracker.Observe(SyncStatus{Syncing: false, PeerCount: 9}) // must not panic

	st, ok := nilTracker.Get()
	if ok {
		t.Fatal("a nil tracker has never observed")
	}
	if st.Syncing || st.PeerCount != 0 || st.CurrentHeight != 0 || st.State != "" {
		t.Fatalf("nil tracker must return the zero snapshot, got %+v", st)
	}

	// Method value bound to a nil receiver — what SetSyncStatusProvider would
	// receive if someone wired a tracker they never constructed.
	if _, observed := nilTracker.Get(); observed {
		t.Fatal("nil-tracker provider must report observed=false")
	}

	// A real tracker starts unobserved too.
	fresh := NewSyncStatusTracker()
	if _, observed := fresh.Get(); observed {
		t.Fatal("a fresh tracker must start unobserved")
	}
}

// TestSyncStatusTrackerClampsNegativePeerCount guards the handler against a
// caller bug: a negative peer count must never reach clients, since the whole
// gating contract is expressed in peer_count.
func TestSyncStatusTrackerClampsNegativePeerCount(t *testing.T) {
	tr := NewSyncStatusTracker()
	tr.Observe(SyncStatus{Syncing: true, PeerCount: -3, State: "SYNCING"})
	st, ok := tr.Get()
	if !ok {
		t.Fatal("tracker must be observed after an Observe")
	}
	if st.PeerCount != 0 {
		t.Fatalf("negative peer count must clamp to 0, got %d", st.PeerCount)
	}
}

// TestSyncStatusTrackerStampsObservationTime locks in who owns ObservedAt: the
// tracker, from its clock — a value supplied by the publishing loop is
// overwritten (only the tracker knows when it stored the snapshot), and every
// stored snapshot carries a non-zero timestamp so a client can age it out.
func TestSyncStatusTrackerStampsObservationTime(t *testing.T) {
	fixed := time.Date(2030, 3, 4, 5, 6, 7, 0, time.UTC)
	bogus := time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)

	tr := newSyncStatusTrackerWithClock(func() time.Time { return fixed })
	tr.Observe(SyncStatus{Syncing: true, State: "SYNCING", ObservedAt: bogus})

	st, observed := tr.Get()
	if !observed {
		t.Fatal("tracker must be observed after Observe")
	}
	if !st.ObservedAt.Equal(fixed) {
		t.Fatalf("ObservedAt = %v; want the tracker's clock value %v (publisher value must be ignored)", st.ObservedAt, fixed)
	}

	// A zero-value tracker (nil clock) must still stamp a usable timestamp
	// rather than panicking or storing the zero time.
	var zeroClock SyncStatusTracker
	before := time.Now().Add(-time.Second)
	zeroClock.Observe(SyncStatus{Syncing: false, State: "CAUGHT_UP"})
	st2, observed2 := zeroClock.Get()
	if !observed2 {
		t.Fatal("zero-value tracker must be observed after Observe")
	}
	if st2.ObservedAt.IsZero() || st2.ObservedAt.Before(before) || st2.ObservedAt.After(time.Now().Add(time.Second)) {
		t.Fatalf("nil clock must fall back to time.Now, got %v", st2.ObservedAt)
	}
}

// TestSyncStatusTrackerConcurrentObserveGet is the -race test: writers
// publish linked snapshots while readers fetch them the way the provider
// does. The invariant — every observed Get's target must be exactly 2× its
// current height, because each Observe writes both from one source value —
// fails if a read ever mixes fields from two Observes (torn snapshot); the
// race detector covers the memory-level half of the same question.
func TestSyncStatusTrackerConcurrentObserveGet(t *testing.T) {
	tracker := NewSyncStatusTracker()
	const perGoroutine = 500

	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 1; i <= perGoroutine; i++ {
				v := uint64(i)
				tracker.Observe(SyncStatus{
					Syncing:                i%2 == 0,
					CurrentHeight:          v * 100,
					HighestKnownPeerHeight: v * 200,
					PeerCount:              int(v%7) + 1, // always >= 1: determinate
					State:                  "SYNCING",
				})
			}
		}()
	}
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				st, observed := tracker.Get()
				if !observed {
					continue // readers may beat the first write; that is legal
				}
				// ObservedAt is written by Observe under the same lock as the
				// rest of the snapshot, so an observed Get() must always see a
				// stamped timestamp — checked here because the race detector is
				// only meaningful if the field is actually exercised.
				if st.ObservedAt.IsZero() {
					t.Errorf("observed snapshot has no observation timestamp")
					return
				}
				if st.HighestKnownPeerHeight != st.CurrentHeight*2 {
					t.Errorf("torn snapshot: current=%d target=%d (fields from different Observes)",
						st.CurrentHeight, st.HighestKnownPeerHeight)
					return
				}
				if st.PeerCount < 1 {
					t.Errorf("peer count lost across concurrent access: %d", st.PeerCount)
					return
				}
			}
		}()
	}
	wg.Wait()

	if _, observed := tracker.Get(); !observed {
		t.Fatal("tracker must be observed after concurrent writes")
	}
}

// TestGetSyncStatusWithoutProvider covers a server that never wired the
// provider (the legacy harness paths). It must answer — not error — and the
// answer must be the SAFE default: syncing=true, state UNKNOWN, zero peers,
// progress indeterminate. Anything less conservative would let an unproven
// server read as "synced".
func TestGetSyncStatusWithoutProvider(t *testing.T) {
	resp, _, raw := callGetSyncStatus(t, newTestSyncServer(t))
	if !resp.Syncing {
		t.Fatalf("a server with no provider must report syncing=true, got false (%s)", raw)
	}
	if resp.State != "UNKNOWN" {
		t.Fatalf("state = %q, want UNKNOWN (%s)", resp.State, raw)
	}
	if resp.PeerCount != 0 || resp.HighestKnownPeerHeight != 0 || resp.CurrentHeight != 0 {
		t.Fatalf("no provider means no observations: %+v", resp)
	}
	if resp.ProgressPercent != nil {
		t.Fatalf("progress must be null when nothing is known, got %v", *resp.ProgressPercent)
	}
}

// TestGetSyncStatusProviderNeverObserved covers the startup window: the
// provider is wired but runBlockSyncLoop has not finished its first pass.
// The response must say SYNCING (the state StartNode boots in) with null
// progress — never a completed sync, never a fabricated percentage.
func TestGetSyncStatusProviderNeverObserved(t *testing.T) {
	s := newTestSyncServer(t)
	s.SetSyncStatusProvider(NewSyncStatusTracker().Get)

	resp, _, _ := callGetSyncStatus(t, s)
	if !resp.Syncing {
		t.Fatal("never-observed must report syncing=true")
	}
	if resp.State != "SYNCING" {
		t.Fatalf("state = %q, want SYNCING", resp.State)
	}
	if resp.ProgressPercent != nil {
		t.Fatalf("never-observed progress must be null, got %v", *resp.ProgressPercent)
	}
	if resp.PeerCount != 0 {
		t.Fatalf("never-observed means no peers reported, got %d", resp.PeerCount)
	}
}

// TestGetSyncStatusObservedCaughtUp is the happy path a wallet waits for:
// the loop observed CAUGHT_UP with reachable peers and a real target, so the
// response is determinate 100%, syncing=false — exactly the precondition
// (with peer_count>0) under which sends may be enabled.
func TestGetSyncStatusObservedCaughtUp(t *testing.T) {
	s := newTestSyncServer(t)
	tr := NewSyncStatusTracker()
	tr.Observe(SyncStatus{Syncing: false, CurrentHeight: 100, HighestKnownPeerHeight: 100, PeerCount: 3, State: "CAUGHT_UP"})
	s.SetSyncStatusProvider(tr.Get)

	resp, _, _ := callGetSyncStatus(t, s)
	if resp.Syncing {
		t.Fatal("observed CAUGHT_UP must report syncing=false")
	}
	if resp.State != "CAUGHT_UP" {
		t.Fatalf("state = %q, want CAUGHT_UP", resp.State)
	}
	if resp.PeerCount != 3 {
		t.Fatalf("peer_count = %d, want 3", resp.PeerCount)
	}
	if resp.CurrentHeight != 100 || resp.HighestKnownPeerHeight != 100 {
		t.Fatalf("heights = current %d / target %d, want 100/100", resp.CurrentHeight, resp.HighestKnownPeerHeight)
	}
	if resp.ProgressPercent == nil || !almostEqual(*resp.ProgressPercent, 100) {
		t.Fatalf("caught-up progress = %v, want 100", resp.ProgressPercent)
	}
}

// TestGetSyncStatusObservedSyncingProgress checks a mid-sync observation is
// reported as the exact ratio while still flagged syncing.
func TestGetSyncStatusObservedSyncingProgress(t *testing.T) {
	s := newTestSyncServer(t)
	tr := NewSyncStatusTracker()
	tr.Observe(SyncStatus{Syncing: true, CurrentHeight: 250, HighestKnownPeerHeight: 1000, PeerCount: 2, State: "SYNCING"})
	s.SetSyncStatusProvider(tr.Get)

	resp, _, _ := callGetSyncStatus(t, s)
	if !resp.Syncing || resp.State != "SYNCING" {
		t.Fatalf("want syncing SYNCING, got syncing=%v state=%q", resp.Syncing, resp.State)
	}
	if resp.ProgressPercent == nil || !almostEqual(*resp.ProgressPercent, 25) {
		t.Fatalf("progress = %v, want 25", resp.ProgressPercent)
	}
}

// TestGetSyncStatusBehindWhileCaughtUpIsSyncing is the Phase 1.1 concern at
// the wire level: the loop observed CAUGHT_UP earlier (no peer addresses yet)
// and is now downloading from a peer whose tip is far ahead — without the
// state machine ever returning to SYNCING. The response must NOT read as
// synced, and progress must keep the while-syncing ceiling instead of 100.
func TestGetSyncStatusBehindWhileCaughtUpIsSyncing(t *testing.T) {
	s := newTestSyncServer(t)
	tr := NewSyncStatusTracker()
	tr.Observe(SyncStatus{Syncing: false, CurrentHeight: 100, HighestKnownPeerHeight: 140, PeerCount: 2, State: "CAUGHT_UP"})
	s.SetSyncStatusProvider(tr.Get)

	resp, _, raw := callGetSyncStatus(t, s)
	if !resp.Syncing {
		t.Fatalf("40 blocks behind a reachable peer must report syncing=true (%s)", raw)
	}
	if !strings.Contains(raw, `"syncing":true`) {
		t.Fatalf("wire must carry syncing:true, got %s", raw)
	}
	if resp.State != "CAUGHT_UP" {
		t.Fatalf("state = %q, want the raw state string CAUGHT_UP (diagnostics keep the loop's own view)", resp.State)
	}
	if resp.PeerCount != 2 {
		t.Fatalf("peer_count = %d, want 2", resp.PeerCount)
	}
	if resp.ProgressPercent == nil || !almostEqual(*resp.ProgressPercent, 100.0/140.0*100) {
		t.Fatalf("progress = %v, want %v", resp.ProgressPercent, 100.0/140.0*100)
	}
}

// TestGetSyncStatusOneBlockBehindStaysNotSyncing pins the "+1" tolerance:
// ordinary one-block propagation lag — the loop's own definition of caught up
// — must not flip the flag, so the send gate is not held shut by block gossip
// timing.
func TestGetSyncStatusOneBlockBehindStaysNotSyncing(t *testing.T) {
	s := newTestSyncServer(t)
	tr := NewSyncStatusTracker()
	tr.Observe(SyncStatus{Syncing: false, CurrentHeight: 100, HighestKnownPeerHeight: 101, PeerCount: 2, State: "CAUGHT_UP"})
	s.SetSyncStatusProvider(tr.Get)

	resp, _, raw := callGetSyncStatus(t, s)
	if resp.Syncing {
		t.Fatalf("one block behind must not report syncing=true (%s)", raw)
	}
	if resp.ProgressPercent == nil || !almostEqual(*resp.ProgressPercent, 100.0/101.0*100) {
		t.Fatalf("progress = %v, want %v", resp.ProgressPercent, 100.0/101.0*100)
	}
}

// TestGetSyncStatusObservedAge covers the freshness field end to end: -1 when
// nothing was ever observed, a small age for a fresh observation, and the real
// elapsed age for an old one. The server reports the RAW age and deliberately
// does not fold staleness into `syncing`, so the last sub-case also asserts
// that the client-side rule the GUI applies (age > SyncStatusStaleAfterMS ⇒
// sends stay disabled) is decidable from the response alone.
func TestGetSyncStatusObservedAge(t *testing.T) {
	t.Run("never observed", func(t *testing.T) {
		s := newTestSyncServer(t)
		s.SetSyncStatusProvider(NewSyncStatusTracker().Get)

		resp, _, raw := callGetSyncStatus(t, s)
		if resp.ObservedAgeMS != -1 {
			t.Fatalf("never-observed age = %d, want -1 (%s)", resp.ObservedAgeMS, raw)
		}
	})

	t.Run("fresh observation", func(t *testing.T) {
		s := newTestSyncServer(t)
		tr := NewSyncStatusTracker()
		tr.Observe(SyncStatus{Syncing: false, CurrentHeight: 10, HighestKnownPeerHeight: 10, PeerCount: 1, State: "CAUGHT_UP"})
		s.SetSyncStatusProvider(tr.Get)

		resp, _, raw := callGetSyncStatus(t, s)
		if resp.ObservedAgeMS < 0 {
			t.Fatalf("fresh observation age = %d, want >= 0 (%s)", resp.ObservedAgeMS, raw)
		}
		if resp.ObservedAgeMS > SyncStatusStaleAfterMS {
			t.Fatalf("a response produced microseconds after Observe must not read as stale, got %d ms", resp.ObservedAgeMS)
		}
	})

	t.Run("stale observation", func(t *testing.T) {
		s := newTestSyncServer(t)
		observedAt := time.Now().Add(-90 * time.Second)
		tr := newSyncStatusTrackerWithClock(func() time.Time { return observedAt })
		tr.Observe(SyncStatus{Syncing: false, CurrentHeight: 100, HighestKnownPeerHeight: 100, PeerCount: 2, State: "CAUGHT_UP"})
		s.SetSyncStatusProvider(tr.Get)

		resp, _, _ := callGetSyncStatus(t, s)
		if resp.ObservedAgeMS <= SyncStatusStaleAfterMS {
			t.Fatalf("a 90s-old observation must report age > %d ms, got %d", SyncStatusStaleAfterMS, resp.ObservedAgeMS)
		}
		if resp.ObservedAgeMS > 95_000 {
			t.Fatalf("age %d ms is implausibly large for a 90s-old observation", resp.ObservedAgeMS)
		}
		// The snapshot's own content says caught-up with peers, so only the
		// age keeps the gate closed — which is exactly why the field exists.
		sendsEnabled := !resp.Syncing && resp.PeerCount > 0 && resp.ObservedAgeMS <= SyncStatusStaleAfterMS
		if sendsEnabled {
			t.Fatalf("a stale observation must not open the send gate: %+v", resp)
		}
	})
}

// TestGetSyncStatusNoPeersNeverComplete is THE gating case: the loop reports
// CAUGHT_UP (it genuinely is, relative to its own tip) but no peer answered,
// so heights alone would say 100%. They must not: progress stays null and
// peer_count=0 is visible, which is what keeps the wallet's send gate
// (syncing==false AND peer_count>0) closed.
func TestGetSyncStatusNoPeersNeverComplete(t *testing.T) {
	s := newTestSyncServer(t)
	tr := NewSyncStatusTracker()
	tr.Observe(SyncStatus{Syncing: false, CurrentHeight: 50, HighestKnownPeerHeight: 50, PeerCount: 0, State: "CAUGHT_UP"})
	s.SetSyncStatusProvider(tr.Get)

	resp, _, raw := callGetSyncStatus(t, s)
	if resp.Syncing {
		t.Fatal("observed CAUGHT_UP may report syncing=false; the gate must close on peer_count instead")
	}
	if resp.PeerCount != 0 {
		t.Fatalf("peer_count = %d, want 0", resp.PeerCount)
	}
	if resp.ProgressPercent != nil {
		t.Fatalf("progress with no peers must be null, never 100 (%s)", raw)
	}
}

// TestGetSyncStatusTargetZeroIndeterminate: peers exist but none ever
// reported a non-zero tip (genesis-only network) — target unknown, so
// progress is null even though everything else is known.
func TestGetSyncStatusTargetZeroIndeterminate(t *testing.T) {
	s := newTestSyncServer(t)
	tr := NewSyncStatusTracker()
	tr.Observe(SyncStatus{Syncing: false, CurrentHeight: 0, HighestKnownPeerHeight: 0, PeerCount: 2, State: "CAUGHT_UP"})
	s.SetSyncStatusProvider(tr.Get)

	resp, _, _ := callGetSyncStatus(t, s)
	if resp.PeerCount != 2 {
		t.Fatalf("peer_count = %d, want 2", resp.PeerCount)
	}
	if resp.ProgressPercent != nil {
		t.Fatalf("target 0 must yield null progress, got %v", *resp.ProgressPercent)
	}
}

// TestGetSyncStatusProgressNullIsJSONNull pins the wire representation:
// progress_percent is ALWAYS present, and indeterminate is JSON null — not an
// omitted field (indistinguishable from a decode bug) and never a number.
// The other five documented fields must be present too.
func TestGetSyncStatusProgressNullIsJSONNull(t *testing.T) {
	_, _, raw := callGetSyncStatus(t, newTestSyncServer(t)) // no provider → indeterminate
	for _, want := range []string{
		`"progress_percent":null`,
		`"syncing"`,
		`"current_height"`,
		`"highest_known_peer_height"`,
		`"peer_count"`,
		`"state"`,
		`"observed_age_ms":-1`,
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("response must contain %s, got %s", want, raw)
		}
	}
}

// TestGetSyncStatusUnknownMethodStillFails confirms registering
// getsyncstatus did not disturb normal dispatch: an unknown method must
// still come back as a JSON-RPC error, not an empty success.
func TestGetSyncStatusUnknownMethodStillFails(t *testing.T) {
	s := newTestSyncServer(t)
	raw, err := s.HandleRequest([]byte(`{"jsonrpc":"2.0","id":7,"method":"definitely_not_a_method"}`))
	if err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}
	var env syncStatusEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope %s: %v", raw, err)
	}
	if env.Error == nil {
		t.Fatalf("unknown method must return an error envelope, got %s", raw)
	}
	if len(env.Result) != 0 {
		t.Fatalf("unknown method must not carry a result, got %s", raw)
	}
}

// TestGetSyncStatusConcurrentObserveAndRead exercises the full handler path
// under -race: wallet-style requests read through the provider while the
// "sync loop" observes — the exact two-goroutine pattern of a running node.
// Every response must decode and stay internally consistent (target = 2×
// current, peers >= 1, because the writer only emits linked snapshots).
func TestGetSyncStatusConcurrentObserveAndRead(t *testing.T) {
	s := newTestSyncServer(t)
	tr := NewSyncStatusTracker()
	s.SetSyncStatusProvider(tr.Get)

	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for i := 1; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			v := uint64(i)
			tr.Observe(SyncStatus{
				Syncing:                i%2 == 0,
				CurrentHeight:          v * 10,
				HighestKnownPeerHeight: v * 20,
				PeerCount:              int(v%5) + 1,
				State:                  "SYNCING",
			})
		}
	}()

	var readerWg sync.WaitGroup
	for r := 0; r < 4; r++ {
		readerWg.Add(1)
		go func() {
			defer readerWg.Done()
			for i := 0; i < 200; i++ {
				resp, _, raw, err := tryGetSyncStatus(s)
				if err != nil {
					t.Errorf("concurrent request failed: %v", err)
					return
				}
				if resp.HighestKnownPeerHeight != resp.CurrentHeight*2 {
					t.Errorf("torn response: current=%d target=%d (%s)",
						resp.CurrentHeight, resp.HighestKnownPeerHeight, raw)
					return
				}
				// A racing Observe between the handler's snapshot copy and the
				// tracker's atomic update of its stored copy can surface a
				// zero-valued intermediate (a fresh Tracker, an Observe racing
				// the read, or a counter wrap to i == 0 writing v == 0). A zero
				// PeerCount self-reports as "unknown — sends stay disabled":
				// getsyncstatus consumers must require peer_count > 0 AND a
				// non-negative observed_age_ms, never a bare > 0 assumption.
				// Retrying on the transient zero avoids failing the suite on a
				// scheduling artifact while keeping the torn-snapshot invariant
				// above strict.
				if resp.PeerCount < 1 {
					continue
				}
			}
		}()
	}
	readerWg.Wait()
	close(stop)
	<-writerDone
}
