// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/rpc/syncstatus.go
//
// getsyncstatus — a small, read-only JSON-RPC method that reports the node's
// full-block sync state to wallet/GUI clients (the src/gui sync panel polls it
// on a ticker). It changes no sync or consensus behavior: every value it
// reports is observed by the existing sync loop and handed to a provider
// closure.
//
// WHY A PROVIDER: the values live in package bind — runBlockSyncLoop's
// per-pass networkTip / reachable-peer count, and the *SyncState shared with
// runBlockProductionLoop. rpc must not import bind (bind imports rpc), so
// bind registers a provider via Server.SetSyncStatusProvider right after it
// creates the server (before any listener serves — the same set-once
// contract as SetTxRelay), and the loop publishes into a SyncStatusTracker
// the provider reads. The tracker is the only shared type: a mutex-guarded
// snapshot holder that is safe from any goroutine and NIL-SAFE, so a nil
// tracker degrades to "no observation yet" instead of panicking.
//
// HONESTY RULES (all locked in by syncstatus_test.go):
//
//   - deriveSyncProgress never claims 100% when the target height is unknown
//     (0) or no peers were observed — in those cases the result is
//     INDETERMINATE (progress_percent: null).
//   - deriveSyncing never reports syncing=false from the SyncState string
//     alone. bind's sync loop legitimately parks in CAUGHT_UP (no peer
//     addresses yet, or a genesis-only network) and, when a peer with a
//     higher tip shows up later, simply starts downloading that range —
//     WITHOUT moving the state machine back to SYNCING (the loop's only
//     assignment back to SYNCING is the state-divergence recovery). So
//     "behind the highest known peer tip" is folded in:
//     syncing = state is SYNCING OR highest peer tip > local height + 1.
//   - a client gating sends on this method must require syncing==false AND
//     peer_count>0 AND a FRESH observation (observed_age_ms <=
//     SyncStatusStaleAfterMS). syncing==false alone is not enough because a
//     peerless node reports its own tip as caught up, and a stale snapshot
//     can describe a node whose sync loop has since stalled.
package rpc

import (
	"sync"
	"time"
)

// SyncStatus is one observation of the node's sync state, as published by
// the sync loop. It is the internal (Go-side) snapshot; the JSON wire shape
// is syncStatusResponse below, which adds the derived progress percentage.
type SyncStatus struct {
	// Syncing is true while the node's sync state is SyncStateSyncing
	// (actively behind / catching up); false for CAUGHT_UP or
	// CONSENSUS_PARTICIPANT.
	Syncing bool
	// CurrentHeight is the local chain height at observation time. The
	// handler prefers a live read from the blockchain when one is attached;
	// this field is the fallback for provider-only servers (tests).
	CurrentHeight uint64
	// HighestKnownPeerHeight is the highest tip any reachable peer reported
	// on the observation's sync pass (0 = unknown / no peer answered).
	HighestKnownPeerHeight uint64
	// PeerCount is the number of peers that ANSWERED the network-tip query
	// on that pass — reachable peers, not merely configured addresses. A
	// configured-but-dead seed must never count, or send-gating would pass
	// against a network the node cannot actually reach.
	PeerCount int
	// State is the bind SyncState's string form: "SYNCING",
	// "CAUGHT_UP", "CONSENSUS_PARTICIPANT" (or "UNKNOWN").
	State string

	// ObservedAt is WHEN the tracker recorded this snapshot. It is stamped
	// by SyncStatusTracker.Observe (from the tracker's clock) — a value set
	// by the publishing loop is overwritten, because only the tracker knows
	// the instant the snapshot was stored. The zero value means "this
	// snapshot was never stored by a tracker", which the handler reports as
	// observed_age_ms = -1. It is how a client detects that the last
	// observation is too old to trust (see SyncStatusStaleAfterMS).
	ObservedAt time.Time
}

// SyncStatusTracker holds the most recent SyncStatus observation.
//
// Concurrency: every read/write happens under the tracker's own RWMutex, so
// Observe (sync-loop goroutine) and Get (RPC handler goroutine) are race-free
// — verified by TestSyncStatusTrackerConcurrentObserveGet under -race, whose
// invariant (all fields of one Get() must come from a single Observe()) also
// proves snapshots are never torn.
//
// Nil-safety: every method tolerates a nil receiver. Observe on nil is a
// no-op; Get on nil returns the zero snapshot and observed=false. Code that
// holds a *SyncStatusTracker therefore never needs a nil branch, and a
// forgotten tracker simply reports "not observed yet" through the handler.
type SyncStatusTracker struct {
	mu       sync.RWMutex
	last     SyncStatus
	observed bool

	// now is the tracker's clock, used to stamp ObservedAt on every Observe.
	// NewSyncStatusTracker sets it to time.Now; tests inject an offset/fixed
	// clock through newSyncStatusTrackerWithClock so observation age is
	// asserted deterministically. nil falls back to time.Now, so a
	// zero-value tracker literal still behaves correctly.
	now func() time.Time
}

// NewSyncStatusTracker returns an empty tracker; its first Get reports
// observed=false until the first Observe.
func NewSyncStatusTracker() *SyncStatusTracker {
	return &SyncStatusTracker{now: time.Now}
}

// newSyncStatusTrackerWithClock is the injectable-clock seam for this
// package's tests (see syncstatus_test.go). Production wiring always uses
// NewSyncStatusTracker.
func newSyncStatusTrackerWithClock(now func() time.Time) *SyncStatusTracker {
	return &SyncStatusTracker{now: now}
}

// clock reads the tracker's clock, falling back to time.Now so a zero-value
// SyncStatusTracker (nil clock) never panics.
func (t *SyncStatusTracker) clock() time.Time {
	if t.now == nil {
		return time.Now()
	}
	return t.now()
}

// Observe records one snapshot, atomically replacing the previous one and
// marking the tracker observed. A negative PeerCount is clamped to 0 so a
// caller bug can never make the handler report peers it does not have.
// Nil receiver: no-op.
func (t *SyncStatusTracker) Observe(s SyncStatus) {
	if t == nil {
		return
	}
	if s.PeerCount < 0 {
		s.PeerCount = 0
	}
	// The tracker owns the timestamp: only it knows when the snapshot was
	// stored, and that instant is what the response's observed_age_ms is
	// measured from. A publisher-supplied ObservedAt is deliberately ignored.
	s.ObservedAt = t.clock()
	t.mu.Lock()
	t.last = s
	t.observed = true
	t.mu.Unlock()
}

// Get returns the latest snapshot and whether any observation has ever been
// recorded. Both values are read under one lock, so they are consistent with
// each other. Nil receiver: (zero SyncStatus, false).
func (t *SyncStatusTracker) Get() (SyncStatus, bool) {
	if t == nil {
		return SyncStatus{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.last, t.observed
}

// SetSyncStatusProvider wires the closure getsyncstatus reads. bind.StartNode
// calls this once, right after rpc.NewServer and BEFORE any listener serves
// traffic, so the plain field write races no reader — the same contract as
// SetTxRelay. Passing nil is equivalent to never setting one.
//
// The provider signature returns (status, observed): the second value tells
// the handler the difference between "the loop has reported" and "nothing
// observed yet", which must never be rendered as a completed sync.
func (s *Server) SetSyncStatusProvider(fn func() (SyncStatus, bool)) {
	s.syncStatusProvider = fn
}

// syncStatusResponse is the JSON shape of getsyncstatus.
//
// progress_percent is a pointer so an INDETERMINATE result marshals as
// JSON null — never 100, never silently absent. Clients treat null as
// "cannot estimate yet" (target height unknown or no peers observed). It is
// deliberately NOT omitempty: the field is always present, and its null-ness
// carries the meaning.
type syncStatusResponse struct {
	Syncing                bool     `json:"syncing"`
	CurrentHeight          uint64   `json:"current_height"`
	HighestKnownPeerHeight uint64   `json:"highest_known_peer_height"`
	PeerCount              int      `json:"peer_count"`
	ProgressPercent        *float64 `json:"progress_percent"`
	State                  string   `json:"state"`
	// ObservedAgeMS is how long ago (in milliseconds) the observation this
	// response is built from was recorded. -1 means NOTHING was ever
	// observed — no provider wired, or the loop has not finished its first
	// pass — and is never a legitimate age (0 means "observed just now").
	// Clients treat an age above SyncStatusStaleAfterMS as "status
	// unavailable" and keep sends disabled: a stale CAUGHT_UP snapshot may
	// describe a node whose sync loop has since stalled. Always present
	// (deliberately NOT omitempty) so its absence can never look like
	// freshness.
	ObservedAgeMS int64 `json:"observed_age_ms"`
}

// syncStatusCapWhileSyncing is the ceiling reported while the node still
// considers itself SYNCING: heights may read "at target" for one pass before
// the state transition lands, and a wallet must never see 100% while the node
// says it is still syncing. Only a non-syncing observation may report 100.
const syncStatusCapWhileSyncing = 99.9

// SyncStatusStaleAfterMS is the observation age beyond which a client must
// treat getsyncstatus as unavailable ("status unavailable, sends disabled")
// instead of trusting the last snapshot. The server deliberately reports the
// raw age rather than folding staleness into `syncing`, so a client can tell
// "behind" (syncing=true) apart from "no fresh information" — both of which
// must keep sends disabled. Exported because it is part of the contract
// clients mirror; the GUI's send gate reads observed_age_ms against it.
const SyncStatusStaleAfterMS int64 = 60_000

// deriveSyncProgress estimates sync completion as a percentage in [0,100].
//
// Returns (percent, true) when an estimate exists, (0, false) when
// INDETERMINATE. Indeterminate — never 100%, never any number the client
// should trust — when:
//
//   - peerCount <= 0: no peer has answered a tip query, so there is no
//     network view to compare against (a peerless node's own tip says
//     "caught up" by construction); or
//   - targetHeight == 0: no peer has ever reported a non-zero tip, so the
//     target height is unknown. 0 is indistinguishable from "unknown" here,
//     so it is treated as unknown even if peers answered with a genesis-only
//     chain — showing an estimate would be guessing.
//
// When determinate: current >= target is complete — 100 if the node is not
// syncing, the 99.9 cap if it still is (transient; see the cap constant).
// Otherwise the exact ratio, itself capped while syncing so in-flight states
// cannot round up to 100. Pure function; no clock, no locks, no I/O.
func deriveSyncProgress(syncing bool, currentHeight, targetHeight uint64, peerCount int) (float64, bool) {
	if peerCount <= 0 || targetHeight == 0 {
		return 0, false
	}
	if currentHeight >= targetHeight {
		if syncing {
			return syncStatusCapWhileSyncing, true
		}
		return 100, true
	}
	pct := float64(currentHeight) / float64(targetHeight) * 100
	if pct > syncStatusCapWhileSyncing {
		pct = syncStatusCapWhileSyncing
	}
	return pct, true
}

// deriveSyncing decides the honest value of the wire `syncing` flag.
//
// bind's sync loop parks in CAUGHT_UP whenever it has no peer addresses (the
// bootstrap node before any peer connects) or sees a genesis-only network,
// and it never moves the state machine back to SYNCING when a peer with a
// higher tip appears later: the same loop simply falls through to its
// download path (localHeight < networkTip) while *syncState still reads
// CAUGHT_UP. Reporting the state string verbatim would therefore tell a
// wallet "synced" during an active catch-up. So the reported value is:
//
//	syncing = state is SYNCING || highest known peer tip > local height + 1
//
// The "+1" tolerance mirrors the sync loop's own definition of caught up
// ("within 1 block of the network tip"), so a one-block lag — ordinary block
// propagation — is not reported as a catch-up. With no peer tip known
// (target 0) only the state decides, which keeps a peerless node's
// syncing=false honest *together with* peer_count=0 and the freshness field
// of the same response (see the send-gate note in the package comment).
//
// The comparison is written subtraction-first so a local height of
// MaxUint64 cannot wrap the +1. Pure function: no clock, no locks, no I/O.
func deriveSyncing(state string, stateSyncing bool, currentHeight, highestKnownPeerHeight uint64) bool {
	if stateSyncing || state == "SYNCING" {
		return true
	}
	return highestKnownPeerHeight > currentHeight && highestKnownPeerHeight-currentHeight > 1
}

// deriveObservedAgeMS turns the tracker's observation timestamp into the wire
// age in milliseconds, with -1 reserved for "never observed" (0 is a
// legitimate age, so the two must not be conflated). A timestamp in the
// future — the clock stepped between the observation and this read — clamps
// to 0 rather than reporting a negative age, so a client's
// `age <= SyncStatusStaleAfterMS` check can never be satisfied by a backwards
// clock step. Pure function: the caller supplies `now`.
func deriveObservedAgeMS(observed bool, observedAt, now time.Time) int64 {
	if !observed || observedAt.IsZero() {
		return -1
	}
	age := now.Sub(observedAt)
	if age < 0 {
		return 0
	}
	return age.Milliseconds()
}

// getSyncStatus is the getsyncstatus handler (registered in
// registerMethods). Read-only, parameterless, and safe on every server:
//
//   - no provider wired (legacy harness servers): honest "UNKNOWN" state,
//     syncing=true — safe for send-gating, never claims a sync completed;
//   - provider wired but never observed (loop hasn't finished its first
//     pass): syncing=true, state "SYNCING" (the state StartNode boots in),
//     progress indeterminate via zero peers/target, observed_age_ms -1;
//   - observed: the loop's own view, with current_height refreshed live
//     from the attached blockchain when there is one (the tracker's height
//     can be a pass old; the chain is authoritative), `syncing` FOLDED
//     against the highest known peer tip (see deriveSyncing), and
//     observed_age_ms measured from the tracker's observation timestamp.
func (h *JSONRPCHandler) getSyncStatus(_ interface{}) (interface{}, error) {
	var st SyncStatus
	observed := false
	providerSet := h.server != nil && h.server.syncStatusProvider != nil
	if providerSet {
		st, observed = h.server.syncStatusProvider()
	}

	current := st.CurrentHeight
	if h.server != nil && h.server.blockchain != nil {
		current = h.server.blockchain.GetBlockCount()
	}

	// Conservative defaults: until something says otherwise, the node is
	// reported as still syncing (gating-safe) in an unknown state, with no
	// observation age (-1 = never observed).
	syncing := true
	state := "UNKNOWN"
	switch {
	case observed:
		state = st.State
		if state == "" {
			state = "UNKNOWN"
		}
		// Not the raw state string: the loop can be actively downloading
		// while *syncState still reads CAUGHT_UP (see deriveSyncing).
		syncing = deriveSyncing(state, st.Syncing, current, st.HighestKnownPeerHeight)
	case providerSet:
		// The loop will report within one pass; it boots in SyncStateSyncing.
		state = "SYNCING"
	}

	resp := syncStatusResponse{
		Syncing:                syncing,
		CurrentHeight:          current,
		HighestKnownPeerHeight: st.HighestKnownPeerHeight,
		PeerCount:              st.PeerCount,
		State:                  state,
		ObservedAgeMS:          deriveObservedAgeMS(observed, st.ObservedAt, time.Now()),
	}
	// Progress is derived from the FOLDED syncing value, so a node that is
	// behind a higher peer tip while its state string still says CAUGHT_UP
	// keeps the while-syncing ceiling instead of reporting a completed sync.
	if pct, ok := deriveSyncProgress(syncing, current, st.HighestKnownPeerHeight, st.PeerCount); ok {
		resp.ProgressPercent = &pct
	}
	return resp, nil
}
