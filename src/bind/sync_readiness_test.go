// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/sync_readiness_test.go
//
// Tests for the pure sync-readiness decision. Each case below corresponds to a
// named defect or a required liveness property, and the case letters match the
// scenario list in the fix's description.
package bind

import (
	"testing"
	"time"
)

// peersAt builds PeerTips for count distinct responders all reporting height h.
func peersAt(count int, h uint64) []PeerTip {
	out := make([]PeerTip, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, PeerTip{Responder: string(rune('A'+i)) + ":30303", Height: h})
	}
	return out
}

// Case (a): the defect. A restarted validator holds a complete local chain at
// height 2 while its peers have corroborated height 6. HasGenesis is true —
// that is the whole point — and it must NOT imply caught up.
func TestEvaluateSyncReadiness_RestartedNodeBehindIsNotReady(t *testing.T) {
	d := EvaluateSyncReadiness(SyncReadinessInput{
		LocalHeight:      2,
		PeerTips:         peersAt(3, 6),
		ValidatorSetSize: 4,
		HasGenesis:       true,
	})
	if d.Ready {
		t.Fatalf("(a) local 2 behind corroborated tip 6: got Ready=true (%s), want false", d.Reason)
	}
	if d.CorroboratedTip != 6 {
		t.Errorf("(a) corroborated tip = %d, want 6", d.CorroboratedTip)
	}
	if d.Behind != 4 {
		t.Errorf("(a) Behind = %d, want 4", d.Behind)
	}
}

// Case (b): no peer responded. Absence of information is not catch-up. A node
// must not open the PBFT gate on silence alone.
func TestEvaluateSyncReadiness_NoPeerRespondedIsNotReady(t *testing.T) {
	d := EvaluateSyncReadiness(SyncReadinessInput{
		LocalHeight:      2,
		PeerTips:         nil,
		ValidatorSetSize: 4,
		HasGenesis:       true,
	})
	if d.Ready {
		t.Fatalf("(b) zero responders: got Ready=true (%s), want false", d.Reason)
	}
	if d.Responders != 0 {
		t.Errorf("(b) Responders = %d, want 0", d.Responders)
	}
}

// Case (c): every node restarts at the same height. This is the deadlock guard
// — readiness must be reachable, or a synchronized restart wedges forever.
func TestEvaluateSyncReadiness_EqualHeightRestartIsReady(t *testing.T) {
	d := EvaluateSyncReadiness(SyncReadinessInput{
		LocalHeight:      6,
		PeerTips:         peersAt(3, 6),
		ValidatorSetSize: 4,
		HasGenesis:       true,
	})
	if !d.Ready {
		t.Fatalf("(c) equal-height restart: got Ready=false (%s), want true", d.Reason)
	}
}

// Case (d): a fresh genesis network. Nobody can be behind, and peers may not
// even be up yet. Requiring peer tips here would deadlock every cold start.
func TestEvaluateSyncReadiness_FreshGenesisIsReady(t *testing.T) {
	d := EvaluateSyncReadiness(SyncReadinessInput{
		LocalHeight:         0,
		PeerTips:            nil,
		ValidatorSetSize:    4,
		HasGenesis:          true,
		FreshGenesisNetwork: true,
	})
	if !d.Ready {
		t.Fatalf("(d) fresh genesis network: got Ready=false (%s), want true", d.Reason)
	}
}

// Case (e): local height already equals the corroborated tip.
func TestEvaluateSyncReadiness_AtCorroboratedTipIsReady(t *testing.T) {
	d := EvaluateSyncReadiness(SyncReadinessInput{
		LocalHeight:      6,
		PeerTips:         peersAt(2, 6),
		ValidatorSetSize: 4,
		HasGenesis:       true,
	})
	if !d.Ready {
		t.Fatalf("(e) at corroborated tip: got Ready=false (%s), want true", d.Reason)
	}
	if d.Behind != 0 {
		t.Errorf("(e) Behind = %d, want 0", d.Behind)
	}
}

// Case (f): the node is behind, applies blocks to the tip, and only then is
// ready. Readiness follows the chain, not the passage of time.
func TestEvaluateSyncReadiness_BecomesReadyAfterApplyingToTip(t *testing.T) {
	tips := peersAt(3, 6)
	behind := EvaluateSyncReadiness(SyncReadinessInput{
		LocalHeight: 2, PeerTips: tips, ValidatorSetSize: 4, HasGenesis: true,
	})
	if behind.Ready {
		t.Fatalf("(f) before applying blocks: got Ready=true, want false")
	}

	caught := EvaluateSyncReadiness(SyncReadinessInput{
		LocalHeight: 6, PeerTips: tips, ValidatorSetSize: 4, HasGenesis: true,
	})
	if !caught.Ready {
		t.Fatalf("(f) after applying to tip 6: got Ready=false (%s), want true", caught.Reason)
	}
}

// Case (g): the gate must not be one-way. A node that was ready and then falls
// behind must re-enter Syncing and stop proposing. This is the same predicate as
// (a); it is asserted separately because ReadyBefore must not leak into the
// answer.
func TestEvaluateSyncReadiness_ReadyNodeFallingBehindReentersSyncing(t *testing.T) {
	d := EvaluateSyncReadiness(SyncReadinessInput{
		LocalHeight:      6,
		PeerTips:         peersAt(3, 40),
		ValidatorSetSize: 4,
		HasGenesis:       true,
		ReadyBefore:      true,
		ElapsedWait:      10 * time.Minute,
	})
	if d.Ready {
		t.Fatalf("(g) ready node now behind tip 40: got Ready=true (%s), want false — the gate is one-way", d.Reason)
	}
	if d.Behind != 34 {
		t.Errorf("(g) Behind = %d, want 34", d.Behind)
	}
}

// Case (h): a single peer claims an absurd tip. Uncorroborated, so it must not
// move the target and must not wedge a healthy node that is otherwise ready.
func TestEvaluateSyncReadiness_UncorroboratedAbsurdTipCannotWedge(t *testing.T) {
	tips := append(peersAt(3, 6), PeerTip{Responder: "EVIL:30303", Height: 999999999})
	d := EvaluateSyncReadiness(SyncReadinessInput{
		LocalHeight:      6,
		PeerTips:         tips,
		ValidatorSetSize: 4,
		HasGenesis:       true,
	})
	if d.CorroboratedTip != 6 {
		t.Fatalf("(h) corroborated tip = %d, want 6 — one liar must not move the target", d.CorroboratedTip)
	}
	if !d.Ready {
		t.Fatalf("(h) healthy node at corroborated tip 6 was wedged: Ready=false (%s)", d.Reason)
	}
}

// TestSyncLoopGate_NotOneWay asserts the gate helper used by runBlockSyncLoop
// honours a corroborated tip over the presence of a local chain.
//
// This drives the same predicate the loop itself uses. On the pre-fix code the
// readiness decision is `hasGenesis`, so cases (a), (b) and (g) fail here: the
// gate opens for a node that is four blocks behind, for a node that heard from
// nobody, and stays open for a node that has fallen behind since being ready.
func TestSyncLoopGate_NotOneWay(t *testing.T) {
	const setSize = 4

	// (a) restarted node: local chain present, peers corroborated ahead.
	t.Run("restartedNodeBehindNotReady", func(t *testing.T) {
		got := syncGateAdmits(SyncGateInput{
			HasGenesis: true, LocalHeight: 2,
			PeerTips: peersAt(3, 6), ValidatorSetSize: setSize,
		})
		if got.Ready {
			t.Errorf("(a) local 2 behind tip 6: gate admits participation; want not admitted (reason %q)", got.Reason)
		}
	})

	// (b) no peer answered at all.
	t.Run("noPeerRespondedNotReady", func(t *testing.T) {
		got := syncGateAdmits(SyncGateInput{
			HasGenesis: true, LocalHeight: 2,
			PeerTips: nil, ValidatorSetSize: setSize,
		})
		if got.Ready {
			t.Errorf("(b) no responders: gate admits participation; want not admitted (reason %q)", got.Reason)
		}
	})

	// (g) node was ready, then peers corroborate a much higher tip.
	t.Run("readyNodeFallingBehindReentersSyncing", func(t *testing.T) {
		got := syncGateAdmits(SyncGateInput{
			HasGenesis: true, LocalHeight: 6, ReadyBefore: true,
			PeerTips: peersAt(3, 40), ValidatorSetSize: setSize,
			ElapsedWait: 10 * time.Minute,
		})
		if got.Ready {
			t.Errorf("(g) ready node now behind tip 40: gate stays open; want re-entry to Syncing (reason %q)", got.Reason)
		}
	})

	// Liveness counterparts: the fix must not wedge a healthy node.
	t.Run("equalHeightRestartStillReady", func(t *testing.T) {
		got := syncGateAdmits(SyncGateInput{
			HasGenesis: true, LocalHeight: 6,
			PeerTips: peersAt(3, 6), ValidatorSetSize: setSize,
		})
		if !got.Ready {
			t.Errorf("(c) equal-height restart blocked: want admitted (reason %q)", got.Reason)
		}
	})

	t.Run("freshGenesisStillReady", func(t *testing.T) {
		got := syncGateAdmits(SyncGateInput{
			HasGenesis: true, LocalHeight: 0, FreshGenesisNetwork: true,
			ValidatorSetSize: setSize,
		})
		if !got.Ready {
			t.Errorf("(d) fresh genesis network blocked: want admitted (reason %q)", got.Reason)
		}
	})
}
