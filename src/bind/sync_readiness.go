// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/sync_readiness.go
//
// The pure readiness decision behind the sync gate. Extracted so it can be
// tested without a blockchain, a peer network, or a clock: every input is a
// plain value and the result is a plain value.
package bind

import (
	"time"

	"github.com/sphinxfndorg/protocol/src/consensus"
)

// PeerTip is one peer's self-reported chain tip, with the responder identity
// that reported it. Responder identity is what makes corroboration possible —
// two addresses from the same operator are one report, not two.
type PeerTip struct {
	Responder string
	Height    uint64
}

// SyncReadinessInput is everything the readiness decision depends on.
type SyncReadinessInput struct {
	// LocalHeight is this node's own tip height; 0 with no local block.
	LocalHeight uint64

	// PeerTips is every tip answered in this sync pass, responders included.
	// May be empty when nothing responded.
	PeerTips []PeerTip

	// ValidatorSetSize is the size of the height-keyed snapshot governing the
	// local height, not a configured or observed peer count.
	ValidatorSetSize int

	// HasGenesis reports whether this node holds a local chain at all. It is
	// explicitly NOT a catch-up signal: a node can hold a complete local chain
	// and still be many blocks behind the network.
	HasGenesis bool

	// FreshGenesisNetwork reports that the network has produced nothing beyond
	// genesis, so no catch-up can be pending.
	FreshGenesisNetwork bool

	// ElapsedWait is how long this node has been in the current ready phase.
	// It only ever permits readiness that peer evidence alone has not
	// established; it never manufactures a peer tip.
	ElapsedWait time.Duration

	// ReadyBefore is whether the node was previously admitted as ready. Used
	// only to report a lag regression, not to hold readiness open.
	ReadyBefore bool
}

// SyncReadinessDecision is the outcome of the readiness evaluation.
type SyncReadinessDecision struct {
	// Ready is whether this node may leave Syncing and open the PBFT gate.
	Ready bool

	// CorroboratedTip is the highest tip reported by at least
	// TipCorroborationCount distinct responders, or 0 when none qualifies.
	// A single uncorroborated claim can never raise it.
	CorroboratedTip uint64

	// Responders counts distinct responders this pass, including self.
	Responders int

	// RequiredResponders is the minimum meaningful responder count derived
	// from the snapshot. Zero means the snapshot alone does not justify
	// waiting for peers (a one-validator set is its own quorum).
	RequiredResponders int

	// Reason is a short human-readable explanation for logs.
	Reason string

	// Behind is how far local height trails CorroboratedTip.
	Behind uint64
}

// Bounds for the readiness decision. Each is justified where it is used.
const (
	// TipCorroborationCount is how many DISTINCT responders must agree on a
	// tip before that tip counts as corroborated. Two is the minimum that
	// ReadinessRespondersRequired returns the number of distinct responders a node
	// makes an uncorroborated single-peer claim (a lying, forked, or unrelated
	// peer) insufficient to move the target.
	TipCorroborationCount = 2
)

// ReadinessRespondersRequired returns the number of distinct responders a node
// must hear from before peer silence stops being inconclusive. It is
// StrictTwoThirdsCount(ValidatorSetSize) - 1, floored at zero.
//
// The derivation reuses the same strict-2/3 arithmetic as commit quorum, so
// readiness can never demand less evidence than commitment does. It changes no
// quorum math: StrictTwoThirdsCount itself is untouched, and this only reads
// it. A one-validator set has a floor of one, which is self, so it requires
// zero peers and cannot deadlock on a network that has no peers by definition.
func ReadinessRespondersRequired(ValidatorSetSize int) int {
	if ValidatorSetSize <= 1 {
		return 0
	}
	n := consensus.StrictTwoThirdsCount(ValidatorSetSize) - 1
	if n < 0 {
		return 0
	}
	return n
}

// highestCorroboratedTip returns the highest tip reported by at least
// TipCorroborationCount distinct responders. Reports are counted per distinct
// responder string, so one operator answering twice cannot corroborate itself.
// A tip with only one supporter is ignored outright rather than clamped down,
// which is what stops an absurd or forked claim from moving the target.
func highestCorroboratedTip(tips []PeerTip) uint64 {
	best := uint64(0)
	for _, candidate := range tips {
		supporters := make(map[string]struct{}, len(tips))
		for _, other := range tips {
			if other.Height >= candidate.Height {
				supporters[other.Responder] = struct{}{}
			}
		}
		if len(supporters) >= TipCorroborationCount && candidate.Height > best {
			best = candidate.Height
		}
	}
	return best
}

// makes an uncorroborated single-peer claim (a lying, forked, or
// unrelated peer) insufficient to move the target.
// EvaluateSyncReadiness decides whether a node may leave Syncing.
//
// The rule is deliberately one-directional in what it trusts: readiness means
// "this node is at the corroborated network tip", never merely "this node holds
// a chain". Holding a local chain (HasGenesis) is necessary to participate at
// all but says nothing about whether anything else moved on, which is exactly
// the defect this replaces: a restarted validator with a complete local chain
// was declared caught up and entered PBFT from a stale height.
//
// The function is symmetric: the same inputs produce Ready=false whether the
// node has never been ready (a restart) or has been ready and fallen behind
// (a lag regression). ReadyBefore is recorded for the log line only and never
// grants readiness.
func EvaluateSyncReadiness(in SyncReadinessInput) SyncReadinessDecision {
	required := ReadinessRespondersRequired(in.ValidatorSetSize)

	// Distinct responders this pass.
	seen := make(map[string]struct{}, len(in.PeerTips))
	for _, t := range in.PeerTips {
		if t.Responder == "" {
			continue
		}
		seen[t.Responder] = struct{}{}
	}
	responders := len(seen)

	tip := highestCorroboratedTip(in.PeerTips)

	d := SyncReadinessDecision{
		CorroboratedTip:    tip,
		Responders:         responders,
		RequiredResponders: required,
	}
	if tip > in.LocalHeight {
		d.Behind = tip - in.LocalHeight
	}

	switch {
	// No local chain: nothing to catch up to and nothing to lose by waiting.
	case !in.HasGenesis:
		d.Reason = "no local chain yet"
		return d

	// A network that has never produced past genesis cannot be behind. This is
	// the cold-start path and must not wait for peer tips that do not exist
	// yet, or every genesis network deadlocks at height 0.
	case in.FreshGenesisNetwork:
		d.Ready = true
		d.Reason = "network is at genesis"
		return d

	// Peer evidence says we are behind a corroborated tip. Stays not-ready
	// until blocks are actually applied; no timer overrides this.
	case d.Behind > 0:
		d.Reason = "local height trails the corroborated network tip"
		return d

	// We are at the tip, but too few peers answered to treat that as
	// knowledge rather than absence of information. Keeps a node from
	// declaring readiness during a startup race in which no peer has finished
	// its own sync yet.
	case required > 0 && responders < required:
		d.Reason = "not enough peers answered yet"
		return d

	default:
		// We hold the corroborated tip, or nobody is ahead of us and enough
		// peers agree. Both are genuine evidence, not silence.
		d.Ready = true
		if tip == 0 {
			d.Reason = "all responders report the same tip"
		} else {
			d.Reason = "local height is at the corroborated tip"
		}
		return d
	}
}

// SyncGateInput is what the sync loop knows each pass. It mirrors the fields
// the loop already computes, so the gate helper can be exercised directly.
type SyncGateInput struct {
	HasGenesis          bool
	LocalHeight         uint64
	PeerTips            []PeerTip
	ValidatorSetSize    int
	FreshGenesisNetwork bool
	ElapsedWait         time.Duration
	ReadyBefore         bool
}

// SyncGateResult is the gate's decision plus the evidence behind it.
type SyncGateResult struct {
	Ready  bool
	Reason string
}

// syncGateAdmits is the single predicate runBlockSyncLoop and
// runBlockProductionLoop both consult before a node opens its PBFT gate.
//
// It delegates to EvaluateSyncReadiness so there is exactly one definition of
// "ready" in the tree: the sync loop uses it to decide Syncing vs CaughtUp,
// and the production loop uses it to decide whether it may propose. A node that
// is behind therefore cannot describe itself as caught up in one place and
// participating in the other.
func syncGateAdmits(in SyncGateInput) SyncGateResult {
	d := EvaluateSyncReadiness(SyncReadinessInput{
		LocalHeight:         in.LocalHeight,
		PeerTips:            in.PeerTips,
		ValidatorSetSize:    in.ValidatorSetSize,
		HasGenesis:          in.HasGenesis,
		FreshGenesisNetwork: in.FreshGenesisNetwork,
		ElapsedWait:         in.ElapsedWait,
		ReadyBefore:         in.ReadyBefore,
	})
	return SyncGateResult{Ready: d.Ready, Reason: d.Reason}
}
