// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/cge_witness.go
package core

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	txtypes "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
)

type multisigWitnessRef struct {
	witness multisig.MultiSigWitness
}

// WitnessForRelease builds a witness from a policy and a partial-signature set.
func WitnessForRelease(p multisig.MultiPartyPolicy, sigs map[int][]byte, expiry uint64) multisig.MultiSigWitness {
	return multisig.MultiSigWitness{Policy: p, Sigs: sigs, Expiry: expiry}
}

func witnessRefFor(w multisig.MultiSigWitness) multisigWitnessRef {
	return multisigWitnessRef{witness: w}
}

// BlockWitnesses returns the CGE release witnesses a block carries in its body.
func BlockWitnesses(block *txtypes.Block) []*txtypes.CGEReleaseWitness {
	if block == nil {
		return nil
	}
	return block.Body.CGEWitnesses
}

// witnessRefsFromBlock is the production source of release witnesses: the
// block body. Every node that executes the block — proposer preview, verifier,
// late-joiner replay — reads the identical set, so applyCGEReleases never
// depends on process-local state. A nil result means "no witnesses", which the
// gated path treats as "no release authorized".
func witnessRefsFromBlock(block *txtypes.Block) map[string]multisigWitnessRef {
	if block == nil || len(block.Body.CGEWitnesses) == 0 {
		return nil
	}
	refs := make(map[string]multisigWitnessRef, len(block.Body.CGEWitnesses))
	for _, w := range block.Body.CGEWitnesses {
		if w == nil || w.Recipient == "" {
			continue
		}
		ref := witnessRefFor(w.Witness)
		refs[w.Recipient] = ref
		// Defense-in-depth for block bodies staged before intake
		// canonicalization: also index by the canonical form so an
		// exact-case lookup on alloc.Address still finds it.
		if canon := common.CanonicalAddress(w.Recipient); canon != w.Recipient {
			if _, exists := refs[canon]; !exists {
				refs[canon] = ref
			}
		}
	}
	return refs
}

// ----------------------------------------------------------------------------
// Proposer-side intake
//
// Witnesses are protocol-triggered, not spender-submitted: a custodian only
// pre-authorizes the specific (escrow, recipient, amount, height) release the
// schedule will fire, and the proposer stages that authorization until it
// builds the block for that height. Verifiers need none of this — they read
// the witness back out of the block body.
// ----------------------------------------------------------------------------

type cgeWitnessPool struct {
	mu          sync.Mutex
	byRecipient map[string]*stagedCGEWitness
}

// stagedCGEWitness is one staged release authorization. targetHeight is the
// ceremony's intended block — a NOT-BEFORE hint, not a key: the signed
// message binds the milestone (see multisig.CGEVestingReleaseMessage), so
// what makes a witness usable is "the release is still pending", not "this
// is exactly height N".
type stagedCGEWitness struct {
	targetHeight uint64
	entry        *txtypes.CGEReleaseWitness
}

var (
	cgeWitnessPoolsMu sync.Mutex
	cgeWitnessPools   = map[*Blockchain]*cgeWitnessPool{}
)

func cgeWitnessPoolFor(bc *Blockchain) *cgeWitnessPool {
	cgeWitnessPoolsMu.Lock()
	defer cgeWitnessPoolsMu.Unlock()
	pool := cgeWitnessPools[bc]
	if pool == nil {
		pool = &cgeWitnessPool{byRecipient: map[string]*stagedCGEWitness{}}
		cgeWitnessPools[bc] = pool
	}
	return pool
}

// SubmitCGEWitness stages a custodian witness for one recipient. targetHeight
// is the ceremony's intended block — a NOT-BEFORE hint, not a key: the signed
// message binds the milestone, so the authorization stays usable on any later
// block where the release is still pending. refTime is the expiry-horizon
// reference; it comes from the chain (the last sealed block's timestamp),
// never a clock.
// canonicalCGEWitnessRecipient resolves recipient to the canonical
// DefaultGenesisAllocations address string, matching case-insensitively.
// The string embedded in the block body must be byte-identical to
// alloc.Address: witnessRefsFromBlock keys the refs by w.Recipient and
// applyCGEReleasesWithWitness looks them up by alloc.Address with an exact
// map key, and the signed CGEVestingReleaseMessage binds the recipient bytes.
// Canonicalizing at intake (not just upper-casing the pool key) makes the
// block-body string canonical by construction for every caller, so an
// operator-typed lower/mixed-case rendering still attaches AND verifies.
func lookupTimeBasedCGEAllocation(recipient string) (*GenesisAllocation, bool) {
	want := common.CanonicalAddress(recipient)
	for _, alloc := range DefaultGenesisAllocations() {
		if alloc == nil || alloc.Address == "" {
			continue
		}
		if !policy.CGEScheduleForLabel(alloc.Label).IsTimeBased() {
			continue // liquid (already paid) and module-gated (never by time) take no CGE witnesses
		}
		if alloc.Address == recipient || strings.EqualFold(alloc.Address, recipient) || alloc.Address == want {
			return alloc, true
		}
	}
	return nil, false
}

func (bc *Blockchain) SubmitCGEWitness(recipient string, targetHeight uint64, w multisig.MultiSigWitness, refTime uint64) error {
	if bc == nil {
		return fmt.Errorf("SubmitCGEWitness: nil blockchain")
	}
	if recipient == "" {
		return fmt.Errorf("SubmitCGEWitness: empty recipient")
	}
	// Fail loud at intake when the recipient names no time-based allocation,
	// even case-insensitively: such a witness could never authorize a release
	// (the gated path iterates time-based allocations only), so staging it
	// would be a silent no-op. Same discipline as the target-height/expiry
	// checks below.
	alloc, ok := lookupTimeBasedCGEAllocation(recipient)
	if !ok {
		return fmt.Errorf("SubmitCGEWitness: recipient %q matches no time-based CGE allocation", recipient)
	}
	// Normalize to the canonical allocation address BEFORE staging: the
	// entry.Recipient below is what rides in the block body, and the gated
	// path looks it up by exact alloc.Address.
	recipient = alloc.Address
	if err := multisig.ValidateWitnessExpiry(w.Expiry, refTime); err != nil {
		return err
	}
	if err := bc.validateCGETargetHeight(targetHeight, w.Expiry, refTime); err != nil {
		return err
	}
	if p := activeEscrowPolicy(); p != nil && len(w.Policy.PubKeys) == 0 {
		w.Policy = *p
	}
	pool := cgeWitnessPoolFor(bc)
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.byRecipient == nil {
		pool.byRecipient = map[string]*stagedCGEWitness{}
	}
	// One staged authorization per recipient: a new drop supersedes the
	// previous one for the same release. (Stale milestones are rejected at
	// verification time anyway — see multisig.CGEVestingReleaseMessage.)
	pool.byRecipient[strings.ToUpper(recipient)] = &stagedCGEWitness{
		targetHeight: targetHeight,
		entry:        &txtypes.CGEReleaseWitness{Recipient: recipient, Witness: w},
	}
	return nil
}

// stagedWitnessList returns every staged authorization in canonical
// (recipient-sorted) order so the assembled body is byte-identical regardless
// of submission order. It applies no gating — callers that need "attachable
// right now" use stagedWitnesses.
func (bc *Blockchain) stagedWitnessList() []*txtypes.CGEReleaseWitness {
	if bc == nil {
		return nil
	}
	pool := cgeWitnessPoolFor(bc)
	pool.mu.Lock()
	defer pool.mu.Unlock()
	recipients := make([]string, 0, len(pool.byRecipient))
	for r := range pool.byRecipient {
		recipients = append(recipients, r)
	}
	sort.Strings(recipients)
	out := make([]*txtypes.CGEReleaseWitness, 0, len(recipients))
	for _, r := range recipients {
		if pool.byRecipient[r] != nil && pool.byRecipient[r].entry != nil {
			out = append(out, pool.byRecipient[r].entry)
		}
	}
	return out
}

// validateCGETargetHeight refuses a target_height that could never be used,
// so a fat-fingered ceremony value fails immediately instead of resolving as
// a silent delay in a financial release path.
//
// target_height is only a not-before hint — the pending gate does the actual
// waiting — so it should sit near the chain tip. Two bounds, both derived
// rather than arbitrary:
//
//  1. Reachable-before-expiry: the chain must be able to reach the height
//     while the witness is still alive. Past that point the authorization
//     could never fire no matter how long the operator waits.
//  2. Look-ahead cap: one CGE month of blocks (the same horizon the
//     `multisig coverage` pre-flight uses by default, so the two tools agree
//     on what "too far" means). A height further ahead than a month of chain
//     is not a prediction anyone can make — and if it were honoured it would
//     sit staged, doing nothing, until someone thought to check.
//
// Both are measured against the live tip, so a legitimate "stage for the next
// block" always passes. Returns nil when there is no chain to measure against
// (bare test Blockchain): the check exists for real nodes, which always have
// both storage and params attached.
func (bc *Blockchain) validateCGETargetHeight(targetHeight, expiry, refTime uint64) error {
	if bc == nil || bc.storage == nil {
		return nil
	}
	tip, err := bc.storage.GetLatestBlock()
	if err != nil || tip == nil {
		return nil // no tip yet: nothing to measure from
	}
	blockTime := bc.cgeBlockTime()
	tipHeight := tip.GetHeight()

	if horizonBlocks := uint64(policy.CGEMonthSeconds) / uint64(blockTime.Seconds()); targetHeight > tipHeight+horizonBlocks {
		return fmt.Errorf("SubmitCGEWitness: target_height %d is %d blocks ahead of the tip (%d) — beyond one month of chain at %s; the not-before hint should name a near-term height, the schedule gate does the waiting",
			targetHeight, targetHeight-tipHeight, tipHeight, blockTime)
	}
	if expiry > refTime {
		if reach := (expiry - refTime) / uint64(blockTime.Seconds()); targetHeight > tipHeight+reach {
			return fmt.Errorf("SubmitCGEWitness: target_height %d cannot be reached before this witness expires at %d (tip %d, only %d blocks of validity left at %s)",
				targetHeight, expiry, tipHeight, reach, blockTime)
		}
	}
	return nil
}

// cgeBlockTime is the chain's target block interval, falling back to the
// default when params are not attached.
func (bc *Blockchain) cgeBlockTime() time.Duration {
	if bc != nil && bc.chainParams != nil && bc.chainParams.ConsensusConfig != nil {
		if bt := bc.chainParams.ConsensusConfig.BlockTime; bt > 0 {
			return bt
		}
	}
	return 10 * time.Second
}

// stagedWitnesses returns the staged authorizations that should ride a block
// at nextHeight, given `pending` — the set of recipients computed by
// cgeReleasesPendingAt from the SAME state handle previewStateRoot will then
// mutate. It does no I/O of its own: the caller opens state once, reads the
// pending set, and hands the same handle to the preview.
//
// ★ WHY TWO GATES (this is the fix for the height-bound failure mode):
//
//  1. nextHeight >= the ceremony's target height — a not-before hint, so a
//     file dropped early is not attached to blocks that cannot use it.
//  2. a release is actually PENDING for that recipient at the timestamp being
//     sealed. Attaching a witness to a block where nothing is due would spend
//     it: the release loop returns before verification when target <=
//     released, but the pool still drops it on seal — losing the
//     authorization with nothing to show. Pending-ness is sticky (once due it
//     stays due until released), so waiting is always safe and never loses the
//     witness.
//
// Because the signed message binds the milestone rather than the height, the
// first block that lands with a pending release can carry it — the witness
// no longer has to guess its own block height. A nil pending set means
// "state unreadable": attach nothing, keep everything staged.
func (bc *Blockchain) stagedWitnesses(pending map[string]bool, nextHeight uint64) []*txtypes.CGEReleaseWitness {
	if bc == nil || len(pending) == 0 {
		return nil
	}
	pool := cgeWitnessPoolFor(bc)
	pool.mu.Lock()
	defer pool.mu.Unlock()
	recipients := make([]string, 0, len(pool.byRecipient))
	for r, s := range pool.byRecipient {
		if s == nil || s.entry == nil {
			continue
		}
		if nextHeight < s.targetHeight {
			continue
		}
		if !pending[strings.ToUpper(r)] {
			continue
		}
		recipients = append(recipients, r)
	}
	sort.Strings(recipients)
	out := make([]*txtypes.CGEReleaseWitness, 0, len(recipients))
	for _, r := range recipients {
		out = append(out, pool.byRecipient[r].entry)
	}
	return out
}

// cgeReleasesPendingAt reports which time-based recipients have a release
// pending at headerTimestamp — cumulative target strictly above what is
// already released — using exactly the computation
// applyCGEReleasesWithWitness will perform for that timestamp. Proposer-side
// only: it decides which witnesses may be attached, never what releases.
//
// It takes the state handle rather than opening one, so CreateBlock can read
// the pending set and then hand the same handle to previewStateRoot instead
// of paying a second state open on the proposer's hot path.
//
// A nil stateDB returns nil (attach nothing): the witness stays staged for
// the next block, so the cost is one skipped opportunity, never a lost
// authorization.
func cgeReleasesPendingAt(stateDB *StateDB, headerTimestamp int64) map[string]bool {
	if stateDB == nil {
		return nil
	}
	genesisTS := stateDB.GetCGEGenesisTimestamp()
	if genesisTS == 0 {
		genesisTS = CanonicalGenesisTimestamp
	}
	elapsed := headerTimestamp - genesisTS
	if elapsed <= 0 {
		return nil
	}
	pending := make(map[string]bool, 4)
	for _, alloc := range DefaultGenesisAllocations() {
		if alloc == nil || alloc.BalanceNSPX == nil || alloc.BalanceNSPX.Sign() <= 0 {
			continue
		}
		sched := policy.CGEScheduleForLabel(alloc.Label)
		if !sched.IsTimeBased() {
			continue // liquid (already paid) or module-gated (never by time)
		}
		if sched.UnlockedAt(elapsed, alloc.BalanceNSPX).Cmp(stateDB.GetCGEReleased(alloc.Address)) > 0 {
			pending[strings.ToUpper(alloc.Address)] = true
		}
	}
	return pending
}

// dropStagedWitnesses clears the staged set for authorizations that rode a
// sealed block, so the same authorization can never be attached twice.
func (bc *Blockchain) dropStagedWitnesses(attached []*txtypes.CGEReleaseWitness) {
	if bc == nil || len(attached) == 0 {
		return
	}
	pool := cgeWitnessPoolFor(bc)
	pool.mu.Lock()
	defer pool.mu.Unlock()
	for _, w := range attached {
		if w != nil && w.Recipient != "" {
			delete(pool.byRecipient, strings.ToUpper(w.Recipient))
		}
	}
}

// ApplyCGEWithWitnesses re-runs the gated CGE releases for block against the
// committed state (used by tooling/tests that want the effect without the full
// block pipeline).
func (bc *Blockchain) ApplyCGEWithWitnesses(block *txtypes.Block, refs map[string]multisigWitnessRef) {
	stateDB, err := bc.newStateDB()
	if err != nil {
		return
	}
	applyCGEReleasesWithWitness(bc, block, stateDB, refs)
	if _, err := stateDB.Commit(); err != nil {
		return
	}
}
