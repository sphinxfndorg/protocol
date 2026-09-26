// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/cge_witness.go
package core

import (
	"fmt"
	"sort"
	"sync"

	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	txtypes "github.com/sphinxfndorg/protocol/src/core/transaction"
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
		refs[w.Recipient] = witnessRefFor(w.Witness)
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
	mu       sync.Mutex
	byHeight map[uint64]map[string]*txtypes.CGEReleaseWitness
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
		pool = &cgeWitnessPool{byHeight: map[uint64]map[string]*txtypes.CGEReleaseWitness{}}
		cgeWitnessPools[bc] = pool
	}
	return pool
}

// SubmitCGEWitness stages a custodian witness for the block at targetHeight.
// refTime is the expected release time used for the expiry-horizon check; it
// comes from the chain (the last sealed block's timestamp), never a clock.
func (bc *Blockchain) SubmitCGEWitness(recipient string, targetHeight uint64, w multisig.MultiSigWitness, refTime uint64) error {
	if bc == nil {
		return fmt.Errorf("SubmitCGEWitness: nil blockchain")
	}
	if recipient == "" {
		return fmt.Errorf("SubmitCGEWitness: empty recipient")
	}
	if err := multisig.ValidateWitnessExpiry(w.Expiry, refTime); err != nil {
		return err
	}
	if p := activeEscrowPolicy(); p != nil && len(w.Policy.PubKeys) == 0 {
		w.Policy = *p
	}
	pool := cgeWitnessPoolFor(bc)
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.byHeight[targetHeight] == nil {
		pool.byHeight[targetHeight] = map[string]*txtypes.CGEReleaseWitness{}
	}
	pool.byHeight[targetHeight][recipient] = &txtypes.CGEReleaseWitness{Recipient: recipient, Witness: w}
	return nil
}

// pendingBlockWitnesses returns the witnesses staged for targetHeight in a
// canonical (recipient-sorted) order so the assembled body is byte-identical
// regardless of submission order.
func (bc *Blockchain) pendingBlockWitnesses(targetHeight uint64) []*txtypes.CGEReleaseWitness {
	if bc == nil {
		return nil
	}
	pool := cgeWitnessPoolFor(bc)
	pool.mu.Lock()
	defer pool.mu.Unlock()
	staged := pool.byHeight[targetHeight]
	if len(staged) == 0 {
		return nil
	}
	recipients := make([]string, 0, len(staged))
	for r := range staged {
		recipients = append(recipients, r)
	}
	sort.Strings(recipients)
	out := make([]*txtypes.CGEReleaseWitness, 0, len(recipients))
	for _, r := range recipients {
		cp := *staged[r]
		out = append(out, &cp)
	}
	return out
}

// dropPendingBlockWitnesses clears the staged set once a block consumed it, so
// a witness can never be attached to two different blocks.
func (bc *Blockchain) dropPendingBlockWitnesses(height uint64) {
	if bc == nil {
		return
	}
	pool := cgeWitnessPoolFor(bc)
	pool.mu.Lock()
	defer pool.mu.Unlock()
	delete(pool.byHeight, height)
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
