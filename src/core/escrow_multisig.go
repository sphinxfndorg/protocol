// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/escrow_multisig.go
package core

import (
	"fmt"
	"math/big"
	"sync"

	logger "github.com/sphinxfndorg/protocol/src/console"
	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	"github.com/sphinxfndorg/protocol/src/policy"
)

const escrowMultisigDomain = "sphinx-escrow-v1"

var (
	escrowMultisigMu       sync.RWMutex
	escrowMultisigPolicy   *multisig.MultiPartyPolicy
	escrowMultisigAddr     string
	escrowMultisigEnforced bool
)

func EscrowMultisigEnforced() bool {
	escrowMultisigMu.RLock()
	defer escrowMultisigMu.RUnlock()
	return escrowMultisigEnforced
}

func SetEscrowMultisigEnforced(on bool) {
	escrowMultisigMu.Lock()
	defer escrowMultisigMu.Unlock()
	escrowMultisigEnforced = on
}

func EscrowPolicy() *multisig.MultiPartyPolicy {
	escrowMultisigMu.RLock()
	defer escrowMultisigMu.RUnlock()
	return escrowMultisigPolicy
}

func GetCGEEscrowAddress() string {
	escrowMultisigMu.RLock()
	defer escrowMultisigMu.RUnlock()
	if escrowMultisigAddr != "" {
		return escrowMultisigAddr
	}
	return policy.CGEEscrowAddress
}

func LoadEscrowPolicy(datadir string) (string, error) {
	gf, err := LoadGenesisFile(datadirOf(datadir))
	if err != nil {
		return "", err
	}
	if gf == nil || gf.EscrowMultisig == nil {
		return "", fmt.Errorf("genesis document for %s has no escrow_multisig section", datadir)
	}
	return RegisterEscrowPolicy(gf.EscrowMultisig)
}

func RegisterEscrowPolicy(p *multisig.MultiPartyPolicy) (string, error) {
	if p == nil {
		return "", fmt.Errorf("escrow multisig policy is nil")
	}
	// Register before publishing the address: block validation, mempool
	// admission and gossip all resolve a sender through this registry.
	addr, err := multisig.RegisterPolicy(p)
	if err != nil {
		return "", err
	}
	escrowMultisigMu.Lock()
	defer escrowMultisigMu.Unlock()
	cp := *p
	escrowMultisigPolicy = &cp
	escrowMultisigAddr = addr
	return addr, nil
}

func activeEscrowPolicy() *multisig.MultiPartyPolicy {
	escrowMultisigMu.RLock()
	defer escrowMultisigMu.RUnlock()
	return escrowMultisigPolicy
}

func escrowEnforced() bool {
	escrowMultisigMu.RLock()
	defer escrowMultisigMu.RUnlock()
	return escrowMultisigEnforced && escrowMultisigPolicy != nil
}

func chainIDForWitness(bc *Blockchain) uint64 {
	if bc != nil && bc.chainParams != nil {
		return bc.chainParams.ChainID
	}
	return 7331
}

// publishActiveChainID tells the musig registry which chain this node runs, so
// the custody spend path can reject a witness collected for another chain.
func (bc *Blockchain) publishActiveChainID() {
	multisig.SetActiveChainID(chainIDForWitness(bc))
}

// cgeReleaseMessage builds the exact custodian-signed authorization for one
// time-based CGE escrow release. It binds the MILESTONE (the cumulative
// unlocked target), not a block height: see
// multisig.CGEVestingReleaseMessage. amount is the per-block delta, target
// is the cumulative total those deltas accumulate toward.
func cgeReleaseMessage(bc *Blockchain, recipient string, amount, target *big.Int, expiry uint64) []byte {
	var delta, milestone []byte
	if amount != nil {
		delta = amount.Bytes()
	}
	if target != nil {
		milestone = target.Bytes()
	}
	return multisig.CGEVestingReleaseMessage(escrowMultisigDomain, chainIDForWitness(bc), GetCGEEscrowAddress(), recipient, delta, milestone, expiry)
}

// devModuleReleaseMessage builds the custodian-signed authorization for one
// development-module reward release. It is the message the escrow verification
// hook (escrow_verify_hook.go) hands to policy.ReleaseDevelopmentModuleWithWitness,
// so it must stay the single encoder shared by signer and verifier.
func devModuleReleaseMessage(bc *Blockchain, recipient string, moduleID uint64, expiry uint64) []byte {
	return multisig.DevModuleReleaseMessage(escrowMultisigDomain, chainIDForWitness(bc), GetCGEEscrowAddress(), recipient, moduleID, expiry)
}

func verifyCGEWitness(bc *Blockchain, w multisig.MultiSigWitness, recipient string, amount, target *big.Int, headerTS uint64) bool {
	p := activeEscrowPolicy()
	if p == nil {
		return false
	}
	if w.Policy.Domain != p.Domain {
		w.Policy = *p
	} else if len(w.Policy.PubKeys) == 0 {
		w.Policy = *p
	}
	if err := multisig.ValidateWitnessExpiry(w.Expiry, headerTS); err != nil {
		return false
	}
	msg := cgeReleaseMessage(bc, recipient, amount, target, w.Expiry)
	return multisig.VerifyThreshold(msg, w, headerTS)
}

// ----------------------------------------------------------------------------
// Authorization posture (loud, not silent)
// ----------------------------------------------------------------------------

// CGEReleasesAuthorised reports whether time-based CGE escrow→recipient
// releases are gated by an M-of-N witness.
//
// ★ It is NOT equivalent to "an escrow policy is configured". A loaded policy
// only changes WHERE escrow coins live and gates ordinary spends FROM the
// escrow address; it does not by itself gate the schedule's own releases. That
// additionally needs escrowMultisigEnforced, which has no production caller
// today, so in production this returns false — with OR without
// the escrow_multisig section of config/genesis_state.json.
func CGEReleasesAuthorised() bool {
	return escrowEnforced()
}

// warnCGEAuthorizationStatus states, once per node startup, whether time-based
// CGE releases are authorised. The negative case is a live gap in an
// already-running mechanism, so it must not be a silent default, and the
// message must name the REAL cause so an operator who correctly configured a
// custody policy is not misled into believing the escrow is secured:
//
//   - enforcement is off because SetEscrowMultisigEnforced has no production
//     caller, AND
//   - nothing stages witnesses because SubmitCGEWitness has no production
//     caller, so a block body's witness set is always empty.
//
// The per-release counterpart is emitted in applyCGEReleasesWithWitness, so an
// auditor can see whether one specific release carried authority rather than
// relying on this boot-time line.
func warnCGEAuthorizationStatus() {
	if CGEReleasesAuthorised() {
		logger.Info("CGE release authorization: ON — time-based escrow releases require an M-of-N witness (escrow=%s)",
			GetCGEEscrowAddress())
		return
	}
	policyState := "no escrow custody policy is configured"
	if EscrowPolicy() != nil {
		policyState = "an escrow custody policy IS configured, but it does NOT gate these releases"
	}
	logger.Error("CGE releases are UNAUTHORISED: time-based vesting will move escrow→recipient with NO M-of-N witness (%s; escrow=%s). Cause: enforcement is disabled (SetEscrowMultisigEnforced has no production caller) and nothing stages witnesses (SubmitCGEWitness has no production caller). Do not treat the escrow as secured. See docs/custody-genesis-ceremony.md.",
		policyState, GetCGEEscrowAddress())
}
