// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/escrow_multisig.go
package core

import (
	"encoding/json"
	"math/big"
	"os"
	"sync"

	logger "github.com/sphinxfndorg/protocol/src/console"
	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	"github.com/sphinxfndorg/protocol/src/policy"
)

const defaultEscrowMultisigPath = "config/escrow_multisig.json"

const escrowMultisigDomain = "sphinx-escrow-v1"

var (
	escrowMultisigMu       sync.RWMutex
	escrowMultisigPolicy   *multisig.MultiPartyPolicy
	escrowMultisigAddr     string
	escrowMultisigEnforced bool
)

func init() {
	// Auto-load config/escrow_multisig.json if present at process startup.
	// When absent, GetCGEEscrowAddress falls back to policy.CGEEscrowAddress.
	// Skipped inside `go test` binaries so a locally generated demo policy
	// cannot change every test's escrow address (see core.policyAutoLoadDisabled).
	if policyAutoLoadDisabled() {
		return
	}
	InitEscrowAddress()
}

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

func LoadEscrowPolicy(path string) (string, error) {
	if path == "" {
		path = defaultEscrowMultisigPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var p multisig.MultiPartyPolicy
	if err := json.Unmarshal(data, &p); err != nil {
		return "", err
	}
	// Register before publishing the address: block validation, mempool
	// admission and gossip all resolve a sender through this registry.
	addr, err := multisig.RegisterPolicy(&p)
	if err != nil {
		return "", err
	}
	escrowMultisigMu.Lock()
	defer escrowMultisigMu.Unlock()
	cp := p
	escrowMultisigPolicy = &cp
	escrowMultisigAddr = addr
	return addr, nil
}

func InitEscrowAddress() string {
	if addr, err := LoadEscrowPolicy(defaultEscrowMultisigPath); err == nil {
		// ★ The policy file changes WHERE escrow coins live; it does not by
		// itself gate the vesting schedule's own block-body releases. Say so
		// out loud, because the two are easy to conflate and a silent default
		// here would let an operator believe releases are witness-gated when
		// they are not.
		if !EscrowMultisigEnforced() {
			logger.Warn("escrow custody policy loaded (%s): time-based CGE releases are NOT witness-gated until SetEscrowMultisigEnforced(true) is called; ordinary spends from the escrow address still require M-of-N", addr)
		}
		return addr
	}
	return policy.CGEEscrowAddress
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

func cgeReleaseMessage(bc *Blockchain, recipient string, amount *big.Int, height uint64, expiry uint64) []byte {
	var amt []byte
	if amount != nil {
		amt = amount.Bytes()
	}
	return multisig.CustodyReleaseMessage(escrowMultisigDomain, chainIDForWitness(bc), GetCGEEscrowAddress(), recipient, amt, height, expiry)
}

func devModuleReleaseMessage(bc *Blockchain, recipient string, moduleID uint64, expiry uint64) []byte {
	return multisig.DevModuleReleaseMessage(escrowMultisigDomain, chainIDForWitness(bc), GetCGEEscrowAddress(), recipient, moduleID, expiry)
}

func verifyCGEWitness(bc *Blockchain, w multisig.MultiSigWitness, recipient string, amount *big.Int, height uint64, headerTS uint64) bool {
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
	msg := cgeReleaseMessage(bc, recipient, amount, height, w.Expiry)
	return multisig.VerifyThreshold(msg, w, headerTS)
}

func verifyDevModuleWitness(bc *Blockchain, w multisig.MultiSigWitness, recipient string, moduleID uint64, height uint64, headerTS uint64) bool {
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
	msg := devModuleReleaseMessage(bc, recipient, moduleID, w.Expiry)
	return multisig.VerifyThreshold(msg, w, headerTS)
}
