// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package multisig

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// Custody policies are registered by their derived address when a config file
// is loaded, so every component — block validation in core, mempool admission
// and gossip screening in pool/p2p/bind/rpc — can resolve a transaction sender
// back to the M-of-N policy that owns it. The registry lives here, in the leaf
// package that already owns MultiPartyPolicy, because core imports pool and so
// pool cannot import core.
var (
	policyRegistryMu sync.RWMutex
	policyRegistry   = map[string]MultiPartyPolicy{}
)

// activeChainID is the chain this node is actually running. A custody witness
// binds the transaction's ChainID into the signed message, so custody
// authorization additionally requires the transaction to declare exactly this
// chain's ID — a witness collected for one chain can never authorize a spend
// on another, even when both chains are configured with the same custody
// policy. The value is published by the node before any custody decision runs
// (see core.publishActiveChainID); an unset (zero) value fails closed with
// ErrActiveChainIDUnset instead of skipping the check.
var activeChainID atomic.Uint64

// SetActiveChainID publishes the running chain's ID to the custody path.
// It is called at every admission and commit entry point (see
// core.publishActiveChainID), which makes a missing call impossible to miss:
// the custody-spend check fails closed with ErrActiveChainIDUnset when no
// value was ever published.
func SetActiveChainID(id uint64) { activeChainID.Store(id) }

// GetActiveChainID returns the published chain ID (0 when unset).
func GetActiveChainID() uint64 { return activeChainID.Load() }

// RegisterPolicy derives p's address and records it as a known custody
// address, returning the derived address. Keys are case-folded so an address
// resolves regardless of the case the caller happens to carry it in.
func RegisterPolicy(p *MultiPartyPolicy) (string, error) {
	if p == nil {
		return "", fmt.Errorf("nil policy")
	}
	addr, err := p.Address()
	if err != nil {
		return "", err
	}
	policyRegistryMu.Lock()
	policyRegistry[strings.ToUpper(addr)] = *p
	policyRegistryMu.Unlock()
	return addr, nil
}

// LookupPolicy resolves an address to its registered custody policy. ok==false
// means the address is an ordinary single-key account.
func LookupPolicy(address string) (*MultiPartyPolicy, bool) {
	if address == "" {
		return nil, false
	}
	policyRegistryMu.RLock()
	stored, ok := policyRegistry[strings.ToUpper(address)]
	policyRegistryMu.RUnlock()
	if !ok {
		return nil, false
	}
	p := stored
	return &p, true
}

// ErrActiveChainIDUnset is returned, instead of a validation outcome, when the
// custody path is reached before any chain ID was published. It is the
// tripwire that proves no custody decision can silently run without
// cross-chain protection — see SetActiveChainID.
var ErrActiveChainIDUnset = fmt.Errorf("active chain ID is not published: refusing custody authorization until the node publishes its chain")

// RequireActiveChainID publishes id and returns the previously published value
// so the caller can restore it with SetActiveChainID when finished. Tests call
// this directly because they drive the witness check without a Blockchain
// entry point; production callers publish through core.publishActiveChainID.
func RequireActiveChainID(id uint64) (prev uint64) {
	return activeChainID.Swap(id)
}

// UnregisterPolicy forgets one custody address (chain switches, tests).
func UnregisterPolicy(address string) {
	policyRegistryMu.Lock()
	delete(policyRegistry, strings.ToUpper(address))
	policyRegistryMu.Unlock()
}

// HasSpendWitnessShape is the custody equivalent of
// Transaction.HasFullAuthBundle: a structural screen only, used by gateways
// that reject transactions before the mempool ever verifies them. Threshold is
// taken from the registered policy, never from the witness itself.
func HasSpendWitnessShape(sender string, w *MultiSigWitness) bool {
	if w == nil {
		return false
	}
	p, registered := LookupPolicy(sender)
	if !registered {
		return false
	}
	return len(w.Sigs) >= int(p.Threshold)
}
