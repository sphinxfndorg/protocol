// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// NonceReserver is a process-local nonce reservation: it lets one account claim
// the next nonce while its previous transaction is still uncommitted, which the
// node's exact-nonce mempool rule otherwise turns into a collision. It replaces
// the per-caller copies in the mint package and gui/rpc.go with one table, keyed
// "nodeAddr|sender" because a single process may talk to several nodes.
//
// The zero value is ready to use. Reservations are deliberately unbounded (no
// TTL): a reservation that is never consumed only makes the next nonce too
// high, which the mempool rejects visibly, whereas an expiring one could hand
// the same nonce to two in-flight transactions.
type NonceReserver struct {
	// TTL is the getnonce timeout in seconds; zero uses DefaultNonceTTL.
	TTL uint16

	mu      sync.Mutex
	pending map[string]uint64
}

// DefaultNonceTTL is the getnonce timeout Reserve uses when TTL is unset. It is
// the value both former copies used.
const DefaultNonceTTL uint16 = 60

// NewNonceReserver returns an empty reservation table.
func NewNonceReserver() *NonceReserver { return &NonceReserver{} }

func (r *NonceReserver) key(nodeAddr, sender string) string {
	return nodeAddr + "|" + strings.TrimSpace(sender)
}

func (r *NonceReserver) ttl() uint16 {
	if r == nil || r.TTL == 0 {
		return DefaultNonceTTL
	}
	return r.TTL
}

// Reserve reads the account's committed nonce from the node and claims the next
// unclaimed one, advancing the reservation so a second broadcast in the same
// flow takes the following nonce. Like both former copies, the getnonce call
// happens outside the lock so a slow node cannot serialize unrelated accounts;
// concurrent Reservers for the SAME account can therefore read the same
// committed nonce, which claim's max() and the mempool's exact-nonce rejection
// keep correct rather than merely unlikely.
func (r *NonceReserver) Reserve(client RPCClient, nodeAddr, sender string) (uint64, error) {
	if client == nil {
		return 0, errors.New("nonce reserver: client is required")
	}
	if strings.TrimSpace(nodeAddr) == "" {
		return 0, errors.New("nonce reserver: node address is required")
	}
	raw := strings.TrimSpace(sender)
	if raw == "" {
		return 0, errors.New("nonce reserver: sender is required")
	}
	resp, err := client.CallRPC(nodeAddr, "getnonce", []interface{}{raw}, r.ttl())
	if err != nil {
		return 0, fmt.Errorf("getnonce: %w", err)
	}
	var chainNonce uint64
	if err := json.Unmarshal(resp, &chainNonce); err != nil {
		return 0, fmt.Errorf("parse nonce response: %w", err)
	}
	return r.claim(nodeAddr, raw, chainNonce), nil
}

// claim takes the next unclaimed nonce for (nodeAddr, sender), never below the
// committed nonce the node reported.
func (r *NonceReserver) claim(nodeAddr, sender string, chainNonce uint64) uint64 {
	k := r.key(nodeAddr, sender)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		r.pending = map[string]uint64{}
	}
	next := chainNonce
	if reserved, ok := r.pending[k]; ok && reserved > next {
		next = reserved
	}
	r.pending[k] = next + 1
	return next
}

// Peek reports the next unclaimed nonce for (nodeAddr, sender) without reading
// the chain or claiming anything.
func (r *NonceReserver) Peek(nodeAddr, sender string) (uint64, bool) {
	if r == nil {
		return 0, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	next, ok := r.pending[r.key(nodeAddr, sender)]
	return next, ok
}

// Advance raises the reservation for (nodeAddr, sender) to at least next, for a
// caller that already claimed a nonce through some other path.
func (r *NonceReserver) Advance(nodeAddr, sender string, next uint64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		r.pending = map[string]uint64{}
	}
	k := r.key(nodeAddr, sender)
	if next > r.pending[k] {
		r.pending[k] = next
	}
}

// Release rewinds a reservation whose transaction was never broadcast. It only
// rewinds when nothing has claimed a later nonce since (pending == nonce+1), so
// it can never hand out a nonce an in-flight transaction already owns.
func (r *NonceReserver) Release(nodeAddr, sender string, nonce uint64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k := r.key(nodeAddr, sender)
	if r.pending[k] == nonce+1 {
		r.pending[k] = nonce
	}
}
