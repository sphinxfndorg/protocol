// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"testing"

	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
)

// TestEscrowPolicyDoesNotImplyAuthorisedReleases pins the distinction that made
// the CGE gap easy to miss: a configured escrow custody policy moves WHERE
// escrow coins live and gates ordinary spends FROM the escrow address, but it
// does NOT by itself gate the schedule's own time-based releases. Those need
// escrowMultisigEnforced, which has no production caller — so in production
// CGEReleasesAuthorised() is false with OR without config/escrow_multisig.json.
func TestEscrowPolicyDoesNotImplyAuthorisedReleases(t *testing.T) {
	prevPolicy := escrowMultisigPolicy
	prevAddr := escrowMultisigAddr
	prevEnforced := escrowMultisigEnforced
	t.Cleanup(func() {
		escrowMultisigMu.Lock()
		escrowMultisigPolicy = prevPolicy
		escrowMultisigAddr = prevAddr
		escrowMultisigEnforced = prevEnforced
		escrowMultisigMu.Unlock()
	})

	p := multisig.MultiPartyPolicy{
		PubKeys:   [][]byte{{0x01}},
		Threshold: 1,
		Domain:    escrowMultisigDomain,
	}
	escrowMultisigMu.Lock()
	cp := p
	escrowMultisigPolicy = &cp
	escrowMultisigAddr = "00000000000000000000000000000000000000FF"
	escrowMultisigEnforced = false
	escrowMultisigMu.Unlock()

	// Policy present, enforcement off (the production default): NOT authorised.
	if EscrowPolicy() == nil {
		t.Fatal("test setup: escrow policy should be registered")
	}
	if CGEReleasesAuthorised() {
		t.Fatal("a configured escrow policy must NOT by itself authorise CGE releases")
	}
	if escrowEnforced() {
		t.Fatal("escrowEnforced must stay false while the enforcement flag is off")
	}
	warnCGEAuthorizationStatus() // must take the loud (ERROR) path without panicking

	// Same policy, enforcement on: authorised.
	escrowMultisigMu.Lock()
	escrowMultisigEnforced = true
	escrowMultisigMu.Unlock()
	if !CGEReleasesAuthorised() {
		t.Fatal("enforcement on + policy present must authorise CGE releases")
	}
	warnCGEAuthorizationStatus() // ON path

	// Enforcement on but no policy: fail closed, still not authorised.
	escrowMultisigMu.Lock()
	escrowMultisigPolicy = nil
	escrowMultisigMu.Unlock()
	if CGEReleasesAuthorised() {
		t.Fatal("enforcement on without a policy must not authorise (fail closed)")
	}
}
