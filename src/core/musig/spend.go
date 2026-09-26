// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package multisig

import (
	"fmt"
	"math/big"
	"strings"
)

// SpendMessage is the canonical message an M-of-N custody policy authorizes
// for an outgoing spend. It binds the custody policy's domain, the chain, the
// custodial source address, the destination, the amount, the account nonce and
// the witness expiry — so a collected witness can never be rebound to a
// different spend. The account nonce is part of the message on purpose: the
// vault/escrow account carries an ordinary account nonce like any sender, and
// cosigners must agree on that value before signing (see CheckSpendWitness).
func SpendMessage(policy *MultiPartyPolicy, chainID uint64, from, to string, amount *big.Int, nonce, expiry uint64) []byte {
	var amt []byte
	if amount != nil {
		amt = amount.Bytes()
	}
	return CustodyReleaseMessage(policy.Domain, chainID, from, to, amt, nonce, expiry)
}

// CheckSpendWitness resolves from to a registered custody policy and, when one
// is registered, requires w to carry a threshold-valid authorization for
// exactly (chainID, from, to, amount, nonce) under that policy.
//
// Registered policy is authoritative: the copy of the policy embedded in the
// witness is only cross-checked, never used for verification, so a submitter
// cannot substitute its own custodian set and sign with its own keys.
//
// refTime is the expiry reference (the sealed block header timestamp in the
// block-validation path, 0 where no block is available and only the offline
// expiry checks apply). It is never a wall clock.
//
// ok==false means from is not a custody address and the caller must fall back
// to ordinary single-key authorization. ok==true with a non-nil error means
// the address IS custodial and the witness failed — there is deliberately no
// single-key fallback for a custody address, so a custody spend is fail-closed
// exactly as a missing bundle is.
func CheckSpendWitness(from, to string, chainID uint64, amount *big.Int, nonce uint64, w *MultiSigWitness, refTime uint64) (ok bool, err error) {
	policy, registered := LookupPolicy(from)
	if !registered {
		return false, nil
	}
	if w == nil {
		return true, fmt.Errorf("custody address %s requires an M-of-N witness", from)
	}
	active := GetActiveChainID()
	if active == 0 {
		return true, ErrActiveChainIDUnset
	}
	if chainID != active {
		return true, fmt.Errorf("custody authorization is bound to chain %d but this chain is %d", chainID, active)
	}
	if len(w.Sigs) == 0 {
		return true, fmt.Errorf("witness for custody address %s carries no signatures", from)
	}
	if len(w.Policy.PubKeys) > 0 {
		addr, aerr := w.Policy.Address()
		if aerr != nil {
			return true, fmt.Errorf("witness policy is invalid: %w", aerr)
		}
		if !strings.EqualFold(addr, from) {
			return true, fmt.Errorf("witness policy resolves to %s, not custody address %s", addr, from)
		}
	} else if w.Policy.Domain != "" && w.Policy.Domain != policy.Domain {
		return true, fmt.Errorf("witness domain %q does not match custody domain %q", w.Policy.Domain, policy.Domain)
	}
	if err := ValidateWitnessExpiry(w.Expiry, refTime); err != nil {
		return true, err
	}
	witness := *w
	witness.Policy = *policy
	msg := SpendMessage(policy, chainID, from, to, amount, nonce, w.Expiry)
	if !VerifyThreshold(msg, witness, refTime) {
		return true, fmt.Errorf("custody witness for %s is below threshold %d or does not authorize this spend",
			from, policy.Threshold)
	}
	return true, nil
}
