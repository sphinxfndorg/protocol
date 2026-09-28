// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package multisig

import (
	"encoding/binary"

	"github.com/sphinxfndorg/protocol/src/common"
)

// canonicalRecipient canonicalizes a recipient address for the signed
// message. It is common.CanonicalAddress (pass-through for non-address
// inputs like system ids) — the SAME function cge_witness.go uses on its
// side — so signer and verifier can never drift: one function, one
// canonical string, shared across all three message constructors.
func canonicalRecipient(addr string) string {
	return common.CanonicalAddress(addr)
}

// Note: recipient matching must go through lookupTimeBasedCGEAllocation
// (exact or EqualFold against canonical allocation addresses) and message
// binding through canonicalRecipient — never a bare case fold here, which
// would paper over a mismatch the exact-case execution path does not
// tolerate.

func CustodyReleaseMessage(domain string, chainID uint64, escrow, recipient string, amount []byte, nonce uint64, expiry uint64) []byte {
	buf := make([]byte, 0, 128)
	buf = append(buf, []byte(domain)...)
	buf = append(buf, 0x00)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], chainID)
	buf = append(buf, tmp[:]...)
	buf = append(buf, []byte(canonicalRecipient(escrow))...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte(canonicalRecipient(recipient))...)
	buf = append(buf, 0x00)
	buf = append(buf, amount...)
	buf = append(buf, 0x00)
	binary.BigEndian.PutUint64(tmp[:], nonce)
	buf = append(buf, tmp[:]...)
	binary.BigEndian.PutUint64(tmp[:], expiry)
	buf = append(buf, tmp[:]...)
	return common.SpxHash(buf)
}

func DevModuleReleaseMessage(domain string, chainID uint64, escrow, recipient string, moduleID uint64, expiry uint64) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, []byte(domain)...)
	buf = append(buf, 0x00)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], chainID)
	buf = append(buf, tmp[:]...)
	buf = append(buf, []byte(canonicalRecipient(escrow))...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte(canonicalRecipient(recipient))...)
	buf = append(buf, 0x00)
	binary.BigEndian.PutUint64(tmp[:], moduleID)
	buf = append(buf, tmp[:]...)
	binary.BigEndian.PutUint64(tmp[:], expiry)
	buf = append(buf, tmp[:]...)
	return common.SpxHash(buf)
}

// CGEVestingReleaseMessage binds a time-based CGE escrow release to its
// MILESTONE — the cumulative unlocked target — rather than to a block
// height.
//
// ★ WHY NOT HEIGHT: a witness bound to one exact height authorizes exactly
// one block. A release that lands anywhere else (missed slot, view-change
// delay, any timing variance) skips, and the witness stays dead for the
// rest of the cliff window. A vesting cliff is a threshold crossed, not a
// single block hit on time. Binding the cumulative target makes the witness
// durable: it authorizes whichever block in the window actually lands the
// release, and it can never authorize a different release — after the
// milestone lands, released advances, so a later block rebuilds the message
// with a different target (and usually a different delta) and the stale
// witness fails closed. Same-month replays are harmless: delta recomputes
// to zero, so there is nothing left to authorize.
//
// milestone is the cumulative unlocked total in nSPX
// (policy schedule UnlockedAt(elapsed, allocation)), NOT the per-block
// delta. delta is what moves now; milestone names which release this is.
// Both are bound because the same delta amount can recur across tranches
// (e.g. four identical 25% Founder tranches) — the milestone is what tells
// them apart.
//
// Domain separation from SpendMessage and DevModuleReleaseMessage is
// structural (same discipline as the existing pair): the extra milestone
// field plus the 0x00 separators make the pre-hash buffer a different
// length and shape than either sibling for any attacker-chosen fields, and
// a cross-protocol replay would still need a second preimage on SpxHash.
func CGEVestingReleaseMessage(domain string, chainID uint64, escrow, recipient string, delta, milestone []byte, expiry uint64) []byte {
	buf := make([]byte, 0, 160)
	buf = append(buf, []byte(domain)...)
	buf = append(buf, 0x00)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], chainID)
	buf = append(buf, tmp[:]...)
	buf = append(buf, []byte(canonicalRecipient(escrow))...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte(canonicalRecipient(recipient))...)
	buf = append(buf, 0x00)
	buf = append(buf, delta...)
	buf = append(buf, 0x00)
	buf = append(buf, milestone...)
	buf = append(buf, 0x00)
	binary.BigEndian.PutUint64(tmp[:], expiry)
	buf = append(buf, tmp[:]...)
	return common.SpxHash(buf)
}
