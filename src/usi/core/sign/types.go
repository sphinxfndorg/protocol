// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/sign/types.go
package sign

import "github.com/sphinxfndorg/protocol/src/usi/core/types"

// Re-export Meta from types package for backward compatibility
type Meta = types.Meta

// Signature holds the raw SPHINCS+ signature bytes together with the
// public key that should be used for verification.
type Signature struct {
	Signature []byte `json:"sig"`
	PublicKey []byte `json:"pk,omitempty"`
}

// VerificationResult is a tri-state that lets callers distinguish between a
// fully verified signature (signed by a known registered identity), an
// integrity-only result (cryptographically self-consistent but signer identity
// was NOT verified against a directory), and an invalid result (tampered,
// forged, or revoked).
//
// The SPHINCS+ signature alone only proves "this content matches whatever
// signature and key sit in this file's metadata" — that is tamper-evidence
// against accidental corruption, but not authenticity against a deliberate
// forger, since nothing stops an attacker from replacing all three (content,
// signature, key) consistently. VerificationResult makes this distinction
// explicit so the GUI and API consumers can render the two cases differently.
type VerificationResult int

const (
	// VerificationInvalid means the signature is invalid, the file was
	// tampered with, or the signer's key was revoked / not-registered in the
	// directory. This is a hard failure — the file should not be trusted.
	VerificationInvalid VerificationResult = iota

	// VerificationIntegrityOnly means the signature is self-consistent — it
	// verifies against the embedded public key, and the file hash matches —
	// but the signer's identity could NOT be verified against a directory.
	// This happens when the resolver is nil (offline field use), the
	// directory is unreachable (network error), or no directory has been
	// configured. The file is tamper-evident against accidental corruption
	// but NOT authenticated against a deliberate forger.
	VerificationIntegrityOnly

	// VerificationFullyVerified means the signature is valid AND the signer's
	// public key is registered, active, and org-bound in the directory. This
	// is the only result that provides authenticity (proof of who signed).
	VerificationFullyVerified
)

// String returns a human-readable label for the verification result.
func (r VerificationResult) String() string {
	switch r {
	case VerificationInvalid:
		return "INVALID"
	case VerificationIntegrityOnly:
		return "INTEGRITY_ONLY"
	case VerificationFullyVerified:
		return "FULLY_VERIFIED"
	default:
		return "UNKNOWN"
	}
}

// IsValid returns true if the result is either IntegrityOnly or FullyVerified.
// This is a convenience for callers that only need to know whether the file
// is tamper-evident, without distinguishing the assurance level.
func (r VerificationResult) IsValid() bool {
	return r == VerificationIntegrityOnly || r == VerificationFullyVerified
}

// IsFullyVerified returns true only when the signature was verified against a
// known, registered, active directory key — i.e. authenticity was confirmed.
func (r VerificationResult) IsFullyVerified() bool {
	return r == VerificationFullyVerified
}
