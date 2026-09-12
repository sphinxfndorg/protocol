// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/sign/verification_result_test.go
package sign

import (
	"errors"
	"testing"

	pubkeydir "github.com/sphinxfndorg/protocol/src/usi/server/server"
)

// stubResolver is a deterministic in-memory orgBundleResolver for tests.
type stubResolver struct {
	bundle pubkeydir.PublicKeyBundle
	err    error
}

func (s *stubResolver) LookupByPublicKey(pubKeyHex string) (pubkeydir.PublicKeyBundle, error) {
	if s.err != nil {
		return pubkeydir.PublicKeyBundle{}, s.err
	}
	return s.bundle, nil
}

func (s *stubResolver) Close() error { return nil }

const testPubKeyHex = "aabbccdd"

func TestVerificationResultOrdering(t *testing.T) {
	// recordResult in VerifyUniversal relies on Invalid < IntegrityOnly <
	// FullyVerified. If the iota order changes, best-channel tracking breaks.
	if !(VerificationInvalid < VerificationIntegrityOnly && VerificationIntegrityOnly < VerificationFullyVerified) {
		t.Fatalf("tri-state iota order is wrong: Invalid=%d IntegrityOnly=%d FullyVerified=%d",
			VerificationInvalid, VerificationIntegrityOnly, VerificationFullyVerified)
	}
}

func TestVerificationResultLabels(t *testing.T) {
	if VerificationInvalid.String() != "INVALID" ||
		VerificationIntegrityOnly.String() != "INTEGRITY_ONLY" ||
		VerificationFullyVerified.String() != "FULLY_VERIFIED" {
		t.Fatalf("String() labels wrong: %s %s %s",
			VerificationInvalid, VerificationIntegrityOnly, VerificationFullyVerified)
	}
	if VerificationInvalid.IsValid() {
		t.Fatal("INVALID must not be IsValid()")
	}
	if !VerificationIntegrityOnly.IsValid() || !VerificationFullyVerified.IsValid() {
		t.Fatal("IntegrityOnly and FullyVerified must be IsValid()")
	}
	if VerificationIntegrityOnly.IsFullyVerified() || VerificationInvalid.IsFullyVerified() {
		t.Fatal("only FullyVerified may be IsFullyVerified()")
	}
	if !VerificationFullyVerified.IsFullyVerified() {
		t.Fatal("FullyVerified must be IsFullyVerified()")
	}
}

func TestValidateOrgBindingNilResolverSoftSkips(t *testing.T) {
	// Offline field use: resolver nil must soft-skip, NOT hard-fail.
	meta := &Meta{PublicKey: testPubKeyHex}
	verified, err := validateOrgBinding(meta, nil)
	if err != nil {
		t.Fatalf("nil resolver must soft-skip (err=nil), got: %v", err)
	}
	if verified {
		t.Fatal("nil resolver must NOT report binding as verified")
	}
}

func TestValidateOrgBindingMissingKeyHardFails(t *testing.T) {
	meta := &Meta{PublicKey: ""}
	verified, err := validateOrgBinding(meta, &stubResolver{})
	if err == nil {
		t.Fatal("missing public key must hard-fail")
	}
	if verified {
		t.Fatal("missing public key must not report verified")
	}
}

func TestValidateOrgBindingNotRegisteredHardFails(t *testing.T) {
	// The exact attack: a freshly generated unregistered key in the file.
	// This must be a hard failure — the old code logged and continued.
	meta := &Meta{PublicKey: testPubKeyHex, OrgCode: "SPIF"}
	verified, err := validateOrgBinding(meta, &stubResolver{err: pubkeydir.ErrNotFound})
	if err == nil {
		t.Fatal("unregistered key must hard-fail, not warn-and-continue")
	}
	if verified {
		t.Fatal("unregistered key must not report verified")
	}
	if !errors.Is(err, pubkeydir.ErrNotFound) {
		t.Fatalf("unregistered key error should wrap ErrNotFound, got: %v", err)
	}
}

func TestValidateOrgBindingRevokedHardFails(t *testing.T) {
	meta := &Meta{PublicKey: testPubKeyHex, OrgCode: "SPIF"}
	verified, err := validateOrgBinding(meta, &stubResolver{
		bundle: pubkeydir.PublicKeyBundle{
			Status:           pubkeydir.StatusRevoked,
			RevocationReason: "key compromise",
			Organization:     "SPIF",
		},
	})
	if err == nil {
		t.Fatal("revoked key must hard-fail")
	}
	if verified {
		t.Fatal("revoked key must not report verified")
	}
}

func TestValidateOrgBindingMismatchHardFails(t *testing.T) {
	meta := &Meta{PublicKey: testPubKeyHex, OrgCode: "SPIF"}
	verified, err := validateOrgBinding(meta, &stubResolver{
		bundle: pubkeydir.PublicKeyBundle{Status: "active", Organization: "OTHER"},
	})
	if err == nil {
		t.Fatal("org mismatch must hard-fail")
	}
	if verified {
		t.Fatal("org mismatch must not report verified")
	}
}

func TestValidateOrgBindingRegisteredActiveVerified(t *testing.T) {
	meta := &Meta{PublicKey: testPubKeyHex, OrgCode: "SPIF"}
	verified, err := validateOrgBinding(meta, &stubResolver{
		bundle: pubkeydir.PublicKeyBundle{Status: "active", Organization: "SPIF"},
	})
	if err != nil {
		t.Fatalf("registered active key with matching org must verify, got: %v", err)
	}
	if !verified {
		t.Fatal("registered active key with matching org must report verified")
	}
}

func TestCheckOrgBindingNilMetaPublicKeyFails(t *testing.T) {
	// checkOrgBinding is the fail-closed gate: an empty embedded public key
	// can never be FullyVerified.
	meta := &Meta{PublicKey: ""}
	result, err := checkOrgBinding(meta)
	if err == nil {
		t.Fatal("empty public key must hard-fail the binding gate")
	}
	if result != VerificationInvalid {
		t.Fatalf("empty public key must yield VerificationInvalid, got %s", result)
	}
}
