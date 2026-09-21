// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/mint_verify_test.go
package utils

import (
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/storage"
)

// TestIsLocalOnlyCommitment covers the classification that makes
// "sphinx ipfs verify" able to say "NEVER UPLOADED" instead of reporting an
// opaque fetch failure. A spxhash- value is content-addressed and stable, so it
// round-trips through the on-chain CID commitment and looks superficially
// legitimate — which is exactly why the distinction must be explicit. It now
// lives in the storage package so the CLI and the wallet GUI share it.
func TestIsLocalOnlyCommitment(t *testing.T) {
	cases := []struct {
		name string
		cid  string
		want bool
	}{
		{"local content hash", "spxhash-723a7f8b07b5907ccd8f7b81fee77c299a143756ae83d715482da722012a0299", true},
		{"local content hash with padding", "  spxhash-abc123  ", true},
		{"real CIDv1", "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi", false},
		{"real CIDv0", "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG", false},
		{"empty", "", false},
		// Only the exact prefix counts: a real CID that merely contains the
		// substring must not be misclassified as never-uploaded.
		{"substring not prefix", "bafyspxhash-abc", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := storage.IsLocalOnlyCommitment(tc.cid); got != tc.want {
				t.Fatalf("IsLocalOnlyCommitment(%q) = %v, want %v", tc.cid, got, tc.want)
			}
		})
	}
}

// TestIsLocalGatewayURL guards the durability verdict: a fetch that succeeds
// against a gateway on this machine proves only that the local daemon still has
// the bytes, so it must not be reported as durably pinned.
func TestIsLocalGatewayURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"http://127.0.0.1:8080", true},
		{"http://localhost:8080", true},
		{"http://LOCALHOST:8080", true},
		{"http://[::1]:8080", true},
		{"http://0.0.0.0:8080", true},
		{"https://ipfs.io", false},
		{"https://gateway.pinata.cloud", false},
		{"http://10.0.0.5:8080", false},
		{"", false},
		{"not a url", false},
	}
	for _, tc := range cases {
		if got := storage.IsLocalGatewayURL(tc.url); got != tc.want {
			t.Fatalf("IsLocalGatewayURL(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

// TestDurabilityStringsAreStable keeps the machine-readable verdicts stable, so
// scripts can compare against a documented string rather than parsing prose.
// They are shared with the wallet GUI (storage.Durability.String), so a change
// here is user-visible on both surfaces. They must also be distinct — a
// collapse would make "local-only" and "not-uploaded" indistinguishable.
func TestDurabilityStringsAreStable(t *testing.T) {
	want := map[storage.Durability]string{
		storage.DurabilityNotUploaded:  "not-uploaded",
		storage.DurabilityNotReachable: "not-reachable",
		storage.DurabilityLocalOnly:    "local-only",
		storage.DurabilityRemotePinned: "remote-pinned",
	}
	seen := map[string]bool{}
	for d, expected := range want {
		got := d.String()
		if got != expected {
			t.Fatalf("durability %d renders %q, want %q", d, got, expected)
		}
		if seen[got] {
			t.Fatalf("durability verdict %q is not distinct", got)
		}
		seen[got] = true
	}
}

// TestVerifyDurabilityDecisionTable pins the verdict a user acts on. The
// important cases: a gateway on THIS machine is not evidence of durability, and
// a local-only success must be reported as local-only rather than reachable.
// The decision table lives in the storage package so the CLI and the wallet GUI
// cannot describe the same state differently.
func TestVerifyDurabilityDecisionTable(t *testing.T) {
	cases := []struct {
		name     string
		remoteOK bool
		localOK  bool
		want     storage.Durability
	}{
		{"a public gateway served it", true, false, storage.DurabilityRemotePinned},
		{"public served it, local also has it", true, true, storage.DurabilityRemotePinned},
		{"only local infrastructure served it", false, true, storage.DurabilityLocalOnly},
		{"nobody could serve it", false, false, storage.DurabilityNotReachable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := storage.ClassifyRetrievability(tc.remoteOK, tc.localOK); got != tc.want {
				t.Fatalf("ClassifyRetrievability(%v, %v) = %s, want %s",
					tc.remoteOK, tc.localOK, got, tc.want)
			}
		})
	}

	// A local-only success must never be labelled durable: that daemon going
	// offline is precisely the failure this verdict warns about.
	if got := storage.ClassifyRetrievability(false, true); got == storage.DurabilityRemotePinned {
		t.Fatal("a local-only fetch must never be reported as remotely pinned")
	}
}

// TestFileMatchesRecordedCID is the security check that makes "ipfs repin"
// safe. A local-only commitment (spxhash-<hash of the original bytes>) can be
// recomputed from a candidate file, so a re-pin can PROVE it is pushing the
// bytes the anchor describes. Without this, repin would happily publish an
// arbitrary file under someone's on-chain commitment.
func TestFileMatchesRecordedCID(t *testing.T) {
	original := []byte("the original document bytes")
	other := []byte("a completely different document")

	localCID := storage.FallbackCIDFor(original)
	if !strings.HasPrefix(localCID, "spxhash-") {
		t.Fatalf("expected a local-only identifier, got %q", localCID)
	}

	// The genuine original: verifiable and matching.
	matches, checkable, expected := fileMatchesRecordedCID(localCID, original)
	if !checkable || !matches {
		t.Fatalf("the original must verify against its own commitment: matches=%v checkable=%v", matches, checkable)
	}
	if expected != localCID {
		t.Fatalf("expected identifier must be reported for diagnostics: got %q want %q", expected, localCID)
	}

	// A different file must be refused, and the mismatch must be explainable.
	matches, checkable, expected = fileMatchesRecordedCID(localCID, other)
	if !checkable {
		t.Fatal("a local-only commitment must always be checkable")
	}
	if matches {
		t.Fatal("a different file must never verify against the anchor's commitment")
	}
	if expected == localCID {
		t.Fatal("the expected identifier must differ for a non-matching file")
	}
	// Sanity: the reported expectation really is a function of the given bytes.
	if expected != storage.FallbackCIDFor(other) {
		t.Fatalf("expected identifier must be derived from the supplied file: got %q", expected)
	}

	// Single-byte tampering must be caught — the check is on exact bytes.
	tampered := append([]byte{}, original...)
	tampered[len(tampered)-1] ^= 0x01
	if matches, checkable, _ := fileMatchesRecordedCID(localCID, tampered); matches || !checkable {
		t.Fatal("single-byte tampering must be detected")
	}

	// A real CID is NOT locally recomputable, so the check reports itself as
	// unavailable rather than guessing (and never as a false "match").
	for _, realCID := range []string{
		"bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		"QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
		"",
	} {
		matches, checkable, expected := fileMatchesRecordedCID(realCID, original)
		if checkable {
			t.Fatalf("a real/empty CID (%q) must not be reported as locally checkable", realCID)
		}
		if matches {
			t.Fatalf("a non-checkable CID (%q) must never report a match", realCID)
		}
		if expected != "" {
			t.Fatalf("no expected identifier may be invented for %q, got %q", realCID, expected)
		}
	}
}

// TestBuildAndParseAnchorPayloadRoundTrip locks in the on-chain commitment
// shape the verify command reads back: the CID and its hash must survive the
// ReturnData round-trip verbatim, because ValidateAnchorData recomputes the
// binding from exactly these bytes.
func TestBuildAndParseAnchorPayloadRoundTrip(t *testing.T) {
	const (
		mintID  = "554f471215ed560292c81f13f6cb3b56be373b906bcc06a843997922be07dbb2"
		subject = "Freedom Document"
		cid     = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	)
	cidHash := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

	data := buildAnchorPayload(mintID, subject, cid, cidHash)
	parsed, err := parseAnchorPayload(data)
	if err != nil {
		t.Fatalf("parseAnchorPayload: %v", err)
	}
	if parsed.MintID != mintID || parsed.Subject != subject {
		t.Fatalf("identity fields did not round-trip: %+v", parsed)
	}
	if parsed.CID != cid || parsed.CIDHashHex != cidHash {
		t.Fatalf("commitment fields did not round-trip: cid=%q hash=%q", parsed.CID, parsed.CIDHashHex)
	}

	// An incomplete payload must be rejected rather than silently yielding an
	// empty CID (which a verify would then report as merely unreachable).
	if _, err := parseAnchorPayload([]byte(`{"mid":"x"}`)); err == nil {
		t.Fatal("an anchor payload missing cid/cid_hash_hex must be rejected")
	}
	if _, err := parseAnchorPayload([]byte(`not json`)); err == nil {
		t.Fatal("a non-JSON anchor payload must be rejected")
	}
}
