// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package storage

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// kuboStub serves the two IPFS HTTP API endpoints this package uses:
// /api/v0/add (returns cid) and /api/v0/cat (returns body). addQuery, when
// non-nil, receives the raw query string of the last add request so tests can
// assert the CID version is pinned.
func kuboStub(t *testing.T, cid string, body []byte, addQuery *string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v0/add", func(w http.ResponseWriter, r *http.Request) {
		if addQuery != nil {
			*addQuery = r.URL.RawQuery
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"Hash": cid, "Name": "payload"})
	})
	mux.HandleFunc("/api/v0/cat", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// pinataCapture records what a stubbed Pinata endpoint received.
type pinataCapture struct {
	auth     string
	path     string
	options  string
	metadata string
	fileName string
	content  []byte
	calls    int
}

// pinataStub serves the Pinata pinFileToIPFS endpoint, returning the given CID
// and status while capturing the request for assertions.
func pinataStub(t *testing.T, cid string, status int, cap *pinataCapture) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/pinning/pinFileToIPFS", func(w http.ResponseWriter, r *http.Request) {
		if cap != nil {
			cap.calls++
			cap.auth = r.Header.Get("Authorization")
			cap.path = r.URL.Path
			if err := r.ParseMultipartForm(8 << 20); err == nil {
				cap.options = r.FormValue("pinataOptions")
				cap.metadata = r.FormValue("pinataMetadata")
				if f, hdr, ferr := r.FormFile("file"); ferr == nil {
					defer f.Close()
					cap.fileName = hdr.Filename
					cap.content, _ = io.ReadAll(f)
				}
			}
		}
		w.WriteHeader(status)
		if status >= 200 && status < 300 {
			_ = json.NewEncoder(w).Encode(map[string]string{"IpfsHash": cid, "PinSize": "10"})
			return
		}
		_, _ = w.Write([]byte(`{"error":{"reason":"AUTHENTICATION_FAILED","details":"bad token"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// kuboStubFailingCat serves an /api/v0/add that succeeds while /api/v0/cat
// FAILS, modelling a partial write: the daemon accepted the block (or claims to
// have) but the bytes cannot actually be read back out of its blockstore — the
// disk-full / interrupted-write case. Read-back verification exists precisely to
// refuse to treat that as a pin.
func kuboStubFailingCat(t *testing.T, cid string, catStatus int, addStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v0/add", func(w http.ResponseWriter, r *http.Request) {
		if addStatus >= 200 && addStatus < 300 {
			_ = json.NewEncoder(w).Encode(map[string]string{"Hash": cid, "Name": "payload"})
			return
		}
		w.WriteHeader(addStatus)
		_, _ = w.Write([]byte("blockstore write failed: no space left on device"))
	})
	mux.HandleFunc("/api/v0/cat", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(catStatus)
		_, _ = w.Write([]byte("cat failed: block not found"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// hangingStub serves a Pinata endpoint that never responds, so the client's
// configured timeout is the only thing that can end the request.
func hangingStub(t *testing.T, hold time.Duration) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/pinning/pinFileToIPFS", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(hold)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func testClient(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	return NewClient(cfg)
}

// TestPinPayloadOfflineOptInIsTheOnlyFallbackPath locks in the core fix: the
// spxhash- identifier is produced ONLY in explicit offline mode, and even then
// the outcome says plainly that nothing was uploaded.
func TestPinPayloadOfflineOptInIsTheOnlyFallbackPath(t *testing.T) {
	c := testClient(Config{DisableIPFS: true, IPFSAddr: "http://127.0.0.1:5001"})
	out := c.PinPayload([]byte("hello world"), "test.txt")

	if out.Uploaded() {
		t.Fatal("offline mode must never report the payload as uploaded")
	}
	if !out.OptIn {
		t.Fatal("offline mode is an explicit opt-in and must be reported as one")
	}
	if out.Durability != DurabilityNotUploaded {
		t.Fatalf("durability: got %s want %s", out.Durability, DurabilityNotUploaded)
	}
	if !strings.HasPrefix(out.CID, "spxhash-") {
		t.Fatalf("offline mode keeps the documented spxhash- identifier, got %q", out.CID)
	}
	if !errors.Is(out.Warn, ErrNotUploaded) {
		t.Fatalf("offline mode must warn with ErrNotUploaded, got %v", out.Warn)
	}
}

// TestPinPayloadWithNoBackendReturnsNoCID is the regression guard for the bug
// this work fixes: an unreachable daemon used to yield a plausible CID that got
// anchored on-chain. It must now yield NO CID and an ErrNotUploaded warning.
func TestPinPayloadWithNoBackendReturnsNoCID(t *testing.T) {
	c := testClient(Config{IPFSAddr: "", GatewayBaseURL: "http://127.0.0.1:8080"})
	out := c.PinPayload([]byte("never uploaded"), "x.bin")

	if out.CID != "" {
		t.Fatalf("a failed upload must not invent a CID, got %q", out.CID)
	}
	if out.Uploaded() {
		t.Fatal("no backend accepted the payload; Uploaded() must be false")
	}
	if out.OptIn {
		t.Fatal("a backend failure is not an opt-in")
	}
	if !errors.Is(out.Warn, ErrNotUploaded) {
		t.Fatalf("want ErrNotUploaded, got %v", out.Warn)
	}
}

// TestPinPayloadLocalOnlyIsVerifiedAndFlaggedNotDurable covers the common
// "kubo running, no pinning service" case: the CID is read back and compared,
// and the result is explicitly non-durable.
func TestPinPayloadLocalOnlyIsVerifiedAndFlaggedNotDurable(t *testing.T) {
	payload := []byte("local payload bytes")
	var addQuery string
	srv := kuboStub(t, "bafyLOCAL", payload, &addQuery)

	c := testClient(Config{IPFSAddr: srv.URL, GatewayBaseURL: srv.URL})
	out := c.PinPayload(payload, "p.bin")

	if !out.Uploaded() || !out.Verified {
		t.Fatalf("local pin must be uploaded and read-back verified, got %+v", out)
	}
	if out.Durability != DurabilityLocalOnly || out.Source != "local" {
		t.Fatalf("local-only outcome expected, got durability=%s source=%s", out.Durability, out.Source)
	}
	if !errors.Is(out.Warn, ErrNotDurable) {
		t.Fatalf("a local-only pin must be flagged ErrNotDurable, got %v", out.Warn)
	}
	// The daemon must be asked for CIDv1, or the local CID and a pinning
	// service's CIDv1 would be different strings for identical bytes.
	if !strings.Contains(addQuery, "cid-version=1") {
		t.Fatalf("add request must pin CID version 1, got query %q", addQuery)
	}
}

// TestPinPayloadUnverifiableReadbackIsNotAPin ensures a CID that cannot be read
// back (or reads back as different bytes) is treated as a failure rather than
// committed.
func TestPinPayloadUnverifiableReadbackIsNotAPin(t *testing.T) {
	payload := []byte("the real bytes")
	// cat returns DIFFERENT bytes for the CID the daemon just "added".
	srv := kuboStub(t, "bafyWRONG", []byte("tampered bytes"), nil)

	c := testClient(Config{IPFSAddr: srv.URL, GatewayBaseURL: srv.URL})
	out := c.PinPayload(payload, "p.bin")

	if out.Uploaded() {
		t.Fatalf("a CID whose bytes do not read back must not count as pinned, got %+v", out)
	}
	if out.CID != "" {
		t.Fatalf("no CID may be committed for an unverifiable pin, got %q", out.CID)
	}
}

// TestPinPayloadMirrorsToPinataAndIsDurable is the happy path for the durable
// tier: local kubo + Pinata agree on the CID, so the outcome is remote-pinned
// with no warning and the commitment is backed by both.
func TestPinPayloadMirrorsToPinataAndIsDurable(t *testing.T) {
	payload := []byte("durably pinned bytes")
	const cid = "bafySAME"
	cap := &pinataCapture{}
	pin := pinataStub(t, cid, http.StatusOK, cap)
	kubo := kuboStub(t, cid, payload, nil)

	c := testClient(Config{
		IPFSAddr:            kubo.URL,
		GatewayBaseURL:      kubo.URL,
		PinningServiceURL:   pin.URL,
		PinningServiceToken: "test-jwt",
	})
	out := c.PinPayload(payload, "p.bin")

	if !out.Durable() {
		t.Fatalf("expected a remote-pinned outcome, got durability=%s warn=%v", out.Durability, out.Warn)
	}
	if out.Source != "local+pinata" {
		t.Fatalf("source must name both backends, got %q", out.Source)
	}
	if out.CID != cid {
		t.Fatalf("CID mismatch: got %q want %q", out.CID, cid)
	}
	if out.Warn != nil {
		t.Fatalf("a fully durable pin must not warn, got %v", out.Warn)
	}
	if cap.auth != "Bearer test-jwt" {
		t.Fatalf("pinata must receive the bearer token, got %q", cap.auth)
	}
	if string(cap.content) != string(payload) {
		t.Fatalf("pinata must receive the exact payload bytes, got %q", cap.content)
	}
	if cap.options == "" || !strings.Contains(cap.options, `"cidVersion":1`) {
		t.Fatalf("pinata must be asked for CIDv1, got options %q", cap.options)
	}
}

// TestPinPayloadRemoteCIDMismatchStaysLocalOnly documents the CID-version
// gotcha: if the durable service addresses the same bytes under a different
// identifier, that copy does not back the commitment we make, so the local CID
// is kept and the mismatch is surfaced instead of silently committed.
func TestPinPayloadRemoteCIDMismatchStaysLocalOnly(t *testing.T) {
	payload := []byte("misaddressed bytes")
	pin := pinataStub(t, "bafyDIFFERENT", http.StatusOK, nil)
	kubo := kuboStub(t, "bafyLOCALCID", payload, nil)

	c := testClient(Config{
		IPFSAddr:            kubo.URL,
		GatewayBaseURL:      kubo.URL,
		PinningServiceURL:   pin.URL,
		PinningServiceToken: "jwt",
	})
	out := c.PinPayload(payload, "p.bin")

	if out.CID != "bafyLOCALCID" {
		t.Fatalf("must keep the verified local CID, got %q", out.CID)
	}
	if out.Durable() {
		t.Fatal("a differently-addressed durable copy must not be reported as durable")
	}
	if !errors.Is(out.Warn, ErrNotDurable) {
		t.Fatalf("want an ErrNotDurable mismatch warning, got %v", out.Warn)
	}
}

// TestPinPayloadRemoteOnlyIsDurable covers a machine with no local daemon but a
// configured pinning service: the service is the only backend, and the result
// is durable.
func TestPinPayloadRemoteOnlyIsDurable(t *testing.T) {
	payload := []byte("remote only")
	pin := pinataStub(t, "bafyREMOTE", http.StatusOK, nil)

	c := testClient(Config{
		IPFSAddr:            "",
		PinningServiceURL:   pin.URL,
		PinningServiceToken: "jwt",
	})
	out := c.PinPayload(payload, "p.bin")

	if !out.Durable() || out.Source != "pinata" {
		t.Fatalf("expected a pinata-backed durable outcome, got durability=%s source=%s", out.Durability, out.Source)
	}
	if out.CID != "bafyREMOTE" {
		t.Fatalf("CID: got %q want bafyREMOTE", out.CID)
	}
	// The warning is informational here: durable, but the local tier was
	// missing, which the caller should still surface.
	if out.Warn == nil {
		t.Fatal("a remote-only pin should note that the local daemon was unavailable")
	}
	if errors.Is(out.Warn, ErrNotUploaded) {
		t.Fatal("a remote-only pin WAS uploaded; it must not report ErrNotUploaded")
	}
}

// TestPinataCIDv0IsRejected guards the identifier-consistency rule: a CIDv0
// response would not match the local daemon's CIDv1 for the same bytes, so it
// must not be accepted as backing the commitment.
func TestPinataCIDv0IsRejected(t *testing.T) {
	payload := []byte("v0 mismatch")
	// Pinata "ignores" cidVersion and hands back a v0 CID.
	pin := pinataStub(t, "QmSomeV0Cid", http.StatusOK, nil)

	c := testClient(Config{
		IPFSAddr:            "",
		PinningServiceURL:   pin.URL,
		PinningServiceToken: "jwt",
	})
	out := c.PinPayload(payload, "p.bin")

	if out.Uploaded() {
		t.Fatalf("a CIDv0-only remote result must not be reported as pinned, got %+v", out)
	}
	if !errors.Is(out.Warn, ErrNotUploaded) {
		t.Fatalf("want ErrNotUploaded, got %v", out.Warn)
	}
	if out.Warn != nil && !strings.Contains(out.Warn.Error(), "CIDv0") {
		t.Fatalf("the refusal must explain the CIDv0 reason, got %v", out.Warn)
	}
}

// TestPinataFailureReasonIsSurfaced ensures an authenticated pin failure
// surfaces Pinata's own reason instead of an opaque status code.
func TestPinataFailureReasonIsSurfaced(t *testing.T) {
	payload := []byte("rejected")
	pin := pinataStub(t, "", http.StatusUnauthorized, nil)

	c := testClient(Config{
		IPFSAddr:            "",
		PinningServiceURL:   pin.URL,
		PinningServiceToken: "bad",
	})
	out := c.PinPayload(payload, "p.bin")

	if out.Uploaded() {
		t.Fatalf("a 401 from the pinning service is not a pin, got %+v", out)
	}
	if out.Warn == nil || !strings.Contains(out.Warn.Error(), "AUTHENTICATION_FAILED") {
		t.Fatalf("the service's reason must reach the caller, got %v", out.Warn)
	}
}

// TestDefaultConfigPinningServiceEnv verifies the remote-pinning env vars are
// read, and that a token alone selects Pinata.
func TestDefaultConfigPinningServiceEnv(t *testing.T) {
	t.Setenv("SPHINX_IPFS_PINNING_TOKEN", "env-jwt")
	t.Setenv("SPHINX_IPFS_PINNING_SERVICE", "")

	cfg := DefaultConfig()
	if cfg.PinningServiceToken != "env-jwt" {
		t.Fatalf("token env not applied: %q", cfg.PinningServiceToken)
	}

	// NewClient supplies the Pinata default when only a token is given.
	c := NewClient(cfg)
	if c.cfg.PinningServiceURL != defaultPinataAPI {
		t.Fatalf("a token alone must select Pinata, got %q", c.cfg.PinningServiceURL)
	}

	t.Setenv("SPHINX_IPFS_PINNING_SERVICE", "https://pin.example.test")
	if got := DefaultConfig().PinningServiceURL; got != "https://pin.example.test" {
		t.Fatalf("service env not applied: %q", got)
	}
}

// TestPinPayloadLocalWriteFailureIsNotAPin covers a daemon that is UP but
// rejects the write (disk full, read-only blockstore, permission error): the
// add itself fails, so there is nothing to commit and no CID may be returned.
func TestPinPayloadLocalWriteFailureIsNotAPin(t *testing.T) {
	srv := kuboStubFailingCat(t, "bafyNEVER", http.StatusInternalServerError, http.StatusInternalServerError)

	c := testClient(Config{IPFSAddr: srv.URL, GatewayBaseURL: srv.URL})
	out := c.PinPayload([]byte("cannot be stored"), "p.bin")

	if out.Uploaded() {
		t.Fatalf("a rejected local write must not be reported as pinned, got %+v", out)
	}
	if out.CID != "" {
		t.Fatalf("no CID may be returned when the write failed, got %q", out.CID)
	}
	if !errors.Is(out.Warn, ErrNotUploaded) {
		t.Fatalf("want ErrNotUploaded, got %v", out.Warn)
	}
}

// TestPinPayloadPartialWriteIsNeverLocalOnly is the disk-full-mid-upload case:
// the daemon claims the add succeeded but the block cannot be read back out.
// Accepting the returned CID would commit the anchor to bytes nobody can fetch,
// so this must downgrade rather than report LocalOnly.
func TestPinPayloadPartialWriteIsNeverLocalOnly(t *testing.T) {
	srv := kuboStubFailingCat(t, "bafyPARTIAL", http.StatusInternalServerError, http.StatusOK)

	c := testClient(Config{IPFSAddr: srv.URL, GatewayBaseURL: srv.URL})
	out := c.PinPayload([]byte("half written"), "p.bin")

	if out.Uploaded() {
		t.Fatalf("a CID that cannot be read back must not count as pinned, got %+v", out)
	}
	if out.Durability == DurabilityLocalOnly {
		t.Fatal("a partial write must never be reported as local-only")
	}
	if out.CID != "" {
		t.Fatalf("no CID may be committed for an unverifiable pin, got %q", out.CID)
	}
}

// TestPinPayloadFallsBackToRemoteWhenLocalReadbackFails covers a network flap
// between the upload and the roundtrip: the local read-back fails, but the
// durable service accepted the same bytes under the same CID. The mint should
// still succeed (durably) rather than abort over a transient local failure.
func TestPinPayloadFallsBackToRemoteWhenLocalReadbackFails(t *testing.T) {
	const cid = "bafyREMOTEOK"
	// add OK, cat fails (the flap).
	kubo := kuboStubFailingCat(t, cid, http.StatusInternalServerError, http.StatusOK)
	pin := pinataStub(t, cid, http.StatusOK, nil)

	c := testClient(Config{
		IPFSAddr:            kubo.URL,
		GatewayBaseURL:      kubo.URL,
		PinningServiceURL:   pin.URL,
		PinningServiceToken: "jwt",
	})
	out := c.PinPayload([]byte("survives the flap"), "p.bin")

	if out.Durability != DurabilityRemotePinned {
		t.Fatalf("expected the durable service to carry the mint, got durability=%s warn=%v", out.Durability, out.Warn)
	}
	if out.Source != "pinata" {
		t.Fatalf("the local tier failed verification, so source must be the service alone, got %q", out.Source)
	}
	if out.CID != cid {
		t.Fatalf("CID: got %q want %q", out.CID, cid)
	}
}

// TestPinPayloadExpiredTokenDegradesToLocalOnly covers a configured pinning
// service whose token is invalid/expired. That must degrade to a loud
// local-only result — NOT silently claim durability, and not fail the mint when
// a perfectly good local pin exists.
func TestPinPayloadExpiredTokenDegradesToLocalOnly(t *testing.T) {
	payload := []byte("local still works")
	kubo := kuboStub(t, "bafyLOCALONLY", payload, nil)
	pin := pinataStub(t, "", http.StatusUnauthorized, nil)

	c := testClient(Config{
		IPFSAddr:            kubo.URL,
		GatewayBaseURL:      kubo.URL,
		PinningServiceURL:   pin.URL,
		PinningServiceToken: "expired",
	})
	out := c.PinPayload(payload, "p.bin")

	if out.Durability != DurabilityLocalOnly || !out.Uploaded() {
		t.Fatalf("an expired token must degrade to local-only, got %+v", out)
	}
	if out.Durable() {
		t.Fatal("a rejected mirror must never be reported as durable")
	}
	if !errors.Is(out.Warn, ErrNotDurable) {
		t.Fatalf("want an ErrNotDurable warning, got %v", out.Warn)
	}
	if out.Warn == nil || !strings.Contains(out.Warn.Error(), "AUTHENTICATION_FAILED") {
		t.Fatalf("the service's own reason must be surfaced, got %v", out.Warn)
	}
}

// TestPinPayloadHangingServiceIsBoundedByTimeout ensures a pinning service that
// accepts the connection and then never responds cannot hang a mint. The
// client's configured timeout must end it, and the result must be an honest
// NotUploaded rather than an indefinitely-blocked dialog.
func TestPinPayloadHangingServiceIsBoundedByTimeout(t *testing.T) {
	// Never responds; only the client timeout can end the request.
	pin := hangingStub(t, 2*time.Second)

	c := NewClient(Config{
		// A closed port: the local tier fails fast so the hang is the only
		// remaining path under test.
		IPFSAddr:            "http://127.0.0.1:9",
		PinningServiceURL:   pin.URL,
		PinningServiceToken: "jwt",
		Timeout:             200 * time.Millisecond,
	})

	start := time.Now()
	out := c.PinPayload([]byte("hangs"), "p.bin")
	elapsed := time.Since(start)

	if out.Uploaded() || out.CID != "" {
		t.Fatalf("a hung service must yield nothing to commit, got %+v", out)
	}
	if !errors.Is(out.Warn, ErrNotUploaded) {
		t.Fatalf("want ErrNotUploaded, got %v", out.Warn)
	}
	// Bounded well below the server's 2s hold: proves the timeout, not the
	// server, ended the request.
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("a hanging service must be cut off by the client timeout, took %s", elapsed)
	}
}

// gatewayStub serves the /ipfs/<cid> gateway path with a fixed status, so
// retrievability can be tested without touching the network.
func gatewayStub(t *testing.T, status int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ipfs/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if status >= 200 && status < 300 {
			_, _ = w.Write([]byte("x"))
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestProbeCIDDoesNotDownloadThePayload guards the reason ProbeCID exists: a
// "is this still pinned?" check must not transfer the whole payload. The stub
// writes exactly one byte, and the probe must never read more than that.
func TestProbeCIDDoesNotDownloadThePayload(t *testing.T) {
	var served int64
	mux := http.NewServeMux()
	mux.HandleFunc("/ipfs/", func(w http.ResponseWriter, r *http.Request) {
		// Honour Range like a real gateway: one byte, not the whole object.
		w.Header().Set("Content-Length", "1")
		w.WriteHeader(http.StatusPartialContent)
		n, _ := w.Write([]byte("x"))
		served += int64(n)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := testClient(Config{GatewayBaseURL: srv.URL, Timeout: 5 * time.Second})
	if err := c.ProbeCID("bafySOMETHING"); err != nil {
		t.Fatalf("ProbeCID: %v", err)
	}
	if served > 1 {
		t.Fatalf("a retrievability probe must not download the payload; server wrote %d bytes", served)
	}
}

// TestProbeCIDStatusCoverage pins the status handling: only a 2xx counts as
// retrievable, so a gateway 404 (unpinned/unknown CID) is a negative answer
// rather than a silent success.
func TestProbeCIDStatusCoverage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		wantErr bool
	}{
		{"ok", http.StatusOK, false},
		{"partial content (honoured Range)", http.StatusPartialContent, false},
		{"not found (not pinned here)", http.StatusNotFound, true},
		{"gateway error", http.StatusInternalServerError, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := gatewayStub(t, tc.status)
			c := testClient(Config{GatewayBaseURL: srv.URL})
			err := c.ProbeCID("bafyX")
			if tc.wantErr && err == nil {
				t.Fatalf("status %d must not count as retrievable", tc.status)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("status %d must count as retrievable, got %v", tc.status, err)
			}
		})
	}

	// No gateway configured is an error, never a verdict.
	if err := testClient(Config{GatewayBaseURL: ""}).ProbeCID("bafyX"); err == nil {
		t.Fatal("an empty gateway URL must be an error")
	}
	if err := testClient(Config{DisableIPFS: true, GatewayBaseURL: "http://x"}).ProbeCID("bafyX"); err == nil {
		t.Fatal("offline mode must not claim a probe result")
	}
}

// TestCheckRetrievabilityVerdicts covers the classification a user acts on,
// using stubs so no external network is touched:
//
//	not-uploaded   — spxhash- identifier: nothing was ever uploaded
//	remote-pinned  — a NON-local gateway served it
//	local-only     — only this machine could
//	not-reachable  — a real CID, but nobody could serve it
func TestCheckRetrievabilityVerdicts(t *testing.T) {
	// 1. A local-only commitment is never probed, and never called unreachable.
	localOnlyClient := testClient(Config{
		GatewayBaseURL:   "http://127.0.0.1:9",
		PublicGatewayURL: "http://127.0.0.1:9",
	})
	got, err := localOnlyClient.CheckRetrievability("spxhash-abc123")
	if err != nil {
		t.Fatalf("a local-only commitment must not error: %v", err)
	}
	if got != DurabilityNotUploaded {
		t.Fatalf("spxhash- must classify as not-uploaded, got %s", got)
	}

	// 2. A public gateway serving it => remote-pinned, even with no local daemon.
	publicGW := gatewayStub(t, http.StatusOK)
	remoteClient := testClient(Config{
		IPFSAddr:         "http://127.0.0.1:9",
		GatewayBaseURL:   "http://127.0.0.1:9",
		PublicGatewayURL: publicGW.URL,
	})
	got, err = remoteClient.CheckRetrievability("bafyREMOTE")
	if err != nil {
		t.Fatalf("CheckRetrievability: %v", err)
	}
	if got != DurabilityRemotePinned {
		t.Fatalf("a public gateway serving the CID must be remote-pinned, got %s", got)
	}

	// 3. Only the LOCAL gateway has it => local-only, never remote-pinned.
	localGW := gatewayStub(t, http.StatusOK)
	localClient := testClient(Config{
		GatewayBaseURL:   localGW.URL, // httptest binds 127.0.0.1 => local
		PublicGatewayURL: "http://127.0.0.1:9",
	})
	if !IsLocalGatewayURL(localGW.URL) {
		t.Fatal("an httptest gateway is on this host and must be treated as local")
	}
	got, err = localClient.CheckRetrievability("bafyLOCAL")
	if err != nil {
		t.Fatalf("CheckRetrievability: %v", err)
	}
	if got != DurabilityLocalOnly {
		t.Fatalf("a localhost gateway must classify as local-only, got %s", got)
	}

	// 4. Nobody can serve it => not-reachable, which is DISTINCT from
	// not-uploaded: a real CID existed and might come back.
	deadClient := testClient(Config{
		IPFSAddr:         "http://127.0.0.1:9",
		GatewayBaseURL:   "http://127.0.0.1:9",
		PublicGatewayURL: "http://127.0.0.1:9",
	})
	got, err = deadClient.CheckRetrievability("bafyGONE")
	if err != nil {
		t.Fatalf("CheckRetrievability: %v", err)
	}
	if got != DurabilityNotReachable {
		t.Fatalf("an unreachable real CID must classify as not-reachable, got %s", got)
	}
	if got == DurabilityNotUploaded {
		t.Fatal("not-reachable must not collapse into not-uploaded — the remedies differ")
	}

	// An empty CID is a caller error, not a verdict.
	if _, err := deadClient.CheckRetrievability(""); err == nil {
		t.Fatal("an empty CID must be an error")
	}
}
