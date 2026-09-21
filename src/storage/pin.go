// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package storage

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/sphinxfndorg/protocol/src/common"
)

// ErrNotUploaded reports that no IPFS backend accepted the payload: nothing
// left this machine, no retrievable CID exists, and no CID may be committed.
//
// It exists so callers can branch on the failure instead of string-matching an
// error, and — critically — so a mint can never again mistake a local content
// hash for a real pin.
var ErrNotUploaded = errors.New("payload was not uploaded to IPFS")

// ErrNotDurable reports that the payload IS pinned, but only on this machine's
// local daemon: it becomes unreachable as soon as that daemon goes offline.
// This is a retrievability warning, not an upload failure — callers should
// surface it (and can still commit the CID) rather than treat it as fatal.
var ErrNotDurable = errors.New("pinned only to a local IPFS daemon (not durable)")

// Durability describes how retrievable a pinned payload actually is.
type Durability int

const (
	// DurabilityNotUploaded means nothing was uploaded: the bytes never left
	// this machine and any identifier returned is a local content hash
	// (spxhash-…), NOT a retrievable IPFS CID.
	DurabilityNotUploaded Durability = iota
	// DurabilityLocalOnly means the bytes are in a local IPFS daemon's
	// blockstore. They are retrievable only while that daemon stays online
	// and is found by peers — NOT durable, and dependent on this machine.
	DurabilityLocalOnly
	// DurabilityRemotePinned means a remote pinning service accepted and
	// pinned the bytes, so retrievability does not depend on this machine.
	DurabilityRemotePinned
	// DurabilityNotReachable is the RE-CHECK outcome for an existing
	// commitment: a real CID was recorded, but neither a public gateway nor
	// the local daemon could serve the bytes just now. It is distinct from
	// DurabilityNotUploaded (which means no CID ever existed) because the
	// remedies differ: an unreachable pin may come back when a daemon or
	// gateway is online, whereas a local-only commitment never will.
	DurabilityNotReachable
)

func (d Durability) String() string {
	switch d {
	case DurabilityRemotePinned:
		return "remote-pinned"
	case DurabilityLocalOnly:
		return "local-only"
	case DurabilityNotReachable:
		return "not-reachable"
	default:
		return "not-uploaded"
	}
}

// ClassifyRetrievability turns the outcomes of the two reachability probes into
// a single verdict. It is the shared decision table for every surface that
// reports retrievability (the wallet GUI and the CLI's "ipfs verify"), so the
// same underlying state can never be described two different ways.
//
//	remoteOK — a NON-LOCAL gateway served the bytes, which is the only result
//	           that proves retrievability does not depend on this machine
//	localOK  — only local infrastructure served them: the daemon's blockstore,
//	           or a gateway running on this host
//
// A local success is never reported as remote-pinned: that daemon going offline
// is precisely the failure the verdict exists to warn about.
func ClassifyRetrievability(remoteOK, localOK bool) Durability {
	switch {
	case remoteOK:
		return DurabilityRemotePinned
	case localOK:
		return DurabilityLocalOnly
	default:
		return DurabilityNotReachable
	}
}

// IsLocalGatewayURL reports whether a gateway URL points at this machine, in
// which case a successful fetch proves only that the LOCAL node still has the
// bytes — not that anyone else can reach them.
func IsLocalGatewayURL(gatewayBaseURL string) bool {
	u, err := url.Parse(strings.TrimSpace(gatewayBaseURL))
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	}
	return false
}

// PinOutcome is the full, honest result of a resilient pin: the identifier to
// commit to, PLUS how durable that commitment is and where it came from.
//
// It replaces the old silent-fallback contract, under which an unreachable
// daemon still produced a plausible-looking CID that callers committed on-chain
// with no way to tell it was never uploaded.
type PinOutcome struct {
	// CID is the identifier to commit to. Empty when nothing was uploaded
	// (DurabilityNotUploaded with OptIn == false) — an authoritative "there is
	// no CID", never a placeholder.
	CID string
	// Durability says how retrievable CID is.
	Durability Durability
	// Source names the backend(s) holding the payload: "local", "pinata",
	// "local+pinata", "disabled", or "" when nothing was uploaded.
	Source string
	// OptIn is true when the not-uploaded result comes from an explicit
	// offline configuration (SPHINX_IPFS_DISABLE), i.e. the operator asked for
	// a local-only commitment rather than hitting a failure. The spxhash- CID
	// is only ever produced in this case.
	OptIn bool
	// Verified is true when the pinned bytes were read back and compared
	// byte-for-byte against what was uploaded. A 200 from `add` alone only
	// proves the request was accepted.
	Verified bool
	// Warn is non-nil whenever the outcome is degraded (not durable, opted-in
	// offline, or a durability mirror that failed), so callers surface it
	// instead of quietly proceeding.
	Warn error
}

// Uploaded reports whether a real, retrievable IPFS CID exists.
func (p PinOutcome) Uploaded() bool { return p.Durability != DurabilityNotUploaded }

// Durable reports whether retrievability is independent of this machine.
func (p PinOutcome) Durable() bool { return p.Durability == DurabilityRemotePinned }

// fallbackCIDFor is the deterministic local content identifier used ONLY in
// explicit offline mode. It is content-addressed (same bytes ⇒ same id) but is
// NOT a CID: no IPFS node can serve it, and it must never be treated as pinned.
func fallbackCIDFor(data []byte) string {
	return "spxhash-" + hex.EncodeToString(common.SpxHash(data))
}

// FallbackCIDFor returns the deterministic local content identifier for data —
// the value produced only in explicit offline mode (see PinPayload).
//
// Exported so callers can VERIFY a local file against a recorded spxhash-
// commitment without re-deriving the formula themselves. That matters: the
// identifier is a hash of the exact original bytes, so recomputing it is a
// strong proof that a file being re-pinned is the one the anchor committed to.
// A second, hand-rolled copy of the formula in a caller would silently stop
// matching if this ever changed, turning that proof into a false negative.
func FallbackCIDFor(data []byte) string { return fallbackCIDFor(data) }

// IsLocalOnlyCommitment reports whether a recorded CID is a local content hash
// (spxhash-…) rather than a retrievable IPFS identifier — i.e. the mint it came
// from never uploaded anything.
func IsLocalOnlyCommitment(cid string) bool {
	return strings.HasPrefix(strings.TrimSpace(cid), "spxhash-")
}

// PinPayload uploads data with the durability tiering this package documents:
//
//  1. local daemon (SPHINX_IPFS_ADDR) — fast and free, then
//  2. remote pinning service (SPHINX_IPFS_PINNING_SERVICE/_TOKEN) — durable.
//
// The local result is verified by reading the bytes back before it is trusted.
// Every outcome states plainly whether anything was uploaded, so callers can
// refuse to commit a CID that only exists on this disk. The spxhash- fallback
// is produced solely in explicit offline mode (DisableIPFS).
func (c *Client) PinPayload(data []byte, filename string) PinOutcome {
	if len(data) == 0 {
		return PinOutcome{Durability: DurabilityNotUploaded, Warn: fmt.Errorf("%w: empty payload", ErrNotUploaded)}
	}

	// Explicit offline mode: the operator opted in (SPHINX_IPFS_DISABLE=true).
	// This is the ONLY path that yields a spxhash- identifier — it keeps the
	// documented offline mode working, while still reporting honestly that
	// nothing was uploaded.
	if c.cfg.DisableIPFS {
		cid := fallbackCIDFor(data)
		return PinOutcome{
			CID:        cid,
			Durability: DurabilityNotUploaded,
			Source:     "disabled",
			OptIn:      true,
			Warn: fmt.Errorf("%w: IPFS is disabled (SPHINX_IPFS_DISABLE) — %s is a local content hash, not a retrievable CID",
				ErrNotUploaded, cid),
		}
	}

	var localErr error

	// Tier 1 — local daemon.
	if strings.TrimSpace(c.cfg.IPFSAddr) != "" {
		cid, err := c.AddBytesToIPFS(data, filename)
		if err != nil {
			localErr = err
		} else if verr := c.VerifyPinned(cid, data); verr != nil {
			// A CID we cannot read back is not a pin: treat it as a failure
			// rather than committing an identifier for bytes nobody can fetch.
			localErr = fmt.Errorf("local daemon returned CID %s but it could not be read back: %w", cid, verr)
		} else {
			out := PinOutcome{CID: cid, Durability: DurabilityLocalOnly, Source: "local", Verified: true}

			// Tier 2 — mirror to the durable service.
			remoteCID, service, rerr := c.pinRemotely(data, filename)
			if rerr != nil {
				out.Warn = fmt.Errorf("%w: the local IPFS daemon is not durable storage — the content becomes unreachable once this machine's daemon goes offline. Configure SPHINX_IPFS_PINNING_SERVICE/_TOKEN to pin durably (mirror failed: %v)",
					ErrNotDurable, rerr)
				return out
			}
			if remoteCID != cid {
				// Same bytes, different identifier: the durable copy does NOT
				// back this commitment. Committing the remote CID instead would
				// mean committing something this client never verified, so the
				// local CID is kept and the mismatch is reported.
				out.Warn = fmt.Errorf("%w: durable pin landed under a different CID (%s via %s) than the local daemon produced (%s) — this commitment is backed only by the local daemon; check that both backends use CIDv1",
					ErrNotDurable, remoteCID, service, cid)
				return out
			}
			out.Durability = DurabilityRemotePinned
			out.Source = "local+" + service
			return out
		}
	}

	// Tier 2 standalone — the local daemon is unavailable, so the pinning
	// service is the only backend that can hold the bytes.
	remoteCID, service, rerr := c.pinRemotely(data, filename)
	if rerr == nil {
		return PinOutcome{
			CID:        remoteCID,
			Durability: DurabilityRemotePinned,
			Source:     service,
			Warn: fmt.Errorf("local IPFS daemon unavailable (%v); pinned directly to %s — retrievability does not depend on this machine",
				localErr, service),
		}
	}

	// Nothing accepted the payload: report it as such, with NO CID.
	return PinOutcome{
		Durability: DurabilityNotUploaded,
		Warn: fmt.Errorf("%w: no IPFS backend accepted the payload — start an IPFS daemon at %s or set SPHINX_IPFS_PINNING_SERVICE/_TOKEN (local: %v; remote: %v)",
			ErrNotUploaded, c.cfg.IPFSAddr, localErr, rerr),
	}
}

// VerifyPinned reads cid back from the local daemon (or, failing that, the
// configured gateway) and compares it byte-for-byte with want. Success is the
// only proof that the bytes are actually in the blockstore.
func (c *Client) VerifyPinned(cid string, want []byte) error {
	if strings.TrimSpace(cid) == "" {
		return errors.New("empty cid")
	}
	got, err := c.catFromDaemon(cid)
	if err != nil {
		if c.cfg.DisableIPFS {
			return err
		}
		// The daemon's /api/v0/cat may be unavailable (e.g. a read-only
		// gateway in front of it); fall back to the configured gateway.
		got, err = c.GetBytesFromIPFS(cid)
		if err != nil {
			return fmt.Errorf("read back %s: %w", cid, err)
		}
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("read-back mismatch for %s: got %d bytes, want %d — content is not the bytes that were uploaded", cid, len(got), len(want))
	}
	return nil
}

// FetchFromDaemon retrieves a CID's bytes from the configured IPFS HTTP API
// (/api/v0/cat) — i.e. from the daemon's own blockstore, not via a gateway.
// Callers use it to distinguish "only your own node still has this" from
// "nobody can serve this", which is the durability question a verify screen
// needs to answer.
func (c *Client) FetchFromDaemon(cid string) ([]byte, error) {
	return c.catFromDaemon(cid)
}

// FetchPayload retrieves a CID's bytes with the same backend tiering PinPayload
// writes with: the configured gateway first, then the local daemon's
// blockstore. A caller that only tried the gateway would report "not
// retrievable" for content the local daemon still holds perfectly well — the
// exact state a local-only pin leaves behind.
func (c *Client) FetchPayload(cid string) ([]byte, error) {
	if strings.TrimSpace(cid) == "" {
		return nil, errors.New("empty cid")
	}
	if c.cfg.DisableIPFS {
		return nil, errors.New("ipfs disabled in config; cannot fetch bytes")
	}
	gatewayErr := error(nil)
	if data, err := c.GetBytesFromIPFS(cid); err == nil && len(data) > 0 {
		return data, nil
	} else if err != nil {
		gatewayErr = err
	}
	data, daemonErr := c.catFromDaemon(cid)
	if daemonErr == nil && len(data) > 0 {
		return data, nil
	}
	if gatewayErr != nil {
		return nil, fmt.Errorf("gateway: %v; daemon: %v", gatewayErr, daemonErr)
	}
	return nil, daemonErr
}

// ProbeCID reports whether a gateway can serve cid, WITHOUT downloading the
// payload: it inspects the response status and closes the body immediately,
// asking for the first byte only via a Range header where the server honours
// it.
//
// A retrievability question must not cost a full transfer. Reading the whole
// CID back (as GetBytesFromIPFS does) is right when you need the bytes — the
// CLI's content check does — but a status screen asking "is this still pinned?"
// would otherwise re-download a multi-gigabyte mint just to answer yes.
func (c *Client) ProbeCID(cid string) error {
	if strings.TrimSpace(cid) == "" {
		return errors.New("empty cid")
	}
	if c.cfg.DisableIPFS {
		return errors.New("ipfs disabled in config; cannot probe")
	}
	gateway, err := url.Parse(c.cfg.GatewayBaseURL)
	if err != nil {
		return fmt.Errorf("parse gateway url: %w", err)
	}
	gateway.Path = path.Join(gateway.Path, "/ipfs/", cid)

	req, err := http.NewRequest(http.MethodGet, gateway.String(), nil)
	if err != nil {
		return fmt.Errorf("create probe request: %w", err)
	}
	// Ask for a single byte: servers that honour Range send almost nothing,
	// and those that ignore it are still cut off by closing the body below.
	req.Header.Set("Range", "bytes=0-0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("gateway probe http error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("gateway probe failed: %s", resp.Status)
	}
	return nil
}

// probeDaemon checks the local daemon's blockstore via /api/v0/cat, again
// without reading the payload — only the status distinguishes "the daemon has
// it" from "it does not".
func (c *Client) probeDaemon(cid string) error {
	if c.cfg.DisableIPFS {
		return errors.New("ipfs disabled in config; cannot probe")
	}
	if strings.TrimSpace(c.cfg.IPFSAddr) == "" {
		return errors.New("no IPFS API address configured")
	}
	u, err := url.Parse(c.cfg.IPFSAddr)
	if err != nil {
		return fmt.Errorf("parse ipfs addr: %w", err)
	}
	u.Path = path.Join(u.Path, "/api/v0/cat")
	q := u.Query()
	q.Set("arg", cid)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodPost, u.String(), nil)
	if err != nil {
		return fmt.Errorf("create daemon probe request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("daemon probe http error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("daemon probe failed: %s", resp.Status)
	}
	return nil
}

// CheckRetrievability re-checks an EXISTING commitment: how retrievable are the
// bytes behind this CID right now? PinPayload answers that at write time;
// this answers it later, for a document whose provenance recorded a CID at mint.
//
// It probes a public gateway first (the only signal that proves this machine is
// not required) and then local infrastructure, and classifies through
// ClassifyRetrievability so the verdict is identical to the CLI's. A local-only
// commitment (spxhash-…) is reported as NotUploaded without any network call:
// there is nothing to probe, and calling it merely "unreachable" would hide
// that nothing was ever uploaded.
//
// Retrievability needs the GATEWAY, not just the API address, so a client with
// no gateway configured returns an error rather than a misleading verdict.
//
// The error return is reserved for "could not ask"; the normal outcomes are all
// values of Durability, not failures.
func (c *Client) CheckRetrievability(cid string) (Durability, error) {
	if strings.TrimSpace(cid) == "" {
		return DurabilityNotUploaded, errors.New("empty cid")
	}
	if IsLocalOnlyCommitment(cid) {
		return DurabilityNotUploaded, nil
	}
	if c.cfg.DisableIPFS {
		// Offline mode cannot probe anything; report what the identifier alone
		// proves rather than claiming unreachability.
		return DurabilityNotUploaded, errors.New("ipfs disabled in config; cannot check retrievability")
	}

	// Remote probe: a genuinely public gateway. Only its success is evidence
	// of durability, so a failure here is not itself an error. The gateway is
	// configurable (SPHINX_IPFS_PUBLIC_GATEWAY) so operators on networks that
	// block the default can still get a truthful answer.
	publicGateway := NewClient(PublicGatewayConfig())
	if override := strings.TrimSpace(c.cfg.PublicGatewayURL); override != "" {
		publicCfg := PublicGatewayConfig()
		publicCfg.GatewayBaseURL = override
		publicGateway = NewClient(publicCfg)
	}
	if err := publicGateway.ProbeCID(cid); err == nil {
		return ClassifyRetrievability(true, false), nil
	}

	// Local probes: the configured gateway (which counts as local only when it
	// actually runs on this host) plus the daemon's blockstore. A configured
	// NON-local gateway still counts as remote — a different public gateway
	// serving the bytes is just as good a durability signal as the default one.
	configuredIsLocal := IsLocalGatewayURL(c.cfg.GatewayBaseURL)
	configuredOK := c.ProbeCID(cid) == nil
	daemonOK := false
	if !configuredOK {
		daemonOK = c.probeDaemon(cid) == nil
	}
	return ClassifyRetrievability(
		configuredOK && !configuredIsLocal,
		daemonOK || (configuredOK && configuredIsLocal),
	), nil
}

// catFromDaemon fetches a CID's bytes from the IPFS HTTP API (/api/v0/cat).
// Unlike a gateway fetch this proves the bytes are staged in the daemon's own
// blockstore.
func (c *Client) catFromDaemon(cid string) ([]byte, error) {
	if c.cfg.DisableIPFS {
		return nil, errors.New("ipfs disabled in config; cannot cat")
	}
	if strings.TrimSpace(c.cfg.IPFSAddr) == "" {
		return nil, errors.New("no IPFS API address configured")
	}
	u, err := url.Parse(c.cfg.IPFSAddr)
	if err != nil {
		return nil, fmt.Errorf("parse ipfs addr: %w", err)
	}
	u.Path = path.Join(u.Path, "/api/v0/cat")
	q := u.Query()
	q.Set("arg", cid)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodPost, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create cat request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ipfs cat http error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return nil, fmt.Errorf("ipfs cat failed: %s: %s", resp.Status, string(b))
	}
	return io.ReadAll(resp.Body)
}
