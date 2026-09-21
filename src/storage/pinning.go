// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
)

// defaultPinataAPI is the Pinata pinning API base. Pinata is the first
// remote-pinning backend; the call site is isolated here so another service can
// be added behind the same pinRemotely contract without touching the durability
// model in pin.go.
const defaultPinataAPI = "https://api.pinata.cloud"

// pinataFileEndpoint pins a single file.
const pinataFileEndpoint = "/pinning/pinFileToIPFS"

// pinataCIDVersion is the CID version requested from every backend — see
// AddBytesToIPFS for why this package commits exactly one CID version.
const pinataCIDVersion = 1

// pinRemotely mirrors data to the configured durable pinning service and
// returns the CID it reports plus the service's short name (used as the
// PinOutcome.Source suffix).
func (c *Client) pinRemotely(data []byte, filename string) (cid, service string, err error) {
	token := strings.TrimSpace(c.cfg.PinningServiceToken)
	if token == "" {
		return "", "", errors.New("no remote pinning service configured (set SPHINX_IPFS_PINNING_SERVICE and SPHINX_IPFS_PINNING_TOKEN)")
	}
	base := strings.TrimSpace(c.cfg.PinningServiceURL)
	if base == "" {
		base = defaultPinataAPI
	}
	cid, err = c.pinToPinata(base, token, data, filename)
	if err != nil {
		return "", "", err
	}
	return cid, "pinata", nil
}

// pinToPinata uploads data to Pinata's pinFileToIPFS endpoint and returns the
// CID Pinata reports.
func (c *Client) pinToPinata(base, token string, data []byte, filename string) (string, error) {
	if len(data) == 0 {
		return "", errors.New("empty payload")
	}
	if strings.TrimSpace(filename) == "" {
		filename = "payload.bin"
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return "", fmt.Errorf("build pinata form file: %w", err)
	}
	if _, err := fw.Write(data); err != nil {
		return "", fmt.Errorf("write pinata form file: %w", err)
	}
	// pinataOptions states the CID VERSION explicitly. Pinata happens to
	// default to CIDv1, but relying on that default would mean a change on
	// their side silently invalidates every on-chain cid_hash_hex commitment
	// this wallet made against the returned CID string.
	opts, err := json.Marshal(map[string]int{"cidVersion": pinataCIDVersion})
	if err != nil {
		return "", fmt.Errorf("encode pinata options: %w", err)
	}
	if err := mw.WriteField("pinataOptions", string(opts)); err != nil {
		return "", fmt.Errorf("write pinata options: %w", err)
	}
	// pinataMetadata is display-only: it names the pin in the Pinata UI.
	meta, err := json.Marshal(map[string]string{"name": filename})
	if err != nil {
		return "", fmt.Errorf("encode pinata metadata: %w", err)
	}
	if err := mw.WriteField("pinataMetadata", string(meta)); err != nil {
		return "", fmt.Errorf("write pinata metadata: %w", err)
	}
	if err := mw.Close(); err != nil {
		return "", fmt.Errorf("close pinata form: %w", err)
	}

	endpoint := strings.TrimRight(base, "/") + pinataFileEndpoint
	req, err := http.NewRequest(http.MethodPost, endpoint, &body)
	if err != nil {
		return "", fmt.Errorf("create pinata request: %w", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("pinata http error: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("read pinata response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("pinata pin failed: %s: %s", resp.Status, pinataErrorMessage(raw))
	}

	var out struct {
		IpfsHash string `json:"IpfsHash"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("parse pinata response: %w", err)
	}
	cid := strings.TrimSpace(out.IpfsHash)
	if cid == "" {
		return "", fmt.Errorf("pinata response carried no IpfsHash: %s", pinataErrorMessage(raw))
	}
	// Enforce the canonical CID version. A v0 CID here is a DIFFERENT string
	// for the same bytes: it would not match the local daemon's CIDv1, so the
	// durable copy would be unreachable under the identifier we commit to.
	if strings.HasPrefix(cid, "Qm") {
		return "", fmt.Errorf("pinata returned a CIDv0 identifier (%s); this package commits CIDv1 only — refusing, so the on-chain commitment cannot point at a differently-addressed copy", cid)
	}
	return cid, nil
}

// pinataErrorMessage extracts Pinata's human-readable error reason, falling
// back to the raw body so an unexpected shape is still surfaced rather than
// swallowed.
func pinataErrorMessage(raw []byte) string {
	var e struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && len(e.Error) > 0 {
		var reason struct {
			Reason  string `json:"reason"`
			Details string `json:"details"`
		}
		if json.Unmarshal(e.Error, &reason) == nil && strings.TrimSpace(reason.Reason) != "" {
			if strings.TrimSpace(reason.Details) != "" {
				return reason.Reason + ": " + reason.Details
			}
			return reason.Reason
		}
		return string(e.Error)
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
