// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/server/server/client.go
package pubkeydir

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Verifier   Verifier
}

func NewClient(baseURL string, verifier Verifier) *Client {
	log.Printf("[INFO] NewClient: creating new client for base URL: %s", baseURL)

	client := &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: http.DefaultClient,
		Verifier:   verifier,
	}

	log.Printf("[SUCCESS] NewClient: client created with base URL: %s", client.BaseURL)
	return client
}

// Get implements the Store interface by fingerprint lookup
func (c *Client) Get(fingerprint string) (PublicKeyBundle, error) {
	log.Printf("[INFO] Get: looking up bundle by fingerprint: %.16s...", fingerprint)
	return c.Lookup(fingerprint)
}

// LookupByPublicKey resolves a bundle by raw public key hex string.
func (c *Client) LookupByPublicKey(pubKeyHex string) (PublicKeyBundle, error) {
	log.Printf("[INFO] LookupByPublicKey: resolving bundle by public key hex: %.16s...", pubKeyHex)
	log.Printf("[DEBUG] LookupByPublicKey: full public key hex length: %d chars", len(pubKeyHex))

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		log.Printf("[ERROR] LookupByPublicKey: invalid public key hex: %v", err)
		return PublicKeyBundle{}, fmt.Errorf("invalid public key hex: %w", err)
	}
	log.Printf("[DEBUG] LookupByPublicKey: decoded public key bytes: %d bytes", len(pubKeyBytes))

	fp := Fingerprint(pubKeyBytes)
	log.Printf("[DEBUG] LookupByPublicKey: computed fingerprint: %.16s...", fp)

	bundle, err := c.Lookup(fp)
	if err != nil {
		log.Printf("[ERROR] LookupByPublicKey: lookup failed: %v", err)
		return PublicKeyBundle{}, err
	}

	log.Printf("[SUCCESS] LookupByPublicKey: resolved bundle for fingerprint: %.16s...", fp)
	return bundle, nil
}

func (c *Client) Put(bundle PublicKeyBundle) error {
	log.Printf("[INFO] Put: storing bundle for fingerprint: %.16s...", bundle.Fingerprint)
	log.Printf("[DEBUG] Put: bundle label: %s, organization: %s", bundle.Label, bundle.Organization)
	log.Printf("[DEBUG] Put: signature public key size: %d bytes, KEM public key size: %d bytes",
		len(bundle.SignaturePublicKey), len(bundle.KEMPublicKey))

	body, err := json.Marshal(bundle)
	if err != nil {
		log.Printf("[ERROR] Put: failed to marshal bundle: %v", err)
		return err
	}
	log.Printf("[DEBUG] Put: marshaled bundle size: %d bytes", len(body))

	url := c.BaseURL + "/bundles"
	log.Printf("[DEBUG] Put: POST request to %s", url)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[ERROR] Put: failed to create request: %v", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http().Do(req)
	if err != nil {
		log.Printf("[ERROR] Put: HTTP request failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	log.Printf("[DEBUG] Put: response status: %s", resp.Status)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("[ERROR] Put: server returned error status: %s", resp.Status)
		return fmt.Errorf("public key directory returned %s", resp.Status)
	}

	log.Printf("[SUCCESS] Put: bundle stored successfully for fingerprint: %.16s...", bundle.Fingerprint)
	return nil
}

func (c *Client) Lookup(fingerprint string) (PublicKeyBundle, error) {
	log.Printf("[INFO] Lookup: looking up bundle for fingerprint: %.16s...", fingerprint)

	fp, err := NormalizeFingerprint(fingerprint)
	if err != nil {
		log.Printf("[ERROR] Lookup: failed to normalize fingerprint: %v", err)
		return PublicKeyBundle{}, err
	}
	log.Printf("[DEBUG] Lookup: normalized fingerprint: %.16s...", fp)

	url := c.BaseURL + "/bundles/" + fp
	log.Printf("[DEBUG] Lookup: GET request to %s", url)

	resp, err := c.http().Get(url)
	if err != nil {
		log.Printf("[ERROR] Lookup: HTTP request failed: %v", err)
		return PublicKeyBundle{}, err
	}
	defer resp.Body.Close()

	log.Printf("[DEBUG] Lookup: response status: %s", resp.Status)

	if resp.StatusCode == http.StatusNotFound {
		log.Printf("[INFO] Lookup: bundle not found for fingerprint: %.16s...", fp)
		return PublicKeyBundle{}, ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("[ERROR] Lookup: server returned error status: %s", resp.Status)
		return PublicKeyBundle{}, fmt.Errorf("public key directory returned %s", resp.Status)
	}

	var bundle PublicKeyBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		log.Printf("[ERROR] Lookup: failed to decode response: %v", err)
		return PublicKeyBundle{}, err
	}
	log.Printf("[DEBUG] Lookup: decoded bundle - label: %s, org: %s", bundle.Label, bundle.Organization)

	if err := ValidateBundle(bundle, c.Verifier); err != nil {
		log.Printf("[ERROR] Lookup: bundle validation failed: %v", err)
		return PublicKeyBundle{}, err
	}

	log.Printf("[SUCCESS] Lookup: bundle found and validated for fingerprint: %.16s...", fp)
	return bundle, nil
}

// List retrieves all bundles from the server
func (c *Client) List() ([]PublicKeyBundle, error) {
	log.Printf("[INFO] List: retrieving all bundles from server")

	url := c.BaseURL + "/bundles"
	log.Printf("[DEBUG] List: GET request to %s", url)

	resp, err := c.http().Get(url)
	if err != nil {
		log.Printf("[ERROR] List: HTTP request failed: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	log.Printf("[DEBUG] List: response status: %s", resp.Status)

	if resp.StatusCode != http.StatusOK {
		log.Printf("[ERROR] List: server returned error status: %s", resp.Status)
		return nil, fmt.Errorf("server returned %s", resp.Status)
	}

	var bundles []PublicKeyBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundles); err != nil {
		log.Printf("[ERROR] List: failed to decode response: %v", err)
		return nil, err
	}

	log.Printf("[SUCCESS] List: retrieved %d bundles from server", len(bundles))
	return bundles, nil
}

// Revoke revokes a bundle on the server
func (c *Client) Revoke(fingerprint, reason string) error {
	log.Printf("[INFO] Revoke: revoking bundle for fingerprint: %.16s...", fingerprint)
	log.Printf("[DEBUG] Revoke: reason: %s", reason)

	reqBody := struct {
		Reason string `json:"reason"`
	}{Reason: reason}

	body, err := json.Marshal(reqBody)
	if err != nil {
		log.Printf("[ERROR] Revoke: failed to marshal request body: %v", err)
		return err
	}
	log.Printf("[DEBUG] Revoke: marshaled request size: %d bytes", len(body))

	fp, err := NormalizeFingerprint(fingerprint)
	if err != nil {
		log.Printf("[ERROR] Revoke: failed to normalize fingerprint: %v", err)
		return err
	}
	log.Printf("[DEBUG] Revoke: normalized fingerprint: %.16s...", fp)

	url := c.BaseURL + "/bundles/" + fp + "/revoke"
	log.Printf("[DEBUG] Revoke: POST request to %s", url)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[ERROR] Revoke: failed to create request: %v", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http().Do(req)
	if err != nil {
		log.Printf("[ERROR] Revoke: HTTP request failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	log.Printf("[DEBUG] Revoke: response status: %s", resp.Status)

	if resp.StatusCode != http.StatusNoContent {
		log.Printf("[ERROR] Revoke: server returned error status: %s", resp.Status)
		return fmt.Errorf("server returned %s", resp.Status)
	}

	log.Printf("[SUCCESS] Revoke: bundle revoked successfully for fingerprint: %.16s...", fp)
	return nil
}

// Close implements the Store interface for HTTP client
// For HTTP client, Close is a no-op since there's no persistent connection to close
func (c *Client) Close() error {
	log.Printf("[DEBUG] Close: closing client connection (no-op for HTTP client)")
	// HTTP client doesn't need to close anything
	// This satisfies the Store interface
	return nil
}

func (c *Client) http() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	log.Printf("[DEBUG] http: using default HTTP client")
	return http.DefaultClient
}
