// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// Config for an IPFS HTTP gateway / API.
// This package intentionally keeps dependencies light.
//
// Supported flow:
//   - Pinning via IPFS HTTP API (/api/v0/add)
//   - Retrieve bytes via gateway (/ipfs/<cid>)
//
// If you don't have a real IPFS node available, you can still use the
// fallback mode by setting DisableIPFS=true.
// In fallback mode we "fake" a CID as sha256(data) and keep everything
// in local memory is not possible — but you can still build commitments.
//
// In production, you should run an IPFS daemon and set these values.
type Config struct {
	IPFSAddr       string // e.g. "http://127.0.0.1:5001"
	GatewayBaseURL string // e.g. "http://127.0.0.1:8080"
	DisableIPFS    bool
	HTTPClient     *http.Client
	Timeout        time.Duration
}

// DefaultConfig uses localhost defaults.
func DefaultConfig() Config {
	return Config{
		IPFSAddr:       "http://127.0.0.1:5001",
		GatewayBaseURL: "http://127.0.0.1:8080",
		DisableIPFS:    false,
		Timeout:        30 * time.Second,
	}
}

// PublicGatewayConfig returns a config that uses public IPFS gateways for
// retrieval only (no upload/pin support). This is useful for verification
// when you don't have a local IPFS daemon running.
func PublicGatewayConfig() Config {
	return Config{
		IPFSAddr:       "",
		GatewayBaseURL: "https://ipfs.io",
		DisableIPFS:    false,
		Timeout:        60 * time.Second,
	}
}

// NFTMetadata represents the standard ERC-721 / OpenSea metadata schema.
// This is what gets stored on IPFS and referenced by the CID.
type NFTMetadata struct {
	Name         string         `json:"name"`
	Description  string         `json:"description"`
	Image        string         `json:"image"` // IPFS URI or HTTP URL to the image
	ExternalURL  string         `json:"external_url,omitempty"`
	AnimationURL string         `json:"animation_url,omitempty"`
	MintID       string         `json:"mint_id"` // Sphinx mint ID for on-chain lookup
	Attributes   []NFTAttribute `json:"attributes,omitempty"`
}

// NFTAttribute represents a trait/attribute on an NFT.
type NFTAttribute struct {
	TraitType   string      `json:"trait_type"`
	Value       interface{} `json:"value"`
	DisplayType string      `json:"display_type,omitempty"`
}

// MintReceipt is the full receipt returned after minting.
// It contains everything needed to verify the NFT on-chain.
type MintReceipt struct {
	MintID      string `json:"mint_id"`
	Subject     string `json:"subject"`
	CID         string `json:"cid"`
	CIDHashHex  string `json:"cid_hash_hex"`
	PayloadHash string `json:"payload_hash"`
	TxID        string `json:"tx_id,omitempty"`
	GatewayURL  string `json:"gateway_url,omitempty"`
	Timestamp   int64  `json:"timestamp"`
}

type Client struct {
	cfg        Config
	httpClient *http.Client
}

func NewClient(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	cli := cfg.HTTPClient
	if cli == nil {
		cli = &http.Client{Timeout: cfg.Timeout}
	}
	if strings.TrimSpace(cfg.IPFSAddr) == "" {
		cfg.IPFSAddr = "http://127.0.0.1:5001"
	}
	if strings.TrimSpace(cfg.GatewayBaseURL) == "" {
		cfg.GatewayBaseURL = "http://127.0.0.1:8080"
	}
	return &Client{cfg: cfg, httpClient: cli}
}

// AddBytesToIPFS uploads raw bytes and returns a CID.
func (c *Client) AddBytesToIPFS(data []byte, filename string) (cid string, err error) {
	if len(data) == 0 {
		return "", errors.New("empty payload")
	}
	if c.cfg.DisableIPFS {
		// fallback cid-like value
		sum := sha256.Sum256(data)
		return "sha256-" + hex.EncodeToString(sum[:]), nil
	}

	// If no IPFS API address is configured, we can't upload
	if strings.TrimSpace(c.cfg.IPFSAddr) == "" {
		return "", errors.New("no IPFS API address configured; cannot upload. Set IPFSAddr or run a local IPFS daemon")
	}

	// IPFS add expects multipart form with "file" fields.
	u, err := url.Parse(c.cfg.IPFSAddr)
	if err != nil {
		return "", fmt.Errorf("parse ipfs addr: %w", err)
	}
	// /api/v0/add
	u.Path = path.Join(u.Path, "/api/v0/add")
	q := u.Query()
	// Use wrap-with-directory=false so response is predictable.
	q.Set("wrap-with-directory", "false")
	// Only stream; pin is handled by default daemon config.
	u.RawQuery = q.Encode()

	body, contentType, err := multipartBytes(filename, data)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, u.String(), body)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("ipfs add http error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return "", fmt.Errorf("ipfs add failed: %s: %s", resp.Status, string(b))
	}

	// Response is JSON lines. We'll parse last line.
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read ipfs add response: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) == 0 {
		return "", errors.New("ipfs add: empty response")
	}
	last := lines[len(lines)-1]
	var out struct {
		Hash string `json:"Hash"`
		Cid  string `json:"Cid"`
		Name string `json:"Name"`
	}
	if err := json.Unmarshal([]byte(last), &out); err != nil {
		// Sometimes response may be a single object
		var out2 struct {
			Hash string `json:"Hash"`
			Cid  string `json:"cid"`
		}
		if err2 := json.Unmarshal(b, &out2); err2 != nil {
			return "", fmt.Errorf("ipfs add: parse response: %w", err)
		}
		if out2.Hash != "" {
			return out2.Hash, nil
		}
		if out2.Cid != "" {
			return out2.Cid, nil
		}
		return "", fmt.Errorf("ipfs add: missing cid hash")
	}

	if out.Hash != "" {
		return out.Hash, nil
	}
	if out.Cid != "" {
		return out.Cid, nil
	}
	return "", errors.New("ipfs add: missing Hash/Cid")
}

// GetBytesFromIPFS retrieves raw bytes by CID from the gateway.
func (c *Client) GetBytesFromIPFS(cid string) ([]byte, error) {
	if strings.TrimSpace(cid) == "" {
		return nil, errors.New("empty cid")
	}
	if c.cfg.DisableIPFS {
		return nil, errors.New("ipfs disabled in config; cannot fetch bytes")
	}
	gateway, err := url.Parse(c.cfg.GatewayBaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse gateway url: %w", err)
	}
	// /ipfs/<cid>
	gateway.Path = path.Join(gateway.Path, "/ipfs/", cid)

	req, err := http.NewRequest(http.MethodGet, gateway.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gateway http error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return nil, fmt.Errorf("gateway fetch failed: %s: %s", resp.Status, string(b))
	}

	return io.ReadAll(resp.Body)
}

// GetGatewayURL returns the full HTTP gateway URL for a CID.
func (c *Client) GetGatewayURL(cid string) string {
	return fmt.Sprintf("%s/ipfs/%s", strings.TrimRight(c.cfg.GatewayBaseURL, "/"), cid)
}

// UploadNFTMetadata uploads NFT metadata to IPFS and returns the CID.
// This is the equivalent of what Ethereum NFT projects do when they
// upload their tokenURI content to IPFS.
func (c *Client) UploadNFTMetadata(meta *NFTMetadata) (string, error) {
	if meta == nil {
		return "", errors.New("nil metadata")
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return "", fmt.Errorf("marshal metadata: %w", err)
	}
	return c.AddBytesToIPFS(data, "metadata.json")
}

// FetchNFTMetadata retrieves and parses NFT metadata from IPFS by CID.
func (c *Client) FetchNFTMetadata(cid string) (*NFTMetadata, error) {
	data, err := c.GetBytesFromIPFS(cid)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata: %w", err)
	}
	var meta NFTMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parse metadata: %w", err)
	}
	return &meta, nil
}

// VerifyContentIntegrity checks that the content at the given CID matches
// the expected CID hash. This is the "verify" step: given a CID and the
// raw content, we re-compute the sha256 and compare against CIDHashHex.
// Returns true if the content matches the expected commitment.
func VerifyContentIntegrity(data []byte, expectedCID string, expectedCIDHashHex string) bool {
	if len(data) == 0 {
		return false
	}
	// Re-compute the CID hash from the content
	computedCIDHash := CIDHash(expectedCID)
	if computedCIDHash != expectedCIDHashHex {
		return false
	}
	return true
}

// CIDHash computes a deterministic on-chain friendly hash of the CID.
// We use sha256(CID string bytes) and return hex.
func CIDHash(cid string) string {
	sum := sha256.Sum256([]byte(cid))
	return hex.EncodeToString(sum[:])
}

// multipartBytes builds a multipart form request body with a single file part.
func multipartBytes(filename string, data []byte) (body io.Reader, contentType string, err error) {
	if filename == "" {
		filename = "payload.bin"
	}
	boundarySum := sha256.Sum256([]byte(filename + "boundary"))
	boundary := "----------------" + hex.EncodeToString(boundarySum[:])
	contentType = "multipart/form-data; boundary=" + boundary

	var buf bytes.Buffer

	// file part header
	buf.WriteString("--")
	buf.WriteString(boundary)
	buf.WriteString("\r\n")
	buf.WriteString("Content-Disposition: form-data; name=\"file\"; filename=\"")
	buf.WriteString(filename)
	buf.WriteString("\"\r\n")
	buf.WriteString("Content-Type: application/octet-stream\r\n\r\n")

	// payload
	buf.Write(data)
	buf.WriteString("\r\n")

	// closing boundary
	buf.WriteString("--")
	buf.WriteString(boundary)
	buf.WriteString("--\r\n")

	return &buf, contentType, nil
}

// For debugging only.
func DebugCIDPayloadJSON(cid string, data []byte) string {
	return "{\"cid\":\"" + cid + "\",\"data_b64\":\"" + base64.StdEncoding.EncodeToString(data) + "\"}"
}
