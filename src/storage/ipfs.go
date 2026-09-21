// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package storage

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	spxhash "github.com/sphinxfndorg/protocol/src/spxhash/hash"
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

	// Remote pinning service — the DURABLE tier. A local kubo daemon at
	// 127.0.0.1:5001 only serves the content while that daemon stays online
	// and is reachable by peers, so it is not durable storage on its own.
	// When PinningServiceToken is set, every pin is additionally mirrored to
	// the service (currently Pinata), so retrievability no longer depends on
	// the user's machine. See pin.go for the outcome/durability model.
	PinningServiceURL   string // e.g. "https://api.pinata.cloud"
	PinningServiceToken string // Bearer token (Pinata JWT)

	// PublicGatewayURL is the NEUTRAL third-party gateway used only to answer
	// "can someone other than me fetch this?" (CheckRetrievability). It must
	// be independent of this machine and of the user's own daemon, which is
	// exactly why it is separate from GatewayBaseURL — a success here is the
	// only evidence that a pin is durable.
	//
	// Overridable via SPHINX_IPFS_PUBLIC_GATEWAY for networks where the
	// default is blocked.
	PublicGatewayURL string
}

// DefaultConfig uses localhost defaults, overridable through environment:
//
//	SPHINX_IPFS_ADDR            → IPFS HTTP API address (default "http://127.0.0.1:5001")
//	SPHINX_IPFS_GATEWAY         → IPFS gateway base URL  (default "http://127.0.0.1:8080")
//	SPHINX_IPFS_DISABLE         → "true" to use the offline fallback CID mode
//	SPHINX_IPFS_PINNING_SERVICE → remote pinning service API (default "https://api.pinata.cloud"
//	                              when a token is set; currently Pinata)
//	SPHINX_IPFS_PINNING_TOKEN   → Bearer token for the pinning service (Pinata JWT). When
//	                              set, pins are mirrored there so they survive this machine
//	                              going offline.
//
// IPFS is a separate daemon from the Sphinx node. If you run the daemon on a
// non-default host/port (or behind a tunnel), export SPHINX_IPFS_ADDR so the
// wallet and CLI talk to the real API endpoint instead of attempting
// 127.0.0.1:5001.
func DefaultConfig() Config {
	cfg := Config{
		IPFSAddr:         "http://127.0.0.1:5001",
		GatewayBaseURL:   "http://127.0.0.1:8080",
		DisableIPFS:      false,
		Timeout:          30 * time.Second,
		PublicGatewayURL: defaultPublicGatewayURL,
	}
	if v := strings.TrimSpace(os.Getenv("SPHINX_IPFS_ADDR")); v != "" {
		cfg.IPFSAddr = v
	}
	if v := strings.TrimSpace(os.Getenv("SPHINX_IPFS_GATEWAY")); v != "" {
		cfg.GatewayBaseURL = v
	}
	if v := strings.TrimSpace(os.Getenv("SPHINX_IPFS_DISABLE")); v != "" && strings.EqualFold(v, "true") {
		cfg.DisableIPFS = true
	}
	if v := strings.TrimSpace(os.Getenv("SPHINX_IPFS_PINNING_SERVICE")); v != "" {
		cfg.PinningServiceURL = v
	}
	if v := strings.TrimSpace(os.Getenv("SPHINX_IPFS_PINNING_TOKEN")); v != "" {
		cfg.PinningServiceToken = v
	}
	if v := strings.TrimSpace(os.Getenv("SPHINX_IPFS_PUBLIC_GATEWAY")); v != "" {
		cfg.PublicGatewayURL = v
	}
	return cfg
}

// PublicGatewayConfig returns a config that uses public IPFS gateways for
// retrieval only (no upload/pin support). This is useful for verification
// when you don't have a local IPFS daemon running.
func PublicGatewayConfig() Config {
	return Config{
		IPFSAddr:         "",
		GatewayBaseURL:   defaultPublicGatewayURL,
		DisableIPFS:      false,
		Timeout:          60 * time.Second,
		PublicGatewayURL: defaultPublicGatewayURL,
	}
}

// defaultPublicGatewayURL is the neutral third-party gateway used to answer
// "can someone other than me fetch this?" (Config.PublicGatewayURL). It is
// deliberately independent of the wallet's own daemon: a fetch served by this
// machine says nothing about durability.
const defaultPublicGatewayURL = "https://ipfs.io"

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
	// Heal a common misconfiguration before it hits the dialer: an IPv4
	// address with the port written as one more dotted label
	// ("http://127.0.0.1.5001") parses as a bare hostname and silently dials
	// the wrong target. Rewrite the trailing numeric label as the port.
	cfg.IPFSAddr = normalizeIPFSAddr(cfg.IPFSAddr)
	// A token with no explicit service URL means "Pinata": defaulting here
	// (rather than in the pin path) keeps every caller — GUI, CLI, tests —
	// consistent about which backend a token selects.
	if strings.TrimSpace(cfg.PinningServiceToken) != "" && strings.TrimSpace(cfg.PinningServiceURL) == "" {
		cfg.PinningServiceURL = defaultPinataAPI
	}
	return &Client{cfg: cfg, httpClient: cli}
}

// normalizeIPFSAddr corrects a dotted-IPv4-with-port typo. Given
// "http://127.0.0.1.5001" it returns "http://127.0.0.1:5001"; any address
// that already has a port or does not match the pattern is left unchanged.
func normalizeIPFSAddr(addr string) string {
	if strings.TrimSpace(addr) == "" {
		return addr
	}
	u, err := url.Parse(addr)
	if err != nil || u.Hostname() == "" || u.Port() != "" {
		return addr
	}
	labels := strings.Split(u.Hostname(), ".")
	if len(labels) < 3 {
		return addr
	}
	last := labels[len(labels)-1]
	if last == "" {
		return addr
	}
	if _, err := strconv.ParseUint(last, 10, 32); err == nil {
		u.Host = strings.Join(labels[:len(labels)-1], ".") + ":" + last
		return u.String()
	}
	return addr
}

// AddBytesToIPFS uploads raw bytes and returns a CID.
func (c *Client) AddBytesToIPFS(data []byte, filename string) (cid string, err error) {
	if len(data) == 0 {
		return "", errors.New("empty payload")
	}
	if c.cfg.DisableIPFS {
		// fallback cid-like value, committed with the Sphinx hash so the
		// offline CID feeds the same SpxHash-based CIDHash commitment below.
		return "spxhash-" + hex.EncodeToString(common.SpxHash(data)), nil
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
	// ★ CID VERSION IS PINNED TO 1 ON PURPOSE. The CID string is what gets
	// committed on-chain (AnchorTag.CID + cid_hash_hex), and it is also what
	// a remote pinning service returns for the same bytes. kubo defaults to
	// CIDv0 ("Qm…") while Pinata/nft.storage/web3.storage hand back CIDv1
	// ("bafy…"), so the same payload would end up with two DIFFERENT
	// identifiers depending on which backend accepted it — the durable copy
	// would then sit under a CID the on-chain anchor never commits to.
	// Forcing CIDv1 on every backend keeps exactly one canonical identifier
	// per payload, which is what makes "local first, then pinning service"
	// verifiable. See PinOutcome in pin.go.
	q.Set("cid-version", "1")
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

// DecodeHexStorageValue decodes the hex-encoded getcontractstorage payload.
// The node returns raw storage bytes as hex; SDKs must not hand-roll this.
func DecodeHexStorageValue(hexStr string) ([]byte, error) {
	hexStr = strings.TrimSpace(hexStr)
	if hexStr == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
	if err != nil {
		return nil, fmt.Errorf("decode storage hex: %w", err)
	}
	return b, nil
}

// AddBytesToIPFSWithFallback is the legacy resilient pin.
//
// Deprecated: it returns a plausible-looking spxhash- CID when nothing was
// uploaded, so a caller could not distinguish "pinned" from "never left this
// machine" — the root cause of mints that silently committed un-retrievable
// data. Use PinPayload instead, which reports durability explicitly and never
// invents a CID for a failed upload.
//
// Retained only for backward compatibility, and still behaves exactly as
// documented before: the deterministic fallback CID with a nil error in
// explicit offline mode (DisableIPFS), and the fallback CID plus a warning when
// an upload was attempted and failed. The fallback CID is a local content hash,
// NOT a retrievable IPFS CID.
func (c *Client) AddBytesToIPFSWithFallback(data []byte, filename string) (string, error) {
	if len(data) == 0 {
		return "", errors.New("empty payload")
	}
	if c.cfg.DisableIPFS {
		return fallbackCIDFor(data), nil
	}
	if seed, err := c.AddBytesToIPFS(data, filename); err == nil {
		return seed, nil
	}
	fallbackCID := fallbackCIDFor(data)
	return fallbackCID, fmt.Errorf("ipfs upload failed — using deterministic local content hash %s (this is NOT a retrievable CID; use PinPayload for durability-aware pinning)", fallbackCID)
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
// Uses common.SpxHash(CID string bytes) — NOT sha256 — so the wallet-side
// artifact commitment matches core.CIDHashHexFor byte-for-byte and the whole
// NFT mint / SPX transfer anchor pipeline stays in one hash family (the same
// family the SVM signature opcodes verify with).
func CIDHash(cid string) string {
	return hex.EncodeToString(common.SpxHash([]byte(cid)))
}

// boundaryHash derives a multipart boundary tag with the same Sphinx hash so
// no sha256 remains in this package's content-commitment paths. It is only a
// transport framing value, never a consensus commitment.
func boundaryHash(s string) []byte {
	h, err := spxhash.NewSphinxHash(256, spxhash.ProtocolSalt)
	if err != nil {
		return common.SpxHash([]byte(s))
	}
	return h.GetHash([]byte(s))
}

// multipartBytes builds a multipart form request body with a single file part.
func multipartBytes(filename string, data []byte) (body io.Reader, contentType string, err error) {
	if filename == "" {
		filename = "payload.bin"
	}
	boundarySum := boundaryHash(filename + "boundary")
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
