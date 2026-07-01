// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/p2p/dnsdiscovery/types.go
//
// EIP-1459-style DNS-based node discovery for Sphinx.
// Instead of plain-IP seeds, we publish cryptographically signed
// Merkle trees of node records in DNS TXT records.  Clients fetch
// the signed root, verify the SPHINCS+ signature, and traverse the
// tree to collect peer addresses — all without trusting the DNS
// operator.

package dnsdiscovery

import (
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/network"
)

// Scheme constants
const (
	// ENRTreeScheme is the URI scheme for DNS discovery URLs
	ENRTreeScheme = "enrtree"

	// ENRTreeVersion is the current version of the DNS tree format
	ENRTreeVersion = "v1"

	// DNSTimeout is the default timeout for DNS lookups
	DNSTimeout = 10 * time.Second

	// MaxDNSRetries is the maximum number of DNS lookup retries
	MaxDNSRetries = 3

	// DefaultTreeTTL is the default TTL for cached tree data
	DefaultTreeTTL = 30 * time.Minute
)

// SphinxNodeRecord (SNR) is the Sphinx equivalent of an Ethereum ENR.
// It carries everything needed to dial and authenticate a peer.
type SphinxNodeRecord struct {
	// ID is the node's unique identifier (Node.ID in the P2P layer)
	ID string `json:"id"`

	// KademliaID is the 32-byte Kademlia DHT identifier (hex-encoded)
	KademliaID string `json:"k"`

	// Address is the dialable TCP address (host:port)
	Address string `json:"a"`

	// UDPPort is the node's discovery UDP port
	UDPPort string `json:"u"`

	// PublicKey is the SPHINCS+ public key (hex-encoded)
	PublicKey string `json:"pk"`

	// ProtocolVersion identifies the wire protocol version
	ProtocolVersion string `json:"pv"`
}

// TreeRoot is the signed root of a DNS discovery tree.
// It is stored as a TXT record at root.<domain>.
type TreeRoot struct {
	// Version is always "v1"
	Version string `json:"version"`

	// ERoot is the hex-encoded Merkle root hash of the ENR tree
	ERoot string `json:"eroot"`

	// LRoot is the hex-encoded Merkle root hash of the link tree (empty if no links)
	LRoot string `json:"lroot"`

	// Sequence is the tree sequence number (monotonically increasing)
	Sequence uint64 `json:"seq"`

	// Signature is the SPHINCS+ signature over (version || eroot || lroot || seq)
	Signature string `json:"sig"`

	// PublicKey is the SPHINCS+ public key that signed this root (hex-encoded)
	PublicKey string `json:"pk"`
}

// ParseError represents an error during DNS discovery parsing
type ParseError struct {
	Domain string
	Record string
	Err    error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("dnsdiscovery: parse error for %s record %q: %v",
		e.Domain, e.Record, e.Err)
}

// VerificationError represents a cryptographic verification failure
type VerificationError struct {
	Reason string
	Domain string
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("dnsdiscovery: verification failed for %s: %s",
		e.Domain, e.Reason)
}

// TreeError represents an error during tree traversal
type TreeError struct {
	Domain string
	Path   string
	Err    error
}

func (e *TreeError) Error() string {
	return fmt.Sprintf("dnsdiscovery: tree error at %s/%s: %v",
		e.Domain, e.Path, e.Err)
}

// hexEncode is a helper to hex-encode bytes
func hexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

// hexDecode is a helper to hex-decode a string
func hexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// Client manages DNS-based peer discovery.
type Client struct {
	mu            sync.RWMutex
	resolver      *net.Resolver
	timeout       time.Duration
	retries       int
	cache         map[string]cachedTree
	cacheTTL      time.Duration
	knownTreeURLs []string // enrtree:// URLs to query
	verifier      TreeRootVerifier
}

// cachedTree holds a fetched and verified DNS tree with its expiry
type cachedTree struct {
	peers    []network.PeerInfo
	expiry   time.Time
	sequence uint64
}

// TreeRootVerifier verifies the cryptographic signature of a TreeRoot.
// In production this uses SPHINCS+; in tests it can be overridden.
type TreeRootVerifier interface {
	// VerifyTreeRoot checks the signature on the tree root.
	VerifyTreeRoot(root *TreeRoot) error
}

// SPHINCSTreeVerifier is the production verifier using SPHINCS+.
type SPHINCSTreeVerifier struct {
	// In a full implementation, this would hold a reference to the
	// Sphinx SPHINCS+ key manager for verification.
	// For now we perform basic structural validation.
}
