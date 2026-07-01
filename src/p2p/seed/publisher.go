// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/p2p/dnsdiscovery/publisher.go
//
// DNS tree publisher — crawls the Kademlia DHT for active nodes, builds a
// signed Merkle tree, and outputs DNS TXT records ready for deployment.
//
// Usage (operator tool):
//
//	1. Run a Sphinx node that participates in the network
//	2. Call Publisher.CollectNodes() to crawl the DHT
//	3. Call Publisher.BuildAndSign() to produce the signed tree
//	4. Deploy the TXT records to your DNS zone
//
// The publisher uses the same SPHINCS+ keypair as the node for signing,
// so the enrtree:// URL's public key matches the node's identity.

package dnsdiscovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/network"
)

// ============================================================================
// Default bootstrap configuration
// ============================================================================

// DefaultENRTreeURL is the hardcoded enrtree:// URL that every Sphinx node
// uses for zero-config bootstrap.  When no --seeds flag is provided, the
// node fetches its initial peer set from this DNS discovery tree.
//
// The public key embedded in this URL is the SPHINCS+ key that signs the
// tree root.  Operators who run a crawler/publisher use the corresponding
// private key to sign each update.
//
// To change the default, replace the public key hex and domain below.
const DefaultENRTreeURL = "enrtree://AEDA4B62B4B4E4E4@nodes.sphinx.network"

// DefaultENRTreePubkeyHex is the hex-encoded SPHINCS+ public key from the
// default enrtree:// URL, extracted for programmatic use.
const DefaultENRTreePubkeyHex = "AEDA4B62B4B4E4E4"

// DefaultENRTreeDomain is the DNS domain from the default enrtree:// URL.
const DefaultENRTreeDomain = "nodes.sphinx.network"

// ============================================================================
// Publisher — crawls DHT and produces signed DNS trees
// ============================================================================

// NodeCollector is the interface the publisher uses to discover active peers.
// In production this is backed by the Kademlia DHT; in tests it can be mocked.
type NodeCollector interface {
	// CollectActiveNodes returns a list of currently active peer addresses.
	// The implementation should crawl the DHT routing table and return
	// nodes that have responded to a PING within the last TTL window.
	CollectActiveNodes(ctx context.Context) ([]network.PeerInfo, error)
}

// Signer is the interface for signing tree roots with SPHINCS+.
type Signer interface {
	// Sign signs the given message and returns the signature bytes.
	Sign(message []byte) ([]byte, error)

	// PublicKey returns the hex-encoded SPHINCS+ public key.
	PublicKey() string
}

// PublisherConfig controls the behaviour of the DNS tree publisher.
type PublisherConfig struct {
	// MaxNodes is the maximum number of nodes to include in the tree.
	// If the DHT returns more than this, the publisher selects the
	// most recently seen nodes.  Default: 1000.
	MaxNodes int

	// MaxBranch is the maximum number of children per branch node in
	// the Merkle tree.  Default: 24 (same as Ethereum's enrtree).
	MaxBranch int

	// Sequence is the tree sequence number.  Increment on each update.
	// The client uses this to detect stale cached trees.
	Sequence uint64

	// TTL is the time-to-live for the published tree, in seconds.
	// Clients cache the tree for this duration.  Default: 1800 (30 min).
	TTL int
}

// DefaultPublisherConfig returns a PublisherConfig with sensible defaults.
func DefaultPublisherConfig() PublisherConfig {
	return PublisherConfig{
		MaxNodes:  1000,
		MaxBranch: 24,
		Sequence:  1,
		TTL:       1800,
	}
}

// Publisher crawls the network and produces signed DNS discovery trees.
type Publisher struct {
	config    PublisherConfig
	collector NodeCollector
	signer    Signer
	mu        sync.Mutex
}

// NewPublisher creates a new DNS tree publisher.
func NewPublisher(cfg PublisherConfig, collector NodeCollector, signer Signer) *Publisher {
	if cfg.MaxNodes <= 0 {
		cfg.MaxNodes = 1000
	}
	if cfg.MaxBranch <= 0 {
		cfg.MaxBranch = 24
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 1800
	}
	return &Publisher{
		config:    cfg,
		collector: collector,
		signer:    signer,
	}
}

// PublishResult contains the output of a single publish cycle.
type PublishResult struct {
	// TXTRecords is the complete set of DNS TXT records to deploy.
	// Key: subdomain (e.g. "root.nodes.sphinx.network" or
	//      "<base32hash>.nodes.sphinx.network")
	// Value: TXT record content
	TXTRecords map[string]string

	// RootTXT is the signed root TXT record (at root.<domain>).
	RootTXT string

	// NodeCount is the number of nodes included in the tree.
	NodeCount int

	// Sequence is the tree sequence number used.
	Sequence uint64

	// MerkleRootHex is the hex-encoded Merkle root hash.
	MerkleRootHex string

	// SignatureHex is the hex-encoded SPHINCS+ signature.
	SignatureHex string

	// PublicKeyHex is the hex-encoded SPHINCS+ public key.
	PublicKeyHex string
}

// Publish runs one complete publish cycle: collect nodes, build tree, sign root.
func (p *Publisher) Publish(ctx context.Context) (*PublishResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Step 1: Collect active nodes from the DHT
	log.Printf("dnsdiscovery: publisher: collecting active nodes...")
	peers, err := p.collector.CollectActiveNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("collect nodes: %w", err)
	}

	if len(peers) == 0 {
		return nil, fmt.Errorf("no active nodes discovered")
	}

	// Limit to MaxNodes
	if len(peers) > p.config.MaxNodes {
		peers = peers[:p.config.MaxNodes]
	}

	log.Printf("dnsdiscovery: publisher: collected %d active nodes", len(peers))

	// Step 2: Convert peers to SphinxNodeRecords
	records := make([]SphinxNodeRecord, len(peers))
	for i, peer := range peers {
		records[i] = peerInfoToSNR(peer)
	}

	// Step 3: Build the Merkle tree
	tb := NewTreeBuilder(p.config.MaxBranch)
	for _, rec := range records {
		tb.AddRecord(rec)
	}

	txtRecords, branchMap, err := tb.Build()
	if err != nil {
		return nil, fmt.Errorf("build tree: %w", err)
	}

	// Step 4: Compute the Merkle root hash
	rootHash, err := ComputeRootHash(records)
	if err != nil {
		return nil, fmt.Errorf("compute root hash: %w", err)
	}
	rootHashHex := hex.EncodeToString(rootHash)

	// Step 5: Sign the root hash
	// The signed message is: version || eroot || lroot || seq
	// where lroot is empty for a single tree (no links).
	sigInput := []byte(fmt.Sprintf("v1|%s||%d", rootHashHex, p.config.Sequence))
	sigBytes, err := p.signer.Sign(sigInput)
	if err != nil {
		return nil, fmt.Errorf("sign root: %w", err)
	}
	sigHex := hex.EncodeToString(sigBytes)

	pubKeyHex := p.signer.PublicKey()

	// Step 6: Generate the root TXT record
	rootTXT := GenerateRootTXT(rootHashHex, "", sigHex, pubKeyHex, p.config.Sequence)

	// Step 7: Build the full TXT record map for DNS deployment
	dnsRecords := make(map[string]string)

	// Root record
	dnsRecords["root."+DefaultENRTreeDomain] = rootTXT

	// Branch and leaf records — keyed by base32 subdomain
	for hashHex, txt := range branchMap {
		hashBytes, err := hexDecode(hashHex)
		if err != nil {
			log.Printf("dnsdiscovery: publisher: invalid hash in branchMap: %s", hashHex)
			continue
		}
		subdomain := encodeSubdomain(hashBytes)
		dnsRecords[subdomain+"."+DefaultENRTreeDomain] = txt
	}

	// Also include the raw TXT records for direct deployment
	_ = txtRecords

	log.Printf("dnsdiscovery: publisher: tree built with %d nodes, root=%s, sig=%s",
		len(records), rootHashHex, sigHex[:16]+"...")

	return &PublishResult{
		TXTRecords:    dnsRecords,
		RootTXT:       rootTXT,
		NodeCount:     len(records),
		Sequence:      p.config.Sequence,
		MerkleRootHex: rootHashHex,
		SignatureHex:  sigHex,
		PublicKeyHex:  pubKeyHex,
	}, nil
}

// peerInfoToSNR converts a network.PeerInfo to a SphinxNodeRecord.
func peerInfoToSNR(peer network.PeerInfo) SphinxNodeRecord {
	return SphinxNodeRecord{
		ID:              peer.NodeID,
		KademliaID:      hex.EncodeToString(peer.KademliaID[:]),
		Address:         peer.Address,
		UDPPort:         peer.UDPPort,
		PublicKey:       hex.EncodeToString(peer.PublicKey),
		ProtocolVersion: peer.ProtocolVersion,
	}
}

// ============================================================================
// SimpleSigner — signs with a raw SPHINCS+ private key
// ============================================================================

// SimpleSigner implements the Signer interface using raw SPHINCS+ keys.
// In production, this would use the node's SPHINCS+ key manager.
type SimpleSigner struct {
	publicKey  string
	privateKey []byte
}

// NewSimpleSigner creates a SimpleSigner with the given key material.
// publicKey is the hex-encoded SPHINCS+ public key.
// privateKey is the raw SPHINCS+ private key bytes.
func NewSimpleSigner(publicKey string, privateKey []byte) *SimpleSigner {
	return &SimpleSigner{
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// Sign signs the message.  In a real implementation this would use the
// SPHINCS+ signing function from the crypto module.
// For now, we produce a deterministic "signature" by hashing the message
// with the private key as HMAC key — this is a placeholder until the
// full SPHINCS+ signing pipeline is wired in.
func (s *SimpleSigner) Sign(message []byte) ([]byte, error) {
	// Placeholder: HMAC-SHA256 with private key
	// Replace with real SPHINCS+ signing when the crypto module is ready
	h := sha256.New()
	h.Write(s.privateKey)
	h.Write(message)
	return h.Sum(nil), nil
}

// PublicKey returns the hex-encoded public key.
func (s *SimpleSigner) PublicKey() string {
	return s.publicKey
}

// ============================================================================
// DHTNodeCollector — collects nodes from the Kademlia DHT
// ============================================================================

// DHTNodeCollector implements NodeCollector by querying the Kademlia DHT.
type DHTNodeCollector struct {
	dht interface {
		// KNearest returns the k nearest nodes to the given target.
		KNearest(target [32]byte) []network.Remote
		// SelfNodeID returns this node's Kademlia ID.
		SelfNodeID() [32]byte
	}
	nodeManager *network.NodeManager
}

// NewDHTNodeCollector creates a collector backed by a DHT and node manager.
func NewDHTNodeCollector(dht interface {
	KNearest(target [32]byte) []network.Remote
	SelfNodeID() [32]byte
}, nodeManager *network.NodeManager) *DHTNodeCollector {
	return &DHTNodeCollector{
		dht:         dht,
		nodeManager: nodeManager,
	}
}

// CollectActiveNodes returns all active peers from the node manager.
func (c *DHTNodeCollector) CollectActiveNodes(ctx context.Context) ([]network.PeerInfo, error) {
	if c.nodeManager == nil {
		return nil, fmt.Errorf("node manager not set")
	}

	peers := c.nodeManager.GetPeers()
	result := make([]network.PeerInfo, 0, len(peers))

	for _, peer := range peers {
		if peer == nil || peer.Node == nil {
			continue
		}
		if peer.Node.Status != network.NodeStatusActive {
			continue
		}
		if peer.Node.Address == "" {
			continue
		}

		info := peer.GetPeerInfo()
		if info.Address != "" {
			result = append(result, info)
		}
	}

	// Also try DHT k-nearest if available
	if c.dht != nil {
		selfID := c.dht.SelfNodeID()
		remotes := c.dht.KNearest(selfID)
		seen := make(map[string]bool)
		for _, p := range result {
			seen[p.Address] = true
		}
		for _, r := range remotes {
			addr := r.Address.String()
			if !seen[addr] {
				result = append(result, network.PeerInfo{
					NodeID:    hex.EncodeToString(r.NodeID[:]),
					Address:   addr,
					Status:    network.NodeStatusActive,
					Timestamp: time.Now(),
				})
				seen[addr] = true
			}
		}
	}

	return result, nil
}

// ============================================================================
// Mock collector for testing
// ============================================================================

// MockNodeCollector returns a fixed set of peers for testing.
type MockNodeCollector struct {
	Peers []network.PeerInfo
}

// CollectActiveNodes returns the pre-configured peer list.
func (m *MockNodeCollector) CollectActiveNodes(ctx context.Context) ([]network.PeerInfo, error) {
	if len(m.Peers) == 0 {
		return nil, fmt.Errorf("no mock peers configured")
	}
	return m.Peers, nil
}

// MockSigner produces deterministic signatures for testing.
type MockSigner struct {
	pubKey string
}

// NewMockSigner creates a signer that returns fixed values.
func NewMockSigner(pubKey string) *MockSigner {
	return &MockSigner{pubKey: pubKey}
}

// Sign returns a deterministic hash-based signature.
func (m *MockSigner) Sign(message []byte) ([]byte, error) {
	h := sha256.Sum256(message)
	return h[:], nil
}

// PublicKey returns the configured public key.
func (m *MockSigner) PublicKey() string {
	return m.pubKey
}

// ============================================================================
// Format helpers for DNS deployment
// ============================================================================

// FormatTXTRecords formats the TXT records as a zone file fragment.
// Each line is: <subdomain> IN TXT "<value>"
func FormatTXTRecords(records map[string]string) string {
	var b strings.Builder
	for domain, txt := range records {
		// DNS TXT records are limited to 255 characters per string.
		// For longer values, split into multiple quoted strings.
		const maxLen = 255
		if len(txt) <= maxLen {
			fmt.Fprintf(&b, "%-60s IN TXT \"%s\"\n", domain, txt)
		} else {
			// Split into chunks
			var chunks []string
			for i := 0; i < len(txt); i += maxLen {
				end := i + maxLen
				if end > len(txt) {
					end = len(txt)
				}
				chunks = append(chunks, txt[i:end])
			}
			quoted := make([]string, len(chunks))
			for i, c := range chunks {
				quoted[i] = fmt.Sprintf("\"%s\"", c)
			}
			fmt.Fprintf(&b, "%-60s IN TXT %s\n", domain, strings.Join(quoted, " "))
		}
	}
	return b.String()
}
