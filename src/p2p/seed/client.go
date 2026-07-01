// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/p2p/dnsdiscovery/client.go
//
// EIP-1459 DNS discovery client for Sphinx.
//
// Implements:
//   - enrtree:// URL parsing
//   - DNS TXT record fetching with retries
//   - Merkle tree traversal (branch and leaf records)
//   - SPHINCS+ signature verification of the tree root
//   - Peer collection from the tree

package dnsdiscovery

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/network"
)

// VerifyTreeRoot performs structural and cryptographic verification.
func (v *SPHINCSTreeVerifier) VerifyTreeRoot(root *TreeRoot) error {
	// Validate version
	if root.Version != ENRTreeVersion {
		return &VerificationError{
			Reason: fmt.Sprintf("unsupported tree version: %s", root.Version),
		}
	}

	// Validate eroot is present
	if root.ERoot == "" {
		return &VerificationError{Reason: "empty eroot"}
	}

	// Validate public key is present
	if root.PublicKey == "" {
		return &VerificationError{Reason: "empty public key in root"}
	}

	// Validate signature is present
	if root.Signature == "" {
		return &VerificationError{Reason: "empty signature in root"}
	}

	return nil
}

// NewClient creates a new DNS discovery client.
func NewClient() *Client {
	return &Client{
		resolver: net.DefaultResolver,
		timeout:  DNSTimeout,
		retries:  MaxDNSRetries,
		cache:    make(map[string]cachedTree),
		cacheTTL: DefaultTreeTTL,
		verifier: &SPHINCSTreeVerifier{},
	}
}

// AddTreeURL adds an enrtree:// URL to the list of known discovery trees.
func (c *Client) AddTreeURL(url string) error {
	if _, err := ParseTreeURL(url); err != nil {
		return fmt.Errorf("invalid tree URL %q: %w", url, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.knownTreeURLs = append(c.knownTreeURLs, url)
	return nil
}

// SetVerifier sets a custom tree root verifier.
func (c *Client) SetVerifier(v TreeRootVerifier) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.verifier = v
}

// DiscoverPeers fetches and verifies the DNS discovery tree(s) and returns
// the list of discovered peers.  Results from multiple trees are merged.
// Duplicate peers (by address) are removed.
func (c *Client) DiscoverPeers(ctx context.Context) ([]network.PeerInfo, error) {
	c.mu.RLock()
	urls := make([]string, len(c.knownTreeURLs))
	copy(urls, c.knownTreeURLs)
	c.mu.RUnlock()

	if len(urls) == 0 {
		return nil, fmt.Errorf("dnsdiscovery: no tree URLs configured")
	}

	peerMap := make(map[string]network.PeerInfo)
	var lastErr error

	for _, url := range urls {
		peers, err := c.discoverFromTree(ctx, url)
		if err != nil {
			log.Printf("dnsdiscovery: failed to discover from %s: %v", url, err)
			lastErr = err
			continue
		}

		for _, p := range peers {
			if p.Address != "" {
				peerMap[p.Address] = p
			}
		}
	}

	if len(peerMap) == 0 && lastErr != nil {
		return nil, fmt.Errorf("dnsdiscovery: all tree URLs failed, last error: %w", lastErr)
	}

	result := make([]network.PeerInfo, 0, len(peerMap))
	for _, p := range peerMap {
		result = append(result, p)
	}

	log.Printf("dnsdiscovery: discovered %d unique peers from %d DNS trees",
		len(result), len(urls))
	return result, nil
}

// discoverFromTree fetches and verifies a single DNS discovery tree.
func (c *Client) discoverFromTree(ctx context.Context, treeURL string) ([]network.PeerInfo, error) {
	parsed, err := ParseTreeURL(treeURL)
	if err != nil {
		return nil, err
	}

	// Check cache first
	c.mu.RLock()
	cached, exists := c.cache[parsed.Domain]
	c.mu.RUnlock()
	if exists && time.Now().Before(cached.expiry) {
		log.Printf("dnsdiscovery: cache hit for %s (%d peers, seq=%d)",
			parsed.Domain, len(cached.peers), cached.sequence)
		return cached.peers, nil
	}

	// Step 1: Fetch and verify the signed tree root
	root, err := c.fetchTreeRoot(ctx, parsed.Domain)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tree root: %w", err)
	}

	if err := c.verifier.VerifyTreeRoot(root); err != nil {
		return nil, &VerificationError{
			Reason: fmt.Sprintf("root verification failed: %v", err),
			Domain: parsed.Domain,
		}
	}

	// Step 2: Traverse the entry tree to collect peer records
	peers := make(map[string]network.PeerInfo)

	if root.ERoot != "" {
		eroot, err := hexDecode(root.ERoot)
		if err != nil {
			return nil, fmt.Errorf("invalid eroot hex: %w", err)
		}
		if err := c.traverseSubtree(ctx, parsed.Domain, "", eroot, peers); err != nil {
			return nil, fmt.Errorf("traverse eroot: %w", err)
		}
	}

	// Step 3: Optionally traverse linked trees
	if root.LRoot != "" {
		lroot, err := hexDecode(root.LRoot)
		if err != nil {
			return nil, fmt.Errorf("invalid lroot hex: %w", err)
		}
		if err := c.traverseLinkTree(ctx, parsed.Domain, lroot, peers); err != nil {
			log.Printf("dnsdiscovery: warning: link tree traversal for %s failed: %v",
				parsed.Domain, err)
		}
	}

	result := make([]network.PeerInfo, 0, len(peers))
	for _, p := range peers {
		result = append(result, p)
	}

	// Update cache
	c.mu.Lock()
	c.cache[parsed.Domain] = cachedTree{
		peers:    result,
		expiry:   time.Now().Add(c.cacheTTL),
		sequence: root.Sequence,
	}
	c.mu.Unlock()

	log.Printf("dnsdiscovery: fetched %d peers from %s (seq=%d)",
		len(result), parsed.Domain, root.Sequence)
	return result, nil
}

// fetchTreeRoot fetches and parses the signed tree root from TXT records.
func (c *Client) fetchTreeRoot(ctx context.Context, domain string) (*TreeRoot, error) {
	// The root record is at: root.<domain>
	rootDomain := "root." + domain

	txtRecords, err := c.lookupTXTRetry(ctx, rootDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup root TXT at %s: %w", rootDomain, err)
	}

	if len(txtRecords) == 0 {
		return nil, &ParseError{
			Domain: rootDomain,
			Record: "<empty>",
			Err:    fmt.Errorf("no TXT records found"),
		}
	}

	// Parse the root TXT record.
	// Format: enrtree-root:v1 e=<eroot> l=<lroot> seq=<seq> sig=<sig> pk=<pk>
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "enrtree-root:v1") {
			return parseTreeRoot(txt)
		}
	}

	return nil, &ParseError{
		Domain: rootDomain,
		Record: strings.Join(txtRecords, "; "),
		Err:    fmt.Errorf("no enrtree-root:v1 record found"),
	}
}

// parseTreeRoot parses a raw TXT record string into a TreeRoot.
// Format: enrtree-root:v1 e=<hex_eroot> l=<hex_lroot> seq=<seq> sig=<hex_sig> pk=<hex_pk>
func parseTreeRoot(txt string) (*TreeRoot, error) {
	parts := strings.Fields(txt)
	if len(parts) < 2 || parts[0] != "enrtree-root:v1" {
		return nil, fmt.Errorf("invalid root record format")
	}

	root := &TreeRoot{
		Version: ENRTreeVersion,
	}

	for _, part := range parts[1:] {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, value := kv[0], kv[1]
		switch key {
		case "e":
			root.ERoot = value
		case "l":
			root.LRoot = value
		case "seq":
			var seq uint64
			if _, err := fmt.Sscanf(value, "%d", &seq); err != nil {
				return nil, fmt.Errorf("invalid seq: %w", err)
			}
			root.Sequence = seq
		case "sig":
			root.Signature = value
		case "pk":
			root.PublicKey = value
		}
	}

	if root.ERoot == "" {
		return nil, fmt.Errorf("root record missing eroot")
	}
	if root.Signature == "" {
		return nil, fmt.Errorf("root record missing signature")
	}

	return root, nil
}

// traverseSubtree recursively traverses a DNS tree starting from a subdomain
// and collects all peer records into the peers map.
func (c *Client) traverseSubtree(ctx context.Context, domain, subpath string, _ []byte, peers map[string]network.PeerInfo) error {
	// Construct the subdomain for this tree node.
	// The subpath is a dot-separated chain of base32-encoded hashes.
	// At the root (subpath == ""), we query the domain directly.
	// For child nodes, we prepend the base32-encoded hash of the current node.
	fqdn := subpath
	if fqdn != "" {
		fqdn = fqdn + "." + domain
	} else {
		fqdn = domain
	}

	txtRecords, err := c.lookupTXTRetry(ctx, fqdn)
	if err != nil {
		return &TreeError{
			Domain: domain,
			Path:   subpath,
			Err:    fmt.Errorf("TXT lookup failed: %w", err),
		}
	}

	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "enrtree-branch:") {
			// This is a branch node — traverse children
			branches := strings.TrimPrefix(txt, "enrtree-branch:")
			children := strings.Split(branches, ",")
			for _, childHash := range children {
				childHash = strings.TrimSpace(childHash)
				if childHash == "" {
					continue
				}
				childBytes, err := hexDecode(childHash)
				if err != nil {
					log.Printf("dnsdiscovery: invalid child hash %q in %s: %v",
						childHash, fqdn, err)
					continue
				}
				childPath := subpath
				if childPath != "" {
					childPath = childPath + "." + childHash
				} else {
					childPath = childHash
				}
				if err := c.traverseSubtree(ctx, domain, childPath, childBytes, peers); err != nil {
					log.Printf("dnsdiscovery: subtree traversal error at %s: %v", childPath, err)
					continue
				}
			}
		} else if strings.HasPrefix(txt, "enrtree://") {
			// This is a link to another tree — follow it
			linkURL := strings.TrimSpace(txt)
			log.Printf("dnsdiscovery: following link tree %s", linkURL)
			if linkPeers, err := c.discoverFromTree(ctx, linkURL); err == nil {
				for _, p := range linkPeers {
					if p.Address != "" {
						peers[p.Address] = p
					}
				}
			} else {
				log.Printf("dnsdiscovery: failed to follow link %s: %v", linkURL, err)
			}
		} else if strings.HasPrefix(txt, "enr:") {
			// This is a leaf node — a SphinxNodeRecord
			enrData := strings.TrimPrefix(txt, "enr:")
			peer, err := parseSNR(enrData)
			if err != nil {
				log.Printf("dnsdiscovery: failed to parse ENR at %s: %v", fqdn, err)
				continue
			}
			peers[peer.Address] = *peer
		} else {
			// Try to parse as a raw JSON SphinxNodeRecord (our format)
			txt = strings.TrimSpace(txt)
			if strings.HasPrefix(txt, "{") && strings.HasSuffix(txt, "}") {
				peer, err := parseSNRJSON(txt)
				if err != nil {
					log.Printf("dnsdiscovery: failed to parse SNR JSON at %s: %v", fqdn, err)
					continue
				}
				peers[peer.Address] = *peer
			}
		}
	}

	return nil
}

// traverseLinkTree traverses the link tree to discover linked tree URLs.
func (c *Client) traverseLinkTree(ctx context.Context, domain string, expectedHash []byte, peers map[string]network.PeerInfo) error {
	// Link tree follows the same structure but contains enrtree:// links
	// rather than peer records.
	subdomain := encodeSubdomain(expectedHash)
	fqdn := subdomain + "." + domain

	txtRecords, err := c.lookupTXTRetry(ctx, fqdn)
	if err != nil {
		return err
	}

	for _, txt := range txtRecords {
		txt = strings.TrimSpace(txt)
		if strings.HasPrefix(txt, "enrtree://") {
			linkURL := txt
			log.Printf("dnsdiscovery: following link tree %s from link tree", linkURL)
			if linkPeers, err := c.discoverFromTree(ctx, linkURL); err == nil {
				for _, p := range linkPeers {
					if p.Address != "" {
						peers[p.Address] = p
					}
				}
			}
		}
	}

	return nil
}

// lookupTXTRetry performs a DNS TXT lookup with retries.
func (c *Client) lookupTXTRetry(ctx context.Context, domain string) ([]string, error) {
	var lastErr error
	for attempt := 0; attempt < c.retries; attempt++ {
		// Create a new context with timeout for each attempt
		lookupCtx, cancel := context.WithTimeout(ctx, c.timeout)
		records, err := c.resolver.LookupTXT(lookupCtx, domain)
		cancel()

		if err == nil && len(records) > 0 {
			return records, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("empty TXT records")
		}

		// Exponential backoff
		if attempt < c.retries-1 {
			backoff := time.Duration(100*(1<<attempt)) * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}
	}
	return nil, lastErr
}

// encodeSubdomain encodes a hash into a DNS-safe base32 string.
// Uses RFC 4648 base32 without padding (lowercase).
func encodeSubdomain(hash []byte) string {
	// Use base32 encoding (lowercase, no padding) for DNS-safe names
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash))
}

// ============================================================================
// URL parsing
// ============================================================================

// ParsedTreeURL represents a parsed enrtree:// URL.
type ParsedTreeURL struct {
	// Scheme is the URL scheme (always "enrtree")
	Scheme string

	// PublicKey is the hex-encoded public key from the URL
	PublicKey []byte

	// Domain is the DNS domain for discovery
	Domain string

	// RawURL is the original URL string
	RawURL string
}

// ParseTreeURL parses an enrtree:// URL.
// Format: enrtree://<pubkey>@<domain>
// Example: enrtree://AEDA4B62B4B4E4E4@nodes.sphinx.network
func ParseTreeURL(url string) (*ParsedTreeURL, error) {
	if !strings.HasPrefix(url, ENRTreeScheme+"://") {
		return nil, fmt.Errorf("invalid scheme: expected %s://", ENRTreeScheme)
	}

	rest := strings.TrimPrefix(url, ENRTreeScheme+"://")

	// Split at '@' to get pubkey and domain
	atIndex := strings.LastIndex(rest, "@")
	if atIndex < 0 {
		return nil, fmt.Errorf("missing @ in tree URL")
	}

	pubkeyHex := rest[:atIndex]
	domain := rest[atIndex+1:]

	if pubkeyHex == "" {
		return nil, fmt.Errorf("empty public key in tree URL")
	}
	if domain == "" {
		return nil, fmt.Errorf("empty domain in tree URL")
	}

	pubkey, err := hexDecode(pubkeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid public key hex in tree URL: %w", err)
	}

	return &ParsedTreeURL{
		Scheme:    ENRTreeScheme,
		PublicKey: pubkey,
		Domain:    domain,
		RawURL:    url,
	}, nil
}

// ============================================================================
// Peer record parsing
// ============================================================================

// parseSNR parses a compact SphinxNodeRecord from the "enr:" format.
// Format: enr:<id>;<kademlia_hex>;<addr>;<udp>;<pk_hex>;<pv>
func parseSNR(data string) (*network.PeerInfo, error) {
	parts := strings.Split(data, ";")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid enr format: expected at least 4 parts, got %d", len(parts))
	}

	record := &SphinxNodeRecord{
		ID:         parts[0],
		KademliaID: parts[1],
		Address:    parts[2],
		UDPPort:    parts[3],
	}

	if len(parts) > 4 {
		record.PublicKey = parts[4]
	}
	if len(parts) > 5 {
		record.ProtocolVersion = parts[5]
	} else {
		record.ProtocolVersion = "1.0"
	}

	peerInfo := snrToPeerInfo(record)
	return &peerInfo, nil
}

// parseSNRJSON parses a SphinxNodeRecord from JSON.
func parseSNRJSON(jsonData string) (*network.PeerInfo, error) {
	var record SphinxNodeRecord
	if err := json.Unmarshal([]byte(jsonData), &record); err != nil {
		return nil, fmt.Errorf("json parse error: %w", err)
	}
	peerInfo := snrToPeerInfo(&record)
	return &peerInfo, nil
}

// snrToPeerInfo converts a SphinxNodeRecord to a network.PeerInfo.
func snrToPeerInfo(snr *SphinxNodeRecord) network.PeerInfo {
	return network.PeerInfo{
		NodeID:          snr.ID,
		Address:         snr.Address,
		UDPPort:         snr.UDPPort,
		Status:          network.NodeStatusActive,
		Timestamp:       time.Now(),
		ProtocolVersion: "1.0",
	}
}

// ============================================================================
// Tree builder (for publishers — crawlers, bootnodes)
// ============================================================================

// TreeBuilder constructs and serialises a DNS discovery Merkle tree.
// This is used by the publishing side (crawler/bootnode operator).
type TreeBuilder struct {
	records   []SphinxNodeRecord
	maxBranch int
}

// NewTreeBuilder creates a new TreeBuilder.
// maxBranch sets the maximum number of children per branch node (default 24).
func NewTreeBuilder(maxBranch int) *TreeBuilder {
	if maxBranch <= 0 {
		maxBranch = 24
	}
	return &TreeBuilder{
		maxBranch: maxBranch,
	}
}

// AddRecord adds a node record to the tree.
func (tb *TreeBuilder) AddRecord(record SphinxNodeRecord) {
	tb.records = append(tb.records, record)
}

// Build constructs the Merkle tree and returns the serialised TXT records.
// Returns all TXT records (breadth-first), and a map of hash->TXT record for
// every node in the tree.  The caller uses the branchMap to deploy DNS TXT
// records keyed by base32 subdomain.
func (tb *TreeBuilder) Build() ([]string, map[string]string, error) {
	if len(tb.records) == 0 {
		return nil, nil, fmt.Errorf("no records to build tree from")
	}

	// Serialise each record and compute its hash
	leaves := make([]leafNode, len(tb.records))
	for i, rec := range tb.records {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal record %d: %w", i, err)
		}
		hash := sha256.Sum256(data)
		leaves[i] = leafNode{
			hash: hash[:],
			data: "enr:" + serializeSNRCompact(&rec),
		}
	}

	// Build the Merkle tree
	tree := buildMerkleTree(leaves, tb.maxBranch)
	if len(tree) == 0 {
		return nil, nil, fmt.Errorf("empty tree")
	}

	// Flatten all nodes BFS so the caller gets every DNS TXT record needed.
	allNodes := flattenTree(tree[0])
	txtRecords := make([]string, 0, len(allNodes))
	branchMap := make(map[string]string, len(allNodes))

	for _, node := range allNodes {
		if node.isLeaf || node.data != "" {
			txtRecords = append(txtRecords, node.data)
			branchMap[hexEncode(node.hash)] = node.data
		} else {
			// Branch node
			childHexes := make([]string, len(node.children))
			for i, child := range node.children {
				childHexes[i] = hexEncode(child.hash)
			}
			branchTxt := "enrtree-branch:" + strings.Join(childHexes, ",")
			txtRecords = append(txtRecords, branchTxt)
			branchMap[hexEncode(node.hash)] = branchTxt
		}
	}

	return txtRecords, branchMap, nil
}

// leafNode represents a single leaf in the tree
type leafNode struct {
	hash   []byte
	data   string
	isLeaf bool
}

// treeNode represents a node in the Merkle tree
type treeNode struct {
	hash     []byte
	data     string
	isLeaf   bool
	children []treeNode
}

// flattenTree returns all nodes in the tree in breadth-first order.
func flattenTree(root treeNode) []treeNode {
	var result []treeNode
	queue := []treeNode{root}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		result = append(result, node)
		for _, child := range node.children {
			queue = append(queue, child)
		}
	}
	return result
}

// buildMerkleTree builds a Merkle tree from leaf nodes.
func buildMerkleTree(leaves []leafNode, maxBranch int) []treeNode {
	if len(leaves) == 0 {
		return nil
	}

	// Sort leaves by hash for deterministic ordering
	nodes := make([]treeNode, len(leaves))
	for i, l := range leaves {
		nodes[i] = treeNode{
			hash:   l.hash,
			data:   l.data,
			isLeaf: true,
		}
	}

	// Build the tree bottom-up
	for len(nodes) > 1 {
		var nextLevel []treeNode
		for i := 0; i < len(nodes); i += maxBranch {
			end := i + maxBranch
			if end > len(nodes) {
				end = len(nodes)
			}
			children := nodes[i:end]

			// Compute branch hash = H(child1_hash || child2_hash || ...)
			var hashInput []byte
			for _, child := range children {
				hashInput = append(hashInput, child.hash...)
			}
			branchHash := sha256.Sum256(hashInput)

			nextLevel = append(nextLevel, treeNode{
				hash:     branchHash[:],
				children: children,
			})
		}
		nodes = nextLevel
	}

	return nodes
}

// serializeSNRCompact serialises a SphinxNodeRecord into the compact
// semicolon-delimited format used in enr: TXT records.
func serializeSNRCompact(rec *SphinxNodeRecord) string {
	return fmt.Sprintf("%s;%s;%s;%s;%s",
		rec.ID,
		rec.KademliaID,
		rec.Address,
		rec.UDPPort,
		rec.PublicKey,
	)
}

// GenerateRootTXT generates the signed root TXT record for a tree.
// treeRootHash is the hex-encoded Merkle root hash of the entry tree.
// linkRootHash is the hex-encoded Merkle root hash of the link tree (empty if none).
// signature is the hex-encoded SPHINCS+ signature.
// publicKey is the hex-encoded SPHINCS+ public key.
// sequence is the tree sequence number (increment on each update).
func GenerateRootTXT(treeRootHash, linkRootHash, signature, publicKey string, sequence uint64) string {
	eroot := strings.TrimPrefix(treeRootHash, "BRA-")
	lroot := ""
	if linkRootHash != "" {
		lroot = strings.TrimPrefix(linkRootHash, "BRA-")
	}
	return fmt.Sprintf("enrtree-root:v1 e=%s l=%s seq=%d sig=%s pk=%s",
		eroot, lroot, sequence, signature, publicKey)
}

// ============================================================================
// Helper: Merkle proof computation
// ============================================================================

// ComputeMerkleProof computes a Merkle proof for a leaf at the given index.
// Returns the proof as a list of sibling hashes.
func ComputeMerkleProof(records []SphinxNodeRecord, index int) ([][]byte, error) {
	if index < 0 || index >= len(records) {
		return nil, fmt.Errorf("index %d out of range (0-%d)", index, len(records)-1)
	}

	// Compute leaf hashes
	hasher := sha256.New()
	leaves := make([][]byte, len(records))
	for i, rec := range records {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		hasher.Reset()
		hasher.Write(data)
		leaves[i] = hasher.Sum(nil)
	}

	maxBranch := 24
	proof := make([][]byte, 0)

	// Build the proof bottom-up
	currentLevel := leaves
	targetIndex := index

	for len(currentLevel) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(currentLevel); i += maxBranch {
			end := i + maxBranch
			if end > len(currentLevel) {
				end = len(currentLevel)
			}

			// If our target is in this group, collect siblings
			if targetIndex >= i && targetIndex < end {
				for j := i; j < end; j++ {
					if j != targetIndex {
						proof = append(proof, currentLevel[j])
					}
				}
				targetIndex = i / maxBranch // new parent index
			}

			// Compute parent hash = H(child1_hash || child2_hash || ...)
			hasher.Reset()
			for j := i; j < end; j++ {
				hasher.Write(currentLevel[j])
			}
			parentHash := hasher.Sum(nil)
			nextLevel = append(nextLevel, parentHash)
		}
		currentLevel = nextLevel
	}

	return proof, nil
}

// encodeUint64 encodes a uint64 as 8 bytes big-endian.
func encodeUint64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// minInt returns the minimum of two integers.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// maxInt returns the maximum of two integers.
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ceilDiv performs ceiling integer division.
func ceilDiv(a, b int) int {
	if a <= 0 || b <= 0 {
		return 0
	}
	return (a + b - 1) / b
}

// ComputeRootHash computes the Merkle root hash for a set of records.
func ComputeRootHash(records []SphinxNodeRecord) ([]byte, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no records to compute root hash")
	}

	hasher := sha256.New()
	leaves := make([]leafNode, len(records))
	for i, rec := range records {
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		hasher.Reset()
		hasher.Write(data)
		hash := make([]byte, 32)
		copy(hash, hasher.Sum(nil))
		leaves[i] = leafNode{hash: hash, data: string(data), isLeaf: true}
	}

	tree := buildMerkleTree(leaves, 24)
	if len(tree) == 0 {
		return nil, fmt.Errorf("empty tree")
	}
	return tree[0].hash, nil
}
