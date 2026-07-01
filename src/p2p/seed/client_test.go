// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package dnsdiscovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/network"
)

// ============================================================================
// URL Parsing Tests
// ============================================================================

func TestParseTreeURL_Valid(t *testing.T) {
	tests := []struct {
		url        string
		wantPub    string
		wantDomain string
	}{
		{
			url:        "enrtree://AEDA4B62B4B4E4E4@nodes.sphinx.network",
			wantPub:    "aeda4b62b4b4e4e4",
			wantDomain: "nodes.sphinx.network",
		},
		{
			url:        "enrtree://ABCD1234@test.example.com",
			wantPub:    "abcd1234",
			wantDomain: "test.example.com",
		},
		{
			url:        "enrtree://0102030405060708@bootnodes.sphinx.network",
			wantPub:    "0102030405060708",
			wantDomain: "bootnodes.sphinx.network",
		},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			parsed, err := ParseTreeURL(tt.url)
			if err != nil {
				t.Fatalf("ParseTreeURL(%q) unexpected error: %v", tt.url, err)
			}
			if parsed.Scheme != ENRTreeScheme {
				t.Errorf("scheme = %q, want %q", parsed.Scheme, ENRTreeScheme)
			}
			if hex.EncodeToString(parsed.PublicKey) != tt.wantPub {
				t.Errorf("pubkey hex = %q, want %q", hex.EncodeToString(parsed.PublicKey), tt.wantPub)
			}
			if parsed.Domain != tt.wantDomain {
				t.Errorf("domain = %q, want %q", parsed.Domain, tt.wantDomain)
			}
			if parsed.RawURL != tt.url {
				t.Errorf("rawURL = %q, want %q", parsed.RawURL, tt.url)
			}
		})
	}
}

func TestParseTreeURL_Invalid(t *testing.T) {
	tests := []struct {
		url string
		err string
	}{
		{"", "invalid scheme"},
		{"http://example.com", "invalid scheme"},
		{"enrtree://", "missing @"},
		{"enrtree://@domain.com", "empty public key"},
		{"enrtree://pubkey@", "empty domain"},
		{"enrtree://invalid!hex@domain.com", "invalid public key hex"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			_, err := ParseTreeURL(tt.url)
			if err == nil {
				t.Fatalf("ParseTreeURL(%q) expected error containing %q, got nil", tt.url, tt.err)
			}
			if !strings.Contains(err.Error(), tt.err) {
				t.Errorf("ParseTreeURL(%q) error = %q, want containing %q", tt.url, err.Error(), tt.err)
			}
		})
	}
}

// ============================================================================
// Tree Root Parsing Tests
// ============================================================================

func TestParseTreeRoot_Valid(t *testing.T) {
	txt := "enrtree-root:v1 e=abc123 l=def456 seq=42 sig=deadbeef pk=feedface"
	root, err := parseTreeRoot(txt)
	if err != nil {
		t.Fatalf("parseTreeRoot unexpected error: %v", err)
	}

	if root.Version != "v1" {
		t.Errorf("Version = %q, want %q", root.Version, "v1")
	}
	if root.ERoot != "abc123" {
		t.Errorf("ERoot = %q, want %q", root.ERoot, "abc123")
	}
	if root.LRoot != "def456" {
		t.Errorf("LRoot = %q, want %q", root.LRoot, "def456")
	}
	if root.Sequence != 42 {
		t.Errorf("Sequence = %d, want %d", root.Sequence, 42)
	}
	if root.Signature != "deadbeef" {
		t.Errorf("Signature = %q, want %q", root.Signature, "deadbeef")
	}
	if root.PublicKey != "feedface" {
		t.Errorf("PublicKey = %q, want %q", root.PublicKey, "feedface")
	}
}

func TestParseTreeRoot_NoLink(t *testing.T) {
	txt := "enrtree-root:v1 e=abc123 l= seq=1 sig=sig123 pk=pk456"
	root, err := parseTreeRoot(txt)
	if err != nil {
		t.Fatalf("parseTreeRoot unexpected error: %v", err)
	}
	if root.LRoot != "" {
		t.Errorf("LRoot = %q, want empty", root.LRoot)
	}
}

func TestParseTreeRoot_Invalid(t *testing.T) {
	tests := []struct {
		txt string
		err string
	}{
		{"", "invalid root record format"},
		{"not-a-root-record", "invalid root record format"},
		{"enrtree-root:v1", "invalid root record format"},
		{"enrtree-root:v1 e=abc123", "missing signature"},
	}

	for _, tt := range tests {
		t.Run(tt.txt, func(t *testing.T) {
			_, err := parseTreeRoot(tt.txt)
			if err == nil {
				t.Fatalf("parseTreeRoot(%q) expected error, got nil", tt.txt)
			}
			if !strings.Contains(err.Error(), tt.err) {
				t.Errorf("parseTreeRoot(%q) error = %q, want containing %q", tt.txt, err.Error(), tt.err)
			}
		})
	}
}

// ============================================================================
// SNR Parsing Tests
// ============================================================================

func TestParseSNR_Valid(t *testing.T) {
	data := "node1;kad123;192.168.1.1:30303;30304;pkhex123;1.0"
	peer, err := parseSNR(data)
	if err != nil {
		t.Fatalf("parseSNR unexpected error: %v", err)
	}

	if peer.NodeID != "node1" {
		t.Errorf("NodeID = %q, want %q", peer.NodeID, "node1")
	}
	if peer.Address != "192.168.1.1:30303" {
		t.Errorf("Address = %q, want %q", peer.Address, "192.168.1.1:30303")
	}
	if peer.UDPPort != "30304" {
		t.Errorf("UDPPort = %q, want %q", peer.UDPPort, "30304")
	}
}

func TestParseSNR_Minimal(t *testing.T) {
	data := "node1;kad123;192.168.1.1:30303;30304"
	peer, err := parseSNR(data)
	if err != nil {
		t.Fatalf("parseSNR unexpected error: %v", err)
	}
	if peer.NodeID != "node1" {
		t.Errorf("NodeID = %q, want %q", peer.NodeID, "node1")
	}
}

func TestParseSNR_Invalid(t *testing.T) {
	_, err := parseSNR("a;b")
	if err == nil {
		t.Fatal("parseSNR expected error for too few parts, got nil")
	}
}

func TestParseSNRJSON_Valid(t *testing.T) {
	record := SphinxNodeRecord{
		ID:         "node1",
		KademliaID: "kad123",
		Address:    "192.168.1.1:30303",
		UDPPort:    "30304",
		PublicKey:  "pkhex123",
	}
	data, _ := json.Marshal(record)

	peer, err := parseSNRJSON(string(data))
	if err != nil {
		t.Fatalf("parseSNRJSON unexpected error: %v", err)
	}
	if peer.NodeID != "node1" {
		t.Errorf("NodeID = %q, want %q", peer.NodeID, "node1")
	}
	if peer.Address != "192.168.1.1:30303" {
		t.Errorf("Address = %q, want %q", peer.Address, "192.168.1.1:30303")
	}
}

// ============================================================================
// Merkle Tree Building Tests
// ============================================================================

func TestTreeBuilder_Build(t *testing.T) {
	records := []SphinxNodeRecord{
		{ID: "node1", KademliaID: "kad1", Address: "192.168.1.1:30303", UDPPort: "30304", PublicKey: "pk1"},
		{ID: "node2", KademliaID: "kad2", Address: "192.168.1.2:30303", UDPPort: "30304", PublicKey: "pk2"},
		{ID: "node3", KademliaID: "kad3", Address: "192.168.1.3:30303", UDPPort: "30304", PublicKey: "pk3"},
	}

	tb := NewTreeBuilder(2) // small branch factor for testing
	for _, rec := range records {
		tb.AddRecord(rec)
	}

	txtRecords, branchMap, err := tb.Build()
	if err != nil {
		t.Fatalf("TreeBuilder.Build() unexpected error: %v", err)
	}

	if len(txtRecords) == 0 {
		t.Fatal("expected at least 1 TXT record")
	}

	// Verify all records are in the branch map
	for _, rec := range records {
		compact := "enr:" + serializeSNRCompact(&rec)
		found := false
		for _, txt := range txtRecords {
			if txt == compact {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("record %q not found in TXT records", rec.ID)
		}
	}

	// Verify branch map has entries
	if len(branchMap) == 0 {
		t.Fatal("expected non-empty branch map")
	}
}

func TestTreeBuilder_Empty(t *testing.T) {
	tb := NewTreeBuilder(24)
	_, _, err := tb.Build()
	if err == nil {
		t.Fatal("expected error for empty tree builder")
	}
}

func TestTreeBuilder_SingleRecord(t *testing.T) {
	tb := NewTreeBuilder(24)
	tb.AddRecord(SphinxNodeRecord{
		ID: "node1", KademliaID: "kad1", Address: "192.168.1.1:30303", UDPPort: "30304",
	})

	txtRecords, _, err := tb.Build()
	if err != nil {
		t.Fatalf("TreeBuilder.Build() unexpected error: %v", err)
	}

	if len(txtRecords) != 1 {
		t.Errorf("expected 1 TXT record, got %d", len(txtRecords))
	}
}

// ============================================================================
// Merkle Root Hash Tests
// ============================================================================

func TestComputeRootHash_Deterministic(t *testing.T) {
	records := []SphinxNodeRecord{
		{ID: "node1", KademliaID: "kad1", Address: "192.168.1.1:30303", UDPPort: "30304", PublicKey: "pk1"},
		{ID: "node2", KademliaID: "kad2", Address: "192.168.1.2:30303", UDPPort: "30304", PublicKey: "pk2"},
	}

	hash1, err := ComputeRootHash(records)
	if err != nil {
		t.Fatalf("ComputeRootHash unexpected error: %v", err)
	}

	hash2, err := ComputeRootHash(records)
	if err != nil {
		t.Fatalf("ComputeRootHash unexpected error: %v", err)
	}

	if !bytesEqual(hash1, hash2) {
		t.Error("ComputeRootHash is not deterministic")
	}
}

func TestComputeRootHash_Empty(t *testing.T) {
	_, err := ComputeRootHash(nil)
	if err == nil {
		t.Fatal("expected error for empty records")
	}
}

// ============================================================================
// GenerateRootTXT Tests
// ============================================================================

func TestGenerateRootTXT(t *testing.T) {
	txt := GenerateRootTXT("abc123", "def456", "sig123", "pk456", 42)
	expected := "enrtree-root:v1 e=abc123 l=def456 seq=42 sig=sig123 pk=pk456"
	if txt != expected {
		t.Errorf("GenerateRootTXT = %q, want %q", txt, expected)
	}
}

func TestGenerateRootTXT_NoLink(t *testing.T) {
	txt := GenerateRootTXT("abc123", "", "sig123", "pk456", 1)
	expected := "enrtree-root:v1 e=abc123 l= seq=1 sig=sig123 pk=pk456"
	if txt != expected {
		t.Errorf("GenerateRootTXT = %q, want %q", txt, expected)
	}
}

// ============================================================================
// SPHINCSTreeVerifier Tests
// ============================================================================

func TestSPHINCSTreeVerifier_Valid(t *testing.T) {
	verifier := &SPHINCSTreeVerifier{}
	root := &TreeRoot{
		Version:   "v1",
		ERoot:     "abc123",
		LRoot:     "",
		Sequence:  1,
		Signature: "sig123",
		PublicKey: "pk123",
	}

	if err := verifier.VerifyTreeRoot(root); err != nil {
		t.Fatalf("VerifyTreeRoot unexpected error: %v", err)
	}
}

func TestSPHINCSTreeVerifier_Invalid(t *testing.T) {
	verifier := &SPHINCSTreeVerifier{}

	tests := []struct {
		name string
		root *TreeRoot
	}{
		{"wrong version", &TreeRoot{Version: "v2", ERoot: "abc", Signature: "sig", PublicKey: "pk"}},
		{"empty eroot", &TreeRoot{Version: "v1", ERoot: "", Signature: "sig", PublicKey: "pk"}},
		{"empty pubkey", &TreeRoot{Version: "v1", ERoot: "abc", Signature: "sig", PublicKey: ""}},
		{"empty sig", &TreeRoot{Version: "v1", ERoot: "abc", Signature: "", PublicKey: "pk"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := verifier.VerifyTreeRoot(tt.root); err == nil {
				t.Errorf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

// ============================================================================
// Client Tests
// ============================================================================

func TestClient_DiscoverPeers_NoTrees(t *testing.T) {
	c := NewClient()
	_, err := c.DiscoverPeers(context.Background())
	if err == nil {
		t.Fatal("expected error for no trees configured")
	}
}

func TestClient_AddTreeURL_Invalid(t *testing.T) {
	c := NewClient()
	err := c.AddTreeURL("invalid://url")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestClient_AddTreeURL_Valid(t *testing.T) {
	c := NewClient()
	err := c.AddTreeURL("enrtree://AEDA4B62B4B4E4E4@nodes.sphinx.network")
	if err != nil {
		t.Fatalf("AddTreeURL unexpected error: %v", err)
	}
}

// ============================================================================
// Resolver Tests
// ============================================================================

func TestClassifySeed(t *testing.T) {
	tests := []struct {
		seed string
		want SeedType
	}{
		{"enrtree://pubkey@domain.com", SeedDNSTree},
		{"192.168.1.1:30303", SeedPlain},
		{"1.2.3.4:5678", SeedPlain},
		{"", SeedPlain},
	}

	for _, tt := range tests {
		t.Run(tt.seed, func(t *testing.T) {
			got := ClassifySeed(tt.seed)
			if got != tt.want {
				t.Errorf("ClassifySeed(%q) = %v, want %v", tt.seed, got, tt.want)
			}
		})
	}
}

func TestHasDNSTreeSeeds(t *testing.T) {
	tests := []struct {
		seeds string
		want  bool
	}{
		{"enrtree://pubkey@domain.com", true},
		{"enrtree://AEDA4B62B4B4E4E4@d1.com,enrtree://0102030405060708@d2.com", true},
		{"enrtree://AEDA4B62B4B4E4E4@d.com,1.2.3.4:30303", true},
		{"1.2.3.4:30303", false},
		{"", false},
		{"1.2.3.4:30303,5.6.7.8:9090", false},
	}

	for _, tt := range tests {
		t.Run(tt.seeds, func(t *testing.T) {
			got := HasDNSTreeSeeds(tt.seeds)
			if got != tt.want {
				t.Errorf("HasDNSTreeSeeds(%q) = %v, want %v", tt.seeds, got, tt.want)
			}
		})
	}
}

func TestFilterDNSTrees(t *testing.T) {
	seedList := "enrtree://AEDA4B62B4B4E4E4@d1.com,1.2.3.4:30303,enrtree://0102030405060708@d2.com,5.6.7.8:9090"
	plainSeeds, resolver := FilterDNSTrees(seedList)

	if !resolver.HasTrees() {
		t.Error("expected resolver to have trees")
	}

	expectedPlain := []string{"1.2.3.4:30303", "5.6.7.8:9090"}
	if len(plainSeeds) != len(expectedPlain) {
		t.Errorf("plainSeeds = %v, want %v", plainSeeds, expectedPlain)
	}
}

func TestMergePeers(t *testing.T) {
	dnsPeers := []network.PeerInfo{
		{NodeID: "dns1", Address: "1.1.1.1:30303"},
		{NodeID: "dns2", Address: "2.2.2.2:30303"},
	}
	seedPeers := []network.PeerInfo{
		{NodeID: "seed1", Address: "1.1.1.1:30303"}, // duplicate
		{NodeID: "seed2", Address: "3.3.3.3:30303"},
	}

	merged := MergePeers(dnsPeers, seedPeers)

	if len(merged) != 3 {
		t.Errorf("expected 3 merged peers, got %d", len(merged))
	}

	// Seed peers should come first
	if merged[0].NodeID != "seed1" {
		t.Errorf("first peer should be seed1, got %s", merged[0].NodeID)
	}
}

// ============================================================================
// Helper Tests
// ============================================================================

func TestEncodeSubdomain(t *testing.T) {
	hash := sha256.Sum256([]byte("test"))
	encoded := encodeSubdomain(hash[:])

	if len(encoded) == 0 {
		t.Fatal("expected non-empty encoded subdomain")
	}

	// Should be lowercase base32 without padding
	for _, c := range encoded {
		if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')) {
			t.Errorf("invalid base32 character: %c", c)
		}
	}
}

func TestHexEncodeDecode(t *testing.T) {
	original := []byte{0xde, 0xad, 0xbe, 0xef}
	encoded := hexEncode(original)
	decoded, err := hexDecode(encoded)
	if err != nil {
		t.Fatalf("hexDecode unexpected error: %v", err)
	}
	if !bytesEqual(original, decoded) {
		t.Errorf("round-trip failed: %x -> %s -> %x", original, encoded, decoded)
	}
}

func TestEncodeUint64(t *testing.T) {
	b := encodeUint64(0x0102030405060708)
	expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if !bytesEqual(b, expected) {
		t.Errorf("encodeUint64 = %x, want %x", b, expected)
	}
}

func TestMinMaxInt(t *testing.T) {
	if minInt(1, 2) != 1 {
		t.Error("minInt(1,2) should be 1")
	}
	if minInt(5, 3) != 3 {
		t.Error("minInt(5,3) should be 3")
	}
	if maxInt(1, 2) != 2 {
		t.Error("maxInt(1,2) should be 2")
	}
	if maxInt(5, 3) != 5 {
		t.Error("maxInt(5,3) should be 5")
	}
}

func TestCeilDiv(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{10, 3, 4},
		{9, 3, 3},
		{1, 1, 1},
		{0, 5, 0},
		{5, 0, 0},
	}
	for _, tt := range tests {
		got := ceilDiv(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("ceilDiv(%d,%d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// ============================================================================
// Integration-style test: Build tree, generate root, parse root
// ============================================================================

func TestTreeBuildAndRootRoundTrip(t *testing.T) {
	records := []SphinxNodeRecord{
		{ID: "node1", KademliaID: "kad1", Address: "192.168.1.1:30303", UDPPort: "30304", PublicKey: "pk1"},
		{ID: "node2", KademliaID: "kad2", Address: "192.168.1.2:30303", UDPPort: "30304", PublicKey: "pk2"},
		{ID: "node3", KademliaID: "kad3", Address: "192.168.1.3:30303", UDPPort: "30304", PublicKey: "pk3"},
		{ID: "node4", KademliaID: "kad4", Address: "192.168.1.4:30303", UDPPort: "30304", PublicKey: "pk4"},
		{ID: "node5", KademliaID: "kad5", Address: "192.168.1.5:30303", UDPPort: "30304", PublicKey: "pk5"},
	}

	// Build the tree
	tb := NewTreeBuilder(3)
	for _, rec := range records {
		tb.AddRecord(rec)
	}
	_, branchMap, err := tb.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Compute root hash
	rootHash, err := ComputeRootHash(records)
	if err != nil {
		t.Fatalf("ComputeRootHash failed: %v", err)
	}

	// Generate root TXT
	rootTXT := GenerateRootTXT(hex.EncodeToString(rootHash), "", "sig123", "pk456", 1)

	// Parse it back
	parsed, err := parseTreeRoot(rootTXT)
	if err != nil {
		t.Fatalf("parseTreeRoot failed: %v", err)
	}

	if parsed.ERoot != hex.EncodeToString(rootHash) {
		t.Errorf("ERoot mismatch: %q vs %q", parsed.ERoot, hex.EncodeToString(rootHash))
	}

	// Verify branch map has entries for all records
	if len(branchMap) < len(records) {
		t.Errorf("branchMap has %d entries, expected at least %d", len(branchMap), len(records))
	}
}

// ============================================================================
// Benchmark: Merkle tree building
// ============================================================================

func BenchmarkTreeBuilder_Build(b *testing.B) {
	records := make([]SphinxNodeRecord, 1000)
	for i := 0; i < 1000; i++ {
		records[i] = SphinxNodeRecord{
			ID:         fmt.Sprintf("node-%d", i),
			KademliaID: fmt.Sprintf("kad-%d", i),
			Address:    fmt.Sprintf("192.168.%d.%d:30303", i/256, i%256),
			UDPPort:    "30304",
			PublicKey:  fmt.Sprintf("pk-%d", i),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb := NewTreeBuilder(24)
		for _, rec := range records {
			tb.AddRecord(rec)
		}
		_, _, err := tb.Build()
		if err != nil {
			b.Fatalf("Build failed: %v", err)
		}
	}
}

// ============================================================================
// Helpers
// ============================================================================

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
