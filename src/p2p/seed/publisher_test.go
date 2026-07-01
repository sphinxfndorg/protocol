// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package dnsdiscovery

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/network"
)

func TestDefaultENRTreeURL(t *testing.T) {
	// Verify the default URL parses correctly
	parsed, err := ParseTreeURL(DefaultENRTreeURL)
	if err != nil {
		t.Fatalf("DefaultENRTreeURL %q failed to parse: %v", DefaultENRTreeURL, err)
	}
	if parsed.Domain != DefaultENRTreeDomain {
		t.Errorf("domain = %q, want %q", parsed.Domain, DefaultENRTreeDomain)
	}
	if hex.EncodeToString(parsed.PublicKey) != strings.ToLower(DefaultENRTreePubkeyHex) {
		t.Errorf("pubkey hex = %q, want %q", hex.EncodeToString(parsed.PublicKey), strings.ToLower(DefaultENRTreePubkeyHex))
	}
}

func TestMockNodeCollector(t *testing.T) {
	collector := &MockNodeCollector{
		Peers: []network.PeerInfo{
			{NodeID: "node1", Address: "192.168.1.1:30303", UDPPort: "30304"},
			{NodeID: "node2", Address: "192.168.1.2:30303", UDPPort: "30304"},
		},
	}

	peers, err := collector.CollectActiveNodes(context.Background())
	if err != nil {
		t.Fatalf("CollectActiveNodes failed: %v", err)
	}
	if len(peers) != 2 {
		t.Errorf("expected 2 peers, got %d", len(peers))
	}
}

func TestMockNodeCollector_Empty(t *testing.T) {
	collector := &MockNodeCollector{}
	_, err := collector.CollectActiveNodes(context.Background())
	if err == nil {
		t.Fatal("expected error for empty collector")
	}
}

func TestMockSigner(t *testing.T) {
	signer := NewMockSigner("deadbeef")
	pub := signer.PublicKey()
	if pub != "deadbeef" {
		t.Errorf("PublicKey = %q, want %q", pub, "deadbeef")
	}

	sig, err := signer.Sign([]byte("hello"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) != 32 {
		t.Errorf("expected 32-byte signature, got %d", len(sig))
	}
}

func TestPublisher_Publish(t *testing.T) {
	collector := &MockNodeCollector{
		Peers: []network.PeerInfo{
			{NodeID: "node1", Address: "192.168.1.1:30303", UDPPort: "30304"},
			{NodeID: "node2", Address: "192.168.1.2:30303", UDPPort: "30304"},
			{NodeID: "node3", Address: "192.168.1.3:30303", UDPPort: "30304"},
		},
	}
	signer := NewMockSigner("AEDA4B62B4B4E4E4")

	cfg := DefaultPublisherConfig()
	cfg.MaxBranch = 2 // small for testing
	pub := NewPublisher(cfg, collector, signer)

	result, err := pub.Publish(context.Background())
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	if result.NodeCount != 3 {
		t.Errorf("NodeCount = %d, want 3", result.NodeCount)
	}
	if result.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1", result.Sequence)
	}
	if result.MerkleRootHex == "" {
		t.Error("MerkleRootHex is empty")
	}
	if result.SignatureHex == "" {
		t.Error("SignatureHex is empty")
	}
	if result.PublicKeyHex != "AEDA4B62B4B4E4E4" {
		t.Errorf("PublicKeyHex = %q, want %q", result.PublicKeyHex, "AEDA4B62B4B4E4E4")
	}
	if result.RootTXT == "" {
		t.Error("RootTXT is empty")
	}

	// Verify root TXT parses correctly
	parsed, err := parseTreeRoot(result.RootTXT)
	if err != nil {
		t.Fatalf("parseTreeRoot failed: %v", err)
	}
	if parsed.ERoot != result.MerkleRootHex {
		t.Errorf("ERoot mismatch: %q vs %q", parsed.ERoot, result.MerkleRootHex)
	}
	if parsed.Signature != result.SignatureHex {
		t.Errorf("Signature mismatch: %q vs %q", parsed.Signature, result.SignatureHex)
	}

	// Verify TXT records include root
	if _, ok := result.TXTRecords["root."+DefaultENRTreeDomain]; !ok {
		t.Errorf("missing root TXT record for %s", "root."+DefaultENRTreeDomain)
	}

	// Should have at least 3 leaf records + branch records
	if len(result.TXTRecords) < 3 {
		t.Errorf("expected at least 3 TXT records, got %d", len(result.TXTRecords))
	}
}

func TestPublisher_EmptyCollector(t *testing.T) {
	collector := &MockNodeCollector{}
	signer := NewMockSigner("pk")
	pub := NewPublisher(DefaultPublisherConfig(), collector, signer)

	_, err := pub.Publish(context.Background())
	if err == nil {
		t.Fatal("expected error for empty collector")
	}
}

func TestFormatTXTRecords(t *testing.T) {
	records := map[string]string{
		"root.nodes.sphinx.network": "enrtree-root:v1 e=abc123 l= seq=1 sig=sig123 pk=pk456",
		"abc.nodes.sphinx.network":  "enrtree-branch:def,ghi",
	}

	formatted := FormatTXTRecords(records)

	if !strings.Contains(formatted, "IN TXT") {
		t.Error("formatted output missing IN TXT")
	}
	if !strings.Contains(formatted, "enrtree-root:v1") {
		t.Error("formatted output missing root record")
	}
	if !strings.Contains(formatted, "enrtree-branch:def,ghi") {
		t.Error("formatted output missing branch record")
	}
}

func TestFormatTXTRecords_LongValue(t *testing.T) {
	// Create a value longer than 255 chars to test splitting
	longVal := strings.Repeat("A", 300)
	records := map[string]string{
		"test.domain": longVal,
	}

	formatted := FormatTXTRecords(records)
	if !strings.Contains(formatted, "\"") {
		t.Error("formatted output missing quotes for long value")
	}
}

func TestSimpleSigner(t *testing.T) {
	signer := NewSimpleSigner("pkhex", []byte("secret-key"))
	pub := signer.PublicKey()
	if pub != "pkhex" {
		t.Errorf("PublicKey = %q, want %q", pub, "pkhex")
	}

	sig, err := signer.Sign([]byte("test message"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) != 32 {
		t.Errorf("expected 32-byte signature, got %d", len(sig))
	}

	// Deterministic: same message + same key = same signature
	sig2, _ := signer.Sign([]byte("test message"))
	if !bytesEqual(sig, sig2) {
		t.Error("signature not deterministic")
	}
}

func TestPeerInfoToSNR(t *testing.T) {
	peer := network.PeerInfo{
		NodeID:          "test-node",
		Address:         "192.168.1.1:30303",
		UDPPort:         "30304",
		ProtocolVersion: "1.0",
	}

	snr := peerInfoToSNR(peer)
	if snr.ID != "test-node" {
		t.Errorf("ID = %q, want %q", snr.ID, "test-node")
	}
	if snr.Address != "192.168.1.1:30303" {
		t.Errorf("Address = %q, want %q", snr.Address, "192.168.1.1:30303")
	}
	if snr.UDPPort != "30304" {
		t.Errorf("UDPPort = %q, want %q", snr.UDPPort, "30304")
	}
}
