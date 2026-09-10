// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package storage

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestDefaultConfigEnvOverrides verifies DefaultConfig honours the env
// overrides used to point the wallet/CLI at a non-default IPFS node.
func TestDefaultConfigEnvOverrides(t *testing.T) {
	defer func() {
		os.Unsetenv("SPHINX_IPFS_ADDR")
		os.Unsetenv("SPHINX_IPFS_GATEWAY")
		os.Unsetenv("SPHINX_IPFS_DISABLE")
	}()

	cfg := DefaultConfig()
	if cfg.IPFSAddr != "http://127.0.0.1:5001" {
		t.Fatalf("default ipfs addr: want localhost, got %q", cfg.IPFSAddr)
	}

	if err := os.Setenv("SPHINX_IPFS_ADDR", "http://10.0.0.5:5001"); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("SPHINX_IPFS_GATEWAY", "https://ipfs.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("SPHINX_IPFS_DISABLE", "true"); err != nil {
		t.Fatal(err)
	}

	cfg = DefaultConfig()
	if cfg.IPFSAddr != "http://10.0.0.5:5001" {
		t.Fatalf("env ipfs addr not applied: %q", cfg.IPFSAddr)
	}
	if cfg.GatewayBaseURL != "https://ipfs.example.test" {
		t.Fatalf("env gateway not applied: %q", cfg.GatewayBaseURL)
	}
	if !cfg.DisableIPFS {
		t.Fatal("env SPHINX_IPFS_DISABLE=true should enable fallback mode")
	}
}

// TestAddBytesToIPFSWithFallbackUnconfigured verifies that with no IPFS API
// address the resilient helper returns a deterministic fallback CID plus a
// non-fatal warning, so a mint can continue without a real daemon.
func TestAddBytesToIPFSWithFallbackUnconfigured(t *testing.T) {
	c := &Client{
		cfg:        Config{IPFSAddr: "", GatewayBaseURL: "http://127.0.0.1:8080"},
		httpClient: &http.Client{},
	}
	cid, warn := c.AddBytesToIPFSWithFallback([]byte("hello world"), "test.txt")
	if !strings.HasPrefix(cid, "sha256-") {
		t.Fatalf("expected fallback sha256- CID, got %q", cid)
	}
	if warn == nil {
		t.Fatal("expected a fallback warning when IPFS is not configured")
	}
	if strings.Contains(cid, "\n") {
		t.Fatalf("fallback CID must be a single token, got %q", cid)
	}
}

// TestAddBytesToIPFSWithFallbackDisabledMode verifies DisableIPFS=true keeps
// returning the fallback CID with no warning (the existing documented behaviour).
func TestAddBytesToIPFSWithFallbackDisabledMode(t *testing.T) {
	c := &Client{
		cfg:        Config{IPFSAddr: "http://127.0.0.1:5001", GatewayBaseURL: "http://127.0.0.1:8080", DisableIPFS: true},
		httpClient: &http.Client{},
	}
	cid, warn := c.AddBytesToIPFSWithFallback([]byte("payload"), "p.bin")
	if !strings.HasPrefix(cid, "sha256-") {
		t.Fatalf("expected fallback CID, got %q", cid)
	}
	if warn != nil {
		t.Fatalf("DisableIPFS mode should fall back without error, got %v", warn)
	}
}

// TestNormalizeIPFSAddr verifies the dotted-IPv4-with-port typo is rewritten
// to the correct colon form, and that already-correct or odd addresses are
// left untouched.
func TestNormalizeIPFSAddr(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:5001":     "http://127.0.0.1:5001", // already fine
		"http://127.0.0.1.5001":     "http://127.0.0.1:5001", // stray dot → port
		"http://10.0.0.5:8080":      "http://10.0.0.5:8080",  // fine
		"http://localhost:5001":     "http://localhost:5001", // fine
		"http://ipfs.internal:5001": "http://ipfs.internal:5001",
		"http://127.0.0.1:notaport": "http://127.0.0.1:notaport", // has a port, keep
	}
	for addr, want := range cases {
		if got := normalizeIPFSAddr(addr); got != want {
			t.Fatalf("normalizeIPFSAddr(%q): want %q, got %q", addr, want, got)
		}
	}

	// NewClient applies the normalization to cfg.IPFSAddr.
	c := NewClient(Config{IPFSAddr: "http://127.0.0.1.5001"})
	if c.cfg.IPFSAddr != "http://127.0.0.1:5001" {
		t.Fatalf("NewClient did not normalize ipfs addr: %q", c.cfg.IPFSAddr)
	}
}
