// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/nft_metadata_pin_test.go
package gui

import (
	"strings"
	"testing"
	"time"

	"github.com/sphinxfndorg/protocol/src/storage"
	"github.com/sphinxfndorg/protocol/src/usi/core/mint"
)

// TestPinNFTMetadataFallsBackWhenIPFSUnreachable locks in the fix for
// "Marketplace Token Failed: a collection mint needs an ERC-721 metadata
// tokenURI — fill in the NFT name".
//
// The NFT name WAS filled in: the strict metadata upload failed because the
// IPFS daemon was unreachable, and the resulting empty tokenURI was then
// misreported as a missing name — aborting the mint after the file had already
// been signed. The metadata pin must use the same deterministic fallback as the
// media payload pin, so an unreachable daemon yields a usable tokenURI instead.
func TestPinNFTMetadataFallsBackWhenIPFSUnreachable(t *testing.T) {
	// A client pointed at a closed port: the strict upload fails immediately and
	// the fallback must still produce a usable tokenURI.
	cfg := storage.DefaultConfig()
	cfg.IPFSAddr = "http://127.0.0.1:9"
	cfg.DisableIPFS = false
	cfg.Timeout = 2 * time.Second
	client := storage.NewClient(cfg)

	meta := mint.BuildNFTMetadata(
		"Freedom Document", "A signed declaration", "spxhash-media",
		nil, "SPIFPUBKEY", "SPIF", "freedom.pdf", "", 0)

	cid, uri, warn := pinNFTMetadata(client, meta, "freedom.pdf_metadata.json")
	if warn == nil {
		t.Fatal("an unreachable IPFS daemon must report the fallback as a warning")
	}
	if !strings.HasPrefix(cid, "spxhash-") {
		t.Fatalf("fallback CID must be the deterministic spxhash form, got %q", cid)
	}
	if uri != "ipfs://"+cid || strings.TrimSpace(uri) == "ipfs://" {
		t.Fatalf("tokenURI must be a usable ipfs://<cid>, got %q", uri)
	}

	// Content-addressed and stable: the on-chain tokenURI commitment must be
	// identical no matter what filename/daemon state produced it, so the
	// metadata is retrievable under it once pinning succeeds.
	cid2, uri2, _ := pinNFTMetadata(client, meta, "completely-different-name.json")
	if cid2 != cid || uri2 != uri {
		t.Fatalf("fallback must be content-addressed and stable: %q/%q vs %q/%q", cid, uri, cid2, uri2)
	}

	// Offline mode (DisableIPFS) yields the same tokenURI with NO warning.
	disabledCfg := storage.DefaultConfig()
	disabledCfg.DisableIPFS = true
	disabled := storage.NewClient(disabledCfg)
	cid3, uri3, warn3 := pinNFTMetadata(disabled, meta, "m.json")
	if warn3 != nil {
		t.Fatalf("disabled-IPFS mode must not warn, got %v", warn3)
	}
	if cid3 != cid || uri3 != uri {
		t.Fatalf("disabled-IPFS mode must yield the same deterministic tokenURI, got %q/%q", cid3, uri3)
	}

	// Nil metadata is a hard error (no tokenURI can be produced), not a warning.
	if _, _, err := pinNFTMetadata(client, nil, "m.json"); err == nil {
		t.Fatal("nil metadata must be a hard error")
	}
}
