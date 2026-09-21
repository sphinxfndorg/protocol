// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/nft_metadata_pin_test.go
package gui

import (
	"errors"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2/widget"

	"github.com/sphinxfndorg/protocol/src/storage"
	"github.com/sphinxfndorg/protocol/src/usi/core/mint"
)

// TestPinNFTMetadataReportsNotUploadedInsteadOfFakingACID locks in the fix for
// the silent-fallback bug: an unreachable daemon used to yield a spxhash- CID
// that was then committed on-chain as an ipfs:// tokenURI, so a collection mint
// "succeeded" while pinning nothing anyone could ever fetch.
//
// pinNFTMetadata must now report the failure as an ErrNotUploaded outcome with
// NO CID and NO tokenURI, which is exactly what makes the mint worker stop
// before signing instead of producing an NFT whose metadata does not exist.
func TestPinNFTMetadataReportsNotUploadedInsteadOfFakingACID(t *testing.T) {
	// A client pointed at a closed port: the upload fails immediately.
	cfg := storage.DefaultConfig()
	cfg.IPFSAddr = "http://127.0.0.1:9"
	cfg.DisableIPFS = false
	cfg.Timeout = 2 * time.Second
	// Clear any ambient pinning-service config so this test can only fail.
	cfg.PinningServiceToken = ""
	cfg.PinningServiceURL = ""
	client := storage.NewClient(cfg)

	meta := mint.BuildNFTMetadata(
		"Freedom Document", "A signed declaration", "bafy-media",
		nil, "SPIFPUBKEY", "SPIF", "freedom.pdf", "", 0)

	cid, uri, outcome := pinNFTMetadata(client, meta, "freedom.pdf_metadata.json")

	if outcome.Uploaded() {
		t.Fatal("an unreachable IPFS daemon must not report the metadata as uploaded")
	}
	if cid != "" || uri != "" {
		t.Fatalf("no CID/tokenURI may be fabricated for a failed pin, got cid=%q uri=%q", cid, uri)
	}
	if outcome.OptIn {
		t.Fatal("a transport failure is not an opted-in offline mint")
	}
	if !errors.Is(outcome.Warn, storage.ErrNotUploaded) {
		t.Fatalf("want an ErrNotUploaded outcome, got %v", outcome.Warn)
	}

	// Deterministic: a retry cannot silently invent a different identifier.
	cid2, uri2, outcome2 := pinNFTMetadata(client, meta, "completely-different-name.json")
	if cid2 != "" || uri2 != "" || outcome2.Uploaded() {
		t.Fatalf("a failed pin must stay failed, got cid=%q uri=%q", cid2, uri2)
	}

	// Explicit offline mode (SPHINX_IPFS_DISABLE) keeps the documented
	// deterministic identifier, and is reported as an opt-in non-upload so the
	// UI can flag it loudly rather than presenting it as a real pin.
	offlineCfg := storage.DefaultConfig()
	offlineCfg.DisableIPFS = true
	offCid, offURI, offOutcome := pinNFTMetadata(storage.NewClient(offlineCfg), meta, "m.json")
	if offOutcome.Uploaded() || !offOutcome.OptIn {
		t.Fatalf("offline mode must report an opted-in non-upload, got %+v", offOutcome)
	}
	if !strings.HasPrefix(offCid, "spxhash-") || offURI != "ipfs://"+offCid {
		t.Fatalf("offline mode keeps the deterministic spxhash identifier, got cid=%q uri=%q", offCid, offURI)
	}
	if !errors.Is(offOutcome.Warn, storage.ErrNotUploaded) {
		t.Fatalf("offline mode must still warn that nothing was uploaded, got %v", offOutcome.Warn)
	}

	// Nil inputs are hard errors, not not-uploaded outcomes with a fake CID.
	if _, _, o := pinNFTMetadata(client, nil, "m.json"); o.Warn == nil || o.Uploaded() {
		t.Fatal("nil metadata must be reported as an error, never as a pin")
	}
	if _, _, o := pinNFTMetadata(nil, meta, "m.json"); o.Warn == nil {
		t.Fatal("nil uploader must be reported as an error")
	}
}

// TestPinBannerStatesEveryOutcomeHonestly pins the Mint Status banner text to
// the pin outcome, so a completed mint can never show an unqualified success
// while the payload is only local — or never uploaded at all.
func TestPinBannerStatesEveryOutcomeHonestly(t *testing.T) {
	cases := []struct {
		name    string
		outcome storage.PinOutcome
		mustSay []string
	}{
		{
			name:    "durably pinned",
			outcome: storage.PinOutcome{CID: "bafy1", Durability: storage.DurabilityRemotePinned, Source: "local+pinata", Verified: true},
			mustSay: []string{"Pinned durably", "local+pinata", "without this machine"},
		},
		{
			name:    "local daemon only",
			outcome: storage.PinOutcome{CID: "bafy2", Durability: storage.DurabilityLocalOnly, Source: "local", Verified: true},
			mustSay: []string{"LOCAL IPFS DAEMON ONLY", "goes offline", "SPHINX_IPFS_PINNING_TOKEN"},
		},
		{
			name:    "never uploaded",
			outcome: storage.PinOutcome{Durability: storage.DurabilityNotUploaded},
			mustSay: []string{"NOTHING WAS UPLOADED", "only on this disk"},
		},
		{
			name:    "opted-in offline",
			outcome: storage.PinOutcome{CID: "spxhash-abc", Durability: storage.DurabilityNotUploaded, OptIn: true, Source: "disabled"},
			mustSay: []string{"OFFLINE MODE", "spxhash-abc", "NOT a retrievable IPFS CID"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := pinBannerMessage(tc.outcome)
			for _, want := range tc.mustSay {
				if !strings.Contains(msg, want) {
					t.Fatalf("banner %q must mention %q", msg, want)
				}
			}
			got := pinBannerImportance(tc.outcome)
			want := widget.SuccessImportance
			switch {
			case !tc.outcome.Uploaded():
				want = widget.DangerImportance
			case !tc.outcome.Durable():
				want = widget.WarningImportance
			}
			if got != want {
				t.Fatalf("importance for %s: got %v want %v", tc.name, got, want)
			}
		})
	}
}
