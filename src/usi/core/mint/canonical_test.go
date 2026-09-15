package mint

import "testing"

// TestCanonicalReceiptBytes_MetadataRoundTrip guards against the nil-vs-empty
// metadata divergence that broke Verify() for every save/load round-trip.
func TestCanonicalReceiptBytes_MetadataRoundTrip(t *testing.T) {
	fresh := &MintReceipt{
		Version:  ReceiptVersion,
		MintID:   "abc",
		Subject:  "subj",
		Metadata: map[string]string{}, // what Mint() produces
	}
	loaded := &MintReceipt{
		Version:  ReceiptVersion,
		MintID:   "abc",
		Subject:  "subj",
		Metadata: nil, // what LoadReceipt gives back after omitempty drops it
	}

	freshBytes, err := canonicalReceiptBytes(fresh)
	if err != nil {
		t.Fatalf("canonicalize fresh: %v", err)
	}
	loadedBytes, err := canonicalReceiptBytes(loaded)
	if err != nil {
		t.Fatalf("canonicalize loaded: %v", err)
	}
	if string(freshBytes) != string(loadedBytes) {
		t.Fatalf("canonical bytes differ between empty-map and nil-map metadata:\nfresh:  %x\nloaded: %x", freshBytes, loadedBytes)
	}
}
