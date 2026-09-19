// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/transaction/bloom_test.go
package types

import (
	"encoding/hex"
	"testing"

	"github.com/sphinxfndorg/protocol/src/core/bloom"
)

// fixedBloomBody is the canonical vector body for the frozen block-bloom
// assertions below.
func fixedBloomBody() *BlockBody {
	return &BlockBody{
		TxsList: []*Transaction{
			{ID: "tx-0001", Sender: "xAlice", Receiver: "xBob"},
			{ID: "tx-0002", Sender: "xCarol", Receiver: "xDave"},
			{ID: "tx-0003", Sender: "xEve", Receiver: "xContract123", ToContract: "xContract123"},
			{ID: "tx-0004", Sender: "xAlice", Receiver: "xBob"},
			{ID: "tx-0005", Sender: "", Receiver: ""},
		},
	}
}

// frozenBlockBloomHex is consensus-frozen: it is the exact LogsBloom every
// node must produce for fixedBloomBody(). LogsBloom is an input to
// GenerateBlockHash/FinalizeHash, so a mismatch here is a hard fork.
const frozenBlockBloomHex = "00000000000000000000000000080000000000000000080000000000000000000000040400000000000000000000010000000000000001000000000000000000008000004000000000000000000000000008080100000000000000000000100020000000000008000040000000000000000000400000000000000000000000000000000000000000000000000000000001000010000100000000000000000000000000000000000000000000000000000002000100000000200800000000000001000000000000000002000000000000800000000000000000400008000000000000000001000000400000000000000000000000000000000000000000100048"

func TestFrozenBlockBloomFilter(t *testing.T) {
	bf := BuildBlockBloomFilter(fixedBloomBody())

	raw := bf.Bytes()
	if len(raw) != bloom.BloomBytes {
		t.Fatalf("filter is %d bytes, want %d", len(raw), bloom.BloomBytes)
	}
	if got := hex.EncodeToString(raw); got != frozenBlockBloomHex {
		t.Fatalf("block bloom bytes changed:\n got %s\nwant %s", got, frozenBlockBloomHex)
	}
}

func TestBuildBlockBloomFilterNoFalseNegatives(t *testing.T) {
	body := fixedBloomBody()
	bf := BuildBlockBloomFilter(body)

	for _, tx := range body.TxsList {
		for _, key := range []string{tx.ID, tx.Sender, tx.Receiver, tx.ToContract} {
			if key == "" {
				continue
			}
			if !bf.Contains([]byte(key)) {
				t.Fatalf("key %q missing from filter after Add", key)
			}
		}
	}
}

func TestBuildBlockBloomFilterNilBody(t *testing.T) {
	bf := BuildBlockBloomFilter(nil)
	if bf == nil {
		t.Fatal("nil body must still return a usable, empty filter")
	}
	if n := bf.CountBits(); n != 0 {
		t.Fatalf("nil body produced %d set bits, want 0", n)
	}
}

// TestMayContainAddressMatchesDecodedFilter pins the equivalence between
// the decode-free ContainsRaw path used by MayContainAddress and the
// allocating BloomFilter.Contains path it replaced.
func TestMayContainAddressMatchesDecodedFilter(t *testing.T) {
	body := fixedBloomBody()
	header := &BlockHeader{}
	header.SetBloomFilter(BuildBlockBloomFilter(body))

	decoded, err := header.DecodeBloomFilter()
	if err != nil {
		t.Fatal(err)
	}

	probes := []string{
		"xAlice", "xBob", "xCarol", "xDave", "xEve", "xContract123",
		"tx-0001", "tx-0003", "tx-0005", "xMallory", "tx-9999", "",
	}
	for _, p := range probes {
		want := decoded.Contains([]byte(p))
		if got := header.MayContainAddress(p); got != want {
			t.Fatalf("MayContainAddress(%q) = %v, decoded filter says %v", p, got, want)
		}
		if got := header.MayContainTxID(p); got != want {
			t.Fatalf("MayContainTxID(%q) = %v, decoded filter says %v", p, got, want)
		}
	}
}

func TestMayContainAddressRejectsMalformedFilter(t *testing.T) {
	for _, raw := range [][]byte{nil, {}, make([]byte, 255), make([]byte, 257)} {
		h := &BlockHeader{LogsBloom: raw}
		if h.MayContainAddress("xAlice") {
			t.Fatalf("len(LogsBloom)=%d must never report a match", len(raw))
		}
	}

	var nilHeader *BlockHeader
	if nilHeader.MayContainAddress("xAlice") {
		t.Fatal("nil header must report false")
	}
}

func TestMayContainAddressFindsEveryBodyKey(t *testing.T) {
	body := fixedBloomBody()
	header := &BlockHeader{}
	header.SetBloomFilter(BuildBlockBloomFilter(body))

	// Every key a body scan would match must pass the header pre-check —
	// a false negative here would make a chain scan skip a real block.
	for _, tx := range body.TxsList {
		for _, key := range []string{tx.ID, tx.Sender, tx.Receiver, tx.ToContract} {
			if key == "" {
				continue
			}
			if !header.MayContainAddress(key) {
				t.Fatalf("header pre-check missed %q, which is in the body", key)
			}
		}
	}
}
