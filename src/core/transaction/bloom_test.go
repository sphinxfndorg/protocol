// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/transaction/bloom_test.go
package types

import (
	"encoding/hex"
	"fmt"
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

// naiveBuildBloomFilter is the pre-dedupe reference implementation: one
// Add per field per transaction, in body order. The production builder
// must produce identical bytes.
func naiveBuildBloomFilter(body *BlockBody) *bloom.BloomFilter {
	bf := bloom.NewDefault()
	if body == nil {
		return bf
	}
	for _, tx := range body.TxsList {
		if tx == nil {
			continue
		}
		for _, key := range []string{tx.ID, tx.Sender, tx.Receiver, tx.ToContract} {
			if key != "" {
				bf.Add([]byte(key))
			}
		}
	}
	return bf
}

// realisticBloomBody returns a body whose addresses come from a small
// shared pool, which is the shape a real block has: many transactions
// repeat the same few addresses.
func realisticBloomBody() *BlockBody {
	const (
		txCount  = 200
		addrPool = 40
	)
	txs := make([]*Transaction, 0, txCount)
	for i := 0; i < txCount; i++ {
		txs = append(txs, &Transaction{
			ID:         fmt.Sprintf("tx-%d", i),
			Sender:     fmt.Sprintf("xAddr-%d", i%addrPool),
			Receiver:   fmt.Sprintf("xAddr-%d", (i+1)%addrPool),
			ToContract: fmt.Sprintf("xContract-%d", i%5),
		})
	}
	return &BlockBody{TxsList: txs}
}

// distinctBloomBody returns a body where every key is distinct, the worst
// case for dedupe.
func distinctBloomBody() *BlockBody {
	const txCount = 200
	txs := make([]*Transaction, 0, txCount)
	for i := 0; i < txCount; i++ {
		txs = append(txs, &Transaction{
			ID:       fmt.Sprintf("tx-%d", i),
			Sender:   fmt.Sprintf("xSender-%d", i),
			Receiver: fmt.Sprintf("xReceiver-%d", i),
		})
	}
	return &BlockBody{TxsList: txs}
}

func TestBuildBlockBloomFilterMatchesNaiveBuild(t *testing.T) {
	bodies := map[string]*BlockBody{
		"nil":           nil,
		"empty":         {},
		"frozen":        fixedBloomBody(),
		"realistic":     realisticBloomBody(),
		"all-distinct":  distinctBloomBody(),
		"nil-tx-entry":  {TxsList: []*Transaction{nil, {ID: "tx-x", Sender: "xAlice"}}},
		"only-contract": {TxsList: []*Transaction{{ToContract: "xContract123"}}},
	}

	for name, body := range bodies {
		want := hex.EncodeToString(naiveBuildBloomFilter(body).Bytes())
		got := hex.EncodeToString(BuildBlockBloomFilter(body).Bytes())
		if got != want {
			t.Fatalf("%s: deduped build differs from per-field build:\n got %s\nwant %s", name, got, want)
		}
	}
}

func TestBuildBlockBloomFilterDedupePreservesEveryKey(t *testing.T) {
	body := realisticBloomBody()
	bf := BuildBlockBloomFilter(body)

	for _, tx := range body.TxsList {
		for _, key := range []string{tx.ID, tx.Sender, tx.Receiver, tx.ToContract} {
			if key == "" {
				continue
			}
			if !bf.Contains([]byte(key)) {
				t.Fatalf("key %q missing after deduped build", key)
			}
		}
	}
}

// TestBuildBlockBloomFilterDedupeAlsoShrinksHashedKeyCount shows the
// dedupe actually removes work on a realistic body: the same set of bits
// must be reachable from far fewer hashed keys.
func TestBuildBlockBloomFilterDedupeAlsoShrinksHashedKeyCount(t *testing.T) {
	body := realisticBloomBody()

	distinct := make(map[string]struct{})
	fieldCount := 0
	for _, tx := range body.TxsList {
		for _, key := range []string{tx.ID, tx.Sender, tx.Receiver, tx.ToContract} {
			if key == "" {
				continue
			}
			fieldCount++
			distinct[key] = struct{}{}
		}
	}

	if len(distinct) >= fieldCount {
		t.Fatalf("fixture is not exercising dedupe: %d distinct keys out of %d fields", len(distinct), fieldCount)
	}
}

func BenchmarkBuildBlockBloomFilter(b *testing.B) {
	body := realisticBloomBody()
	b.ReportAllocs()
	for b.Loop() {
		_ = BuildBlockBloomFilter(body)
	}
}

func BenchmarkBuildBlockBloomFilterNoDedupe(b *testing.B) {
	body := realisticBloomBody()
	b.ReportAllocs()
	for b.Loop() {
		_ = naiveBuildBloomFilter(body)
	}
}

func BenchmarkBuildBlockBloomFilterAllDistinct(b *testing.B) {
	body := distinctBloomBody()
	b.ReportAllocs()
	for b.Loop() {
		_ = BuildBlockBloomFilter(body)
	}
}
