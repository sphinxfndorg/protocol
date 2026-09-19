// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/bloom_test.go
package rawdb

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	bloom "github.com/sphinxfndorg/protocol/src/core/bloom"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// bloomBlock builds a block whose header's LogsBloom is the real filter for
// its body, i.e. exactly what PopulateLogsBloom would set on the wire.
func bloomBlock(n uint64, txs ...*types.Transaction) *types.Block {
	block := testBlock(n, txs...)
	block.Header.LogsBloom = types.BuildBlockBloomFilter(&block.Body).Bytes()
	return block
}

// TestLogsBloomRoundTripsBitForBit is the invariant the storage move must
// preserve: the 256 filter bytes read back — from the header and straight
// from the bloom: key — are identical to the ones written, so membership
// answers cannot change.
func TestLogsBloomRoundTripsBitForBit(t *testing.T) {
	db := newTestDB(t)
	block := bloomBlock(5, testTx("tx-a", "xAlice", "xBob"), testTx("tx-b", "xBob", "xCarol"))
	mustWriteBlock(t, db, block)

	want := block.Header.LogsBloom
	if len(want) != 256 {
		t.Fatalf("test filter is %d bytes, want 256", len(want))
	}

	raw, err := ReadLogsBloom(db, block.GetHash())
	if err != nil {
		t.Fatalf("ReadLogsBloom: %v", err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatalf("bloom: key returned different bytes than were written")
	}

	header, err := ReadHeader(db, block.GetHash())
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if !bytes.Equal(header.LogsBloom, want) {
		t.Fatalf("ReadHeader did not rehydrate the same filter: got %d bytes", len(header.LogsBloom))
	}
}

// TestStoredHeaderJSONOmitsLogsBloom checks the header JSON actually shrank:
// the filter is not base64-encoded inside it any more.
func TestStoredHeaderJSONOmitsLogsBloom(t *testing.T) {
	db := newTestDB(t)
	block := bloomBlock(6, testTx("tx-a", "xAlice", "xBob"))
	mustWriteBlock(t, db, block)

	data, err := db.GetQuiet(headerKey(block.GetHash()))
	if err != nil {
		t.Fatalf("read stored header JSON: %v", err)
	}
	if bytes.Contains(data, []byte("logs_bloom")) {
		t.Fatalf("stored header JSON still carries logs_bloom: %s", data)
	}
}

// TestLegacyInlineLogsBloomStillReads covers pre-existing data: a header
// written before the move still has logs_bloom inline and must read back
// without a bloom: key.
func TestLegacyInlineLogsBloomStillReads(t *testing.T) {
	db := newTestDB(t)
	hash := hashFor(7)

	legacy := struct {
		Hash      []byte `json:"hash"`
		Block     uint64 `json:"nblock"`
		Height    uint64 `json:"height"`
		LogsBloom []byte `json:"logs_bloom"`
	}{Hash: []byte(hash), Block: 7, Height: 7, LogsBloom: bytes.Repeat([]byte{0xAB}, 256)}

	data, err := json.Marshal(&legacy)
	if err != nil {
		t.Fatalf("marshal legacy header: %v", err)
	}
	if err := db.Put(headerKey(hash), data); err != nil {
		t.Fatalf("Put legacy header: %v", err)
	}

	if _, err := ReadLogsBloom(db, hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("legacy header unexpectedly has a bloom: key: %v", err)
	}

	header, err := ReadHeader(db, hash)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if !bytes.Equal(header.LogsBloom, legacy.LogsBloom) {
		t.Fatalf("legacy inline filter was not read back: got %d bytes", len(header.LogsBloom))
	}
}

// TestMayContainAddressFromRawKey feeds the raw bloom: bytes straight to
// bloom.ContainsRaw — no header decode — and cross-checks the answer
// against the same test run through the header method.
func TestMayContainAddressFromRawKey(t *testing.T) {
	db := newTestDB(t)
	block := bloomBlock(8, testTx("tx-a", "xAlice", "xBob"))
	mustWriteBlock(t, db, block)

	raw, err := ReadLogsBloom(db, block.GetHash())
	if err != nil {
		t.Fatalf("ReadLogsBloom: %v", err)
	}

	cfg := bloom.DefaultConfig()
	if !bloom.ContainsRaw(raw, cfg, []byte("xAlice")) {
		t.Fatal("ContainsRaw on the stored filter says xAlice is absent")
	}
	if !bloom.ContainsRaw(raw, cfg, []byte("xBob")) {
		t.Fatal("ContainsRaw on the stored filter says xBob is absent")
	}

	header, err := ReadHeader(db, block.GetHash())
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if !header.MayContainAddress("xAlice") {
		t.Fatal("MayContainAddress on the rehydrated header says xAlice is absent")
	}
}

// TestBloomDeletedWithBlock guards against an orphaned filter outliving its
// header and answering membership for a block that is gone.
func TestBloomDeletedWithBlock(t *testing.T) {
	db := newTestDB(t)
	block := bloomBlock(9, testTx("tx-a", "xAlice", "xBob"))
	mustWriteBlock(t, db, block)

	if err := DeleteBlock(db, block.GetHash()); err != nil {
		t.Fatalf("DeleteBlock: %v", err)
	}
	if _, err := ReadLogsBloom(db, block.GetHash()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bloom survived DeleteBlock: %v", err)
	}
	if _, err := ReadHeader(db, block.GetHash()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("header survived DeleteBlock: %v", err)
	}
}

// TestWriteHeaderStoresBloomSeparately covers the standalone header writer,
// not just the block batch path.
func TestWriteHeaderStoresBloomSeparately(t *testing.T) {
	db := newTestDB(t)
	block := bloomBlock(10, testTx("tx-a", "xAlice", "xBob"))
	want := block.Header.LogsBloom

	if err := WriteHeader(db, block.Header); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}

	data, err := db.GetQuiet(headerKey(block.GetHash()))
	if err != nil {
		t.Fatalf("read stored header JSON: %v", err)
	}
	if bytes.Contains(data, []byte("logs_bloom")) {
		t.Fatalf("stored header JSON still carries logs_bloom: %s", data)
	}

	raw, err := ReadLogsBloom(db, block.GetHash())
	if err != nil {
		t.Fatalf("ReadLogsBloom: %v", err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatal("WriteHeader stored a different filter than the header carried")
	}
}