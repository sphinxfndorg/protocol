// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/rawdb_test.go
package rawdb

import (
	"errors"
	"fmt"
	"testing"

	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// newTestDB opens a throwaway LevelDB for the duration of the test.
func newTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.NewLevelDB(t.TempDir() + "/db")
	if err != nil {
		t.Fatalf("NewLevelDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// hashFor returns a printable 64-character hex hash, which
// Block.GetHash() passes through unchanged.
func hashFor(n uint64) string { return fmt.Sprintf("%064x", n+1) }

// testBlock builds a minimal block. Height comes from Header.Block (that
// is what GetHeight reads), and the hash must be set or WriteBlock
// refuses it.
func testBlock(n uint64, txs ...*types.Transaction) *types.Block {
	return &types.Block{
		Header: &types.BlockHeader{
			Hash:   []byte(hashFor(n)),
			Block:  n,
			Height: n,
		},
		Body: types.BlockBody{TxsList: txs},
	}
}

func testTx(id, sender, receiver string) *types.Transaction {
	return &types.Transaction{ID: id, Sender: sender, Receiver: receiver}
}

func mustWriteBlock(t *testing.T, db *database.DB, block *types.Block) {
	t.Helper()
	if err := WriteBlock(db, block); err != nil {
		t.Fatalf("WriteBlock(%s): %v", block.GetHash(), err)
	}
}

func TestReadHeaderMissingIsErrNotFound(t *testing.T) {
	db := newTestDB(t)

	_, err := ReadHeader(db, hashFor(0))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadHeader on a missing key returned %v, want ErrNotFound", err)
	}
}

func TestReadBodyMissingIsErrNotFound(t *testing.T) {
	db := newTestDB(t)

	_, err := ReadBody(db, hashFor(0))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadBody on a missing key returned %v, want ErrNotFound", err)
	}
}

func TestReadTxLookupEntryMissingIsErrNotFound(t *testing.T) {
	db := newTestDB(t)

	_, err := ReadTxLookupEntry(db, "tx-unknown")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadTxLookupEntry on a missing key returned %v, want ErrNotFound", err)
	}
}

func TestReadReceiptMissingIsErrNotFound(t *testing.T) {
	db := newTestDB(t)

	_, err := ReadReceipt(db, "tx-unknown")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadReceipt on a missing key returned %v, want ErrNotFound", err)
	}
}

func TestReadCanonicalHashMissingIsErrNotFound(t *testing.T) {
	db := newTestDB(t)

	if _, err := ReadCanonicalHash(db, 7); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadCanonicalHash on a missing key returned %v, want ErrNotFound", err)
	}
	if _, err := ReadHeightByHash(db, hashFor(7)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadHeightByHash on a missing key returned %v, want ErrNotFound", err)
	}
}

func TestReadSingletonsMissingIsErrNotFound(t *testing.T) {
	db := newTestDB(t)

	if _, err := ReadHeadBlockHash(db); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadHeadBlockHash returned %v, want ErrNotFound", err)
	}
	if _, err := ReadHeadHeaderHash(db); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadHeadHeaderHash returned %v, want ErrNotFound", err)
	}
	if _, err := ReadGenesisHash(db); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadGenesisHash returned %v, want ErrNotFound", err)
	}
}

// TestHasIsSilentOnAMiss documents that the existence probes are silent: a
// miss is (false, nil), so a loop over candidate hashes does not produce an
// error path per absent key.
func TestHasIsSilentOnAMiss(t *testing.T) {
	db := newTestDB(t)

	if HasHeader(db, hashFor(0)) {
		t.Fatal("HasHeader reported a missing header as present")
	}
	if HasBody(db, hashFor(0)) {
		t.Fatal("HasBody reported a missing body as present")
	}
}

// TestReadFailureIsNotReportedAsNotFound guards the distinction the quiet
// read path exists to preserve: a broken database must not look like an
// absent record, or a caller would silently treat an outage as a miss.
func TestReadFailureIsNotReportedAsNotFound(t *testing.T) {
	db := newTestDB(t)
	mustWriteBlock(t, db, testBlock(1, testTx("tx-1", "xAlice", "xBob")))

	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	readers := map[string]func() error{
		"ReadHeader":        func() error { _, err := ReadHeader(db, hashFor(1)); return err },
		"ReadBody":          func() error { _, err := ReadBody(db, hashFor(1)); return err },
		"ReadTxLookupEntry": func() error { _, err := ReadTxLookupEntry(db, "tx-1"); return err },
		"ReadCanonicalHash": func() error { _, err := ReadCanonicalHash(db, 1); return err },
		"ReadReceipt":       func() error { _, err := ReadReceipt(db, "tx-1"); return err },
	}

	for name, read := range readers {
		err := read()
		if err == nil {
			t.Errorf("%s on a closed DB returned no error", name)
			continue
		}
		if errors.Is(err, ErrNotFound) {
			t.Errorf("%s on a closed DB reported ErrNotFound: %v", name, err)
		}
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	db := newTestDB(t)
	block := testBlock(3, testTx("tx-a", "xAlice", "xBob"), testTx("tx-b", "xBob", "xCarol"))
	mustWriteBlock(t, db, block)

	header, err := ReadHeader(db, block.GetHash())
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if header.Block != 3 {
		t.Fatalf("header height = %d, want 3", header.Block)
	}

	body, err := ReadBody(db, block.GetHash())
	if err != nil {
		t.Fatalf("ReadBody: %v", err)
	}
	if len(body.TxsList) != 2 {
		t.Fatalf("body has %d txs, want 2", len(body.TxsList))
	}

	got, err := ReadBlock(db, block.GetHash())
	if err != nil {
		t.Fatalf("ReadBlock: %v", err)
	}
	if got.GetHeight() != 3 || len(got.Body.TxsList) != 2 {
		t.Fatalf("ReadBlock returned height %d with %d txs", got.GetHeight(), len(got.Body.TxsList))
	}

	if hash, err := ReadCanonicalHash(db, 3); err != nil || hash != block.GetHash() {
		t.Fatalf("ReadCanonicalHash(3) = %q, %v; want %q", hash, err, block.GetHash())
	}
	if height, err := ReadHeightByHash(db, block.GetHash()); err != nil || height != 3 {
		t.Fatalf("ReadHeightByHash = %d, %v; want 3", height, err)
	}
}
