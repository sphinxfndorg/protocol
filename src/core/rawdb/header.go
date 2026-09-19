// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/header.go
package rawdb

import (
	"encoding/json"
	"errors"
	"fmt"

	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// storedHeaderCopy returns a shallow copy of h with LogsBloom cleared so the
// stored header JSON omits it (the field is tagged omitempty) and the 256
// filter bytes live under bloomKey(hash) in their raw wire format instead.
// Every other field, including the *big.Int pointers, is shared with h and
// only read; BlockHeader has no lock to copy.
func storedHeaderCopy(h *types.BlockHeader) *types.BlockHeader {
	c := *h
	c.LogsBloom = nil
	return &c
}

// writeBloom stores h.LogsBloom under bloomKey(hash). Called before the
// header JSON so a readable header always has its filter, and so a failed
// bloom write leaves no header pointing at a missing filter.
func writeBloom(db *database.DB, hash string, h *types.BlockHeader) error {
	if len(h.LogsBloom) == 0 {
		return nil
	}
	if err := db.Put(bloomKey(hash), h.LogsBloom); err != nil {
		return fmt.Errorf("rawdb: write bloom %s: %w", hash, err)
	}
	return nil
}

// ReadLogsBloom returns the raw filter bytes stored for hash, ready to hand
// straight to bloom.ContainsRaw: no header JSON decode and no BloomFilter
// allocation. A block written before the filter moved to its own key has no
// bloom: entry, so callers should fall back to ReadHeader, which rehydrates
// it from the header's inline logs_bloom field.
func ReadLogsBloom(db *database.DB, hash string) ([]byte, error) {
	data, err := db.GetQuiet(bloomKey(hash))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, fmt.Errorf("%w: bloom %s", ErrNotFound, hash)
		}
		return nil, fmt.Errorf("rawdb: read bloom %s: %w", hash, err)
	}
	return data, nil
}

// WriteHeader stores h keyed by its own hash, derived via hashString(h.Hash).
// LogsBloom is written under bloomKey(hash) rather than inside the header
// JSON, shrinking the header and keeping the filter in its raw wire format.
func WriteHeader(db *database.DB, h *types.BlockHeader) error {
	if h == nil {
		return fmt.Errorf("rawdb: nil header")
	}
	hash := hashString(h.Hash)
	if hash == "" {
		return fmt.Errorf("rawdb: header has empty hash")
	}
	if err := writeBloom(db, hash, h); err != nil {
		return err
	}
	data, err := json.Marshal(storedHeaderCopy(h))
	if err != nil {
		return fmt.Errorf("rawdb: marshal header %s: %w", hash, err)
	}
	if err := db.Put(headerKey(hash), data); err != nil {
		return fmt.Errorf("rawdb: write header %s: %w", hash, err)
	}
	return nil
}

// ReadHeader looks up a header by hash. Returns an error wrapping
// ErrNotFound if the key does not exist, distinct from a corrupt-JSON error
// and from a genuine read failure.
func ReadHeader(db *database.DB, hash string) (*types.BlockHeader, error) {
	data, err := db.GetQuiet(headerKey(hash))
	if err != nil {
		// A missing header is an expected outcome (probing, backfill
		// checks, pruning); only real failures are reported as such.
		if errors.Is(err, database.ErrNotFound) {
			return nil, fmt.Errorf("%w: header %s", ErrNotFound, hash)
		}
		return nil, fmt.Errorf("rawdb: read header %s: %w", hash, err)
	}
	var h types.BlockHeader
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("rawdb: corrupt header %s: %w", hash, err)
	}
	// Headers written after the filter moved to its own key carry none
	// inline, so rehydrate from it. Older headers still have logs_bloom in
	// the JSON, which the unmarshal above already filled in, so this lookup
	// is skipped and the read stays a single Get.
	if len(h.LogsBloom) == 0 {
		if raw, err := ReadLogsBloom(db, hash); err == nil {
			h.LogsBloom = raw
		}
	}
	return &h, nil
}

// HasHeader reports whether a header exists for hash. Any underlying error
// is treated as "not present" — callers that need to distinguish a real
// error from a genuine miss should use ReadHeader directly.
func HasHeader(db *database.DB, hash string) bool {
	ok, err := db.Has(headerKey(hash))
	return err == nil && ok
}

func DeleteHeader(db *database.DB, hash string) error {
	if err := db.Delete(headerKey(hash)); err != nil {
		return fmt.Errorf("rawdb: delete header %s: %w", hash, err)
	}
	// Also drop the filter stored alongside it; an orphaned bloom: key
	// would keep serving membership hits for a header that is gone.
	if err := db.Delete(bloomKey(hash)); err != nil {
		return fmt.Errorf("rawdb: delete bloom %s: %w", hash, err)
	}
	return nil
}
