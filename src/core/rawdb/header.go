// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/header.go
package rawdb

import (
	"encoding/json"
	"fmt"

	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// WriteHeader stores h keyed by its own hash, derived via hashString(h.Hash).
func WriteHeader(db *database.DB, h *types.BlockHeader) error {
	if h == nil {
		return fmt.Errorf("rawdb: nil header")
	}
	hash := hashString(h.Hash)
	if hash == "" {
		return fmt.Errorf("rawdb: header has empty hash")
	}
	data, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("rawdb: marshal header %s: %w", hash, err)
	}
	if err := db.Put(headerKey(hash), data); err != nil {
		return fmt.Errorf("rawdb: write header %s: %w", hash, err)
	}
	return nil
}

// ReadHeader looks up a header by hash. Returns an error wrapping
// ErrNotFound if the key does not exist, distinct from a corrupt-JSON error.
func ReadHeader(db *database.DB, hash string) (*types.BlockHeader, error) {
	data, err := db.Get(headerKey(hash))
	if err != nil {
		return nil, fmt.Errorf("%w: header %s", ErrNotFound, hash)
	}
	var h types.BlockHeader
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("rawdb: corrupt header %s: %w", hash, err)
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
	return nil
}
