// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/body.go
package rawdb

import (
	"encoding/json"
	"fmt"

	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// WriteBody stores b keyed by hash — the same hash as the header it
// belongs to. Bodies don't carry their own hash field, so the caller
// (WriteBlock, or anyone reindexing) supplies it explicitly.
func WriteBody(db *database.DB, hash string, b *types.BlockBody) error {
	if hash == "" {
		return fmt.Errorf("rawdb: empty hash")
	}
	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("rawdb: marshal body %s: %w", hash, err)
	}
	if err := db.Put(bodyKey(hash), data); err != nil {
		return fmt.Errorf("rawdb: write body %s: %w", hash, err)
	}
	return nil
}

func ReadBody(db *database.DB, hash string) (*types.BlockBody, error) {
	data, err := db.Get(bodyKey(hash))
	if err != nil {
		return nil, fmt.Errorf("%w: body %s", ErrNotFound, hash)
	}
	var body types.BlockBody
	if err := json.Unmarshal(data, &body); err != nil {
		return nil, fmt.Errorf("rawdb: corrupt body %s: %w", hash, err)
	}
	return &body, nil
}

func HasBody(db *database.DB, hash string) bool {
	ok, err := db.Has(bodyKey(hash))
	return err == nil && ok
}

func DeleteBody(db *database.DB, hash string) error {
	if err := db.Delete(bodyKey(hash)); err != nil {
		return fmt.Errorf("rawdb: delete body %s: %w", hash, err)
	}
	return nil
}
