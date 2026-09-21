// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/body.go
package rawdb

import (
	"encoding/json"
	"errors"
	"fmt"

	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// WriteBody stores b keyed by hash — the same hash as the header it
// belongs to. Bodies don't carry their own hash field, so the caller
// (WriteBlock, or anyone reindexing) supplies it explicitly.
//
// NOTE (R8 Commit B): this standalone writer is retained, not deleted. Its
// only production-adjacent caller is the tx_payload_test.go legacy fixture
// (pre-payload chain reconstruction via WriteHeader+WriteBody+
// WriteTxLookupEntries), and WriteTxLookupEntries in lookup.go keeps the
// same standalone shape for backfills. Deleting WriteBody while keeping its
// siblings would be asymmetric churn for zero behavioral gain; the atomic
// commit path (writeBlockBatch) never calls it, so it cannot diverge from a
// committed block.
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
	data, err := db.GetQuiet(bodyKey(hash))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, fmt.Errorf("%w: body %s", ErrNotFound, hash)
		}
		return nil, fmt.Errorf("rawdb: read body %s: %w", hash, err)
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
