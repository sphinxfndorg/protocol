// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/iterator.go
package rawdb

import (
	"fmt"

	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// ReadBlocksByHeightRange returns every canonical block with height in
// [from, to], inclusive, in ascending height order. A missing height inside
// the range (a gap in the canonical chain) is reported as an error rather
// than silently skipped — a gap means corruption or an incomplete sync,
// not something callers should quietly paper over.
func ReadBlocksByHeightRange(db *database.DB, from, to uint64) ([]*types.Block, error) {
	if from > to {
		return nil, fmt.Errorf("rawdb: invalid range [%d, %d]", from, to)
	}
	blocks := make([]*types.Block, 0, to-from+1)
	for height := from; height <= to; height++ {
		hash, err := ReadCanonicalHash(db, height)
		if err != nil {
			return nil, fmt.Errorf("rawdb: no canonical block at height %d: %w", height, err)
		}
		block, err := ReadBlock(db, hash)
		if err != nil {
			return nil, fmt.Errorf("rawdb: reading block at height %d: %w", height, err)
		}
		blocks = append(blocks, block)
	}
	return blocks, nil
}

// ReadCanonicalHashRange returns the canonical hash at every height in
// [from, to], inclusive, in ascending order — cheaper than
// ReadBlocksByHeightRange when a caller only needs hashes, e.g. building a
// header-chain sync response.
func ReadCanonicalHashRange(db *database.DB, from, to uint64) ([]string, error) {
	if from > to {
		return nil, fmt.Errorf("rawdb: invalid range [%d, %d]", from, to)
	}
	hashes := make([]string, 0, to-from+1)
	for height := from; height <= to; height++ {
		hash, err := ReadCanonicalHash(db, height)
		if err != nil {
			return nil, fmt.Errorf("rawdb: no canonical hash at height %d: %w", height, err)
		}
		hashes = append(hashes, hash)
	}
	return hashes, nil
}
