// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/prune.go
package rawdb

import (
	"fmt"

	database "github.com/sphinxfndorg/protocol/src/core/state"
)

// PruneBodies removes all block bodies (and their tx lookup entries) at or
// below the given pruneHeight, retaining only headers, canonical pointers,
// and height lookups so that range-scans (GetTransactionHistory, etc.) can
// still resolve block existence without pulling full transaction lists.
//
// This is NOT a freezer/ancient-store — it's a simpler pruning strategy:
// once blocks reach a certain age (measured in height from tip), their
// bodies are deleted to reclaim space. If a pruned body is later needed
// (e.g. for a deep reorg or historical RPC), it must be re-fetched from
// a peer. This is acceptable for nodes that prioritize disk efficiency
// over full archival capability.
//
// The caller is responsible for determining the prune height. A typical
// strategy is: pruneHeight = currentTip - retainBlocks, where retainBlocks
// is the number of recent blocks to keep fully (e.g. 1,000).
func PruneBodies(db *database.DB, pruneHeight uint64) (int, error) {
	// We need the ability to iterate heights. Rawdb stores canonical
	// pointers as "H:<hex_height>" -> hash. We walk heights from 0 to
	// pruneHeight and delete each body + tx lookup entries.
	pruned := 0

	for height := uint64(0); height <= pruneHeight; height++ {
		canonKey := canonicalKey(height)
		hashData, err := db.Get(canonKey)
		if err != nil {
			// No canonical entry at this height — either genesis not yet
			// stored or gap. Skip silently.
			continue
		}
		hash := string(hashData)
		if hash == "" {
			continue
		}

		// Check if the body actually exists before trying to read it.
		has, err := db.Has(bodyKey(hash))
		if err != nil {
			return pruned, fmt.Errorf("PruneBodies: Has(%s): %w", bodyKey(hash), err)
		}
		if !has {
			continue // already pruned
		}

		// We need the tx list to delete tx lookup entries.
		body, err := ReadBody(db, hash)
		if err != nil {
			// Body key exists but unreadable — log and skip body
			// deletion so we don't orphan tx lookups.
			continue
		}

		batch := db.NewWriteBatch()
		batch.Delete(bodyKey(hash))
		if body != nil {
			for _, tx := range body.TxsList {
				if tx != nil && tx.ID != "" {
					batch.Delete(txLookupKey(tx.ID))
				}
			}
		}
		if err := batch.Commit(); err != nil {
			return pruned, fmt.Errorf("PruneBodies: commit batch at height %d: %w", height, err)
		}
		pruned++
	}

	return pruned, nil
}
