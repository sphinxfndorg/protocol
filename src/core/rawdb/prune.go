// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/prune.go
package rawdb

import (
	"errors"
	"fmt"

	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// pruneCommitEvery bounds how much work is committed at once. Commits are
// durable (one WAL sync each), so batching keeps the fsync count
// proportional to the number of prune operations rather than the number of
// heights walked, while still checkpointing often enough that a crash
// mid-prune only loses a bounded amount of progress.
const pruneCommitEvery = 10000

// PruneBodies removes all block bodies (and the per-transaction records
// that only exist to serve whole-body reads) at or below the given
// pruneHeight, retaining headers, canonical pointers and height lookups so
// that range-scans can still resolve block existence without pulling full
// transaction lists.
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
//
// Ordering, so a crash never leaves an index pointing at data that is gone:
// the per-transaction records are deleted before the body and its tx
// lookups. A transaction whose body is still present is therefore always
// resolvable, whichever side of a crash the node restarts on.
func PruneBodies(db *database.DB, pruneHeight uint64) (int, error) {
	pruned := 0
	pending := 0
	batch := db.NewWriteBatch()

	commit := func() error {
		if pending == 0 {
			return nil
		}
		if err := batch.Commit(); err != nil {
			return fmt.Errorf("PruneBodies: commit batch: %w", err)
		}
		batch = db.NewWriteBatch()
		pending = 0
		return nil
	}

	// One ordered walk of the canonical pointers covering the range, rather
	// than a point lookup for every height in it. Iteration stops as soon as
	// the key exceeds the bound, so a sparse or short chain is as cheap as
	// it looks.
	var walkErr error
	bound := canonicalKey(pruneHeight)
	err := db.IterateEntriesWithPrefix(canonicalPrefix, func(key string, value []byte) bool {
		if key > bound {
			return false
		}
		hash := string(value)
		if hash == "" {
			return true
		}

		// The body is needed to learn which transaction records belong to
		// this block. A missing body means an earlier prune already handled
		// this height — and removed its transaction records with it — so
		// there is nothing left to do.
		body, err := ReadBody(db, hash)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return true
			}
			walkErr = fmt.Errorf("PruneBodies: read body %s: %w", hash, err)
			return false
		}

		// Transaction records are deleted before the body and its lookups,
		// so a crash can only leave a transaction whose body still exists.
		block := &types.Block{Body: *body}
		DeleteTxPayloads(batch, block)
		batch.Delete(bodyKey(hash))
		for _, tx := range body.TxsList {
			if tx == nil || tx.ID == "" {
				continue
			}
			batch.Delete(txLookupKey(tx.ID))
		}

		pruned++
		pending++
		if pending >= pruneCommitEvery {
			if err := commit(); err != nil {
				walkErr = err
				return false
			}
		}
		return true
	})
	if walkErr != nil {
		return pruned, walkErr
	}
	if err != nil {
		return pruned, fmt.Errorf("PruneBodies: iterate canonical pointers: %w", err)
	}
	if err := commit(); err != nil {
		return pruned, err
	}

	return pruned, nil
}
