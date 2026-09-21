// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/canonical.go
package rawdb

import (
	"errors"
	"fmt"

	database "github.com/sphinxfndorg/protocol/src/core/state"
)

// WriteCanonicalHash records hash as the canonical block at height, and
// keeps the reverse hash->height lookup in sync alongside it.
func WriteCanonicalHash(db *database.DB, height uint64, hash string) error {
	if err := db.Put(canonicalKey(height), []byte(hash)); err != nil {
		return fmt.Errorf("rawdb: write canonical hash at %d: %w", height, err)
	}
	if err := db.Put(heightLookupKey(hash), []byte(encodeHeight(height))); err != nil {
		return fmt.Errorf("rawdb: write height lookup for %s: %w", hash, err)
	}
	return nil
}

func ReadCanonicalHash(db *database.DB, height uint64) (string, error) {
	data, err := db.GetQuiet(canonicalKey(height))
	if err != nil {
		// Range scans and pruning walk every height, so an absent one is
		// routine rather than an error worth logging.
		if errors.Is(err, database.ErrNotFound) {
			return "", fmt.Errorf("%w: canonical hash at height %d", ErrNotFound, height)
		}
		return "", fmt.Errorf("rawdb: read canonical hash at height %d: %w", height, err)
	}
	return string(data), nil
}

// ReadHeightLookups returns every hash->height pair recorded under the h:
// prefix. WriteCanonicalHash and writeBlockBatch maintain that prefix for
// every stored block, so it is a durable reverse index that a caller can
// rebuild an in-memory hash->height map from without reading a single block
// body, or depending on the periodically-checkpointed block_index.json.
// Corrupt or malformed entries are skipped rather than aborting the read.
func ReadHeightLookups(db *database.DB) (map[string]uint64, error) {
	keys, values, err := db.ListEntriesWithPrefix(heightLookupPrefix, 0)
	if err != nil {
		return nil, fmt.Errorf("rawdb: list height lookups: %w", err)
	}

	out := make(map[string]uint64, len(keys))
	for i, key := range keys {
		if len(key) <= len(heightLookupPrefix) {
			continue
		}
		height, err := decodeHeight(string(values[i]))
		if err != nil {
			continue
		}
		out[key[len(heightLookupPrefix):]] = height
	}
	return out, nil
}

func ReadHeightByHash(db *database.DB, hash string) (uint64, error) {
	data, err := db.GetQuiet(heightLookupKey(hash))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return 0, fmt.Errorf("%w: height for hash %s", ErrNotFound, hash)
		}
		return 0, fmt.Errorf("rawdb: read height for hash %s: %w", hash, err)
	}
	return decodeHeight(string(data))
}

func WriteHeadBlockHash(db *database.DB, hash string) error {
	if err := db.Put(headBlockKey, []byte(hash)); err != nil {
		return fmt.Errorf("rawdb: write head block hash: %w", err)
	}
	return nil
}

func ReadHeadBlockHash(db *database.DB) (string, error) {
	data, err := db.GetQuiet(headBlockKey)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return "", fmt.Errorf("%w: head block hash", ErrNotFound)
		}
		return "", fmt.Errorf("rawdb: read head block hash: %w", err)
	}
	return string(data), nil
}

func WriteHeadHeaderHash(db *database.DB, hash string) error {
	if err := db.Put(headHeaderKey, []byte(hash)); err != nil {
		return fmt.Errorf("rawdb: write head header hash: %w", err)
	}
	return nil
}

func ReadHeadHeaderHash(db *database.DB) (string, error) {
	data, err := db.GetQuiet(headHeaderKey)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return "", fmt.Errorf("%w: head header hash", ErrNotFound)
		}
		return "", fmt.Errorf("rawdb: read head header hash: %w", err)
	}
	return string(data), nil
}

// WriteGenesisHash records the genesis hash the first time it's called. If
// a genesis hash is already stored and differs from hash, it returns an
// error rather than silently overwriting — genesis identity must never
// change under a running node.
func WriteGenesisHash(db *database.DB, hash string) error {
	existing, err := ReadGenesisHash(db)
	if err == nil && existing != "" && existing != hash {
		return fmt.Errorf("rawdb: genesis hash already set to %s, refusing to overwrite with %s", existing, hash)
	}
	if err := db.Put(genesisHashKey, []byte(hash)); err != nil {
		return fmt.Errorf("rawdb: write genesis hash: %w", err)
	}
	return nil
}

// ForceWriteGenesisHash overwrites the stored genesis hash unconditionally,
// bypassing WriteGenesisHash's mismatch check. This exists for exactly one
// caller: a late-joining node's Storage.ReplaceGenesis, which adopts the
// network's canonical genesis in place of a locally-mined one before the
// node has synced any other blocks. Every other caller should use
// WriteGenesisHash, whose refusal to overwrite is the correct behavior once
// a chain is actually running.
func ForceWriteGenesisHash(db *database.DB, hash string) error {
	if err := db.Put(genesisHashKey, []byte(hash)); err != nil {
		return fmt.Errorf("rawdb: force write genesis hash: %w", err)
	}
	return nil
}

func ReadGenesisHash(db *database.DB) (string, error) {
	data, err := db.GetQuiet(genesisHashKey)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return "", fmt.Errorf("%w: genesis hash", ErrNotFound)
		}
		return "", fmt.Errorf("rawdb: read genesis hash: %w", err)
	}
	return string(data), nil
}
