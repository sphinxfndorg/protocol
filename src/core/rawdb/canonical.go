// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/canonical.go
package rawdb

import (
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
	data, err := db.Get(canonicalKey(height))
	if err != nil {
		return "", fmt.Errorf("%w: canonical hash at height %d", ErrNotFound, height)
	}
	return string(data), nil
}

func ReadHeightByHash(db *database.DB, hash string) (uint64, error) {
	data, err := db.Get(heightLookupKey(hash))
	if err != nil {
		return 0, fmt.Errorf("%w: height for hash %s", ErrNotFound, hash)
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
	data, err := db.Get(headBlockKey)
	if err != nil {
		return "", fmt.Errorf("%w: head block hash", ErrNotFound)
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
	data, err := db.Get(headHeaderKey)
	if err != nil {
		return "", fmt.Errorf("%w: head header hash", ErrNotFound)
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
	data, err := db.Get(genesisHashKey)
	if err != nil {
		return "", fmt.Errorf("%w: genesis hash", ErrNotFound)
	}
	return string(data), nil
}
