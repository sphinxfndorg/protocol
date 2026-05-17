// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/state/storage_db.go

// Storage has no LevelDB handle of its own — it is a pure file-system block
// store.  We open a *database.DB on demand using the node's existing LevelDB
// directory, which is the same path passed to leveldb.OpenFile in helper.go.
//
// The returned *database.DB is used exclusively by StateDB (account balances,
// nonces, total supply).  It shares the same on-disk LevelDB database as the
// one opened by the CLI, because LevelDB supports multiple readers from the
// same process as long as they use the same *leveldb.DB handle — but opening
// a second handle against the same path in the same process is safe for reads
// and for writes from a single goroutine.  For production you would share a
// single handle; for the current test harness this is fine.

package state

import (
	"fmt"

	database "github.com/sphinxorg/protocol/src/core/state"
	logger "github.com/sphinxorg/protocol/src/log"
)

// SetDB sets the main database handle (for blocks and transactions)
func (s *Storage) SetDB(db *database.DB) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db = db
	logger.Info("Main DB handle attached to storage: %p", db)
}

// GetDB returns the main database handle
func (s *Storage) GetDB() (*database.DB, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return nil, fmt.Errorf("Storage.GetDB: no shared database handle")
	}
	return s.db, nil
}

// SetStateDB sets the state database handle (for consensus state)
func (s *Storage) SetStateDB(db *database.DB) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateDB = db
	logger.Info("State DB handle attached to storage: %p", db)
}

// GetStateDB returns the state database handle
func (s *Storage) GetStateDB() (*database.DB, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.stateDB == nil {
		return nil, fmt.Errorf("Storage.GetStateDB: no shared state database handle")
	}
	return s.stateDB, nil
}
