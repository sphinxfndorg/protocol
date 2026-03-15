// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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

// go/src/state/storage_db.go
package state

import (
	"fmt"

	database "github.com/sphinxorg/protocol/src/core/state"
)

// GetDB returns the *database.DB handle shared with this Storage instance.
func (s *Storage) GetDB() (*database.DB, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.stateDB == nil {
		return nil, fmt.Errorf("Storage.GetDB: no shared database handle (was NewStorage given a DB?)")
	}
	return s.stateDB, nil
}

// SetDB injects an open *database.DB into this Storage instance.
// Must be called once after NewStorage, before the first CommitBlock.
func (s *Storage) SetDB(db *database.DB) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateDB = db
}
