// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/state/helper.go
package database

import (
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// NewLevelDBAdapter creates a new adapter that wraps a leveldb.DB
func NewLevelDBAdapter(ldb *leveldb.DB) *DB {
	adapter := &LevelDBAdapter{db: ldb}
	return &DB{
		db:    adapter, // Now this works because adapter implements LevelDBInterface
		mutex: sync.RWMutex{},
	}
}

// Put implements LevelDBInterface
func (a *LevelDBAdapter) Put(key []byte, value []byte, wo *opt.WriteOptions) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.db.Put(key, value, wo)
}

// Get implements LevelDBInterface
func (a *LevelDBAdapter) Get(key []byte, ro *opt.ReadOptions) ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.db.Get(key, ro)
}

// Delete implements LevelDBInterface
func (a *LevelDBAdapter) Delete(key []byte, wo *opt.WriteOptions) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.db.Delete(key, wo)
}

// Has implements LevelDBInterface
func (a *LevelDBAdapter) Has(key []byte, ro *opt.ReadOptions) (bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.db.Has(key, ro)
}

// Close implements LevelDBInterface
func (a *LevelDBAdapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.db.Close()
}
