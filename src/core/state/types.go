// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/state/types.go
package database

import (
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt" // Add this import
)

// DB wraps a LevelDB instance with thread safety
type DB struct {
	db    LevelDBInterface // Change to use interface instead of concrete type
	mutex sync.RWMutex
}

// LevelDBInterface defines the interface for LevelDB operations
type LevelDBInterface interface {
	Put(key []byte, value []byte, wo *opt.WriteOptions) error // Change to opt.WriteOptions
	Get(key []byte, ro *opt.ReadOptions) ([]byte, error)      // Change to opt.ReadOptions
	Delete(key []byte, wo *opt.WriteOptions) error            // Change to opt.WriteOptions
	Close() error
	Has(key []byte, ro *opt.ReadOptions) (bool, error) // Change to opt.ReadOptions
}

// Ensure leveldb.DB implements LevelDBInterface
var _ LevelDBInterface = (*leveldb.DB)(nil)

// LevelDBAdapter adapts leveldb.DB to database.DB interface
type LevelDBAdapter struct {
	db *leveldb.DB
	mu sync.RWMutex
}
