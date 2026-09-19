// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/state/database_scan.go
package database

import (
	"fmt"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// rawDB unwraps to the concrete *leveldb.DB and returns it without holding
// the DB-wide lock. Callers that iterate must use this rather than holding
// d.mutex for the whole scan: a long scan would otherwise block every
// writer for its duration. goleveldb's DB and its iterators are safe for
// concurrent use, and a Close racing an iteration surfaces as an error from
// Iterator.Error rather than corruption.
func (d *DB) rawDB() (*leveldb.DB, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	if d.db == nil {
		return nil, fmt.Errorf("LevelDB is closed")
	}

	switch v := d.db.(type) {
	case *leveldb.DB:
		return v, nil
	case *LevelDBAdapter:
		// LevelDBAdapter.db is the *leveldb.DB field defined in types.go
		v.mu.RLock()
		defer v.mu.RUnlock()
		return v.db, nil
	default:
		return nil, fmt.Errorf("database type does not support iteration")
	}
}

// IterateEntriesWithPrefixReverse calls fn for every key/value whose key
// starts with prefix, in descending key order, and stops early when fn
// returns false. For a key scheme whose trailing components are fixed-width
// and big-endian — such as rawdb's addrtx:<addr>:<height>:<index> — that
// makes "most recent first, at most N entries" a bounded read instead of a
// full scan plus a sort.
//
// The value slice passed to fn is only valid for the duration of the call;
// copy it if it must outlive the callback. iter.Error() is checked after
// the loop, so a mid-scan failure is reported rather than looking like the
// end of the range.
func (d *DB) IterateEntriesWithPrefixReverse(prefix string, fn func(key string, value []byte) bool) error {
	ldb, err := d.rawDB()
	if err != nil {
		return err
	}

	iter := ldb.NewIterator(util.BytesPrefix([]byte(prefix)), nil)
	defer iter.Release()

	for ok := iter.Last(); ok; ok = iter.Prev() {
		if !fn(string(iter.Key()), iter.Value()) {
			break
		}
	}
	return iter.Error()
}

// ListKeysWithPrefix returns every key whose byte representation starts with
// the given prefix, in lexicographic order.
//
// LevelDBInterface intentionally does not expose NewIterator (it is not part
// of the common read/write contract).  We type-assert to reach the concrete
// *leveldb.DB stored at construction time.  Both paths that NewLevelDB uses
// (direct open and RecoverFile) store a *leveldb.DB; LevelDBAdapter wraps one
// too.  Any other implementation returns an empty list rather than panicking.
func (d *DB) ListKeysWithPrefix(prefix string) ([]string, error) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	if d.db == nil {
		return nil, nil
	}

	// Unwrap to the concrete *leveldb.DB.
	var ldb *leveldb.DB
	switch v := d.db.(type) {
	case *leveldb.DB:
		ldb = v
	case *LevelDBAdapter:
		// LevelDBAdapter.db is the *leveldb.DB field defined in types.go
		v.mu.RLock()
		ldb = v.db
		v.mu.RUnlock()
	default:
		return nil, nil
	}

	var keys []string
	iter := ldb.NewIterator(util.BytesPrefix([]byte(prefix)), nil)
	defer iter.Release()

	for iter.Next() {
		k := make([]byte, len(iter.Key()))
		copy(k, iter.Key())
		keys = append(keys, string(k))
	}
	return keys, iter.Error()
}
