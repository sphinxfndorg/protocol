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

// go/src/core/state/database_scan.go
package database

import (
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

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
