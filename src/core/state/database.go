// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/state/database.go
package database

import (
	stderrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	logger "github.com/sphinxfndorg/protocol/src/console"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// ErrNotFound is returned by GetQuiet (unwrapped) when the requested key
// does not exist. It lets a caller that expects misses — probing for an
// optional record, or scanning a key range where most keys are absent —
// tell "absent" apart from "the database failed", which the logging Get
// conflates into a formatted error string.
var ErrNotFound = stderrors.New("database: key not found")

// WriteBatch represents a batch of pending writes that can be applied atomically
type WriteBatch struct {
	db    *DB
	batch *leveldb.Batch
}

// NewWriteBatch creates a new empty write batch for the given DB
func (d *DB) NewWriteBatch() *WriteBatch {
	return &WriteBatch{
		db:    d,
		batch: &leveldb.Batch{},
	}
}

// Put adds a key-value pair to the batch
func (wb *WriteBatch) Put(key string, value []byte) {
	wb.batch.Put([]byte(key), value)
}

// Delete adds a deletion to the batch
func (wb *WriteBatch) Delete(key string) {
	wb.batch.Delete([]byte(key))
}

// Commit atomically applies all batched operations to the database.
// This is durable - changes are written to disk before returning.
// Returns error if commit fails, leaving database unchanged.
func (wb *WriteBatch) Commit() error {
	if wb.db == nil || wb.db.db == nil {
		return fmt.Errorf("database is closed")
	}
	if wb.batch == nil {
		return nil
	}

	// Write the batch using the underlying leveldb.DB
	// This requires accessing the concrete *leveldb.DB through the interface
	var ldb *leveldb.DB
	switch v := wb.db.db.(type) {
	case *leveldb.DB:
		ldb = v
	case *LevelDBAdapter:
		v.mu.RLock()
		ldb = v.db
		v.mu.RUnlock()
	default:
		return fmt.Errorf("database type does not support batch writes")
	}

	// Apply batch atomically - this is a single write to the WAL
	if err := ldb.Write(wb.batch, nil); err != nil {
		logger.Error("Failed to commit write batch: %v", err)
		return fmt.Errorf("failed to commit write batch: %w", err)
	}

	logger.Debug("Successfully committed write batch with %d operations", wb.batch.Len())
	return nil
}

// Rollback discards the batch without applying changes
func (wb *WriteBatch) Rollback() {
	wb.batch.Reset()
}

// NewLevelDB initializes a new LevelDB instance at the specified path with retry logic.
// Parameters:
//   - path: File system path where the LevelDB database will be stored
//
// Returns: Database instance and error if initialization fails
func NewLevelDB(path string) (*DB, error) {
	// Define retry constants for database initialization
	const maxRetries = 3               // Maximum number of initialization attempts
	const retryDelay = 1 * time.Second // Delay between retry attempts

	// Create parent directory if it doesn't exist
	// Ensure the directory structure exists before creating the database
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		logger.Error("Failed to create parent directory for LevelDB at %s: %v", path, err)
		return nil, fmt.Errorf("failed to create parent directory for LevelDB at %s: %w", path, err)
	}

	// Attempt to open the database with retry logic.
	//
	// SECURITY/SAFETY: we deliberately do NOT delete the LevelDB LOCK file
	// before opening. goleveldb uses it as an OS advisory lock (flock), which
	// the kernel releases automatically when the owning process exits — so an
	// unclean shutdown never leaves a lock that blocks the next open. Deleting
	// the LOCK file unconditionally therefore buys nothing on the recovery path
	// and is actively dangerous: if a live process still holds the database
	// (or the same process already opened this path), removing its lock lets a
	// second handle open the same files and corrupt them.
	//
	// Callers that need BOTH a raw *leveldb.DB and a *DB wrapper for the same
	// path must therefore open it once and reuse the handle via
	// NewLevelDBWithHandle — a second OpenFile on the same path fails with
	// EAGAIN ("resource temporarily unavailable").
	//
	// If OpenFile fails because the database really is locked, we surface an
	// error instead of stealing the lock.
	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Attempt to open the LevelDB database
		// ErrorIfExist: false allows opening existing database
		db, err := leveldb.OpenFile(path, &opt.Options{ErrorIfExist: false})
		if err == nil {
			// Successfully opened database
			logger.Info("Successfully opened LevelDB at %s on attempt %d", path, attempt)
			return &DB{
				db:    db,             // Underlying LevelDB instance
				mutex: sync.RWMutex{}, // Read-write mutex for thread safety
			}, nil
		}

		// A lock conflict is NOT transient: the flock is held by a live
		// process (or another handle in this one). Retrying cannot clear it,
		// and falling through to leveldb.RecoverFile would be worse than
		// useless — it rewrites the manifest/table files of a database
		// someone else is actively using. Fail fast with an actionable
		// message instead.
		if isLevelDBLockedError(err) {
			logger.Error("LevelDB at %s is locked by another live process (or another open handle in this process); "+
				"refusing to remove the lock file or run recovery. Stop the other process (or point this node at a "+
				"different data directory) and retry.", path)
			return nil, fmt.Errorf("leveldb at %s is locked: %w", path, err)
		}

		// Log failure for this attempt
		logger.Error("Failed to open LevelDB at %s on attempt %d: %v", path, attempt, err)
		if attempt < maxRetries {
			// Wait before retrying if not the last attempt
			logger.Info("Retrying LevelDB initialization at %s in %v", path, retryDelay)
			time.Sleep(retryDelay)
		}
	}

	// All open attempts failed, attempt recovery
	logger.Warn("All attempts to open LevelDB at %s failed, attempting recovery", path)
	// Try to recover the database from potential corruption
	db, err := leveldb.RecoverFile(path, nil)
	if err != nil {
		// Recovery failed, return error
		logger.Error("Failed to recover LevelDB at %s: %v", path, err)
		return nil, fmt.Errorf("failed to recover LevelDB at %s: %w", path, err)
	}

	// Successfully recovered the database
	logger.Info("Successfully recovered LevelDB at %s", path)
	return &DB{
		db:    db,             // Recovered database instance
		mutex: sync.RWMutex{}, // Read-write mutex for thread safety
	}, nil
}

// NewLevelDBWithHandle wraps an ALREADY-OPEN goleveldb handle in a *DB, using
// the same directory path for bookkeeping.
//
// It exists because some callers need two views of one database: the raw
// *leveldb.DB (e.g. sign.NewSTHINCSManager persists SPHINCS+ keys directly
// through it) and this package's *DB wrapper for the same path. Opening the
// path twice is not allowed — goleveldb holds an exclusive OS lock on the
// database directory, so the second OpenFile fails with EAGAIN ("resource
// temporarily unavailable"), and stealing that lock by deleting the LOCK file
// is exactly what NewLevelDB refuses to do for safety.
//
// The caller keeps ownership of the handle's lifetime: this does not close it.
func NewLevelDBWithHandle(path string, handle *leveldb.DB) (*DB, error) {
	if handle == nil {
		return nil, fmt.Errorf("nil LevelDB handle for %s", path)
	}
	return &DB{
		db:    handle,
		mutex: sync.RWMutex{},
	}, nil
}

// isLevelDBLockedError reports whether err is goleveldb's "database is locked
// by another process/handle" failure. On Unix that surfaces as EAGAIN, whose
// message is "resource temporarily unavailable"; goleveldb's own sentinel is
// storage.ErrLocked ("leveldb/storage: locked"). Both are checked without
// importing the storage sub-package, because the raw syscall error is what
// OpenFile actually returns here (verified on darwin/linux).
func isLevelDBLockedError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "resource temporarily unavailable") ||
		strings.Contains(msg, "leveldb: locked") ||
		strings.Contains(msg, "leveldb/storage: locked")
}

// Close closes the LevelDB instance.
// Returns: Error if closing fails
func (d *DB) Close() error {
	// Acquire write lock to prevent concurrent operations
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// Check if database is already closed
	if d.db == nil {
		return nil // Already closed, no error
	}

	// Attempt to close the underlying LevelDB
	if err := d.db.Close(); err != nil {
		logger.Error("Failed to close LevelDB: %v", err)
		return fmt.Errorf("failed to close LevelDB: %w", err)
	}

	// Mark database as closed by setting to nil
	d.db = nil
	logger.Info("Successfully closed LevelDB")
	return nil
}

// Put stores a key-value pair in the database.
// Parameters:
//   - key: String key to store
//   - value: Byte slice value to store
//
// Returns: Error if storage fails
func (d *DB) Put(key string, value []byte) error {
	// Acquire write lock for thread-safe write operation
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// Check if database is open
	if d.db == nil {
		return fmt.Errorf("LevelDB is closed")
	}

	// Store key-value pair in LevelDB
	// []byte(key) converts string key to byte slice
	if err := d.db.Put([]byte(key), value, nil); err != nil {
		// Log and return error on failure
		logger.Error("Failed to put key %s in LevelDB: %s", key, err.Error())
		return fmt.Errorf("failed to put key %s in LevelDB: %w", key, err)
	}

	// Log successful storage
	logger.Debug("Successfully stored key %s in LevelDB", key)
	return nil
}

// GetQuiet retrieves a value by key without emitting any log line, so a
// caller that probes for optional records — or loops over a key range where
// most keys are absent — does not pay for a formatted warning, and the
// renderer's global lock behind it, on every miss.
//
// A missing key returns ErrNotFound unwrapped; any other failure returns a
// distinct wrapped error, so callers can tell the two apart with
// errors.Is(err, ErrNotFound).
func (d *DB) GetQuiet(key string) ([]byte, error) {
	// Acquire read lock for concurrent read access
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	// Check if database is open
	if d.db == nil {
		return nil, fmt.Errorf("LevelDB is closed")
	}

	// Attempt to retrieve value for key
	data, err := d.db.Get([]byte(key), nil)
	if err != nil {
		// Handle the not-found case separately: it is an expected outcome
		// for a probing caller, not a failure worth reporting.
		if err == errors.ErrNotFound {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get key %s from LevelDB: %w", key, err)
	}

	return data, nil
}

// Get retrieves a value by key from the database, logging the outcome.
// Prefer GetQuiet on any path where a miss is expected.
// Parameters:
//   - key: String key to retrieve
//
// Returns: Value as byte slice and error if retrieval fails
func (d *DB) Get(key string) ([]byte, error) {
	data, err := d.GetQuiet(key)
	if err != nil {
		if err == ErrNotFound {
			// Key doesn't exist in database. This is the normal case for
			// optional records on a fresh chain, so log at debug.
			logger.Debug("Key %s not found in LevelDB", key)
			// Keep the historical message text, and wrap ErrNotFound so
			// callers can branch on the cause instead of the string.
			return nil, fmt.Errorf("key %s not found in LevelDB: %w", key, ErrNotFound)
		}
		// Other error occurred
		logger.Error("Failed to get key %s from LevelDB: %s", key, err.Error())
		return nil, err
	}

	// Successfully retrieved value
	logger.Debug("Successfully retrieved key %s from LevelDB", key)
	return data, nil
}

// Delete removes a key-value pair from the database.
// Parameters:
//   - key: String key to delete
//
// Returns: Error if deletion fails
func (d *DB) Delete(key string) error {
	// Acquire write lock for thread-safe delete operation
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// Check if database is open
	if d.db == nil {
		return fmt.Errorf("LevelDB is closed")
	}

	// Attempt to delete key from database
	if err := d.db.Delete([]byte(key), nil); err != nil {
		// Log and return error on failure
		logger.Error("Failed to delete key %s from LevelDB: %s", key, err.Error())
		return fmt.Errorf("failed to delete key %s from LevelDB: %w", key, err)
	}

	// Log successful deletion
	logger.Debug("Successfully deleted key %s from LevelDB", key)
	return nil
}

// hasValue reports whether key exists, without logging anything. A missing
// key is (false, nil) — absence is not an error — while an underlying
// failure is returned as an error for the caller to decide about.
//
// It uses LevelDB's own Has rather than Get, so an existence check does not
// read and copy the value.
func (d *DB) hasValue(key string) (bool, error) {
	// Acquire read lock for concurrent read access
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	// Check if database is open
	if d.db == nil {
		return false, fmt.Errorf("LevelDB is closed")
	}

	ok, err := d.db.Has([]byte(key), nil)
	if err != nil {
		return false, fmt.Errorf("failed to check key %s in LevelDB: %w", key, err)
	}

	return ok, nil
}

// Has checks if a key exists in the database. An absent key is (false, nil)
// and is never logged; only a real failure is.
// Parameters:
//   - key: String key to check
//
// Returns: Boolean indicating existence and error if check fails
func (d *DB) Has(key string) (bool, error) {
	ok, err := d.hasValue(key)
	if err != nil {
		// Other error occurred during check
		logger.Error("Failed to check key %s in LevelDB: %s", key, err.Error())
		return false, err
	}

	// Key exists in database
	return ok, nil
}
