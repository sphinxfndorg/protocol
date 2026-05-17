// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/state/database.go
package database

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	logger "github.com/sphinxorg/protocol/src/log"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

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

	// Attempt to open the database with retry logic
	// Multiple attempts to handle temporary issues like stale locks
	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Remove stale lock file before attempting to open
		// This helps recover from previous unclean shutdowns
		if err := removeLockFile(path); err != nil {
			logger.Warn("Failed to remove lock file for LevelDB at %s on attempt %d: %v", path, attempt, err)
		}

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

// removeLockFile removes the LevelDB LOCK file if it exists.
// Parameters:
//   - path: Database directory path
//
// Returns: Error if removal fails (except when file doesn't exist)
func removeLockFile(path string) error {
	// Construct path to the lock file
	lockFile := filepath.Join(path, "LOCK")

	// Check if lock file exists
	if _, err := os.Stat(lockFile); os.IsNotExist(err) {
		// Lock file doesn't exist, nothing to remove
		return nil
	}

	// Attempt to remove the lock file
	if err := os.Remove(lockFile); err != nil {
		// Failed to remove lock file
		return fmt.Errorf("failed to remove lock file at %s: %w", lockFile, err)
	}

	// Successfully removed stale lock file
	logger.Info("Removed stale lock file at %s", lockFile)
	return nil
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
	logger.Info("Successfully stored key %s in LevelDB", key)
	return nil
}

// Get retrieves a value by key from the database.
// Parameters:
//   - key: String key to retrieve
//
// Returns: Value as byte slice and error if retrieval fails
func (d *DB) Get(key string) ([]byte, error) {
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
		// Handle specific error cases
		if err == errors.ErrNotFound {
			// Key doesn't exist in database
			logger.Warn("Key %s not found in LevelDB", key)
			return nil, fmt.Errorf("key %s not found in LevelDB", key)
		}
		// Other error occurred
		logger.Error("Failed to get key %s from LevelDB: %s", key, err.Error())
		return nil, fmt.Errorf("failed to get key %s from LevelDB: %w", key, err)
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
	logger.Info("Successfully deleted key %s from LevelDB", key)
	return nil
}

// Has checks if a key exists in the database.
// Parameters:
//   - key: String key to check
//
// Returns: Boolean indicating existence and error if check fails
func (d *DB) Has(key string) (bool, error) {
	// Acquire read lock for concurrent read access
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	// Check if database is open
	if d.db == nil {
		return false, fmt.Errorf("LevelDB is closed")
	}

	// Attempt to get key to check existence
	_, err := d.db.Get([]byte(key), nil)
	if err != nil {
		// Handle specific error cases
		if err == errors.ErrNotFound {
			// Key doesn't exist, return false (not an error)
			return false, nil
		}
		// Other error occurred during check
		logger.Error("Failed to check key %s in LevelDB: %s", key, err.Error())
		return false, fmt.Errorf("failed to check key %s in LevelDB: %w", key, err)
	}

	// Key exists in database
	return true, nil
}
