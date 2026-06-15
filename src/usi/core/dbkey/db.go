// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/dbkey/db.go
package db

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

const BackupSuffix = ".bak"

// DB wraps LevelDB instance with helper methods and backup support
type DB struct {
	*leveldb.DB
	path          string
	mu            sync.RWMutex
	backupEnabled bool
	backupConfig  BackupConfig
	lastBackup    int64
}

// Open opens or creates a LevelDB database at the given path
func Open(path string) (*DB, error) {
	return OpenWithBackup(path, BackupConfig{
		Enabled:        true,
		BackupDir:      "",
		MaxBackups:     5,
		BackupOnPut:    true,
		BackupOnDelete: true,
		AutoBackup:     true,
		BackupInterval: 3600, // Backup every hour if AutoBackup is enabled
	})
}

// OpenWithBackup opens or creates a LevelDB database with backup support
func OpenWithBackup(path string, config BackupConfig) (*DB, error) {
	log.Printf("Opening LevelDB at: %s", path)

	// Ensure directory exists
	if err := ensureDir(path); err != nil {
		return nil, err
	}

	// Create backup directory if enabled
	if config.Enabled {
		backupDir := config.BackupDir
		if backupDir == "" {
			backupDir = getBackupDir(path)
		}
		if err := os.MkdirAll(backupDir, 0700); err != nil {
			log.Printf("WARNING: Failed to create backup directory %s: %v", backupDir, err)
			config.Enabled = false
		} else {
			log.Printf("Backup directory created at: %s", backupDir)
			config.BackupDir = backupDir
		}
	}

	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		log.Printf("Failed to open LevelDB at %s: %v", path, err)
		return nil, err
	}

	log.Println("LevelDB opened successfully")

	dbInstance := &DB{
		DB:            db,
		path:          path,
		backupEnabled: config.Enabled,
		backupConfig:  config,
		lastBackup:    time.Now().Unix(),
	}

	// Create initial backup if enabled
	if config.Enabled && config.AutoBackup {
		if err := dbInstance.createFullBackup("initial"); err != nil {
			log.Printf("WARNING: Failed to create initial backup: %v", err)
		}
	}

	return dbInstance, nil
}

// Close closes the database
func (d *DB) Close() error {
	if d.DB != nil {
		log.Println("Closing LevelDB")

		// Create final backup if enabled
		if d.backupEnabled && d.backupConfig.AutoBackup {
			log.Println("Creating final backup before closing...")
			if err := d.createFullBackup("final"); err != nil {
				log.Printf("WARNING: Failed to create final backup: %v", err)
			}
		}

		return d.DB.Close()
	}
	return nil
}

// Put stores a key-value pair with optional backup
func (d *DB) Put(key, value []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	log.Printf("DB Put: key=%x", key)

	// Create backup before put if enabled
	if d.backupEnabled && d.backupConfig.BackupOnPut {
		if err := d.createBackupBeforeUpdate(key); err != nil {
			log.Printf("WARNING: Failed to create backup for key %x: %v", key, err)
			// Continue anyway - backup failure shouldn't stop the operation
		}
	}

	err := d.DB.Put(key, value, nil)
	if err != nil {
		log.Printf("DB Put error: %v", err)
		return err
	}

	// Check if we need to do automatic backup
	if d.backupEnabled && d.backupConfig.AutoBackup && d.backupConfig.BackupInterval > 0 {
		d.checkAndAutoBackup()
	}

	log.Println("DB Put: success")
	return nil
}

// Get retrieves a value by key
func (d *DB) Get(key []byte) ([]byte, error) {
	log.Printf("DB Get: key=%x", key)
	data, err := d.DB.Get(key, nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			log.Printf("DB Get: key not found: %x", key)
		} else {
			log.Printf("DB Get error: %v", err)
		}
		return nil, err
	}
	log.Println("DB Get: success")
	return data, nil
}

// Delete removes a key with backup
func (d *DB) Delete(key []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	log.Printf("DB Delete: key=%x", key)

	// Create backup before delete if enabled
	if d.backupEnabled && d.backupConfig.BackupOnDelete {
		if err := d.createBackupBeforeDelete(key); err != nil {
			log.Printf("WARNING: Failed to create backup before delete for key %x: %v", key, err)
		}
	}

	err := d.DB.Delete(key, nil)
	if err == leveldb.ErrNotFound {
		log.Println("DB Delete: key already missing (ignored)")
		return nil
	}
	if err != nil {
		log.Printf("DB Delete error: %v", err)
		return err
	}

	log.Println("DB Delete: success")
	return nil
}

// Has checks if a key exists
func (d *DB) Has(key []byte) (bool, error) {
	log.Printf("DB Has: key=%x", key)
	has, err := d.DB.Has(key, nil)
	if err != nil {
		log.Printf("DB Has error: %v", err)
		return false, err
	}
	log.Printf("DB Has: exists=%v", has)
	return has, nil
}

// Path returns the database path
func (d *DB) Path() string {
	return d.path
}

// createBackupBeforeUpdate creates a backup of existing data before update
func (d *DB) createBackupBeforeUpdate(key []byte) error {
	// Get existing data
	existingData, err := d.DB.Get(key, nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			// No existing data, nothing to backup
			log.Printf("No existing data for key %x, skipping backup", key)
			return nil
		}
		return fmt.Errorf("failed to get existing data: %w", err)
	}

	// Create backup file
	backupPath := d.getBackupPathForOperation(key, "pre_update")
	log.Printf("Creating backup before update at: %s", backupPath)

	// Create backup data structure
	backup := BackupEntry{
		Key:       key,
		Value:     existingData,
		Timestamp: time.Now().Unix(),
		Operation: "pre_update",
		KeyString: string(key),
	}

	return d.writeBackup(backup, backupPath)
}

// createBackupBeforeDelete creates a backup before deletion
func (d *DB) createBackupBeforeDelete(key []byte) error {
	// Get data before deletion
	data, err := d.DB.Get(key, nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			log.Printf("No existing data for key %x, skipping backup", key)
			return nil
		}
		return fmt.Errorf("failed to get data before delete: %w", err)
	}

	// Create backup file
	backupPath := d.getBackupPathForOperation(key, "pre_delete")
	log.Printf("Creating backup before delete at: %s", backupPath)

	// Create backup data structure
	backup := BackupEntry{
		Key:       key,
		Value:     data,
		Timestamp: time.Now().Unix(),
		Operation: "pre_delete",
		KeyString: string(key),
	}

	return d.writeBackup(backup, backupPath)
}

// getBackupPathForOperation returns backup file path for an operation
func (d *DB) getBackupPathForOperation(key []byte, operation string) string {
	timestamp := time.Now().Unix()
	keyStr := fmt.Sprintf("%x", key)
	if len(keyStr) > 32 {
		keyStr = keyStr[:32]
	}

	filename := fmt.Sprintf("%s_%d_%s%s", operation, timestamp, keyStr, BackupSuffix)

	if d.backupConfig.BackupDir != "" {
		return filepath.Join(d.backupConfig.BackupDir, filename)
	}

	return filepath.Join(getBackupDir(d.path), filename)
}

// getBackupPath returns the backup directory path
func getBackupDir(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "backups")
}

// writeBackup writes a backup entry to disk
func (d *DB) writeBackup(backup BackupEntry, path string) error {
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal backup: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	// Write metadata
	metadata := BackupMetadata{
		BackupFile:   path,
		Timestamp:    backup.Timestamp,
		Operation:    backup.Operation,
		Key:          backup.KeyString,
		DBSize:       d.getDatabaseSize(),
		TotalBackups: d.getBackupCount(),
	}

	metaData, _ := json.MarshalIndent(metadata, "", "  ")
	metaPath := path + ".meta"
	os.WriteFile(metaPath, metaData, 0600)

	log.Printf("Backup created successfully: %s", path)
	return nil
}

// createFullBackup creates a complete backup of all data
func (d *DB) createFullBackup(backupType string) error {
	log.Printf("Creating full %s backup...", backupType)

	timestamp := time.Now().Unix()
	backupPath := d.getFullBackupPath(backupType, timestamp)

	// Iterate over all keys
	iter := d.DB.NewIterator(nil, nil)
	defer iter.Release()

	var allData []BackupEntry

	for iter.Next() {
		key := make([]byte, len(iter.Key()))
		value := make([]byte, len(iter.Value()))
		copy(key, iter.Key())
		copy(value, iter.Value())

		allData = append(allData, BackupEntry{
			Key:       key,
			Value:     value,
			Timestamp: timestamp,
			Operation: backupType + "_backup",
			KeyString: string(key),
		})
	}

	if err := iter.Error(); err != nil {
		return fmt.Errorf("iterator error during backup: %w", err)
	}

	// Write full backup
	fullBackup := FullBackup{
		Timestamp: timestamp,
		Type:      backupType,
		DBPath:    d.path,
		Entries:   allData,
		TotalKeys: len(allData),
	}

	data, err := json.MarshalIndent(fullBackup, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal full backup: %w", err)
	}

	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write full backup: %w", err)
	}

	d.lastBackup = timestamp
	log.Printf("Full %s backup created with %d entries at: %s", backupType, len(allData), backupPath)

	// Cleanup old backups if needed
	if d.backupConfig.MaxBackups > 0 {
		d.cleanupOldBackups()
	}

	return nil
}

// getFullBackupPath returns path for full backup
func (d *DB) getFullBackupPath(backupType string, timestamp int64) string {
	filename := fmt.Sprintf("full_%s_%d%s", backupType, timestamp, BackupSuffix)

	if d.backupConfig.BackupDir != "" {
		return filepath.Join(d.backupConfig.BackupDir, filename)
	}

	return filepath.Join(getBackupDir(d.path), filename)
}

// checkAndAutoBackup performs automatic backup if interval has passed
func (d *DB) checkAndAutoBackup() {
	now := time.Now().Unix()
	if now-d.lastBackup >= d.backupConfig.BackupInterval {
		log.Printf("Auto-backup interval reached, creating backup...")
		go func() {
			if err := d.createFullBackup("auto"); err != nil {
				log.Printf("WARNING: Auto-backup failed: %v", err)
			}
		}()
	}
}

// getDatabaseSize returns approximate database size
func (d *DB) getDatabaseSize() int64 {
	var size int64
	iter := d.DB.NewIterator(nil, nil)
	defer iter.Release()

	for iter.Next() {
		size += int64(len(iter.Key()) + len(iter.Value()))
	}
	return size
}

// getBackupCount returns number of backup files
func (d *DB) getBackupCount() int {
	backupDir := d.backupConfig.BackupDir
	if backupDir == "" {
		backupDir = getBackupDir(d.path)
	}

	files, err := os.ReadDir(backupDir)
	if err != nil {
		return 0
	}

	count := 0
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == BackupSuffix {
			count++
		}
	}
	return count
}

// cleanupOldBackups removes old backup files keeping only recent ones
func (d *DB) cleanupOldBackups() {
	backupDir := d.backupConfig.BackupDir
	if backupDir == "" {
		backupDir = getBackupDir(d.path)
	}

	files, err := os.ReadDir(backupDir)
	if err != nil {
		log.Printf("Failed to read backup directory for cleanup: %v", err)
		return
	}

	type backupFile struct {
		name    string
		modTime time.Time
	}
	var backups []backupFile

	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == BackupSuffix {
			info, err := file.Info()
			if err != nil {
				continue
			}
			backups = append(backups, backupFile{
				name:    file.Name(),
				modTime: info.ModTime(),
			})
		}
	}

	// Sort by modification time (oldest first)
	for i := 0; i < len(backups)-1; i++ {
		for j := i + 1; j < len(backups); j++ {
			if backups[i].modTime.After(backups[j].modTime) {
				backups[i], backups[j] = backups[j], backups[i]
			}
		}
	}

	// Remove oldest backups
	maxKeep := d.backupConfig.MaxBackups
	if len(backups) > maxKeep {
		toRemove := backups[:len(backups)-maxKeep]
		for _, backup := range toRemove {
			backupPath := filepath.Join(backupDir, backup.name)
			if err := os.Remove(backupPath); err != nil {
				log.Printf("Failed to remove old backup %s: %v", backup.name, err)
			} else {
				log.Printf("Removed old backup: %s", backup.name)
			}

			// Also remove metadata file
			metaPath := backupPath + ".meta"
			os.Remove(metaPath)
		}
	}
}

// RestoreFromBackup restores data from a backup file
func (d *DB) RestoreFromBackup(backupPath string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	log.Printf("Restoring from backup: %s", backupPath)

	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	// Try to parse as full backup first
	var fullBackup FullBackup
	if err := json.Unmarshal(data, &fullBackup); err == nil && fullBackup.TotalKeys > 0 {
		// It's a full backup
		log.Printf("Restoring full backup with %d entries", fullBackup.TotalKeys)

		// Create a new batch for restoration
		batch := new(leveldb.Batch)

		for _, entry := range fullBackup.Entries {
			batch.Put(entry.Key, entry.Value)
		}

		if err := d.DB.Write(batch, nil); err != nil {
			return fmt.Errorf("failed to restore full backup: %w", err)
		}

		log.Printf("Full backup restored successfully")
		return nil
	}

	// Try to parse as single entry backup
	var backup BackupEntry
	if err := json.Unmarshal(data, &backup); err != nil {
		return fmt.Errorf("failed to parse backup file: %w", err)
	}

	// Restore single entry
	if err := d.DB.Put(backup.Key, backup.Value, nil); err != nil {
		return fmt.Errorf("failed to restore entry: %w", err)
	}

	log.Printf("Restored entry for key: %s", backup.KeyString)
	return nil
}

// ListBackups lists all available backup files
func (d *DB) ListBackups() ([]BackupInfo, error) {
	if !d.backupEnabled {
		return nil, fmt.Errorf("backups are not enabled")
	}

	backupDir := d.backupConfig.BackupDir
	if backupDir == "" {
		backupDir = getBackupDir(d.path)
	}

	var backups []BackupInfo

	files, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return backups, nil
		}
		return nil, fmt.Errorf("failed to read backup directory: %w", err)
	}

	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == BackupSuffix {
			info, err := file.Info()
			if err != nil {
				continue
			}

			backupInfo := BackupInfo{
				Name:    file.Name(),
				Path:    filepath.Join(backupDir, file.Name()),
				Size:    info.Size(),
				ModTime: info.ModTime(),
				IsFull:  len(file.Name()) > 4 && file.Name()[:4] == "full",
			}

			// Try to read metadata if available
			metaPath := backupInfo.Path + ".meta"
			if metaData, err := os.ReadFile(metaPath); err == nil {
				var metadata BackupMetadata
				if json.Unmarshal(metaData, &metadata) == nil {
					backupInfo.Operation = metadata.Operation
					backupInfo.Key = metadata.Key
				}
			}

			backups = append(backups, backupInfo)
		}
	}

	log.Printf("Found %d backup files", len(backups))
	return backups, nil
}

// Helper: ensure parent directory exists
func ensureDir(path string) error {
	dir := filepath.Dir(path)
	log.Printf("Ensuring directory exists: %s", dir)
	return mkdirAll(dir, 0700)
}

func mkdirAll(path string, perm os.FileMode) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("Creating directory: %s", path)
		return os.MkdirAll(path, perm)
	} else if err != nil {
		return err
	}
	return nil
}

// List returns all keys with the given prefix
func (d *DB) List(prefix []byte) ([][]byte, error) {
	log.Printf("DB List: prefix=%x", prefix)

	var keys [][]byte

	iter := d.DB.NewIterator(nil, nil)
	defer iter.Release()

	for iter.Next() {
		key := iter.Key()
		if len(prefix) > 0 && len(key) >= len(prefix) {
			// Check if key starts with prefix
			match := true
			for i := 0; i < len(prefix); i++ {
				if key[i] != prefix[i] {
					match = false
					break
				}
			}
			if match {
				// Make a copy since the iterator's key will be reused
				keyCopy := make([]byte, len(key))
				copy(keyCopy, key)
				keys = append(keys, keyCopy)
			}
		} else if len(prefix) == 0 {
			keyCopy := make([]byte, len(key))
			copy(keyCopy, key)
			keys = append(keys, keyCopy)
		}
	}

	if err := iter.Error(); err != nil {
		log.Printf("DB List error: %v", err)
		return nil, err
	}

	log.Printf("DB List: found %d keys", len(keys))
	return keys, nil
}

// ListKeysString returns all keys with prefix as strings (convenience method)
func (d *DB) ListKeysString(prefix string) ([]string, error) {
	keys, err := d.List([]byte(prefix))
	if err != nil {
		return nil, err
	}

	result := make([]string, len(keys))
	for i, key := range keys {
		result[i] = string(key)
	}
	return result, nil
}

// Iterate over keys with prefix and call callback for each
func (d *DB) Iterate(prefix []byte, callback func(key, value []byte) error) error {
	iter := d.DB.NewIterator(nil, nil)
	defer iter.Release()

	for iter.Next() {
		key := iter.Key()
		if len(prefix) > 0 && len(key) >= len(prefix) {
			match := true
			for i := 0; i < len(prefix); i++ {
				if key[i] != prefix[i] {
					match = false
					break
				}
			}
			if match {
				value := iter.Value()
				// Make copies since iterator values will be reused
				keyCopy := make([]byte, len(key))
				valueCopy := make([]byte, len(value))
				copy(keyCopy, key)
				copy(valueCopy, value)

				if err := callback(keyCopy, valueCopy); err != nil {
					return err
				}
			}
		}
	}

	return iter.Error()
}
