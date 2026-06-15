// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/rawdb/db.go
package rawdata

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sphinxorg/protocol/src/usi/core/types"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const BackupSuffix = ".bak"

var (
	globalDB *RawData
	once     sync.Once
)

// GetDB returns the global RawData database instance
func GetDB() (*RawData, error) {
	log.Printf("[INFO] GetDB: getting global database instance")
	var err error
	once.Do(func() {
		log.Printf("[DEBUG] GetDB: initializing database for first time")
		globalDB, err = NewRawDataWithBackup(BackupConfig{
			Enabled:        true,
			BackupDir:      "",
			MaxBackups:     5,
			BackupOnUpdate: true,
			BackupOnDelete: true,
		})
		if err != nil {
			log.Printf("[ERROR] GetDB: failed to initialize database: %v", err)
		} else {
			log.Printf("[SUCCESS] GetDB: database initialized successfully")
		}
	})
	return globalDB, err
}

// NewRawData creates or opens the RawData database (legacy, without backup)
func NewRawData() (*RawData, error) {
	log.Printf("[INFO] NewRawData: creating/opening RawData database without backup")
	return NewRawDataWithBackup(BackupConfig{Enabled: false})
}

// NewRawDataWithBackup creates or opens the RawData database with backup support
func NewRawDataWithBackup(backupConfig BackupConfig) (*RawData, error) {
	log.Printf("[INFO] NewRawDataWithBackup: creating/opening RawData database with backup config: %+v", backupConfig)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Printf("[ERROR] NewRawDataWithBackup: failed to get home dir: %v", err)
		return nil, fmt.Errorf("failed to get home dir: %w", err)
	}
	log.Printf("[DEBUG] NewRawDataWithBackup: home directory: %s", homeDir)

	dbPath := filepath.Join(homeDir, ".ecp", "rawdata")
	log.Printf("[DEBUG] NewRawDataWithBackup: database path: %s", dbPath)

	if err := os.MkdirAll(dbPath, 0700); err != nil {
		log.Printf("[ERROR] NewRawDataWithBackup: failed to create db dir: %v", err)
		return nil, fmt.Errorf("failed to create db dir: %w", err)
	}
	log.Printf("[DEBUG] NewRawDataWithBackup: database directory created/verified")

	// Create backup directory if enabled
	if backupConfig.Enabled {
		backupDir := backupConfig.BackupDir
		if backupDir == "" {
			backupDir = filepath.Join(dbPath, "backups")
		}
		if err := os.MkdirAll(backupDir, 0700); err != nil {
			log.Printf("[WARN] NewRawDataWithBackup: failed to create backup directory %s: %v", backupDir, err)
		} else {
			log.Printf("[INFO] NewRawDataWithBackup: backup directory created at %s", backupDir)
			backupConfig.BackupDir = backupDir
		}
	}

	opts := &opt.Options{
		Compression: opt.SnappyCompression,
		WriteBuffer: 4 * 1024 * 1024,
	}
	log.Printf("[DEBUG] NewRawDataWithBackup: opening LevelDB with compression=SNAPPY, write buffer=%d", opts.WriteBuffer)

	db, err := leveldb.OpenFile(dbPath, opts)
	if err != nil {
		log.Printf("[ERROR] NewRawDataWithBackup: failed to open database: %v", err)
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	log.Printf("[SUCCESS] NewRawDataWithBackup: database opened successfully at %s", dbPath)

	return &RawData{
		db:            db,
		path:          dbPath,
		backupEnabled: backupConfig.Enabled,
		backupConfig:  backupConfig,
	}, nil
}

// StoreECPMeta stores complete .ecpmeta data for a file
func (r *RawData) StoreECPMeta(filePath string, meta *types.Meta) error {
	log.Printf("[INFO] StoreECPMeta: storing metadata for file: %s", filePath)

	r.mu.Lock()
	defer r.mu.Unlock()
	log.Printf("[DEBUG] StoreECPMeta: acquired write lock")

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		log.Printf("[ERROR] StoreECPMeta: failed to get absolute path: %v", err)
		return fmt.Errorf("failed to get absolute path: %w", err)
	}
	log.Printf("[DEBUG] StoreECPMeta: absolute path: %s", absPath)

	// Create backup before update if enabled
	if r.backupEnabled && r.backupConfig.BackupOnUpdate {
		if err := r.createBackupBeforeUpdate(absPath); err != nil {
			log.Printf("[WARN] StoreECPMeta: failed to create backup for %s: %v", absPath, err)
			// Continue anyway - backup failure shouldn't stop the update
		}
	}

	fileInfo, err := os.Stat(absPath)

	stored := &StoredMeta{
		Meta:     meta,
		StoredAt: time.Now(),
		FilePath: absPath,
	}
	log.Printf("[DEBUG] StoreECPMeta: stored timestamp: %v", stored.StoredAt)

	if err == nil {
		stored.FileSize = fileInfo.Size()
		stored.FileModTime = fileInfo.ModTime().Unix()
		log.Printf("[DEBUG] StoreECPMeta: file size: %d bytes, mod time: %d", stored.FileSize, stored.FileModTime)
	} else {
		log.Printf("[WARN] StoreECPMeta: could not stat file: %v", err)
	}

	// Store by file path (primary key)
	pathKey := []byte("path:" + absPath)
	log.Printf("[DEBUG] StoreECPMeta: storing primary key: %s", pathKey)

	data, err := json.Marshal(stored)
	if err != nil {
		log.Printf("[ERROR] StoreECPMeta: failed to marshal metadata: %v", err)
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	log.Printf("[DEBUG] StoreECPMeta: marshaled data size: %d bytes", len(data))

	if err := r.db.Put(pathKey, data, nil); err != nil {
		log.Printf("[ERROR] StoreECPMeta: failed to store by path: %v", err)
		return fmt.Errorf("failed to store by path: %w", err)
	}
	log.Printf("[DEBUG] StoreECPMeta: stored by path successfully")

	// Store by file hash for quick lookup (secondary index)
	if meta.FileHash != "" {
		hashKey := []byte("hash:" + meta.FileHash)
		log.Printf("[DEBUG] StoreECPMeta: storing hash index: %.16s...", hashKey)
		if err := r.db.Put(hashKey, []byte(absPath), nil); err != nil {
			log.Printf("[ERROR] StoreECPMeta: failed to store hash index: %v", err)
			return fmt.Errorf("failed to store hash index: %w", err)
		}
		log.Printf("[DEBUG] StoreECPMeta: stored hash index successfully")
	}

	// Store by final document hash
	if meta.FinalDocumentHash != "" && meta.FinalDocumentHash != meta.FileHash {
		finalHashKey := []byte("finalhash:" + meta.FinalDocumentHash)
		log.Printf("[DEBUG] StoreECPMeta: storing final hash index: %.16s...", finalHashKey)
		if err := r.db.Put(finalHashKey, []byte(absPath), nil); err != nil {
			log.Printf("[ERROR] StoreECPMeta: failed to store final hash index: %v", err)
			return fmt.Errorf("failed to store final hash index: %w", err)
		}
		log.Printf("[DEBUG] StoreECPMeta: stored final hash index successfully")
	}

	// Store by signature prefix
	if meta.Signature != "" {
		sigPrefix := meta.Signature
		if len(sigPrefix) > 16 {
			sigPrefix = sigPrefix[:16]
		}
		sigKey := []byte("sig:" + sigPrefix)
		log.Printf("[DEBUG] StoreECPMeta: storing signature index: %.16s...", sigKey)
		if err := r.db.Put(sigKey, []byte(absPath), nil); err != nil {
			log.Printf("[WARN] StoreECPMeta: failed to store signature index: %v", err)
			// Non-critical, continue
		} else {
			log.Printf("[DEBUG] StoreECPMeta: stored signature index successfully")
		}
	}

	log.Printf("[SUCCESS] StoreECPMeta: metadata stored successfully for %s", filepath.Base(filePath))
	return nil
}

// LoadECPMeta retrieves complete .ecpmeta data for a file
func (r *RawData) LoadECPMeta(filePath string) (*types.Meta, error) {
	log.Printf("[INFO] LoadECPMeta: loading metadata for file: %s", filePath)

	r.mu.RLock()
	defer r.mu.RUnlock()
	log.Printf("[DEBUG] LoadECPMeta: acquired read lock")

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		log.Printf("[ERROR] LoadECPMeta: failed to get absolute path: %v", err)
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}
	log.Printf("[DEBUG] LoadECPMeta: absolute path: %s", absPath)

	pathKey := []byte("path:" + absPath)
	log.Printf("[DEBUG] LoadECPMeta: looking up key: %s", pathKey)

	data, err := r.db.Get(pathKey, nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			log.Printf("[INFO] LoadECPMeta: metadata not found for %s", filepath.Base(filePath))
			return nil, nil
		}
		log.Printf("[ERROR] LoadECPMeta: failed to load metadata: %v", err)
		return nil, fmt.Errorf("failed to load metadata: %w", err)
	}
	log.Printf("[DEBUG] LoadECPMeta: retrieved data size: %d bytes", len(data))

	var stored StoredMeta
	if err := json.Unmarshal(data, &stored); err != nil {
		log.Printf("[ERROR] LoadECPMeta: failed to unmarshal metadata: %v", err)
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	log.Printf("[SUCCESS] LoadECPMeta: metadata loaded successfully for %s (stored at: %v)", filepath.Base(filePath), stored.StoredAt)
	return stored.Meta, nil
}

// DeleteECPMeta removes .ecpmeta data for a file
func (r *RawData) DeleteECPMeta(filePath string) error {
	log.Printf("[INFO] DeleteECPMeta: deleting metadata for file: %s", filePath)

	r.mu.Lock()
	defer r.mu.Unlock()
	log.Printf("[DEBUG] DeleteECPMeta: acquired write lock")

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		log.Printf("[ERROR] DeleteECPMeta: failed to get absolute path: %v", err)
		return fmt.Errorf("failed to get absolute path: %w", err)
	}
	log.Printf("[DEBUG] DeleteECPMeta: absolute path: %s", absPath)

	// Create backup before delete if enabled
	if r.backupEnabled && r.backupConfig.BackupOnDelete {
		if err := r.createBackupBeforeDelete(absPath); err != nil {
			log.Printf("[WARN] DeleteECPMeta: failed to create backup before delete for %s: %v", absPath, err)
		}
	}

	// Read existing record directly (no lock re-entry).
	pathKey := []byte("path:" + absPath)
	log.Printf("[DEBUG] DeleteECPMeta: reading existing record for key: %s", pathKey)

	data, err := r.db.Get(pathKey, nil)
	if err != nil && err != leveldb.ErrNotFound {
		log.Printf("[ERROR] DeleteECPMeta: failed to read before delete: %v", err)
		return fmt.Errorf("failed to read before delete: %w", err)
	}

	if err := r.db.Delete(pathKey, nil); err != nil {
		log.Printf("[ERROR] DeleteECPMeta: failed to delete path key: %v", err)
		return fmt.Errorf("failed to delete path key: %w", err)
	}
	log.Printf("[DEBUG] DeleteECPMeta: deleted path key successfully")

	if data != nil {
		var stored StoredMeta
		if json.Unmarshal(data, &stored) == nil && stored.Meta != nil {
			log.Printf("[DEBUG] DeleteECPMeta: cleaning up secondary indexes")

			if stored.FileHash != "" {
				hashKey := []byte("hash:" + stored.FileHash)
				log.Printf("[DEBUG] DeleteECPMeta: deleting hash index: %.16s...", hashKey)
				if err := r.db.Delete(hashKey, nil); err != nil {
					log.Printf("[WARN] DeleteECPMeta: failed to delete hash index: %v", err)
				} else {
					log.Printf("[DEBUG] DeleteECPMeta: deleted hash index")
				}
			}

			if stored.FinalDocumentHash != "" && stored.FinalDocumentHash != stored.FileHash {
				finalHashKey := []byte("finalhash:" + stored.FinalDocumentHash)
				log.Printf("[DEBUG] DeleteECPMeta: deleting final hash index: %.16s...", finalHashKey)
				if err := r.db.Delete(finalHashKey, nil); err != nil {
					log.Printf("[WARN] DeleteECPMeta: failed to delete final hash index: %v", err)
				} else {
					log.Printf("[DEBUG] DeleteECPMeta: deleted final hash index")
				}
			}

			if stored.Signature != "" {
				sigPrefix := stored.Signature
				if len(sigPrefix) > 16 {
					sigPrefix = sigPrefix[:16]
				}
				sigKey := []byte("sig:" + sigPrefix)
				log.Printf("[DEBUG] DeleteECPMeta: deleting signature index: %.16s...", sigKey)
				if err := r.db.Delete(sigKey, nil); err != nil {
					log.Printf("[WARN] DeleteECPMeta: failed to delete signature index: %v", err)
				} else {
					log.Printf("[DEBUG] DeleteECPMeta: deleted signature index")
				}
			}
		} else {
			log.Printf("[WARN] DeleteECPMeta: could not unmarshal data for secondary index cleanup")
		}
	}

	log.Printf("[SUCCESS] DeleteECPMeta: metadata deleted successfully for %s", filepath.Base(filePath))
	return nil
}

// HasECPMeta checks if a file has .ecpmeta data stored
func (r *RawData) HasECPMeta(filePath string) (bool, error) {
	log.Printf("[DEBUG] HasECPMeta: checking existence for: %s", filePath)

	meta, err := r.LoadECPMeta(filePath)
	if err != nil {
		log.Printf("[ERROR] HasECPMeta: error loading metadata: %v", err)
		return false, err
	}
	exists := meta != nil
	log.Printf("[DEBUG] HasECPMeta: exists = %v", exists)
	return exists, nil
}

// createBackupBeforeUpdate creates a backup of existing data before update
func (r *RawData) createBackupBeforeUpdate(absPath string) error {
	if !r.backupEnabled {
		return nil
	}

	// Try to get existing data
	pathKey := []byte("path:" + absPath)
	data, err := r.db.Get(pathKey, nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			// No existing data, nothing to backup
			log.Printf("[DEBUG] createBackupBeforeUpdate: no existing data for %s, skipping backup", absPath)
			return nil
		}
		return fmt.Errorf("failed to get existing data: %w", err)
	}

	// Create backup file
	backupPath := r.getBackupPath(absPath)
	log.Printf("[INFO] createBackupBeforeUpdate: creating backup at %s", backupPath)

	// Write backup file
	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	// Add metadata file with timestamp and original path
	metadata := map[string]interface{}{
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"original_path": absPath,
		"backup_type":   "pre_update",
		"database_path": r.path,
	}

	metaData, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		log.Printf("[WARN] createBackupBeforeUpdate: failed to marshal metadata: %v", err)
	} else {
		metaPath := backupPath + ".meta"
		if err := os.WriteFile(metaPath, metaData, 0600); err != nil {
			log.Printf("[WARN] createBackupBeforeUpdate: failed to write metadata file: %v", err)
		}
	}

	log.Printf("[SUCCESS] createBackupBeforeUpdate: backup created successfully at %s", backupPath)
	return nil
}

// createBackupBeforeDelete creates a backup before deletion
func (r *RawData) createBackupBeforeDelete(absPath string) error {
	if !r.backupEnabled {
		return nil
	}

	// Get existing data
	pathKey := []byte("path:" + absPath)
	data, err := r.db.Get(pathKey, nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			log.Printf("[DEBUG] createBackupBeforeDelete: no existing data for %s, skipping backup", absPath)
			return nil
		}
		return fmt.Errorf("failed to get data before delete: %w", err)
	}

	// Create backup file
	backupPath := r.getBackupPath(absPath + ".deleted")
	log.Printf("[INFO] createBackupBeforeDelete: creating backup before deletion at %s", backupPath)

	// Write backup file
	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	// Add metadata
	metadata := map[string]interface{}{
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"original_path": absPath,
		"backup_type":   "pre_delete",
		"database_path": r.path,
		"deleted_at":    time.Now().UTC().Unix(),
	}

	metaData, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		log.Printf("[WARN] createBackupBeforeDelete: failed to marshal metadata: %v", err)
	} else {
		metaPath := backupPath + ".meta"
		if err := os.WriteFile(metaPath, metaData, 0600); err != nil {
			log.Printf("[WARN] createBackupBeforeDelete: failed to write metadata file: %v", err)
		}
	}

	log.Printf("[SUCCESS] createBackupBeforeDelete: backup created successfully at %s", backupPath)
	return nil
}

// getBackupPath returns the backup file path for a given file path
func (r *RawData) getBackupPath(originalPath string) string {
	// Create a safe filename from the original path
	safeName := filepath.Base(originalPath)
	// Add timestamp to avoid collisions
	timestamp := time.Now().UTC().Unix()

	if r.backupConfig.BackupDir != "" {
		return filepath.Join(r.backupConfig.BackupDir, fmt.Sprintf("%s_%d%s", safeName, timestamp, BackupSuffix))
	}

	// Fallback to database directory
	return filepath.Join(r.path, fmt.Sprintf("%s_%d%s", safeName, timestamp, BackupSuffix))
}

// RestoreFromBackup restores data from a backup file
func (r *RawData) RestoreFromBackup(backupFile string) error {
	log.Printf("[INFO] RestoreFromBackup: restoring from backup file: %s", backupFile)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Read backup file
	data, err := os.ReadFile(backupFile)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	// Parse the stored meta
	var stored StoredMeta
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("failed to unmarshal backup data: %w", err)
	}

	// Restore to database
	pathKey := []byte("path:" + stored.FilePath)
	if err := r.db.Put(pathKey, data, nil); err != nil {
		return fmt.Errorf("failed to restore data: %w", err)
	}

	log.Printf("[SUCCESS] RestoreFromBackup: restored data for %s", stored.FilePath)
	return nil
}

// ListBackups lists all available backup files
func (r *RawData) ListBackups() ([]string, error) {
	if !r.backupEnabled {
		return nil, fmt.Errorf("backups are not enabled")
	}

	backupDir := r.backupConfig.BackupDir
	if backupDir == "" {
		backupDir = r.path
	}

	var backups []string

	files, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return backups, nil
		}
		return nil, fmt.Errorf("failed to read backup directory: %w", err)
	}

	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == BackupSuffix {
			backups = append(backups, filepath.Join(backupDir, file.Name()))
		}
	}

	log.Printf("[INFO] ListBackups: found %d backup files", len(backups))
	return backups, nil
}

// CleanupOldBackups removes old backup files keeping only the most recent ones
func (r *RawData) CleanupOldBackups(maxKept int) error {
	if !r.backupEnabled {
		return nil
	}

	if maxKept <= 0 {
		maxKept = r.backupConfig.MaxBackups
		if maxKept <= 0 {
			maxKept = 5
		}
	}

	backupDir := r.backupConfig.BackupDir
	if backupDir == "" {
		backupDir = r.path
	}

	files, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read backup directory: %w", err)
	}

	// Collect backup files with their modification times
	type backupInfo struct {
		path    string
		modTime time.Time
	}
	var backups []backupInfo

	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == BackupSuffix {
			info, err := file.Info()
			if err != nil {
				log.Printf("[WARN] CleanupOldBackups: failed to get info for %s: %v", file.Name(), err)
				continue
			}
			backups = append(backups, backupInfo{
				path:    filepath.Join(backupDir, file.Name()),
				modTime: info.ModTime(),
			})
		}
	}

	// If we have fewer backups than max, nothing to clean
	if len(backups) <= maxKept {
		log.Printf("[DEBUG] CleanupOldBackups: %d backups found, max %d, nothing to clean", len(backups), maxKept)
		return nil
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
	toRemove := backups[:len(backups)-maxKept]
	for _, backup := range toRemove {
		if err := os.Remove(backup.path); err != nil {
			log.Printf("[WARN] CleanupOldBackups: failed to remove old backup %s: %v", backup.path, err)
		} else {
			log.Printf("[DEBUG] CleanupOldBackups: removed old backup %s", backup.path)
		}

		// Also remove metadata file if exists
		metaPath := backup.path + ".meta"
		os.Remove(metaPath)
	}

	log.Printf("[INFO] CleanupOldBackups: removed %d old backups, kept %d", len(toRemove), maxKept)
	return nil
}

// CreateFullBackup creates a complete backup of all data
func (r *RawData) CreateFullBackup() error {
	if !r.backupEnabled {
		return fmt.Errorf("backups are not enabled")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	backupDir := r.backupConfig.BackupDir
	if backupDir == "" {
		backupDir = filepath.Join(r.path, "backups", "full")
	} else {
		backupDir = filepath.Join(backupDir, "full")
	}

	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return fmt.Errorf("failed to create full backup directory: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102_150405")
	fullBackupPath := filepath.Join(backupDir, fmt.Sprintf("full_backup_%s.json", timestamp))

	log.Printf("[INFO] CreateFullBackup: creating full backup at %s", fullBackupPath)

	// Iterate over all keys
	iter := r.db.NewIterator(nil, nil)
	defer iter.Release()

	var allData []struct {
		Key   string          `json:"key"`
		Value json.RawMessage `json:"value"`
	}

	for iter.Next() {
		key := string(iter.Key())
		// Skip index keys if you only want path entries
		// For full backup, include everything
		allData = append(allData, struct {
			Key   string          `json:"key"`
			Value json.RawMessage `json:"value"`
		}{
			Key:   key,
			Value: iter.Value(),
		})
	}

	if err := iter.Error(); err != nil {
		return fmt.Errorf("iterator error: %w", err)
	}

	// Marshal all data
	data, err := json.MarshalIndent(allData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal backup data: %w", err)
	}

	// Write backup file
	if err := os.WriteFile(fullBackupPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write full backup: %w", err)
	}

	log.Printf("[SUCCESS] CreateFullBackup: full backup created with %d items", len(allData))
	return nil
}

// Close closes the database
func (r *RawData) Close() error {
	log.Printf("[INFO] Close: closing database at %s", r.path)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Create final backup before closing if enabled
	if r.backupEnabled {
		log.Printf("[INFO] Close: creating final database backup")
		if err := r.CreateFullBackup(); err != nil {
			log.Printf("[WARN] Close: failed to create final backup: %v", err)
		}
	}

	if err := r.db.Close(); err != nil {
		log.Printf("[ERROR] Close: failed to close database: %v", err)
		return err
	}

	log.Printf("[SUCCESS] Close: database closed successfully")
	return nil
}
