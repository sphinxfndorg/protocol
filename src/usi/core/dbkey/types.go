// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/dbkey/types.go
package db

import (
	"time"
)

// BackupEntry represents a single backup entry
type BackupEntry struct {
	Key       []byte `json:"key"`
	Value     []byte `json:"value"`
	Timestamp int64  `json:"timestamp"`
	Operation string `json:"operation"`
	KeyString string `json:"key_string,omitempty"`
}

// FullBackup represents a complete database backup
type FullBackup struct {
	Timestamp int64         `json:"timestamp"`
	Type      string        `json:"type"`
	DBPath    string        `json:"db_path"`
	Entries   []BackupEntry `json:"entries"`
	TotalKeys int           `json:"total_keys"`
}

// BackupMetadata contains metadata about a backup
type BackupMetadata struct {
	BackupFile   string `json:"backup_file"`
	Timestamp    int64  `json:"timestamp"`
	Operation    string `json:"operation"`
	Key          string `json:"key,omitempty"`
	DBSize       int64  `json:"db_size"`
	TotalBackups int    `json:"total_backups"`
}

// BackupInfo provides information about a backup file
type BackupInfo struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	ModTime   time.Time `json:"mod_time"`
	IsFull    bool      `json:"is_full"`
	Operation string    `json:"operation,omitempty"`
	Key       string    `json:"key,omitempty"`
}

// BackupConfig configures backup behavior for the database
type BackupConfig struct {
	Enabled        bool
	BackupDir      string
	MaxBackups     int
	BackupOnPut    bool
	BackupOnDelete bool
	AutoBackup     bool  // Automatic backup on close
	BackupInterval int64 // Seconds between automatic backups (0 = disabled)
}
