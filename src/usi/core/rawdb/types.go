// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/rawdb/types.go
package rawdata

import (
	"sync"
	"time"

	"github.com/sphinxorg/protocol/src/usi/core/types"
	"github.com/syndtr/goleveldb/leveldb"
)

// BackupConfig configures backup behavior for RawData
type BackupConfig struct {
	Enabled        bool
	BackupDir      string
	MaxBackups     int
	BackupOnUpdate bool
	BackupOnDelete bool
}

// RawData stores complete .ecpmeta data in a database instead of separate files
type RawData struct {
	db            *leveldb.DB
	path          string
	mu            sync.RWMutex
	backupEnabled bool
	backupConfig  BackupConfig
}

// StoredMeta wraps the Meta with additional tracking info
type StoredMeta struct {
	*types.Meta
	StoredAt     time.Time `json:"stored_at"`
	FilePath     string    `json:"file_path"`
	FileSize     int64     `json:"file_size,omitempty"`
	FileModTime  int64     `json:"file_mod_time,omitempty"`
	LastVerified int64     `json:"last_verified,omitempty"`
}
