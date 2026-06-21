// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/key/constants.go
package keys

import (
	"os"
	"path/filepath"
)

// KeyDir is the directory where key files are stored
// This is kept for backward compatibility with gui.go
// The actual storage is managed by StorageManager
var KeyDir string

func init() {
	// Use user's home directory for storage (consistent with wallet pattern)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	KeyDir = filepath.Join(homeDir, ".sphinx", "keys")
}
