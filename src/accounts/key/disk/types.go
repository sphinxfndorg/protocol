// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/account/key/disk/types.go
package disk

import (
	"sync"

	"github.com/sphinxfndorg/protocol/src/accounts/key"
	"github.com/sphinxfndorg/protocol/src/core/wallet/crypter"
)

// DiskKeyStore represents local disk storage for key pairs  // Changed from HotKeyStore
type DiskKeyStore struct { // Changed from HotKeyStore
	mu          sync.RWMutex
	storagePath string
	keys        map[string]*key.KeyPair // In-memory cache
	crypt       *crypter.CCrypter
}
