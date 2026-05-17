// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/sphincs/sign/backend/types.go
package sign

import (
	"sync"

	params "github.com/sphinxorg/protocol/src/core/sthincs/config"
	key "github.com/sphinxorg/protocol/src/core/sthincs/key/backend"
	"github.com/syndtr/goleveldb/leveldb"
)

// SIPS-0011 https://github.com/sphinxorg/SIPS/wiki/sips0011

// SphincsManager holds a reference to KeyManager, the SPHINCS+ parameters,
// and the LevelDB instance used for timestamp-nonce replay prevention.
type SphincsManager struct {
	db         *leveldb.DB
	keyManager *key.KeyManager
	parameters *params.STHINCSParameters
	mu         sync.RWMutex // Mutex for thread-safe database access
}
