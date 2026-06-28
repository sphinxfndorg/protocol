// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/account/key/external/usb.go
package usb

import (
	"sync"

	"github.com/sphinxfndorg/protocol/src/accounts/key"
	"github.com/sphinxfndorg/protocol/src/core/wallet/crypter"
)

// USBKeyStore represents USB storage for key pairs
type USBKeyStore struct {
	mu        sync.RWMutex
	mountPath string
	keys      map[string]*key.KeyPair // In-memory cache (when USB is mounted)
	crypt     *crypter.CCrypter
	isMounted bool
}
