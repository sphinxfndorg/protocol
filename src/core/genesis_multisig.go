// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/genesis_multisig.go
package core

import (
	"encoding/json"
	"os"
	"sync"

	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	txtypes "github.com/sphinxfndorg/protocol/src/core/transaction"
)

const defaultGenesisMultisigPath = "config/genesis_multisig.json"

var (
	genesisMultisigMu     sync.RWMutex
	genesisMultisigPolicy *multisig.MultiPartyPolicy
	genesisMultisigAddr   string
)

func DefaultGenesisVaultAddress() string {
	return legacyGenesisVaultAddress
}

func GetGenesisVaultAddress() string {
	genesisMultisigMu.RLock()
	defer genesisMultisigMu.RUnlock()
	if genesisMultisigAddr != "" {
		return genesisMultisigAddr
	}
	return GenesisVaultAddress
}

func GenesisVaultPolicy() *multisig.MultiPartyPolicy {
	genesisMultisigMu.RLock()
	defer genesisMultisigMu.RUnlock()
	return genesisMultisigPolicy
}

func LoadGenesisVaultPolicy(path string) (string, error) {
	if path == "" {
		path = defaultGenesisMultisigPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var p multisig.MultiPartyPolicy
	if err := json.Unmarshal(data, &p); err != nil {
		return "", err
	}
	// Register before publishing the address: block validation, mempool
	// admission and gossip all resolve a sender through this registry.
	addr, err := multisig.RegisterPolicy(&p)
	if err != nil {
		return "", err
	}
	genesisMultisigMu.Lock()
	defer genesisMultisigMu.Unlock()
	cp := p
	genesisMultisigPolicy = &cp
	genesisMultisigAddr = addr
	GenesisVaultAddress = addr
	txtypes.GenesisVaultAddress = addr
	return addr, nil
}

func InitGenesisVaultAddress() string {
	if addr, err := LoadGenesisVaultPolicy(defaultGenesisMultisigPath); err == nil {
		return addr
	}
	return legacyGenesisVaultAddress
}
