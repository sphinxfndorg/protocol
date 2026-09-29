// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/genesis_vault.go
//
// The genesis VAULT custody policy. There is no separate policy file: the
// M-of-N policy lives in the `multisig` section of the one genesis document,
// <datadir>/config/genesis_state.json (see genesis.go). This file only owns
// the process-level registry: the resolved address and the loaded policy that
// block validation, mempool admission and gossip consult.
package core

import (
	"fmt"
	"sync"

	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	txtypes "github.com/sphinxfndorg/protocol/src/core/transaction"
)

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

// LoadGenesisVaultPolicy resolves the genesis vault from the `multisig` section
// of the single genesis document at path, registers the policy and publishes the
// address it derives.
//
// A document with no multisig section is an error: block-0 authorization fails
// closed once the vault resolves to a registered policy, and silently falling
// back to the legacy vault here would build a different block 0 than every peer.
func LoadGenesisVaultPolicy(path string) (string, error) {
	gf, err := LoadGenesisFile(datadirOf(path))
	if err != nil {
		return "", err
	}
	if gf == nil {
		return "", fmt.Errorf("genesis document %s does not exist", path)
	}
	if gf.Multisig == nil {
		return "", fmt.Errorf("genesis document %s carries no multisig section (the genesis vault policy)", path)
	}
	return registerGenesisVaultPolicy(gf.Multisig)
}

// datadirOf recovers the datadir a per-node genesis-document path lives under, so
// LoadGenesisVaultPolicy can re-read it through the one loader. It simply strips
// the known "config/genesis_state.json" suffix; a path that does not carry that
// suffix is passed through as a datadir, which is what a caller passing a bare
// datadir wants anyway.
func datadirOf(path string) string {
	suffix := GenesisStateFileSubdir
	if len(path) > len(suffix) && path[len(path)-len(suffix):] == suffix {
		return path[:len(path)-len(suffix)]
	}
	return path
}

// registerGenesisVaultPolicy registers p and publishes the address it derives.
// Register happens BEFORE publishing so block validation, mempool admission and
// gossip all see the sender resolved through the registry by the time the address
// becomes visible.
func registerGenesisVaultPolicy(p *multisig.MultiPartyPolicy) (string, error) {
	addr, err := multisig.RegisterPolicy(p)
	if err != nil {
		return "", err
	}
	genesisMultisigMu.Lock()
	defer genesisMultisigMu.Unlock()
	cp := *p
	genesisMultisigPolicy = &cp
	genesisMultisigAddr = addr
	GenesisVaultAddress = addr
	txtypes.GenesisVaultAddress = addr
	return addr, nil
}

// InitGenesisVaultAddress is the package-init entry point. It reads the shared
// repo-root genesis document (the legacy layout, used before a node's own datadir
// is known) and is a no-op when that document is absent or carries no policy.
func InitGenesisVaultAddress() string {
	if addr, err := LoadGenesisVaultPolicy(GenesisStateFileSubdir); err == nil {
		return addr
	}
	return legacyGenesisVaultAddress
}
