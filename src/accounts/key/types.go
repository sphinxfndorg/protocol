// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/account/key/types.go
package key

import (
	"sync"
	"time"
)

// HardwareWalletType represents different wallet storage types
type HardwareWalletType string

const (
	WalletTypeLedger   HardwareWalletType = "Ledger"
	WalletTypeTrezor   HardwareWalletType = "Trezor"
	WalletTypeBIP44    HardwareWalletType = "BIP44"
	WalletTypeBIP49    HardwareWalletType = "BIP49"
	WalletTypeBIP84    HardwareWalletType = "BIP84"
	WalletTypeDisk     HardwareWalletType = "DiskWallet" // Changed from WalletTypeHot
	WalletTypeCold     HardwareWalletType = "ColdWallet"
	WalletTypeSoftware HardwareWalletType = "Software"
	WalletTypeUSB      HardwareWalletType = "USB"
)

// KeyType represents the type of cryptographic key
type KeyType string

const (
	KeyTypeSPHINCSPlus KeyType = "sphincs+"
)

// StorageLocation represents where the key is stored
type StorageLocation string

const (
	StorageLocal  StorageLocation = "local"
	StorageUSB    StorageLocation = "usb"
	StorageRemote StorageLocation = "remote"
)

// KeyPair represents a stored key pair
type KeyPair struct {
	ID             string                 `json:"id"`
	EncryptedSK    []byte                 `json:"encrypted_sk"` // Encrypted secret key
	PublicKey      []byte                 `json:"public_key"`
	Address        string                 `json:"address"`
	KeyType        KeyType                `json:"key_type"`
	WalletType     HardwareWalletType     `json:"wallet_type"`
	DerivationPath string                 `json:"derivation_path,omitempty"`
	ChainID        uint64                 `json:"chain_id"`
	CreatedAt      time.Time              `json:"created_at"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// WalletInfo contains wallet metadata
type WalletInfo struct {
	ID           string             `json:"id"`
	Name         string             `json:"name"`
	WalletType   HardwareWalletType `json:"wallet_type"`
	Storage      StorageLocation    `json:"storage"`
	CreatedAt    time.Time          `json:"created_at"`
	LastAccessed time.Time          `json:"last_accessed"`
	KeyCount     int                `json:"key_count"`
}

// KeystoreConfig holds configuration for hardware wallet integration
type KeystoreConfig struct {
	mu sync.RWMutex

	// Chain-specific parameters
	ChainID       uint64
	ChainName     string
	BIP44CoinType uint32
	LedgerName    string

	// Wallet-specific derivation paths
	DerivationPaths map[HardwareWalletType]string

	// Network identification
	MagicNumber uint32
	Symbol      string
}

// StorageInterface defines the common interface for all storage types
type StorageInterface interface {
	StoreKey(keyPair *KeyPair) error
	GetKey(keyID string) (*KeyPair, error)
	GetKeyByAddress(address string) (*KeyPair, error)
	ListKeys() []*KeyPair
	RemoveKey(keyID string) error
	GetWalletInfo() *WalletInfo
	StoreEncryptedKey(encryptedSK, publicKey []byte, address string, walletType HardwareWalletType, chainID uint64, derivationPath string, metadata map[string]interface{}) (*KeyPair, error)
	EncryptData(data []byte, passphrase string) ([]byte, error)
	DecryptKey(keyPair *KeyPair, passphrase string) ([]byte, error)
}

// StorageManagerInterface defines the interface for storage management
type StorageManagerInterface interface {
	GetStorage(storageType string) StorageInterface
	MountUSB(usbPath string) error
	UnmountUSB()
	IsUSBMounted() bool
	BackupToUSB(passphrase string) error
	RestoreFromUSB(passphrase string) (int, error)
	GetStorageInfo() map[string]interface{}
}
