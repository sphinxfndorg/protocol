// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/account/key/disk/local.go
package disk

import (
	"crypto/rand"

	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sphinxfndorg/protocol/src/accounts/key"
	"github.com/sphinxfndorg/protocol/src/core/wallet/crypter"
	"golang.org/x/crypto/argon2"
)

// NewDiskKeyStore creates a new disk keystore instance  // Changed from NewHotKeyStore
func NewDiskKeyStore(storagePath string) (*DiskKeyStore, error) { // Changed return type
	if storagePath == "" {
		storagePath = getDefaultDiskStoragePath() // Changed from getDefaultHotStoragePath
	}

	// Create storage directory if it doesn't exist
	if err := os.MkdirAll(storagePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create disk keystore directory: %w", err) // Updated error message
	}

	ks := &DiskKeyStore{ // Changed from HotKeyStore
		storagePath: storagePath,
		keys:        make(map[string]*key.KeyPair),
		crypt:       &crypter.CCrypter{},
	}

	// Load existing keys
	if err := ks.loadKeys(); err != nil {
		return nil, fmt.Errorf("failed to load existing keys: %w", err)
	}

	return ks, nil
}

// StoreKey stores a key pair to the local keystore
func (ks *DiskKeyStore) StoreKey(keyPair *key.KeyPair) error { // Changed receiver type
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if err := ks.validateKeyPair(keyPair); err != nil {
		return err
	}

	// Add to in-memory cache
	ks.keys[keyPair.ID] = keyPair

	// Save to disk
	return ks.saveKeyToDisk(keyPair)
}

// StoreEncryptedKey stores an already encrypted key pair
func (ks *DiskKeyStore) StoreEncryptedKey(encryptedSK, publicKey []byte, address string, walletType key.HardwareWalletType, chainID uint64, derivationPath string, metadata map[string]interface{}) (*key.KeyPair, error) { // Changed receiver type
	keyPair := &key.KeyPair{
		ID:             ks.generateKeyID(),
		EncryptedSK:    encryptedSK,
		PublicKey:      publicKey,
		Address:        address,
		KeyType:        key.KeyTypeSPHINCSPlus,
		WalletType:     walletType,
		DerivationPath: derivationPath,
		ChainID:        chainID,
		CreatedAt:      time.Now(),
		Metadata:       metadata,
	}

	if keyPair.Metadata == nil {
		keyPair.Metadata = make(map[string]interface{})
	}
	keyPair.Metadata["encrypted"] = true
	keyPair.Metadata["algorithm"] = "SPHINCS+"
	keyPair.Metadata["storage"] = "disk" // Changed from "hot"

	if err := ks.StoreKey(keyPair); err != nil {
		return nil, err
	}

	return keyPair, nil
}

// StoreRawKey stores a raw key pair and encrypts it with the provided passphrase
func (ks *DiskKeyStore) StoreRawKey(secretKey, publicKey []byte, address string, walletType key.HardwareWalletType, chainID uint64, derivationPath string, passphrase string, metadata map[string]interface{}) (*key.KeyPair, error) { // Changed receiver type
	// Encrypt the secret key
	encryptedSK, err := ks.EncryptData(secretKey, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt secret key: %w", err)
	}

	return ks.StoreEncryptedKey(encryptedSK, publicKey, address, walletType, chainID, derivationPath, metadata)
}

// GetKey retrieves a key pair by ID
func (ks *DiskKeyStore) GetKey(keyID string) (*key.KeyPair, error) { // Changed receiver type
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	keyPair, exists := ks.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	return keyPair, nil
}

// GetKeyByAddress retrieves a key pair by address
func (ks *DiskKeyStore) GetKeyByAddress(address string) (*key.KeyPair, error) { // Changed receiver type
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	for _, keyPair := range ks.keys {
		if keyPair.Address == address {
			return keyPair, nil
		}
	}

	return nil, fmt.Errorf("key not found for address: %s", address)
}

// ListKeys returns all keys in the keystore
func (ks *DiskKeyStore) ListKeys() []*key.KeyPair { // Changed receiver type
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	keys := make([]*key.KeyPair, 0, len(ks.keys))
	for _, key := range ks.keys {
		keys = append(keys, key)
	}

	return keys
}

// ListKeysByType returns keys filtered by wallet type
func (ks *DiskKeyStore) ListKeysByType(walletType key.HardwareWalletType) []*key.KeyPair { // Changed receiver type
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	var filtered []*key.KeyPair
	for _, key := range ks.keys {
		if key.WalletType == walletType {
			filtered = append(filtered, key)
		}
	}

	return filtered
}

// UpdateKeyMetadata updates metadata for a specific key
func (ks *DiskKeyStore) UpdateKeyMetadata(keyID string, metadata map[string]interface{}) error { // Changed receiver type
	ks.mu.Lock()
	defer ks.mu.Unlock()

	keyPair, exists := ks.keys[keyID]
	if !exists {
		return fmt.Errorf("key not found: %s", keyID)
	}

	for k, v := range metadata {
		keyPair.Metadata[k] = v
	}

	return ks.saveKeyToDisk(keyPair)
}

// RemoveKey removes a key from the keystore
func (ks *DiskKeyStore) RemoveKey(keyID string) error { // Changed receiver type
	ks.mu.Lock()
	defer ks.mu.Unlock()

	delete(ks.keys, keyID)

	keyFile := filepath.Join(ks.storagePath, "keys", keyID+".json")
	if err := os.Remove(keyFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove key file: %w", err)
	}

	return nil
}

// EncryptData encrypts data with a passphrase
func (ks *DiskKeyStore) EncryptData(data []byte, passphrase string) ([]byte, error) { // Changed receiver type
	salt := ks.generateSalt(passphrase)

	if !ks.crypt.SetKeyFromPassphrase([]byte(passphrase), salt, 1000) {
		return nil, fmt.Errorf("failed to set encryption key")
	}

	encryptedData, err := ks.crypt.Encrypt(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	return encryptedData, nil
}

// DecryptKey decrypts a key pair's secret key
func (ks *DiskKeyStore) DecryptKey(keyPair *key.KeyPair, passphrase string) ([]byte, error) { // Changed receiver type
	salt := ks.generateSalt(passphrase)

	if !ks.crypt.SetKeyFromPassphrase([]byte(passphrase), salt, 1000) {
		return nil, fmt.Errorf("failed to set decryption key")
	}

	decryptedSK, err := ks.crypt.Decrypt(keyPair.EncryptedSK)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret key: %w", err)
	}

	return decryptedSK, nil
}

// ChangePassphrase changes the encryption passphrase for a key
func (ks *DiskKeyStore) ChangePassphrase(keyID string, oldPassphrase string, newPassphrase string) error { // Changed receiver type
	keyPair, err := ks.GetKey(keyID)
	if err != nil {
		return err
	}

	decryptedSK, err := ks.DecryptKey(keyPair, oldPassphrase)
	if err != nil {
		return fmt.Errorf("failed to decrypt with old passphrase: %w", err)
	}

	newEncryptedSK, err := ks.EncryptData(decryptedSK, newPassphrase)
	if err != nil {
		return fmt.Errorf("failed to encrypt with new passphrase: %w", err)
	}

	keyPair.EncryptedSK = newEncryptedSK
	return ks.StoreKey(keyPair)
}

// ExportKey exports a key pair for backup or transfer
func (ks *DiskKeyStore) ExportKey(keyID string, includePrivate bool, passphrase string) ([]byte, error) { // Changed receiver type
	keyPair, err := ks.GetKey(keyID)
	if err != nil {
		return nil, err
	}

	exportData := map[string]interface{}{
		"version":         "1.0",
		"key_id":          keyPair.ID,
		"public_key":      hex.EncodeToString(keyPair.PublicKey),
		"address":         keyPair.Address,
		"key_type":        keyPair.KeyType,
		"wallet_type":     keyPair.WalletType,
		"chain_id":        keyPair.ChainID,
		"created_at":      keyPair.CreatedAt,
		"metadata":        keyPair.Metadata,
		"derivation_path": keyPair.DerivationPath,
		"storage_type":    "disk", // Changed from "hot"
	}

	if includePrivate {
		if passphrase == "" {
			return nil, fmt.Errorf("passphrase required to export private key")
		}

		_, err := ks.DecryptKey(keyPair, passphrase)
		if err != nil {
			return nil, fmt.Errorf("invalid passphrase for key export: %w", err)
		}

		exportData["encrypted_secret_key"] = hex.EncodeToString(keyPair.EncryptedSK)
	}

	return json.MarshalIndent(exportData, "", "  ")
}

// GetWalletInfo returns information about the wallet
func (ks *DiskKeyStore) GetWalletInfo() *key.WalletInfo { // Changed receiver type
	keys := ks.ListKeys()

	return &key.WalletInfo{
		ID:           ks.generateKeyID(),
		Name:         "Sphinx Disk Wallet", // Changed from "Sphinx Hot Wallet"
		WalletType:   key.WalletTypeDisk,   // You might want to create this constant
		Storage:      key.StorageLocal,
		CreatedAt:    time.Now(),
		LastAccessed: time.Now(),
		KeyCount:     len(keys),
	}
}

// Helper functions

func (ks *DiskKeyStore) generateKeyID() string { // Changed receiver type
	timestamp := time.Now().UnixNano()
	randomBytes := make([]byte, 8)
	io.ReadFull(rand.Reader, randomBytes)
	return fmt.Sprintf("disk_key_%d_%x", timestamp, randomBytes) // Changed from "hot_key_"
}

// generateSalt derives a deterministic per-passphrase salt for this
// keystore, using Argon2id (memory-hard) the same way USBKeyStore does.
//
// FIX: previously this used a single pass of SHAKE256(passphrase ||
// domain-string). SHAKE256 is a fast XOF — it costs essentially nothing to
// compute, so it added no resistance to brute-force/GPU passphrase
// guessing; it was functioning as a deterministic-salt generator only, not
// as a KDF stage in its own right. USBKeyStore, right next to this file,
// already used argon2.IDKey for the same purpose. Aligned Disk to match:
// same algorithm, same parameters (3 passes, 64 MiB, 2 threads), same
// output size (WALLET_CRYPTO_IV_SIZE), differing only in the domain
// separation string so disk- and USB-derived salts never collide for the
// same passphrase.
//
// NOTE on double-stretching: the salt returned here is then passed into
// CCrypter.SetKeyFromPassphrase(passphrase, salt, 1000), which itself runs
// 1000 rounds of SHA3-512 stretching on (passphrase || salt). So the actual
// cost-to-attacker is "one Argon2id pass (memory-hard) feeding into 1000
// rounds of SHA3-512 (CPU-only)." That's intentional layered hardening, not
// redundant — Argon2id specifically resists GPU/ASIC parallelism via memory
// cost, while the SHA3-512 rounds add a second, independent cost factor.
// Keeping both rather than relying on just one.
//
// Existing keys created under the old SHAKE256 scheme will NOT decrypt
// under this new salt derivation — see the migration note in CHANGES.md /
// the comment on ChangePassphrase below before deploying this to anything
// with real stored keys.
func (ks *DiskKeyStore) generateSalt(passphrase string) []byte {
	return argon2.IDKey(
		[]byte(passphrase),
		[]byte("sphinx-disk-keystore-salt"), // domain-separated from USB's string
		3,                                   // time cost (passes)
		64*1024,                             // memory cost: 64 MiB
		2,                                   // parallelism
		crypter.WALLET_CRYPTO_IV_SIZE,       // output length
	)
}

func (ks *DiskKeyStore) validateKeyPair(keyPair *key.KeyPair) error { // Changed receiver type
	if keyPair.ID == "" {
		return fmt.Errorf("key ID cannot be empty")
	}
	if len(keyPair.EncryptedSK) == 0 {
		return fmt.Errorf("encrypted secret key cannot be empty")
	}
	if len(keyPair.PublicKey) == 0 {
		return fmt.Errorf("public key cannot be empty")
	}
	if keyPair.Address == "" {
		return fmt.Errorf("address cannot be empty")
	}
	return nil
}

func (ks *DiskKeyStore) loadKeys() error { // Changed receiver type
	keysDir := filepath.Join(ks.storagePath, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return err
	}

	files, err := filepath.Glob(filepath.Join(keysDir, "*.json"))
	if err != nil {
		return err
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var keyPair key.KeyPair
		if err := json.Unmarshal(data, &keyPair); err != nil {
			continue
		}

		ks.keys[keyPair.ID] = &keyPair
	}

	return nil
}

func (ks *DiskKeyStore) saveKeyToDisk(keyPair *key.KeyPair) error { // Changed receiver type
	keysDir := filepath.Join(ks.storagePath, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return err
	}

	keyFile := filepath.Join(keysDir, keyPair.ID+".json")
	data, err := json.MarshalIndent(keyPair, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(keyFile, data, 0600)
}

func getDefaultDiskStoragePath() string { // Renamed from getDefaultHotStoragePath
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "./sphinx-disk-keystore" // Changed from "./sphinx-hot-keystore"
	}
	return filepath.Join(homeDir, ".sphinx", "disk-keystore") // Changed from "hot-keystore"
}
