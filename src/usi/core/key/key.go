// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/key/key.go
package keys

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/sphinxorg/protocol/src/accounts/key"
	utils "github.com/sphinxorg/protocol/src/accounts/key/utils"
	sphincs "github.com/sphinxorg/protocol/src/core/sthincs/key/backend"
)

// StorageManager is a global storage manager instance
var storageManager *utils.StorageManager
var diskStorage key.StorageInterface
var keyManager *sphincs.KeyManager

// GetKeyManager returns the global SPHINCS+ key manager
func GetKeyManager() *sphincs.KeyManager {
	return keyManager
}

func init() {
	var err error
	storageManager, err = utils.NewStorageManager()
	if err != nil {
		log.Printf("Failed to initialize storage manager: %v", err)
		return
	}
	diskStorage = storageManager.GetStorage(string(utils.StorageTypeDisk))

	// Initialize the SPHINCS+ key manager (matches test_encrypt.go pattern)
	keyManager, err = sphincs.NewKeyManager()
	if err != nil {
		log.Printf("Failed to initialize KeyManager: %v", err)
	}
}

// GetKeyDir returns the key directory path for UI display
func GetKeyDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	return filepath.Join(homeDir, ".sphinx", "keys")
}

// GenerateKeyPairWithOrg is the primary entry point for the registration flow.
// The orgCode is persisted and used to format all future addresses.
func GenerateKeyPairWithOrg(passphrase string, orgCode OrgCode) (*KeyPair, error) {
	log.Printf("Generating SPHINCS+ keypair for org %q", orgCode)

	if !IsValidOrgCode(string(orgCode)) {
		return nil, fmt.Errorf("unsupported organisation code: %q", orgCode)
	}

	// Use the SPHINCS+ key manager (matches test_encrypt.go pattern)
	sk, pk, err := keyManager.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate keys: %w", err)
	}
	log.Println("SPHINCS+ key pair generated successfully")

	pkBytes, err := pk.SerializePK()
	if err != nil {
		return nil, fmt.Errorf("serialize public key: %w", err)
	}
	skBytes, err := sk.SerializeSK()
	if err != nil {
		return nil, fmt.Errorf("serialize private key: %w", err)
	}

	// Use diskStorage.EncryptData (matches test_encrypt.go pattern)
	encryptedSK, err := diskStorage.EncryptData(skBytes, passphrase)
	if err != nil {
		return nil, fmt.Errorf("encrypt private key: %w", err)
	}

	// Generate address from public key
	address := generateAddress(pkBytes, orgCode)

	kp := &KeyPair{
		PublicKey:  pkBytes,
		PrivateKey: encryptedSK,
		OrgCode:    string(orgCode),
		Address:    address,
	}

	if err := saveKeyToDisk(kp); err != nil {
		return nil, fmt.Errorf("save key pair: %w", err)
	}

	return kp, nil
}

// generateAddress creates an address from public key and org code
func generateAddress(pkBytes []byte, orgCode OrgCode) string {
	raw := SHAKE256HashWithOrg(pkBytes, orgCode)
	return FormatOrgAddress(raw, orgCode)
}

// GetPublicKeyFingerprint generates a SHAKE256-based address using the
// organisation code stored in the KeyPair.
func GetPublicKeyFingerprint(kp *KeyPair) string {
	log.Println("Generating public key address")

	if kp.OrgCode != "" && IsValidOrgCode(kp.OrgCode) {
		code := OrgCode(kp.OrgCode)
		raw := SHAKE256HashWithOrg(kp.PublicKey, code)
		formatted := FormatOrgAddress(raw, code)
		log.Printf("Address generated with org prefix %q", kp.OrgCode)
		return formatted
	}

	// Default to SPIF if no org code is set
	log.Println("No org code set; using SPIF format")
	code := OrgCode("SPIF")
	raw := SHAKE256HashWithOrg(kp.PublicKey, code)
	formatted := FormatOrgAddress(raw, code)
	return formatted
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistence using StorageManager (matches test_encrypt.go pattern)
// ─────────────────────────────────────────────────────────────────────────────

func saveKeyToDisk(kp *KeyPair) error {
	log.Println("Saving keypair to disk")

	// Store the encrypted key using diskStorage.StoreEncryptedKey
	// This matches the pattern in test_encrypt.go
	storedKeyPair, err := diskStorage.StoreEncryptedKey(
		kp.PrivateKey,
		kp.PublicKey,
		kp.Address,
		key.WalletTypeDisk,
		7331, // Sphinx Mainnet chain ID
		"",   // derivation path
		nil,  // additional data
	)
	if err != nil {
		return fmt.Errorf("store encrypted key: %w", err)
	}

	kp.Path = storedKeyPair.ID

	// Persist the dynamic key ID so ListKeys can find it on next run.
	indexPath := filepath.Join(GetKeyDir(), "keyindex")
	if err := os.MkdirAll(GetKeyDir(), 0700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	if err := os.WriteFile(indexPath, []byte(storedKeyPair.ID), 0600); err != nil {
		return fmt.Errorf("write key index: %w", err)
	}

	log.Printf("Keypair saved successfully with ID: %s", storedKeyPair.ID)
	return nil
}

// LoadKeyFromDisk loads and decrypts the key pair using StorageManager.
// This follows the test_encrypt.go pattern for loading keys.
func LoadKeyFromDisk(passphrase string) (*KeyPair, []byte, error) {
	log.Println("Loading keypair from disk")

	// Get all key IDs from storage
	keyIDs, err := ListKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("list keys: %w", err)
	}

	if len(keyIDs) == 0 {
		return nil, nil, fmt.Errorf("no keys found in storage")
	}

	// Load the first key found (similar to test_encrypt.go pattern)
	keyID := keyIDs[0]
	loadedKeyPair, err := diskStorage.GetKey(keyID)
	if err != nil {
		return nil, nil, fmt.Errorf("load key pair: %w", err)
	}

	kp := &KeyPair{
		PublicKey:  loadedKeyPair.PublicKey,
		PrivateKey: loadedKeyPair.EncryptedSK,
		Path:       keyID,
	}

	// Decrypt the secret key using diskStorage.DecryptKey (matches test_encrypt.go)
	skBytes, err := diskStorage.DecryptKey(loadedKeyPair, passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("decryption failed (wrong passphrase or corrupted key): %w", err)
	}

	// Verify the decrypted secret matches the stored public key
	// This matches test_encrypt.go step 7
	ok, err := keyManager.VerifyPubKey(skBytes, loadedKeyPair.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("verify public key: %w", err)
	}
	if !ok {
		return nil, nil, fmt.Errorf("decrypted secret key does not match the stored public key")
	}

	// Generate address from public key
	kp.OrgCode = "SPIF"
	kp.Address = GetPublicKeyFingerprint(kp)

	log.Printf("Keypair loaded successfully")
	return kp, skBytes, nil
}

// GetKeyByID loads a specific key by its ID (matches test_encrypt.go pattern)
func GetKeyByID(keyID, passphrase string) (*KeyPair, []byte, error) {
	log.Printf("Loading keypair by ID: %s", keyID)

	loadedKeyPair, err := diskStorage.GetKey(keyID)
	if err != nil {
		return nil, nil, fmt.Errorf("load key pair: %w", err)
	}

	kp := &KeyPair{
		PublicKey:  loadedKeyPair.PublicKey,
		PrivateKey: loadedKeyPair.EncryptedSK,
		Path:       keyID,
	}

	// Decrypt the secret key using diskStorage.DecryptKey
	skBytes, err := diskStorage.DecryptKey(loadedKeyPair, passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Verify the decrypted secret matches the stored public key
	ok, err := keyManager.VerifyPubKey(skBytes, loadedKeyPair.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("verify public key: %w", err)
	}
	if !ok {
		return nil, nil, fmt.Errorf("decrypted secret key does not match the stored public key")
	}

	kp.Address = GetPublicKeyFingerprint(kp)

	return kp, skBytes, nil
}

// ListKeys lists all stored key IDs
// This follows the StorageManager pattern
func ListKeys() ([]string, error) {
	// Read the key ID written by saveKeyToDisk at registration time.
	indexPath := filepath.Join(GetKeyDir(), "keyindex")
	data, err := os.ReadFile(indexPath)
	if err == nil {
		id := string(data)
		if id != "" {
			// Verify the key actually exists in storage before returning.
			if _, err := diskStorage.GetKey(id); err == nil {
				return []string{id}, nil
			}
		}
	}

	// Fallback: probe legacy hardcoded IDs (pre-index registrations).
	for _, id := range []string{"default", "0", "key_0"} {
		if _, err := diskStorage.GetKey(id); err == nil {
			return []string{id}, nil
		}
	}

	return []string{}, nil
}
