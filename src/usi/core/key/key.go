// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/key/key.go
package keys

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/accounts/key"
	utils "github.com/sphinxfndorg/protocol/src/accounts/key/utils"
	"github.com/sphinxfndorg/protocol/src/core"
	sphincs "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
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

	// Use the SPHINCS+ key manager
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

	// Generate KEM keys
	log.Println("Generating KEM keys...")
	kemPub, kemPriv, err := GenerateKEMKeys()
	if err != nil {
		return nil, fmt.Errorf("generate KEM keys: %w", err)
	}
	log.Printf("KEM keys generated: public=%d bytes, private=%d bytes", len(kemPub), len(kemPriv))

	// Combine SPHINCS+ private key and KEM private key
	combinedSK := append(skBytes, kemPriv...)
	log.Printf("Combined private key size: %d bytes", len(combinedSK))

	// Encrypt the combined private key
	encryptedSK, err := diskStorage.EncryptData(combinedSK, passphrase)
	if err != nil {
		return nil, fmt.Errorf("encrypt combined private keys: %w", err)
	}

	// Generate address from public key
	address := generateAddress(pkBytes, orgCode)

	kp := &KeyPair{
		PublicKey:     pkBytes,
		PrivateKey:    encryptedSK,
		OrgCode:       string(orgCode),
		Address:       address,
		KEMPublicKey:  kemPub,
		KEMPrivateKey: kemPriv,
	}

	// Save to disk - this creates ONLY ONE file
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
// Ledger Header Helpers
// ─────────────────────────────────────────────────────────────────────────────

// generateLedgerHeadersForKey creates Ledger header templates for a key
// Uses GetSphinxChainHeader() which is lightweight and does NOT mine blocks
func generateLedgerHeadersForKey(kp *KeyPair) map[string]interface{} {
	// Get chain header WITHOUT mining genesis block
	header := core.GetSphinxChainHeader()
	if header == nil {
		log.Println("[WARN] Failed to get chain header, using defaults")
		header = core.GetMainnetChainHeader()
	}

	// Generate BIP44 derivation path
	bip44CoinType := uint32(header.BIP44CoinType)
	bip44Path := fmt.Sprintf("m/44'/%d'/0'/0/0", bip44CoinType)

	// Return ledger configuration
	return map[string]interface{}{
		"version": "1.0",
		"bip44": map[string]interface{}{
			"path":      bip44Path,
			"coin_type": bip44CoinType,
			"purpose":   44,
			"account":   0,
			"change":    0,
			"index":     0,
		},
		"chain": map[string]interface{}{
			"id":          header.ChainID,
			"name":        header.ChainName,
			"symbol":      header.Symbol,
			"magic":       header.MagicNumber,
			"ledger_name": header.LedgerName,
		},
		"address":       kp.Address,
		"public_key":    base64.StdEncoding.EncodeToString(kp.PublicKey),
		"has_kem":       len(kp.KEMPublicKey) > 0,
		"kem_algorithm": "Kyber768+X25519",
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistence using StorageManager
// ─────────────────────────────────────────────────────────────────────────────

func saveKeyToDisk(kp *KeyPair) error {
	log.Println("Saving keypair to disk")

	if kp == nil {
		return fmt.Errorf("key pair is nil")
	}

	// Generate Ledger headers
	ledgerHeaders := generateLedgerHeadersForKey(kp)

	// Extract BIP44 path from ledger headers
	bip44Path := ""
	if bip44, ok := ledgerHeaders["bip44"].(map[string]interface{}); ok {
		if path, ok := bip44["path"].(string); ok {
			bip44Path = path
		}
	}

	// Create metadata with KEM public key and Ledger headers
	metadata := map[string]interface{}{
		"algorithm":      "SPHINCS+",
		"encrypted":      true,
		"storage":        "disk",
		"kem_public":     base64.StdEncoding.EncodeToString(kp.KEMPublicKey),
		"kem_algorithm":  "Kyber768+X25519",
		"has_kem":        true,
		"ledger":         ledgerHeaders,
		"bip44_path":     bip44Path,
		"ledger_version": "1.0",
	}

	log.Printf("Saving with KEM metadata: has_kem=%v, kem_public_size=%d",
		true, len(kp.KEMPublicKey))

	// Store the encrypted key with KEM metadata
	storedKeyPair, err := diskStorage.StoreEncryptedKey(
		kp.PrivateKey,
		kp.PublicKey,
		kp.Address,
		key.WalletTypeDisk,
		7331, // Sphinx Mainnet chain ID
		"",   // derivation path
		metadata,
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
	f, err := os.OpenFile(indexPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open key index: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(storedKeyPair.ID + "\n"); err != nil {
		return fmt.Errorf("write key index: %w", err)
	}

	log.Printf("Keypair with KEM and Ledger headers saved successfully with ID: %s", storedKeyPair.ID)
	return nil
}

// LoadKeyFromDisk loads and decrypts a key pair using StorageManager.
//
// There is no separate "which account" selector upstream of this (the GUI's
// login screen only collects a passphrase — see helper.go's
// validatePassphraseDialog and gui.go's login/unlock buttons). With multiple
// registered keys on disk, each having its own passphrase, the passphrase
// itself IS the selector. This tries every stored (non-KEM-only) key ID and
// returns the first one this passphrase actually decrypts AND verifies
// against. Previously this picked a single fixed "main" key ID up front and
// only ever tried the passphrase against that one key — so only whichever
// key happened to be selected could ever log in, and every other key's
// correct passphrase was reported as wrong.
func LoadKeyFromDisk(passphrase string) (*KeyPair, []byte, error) {
	log.Println("[INFO] LoadKeyFromDisk: loading keypair from disk")

	keyIDs, err := ListKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("list keys: %w", err)
	}
	if len(keyIDs) == 0 {
		return nil, nil, fmt.Errorf("no keys found in storage")
	}

	const sphincsPrivateKeySize = 64
	var lastErr error
	var failedKeys []string

	for _, id := range keyIDs {
		if len(id) > 4 && id[:4] == "kem_" {
			continue
		}
		log.Printf("[DEBUG] LoadKeyFromDisk: trying key ID %s", id)

		loadedKeyPair, err := diskStorage.GetKey(id)
		if err != nil {
			log.Printf("[WARN] LoadKeyFromDisk: GetKey(%s) failed: %v", id, err)
			lastErr = fmt.Errorf("load key pair %s: %w", id, err)
			failedKeys = append(failedKeys, id)
			continue
		}

		combinedSK, err := diskStorage.DecryptKey(loadedKeyPair, passphrase)
		if err != nil {
			log.Printf("[WARN] LoadKeyFromDisk: DecryptKey(%s) failed: %v", id, err)
			lastErr = fmt.Errorf("decryption failed for %s: %w", id, err)
			failedKeys = append(failedKeys, id)
			continue
		}
		log.Printf("[DEBUG] LoadKeyFromDisk: DecryptKey(%s) succeeded, combined size %d bytes", id, len(combinedSK))

		if len(combinedSK) < sphincsPrivateKeySize {
			log.Printf("[WARN] LoadKeyFromDisk: combined key too short for %s: got %d, need %d", id, len(combinedSK), sphincsPrivateKeySize)
			lastErr = fmt.Errorf("combined key too short for %s", id)
			failedKeys = append(failedKeys, id)
			zeroBytes(combinedSK)
			continue
		}

		skBytes := combinedSK[:sphincsPrivateKeySize]
		kemPrivBytes := combinedSK[sphincsPrivateKeySize:]

		ok, err := keyManager.VerifyPubKey(skBytes, loadedKeyPair.PublicKey)
		if err != nil || !ok {
			log.Printf("[WARN] LoadKeyFromDisk: VerifyPubKey(%s) failed: err=%v, ok=%v", id, err, ok)
			lastErr = fmt.Errorf("public key verification failed for %s", id)
			failedKeys = append(failedKeys, id)
			zeroBytes(skBytes)
			zeroBytes(kemPrivBytes)
			continue
		}
		log.Printf("[INFO] LoadKeyFromDisk: verification passed for %s", id)

		kp := &KeyPair{
			PublicKey:     loadedKeyPair.PublicKey,
			PrivateKey:    loadedKeyPair.EncryptedSK,
			Path:          id,
			KEMPrivateKey: kemPrivBytes,
		}

		if loadedKeyPair.Metadata != nil {
			if kemPubB64, ok := loadedKeyPair.Metadata["kem_public"].(string); ok {
				kemPub, err := base64.StdEncoding.DecodeString(kemPubB64)
				if err == nil {
					kp.KEMPublicKey = kemPub
					log.Printf("[DEBUG] LoadKeyFromDisk: KEM public key loaded from %s", id)
				}
			}
			if _, ok := loadedKeyPair.Metadata["ledger"]; ok { // SUCCESS use _ instead of ledger
				log.Printf("[DEBUG] LoadKeyFromDisk: Ledger headers loaded from %s", id)
			}
		}

		kp.OrgCode = "SPIF"
		kp.Address = GetPublicKeyFingerprint(kp)

		log.Printf("[SUCCESS] LoadKeyFromDisk: successfully loaded key %s", id)
		return kp, skBytes, nil
	}

	// Build a comprehensive error message
	errMsg := fmt.Sprintf("no stored key matched this passphrase. Attempted keys: %v", failedKeys)
	if lastErr != nil {
		errMsg += fmt.Sprintf("; last error: %v", lastErr)
	}
	log.Printf("[ERROR] LoadKeyFromDisk: %s", errMsg)
	return nil, nil, errors.New(errMsg)
}

// GetKeyByID loads a specific key by its ID (matches test_encrypt.go pattern)
func GetKeyByID(keyID, passphrase string) (*KeyPair, []byte, error) {
	log.Printf("Loading keypair by ID: %s", keyID)

	loadedKeyPair, err := diskStorage.GetKey(keyID)
	if err != nil {
		return nil, nil, fmt.Errorf("load key pair: %w", err)
	}

	// Decrypt the combined secret key
	combinedSK, err := diskStorage.DecryptKey(loadedKeyPair, passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Extract SPHINCS+ private key (first 64 bytes)
	const sphincsPrivateKeySize = 64
	if len(combinedSK) < sphincsPrivateKeySize {
		return nil, nil, fmt.Errorf("combined key too short")
	}

	skBytes := combinedSK[:sphincsPrivateKeySize]
	kemPrivBytes := combinedSK[sphincsPrivateKeySize:]

	kp := &KeyPair{
		PublicKey:     loadedKeyPair.PublicKey,
		PrivateKey:    loadedKeyPair.EncryptedSK,
		Path:          keyID,
		KEMPrivateKey: kemPrivBytes,
	}

	// Load KEM public key from metadata
	if loadedKeyPair.Metadata != nil {
		if kemPubB64, ok := loadedKeyPair.Metadata["kem_public"].(string); ok {
			kemPub, err := base64.StdEncoding.DecodeString(kemPubB64)
			if err == nil {
				kp.KEMPublicKey = kemPub
			}
		}
	}

	// Verify the SPHINCS+ private key matches the stored public key
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
	indexPath := filepath.Join(GetKeyDir(), "keyindex")
	data, err := os.ReadFile(indexPath)
	if err == nil {
		var ids []string
		for _, line := range strings.Split(string(data), "\n") {
			id := strings.TrimSpace(line)
			if id == "" {
				continue
			}
			if len(id) > 4 && id[:4] == "kem_" {
				log.Printf("[DEBUG] ListKeys: skipping KEM-only ID %s", id)
				continue
			}
			if _, err := diskStorage.GetKey(id); err == nil {
				ids = append(ids, id)
			} else {
				log.Printf("[WARN] ListKeys: diskStorage.GetKey(%s) failed, skipping: %v", id, err)
			}
		}
		if len(ids) > 0 {
			log.Printf("[INFO] ListKeys: found %d keys via keyindex", len(ids))
			return ids, nil
		}
	}

	// Fallback to scanning disk store
	log.Printf("[INFO] ListKeys: keyindex empty or not found, scanning disk store")
	return findMainKey(), nil
}

// findMainKey returns the main SPHINCS+ key ID (skipping KEM-only keys)
func findMainKey() []string {
	// Get all keys from storage manager
	// Since we can't directly list all keys, we'll use a different approach
	// Check common key patterns
	for _, id := range []string{"default", "0", "key_0"} {
		if _, err := diskStorage.GetKey(id); err == nil {
			return []string{id}
		}
	}

	// Try to find a key that is NOT a KEM key
	// This is a bit hacky but necessary with the current API
	keyDir := GetKeyDir()
	files, err := os.ReadDir(filepath.Join(keyDir, "..", "disk-keystore", "keys"))
	if err == nil {
		for _, file := range files {
			if file.IsDir() {
				continue
			}
			name := file.Name()
			if strings.HasSuffix(name, ".json") {
				id := strings.TrimSuffix(name, ".json")
				// Skip KEM-only keys
				if strings.HasPrefix(id, "kem_") {
					continue
				}
				if _, err := diskStorage.GetKey(id); err == nil {
					return []string{id}
				}
			}
		}
	}

	return []string{}
}

// GetLedgerHeaders returns the Ledger headers from a key pair's metadata
func GetLedgerHeaders(kp *KeyPair) (map[string]interface{}, error) {
	if kp == nil {
		return nil, fmt.Errorf("key pair is nil")
	}

	// Load the key from disk to get metadata
	loadedKeyPair, err := diskStorage.GetKey(kp.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	if loadedKeyPair.Metadata == nil {
		return nil, fmt.Errorf("no metadata found for key")
	}

	ledger, ok := loadedKeyPair.Metadata["ledger"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("no Ledger headers found in metadata")
	}

	return ledger, nil
}

// GenerateLedgerHeader generates a complete Ledger header for a transaction
func GenerateLedgerHeader(kp *KeyPair, operation string, amount float64, memo string) (string, error) {
	if kp == nil {
		return "", fmt.Errorf("key pair is nil")
	}

	// Get Ledger headers from metadata
	ledger, err := GetLedgerHeaders(kp)
	if err != nil {
		return "", fmt.Errorf("failed to get Ledger headers: %w", err)
	}

	// Extract BIP44 path
	bip44, ok := ledger["bip44"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("BIP44 config not found in Ledger headers")
	}
	path, ok := bip44["path"].(string)
	if !ok {
		return "", fmt.Errorf("BIP44 path not found")
	}

	// Extract chain info
	chain, ok := ledger["chain"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("chain info not found in Ledger headers")
	}
	chainName, _ := chain["name"].(string)
	chainID, _ := chain["id"].(uint64)
	symbol, _ := chain["symbol"].(string)

	// Generate the full header
	return fmt.Sprintf(
		"=== SPHINX LEDGER OPERATION ===\n"+
			"Chain: %s\n"+
			"Chain ID: %d\n"+
			"Operation: %s\n"+
			"Amount: %.6f %s\n"+
			"Address: %s\n"+
			"Memo: %s\n"+
			"BIP44: %s\n"+
			"Timestamp: %d\n"+
			"========================",
		chainName,
		chainID,
		operation,
		amount,
		symbol,
		kp.Address,
		memo,
		path,
		time.Now().Unix(),
	), nil
}
