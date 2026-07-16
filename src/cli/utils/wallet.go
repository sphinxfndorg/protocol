// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/wallet.go
//
// Unified wallet management: bridges the encrypted vault wallet (src/core/wallet/vault/)
// with the node's SPHINCS+ signing keys (src/accounts/key/). This is the single
// entry point for creating, importing, and managing SPIF wallets.
package utils

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/accounts/key"
	keyUtils "github.com/sphinxfndorg/protocol/src/accounts/key/utils"
	"github.com/sphinxfndorg/protocol/src/common"
	logger "github.com/sphinxfndorg/protocol/src/console"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
)

// WalletConfig holds the wallet initialization parameters
type WalletConfig struct {
	DataDir    string // Directory for storing wallet data (default: ~/.sphinx/wallet)
	Passphrase string // Passphrase to encrypt the wallet
	Network    string // Network type: mainnet, testnet, devnet
	Label      string // Human-readable label for the wallet
}

// WalletInfo holds the wallet information displayed after initialization
type WalletInfo struct {
	Address        string `json:"address"`
	PublicKeyHex   string `json:"public_key_hex"`
	Fingerprint    string `json:"fingerprint"`
	Network        string `json:"network"`
	ChainID        uint64 `json:"chain_id"`
	DerivationPath string `json:"derivation_path"`
	KeyFile        string `json:"key_file"`
	CreatedAt      string `json:"created_at"`
}

// InitWallet creates a new SPIF wallet with a SPHINCS+ key pair,
// stores the encrypted private key in the vault, and exports the
// public key for use with the node.
func InitWallet(cfg WalletConfig) (*WalletInfo, error) {
	logger.Info("Initializing SPIF wallet (network=%s, label=%s)", cfg.Network, cfg.Label)

	if cfg.Passphrase == "" {
		return nil, fmt.Errorf("passphrase is required to encrypt the wallet")
	}
	if cfg.DataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("cannot determine home directory: %w", err)
		}
		cfg.DataDir = filepath.Join(home, ".sphinx", "wallet")
	}

	// Determine chain parameters
	chainID := uint64(7331) // mainnet default
	switch cfg.Network {
	case "testnet":
		chainID = 17331
	case "devnet":
		chainID = 73310
	}

	// Create wallet directory
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create wallet directory: %w", err)
	}

	// Initialize the storage manager (same pattern as vault.go)
	storageMgr, err := keyUtils.NewStorageManager()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage manager: %w", err)
	}
	diskStorage := storageMgr.GetStorage(string(keyUtils.StorageTypeDisk))

	// Use the USI GUI pattern: generate key pair with passphrase
	// This matches src/usi/core/key/key.go GenerateKeyPairWithOrg
	orgCode := keys.OrgSPIF // Use SPIF organization code

	kp, err := keys.GenerateKeyPairWithOrg(cfg.Passphrase, orgCode)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Extract keys from the generated key pair
	pkBytes := kp.PublicKey
	skBytes := kp.PrivateKey // This is the encrypted private key
	spifAddress := kp.Address
	pubKeyHex := hex.EncodeToString(pkBytes)

	// Store the key pair (already encrypted by GenerateKeyPairWithOrg)
	derivationPath := fmt.Sprintf("m/44'/%d'/0'/0/0", chainID)
	keyPair, err := diskStorage.StoreEncryptedKey(
		skBytes,
		pkBytes,
		spifAddress,
		key.WalletTypeDisk,
		chainID,
		derivationPath,
		map[string]interface{}{
			"label":     cfg.Label,
			"network":   cfg.Network,
			"createdAt": time.Now().UTC().Format(time.RFC3339),
			"org_code":  string(orgCode),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to store encrypted key: %w", err)
	}

	// Export the key file for use with the CLI (sphinx-cli send-tx --key)
	// Note: skBytes here is the encrypted private key from GenerateKeyPairWithOrg
	keyFilePath := filepath.Join(cfg.DataDir, fmt.Sprintf("%s.key.json", spifAddress[:16]))
	keyFileData := map[string]string{
		"private_key": hex.EncodeToString(skBytes),
		"public_key":  pubKeyHex,
		"address":     spifAddress,
		"chain_id":    fmt.Sprintf("%d", chainID),
		"label":       cfg.Label,
		"created_at":  time.Now().UTC().Format(time.RFC3339),
		"org_code":    string(orgCode),
	}
	keyFileJSON, err := json.MarshalIndent(keyFileData, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key file: %w", err)
	}
	if err := os.WriteFile(keyFilePath, keyFileJSON, 0600); err != nil {
		return nil, fmt.Errorf("failed to write key file: %w", err)
	}

	// Also export a public-only key file for sharing
	pubKeyFilePath := filepath.Join(cfg.DataDir, fmt.Sprintf("%s.pub.json", spifAddress[:16]))
	pubKeyFileData := map[string]string{
		"public_key": pubKeyHex,
		"address":    spifAddress,
		"chain_id":   fmt.Sprintf("%d", chainID),
		"label":      cfg.Label,
	}
	pubKeyFileJSON, _ := json.MarshalIndent(pubKeyFileData, "", "  ")
	os.WriteFile(pubKeyFilePath, pubKeyFileJSON, 0644)

	// Create a genesis-compatible allocation entry for this wallet
	// (so the user can add it to genesis allocations)
	allocEntry := map[string]interface{}{
		"address": spifAddress,
		"label":   cfg.Label,
		"type":    "user_wallet",
	}
	allocJSON, _ := json.MarshalIndent(allocEntry, "", "  ")
	allocPath := filepath.Join(cfg.DataDir, fmt.Sprintf("%s.alloc.json", spifAddress[:16]))
	os.WriteFile(allocPath, allocJSON, 0644)

	logger.Info("Wallet created successfully!")
	logger.Info("   Address:      %s", spifAddress)
	logger.Info("   Public Key:   %s...", pubKeyHex[:32])
	logger.Info("   Key File:     %s", keyFilePath)
	logger.Info("   Public File:  %s", pubKeyFilePath)
	logger.Info("   Derivation:   %s", derivationPath)
	logger.Info("   Network:      %s (ChainID: %d)", cfg.Network, chainID)
	logger.Info("")
	logger.Info("To use this wallet with the node:")
	logger.Info("  sphinx-cli send-tx --from %s --to <RECIPIENT> --amount <AMOUNT> --key %s", spifAddress, keyFilePath)
	logger.Info("  sphinx-cli node --reward-address=%s", spifAddress)

	return &WalletInfo{
		Address:        spifAddress,
		PublicKeyHex:   pubKeyHex,
		Fingerprint:    keyPair.ID,
		Network:        cfg.Network,
		ChainID:        chainID,
		DerivationPath: derivationPath,
		KeyFile:        keyFilePath,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// ListWallets lists all wallets in the wallet directory
func ListWallets(dataDir string) ([]WalletInfo, error) {
	if dataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("cannot determine home directory: %w", err)
		}
		dataDir = filepath.Join(home, ".sphinx", "wallet")
	}

	entries, err := os.ReadDir(dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No wallets yet
		}
		return nil, fmt.Errorf("failed to read wallet directory: %w", err)
	}

	var wallets []WalletInfo
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".key.json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dataDir, entry.Name()))
		if err != nil {
			continue
		}
		var info struct {
			PublicKey string `json:"public_key"`
			Address   string `json:"address"`
			ChainID   string `json:"chain_id"`
			Label     string `json:"label"`
		}
		if err := json.Unmarshal(data, &info); err != nil {
			continue
		}

		// Validate address using common utility
		if !common.ValidateSPIFAddress(info.Address) {
			logger.Warn("Skipping invalid SPIF address in %s: %s", entry.Name(), info.Address)
			continue
		}

		wallets = append(wallets, WalletInfo{
			Address:      info.Address,
			PublicKeyHex: info.PublicKey,
			Network:      "mainnet",
			KeyFile:      filepath.Join(dataDir, entry.Name()),
		})
	}
	return wallets, nil
}

// GetBalance queries the balance of a SPIF address from a node
func GetWalletBalance(rpcURL, address string) (*big.Int, error) {
	stateDB, err := getStateDB(rpcURL)
	if err != nil {
		return nil, err
	}
	return stateDB.GetBalance(address)
}

// TransferSPX creates and sends a transfer transaction
func TransferSPX(rpcURL, from, to, amount string, nonce uint64, keyFile string) (string, error) {
	opts := SendTxOptions{
		RPCURL:   rpcURL,
		From:     from,
		To:       to,
		Amount:   amount,
		GasLimit: "21000",
		GasPrice: "1",
		Nonce:    nonce,
		KeyFile:  keyFile,
		Wait:     true,
	}
	if err := SendTransaction(opts); err != nil {
		return "", err
	}
	return "tx sent", nil
}

// stateDBClient is a client that queries balance via HTTP JSON-RPC
type stateDBClient struct {
	rpcURL string
}

// GetBalance queries the balance of an address via RPC
func (c *stateDBClient) GetBalance(address string) (*big.Int, error) {
	if address == "" {
		return nil, fmt.Errorf("address cannot be empty")
	}

	// Call spx_getBalance RPC method (returns hex string)
	var balanceHex string
	err := callRPC(c.rpcURL, "spx_getBalance", []interface{}{address, "latest"}, &balanceHex)
	if err != nil {
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}

	// Parse hex string to big.Int
	balanceHex = strings.TrimPrefix(balanceHex, "0x")
	if balanceHex == "" {
		balanceHex = "0"
	}

	balance, ok := new(big.Int).SetString(balanceHex, 16)
	if !ok {
		return nil, fmt.Errorf("invalid balance format: %s", balanceHex)
	}

	return balance, nil
}

// getStateDB creates a state DB client that queries the node via RPC
func getStateDB(rpcURL string) (interface {
	GetBalance(string) (*big.Int, error)
}, error) {
	if rpcURL == "" {
		return nil, fmt.Errorf("RPC URL is required")
	}

	// Validate RPC URL format (should be host:port)
	if !strings.Contains(rpcURL, ":") {
		return nil, fmt.Errorf("invalid RPC URL format: %s (expected host:port)", rpcURL)
	}

	return &stateDBClient{
		rpcURL: rpcURL,
	}, nil
}
