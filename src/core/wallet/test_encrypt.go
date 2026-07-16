// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/wallet/test_encrypt.go
package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/accounts/key"
	utils "github.com/sphinxfndorg/protocol/src/accounts/key/utils"
	seed "github.com/sphinxfndorg/protocol/src/accounts/phrase"
	"github.com/sphinxfndorg/protocol/src/core"
	sphincs "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	"github.com/sphinxfndorg/protocol/src/core/wallet/vault"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
	"golang.org/x/term"
)

// minPassphraseLen is a floor, not a strength guarantee. It exists to catch
// the obvious case (empty string, single character) — it is NOT a substitute
// for a real strength meter. If this wallet ever handles meaningful value,
// consider zxcvbn-go or similar before relying on length alone.
const minPassphraseLen = 8

// cleanse zeroes a byte slice in place so the passphrase doesn't linger in
// memory longer than necessary. Mirrors the memoryCleanse pattern already
// used in crypter.go (that helper is unexported from the crypter package,
// so this is a local equivalent rather than a cross-package reach-in).
func cleanse(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// readPassphraseMasked reads one line of input from the terminal without
// echoing it to the screen.
//
// term.ReadPassword requires an actual terminal file descriptor (os.Stdin
// must be a TTY). If stdin has been redirected (piped input, some CI/test
// harnesses, certain IDE "run" panels that don't allocate a pty), this
// falls back to a plain bufio read so the program doesn't just hang or
// error out — at the cost of the input being visible in that case.
func readPassphraseMasked(prompt string) ([]byte, error) {
	fmt.Print(prompt)

	if term.IsTerminal(int(os.Stdin.Fd())) {
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println() // ReadPassword doesn't echo the newline the user typed
		if err != nil {
			return nil, fmt.Errorf("failed to read passphrase: %w", err)
		}
		return pw, nil
	}

	// Non-TTY fallback (visible input).
	fmt.Print(" [no TTY detected, input will be visible] ")
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

// promptNewPassphrase prompts twice (entry + confirmation) for a passphrase
// used to encrypt a freshly generated key. Used on the creation path, where
// there's no recovery if the user mistypes it once and only discovers that
// on the next unlock attempt.
//
// The returned []byte is sensitive; caller MUST cleanse it once it's no
// longer needed.
func promptNewPassphrase() ([]byte, error) {
	first, err := readPassphraseMasked("Enter a new encryption passphrase: ")
	if err != nil {
		return nil, err
	}

	if len(first) < minPassphraseLen {
		cleanse(first)
		return nil, fmt.Errorf("passphrase too short: must be at least %d characters", minPassphraseLen)
	}

	second, err := readPassphraseMasked("Confirm passphrase: ")
	if err != nil {
		cleanse(first)
		return nil, err
	}

	if string(first) != string(second) {
		cleanse(first)
		cleanse(second)
		return nil, errors.New("passphrases do not match")
	}

	cleanse(second) // first is the one we return; second has served its purpose
	return first, nil
}

// promptExistingPassphrase prompts once for a passphrase used to unlock an
// already-stored key. Single entry is fine here — an incorrect guess fails
// cleanly via AES-GCM auth in DecryptKey, there's no destructive action to
// guard against the way there is on creation.
func promptExistingPassphrase() ([]byte, error) {
	pw, err := readPassphraseMasked("Enter your passphrase: ")
	if err != nil {
		return nil, err
	}
	if len(pw) == 0 {
		cleanse(pw)
		return nil, errors.New("passphrase cannot be empty")
	}
	return pw, nil
}

func main() {
	// --- 1. Initialize the real storage layer ---
	storageManager, err := utils.NewStorageManager()
	if err != nil {
		log.Fatal("Failed to initialize storage manager:", err)
	}

	diskStorage := storageManager.GetStorage(string(utils.StorageTypeDisk))

	// --- 2. Generate the SPHINCS+ key pair ---
	keyManager, err := sphincs.NewKeyManager()
	if err != nil {
		log.Fatal("Failed to initialize KeyManager:", err)
	}

	sk, pk, err := keyManager.GenerateKey()
	if err != nil {
		log.Fatal("Failed to generate SPHINCS+ keys:", err)
	}

	skBytes, err := sk.SerializeSK()
	if err != nil {
		log.Fatal("Failed to serialize SK:", err)
	}

	pkBytes, err := pk.SerializePK()
	if err != nil {
		log.Fatal("Failed to serialize PK:", err)
	}

	// --- 2.5. Generate SHA3-256 fingerprint for validation ---
	orgCode := keys.OrgSPIF
	sha3Fingerprint := vault.GetSHA3FingerprintFromBytes(pkBytes)
	fmt.Printf("SHA3-256 Fingerprint (validation): %s\n", sha3Fingerprint)

	// --- 3. Generate KEM keys (Kyber768+X25519) ---
	fmt.Println("\nGenerating KEM keys (Kyber768+X25519)...")
	kemPub, kemPriv, err := keys.GenerateKEMKeys()
	if err != nil {
		log.Fatalf("Failed to generate KEM keys: %v", err)
	}
	fmt.Printf("KEM public key size: %d bytes\n", len(kemPub))
	fmt.Printf("KEM private key size: %d bytes\n", len(kemPriv))

	// --- 4. Generate the recovery mnemonic (account root of trust) ---
	mnemonic, base32Passkey, _, _, _, _, err := seed.GenerateKeys()
	if err != nil {
		log.Fatalf("Failed to generate keys from seed: %v", err)
	}
	fmt.Println("\n=== WRITE THIS DOWN — shown only once, never stored ===")
	fmt.Printf("Mnemonic: %s\n", mnemonic)
	fmt.Printf("Base32Passkey: %s\n", base32Passkey)
	fmt.Println("========================================================")

	// --- 5. Set a separate encryption passphrase for routine unlock ---
	passphraseBytes, err := promptNewPassphrase()
	if err != nil {
		log.Fatalf("Failed to read encryption passphrase: %v", err)
	}
	defer cleanse(passphraseBytes)
	encryptionPassphrase := string(passphraseBytes)

	// --- 6. Combine SPHINCS+ private key and KEM private key ---
	combinedSK := append(skBytes, kemPriv...)
	fmt.Printf("\nCombined private key size: %d bytes\n", len(combinedSK))

	// --- 7. Encrypt the combined private key ---
	encryptedSK, err := diskStorage.EncryptData(combinedSK, encryptionPassphrase)
	if err != nil {
		log.Fatalf("Failed to encrypt combined private key: %v", err)
	}

	// --- 8. Generate SPIF address (SHAKE-256 based) ---
	address := keys.GetPublicKeyFingerprintFromBytes(pkBytes, orgCode)
	fmt.Printf("SPIF Address (SHAKE-256): %s\n", address)

	// --- 8.5. Validate fingerprints ---
	fmt.Println("\n--- Fingerprint Validation ---")

	// Validate SHA3-256 fingerprint
	if vault.ValidateFingerprint(pkBytes, sha3Fingerprint) {
		fmt.Println("SUCCESS SHA3-256 fingerprint validation passed")
	} else {
		fmt.Println("ERROR SHA3-256 fingerprint validation failed")
	}

	// Validate SPIF address fingerprint
	if vault.ValidateAddressFingerprint(pkBytes, address, orgCode) {
		fmt.Println("SUCCESS SPIF address validation passed")
	} else {
		fmt.Println("ERROR SPIF address validation failed")
	}

	// Normalize address for comparison
	normalizedAddr, err := keys.NormalizeOrgAddress(address)
	if err == nil {
		fmt.Printf("Normalized Address: %s\n", normalizedAddr)
	}

	// --- 9. Create KeyPair with KEM keys ---
	kp := &keys.KeyPair{
		PublicKey:     pkBytes,
		PrivateKey:    encryptedSK,
		OrgCode:       string(orgCode),
		Address:       address,
		KEMPublicKey:  kemPub,
		KEMPrivateKey: kemPriv,
	}

	// --- 10. Get chain header from params.go (LIGHTWEIGHT - NO BLOCKCHAIN INIT) ---
	// Directly call core.GetSphinxChainHeader() from params.go
	header := core.GetSphinxChainHeader()
	if header == nil {
		header = core.GetMainnetChainHeader()
	}

	// Convert uint64 to uint32 for BIP44 coin type
	bip44CoinType := uint32(header.BIP44CoinType)
	bip44Path := fmt.Sprintf("m/44'/%d'/0'/0/0", bip44CoinType)

	// --- 11. Generate Ledger headers metadata ---
	ledgerHeaders := map[string]interface{}{
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

	// --- 12. Create metadata with KEM and Ledger headers ---
	metadata := map[string]interface{}{
		"algorithm":            "SPHINCS+",
		"encrypted":            true,
		"storage":              "disk",
		"kem_public":           base64.StdEncoding.EncodeToString(kemPub),
		"kem_algorithm":        "Kyber768+X25519",
		"has_kem":              true,
		"ledger":               ledgerHeaders,
		"bip44_path":           bip44Path,
		"ledger_version":       "1.0",
		"sha3_fingerprint":     sha3Fingerprint,
		"fingerprint_verified": true,
	}

	// --- 13. Store the key pair with KEM and Ledger metadata ---
	storedKeyPair, err := diskStorage.StoreEncryptedKey(
		encryptedSK,
		pkBytes,
		address,
		key.WalletTypeDisk,
		7331, // Sphinx Mainnet chain ID
		"",   // derivation path
		metadata,
	)
	if err != nil {
		log.Fatalf("Failed to store key pair: %v", err)
	}
	fmt.Printf("\nStored key pair with ID: %s\n", storedKeyPair.ID)

	// --- 14. Simulate a fresh reload: fetch by ID and decrypt ---
	fmt.Println("\n--- Simulating key reload ---")
	loadedKeyPair, err := diskStorage.GetKey(storedKeyPair.ID)
	if err != nil {
		log.Fatalf("Failed to load key pair: %v", err)
	}

	unlockBytes, err := promptExistingPassphrase()
	if err != nil {
		log.Fatalf("Failed to read unlock passphrase: %v", err)
	}
	defer cleanse(unlockBytes)

	decryptedCombined, err := diskStorage.DecryptKey(loadedKeyPair, string(unlockBytes))
	if err != nil {
		log.Fatalf("Failed to decrypt secret key: %v", err)
	}
	fmt.Printf("Decrypted Combined Key size: %d bytes\n", len(decryptedCombined))

	// Extract SPHINCS+ private key (first 64 bytes)
	const sphincsKeySize = 64
	if len(decryptedCombined) < sphincsKeySize {
		log.Fatal("Decrypted key too short")
	}
	decryptedSK := decryptedCombined[:sphincsKeySize]
	decryptedKEM := decryptedCombined[sphincsKeySize:]

	fmt.Printf("SPHINCS+ private key: %x\n", decryptedSK)
	fmt.Printf("KEM private key size: %d bytes\n", len(decryptedKEM))

	// --- 15. Verify the decrypted SPHINCS+ key matches the stored public key ---
	ok, err := keyManager.VerifyPubKey(decryptedSK, loadedKeyPair.PublicKey)
	if err != nil {
		log.Fatalf("Failed to verify public key: %v", err)
	}
	if !ok {
		log.Fatal("Decrypted secret key does not match the stored public key")
	}
	fmt.Println("SUCCESS Verified: decrypted secret key matches stored public key.")

	// --- 16. Verify fingerprint from metadata ---
	fmt.Println("\n--- Metadata Fingerprint Verification ---")
	if loadedKeyPair.Metadata != nil {
		if storedFP, ok := loadedKeyPair.Metadata["sha3_fingerprint"].(string); ok {
			if vault.ValidateFingerprint(pkBytes, storedFP) {
				fmt.Println("SUCCESS Fingerprint verification from metadata passed")
			} else {
				fmt.Println("ERROR Fingerprint verification from metadata failed")
			}
		}
	}
	// --- 17. Display Ledger header example ---
	fmt.Println("\n--- Ledger Header Example ---")
	headerExample := fmt.Sprintf(
		"=== SPHINX LEDGER OPERATION ===\n"+
			"Chain: %s\n"+
			"Chain ID: %d\n"+
			"Operation: send\n"+
			"Amount: %.6f %s\n"+
			"Address: %s\n"+
			"Memo: Test transaction\n"+
			"BIP44: %s\n"+
			"Timestamp: %d\n"+
			"========================",
		header.ChainName,
		header.ChainID,
		1.0,
		header.Symbol,
		kp.Address,
		bip44Path,
		time.Now().Unix(),
	)
	fmt.Println(headerExample)

	// --- 18. Display the SPIF wallet address summary ---
	fmt.Println("\n=== SPIF WALLET SUMMARY ===")
	fmt.Printf("SPIF Address (SHAKE-256):   %s\n", address)
	fmt.Printf("SHA3-256 Fingerprint:       %s\n", sha3Fingerprint)
	fmt.Printf("Public Key:                 %x\n", pkBytes)
	fmt.Printf("Key ID:                     %s\n", storedKeyPair.ID)
	fmt.Printf("KEM Algorithm:              Kyber768+X25519\n")
	fmt.Printf("KEM Public:                 %x...\n", kemPub[:32])
	fmt.Printf("BIP44 Path:                 %s\n", bip44Path)
	fmt.Printf("Chain:                      %s (ID: %d)\n", header.ChainName, header.ChainID)
	fmt.Println("==========================")
	fmt.Println("\nIMPORTANT: Save your recovery mnemonic and passphrase safely!")
	fmt.Println("The SPIF address above is your identity address.")
	fmt.Println("The SHA3-256 fingerprint is stored in metadata for validation.")
	fmt.Println("Ledger headers are stored in the key file metadata.")
}
