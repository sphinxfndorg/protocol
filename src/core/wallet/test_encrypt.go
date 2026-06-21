// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/wallet/tesst_encrypt.go
package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/sphinxorg/protocol/src/accounts/key"
	utils "github.com/sphinxorg/protocol/src/accounts/key/utils"
	seed "github.com/sphinxorg/protocol/src/accounts/phrase"
	sphincs "github.com/sphinxorg/protocol/src/core/sthincs/key/backend"
	keys "github.com/sphinxorg/protocol/src/usi/core/key"
	"golang.org/x/crypto/sha3"
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

// getFingerprintFromBytes computes the SHA3-256 fingerprint from public key bytes.
// This matches the implementation in keys.GetPublicKeyFingerprint but works with raw bytes.
func getFingerprintFromBytes(pubKeyBytes []byte) string {
	hasher := sha3.New256()
	hasher.Write(pubKeyBytes)
	return hex.EncodeToString(hasher.Sum(nil))
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
		log.Fatal("Failed to generate keys:", err)
	}

	skBytes, err := sk.SerializeSK()
	if err != nil {
		log.Fatal("Failed to serialize SK:", err)
	}

	pkBytes, err := pk.SerializePK()
	if err != nil {
		log.Fatal("Failed to serialize PK:", err)
	}

	// --- 3. Generate the recovery mnemonic (account root of trust) ---
	// Shown once. The wallet itself must NOT persist this — only the user's
	// physical record of it should survive past this point. This is your
	// own SIPS-0003 mnemonic system (seed.GenerateKeys -> sips3.NewMnemonic),
	// untouched here.
	mnemonic, base32Passkey, _, _, _, _, err := seed.GenerateKeys()
	if err != nil {
		log.Fatalf("Failed to generate keys from seed: %v", err)
	}
	fmt.Println("=== WRITE THIS DOWN — shown only once, never stored ===")
	fmt.Printf("Mnemonic: %s\n", mnemonic)
	fmt.Printf("Base32Passkey: %s\n", base32Passkey)
	fmt.Println("========================================================")

	// --- 4. Set a separate encryption passphrase for routine unlock ---
	passphraseBytes, err := promptNewPassphrase()
	if err != nil {
		log.Fatalf("Failed to read encryption passphrase: %v", err)
	}
	defer cleanse(passphraseBytes)
	encryptionPassphrase := string(passphraseBytes)

	// --- 5. Encrypt + store the key pair via the real keystore API ---
	// Generate the SPIF address and fingerprint from the public key bytes
	// This matches the vault package's address derivation pattern
	fingerprint := getFingerprintFromBytes(pkBytes)

	// Normalize the fingerprint (remove spaces, etc.) to match vault format
	normalizedFingerprint, err := keys.NormalizeOrgAddress(fingerprint)
	if err != nil {
		log.Fatalf("Failed to normalize fingerprint: %v", err)
	}

	// Format as SPIF address (matches vault package pattern)
	// In vault.go, addresses are stored as "SPIF" + hex(SHA3-256(public_key))
	spifAddress := "SPIF" + normalizedFingerprint

	fmt.Printf("SPIF Address: %s\n", spifAddress)
	fmt.Printf("Fingerprint: %s\n", normalizedFingerprint)

	derivationPath := "" // fill in if/when this wallet supports HD derivation

	encryptedSK, err := diskStorage.EncryptData(skBytes, encryptionPassphrase)
	if err != nil {
		log.Fatalf("Failed to encrypt secret key: %v", err)
	}

	storedKeyPair, err := diskStorage.StoreEncryptedKey(
		encryptedSK,
		pkBytes,
		spifAddress, // Use the SPIF address as the key ID
		key.WalletTypeDisk,
		7331, // Sphinx Mainnet chain ID, per keystore.go's GetMainnetKeystoreConfig
		derivationPath,
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to store key pair: %v", err)
	}
	fmt.Printf("Stored key pair with ID: %s\n", storedKeyPair.ID)
	fmt.Printf("Stored Encrypted Secret Key: %x\n", storedKeyPair.EncryptedSK)

	// --- 6. Simulate a fresh reload: fetch by ID and decrypt ---
	loadedKeyPair, err := diskStorage.GetKey(storedKeyPair.ID)
	if err != nil {
		log.Fatalf("Failed to load key pair: %v", err)
	}

	unlockBytes, err := promptExistingPassphrase()
	if err != nil {
		log.Fatalf("Failed to read unlock passphrase: %v", err)
	}
	defer cleanse(unlockBytes)

	decryptedSecretKey, err := diskStorage.DecryptKey(loadedKeyPair, string(unlockBytes))
	if err != nil {
		log.Fatalf("Failed to decrypt secret key: %v", err)
	}
	fmt.Printf("Decrypted Secret Key: %x\n", decryptedSecretKey)

	// --- 7. Verify the decrypted secret matches the stored public key ---
	ok, err := keyManager.VerifyPubKey(decryptedSecretKey, loadedKeyPair.PublicKey)
	if err != nil {
		log.Fatalf("Failed to verify public key: %v", err)
	}
	if !ok {
		log.Fatal("Decrypted secret key does not match the stored public key")
	}
	fmt.Println("Verified: decrypted secret key matches stored public key.")

	// --- 8. Display the SPIF wallet address summary ---
	fmt.Println("\n=== SPIF WALLET SUMMARY ===")
	fmt.Printf("SPIF Address:   %s\n", spifAddress)
	fmt.Printf("Fingerprint:    %s\n", normalizedFingerprint)
	fmt.Printf("Public Key:     %x\n", pkBytes)
	fmt.Printf("Key ID:         %s\n", storedKeyPair.ID)
	fmt.Println("==========================")
	fmt.Println("\nIMPORTANT: Save your recovery mnemonic and passphrase safely!")
	fmt.Println("The SPIF address above is your wallet address for receiving funds.")
}
