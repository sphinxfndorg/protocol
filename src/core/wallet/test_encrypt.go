// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/wallet/tesst_encrypt.go
package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/sphinxorg/protocol/src/accounts/key"
	utils "github.com/sphinxorg/protocol/src/accounts/key/utils"
	seed "github.com/sphinxorg/protocol/src/accounts/phrase"
	sphincs "github.com/sphinxorg/protocol/src/core/sthincs/key/backend"
	"golang.org/x/term"
)

// CHANGE FROM ORIGINAL: the previous version of this file talked to
// `config.NewWalletConfig()` / `walletConfig.SaveKeyPair(...)` /
// `walletConfig.LoadKeyPair()` — a LevelDB-backed API that doesn't exist
// anywhere in src/accounts/key/*. It also hand-rolled its own salt
// derivation (the bug from earlier in this conversation: random salt,
// generated independently on encrypt vs decrypt, never persisted).
//
// This version routes everything through `utils.StorageManager` /
// `disk.DiskKeyStore`, which is the real account-setup layer already
// present in this codebase (see local.go / usb.go / keystore.go /
// utils.go). That layer solves salt persistence differently and more
// simply than what we discussed earlier: DiskKeyStore.generateSalt derives
// the salt deterministically from the passphrase itself (now via Argon2id —
// see the fix in local.go), so there is nothing to lose between encrypt and
// decrypt calls. No salt needs to be stored or threaded through at all.
//
// Two secrets are still kept conceptually separate, matching how production
// wallets (Bitcoin Core / Electrum / MetaMask-style HD wallets) do this:
//   - the SIPS-0003 mnemonic from seed.GenerateKeys() (this codebase's own
//     mnemonic/word-list system, src/accounts/mnemonic + src/accounts/phrase)
//     is the wallet's root of trust — shown once, written down by the user,
//     never stored.
//   - a separate `passphrase` (encryption password) is what's actually fed
//     into DiskKeyStore.EncryptData/DecryptKey for routine unlock. Reusing
//     the mnemonic itself as that password is possible but means anyone who
//     ever sees the unlock prompt has effectively seen the recovery phrase
//     too — most wallets avoid that by keeping a shorter, separate password.
//
// NOTE: key.NewKeyManager()/GenerateKey()/SerializeSK()/SerializePK() come
// from src/core/sthincs/key/backend, which is not among the files you've
// shared — I'm keeping its usage as a black box (same call shape as your
// original main.go) since I don't have its source to verify against.

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
	// CHANGE FROM ORIGINAL: the previous version derived the AES key
	// straight from the mnemonic (`passphrase`) via a hand-built salt. Now
	// DiskKeyStore.EncryptData takes a passphrase directly and derives its
	// own salt deterministically (Argon2id) internally — see local.go.
	//
	// CHANGE: was previously hardcoded as a placeholder string. Now reads
	// from a masked terminal prompt, defined directly above in this file —
	// entered twice with confirmation, since this is the creation path.
	// passphraseBytes is sensitive and is cleansed via defer right after
	// it's done being used.
	passphraseBytes, err := promptNewPassphrase()
	if err != nil {
		log.Fatalf("Failed to read encryption passphrase: %v", err)
	}
	defer cleanse(passphraseBytes)
	encryptionPassphrase := string(passphraseBytes)

	// --- 5. Encrypt + store the key pair via the real keystore API ---
	address := fmt.Sprintf("%x", pkBytes[:20]) // placeholder address derivation;
	// replace with your real address scheme (e.g. hash of pkBytes per your
	// chain's address format) — using a raw prefix slice here only so this
	// file compiles end-to-end; it is NOT a real address derivation.

	derivationPath := "" // fill in if/when this wallet supports HD derivation

	// CHANGE FROM ORIGINAL DRAFT: DiskKeyStore.StoreRawKey is a convenience
	// method that does exactly EncryptData + StoreEncryptedKey internally,
	// but it isn't part of key.StorageInterface — only EncryptData and
	// StoreEncryptedKey are. Calling StoreRawKey here would have required
	// a type assertion back to *disk.DiskKeyStore (or importing the disk
	// package directly), defeating the point of coding against
	// StorageInterface in the first place. Calling the two interface
	// methods directly instead keeps this working identically against
	// whatever GetStorage(...) returns — disk or USB — with no assertion.
	encryptedSK, err := diskStorage.EncryptData(skBytes, encryptionPassphrase)
	if err != nil {
		log.Fatalf("Failed to encrypt secret key: %v", err)
	}

	storedKeyPair, err := diskStorage.StoreEncryptedKey(
		encryptedSK,
		pkBytes,
		address,
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
	// This proves the round trip works without relying on any in-memory
	// state from steps above — generateSalt re-derives identically from the
	// passphrase alone, with nothing extra needing to be persisted or
	// threaded through.
	//
	// CHANGE: previously reused the same in-memory `encryptionPassphrase`
	// variable from step 4 for the decrypt call. That's not actually
	// testing a "fresh reload" — a real reload happens in a new process
	// invocation where nothing from step 4 is in scope, and the user must
	// re-enter their passphrase. Prompting again here (single entry) makes
	// this step test what it claims to.
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
	// CHANGE: this step didn't exist before. The original crypter.go had a
	// VerifyPubKey placeholder (bytes.Equal(secret, pubKey)) that could
	// never actually pass for real SPHINCS+ keys — and this file never
	// called it anyway, so a successful decrypt was treated as sufficient
	// proof of correctness. It isn't: AES-GCM decrypting successfully only
	// proves the passphrase was right and the ciphertext wasn't tampered
	// with — it says nothing about whether the resulting key material is
	// the SPHINCS+ keypair you think it is (e.g. after a storage bug, a
	// migration, or a corrupted-but-still-GCM-valid record).
	//
	// keyManager already exists in scope from step 2 with the right
	// Params for this — no new initialization needed, just using it.
	ok, err := keyManager.VerifyPubKey(decryptedSecretKey, loadedKeyPair.PublicKey)
	if err != nil {
		log.Fatalf("Failed to verify public key: %v", err)
	}
	if !ok {
		log.Fatal("Decrypted secret key does not match the stored public key")
	}
	fmt.Println("Verified: decrypted secret key matches stored public key.")
}
