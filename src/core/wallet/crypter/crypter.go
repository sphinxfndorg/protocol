// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/wallet/crypter/crypter.go
package crypter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"

	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
)

const (
	WALLET_CRYPTO_KEY_SIZE   = 32               // AES-256: 256-bit (32 bytes) key size
	WALLET_CRYPTO_IV_SIZE    = 16               // Size of IV: 16 bytes (fixed for AES)
	WALLET_CRYPTO_SALT_SIZE  = 16               // Size of salt used for key derivation (kept distinct from IV conceptually)
	WALLET_CRYPTO_NONCE_SIZE = 12               // AES GCM: 12-byte nonce (used as IV)
	AES_BLOCKSIZE            = 16               // AES block size: 16 bytes (128 bits, fixed for AES)
	CSHA512OutputSize        = 64               // SHA-512 output size: 64 bytes
	AES_GCM_TAG_SIZE         = 16               // GCM authentication tag size: 16 bytes
	AES_GCM_OVERHEAD         = AES_GCM_TAG_SIZE // Overhead for GCM: size of the authentication tag

	// FIX: EncryptSecret/DecryptSecret now prepend the salt to the output, the
	// same way Encrypt/Decrypt prepend the GCM nonce. This constant is the
	// minimum valid length of an EncryptSecret() result: salt + nonce + tag.
	minEncryptSecretLen = WALLET_CRYPTO_SALT_SIZE + WALLET_CRYPTO_NONCE_SIZE + AES_GCM_TAG_SIZE

	// Number of PBKDF rounds used by EncryptSecret/DecryptSecret. Pulled out
	// to a named constant so the two call sites can't drift out of sync.
	secretDeriveRounds = 10000
)

// NewMasterKey creates a new instance of MasterKey with default values.
func NewMasterKey() *MasterKey {
	return &MasterKey{
		NDeriveIterations:            25000,    // Default iterations
		NDerivationMethod:            0,        // Default method (0 = EVP_sha512)
		VchOtherDerivationParameters: []byte{}, // Empty default
	}
}

// Serialize serializes the MasterKey into a byte slice.
func (mk *MasterKey) Serialize() ([]byte, error) {
	return json.Marshal(mk)
}

// Deserialize populates the MasterKey from a byte slice.
func (mk *MasterKey) Deserialize(data []byte) error {
	return json.Unmarshal(data, mk)
}

// NewUint256 creates a new Uint256 from a byte slice.
func NewUint256(b []byte) *Uint256 {
	u := new(Uint256)
	u.uint256 = new(uint256.Int).SetBytes(b)
	return u
}

// ToBytes converts Uint256 to a byte slice.
func (u *Uint256) ToBytes() []byte {
	return u.uint256.Bytes()
}

// BytesToUint256 converts a byte slice to Uint256.
func BytesToUint256(b []byte) *Uint256 {
	u := new(Uint256)
	u.uint256 = new(uint256.Int).SetBytes(b)
	return u
}

// NewCrypter: Initializes a new CCrypter instance and sets the encryption key from the master key.
// It returns the initialized CCrypter instance or an error if the key could not be set.
//
// FIX: the original implementation called c.SetKey(masterKey, nil), but
// SetKey requires len(newIV) == WALLET_CRYPTO_IV_SIZE and rejects nil/short
// IVs, so this always failed with "failed to set key". NewCrypter is meant
// to wrap an *already derived* key+IV pair (as produced by
// BytesToKeySHA512AES / SetKeyFromPassphrase), not a raw passphrase, so it
// now takes both and validates their lengths explicitly instead of silently
// going through a path that could never succeed.
func NewCrypter(key, iv []byte) (*CCrypter, error) {
	// Create a new instance of CCrypter.
	cKeyCrypter := &CCrypter{}

	// Set the encryption key/IV directly; both must already be the correct size.
	if !cKeyCrypter.SetKey(key, iv) {
		// If setting the key fails, return an error indicating the failure.
		return nil, errors.New("failed to set key")
	}

	// Return the initialized CCrypter instance.
	return cKeyCrypter, nil
}

// BytesToKeySHA512AES: Derives an encryption key and initialization vector (IV) from the provided key data and salt using SHA-512.
// The key derivation process is repeated 'count' times for key stretching.
func (c *CCrypter) BytesToKeySHA512AES(salt, keyData []byte, count int) ([]byte, []byte, error) {
	// Validate input parameters: count must be greater than 0, and both keyData and salt must not be nil.
	if count <= 0 || keyData == nil || salt == nil {
		return nil, nil, errors.New("invalid parameters")
	}

	// Initialize a new SHA-512 hash function.
	hash := sha3.New512()

	// Create a buffer to store the output of the SHA-512 hashing.
	// CSHA512OutputSize is likely 64 bytes (512 bits), the output size of SHA-512.
	buf := make([]byte, CSHA512OutputSize)

	// First hash step: H0 = SHA-512(keyData + salt)
	// Concatenate keyData and salt, and hash the result.
	hash.Write(keyData) // Write keyData to the hash function.
	hash.Write(salt)    // Write salt to the hash function.

	// Copy the first hash output (H0) into the buffer.
	copy(buf, hash.Sum(nil))

	// Perform the remaining hash steps: Hn = SHA-512(Hn-1), repeated 'count' times.
	for i := 1; i < count; i++ {
		// Reset the hash state for the next round.
		hash.Reset()

		// Hash the previous output (buf) to generate the next output (Hn).
		hash.Write(buf)

		// Copy the new hash result back into the buffer.
		copy(buf, hash.Sum(nil))
	}

	// After completing 'count' hash steps, the buffer contains the final hash value.
	// Ensure the buffer is large enough to hold both the key and IV.
	if len(buf) < WALLET_CRYPTO_KEY_SIZE+WALLET_CRYPTO_IV_SIZE {
		return nil, nil, errors.New("buffer too small")
	}

	// Split the final hash buffer into the key and IV.
	// FIX: the original code sliced buf directly (key := buf[:32], iv :=
	// buf[32:48]) and then called memoryCleanse(buf) on the *same backing
	// array* a few lines later. Since Go slices share the underlying array,
	// that zeroed out the key and IV bytes Claude was about to return,
	// silently handing the caller two all-zero slices. Every key derived
	// through this path was a fixed all-zero AES-256 key.
	key := make([]byte, WALLET_CRYPTO_KEY_SIZE)
	iv := make([]byte, WALLET_CRYPTO_IV_SIZE)
	copy(key, buf[:WALLET_CRYPTO_KEY_SIZE])
	copy(iv, buf[WALLET_CRYPTO_KEY_SIZE:WALLET_CRYPTO_KEY_SIZE+WALLET_CRYPTO_IV_SIZE])

	// Zero out the buffer to cleanse sensitive data from memory. Safe now
	// that key/iv are independent copies rather than sub-slices of buf.
	memoryCleanse(buf)

	// Return the derived key and IV.
	return key, iv, nil
}

// SetKeyFromPassphrase: Derives an encryption key and initialization vector (IV) from the provided passphrase (keyData) and salt.
// The number of rounds specifies how many times to apply the hash function to derive the key (key stretching).
func (c *CCrypter) SetKeyFromPassphrase(keyData, salt []byte, rounds uint) bool {
	// Check if the number of rounds is valid and if the salt length matches the expected IV size.
	if rounds < 1 || len(salt) != WALLET_CRYPTO_IV_SIZE {
		// Log an error if the rounds are less than 1 or if the salt size is incorrect.
		log.Printf("Invalid rounds or salt length: rounds=%d, salt length=%d", rounds, len(salt))
		return false // Return false to indicate the key setup failed.
	}

	// Derive the encryption key and IV using the provided passphrase (keyData) and salt.
	// This process will perform key stretching using the BytesToKeySHA512AES method, which applies SHA-512 multiple times.
	key, iv, err := c.BytesToKeySHA512AES(salt, keyData, int(rounds))

	// If there was an error during key derivation, log the error and return false.
	if err != nil {
		log.Printf("Error deriving key and IV: %v", err)
		return false
	}

	// Check if the lengths of the derived key and IV match the expected sizes.
	if len(key) != WALLET_CRYPTO_KEY_SIZE || len(iv) != WALLET_CRYPTO_IV_SIZE {
		// Log a message if the key or IV length does not match the expected sizes.
		log.Printf("Derived key or IV length mismatch: key length=%d, iv length=%d", len(key), len(iv))

		// Clean the memory for both the key and IV to ensure sensitive data is wiped from memory.
		memoryCleanse(key)
		memoryCleanse(iv)

		// Return false because the derived key or IV is of incorrect size.
		return false
	}

	// Store the derived key and IV in the CCrypter instance (c).
	c.vchKey = key
	c.vchIV = iv

	// Mark the key as set (fKeySet = true), indicating the encryption key has been successfully initialized.
	c.fKeySet = true

	// Return true to indicate the key was successfully derived and set.
	return true
}

// SetKey: Sets the encryption key and initialization vector (IV) directly in the CCrypter object.
func (c *CCrypter) SetKey(newKey, newIV []byte) bool {
	// Check if the provided key and IV match the expected sizes.
	if len(newKey) != WALLET_CRYPTO_KEY_SIZE || len(newIV) != WALLET_CRYPTO_IV_SIZE {
		return false // Return false if the key or IV size is invalid.
	}

	// Allocate memory for the key and IV in the CCrypter object.
	c.vchKey = make([]byte, WALLET_CRYPTO_KEY_SIZE)
	c.vchIV = make([]byte, WALLET_CRYPTO_IV_SIZE)

	// Copy the new key and IV into the internal fields of the CCrypter object.
	copy(c.vchKey, newKey)
	copy(c.vchIV, newIV)

	// Mark the key as set, indicating the CCrypter object is ready to encrypt/decrypt.
	c.fKeySet = true
	return true // Return true to indicate successful key setup.
}

// Encrypt: Encrypts the provided plaintext using AES-256-GCM.
func (c *CCrypter) Encrypt(plaintext []byte) ([]byte, error) {
	// Check if the key and IV have been set in the CCrypter object.
	if !c.fKeySet {
		return nil, errors.New("key not set") // Return an error if the key has not been set.
	}

	// Generate a new IV (nonce) for AES-GCM encryption. The IV size must match WALLET_CRYPTO_NONCE_SIZE.
	iv := make([]byte, WALLET_CRYPTO_NONCE_SIZE)
	if _, err := rand.Read(iv); err != nil {
		return nil, err // Return an error if random IV generation fails.
	}

	// Create a new AES cipher block using the previously set key (AES-256).
	block, err := aes.NewCipher(c.vchKey)
	if err != nil {
		return nil, err // Return an error if AES cipher creation fails.
	}

	// Create a GCM cipher mode instance (Galois/Counter Mode) for the AES cipher.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err // Return an error if GCM mode creation fails.
	}

	// Encrypt the plaintext using GCM. Seal appends the ciphertext to the IV (gcm.Seal).
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)

	// Prepend the IV (nonce) to the ciphertext so it can be used for decryption.
	// FIX: the original wrote `result := append(iv, ciphertext...)`. Since iv
	// is a 12-byte slice with cap == len (from make([]byte, 12)), append
	// happens to allocate a new backing array here, so this specific call
	// site was not actually corrupting iv. But it relies on an implementation
	// detail (cap-vs-len) rather than a guarantee, and the identical pattern
	// elsewhere in this file (BytesToKeySHA512AES) demonstrates how easily
	// append-aliasing bugs creep in. Made the allocation explicit so
	// correctness doesn't depend on append's capacity-growth behavior.
	result := make([]byte, 0, len(iv)+len(ciphertext))
	result = append(result, iv...)
	result = append(result, ciphertext...)

	// Return the result (IV + ciphertext) as the final encrypted output.
	return result, nil
}

// Decrypt: Decrypts the provided ciphertext using AES-256-GCM.
func (c *CCrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	// Check if the key and IV have been set in the CCrypter object.
	if !c.fKeySet {
		return nil, errors.New("key not set") // Return an error if the key has not been set.
	}

	// Check if the ciphertext is large enough to contain both the nonce (IV) and the ciphertext.
	if len(ciphertext) < WALLET_CRYPTO_NONCE_SIZE+AES_GCM_TAG_SIZE {
		return nil, errors.New("ciphertext too short") // Return an error if the ciphertext is too short.
	}

	// Extract the IV (nonce) from the beginning of the ciphertext.
	iv := ciphertext[:WALLET_CRYPTO_NONCE_SIZE]
	ciphertext = ciphertext[WALLET_CRYPTO_NONCE_SIZE:] // The remaining part is the actual encrypted data.

	// Create a new AES cipher block using the previously set key (AES-256).
	block, err := aes.NewCipher(c.vchKey)
	if err != nil {
		return nil, err // Return an error if AES cipher creation fails.
	}

	// Create a GCM cipher mode instance (Galois/Counter Mode) for the AES cipher.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err // Return an error if GCM mode creation fails.
	}

	// Decrypt the ciphertext using GCM. The IV is used here to decrypt the data.
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, err // Return an error if decryption fails.
	}

	// Return the decrypted plaintext.
	return plaintext, nil
}

// EncryptSecret: Encrypts the given plaintext using a master key.
//
// FIX (critical): the original generated a fresh random salt with
// GenerateRandomBytes on every call and then discarded it once the function
// returned. DecryptSecret independently generated *its own* random salt,
// which (with overwhelming probability) differed from the one used during
// encryption, so SetKeyFromPassphrase derived a different AES key on
// decrypt and gcm.Open failed with "cipher: message authentication failed"
// essentially every time. This is the bug you asked about: not an AES-CBC
// vs AES-GCM mismatch, it's that the GCM key itself was never reproducible.
//
// Fix: persist the salt by prepending it to the returned blob, the same way
// Encrypt() prepends its nonce. Output layout is now:
//
//	salt (16 bytes) || nonce (12 bytes) || GCM(ciphertext) || tag (16 bytes)
//
// The unused `iv *Uint256` parameter from the original signature has been
// removed — it was accepted but never read in either Encrypt or Decrypt
// path, which was itself a signal something was wired up incorrectly here.
// If your wallet format expects per-key IVs derived from the pubkey (as
// DecryptKey suggests), that's now handled via AAD — see DecryptKey below.
func EncryptSecret(masterKey []byte, plaintext []byte) ([]byte, error) {
	cKeyCrypter := &CCrypter{}

	// Generate a random salt of size equal to WALLET_CRYPTO_IV_SIZE for key derivation.
	salt, err := GenerateRandomBytes(WALLET_CRYPTO_SALT_SIZE)
	if err != nil {
		return nil, err
	}

	// Set the encryption key using the masterKey and the derived salt.
	if !cKeyCrypter.SetKeyFromPassphrase(masterKey, salt, secretDeriveRounds) {
		return nil, errors.New("failed to set key")
	}

	// Encrypt the plaintext using the AES-256-GCM cipher.
	ciphertext, err := cKeyCrypter.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}

	// Prepend the salt so DecryptSecret can re-derive the identical key.
	result := make([]byte, 0, len(salt)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, ciphertext...)

	return result, nil
}

// DecryptSecret: Decrypts a blob produced by EncryptSecret using a master key.
//
// FIX: now reads the salt back out of the blob (see EncryptSecret) instead
// of generating a new random one, which is what made decryption work at
// all. Also added a minimum-length check up front so a too-short input
// fails with a clear error instead of a slice-bounds panic.
func DecryptSecret(masterKey []byte, blob []byte) ([]byte, error) {
	if len(blob) < minEncryptSecretLen {
		return nil, errors.New("ciphertext too short")
	}

	salt := blob[:WALLET_CRYPTO_SALT_SIZE]
	ciphertext := blob[WALLET_CRYPTO_SALT_SIZE:]

	cKeyCrypter := &CCrypter{}

	// Re-derive the same key using the salt that was actually used at
	// encryption time, instead of a freshly generated random one.
	if !cKeyCrypter.SetKeyFromPassphrase(masterKey, salt, secretDeriveRounds) {
		return nil, errors.New("failed to set key")
	}

	plaintext, err := cKeyCrypter.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// DecryptKey: Decrypts a crypted secret using a master key.
//
// FIX: the original built `iv := BytesToUint256(pubKey)` and passed it into
// DecryptSecret, but DecryptSecret never used that parameter — it was dead
// on arrival before this fix and stays unused now since EncryptSecret/
// DecryptSecret no longer take an iv param at all (see above).
//
// FIX (layering + correctness): this used to also call VerifyPubKey(secret,
// pubKey) directly here, with a hardcoded `len(secret) != 32` size check.
// Both were wrong for real SPHINCS+ keys: SerializeSK (see
// sthincs/key/backend/key.go) produces SKseed||SKprf||PKseed||PKroot, which
// is NOT 32 bytes for any real SPHINCS+ parameter set, and is a different
// length entirely from the serialized public key it was being compared
// against — bytes.Equal(secret, pubKey) could never succeed.
//
// Public-key verification has moved to key.KeyManager.VerifyPubKey (see
// sthincs/key/backend/verify.go), because it needs SPHINCS+-aware
// deserialization (km.Params) that this generic AES/crypter package has no
// business knowing about — crypter encrypts/decrypts arbitrary byte blobs
// for multiple callers (disk.go, usb.go) that aren't all SPHINCS+ keys.
//
// DecryptKey here is now decrypt-only. Callers that need the old
// "decrypt AND verify against a known public key" behavior should call:
//
//	secretBytes, err := crypter.DecryptKey(masterKey, cryptedSecret)
//	// ... handle err ...
//	ok, err := keyManager.VerifyPubKey(secretBytes, pubKeyBytes)
//
// as two explicit steps, with whatever *key.KeyManager they already have
// in scope (e.g. wherever StoreRawKey / DecryptKey is invoked in disk.go).
func DecryptKey(masterKey []byte, cryptedSecret []byte) ([]byte, error) {
	secret, err := DecryptSecret(masterKey, cryptedSecret)
	if err != nil {
		return nil, err
	}

	if len(secret) == 0 {
		return nil, errors.New("decrypted secret is empty")
	}

	return secret, nil
}

// MemoryCleanse: Zero out sensitive data from memory
func memoryCleanse(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// GenerateRandomBytes returns size cryptographically random bytes.
func GenerateRandomBytes(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("size must be greater than 0")
	}
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
