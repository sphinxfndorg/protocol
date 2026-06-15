// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/crypter/key/aes.go
package crypter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"log"

	"golang.org/x/crypto/argon2"
)

// DeriveKeyFromPassphrase uses Argon2id with SHA3-512 stretching (must match crypter.DeriveKeyFromPassword)
func DeriveKeyFromPassphrase(passphrase string, salt []byte) []byte {
	log.Printf("[INFO] DeriveKeyFromPassphrase: deriving key from passphrase using Argon2id with SHA3-512")
	log.Printf("[DEBUG] DeriveKeyFromPassphrase: passphrase length: %d chars, salt size: %d bytes", len(passphrase), len(salt))
	log.Printf("[DEBUG] DeriveKeyFromPassphrase: salt (first 8 bytes): %x", salt[:min(8, len(salt))])

	// Use EXACT same parameters as crypter.DeriveKeyFromPassword
	// Time=3, Memory=64*1024, Threads=4, KeyLen=32
	argon2Key := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)
	log.Printf("[INFO] DeriveKeyFromPassphrase: Argon2id key derivation completed: %d bytes", len(argon2Key))

	// Additional stretching with SHA3-512 (matches crypter package)
	sha3Hash := sha3.New512()
	if _, err := sha3Hash.Write(argon2Key); err != nil {
		log.Printf("[ERROR] DeriveKeyFromPassphrase: error during SHA3-512 hashing: %v", err)
		for i := range argon2Key {
			argon2Key[i] = 0
		}
		return make([]byte, 32)
	}

	// Take first 32 bytes for AES-256
	finalKey := sha3Hash.Sum(nil)[:32]
	log.Printf("[DEBUG] DeriveKeyFromPassphrase: SHA3-512 hash computed, final key size: %d bytes", len(finalKey))
	log.Printf("[DEBUG] DeriveKeyFromPassphrase: final key (first 8 bytes): %x", finalKey[:8])

	// Clear intermediate buffer
	for i := range argon2Key {
		argon2Key[i] = 0
	}
	log.Printf("[INFO] DeriveKeyFromPassphrase: intermediate buffer cleared")

	log.Printf("[SUCCESS] DeriveKeyFromPassphrase: key derived successfully with SHA3-512 stretching")
	return finalKey
}

// GenerateSalt generates a cryptographically secure random salt
func GenerateSalt(size int) ([]byte, error) {
	log.Printf("[INFO] GenerateSalt: generating salt of size: %d bytes", size)

	if size < 16 {
		log.Printf("[ERROR] GenerateSalt: salt size must be at least 16 bytes, got %d", size)
		return nil, errors.New("salt size must be at least 16 bytes")
	}

	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		log.Printf("[ERROR] GenerateSalt: error generating salt: %v", err)
		return nil, err
	}

	log.Printf("[SUCCESS] GenerateSalt: salt generated successfully: %d bytes", size)
	log.Printf("[DEBUG] GenerateSalt: salt (first 8 bytes): %x", salt[:min(8, len(salt))])
	return salt, nil
}

// Encrypt encrypts the input data using AES-256-GCM with key derived from password
func Encrypt(data, password []byte) ([]byte, error) {
	log.Printf("[INFO] Encrypt: starting encryption with default params")
	log.Printf("[DEBUG] Encrypt: input data size: %d bytes, password length: %d chars", len(data), len(password))
	return EncryptWithParams(data, password, DefaultKeyDerivationParams)
}

// EncryptWithParams encrypts with custom key derivation parameters
func EncryptWithParams(data, password []byte, params KeyDerivationParams) ([]byte, error) {
	log.Printf("[INFO] EncryptWithParams: starting encryption process")
	log.Printf("[DEBUG] EncryptWithParams: data size: %d bytes, password length: %d chars", len(data), len(password))

	// Generate salt for key derivation
	salt, err := GenerateSalt(32) // 32 bytes salt
	if err != nil {
		log.Printf("[ERROR] EncryptWithParams: failed to generate salt: %v", err)
		return nil, err
	}
	log.Printf("[DEBUG] EncryptWithParams: salt generated (size: %d bytes)", len(salt))

	// Derive key from password - FIXED: convert password to string
	key := DeriveKeyFromPassphrase(string(password), salt)
	log.Printf("[DEBUG] EncryptWithParams: key derived")

	// Create SecureBuffer from derived key
	keyBuffer := NewSecureBuffer(key)
	defer keyBuffer.Clear()

	keyBytes := keyBuffer.Bytes()
	if keyBytes == nil {
		log.Printf("[ERROR] EncryptWithParams: failed to derive key")
		return nil, errors.New("failed to derive key")
	}
	log.Printf("[DEBUG] EncryptWithParams: key buffer created (size: %d bytes)", len(keyBytes))

	// Create AES cipher block
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		log.Printf("[ERROR] EncryptWithParams: error creating AES cipher: %v", err)
		return nil, err
	}
	log.Printf("[INFO] EncryptWithParams: AES cipher block created successfully")

	// Initialize GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[ERROR] EncryptWithParams: error initializing GCM: %v", err)
		return nil, err
	}
	log.Printf("[INFO] EncryptWithParams: GCM mode initialized successfully (nonce size: %d bytes)", gcm.NonceSize())

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		log.Printf("[ERROR] EncryptWithParams: error generating nonce: %v", err)
		return nil, err
	}
	log.Printf("[INFO] EncryptWithParams: nonce generated successfully (size: %d bytes)", len(nonce))
	log.Printf("[DEBUG] EncryptWithParams: nonce (first 8 bytes): %x", nonce[:min(8, len(nonce))])

	// Perform encryption
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	log.Printf("[DEBUG] EncryptWithParams: encryption complete, ciphertext size: %d bytes", len(ciphertext))

	// Combine salt + nonce + ciphertext
	result := make([]byte, len(salt)+len(nonce)+len(ciphertext))
	copy(result[:len(salt)], salt)
	copy(result[len(salt):len(salt)+len(nonce)], nonce)
	copy(result[len(salt)+len(nonce):], ciphertext)
	log.Printf("[INFO] EncryptWithParams: combined result size: %d bytes (salt: %d, nonce: %d, ciphertext: %d)",
		len(result), len(salt), len(nonce), len(ciphertext))

	// Clear sensitive data from memory
	clearBytes(salt)
	clearBytes(nonce)
	log.Printf("[DEBUG] EncryptWithParams: sensitive data cleared from memory")

	log.Printf("[SUCCESS] EncryptWithParams: data encrypted successfully")
	return result, nil
}

// Decrypt decrypts the input data using AES-256-GCM with key derived from password
func Decrypt(encryptedData, password []byte) ([]byte, error) {
	log.Printf("[INFO] Decrypt: starting decryption with default params")
	log.Printf("[DEBUG] Decrypt: encrypted data size: %d bytes, password length: %d chars", len(encryptedData), len(password))
	return DecryptWithParams(encryptedData, password, DefaultKeyDerivationParams)
}

// DecryptWithParams decrypts with custom key derivation parameters
func DecryptWithParams(encryptedData, password []byte, params KeyDerivationParams) ([]byte, error) {
	log.Printf("[INFO] DecryptWithParams: starting decryption process")

	// Extract salt, nonce, and ciphertext
	if len(encryptedData) < 32+12 { // salt (32) + minimum nonce size (12)
		log.Printf("[ERROR] DecryptWithParams: ciphertext too short: %d bytes (need at least 44)", len(encryptedData))
		return nil, errors.New("ciphertext too short")
	}

	salt := encryptedData[:32]
	remaining := encryptedData[32:]
	log.Printf("[DEBUG] DecryptWithParams: extracted salt (32 bytes), remaining data: %d bytes", len(remaining))
	log.Printf("[DEBUG] DecryptWithParams: salt (first 8 bytes): %x", salt[:8])

	// Derive key from password - FIXED: convert password to string
	key := DeriveKeyFromPassphrase(string(password), salt)
	log.Printf("[DEBUG] DecryptWithParams: key derived")

	// Create SecureBuffer from derived key
	keyBuffer := NewSecureBuffer(key)
	defer keyBuffer.Clear()

	keyBytes := keyBuffer.Bytes()
	if keyBytes == nil {
		log.Printf("[ERROR] DecryptWithParams: failed to derive key")
		return nil, errors.New("failed to derive key")
	}
	log.Printf("[DEBUG] DecryptWithParams: key buffer created (size: %d bytes)", len(keyBytes))

	// Create AES cipher block
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		log.Printf("[ERROR] DecryptWithParams: error creating AES cipher: %v", err)
		return nil, err
	}
	log.Printf("[INFO] DecryptWithParams: AES cipher block created successfully")

	// Initialize GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[ERROR] DecryptWithParams: error initializing GCM: %v", err)
		return nil, err
	}
	log.Printf("[INFO] DecryptWithParams: GCM mode initialized successfully (nonce size: %d bytes)", gcm.NonceSize())

	// Extract nonce and ciphertext
	nonceSize := gcm.NonceSize()
	if len(remaining) < nonceSize {
		log.Printf("[ERROR] DecryptWithParams: ciphertext too short after salt extraction: need %d bytes for nonce, have %d", nonceSize, len(remaining))
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := remaining[:nonceSize], remaining[nonceSize:]
	log.Printf("[INFO] DecryptWithParams: nonce and ciphertext separated successfully")
	log.Printf("[DEBUG] DecryptWithParams: nonce size: %d bytes, ciphertext size: %d bytes", len(nonce), len(ciphertext))
	log.Printf("[DEBUG] DecryptWithParams: nonce (first 8 bytes): %x", nonce[:min(8, len(nonce))])

	// Perform decryption
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Printf("[ERROR] DecryptWithParams: error decrypting data: %v", err)
		return nil, err
	}
	log.Printf("[DEBUG] DecryptWithParams: decryption successful, plaintext size: %d bytes", len(plaintext))

	log.Printf("[SUCCESS] DecryptWithParams: data decrypted successfully")
	return plaintext, nil
}

// SecureEncryptWithKey encrypts using a pre-derived key (for advanced use cases)
func SecureEncryptWithKey(data []byte, key *SecureBuffer) ([]byte, error) {
	log.Printf("[INFO] SecureEncryptWithKey: starting encryption with pre-derived key")
	log.Printf("[DEBUG] SecureEncryptWithKey: data size: %d bytes", len(data))

	if key == nil || key.Len() != 32 {
		log.Printf("[ERROR] SecureEncryptWithKey: invalid key: must be 32 bytes for AES-256, got %d", key.Len())
		return nil, errors.New("invalid key: must be 32 bytes for AES-256")
	}

	keyBytes := key.Bytes()
	defer clearBytes(keyBytes)
	log.Printf("[DEBUG] SecureEncryptWithKey: key validated (size: %d bytes)", len(keyBytes))

	result, err := encryptWithRawKey(data, keyBytes)
	if err != nil {
		log.Printf("[ERROR] SecureEncryptWithKey: encryption failed: %v", err)
		return nil, err
	}
	log.Printf("[SUCCESS] SecureEncryptWithKey: encryption completed, result size: %d bytes", len(result))
	return result, nil
}

// encryptWithRawKey internal function for encryption with raw key
func encryptWithRawKey(data, key []byte) ([]byte, error) {
	log.Printf("[DEBUG] encryptWithRawKey: starting raw key encryption")
	log.Printf("[DEBUG] encryptWithRawKey: data size: %d bytes, key size: %d bytes", len(data), len(key))

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("[ERROR] encryptWithRawKey: failed to create AES cipher: %v", err)
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[ERROR] encryptWithRawKey: failed to create GCM: %v", err)
		return nil, err
	}
	log.Printf("[DEBUG] encryptWithRawKey: GCM created (nonce size: %d bytes)", gcm.NonceSize())

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		log.Printf("[ERROR] encryptWithRawKey: failed to generate nonce: %v", err)
		return nil, err
	}
	log.Printf("[DEBUG] encryptWithRawKey: nonce generated (size: %d bytes)", len(nonce))

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	log.Printf("[SUCCESS] encryptWithRawKey: raw key encryption completed, ciphertext size: %d bytes", len(ciphertext))
	return ciphertext, nil
}

// SecureDecryptWithKey decrypts using a pre-derived key (matches SecureEncryptWithKey)
func SecureDecryptWithKey(data []byte, key *SecureBuffer) ([]byte, error) {
	log.Printf("[INFO] SecureDecryptWithKey: starting decryption with pre-derived key")
	log.Printf("[DEBUG] SecureDecryptWithKey: encrypted data size: %d bytes", len(data))

	if key == nil || key.Len() != 32 {
		log.Printf("[ERROR] SecureDecryptWithKey: invalid key: must be 32 bytes for AES-256, got %d", key.Len())
		return nil, errors.New("invalid key: must be 32 bytes for AES-256")
	}

	keyBytes := key.Bytes()
	defer clearBytes(keyBytes)
	log.Printf("[DEBUG] SecureDecryptWithKey: key validated (size: %d bytes)", len(keyBytes))

	result, err := decryptWithRawKey(data, keyBytes)
	if err != nil {
		log.Printf("[ERROR] SecureDecryptWithKey: decryption failed: %v", err)
		return nil, err
	}
	log.Printf("[SUCCESS] SecureDecryptWithKey: decryption completed, plaintext size: %d bytes", len(result))
	return result, nil
}

// decryptWithRawKey internal function for decryption with raw key
func decryptWithRawKey(data, key []byte) ([]byte, error) {
	log.Printf("[DEBUG] decryptWithRawKey: starting raw key decryption")
	log.Printf("[DEBUG] decryptWithRawKey: ciphertext size: %d bytes, key size: %d bytes", len(data), len(key))

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("[ERROR] decryptWithRawKey: failed to create AES cipher: %v", err)
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[ERROR] decryptWithRawKey: failed to create GCM: %v", err)
		return nil, err
	}
	log.Printf("[DEBUG] decryptWithRawKey: GCM created (nonce size: %d bytes)", gcm.NonceSize())

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		log.Printf("[ERROR] decryptWithRawKey: ciphertext too short: need %d bytes for nonce, have %d", nonceSize, len(data))
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	log.Printf("[DEBUG] decryptWithRawKey: nonce size: %d bytes, ciphertext size: %d bytes", len(nonce), len(ciphertext))

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Printf("[ERROR] decryptWithRawKey: decryption failed: %v", err)
		return nil, err
	}
	log.Printf("[SUCCESS] decryptWithRawKey: raw key decryption completed, plaintext size: %d bytes", len(plaintext))
	return plaintext, nil
}
