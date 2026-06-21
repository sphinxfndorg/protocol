// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package crypter

import (
	"bytes"
	"testing"
)

func TestEncryptSecret_DecryptSecret_RoundTrip(t *testing.T) {
	masterKey := []byte("this-is-a-test-master-key-12345")
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	ciphertext, err := EncryptSecret(masterKey, plaintext)
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}

	// Regression check for the original bug: encrypting the same plaintext
	// twice must produce different salts (and thus different blobs), since
	// salt+nonce are both fresh random per call.
	ciphertext2, err := EncryptSecret(masterKey, plaintext)
	if err != nil {
		t.Fatalf("EncryptSecret (2nd call) failed: %v", err)
	}
	if bytes.Equal(ciphertext, ciphertext2) {
		t.Fatal("two EncryptSecret calls on identical input produced identical output (salt/nonce not random?)")
	}

	got, err := DecryptSecret(masterKey, ciphertext)
	if err != nil {
		t.Fatalf("DecryptSecret failed (this is the bug being fixed — salt wasn't persisted): %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestDecryptSecret_WrongMasterKey(t *testing.T) {
	plaintext := []byte("secret data")
	ciphertext, err := EncryptSecret([]byte("correct-master-key-padding-1234"), plaintext)
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}

	_, err = DecryptSecret([]byte("wrong-master-key-padding-567890"), ciphertext)
	if err == nil {
		t.Fatal("DecryptSecret succeeded with the wrong master key; expected auth failure")
	}
}

func TestDecryptSecret_TamperedCiphertext(t *testing.T) {
	masterKey := []byte("this-is-a-test-master-key-12345")
	ciphertext, err := EncryptSecret(masterKey, []byte("secret data"))
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xFF // flip a bit in the GCM tag

	_, err = DecryptSecret(masterKey, tampered)
	if err == nil {
		t.Fatal("DecryptSecret succeeded on tampered ciphertext; GCM should have rejected it")
	}
}

func TestDecryptSecret_TooShort(t *testing.T) {
	_, err := DecryptSecret([]byte("master-key"), []byte("short"))
	if err == nil {
		t.Fatal("expected error for too-short ciphertext, got nil")
	}
}

func TestBytesToKeySHA512AES_NotZeroed(t *testing.T) {
	// Regression check for the memoryCleanse-aliasing bug: derived key/iv
	// must not be all-zero (they would be if cleansing the scratch buffer
	// also zeroed the returned slices via shared backing array).
	c := &CCrypter{}
	salt := []byte("0123456789abcdef") // 16 bytes
	key, iv, err := c.BytesToKeySHA512AES(salt, []byte("some passphrase"), 1000)
	if err != nil {
		t.Fatalf("BytesToKeySHA512AES failed: %v", err)
	}

	if bytes.Equal(key, make([]byte, len(key))) {
		t.Fatal("derived key is all-zero — memoryCleanse likely aliased the returned slice")
	}
	if bytes.Equal(iv, make([]byte, len(iv))) {
		t.Fatal("derived iv is all-zero — memoryCleanse likely aliased the returned slice")
	}
}

func TestSetKeyFromPassphrase_Deterministic(t *testing.T) {
	// Same passphrase + same salt + same rounds must always derive the same
	// key/iv pair (this is what makes EncryptSecret/DecryptSecret round-trip
	// once the salt is persisted correctly).
	salt := []byte("0123456789abcdef")
	passphrase := []byte("correct horse battery staple")

	c1 := &CCrypter{}
	if !c1.SetKeyFromPassphrase(passphrase, salt, 5000) {
		t.Fatal("SetKeyFromPassphrase failed (c1)")
	}

	c2 := &CCrypter{}
	if !c2.SetKeyFromPassphrase(passphrase, salt, 5000) {
		t.Fatal("SetKeyFromPassphrase failed (c2)")
	}

	if !bytes.Equal(c1.vchKey, c2.vchKey) {
		t.Fatal("derived keys differ for identical passphrase+salt+rounds")
	}
	if !bytes.Equal(c1.vchIV, c2.vchIV) {
		t.Fatal("derived IVs differ for identical passphrase+salt+rounds")
	}
}

func TestCCrypter_Encrypt_Decrypt_RoundTrip(t *testing.T) {
	c := &CCrypter{}
	key := bytes.Repeat([]byte{0x42}, WALLET_CRYPTO_KEY_SIZE)
	iv := bytes.Repeat([]byte{0x24}, WALLET_CRYPTO_IV_SIZE)
	if !c.SetKey(key, iv) {
		t.Fatal("SetKey failed")
	}

	plaintext := []byte("round trip me")
	ct, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	pt, err := c.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("got %q, want %q", pt, plaintext)
	}
}

func TestDecryptKey(t *testing.T) {
	masterKey := []byte("this-is-a-test-master-key-12345")
	secret := []byte("a fake serialized SPHINCS+ SK blob, any length")

	ciphertext, err := EncryptSecret(masterKey, secret)
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}

	got, err := DecryptKey(masterKey, ciphertext)
	if err != nil {
		t.Fatalf("DecryptKey failed: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("got %q, want %q", got, secret)
	}
}

func TestNewCrypter(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, WALLET_CRYPTO_KEY_SIZE)
	iv := bytes.Repeat([]byte{0x22}, WALLET_CRYPTO_IV_SIZE)

	c, err := NewCrypter(key, iv)
	if err != nil {
		t.Fatalf("NewCrypter failed: %v", err)
	}
	if !c.fKeySet {
		t.Fatal("NewCrypter did not mark key as set")
	}
}
