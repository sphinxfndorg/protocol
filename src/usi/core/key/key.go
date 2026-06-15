// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/key/key.go
package keys

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	crypter "github.com/sphinxorg/protocol/src/usi/core/crypter/key"
	db "github.com/sphinxorg/protocol/src/usi/core/dbkey"
)

// GenerateKeyPairWithOrg is the primary entry point for the registration flow.
// The orgCode is persisted in LevelDB and used to format all future addresses.
func GenerateKeyPairWithOrg(passphrase string, orgCode OrgCode) (*KeyPair, error) {
	log.Printf("Generating SPHINCS+ keypair for org %q", orgCode)

	if !IsValidOrgCode(string(orgCode)) {
		return nil, fmt.Errorf("unsupported organisation code: %q", orgCode)
	}

	sk, pk := sphincs.Spx_keygen(DefaultParams)
	log.Println("SPHINCS+ key pair generated successfully")

	pkBytes, err := pk.SerializePK()
	if err != nil {
		return nil, fmt.Errorf("serialize public key: %w", err)
	}
	skBytes, err := sk.SerializeSK()
	if err != nil {
		return nil, fmt.Errorf("serialize private key: %w", err)
	}

	salt, err := GeneratePureSalt(32)
	if err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	key := DeriveKeyFromPassphrase(passphrase, salt)

	encryptedSK, err := crypter.SecureEncryptWithKey(skBytes, crypter.NewSecureBuffer(key))
	if err != nil {
		return nil, fmt.Errorf("encrypt private key: %w", err)
	}

	kp := &KeyPair{
		PublicKey:  pkBytes,
		PrivateKey: encryptedSK,
		Salt:       salt,
		OrgCode:    string(orgCode),
	}

	if err := saveKeyToDisk(kp); err != nil {
		return nil, fmt.Errorf("save key pair: %w", err)
	}

	return kp, nil
}

// GetPublicKeyFingerprint generates a SHAKE256-based address using the
// organisation code stored in the KeyPair.  Falls back to legacy SPIF format
// if no org code is set (e.g. old vaults loaded from disk).
func GetPublicKeyFingerprint(kp *KeyPair) string {
	log.Println("Generating public key address")

	if kp.OrgCode != "" && IsValidOrgCode(kp.OrgCode) {
		code := OrgCode(kp.OrgCode)
		raw := SHAKE256HashWithOrg(kp.PublicKey, code)
		formatted := FormatOrgAddress(raw, code)
		log.Printf("Address generated with org prefix %q", kp.OrgCode)
		return formatted
	}

	// Legacy path — existing keys without an org code.
	log.Println("No org code set; using legacy SPIF format")
	fingerprint := SHAKE256Hash(kp.PublicKey)
	return FormatECPFingerprint(fingerprint)
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistence
// ─────────────────────────────────────────────────────────────────────────────

// keyMeta is the structure persisted in LevelDB.
type keyMeta struct {
	PublicKey []byte `json:"pk"`
	Salt      []byte `json:"salt"`
	OrgCode   string `json:"org_code,omitempty"`
}

func saveKeyToDisk(kp *KeyPair) error {
	log.Println("Saving keypair to disk")

	if err := os.MkdirAll(KeyDir, 0700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}

	if err := WriteFile(DatPath, kp.PrivateKey); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	kp.Path = DatPath

	metadataDB, err := db.Open(DBPath)
	if err != nil {
		return fmt.Errorf("open metadata DB: %w", err)
	}
	defer metadataDB.Close()

	meta := keyMeta{
		PublicKey: kp.PublicKey,
		Salt:      kp.Salt,
		OrgCode:   kp.OrgCode,
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	if err := metadataDB.Put([]byte("keypair"), data); err != nil {
		return fmt.Errorf("store metadata: %w", err)
	}

	log.Println("Keypair metadata saved successfully")
	return nil
}

// LoadKeyFromDisk loads and decrypts the key pair from key.dat + LevelDB.
func LoadKeyFromDisk(passphrase string) (*KeyPair, []byte, error) {
	log.Println("Loading keypair from disk")

	metadataDB, err := db.Open(DBPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open metadata DB: %w", err)
	}
	defer metadataDB.Close()

	data, err := metadataDB.Get([]byte("keypair"))
	if err != nil {
		return nil, nil, fmt.Errorf("retrieve metadata: %w", err)
	}

	var meta keyMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, nil, fmt.Errorf("unmarshal metadata: %w", err)
	}

	encryptedSK, err := ReadFile(DatPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read encrypted private key: %w", err)
	}

	kp := &KeyPair{
		PublicKey:  meta.PublicKey,
		PrivateKey: encryptedSK,
		Salt:       meta.Salt,
		Path:       DatPath,
		OrgCode:    meta.OrgCode,
	}

	derivedKey := DeriveKeyFromPassphrase(passphrase, kp.Salt)
	secureKey := crypter.NewSecureBuffer(derivedKey)
	defer secureKey.Clear()

	skBytes, err := crypter.SecureDecryptWithKey(kp.PrivateKey, secureKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decryption failed (wrong passphrase or corrupted key): %w", err)
	}

	if _, err = sphincs.DeserializeSK(DefaultParams, skBytes); err != nil {
		return nil, nil, fmt.Errorf("invalid private key: %w", err)
	}
	if _, err = sphincs.DeserializePK(DefaultParams, kp.PublicKey); err != nil {
		return nil, nil, fmt.Errorf("invalid public key: %w", err)
	}

	log.Printf("Keypair loaded successfully (org: %q)", kp.OrgCode)
	return kp, skBytes, nil
}
