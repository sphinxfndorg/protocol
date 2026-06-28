// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/wallet/vault/address.go
package vault

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"os"

	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
	"github.com/sphinxfndorg/protocol/src/usi/core/sign"
	pubkeydir "github.com/sphinxfndorg/protocol/src/usi/server/server"
)

// ─────────────────────────────────────────────────────────────────────────────
// Fingerprint Validation Functions
// ─────────────────────────────────────────────────────────────────────────────

// GetSHA3FingerprintFromBytes computes the SHA3-256 fingerprint from public key bytes.
// This is used for validation purposes and as a secondary fingerprint format.
func GetSHA3FingerprintFromBytes(pubKeyBytes []byte) string {
	hasher := sha3.New256()
	hasher.Write(pubKeyBytes)
	return hex.EncodeToString(hasher.Sum(nil))
}

// ValidateFingerprint validates that a SHA3-256 fingerprint matches the public key.
func ValidateFingerprint(pubKeyBytes []byte, expectedFingerprint string) bool {
	computed := GetSHA3FingerprintFromBytes(pubKeyBytes)
	return computed == expectedFingerprint
}

// ValidateAddressFingerprint validates that a SPIF address matches the public key.
func ValidateAddressFingerprint(pubKeyBytes []byte, address string, orgCode keys.OrgCode) bool {
	computed := keys.GetPublicKeyFingerprintFromBytes(pubKeyBytes, orgCode)
	normalizedComputed, err := keys.NormalizeOrgAddress(computed)
	if err != nil {
		return false
	}
	normalizedAddress, err := keys.NormalizeOrgAddress(address)
	if err != nil {
		return false
	}
	return normalizedComputed == normalizedAddress
}

// ValidateAndNormalizeRecipients processes a list of recipient fingerprints
func ValidateAndNormalizeRecipients(recipientFingerprints []string) ([]string, error) {
	log.Printf("[INFO] ValidateAndNormalizeRecipients: processing %d recipient fingerprints", len(recipientFingerprints))

	normalized := make([]string, 0, len(recipientFingerprints))
	seen := make(map[string]bool)

	for i, fp := range recipientFingerprints {
		log.Printf("[DEBUG] ValidateAndNormalizeRecipients: validating recipient %d: %.16s...", i+1, fp)

		normalizedFP, err := keys.NormalizeOrgAddress(fp)
		if err != nil {
			log.Printf("[ERROR] ValidateAndNormalizeRecipients: invalid fingerprint %d: %v", i+1, err)
			return nil, fmt.Errorf("recipient %d: %w", i+1, err)
		}

		if seen[normalizedFP] {
			log.Printf("[WARN] ValidateAndNormalizeRecipients: duplicate recipient: %.16s...", normalizedFP)
			return nil, fmt.Errorf("duplicate recipient: %s", normalizedFP)
		}
		seen[normalizedFP] = true

		normalized = append(normalized, normalizedFP)
		log.Printf("[DEBUG] ValidateAndNormalizeRecipients: recipient %d normalized to: %.16s...", i+1, normalizedFP)
	}

	log.Printf("[SUCCESS] ValidateAndNormalizeRecipients: successfully validated %d unique recipients", len(normalized))
	return normalized, nil
}

// ResolveRecipient verifies a bundle from the public directory and extracts the HybridPublicKey
func ResolveRecipient(store pubkeydir.Store, fingerprint string) (*HybridPublicKey, error) {
	log.Printf("[INFO] ResolveRecipient: resolving recipient: %.16s...", fingerprint)

	normalizedFP, err := keys.NormalizeOrgAddress(fingerprint)
	if err != nil {
		log.Printf("[ERROR] ResolveRecipient: invalid fingerprint format: %v", err)
		return nil, fmt.Errorf("invalid fingerprint format: %w", err)
	}
	log.Printf("[DEBUG] ResolveRecipient: normalized fingerprint: %.16s...", normalizedFP)

	// Try direct lookup first (canonical fingerprint)
	bundle, err := store.Get(normalizedFP)
	if err != nil {
		if err != pubkeydir.ErrNotFound {
			log.Printf("[ERROR] ResolveRecipient: store lookup error: %v", err)
			return nil, fmt.Errorf("store lookup error: %w", err)
		}

		// Fallback: scan all bundles and find by address fingerprint
		log.Printf("[INFO] ResolveRecipient: direct lookup miss for %.16s..., scanning all bundles", normalizedFP)
		bundle, err = scanBundleByAddressFP(store, normalizedFP)
		if err != nil {
			log.Printf("[ERROR] ResolveRecipient: recipient not found: %v", err)
			return nil, fmt.Errorf("recipient not found: %w", err)
		}
		log.Printf("[INFO] ResolveRecipient: found bundle via scan")
	}

	// Validate the bundle - this will check fingerprint match
	if err := pubkeydir.ValidateBundle(bundle, nil); err != nil {
		if err == pubkeydir.ErrRevoked {
			log.Printf("[ERROR] ResolveRecipient: recipient key has been revoked")
			return nil, fmt.Errorf("recipient key has been revoked")
		}
		if err == pubkeydir.ErrFingerprintMismatch {
			// Log more details for debugging
			log.Printf("[ERROR] ResolveRecipient: fingerprint mismatch - bundle.Fingerprint: %.16s..., expected: %.16s...",
				bundle.Fingerprint, normalizedFP)
			return nil, fmt.Errorf("fingerprint mismatch — bundle may be tampered or wrong recipient")
		}
		log.Printf("[ERROR] ResolveRecipient: bundle validation failed: %v", err)
		return nil, fmt.Errorf("bundle validation failed: %w", err)
	}

	log.Printf("[SUCCESS] ResolveRecipient: bundle validated for %.16s...", normalizedFP)

	x25519Pub, kyberPub, err := splitHybridKey(bundle.KEMPublicKey)
	if err != nil {
		log.Printf("[ERROR] ResolveRecipient: malformed KEM public key: %v", err)
		return nil, fmt.Errorf("malformed KEM public key: %w", err)
	}

	log.Printf("[SUCCESS] ResolveRecipient: successfully resolved recipient %.16s...", normalizedFP)
	return &HybridPublicKey{
		Fingerprint: bundle.Fingerprint,
		X25519Pub:   x25519Pub,
		KyberPub:    kyberPub,
	}, nil
}

// scanBundleByAddressFP walks all stored bundles and returns the first one
// whose address-formatted fingerprint normalizes to the target.
func scanBundleByAddressFP(store pubkeydir.Store, targetNormalized string) (pubkeydir.PublicKeyBundle, error) {
	log.Printf("[INFO] scanBundleByAddressFP: scanning all bundles for target: %.16s...", targetNormalized)

	bundles, err := store.List()
	if err != nil {
		log.Printf("[ERROR] scanBundleByAddressFP: failed to list bundles: %v", err)
		return pubkeydir.PublicKeyBundle{}, fmt.Errorf("failed to list bundles: %w", err)
	}
	log.Printf("[DEBUG] scanBundleByAddressFP: scanning %d bundles", len(bundles))

	for i, b := range bundles {
		// Use the organization from the bundle (this is what the user selected during registration)
		if b.Organization == "" {
			log.Printf("[DEBUG] scanBundleByAddressFP: bundle %d: skipping bundle with no organization: %.16s...", i, b.Fingerprint)
			continue
		}

		if !keys.IsValidOrgCode(b.Organization) {
			log.Printf("[DEBUG] scanBundleByAddressFP: bundle %d: skipping bundle with invalid org %q", i, b.Organization)
			continue
		}

		orgCode := keys.OrgCode(b.Organization)

		// Derive the address fingerprint from the SignaturePublicKey using the bundle's org code
		addressFP := keys.GetPublicKeyFingerprintFromBytes(b.SignaturePublicKey, orgCode)
		normalizedAddress, err := keys.NormalizeOrgAddress(addressFP)
		if err != nil {
			log.Printf("[DEBUG] scanBundleByAddressFP: bundle %d: failed to normalize address: %v", i, err)
			continue
		}

		if normalizedAddress == targetNormalized {
			log.Printf("[SUCCESS] scanBundleByAddressFP: matched bundle %d via address fp %.16s... (canonical: %.16s..., org: %s)",
				i, targetNormalized, b.Fingerprint, orgCode)
			return b, nil
		}
	}

	log.Printf("[WARN] scanBundleByAddressFP: no bundle found for target: %.16s...", targetNormalized)
	return pubkeydir.PublicKeyBundle{}, pubkeydir.ErrNotFound
}

// ResolveMultipleRecipients resolves multiple fingerprints to verified HybridPublicKeys
func ResolveMultipleRecipients(store pubkeydir.Store, fingerprints []string) ([]*HybridPublicKey, error) {
	if len(fingerprints) == 0 {
		log.Printf("[INFO] ResolveMultipleRecipients: no recipients to resolve")
		return nil, nil
	}

	log.Printf("[INFO] ResolveMultipleRecipients: resolving %d recipients", len(fingerprints))

	resolved := make([]*HybridPublicKey, 0, len(fingerprints))
	seen := make(map[string]bool)

	for i, fp := range fingerprints {
		log.Printf("[DEBUG] ResolveMultipleRecipients: resolving recipient %d: %.16s...", i+1, fp)

		normalizedFP, err := keys.NormalizeOrgAddress(fp)
		if err != nil {
			log.Printf("[ERROR] ResolveMultipleRecipients: invalid fingerprint %d: %v", i+1, err)
			return nil, fmt.Errorf("invalid fingerprint %s: %w", fp, err)
		}

		if seen[normalizedFP] {
			log.Printf("[DEBUG] ResolveMultipleRecipients: skipping duplicate recipient: %.16s...", normalizedFP)
			continue
		}
		seen[normalizedFP] = true

		pub, err := ResolveRecipient(store, normalizedFP)
		if err != nil {
			log.Printf("[ERROR] ResolveMultipleRecipients: failed to resolve recipient %.16s...: %v", normalizedFP, err)
			return nil, fmt.Errorf("failed to resolve recipient %.16s...: %w", normalizedFP, err)
		}
		resolved = append(resolved, pub)
		log.Printf("[DEBUG] ResolveMultipleRecipients: successfully resolved recipient %d: %.16s...", i+1, normalizedFP)
	}

	log.Printf("[SUCCESS] ResolveMultipleRecipients: successfully resolved %d/%d recipients", len(resolved), len(fingerprints))
	return resolved, nil
}

// PublishKeyBundle publishes the user's KEM public key bundle to the directory
// This is called once after generating keys
func PublishKeyBundle(store pubkeydir.Store, label, organization, passphrase string) error {
	log.Printf("[INFO] PublishKeyBundle: publishing KEM bundle to directory")
	log.Printf("[DEBUG] PublishKeyBundle: label=%s, organization=%s", label, organization)

	// Load the user's long-term SPHINCS+ key pair
	kp, skBytes, err := keys.LoadKeyFromDisk(passphrase)
	if err != nil {
		log.Printf("[ERROR] PublishKeyBundle: failed to load signature key: %v", err)
		return fmt.Errorf("failed to load signature key: %w", err)
	}
	defer func() {
		for i := range skBytes {
			skBytes[i] = 0
		}
		log.Printf("[INFO] PublishKeyBundle: signature key bytes zeroed")
	}()
	log.Printf("[INFO] PublishKeyBundle: signature key loaded")

	// Load the user's long-term KEM public key (already generated)
	kemPub, err := keys.LoadKEMPublicKey()
	if err != nil {
		log.Printf("[ERROR] PublishKeyBundle: failed to load KEM public key: %v", err)
		return fmt.Errorf("failed to load KEM public key: %w", err)
	}
	log.Printf("[DEBUG] PublishKeyBundle: KEM public key size: %d bytes", len(kemPub))

	// Create binding message
	fingerprint := pubkeydir.Fingerprint(kp.PublicKey)
	bindingMsg := pubkeydir.BindingMessage(fingerprint, kemPub)
	log.Printf("[DEBUG] PublishKeyBundle: binding message created (size: %d bytes)", len(bindingMsg))

	// Sign the binding message
	sig, err := sign.Sign(bindingMsg, passphrase)
	if err != nil {
		log.Printf("[ERROR] PublishKeyBundle: failed to sign KEM public key: %v", err)
		return fmt.Errorf("failed to sign KEM public key: %w", err)
	}
	log.Printf("[DEBUG] PublishKeyBundle: binding message signed (signature size: %d bytes)", len(sig.Signature))

	// Create and publish bundle
	bundle := pubkeydir.NewBundle(
		label,
		organization,
		kp.PublicKey,
		kemPub,
		sig.Signature,
	)

	if err := store.Put(bundle); err != nil {
		log.Printf("[ERROR] PublishKeyBundle: failed to publish bundle: %v", err)
		return fmt.Errorf("failed to publish bundle: %w", err)
	}

	log.Printf("[SUCCESS] PublishKeyBundle: published KEM bundle for fingerprint %.16s...", fingerprint)
	return nil
}

// splitHybridKey splits a concatenated hybrid public key that was marshaled by marshalHybridKey.
// The format is: [2 bytes: len(X25519)] [X25519 key] [Kyber768 key]
func splitHybridKey(hybridKey []byte) (x25519Pub, kyberPub []byte, err error) {
	log.Printf("[DEBUG] splitHybridKey: splitting hybrid key of size %d bytes", len(hybridKey))

	if len(hybridKey) < 2 {
		log.Printf("[ERROR] splitHybridKey: hybrid key too short: %d bytes (need at least 2 for length)", len(hybridKey))
		return nil, nil, fmt.Errorf("hybrid key too short: %d bytes (need at least 2 for length)", len(hybridKey))
	}

	// Read the length prefix (little-endian uint16)
	x25519Len := int(binary.LittleEndian.Uint16(hybridKey[0:2]))
	log.Printf("[DEBUG] splitHybridKey: X25519 key length: %d bytes", x25519Len)

	if len(hybridKey) < 2+x25519Len {
		log.Printf("[ERROR] splitHybridKey: hybrid key too short: need %d bytes for X25519 key, have %d",
			2+x25519Len, len(hybridKey))
		return nil, nil, fmt.Errorf("hybrid key too short: need %d bytes for X25519 key, have %d",
			2+x25519Len, len(hybridKey))
	}

	// Extract X25519 public key
	x25519Pub = make([]byte, x25519Len)
	copy(x25519Pub, hybridKey[2:2+x25519Len])

	// Remaining bytes are Kyber768 public key
	kyberPub = make([]byte, len(hybridKey)-(2+x25519Len))
	copy(kyberPub, hybridKey[2+x25519Len:])

	// Kyber768 public keys should be 1184 bytes
	if len(kyberPub) != 1184 {
		log.Printf("[WARN] splitHybridKey: Kyber public key length %d (expected 1184)", len(kyberPub))
	} else {
		log.Printf("[DEBUG] splitHybridKey: Kyber public key length %d bytes (expected)", len(kyberPub))
	}

	log.Printf("[SUCCESS] splitHybridKey: split successfully - X25519: %d bytes, Kyber: %d bytes", len(x25519Pub), len(kyberPub))
	return x25519Pub, kyberPub, nil
}

// EncryptFolderWithRecipients encrypts a folder for multiple recipients
func EncryptFolderWithRecipients(
	folderPath, passphrase string,
	recipientFingerprints []string,
	recipientPubs []*HybridPublicKey,
) error {
	log.Printf("[INFO] EncryptFolderWithRecipients: starting folder encryption with recipients")
	log.Printf("[DEBUG] EncryptFolderWithRecipients: folderPath=%s, recipients=%d", folderPath, len(recipientFingerprints))

	if len(recipientFingerprints) != len(recipientPubs) {
		log.Printf("[ERROR] EncryptFolderWithRecipients: fingerprint count (%d) does not match public key count (%d)",
			len(recipientFingerprints), len(recipientPubs))
		return fmt.Errorf("fingerprint count (%d) does not match public key count (%d)",
			len(recipientFingerprints), len(recipientPubs))
	}

	normalizedRecipients, err := ValidateAndNormalizeRecipients(recipientFingerprints)
	if err != nil {
		log.Printf("[ERROR] EncryptFolderWithRecipients: invalid recipient fingerprints: %v", err)
		return fmt.Errorf("invalid recipient fingerprints: %w", err)
	}

	for i, pub := range recipientPubs {
		pub.Fingerprint = normalizedRecipients[i]
	}

	log.Printf("[INFO] EncryptFolderWithRecipients: encrypting for %d validated recipients", len(normalizedRecipients))
	return performEncryptionWithRecipients(folderPath, passphrase, recipientPubs)
}

// performEncryptionWithRecipients does the actual hybrid KEM encryption
func performEncryptionWithRecipients(
	folderPath, passphrase string,
	recipientPubs []*HybridPublicKey,
) error {
	log.Printf("[INFO] performEncryptionWithRecipients: starting hybrid KEM encryption (X25519 + Kyber768)")

	// STEP 1: Build tar archive
	log.Printf("[DEBUG] performEncryptionWithRecipients: step 1 - building tar archive")
	tmpTar, err := os.CreateTemp("", "usi-tar-*.tar.gz")
	if err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to create temp tar: %v", err)
		return err
	}
	defer secureRemove(tmpTar.Name())

	m, err := buildManifest(folderPath)
	if err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to build manifest: %v", err)
		return err
	}
	log.Printf("[DEBUG] performEncryptionWithRecipients: manifest built with %d files", len(m.Files))

	if err := tarFolder(folderPath, tmpTar); err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to tar folder: %v", err)
		return err
	}
	tmpTar.Close()
	log.Printf("[INFO] performEncryptionWithRecipients: folder tarred successfully")

	// STEP 2: Sign plaintext hash
	log.Printf("[DEBUG] performEncryptionWithRecipients: step 2 - signing plaintext hash")
	plaintextData, err := os.ReadFile(tmpTar.Name())
	if err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to read plaintext: %v", err)
		return err
	}
	defer clearBytes(plaintextData)

	plaintextHasher := sha3.NewSHAKE256()
	plaintextHasher.Write(plaintextData)
	plaintextHash := make([]byte, 64)
	plaintextHasher.Read(plaintextHash)
	log.Printf("[DEBUG] performEncryptionWithRecipients: plaintext hash computed (size: %d bytes)", len(plaintextHash))

	sig, err := sign.Sign(plaintextHash, passphrase)
	if err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to sign plaintext: %v", err)
		return fmt.Errorf("failed to sign plaintext: %w", err)
	}
	m.Signature = sig.Signature
	m.PublicKey = sig.PublicKey
	log.Printf("[INFO] performEncryptionWithRecipients: plaintext signed with sender's private key (signature size: %d bytes)", len(sig.Signature))

	// STEP 3: Generate one-time session key
	log.Printf("[DEBUG] performEncryptionWithRecipients: step 3 - generating one-time session key")
	sessionKey := make([]byte, keySize)
	if _, err := rand.Read(sessionKey); err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to generate session key: %v", err)
		return err
	}
	defer clearBytes(sessionKey)
	log.Printf("[INFO] performEncryptionWithRecipients: generated ephemeral session key (size: %d bytes)", keySize)

	// STEP 4: Encrypt session key for each recipient using their KEM public key
	log.Printf("[DEBUG] performEncryptionWithRecipients: step 4 - encrypting session key for %d recipients", len(recipientPubs))
	recipientEntries := make([]RecipientEntry, 0, len(recipientPubs))
	for i, pub := range recipientPubs {
		log.Printf("[DEBUG] performEncryptionWithRecipients: wrapping session key for recipient %d: %.16s...", i+1, pub.Fingerprint[:16])

		entry, err := EncryptSessionKeyForRecipient(sessionKey, pub)
		if err != nil {
			log.Printf("[ERROR] performEncryptionWithRecipients: failed to encrypt session key for recipient %d: %v", i+1, err)
			return fmt.Errorf("failed to encrypt session key for recipient %s: %w",
				pub.Fingerprint[:16], err)
		}
		recipientEntries = append(recipientEntries, *entry)
		log.Printf("[DEBUG] performEncryptionWithRecipients: recipient %d encrypted successfully", i+1)
	}

	m.Recipients = recipientEntries
	m.Version = ManifestVersionV3
	log.Printf("[INFO] performEncryptionWithRecipients: session key encrypted for %d recipients", len(recipientEntries))

	// STEP 5: Encrypt payload with session key
	log.Printf("[DEBUG] performEncryptionWithRecipients: step 5 - encrypting payload with session key")
	var encryptedData bytes.Buffer
	if err := encryptStream(tmpTar.Name(), &encryptedData, sessionKey); err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to encrypt stream: %v", err)
		return err
	}
	m.Checksum = computeChecksum(encryptedData.Bytes())
	log.Printf("[DEBUG] performEncryptionWithRecipients: payload encrypted, checksum: %x", m.Checksum[:8])

	// STEP 6: Write vault file
	log.Printf("[DEBUG] performEncryptionWithRecipients: step 6 - writing vault file")
	clean := manifest{
		Files:        m.Files,
		Timestamp:    m.Timestamp,
		OriginalName: m.OriginalName,
		Checksum:     m.Checksum,
		Recipients:   recipientEntries,
		Version:      ManifestVersionV3,
		Signature:    m.Signature,
		PublicKey:    m.PublicKey,
	}

	vaultPath := folderPath + vaultExt
	log.Printf("[DEBUG] performEncryptionWithRecipients: vault path: %s", vaultPath)

	backupPath := ""
	if _, err := os.Stat(vaultPath); err == nil {
		backupPath = vaultPath + ".backup"
		if err := os.Rename(vaultPath, backupPath); err != nil {
			log.Printf("[ERROR] performEncryptionWithRecipients: failed to backup existing vault: %v", err)
			return fmt.Errorf("failed to backup existing vault: %w", err)
		}
		log.Printf("[INFO] performEncryptionWithRecipients: existing vault backed up to %s", backupPath)
	}

	tmpVault, err := os.CreateTemp("", "usi-vault-*.vault")
	if err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to create temp vault: %v", err)
		if backupPath != "" {
			os.Rename(backupPath, vaultPath)
		}
		return err
	}
	defer func() {
		if err != nil {
			secureRemove(tmpVault.Name())
			if backupPath != "" {
				os.Rename(backupPath, vaultPath)
			}
		}
	}()

	// Write magic number
	magicNumber := []byte("USI_VAULT\x00")
	if _, err := tmpVault.Write(magicNumber); err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to write magic number: %v", err)
		return err
	}
	log.Printf("[DEBUG] performEncryptionWithRecipients: magic number written")

	// Set restrictive permissions
	if err := tmpVault.Chmod(0600); err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to set permissions: %v", err)
		return err
	}

	manifestJSON, err := json.MarshalIndent(clean, "", "  ")
	if err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to marshal manifest: %v", err)
		return err
	}
	defer clearBytes(manifestJSON)
	log.Printf("[DEBUG] performEncryptionWithRecipients: manifest JSON size: %d bytes", len(manifestJSON))

	// Compute HMAC for manifest integrity using session key
	hmacKey := sha3.Sum256(sessionKey)
	h := hmac.New(func() hash.Hash { return sha3.New256() }, hmacKey[:])
	if _, err := h.Write(manifestJSON); err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to compute HMAC: %v", err)
		return err
	}
	manifestMAC := h.Sum(nil)
	log.Printf("[DEBUG] performEncryptionWithRecipients: manifest HMAC computed (size: %d bytes)", len(manifestMAC))

	// Write manifest JSON
	if _, err := tmpVault.Write(manifestJSON); err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to write manifest: %v", err)
		return err
	}
	// Write 32-byte HMAC
	if _, err := tmpVault.Write(manifestMAC); err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to write HMAC: %v", err)
		return err
	}
	// Write null delimiter
	if _, err := tmpVault.Write([]byte{0}); err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to write delimiter: %v", err)
		return err
	}
	// Write encrypted payload
	if _, err := tmpVault.Write(encryptedData.Bytes()); err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to write encrypted payload: %v", err)
		return err
	}
	log.Printf("[DEBUG] performEncryptionWithRecipients: encrypted payload written (size: %d bytes)", encryptedData.Len())

	if err := tmpVault.Sync(); err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to sync vault: %v", err)
		return err
	}
	if err := tmpVault.Close(); err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to close vault: %v", err)
		return err
	}
	if err := os.Rename(tmpVault.Name(), vaultPath); err != nil {
		log.Printf("[ERROR] performEncryptionWithRecipients: failed to rename vault: %v", err)
		return err
	}
	if backupPath != "" {
		secureRemove(backupPath)
		log.Printf("[INFO] performEncryptionWithRecipients: backup removed")
	}
	if err := os.RemoveAll(folderPath); err != nil {
		log.Printf("[WARN] performEncryptionWithRecipients: failed to delete original folder: %v", err)
	}

	log.Printf("[SUCCESS] performEncryptionWithRecipients: hybrid KEM encryption completed successfully")
	return nil
}

// GetVaultRecipients reads the recipient fingerprint list from a vault file
func GetVaultRecipients(vaultPath string) ([]string, error) {
	log.Printf("[INFO] GetVaultRecipients: reading recipients from vault: %s", vaultPath)

	f, err := os.Open(vaultPath)
	if err != nil {
		log.Printf("[ERROR] GetVaultRecipients: failed to open vault: %v", err)
		return nil, err
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, 10*1024*1024))
	if err != nil {
		log.Printf("[ERROR] GetVaultRecipients: failed to read vault: %v", err)
		return nil, err
	}
	log.Printf("[DEBUG] GetVaultRecipients: read %d bytes from vault", len(raw))

	split := bytes.Index(raw, []byte{0})
	if split == -1 {
		log.Printf("[ERROR] GetVaultRecipients: manifest delimiter missing")
		return nil, errors.New("manifest delimiter missing")
	}
	log.Printf("[DEBUG] GetVaultRecipients: found manifest delimiter at offset %d", split)

	var m manifest
	if err := json.Unmarshal(raw[:split], &m); err != nil {
		log.Printf("[ERROR] GetVaultRecipients: failed to unmarshal manifest: %v", err)
		return nil, err
	}
	log.Printf("[DEBUG] GetVaultRecipients: manifest has %d recipients", len(m.Recipients))

	fingerprints := make([]string, 0, len(m.Recipients))
	for i, r := range m.Recipients {
		rawHash, err := keys.NormalizeOrgAddress(r.Fingerprint)
		if err != nil {
			log.Printf("[DEBUG] GetVaultRecipients: recipient %d: using raw fingerprint: %.16s...", i+1, r.Fingerprint)
			fingerprints = append(fingerprints, r.Fingerprint)
		} else {
			log.Printf("[DEBUG] GetVaultRecipients: recipient %d: normalized to: %.16s...", i+1, rawHash)
			fingerprints = append(fingerprints, rawHash)
		}
	}

	log.Printf("[SUCCESS] GetVaultRecipients: read %d recipients from vault", len(fingerprints))
	return fingerprints, nil
}

// GetCurrentUserFingerprint returns the current user's normalized fingerprint
func GetCurrentUserFingerprint(passphrase string) (string, error) {
	log.Printf("[INFO] GetCurrentUserFingerprint: getting current user fingerprint")

	kp, _, err := keys.LoadKeyFromDisk(passphrase)
	if err != nil {
		log.Printf("[ERROR] GetCurrentUserFingerprint: failed to load keypair: %v", err)
		return "", fmt.Errorf("failed to load keypair: %w", err)
	}
	raw, err := keys.NormalizeOrgAddress(keys.GetPublicKeyFingerprint(kp))
	if err != nil {
		log.Printf("[ERROR] GetCurrentUserFingerprint: failed to normalize fingerprint: %v", err)
		return "", fmt.Errorf("failed to normalize fingerprint: %w", err)
	}
	log.Printf("[SUCCESS] GetCurrentUserFingerprint: fingerprint: %.16s...", raw)
	return raw, nil
}

// IsUserRecipient checks whether the current user is listed as a vault recipient
func IsUserRecipient(vaultPath, passphrase string) (bool, string, error) {
	log.Printf("[INFO] IsUserRecipient: checking if user is recipient for vault: %s", vaultPath)

	recipients, err := GetVaultRecipients(vaultPath)
	if err != nil {
		log.Printf("[ERROR] IsUserRecipient: failed to read vault recipients: %v", err)
		return false, "", fmt.Errorf("failed to read vault recipients: %w", err)
	}

	if len(recipients) == 0 {
		log.Printf("[INFO] IsUserRecipient: no recipients — vault created by owner")
		return true, "", nil
	}
	log.Printf("[DEBUG] IsUserRecipient: vault has %d recipients", len(recipients))

	userFP, err := GetCurrentUserFingerprint(passphrase)
	if err != nil {
		log.Printf("[ERROR] IsUserRecipient: failed to get user fingerprint: %v", err)
		return false, "", err
	}

	for i, r := range recipients {
		if r == userFP {
			log.Printf("[SUCCESS] IsUserRecipient: user is recipient %d: %.16s...", i+1, r)
			return true, keys.FormatOrgAddressForDisplay(userFP), nil
		}
		log.Printf("[DEBUG] IsUserRecipient: recipient %d: %.16s... (user: %.16s...)", i+1, r, userFP)
	}

	log.Printf("[INFO] IsUserRecipient: user is NOT a recipient (user: %.16s...)", userFP)
	return false, keys.FormatOrgAddressForDisplay(userFP), nil
}

// DecryptVaultWithRecipientCheck is the GUI-facing decryption wrapper
func DecryptVaultWithRecipientCheck(vaultPath, passphrase string) error {
	log.Printf("[INFO] DecryptVaultWithRecipientCheck: starting decryption check for: %s", vaultPath)
	return DecryptVault(vaultPath, passphrase)
}

// GetFingerprintFormatDescription describes supported fingerprint formats
func GetFingerprintFormatDescription() string {
	return "Fingerprint format: 64 hex characters (terminal: no spaces, GUI: groups of 4 with spaces)"
}

// EncryptFolderWithResolvedKeys encrypts a folder using pre-resolved public keys
func EncryptFolderWithResolvedKeys(
	folderPath, passphrase string,
	recipientFingerprints []string,
	recipientPubs []*HybridPublicKey,
) error {
	log.Printf("[INFO] EncryptFolderWithResolvedKeys: encrypting with resolved keys for %d recipients", len(recipientPubs))
	log.Printf("[DEBUG] EncryptFolderWithResolvedKeys: folderPath=%s", folderPath)

	if len(recipientFingerprints) != len(recipientPubs) {
		log.Printf("[ERROR] EncryptFolderWithResolvedKeys: fingerprint count (%d) does not match public key count (%d)",
			len(recipientFingerprints), len(recipientPubs))
		return fmt.Errorf("fingerprint count (%d) does not match public key count (%d)",
			len(recipientFingerprints), len(recipientPubs))
	}

	normalizedRecipients, err := ValidateAndNormalizeRecipients(recipientFingerprints)
	if err != nil {
		log.Printf("[ERROR] EncryptFolderWithResolvedKeys: invalid recipient fingerprints: %v", err)
		return fmt.Errorf("invalid recipient fingerprints: %w", err)
	}

	for i, pub := range recipientPubs {
		pub.Fingerprint = normalizedRecipients[i]
		log.Printf("[DEBUG] EncryptFolderWithResolvedKeys: recipient %d fingerprint set: %.16s...", i+1, normalizedRecipients[i])
	}

	log.Printf("[INFO] EncryptFolderWithResolvedKeys: starting encryption for %d recipients", len(normalizedRecipients))
	return performEncryptionWithRecipients(folderPath, passphrase, recipientPubs)
}
