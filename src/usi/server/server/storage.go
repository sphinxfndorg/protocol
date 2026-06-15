// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/server/server/storage.go
package pubkeydir

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

// DefaultDBPath is the default path for the LevelDB database
// Changed to a consistent location: ./server/pubkeydir.db
const DefaultDBPath = "server/pubkeydir.db"

type LevelDBStore struct {
	db *leveldb.DB
}

func NewLevelDBStore(path string) (*LevelDBStore, error) {
	log.Printf("[INFO] NewLevelDBStore: creating new LevelDB store at path: %s", path)

	if path == "" {
		path = DefaultDBPath
		log.Printf("[DEBUG] NewLevelDBStore: using default path: %s", path)
	}

	// Ensure the directory exists
	dir := filepath.Dir(path)
	log.Printf("[DEBUG] NewLevelDBStore: ensuring directory exists: %s", dir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("[ERROR] NewLevelDBStore: failed to create directory %s: %v", dir, err)
		return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	log.Printf("[DEBUG] NewLevelDBStore: directory created/verified")

	log.Printf("[DEBUG] NewLevelDBStore: opening LevelDB at: %s", filepath.Clean(path))
	db, err := leveldb.OpenFile(filepath.Clean(path), nil)
	if err != nil {
		log.Printf("[ERROR] NewLevelDBStore: failed to open LevelDB: %v", err)
		return nil, err
	}
	log.Printf("[SUCCESS] NewLevelDBStore: LevelDB opened successfully")

	return &LevelDBStore{db: db}, nil
}

func NewFileStore(path string) (*LevelDBStore, error) {
	log.Printf("[INFO] NewFileStore: creating file store at path: %s", path)
	return NewLevelDBStore(path)
}

func (s *LevelDBStore) LookupByPublicKey(pubKeyHex string) (PublicKeyBundle, error) {
	log.Printf("[INFO] LookupByPublicKey: looking up bundle by public key hex: %.16s...", pubKeyHex)
	log.Printf("[DEBUG] LookupByPublicKey: full public key hex length: %d chars", len(pubKeyHex))

	if s == nil || s.db == nil {
		log.Printf("[ERROR] LookupByPublicKey: store is closed")
		return PublicKeyBundle{}, errors.New("store is closed")
	}

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		log.Printf("[ERROR] LookupByPublicKey: invalid public key hex: %v", err)
		return PublicKeyBundle{}, fmt.Errorf("invalid public key hex: %w", err)
	}
	log.Printf("[DEBUG] LookupByPublicKey: decoded public key bytes: %d bytes", len(pubKeyBytes))

	fp := Fingerprint(pubKeyBytes)
	log.Printf("[DEBUG] LookupByPublicKey: computed fingerprint: %.16s...", fp)

	bundle, err := s.Get(fp)
	if err != nil {
		log.Printf("[ERROR] LookupByPublicKey: failed to get bundle: %v", err)
		return PublicKeyBundle{}, err
	}

	log.Printf("[SUCCESS] LookupByPublicKey: found bundle for fingerprint: %.16s...", fp)
	return bundle, nil
}

func (s *LevelDBStore) Put(bundle PublicKeyBundle) error {
	fpShort := bundle.Fingerprint
	if len(fpShort) > 16 {
		fpShort = fpShort[:16] + "..."
	}

	log.Printf("[INFO] Put: storing bundle for fingerprint: %s", fpShort)
	log.Printf("[DEBUG] Put: bundle organization: %s, label: %s", bundle.Organization, bundle.Label)
	log.Printf("[DEBUG] Put: signature public key size: %d bytes, KEM public key size: %d bytes",
		len(bundle.SignaturePublicKey), len(bundle.KEMPublicKey))

	if s == nil || s.db == nil {
		log.Printf("[ERROR] Put: public key directory store is closed")
		return errors.New("public key directory store is closed")
	}

	fp, err := NormalizeFingerprint(bundle.Fingerprint)
	if err != nil {
		log.Printf("[ERROR] Put: failed to normalize fingerprint: %v", err)
		return err
	}
	if fp != bundle.Fingerprint {
		log.Printf("[DEBUG] Put: normalized fingerprint from %.16s... to %.16s...", bundle.Fingerprint, fp)
	}
	bundle.Fingerprint = fp

	if bundle.Version == 0 {
		bundle.Version = BundleVersion
		log.Printf("[DEBUG] Put: set bundle version to %d", BundleVersion)
	}
	if bundle.Status == "" {
		bundle.Status = StatusActive
		log.Printf("[DEBUG] Put: set bundle status to %s", StatusActive)
	}

	now := time.Now().UTC()
	if bundle.CreatedAt.IsZero() {
		bundle.CreatedAt = now
		log.Printf("[DEBUG] Put: set created at to %v", now)
	}
	bundle.UpdatedAt = now
	log.Printf("[DEBUG] Put: set updated at to %v", now)

	data, err := json.Marshal(bundle)
	if err != nil {
		log.Printf("[ERROR] Put: failed to marshal bundle: %v", err)
		return err
	}
	log.Printf("[DEBUG] Put: marshaled bundle size: %d bytes", len(data))

	key := bundleKey(fp)
	log.Printf("[DEBUG] Put: storing at key: %s", key)

	if err := s.db.Put(key, data, nil); err != nil {
		log.Printf("[ERROR] Put: failed to store bundle: %v", err)
		return err
	}

	log.Printf("[SUCCESS] Put: bundle stored successfully for fingerprint: %s", fpShort)
	return nil
}

func (s *LevelDBStore) Get(fingerprint string) (PublicKeyBundle, error) {
	fpShort := fingerprint
	if len(fpShort) > 16 {
		fpShort = fpShort[:16] + "..."
	}

	log.Printf("[INFO] Get: retrieving bundle for fingerprint: %s", fpShort)

	if s == nil || s.db == nil {
		log.Printf("[ERROR] Get: public key directory store is closed")
		return PublicKeyBundle{}, errors.New("public key directory store is closed")
	}

	fp, err := NormalizeFingerprint(fingerprint)
	if err != nil {
		log.Printf("[ERROR] Get: failed to normalize fingerprint: %v", err)
		return PublicKeyBundle{}, err
	}
	log.Printf("[DEBUG] Get: normalized fingerprint: %.16s...", fp)

	key := bundleKey(fp)
	log.Printf("[DEBUG] Get: looking up key: %s", key)

	data, err := s.db.Get(key, nil)
	if errors.Is(err, leveldb.ErrNotFound) {
		log.Printf("[INFO] Get: bundle not found for fingerprint: %s", fpShort)
		return PublicKeyBundle{}, ErrNotFound
	}
	if err != nil {
		log.Printf("[ERROR] Get: database error for fingerprint %s: %v", fpShort, err)
		return PublicKeyBundle{}, err
	}
	log.Printf("[DEBUG] Get: retrieved data size: %d bytes", len(data))

	var bundle PublicKeyBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		log.Printf("[ERROR] Get: failed to decode bundle: %v", err)
		return PublicKeyBundle{}, fmt.Errorf("decode public key bundle: %w", err)
	}

	log.Printf("[SUCCESS] Get: bundle retrieved for fingerprint: %s", fpShort)
	log.Printf("[DEBUG] Get: bundle org: %s, status: %s, version: %d", bundle.Organization, bundle.Status, bundle.Version)
	return bundle, nil
}

func (s *LevelDBStore) List() ([]PublicKeyBundle, error) {
	log.Printf("[INFO] List: listing all bundles in store")

	if s == nil || s.db == nil {
		log.Printf("[ERROR] List: public key directory store is closed")
		return nil, errors.New("public key directory store is closed")
	}

	log.Printf("[DEBUG] List: creating database iterator")
	iter := s.db.NewIterator(nil, nil)
	defer iter.Release()

	var out []PublicKeyBundle
	bundleCount := 0

	for iter.Next() {
		key := iter.Key()
		if len(key) < len(bundleKeyPrefix) || string(key[:len(bundleKeyPrefix)]) != bundleKeyPrefix {
			continue
		}

		bundleCount++
		keyStr := string(key)
		log.Printf("[DEBUG] List: processing key: %s", keyStr)

		var bundle PublicKeyBundle
		if err := json.Unmarshal(iter.Value(), &bundle); err != nil {
			log.Printf("[ERROR] List: failed to decode bundle for key %s: %v", keyStr, err)
			return nil, fmt.Errorf("decode public key bundle: %w", err)
		}

		fpShort := bundle.Fingerprint
		if len(fpShort) > 16 {
			fpShort = fpShort[:16] + "..."
		}
		log.Printf("[DEBUG] List: loaded bundle %d - fingerprint: %s, org: %s, status: %s",
			bundleCount, fpShort, bundle.Organization, bundle.Status)

		out = append(out, bundle)
	}

	if err := iter.Error(); err != nil {
		log.Printf("[ERROR] List: iterator error: %v", err)
		return nil, err
	}

	log.Printf("[SUCCESS] List: retrieved %d bundles from store", len(out))
	return out, nil
}

func (s *LevelDBStore) Revoke(fingerprint, reason string) error {
	fpShort := fingerprint
	if len(fpShort) > 16 {
		fpShort = fpShort[:16] + "..."
	}

	log.Printf("[INFO] Revoke: revoking bundle for fingerprint: %s", fpShort)
	log.Printf("[DEBUG] Revoke: reason: %s", reason)

	bundle, err := s.Get(fingerprint)
	if err != nil {
		log.Printf("[ERROR] Revoke: failed to get bundle for fingerprint %s: %v", fpShort, err)
		return err
	}

	oldStatus := bundle.Status
	now := time.Now().UTC()
	bundle.Status = StatusRevoked
	bundle.RevokedAt = now
	bundle.RevocationReason = reason
	bundle.UpdatedAt = now

	log.Printf("[DEBUG] Revoke: changing status from %s to %s", oldStatus, StatusRevoked)
	log.Printf("[DEBUG] Revoke: revoked at: %v, reason: %s", now, reason)

	if err := s.Put(bundle); err != nil {
		log.Printf("[ERROR] Revoke: failed to store revoked bundle: %v", err)
		return err
	}

	log.Printf("[SUCCESS] Revoke: bundle revoked successfully for fingerprint: %s", fpShort)
	return nil
}

func (s *LevelDBStore) Close() error {
	log.Printf("[INFO] Close: closing LevelDB store")

	if s == nil || s.db == nil {
		log.Printf("[DEBUG] Close: store already closed or nil")
		return nil
	}

	err := s.db.Close()
	if err != nil {
		log.Printf("[ERROR] Close: error closing database: %v", err)
	} else {
		log.Printf("[SUCCESS] Close: database closed successfully")
	}
	s.db = nil
	return err
}

const bundleKeyPrefix = "bundle:"

func bundleKey(fingerprint string) []byte {
	key := []byte(bundleKeyPrefix + fingerprint)
	log.Printf("[DEBUG] bundleKey: generated key: %s", key)
	return key
}
