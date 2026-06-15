// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/server/server/types.go
package pubkeydir

import (
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

const (
	BundleVersion = 1
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

var (
	ErrNotFound            = errors.New("public key bundle not found")
	ErrInvalidFingerprint  = errors.New("invalid fingerprint")
	ErrFingerprintMismatch = errors.New("fingerprint does not match signature public key")
	ErrInvalidSignature    = errors.New("invalid KEM public key signature")
	ErrRevoked             = errors.New("public key bundle is revoked")
)

type PublicKeyBundle struct {
	Version               int       `json:"version"`
	Fingerprint           string    `json:"fingerprint"`
	Label                 string    `json:"label,omitempty"`
	Organization          string    `json:"organization,omitempty"`
	SignaturePublicKey    []byte    `json:"signature_public_key"`
	KEMPublicKey          []byte    `json:"kem_public_key"`
	KEMPublicKeySignature []byte    `json:"kem_public_key_signature"`
	KEMAlgorithm          string    `json:"kem_algorithm"`
	SignatureAlgorithm    string    `json:"signature_algorithm"`
	Status                string    `json:"status"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
	RevokedAt             time.Time `json:"revoked_at,omitempty"`
	RevocationReason      string    `json:"revocation_reason,omitempty"`
}

type Store interface {
	Put(bundle PublicKeyBundle) error
	Get(fingerprint string) (PublicKeyBundle, error)
	List() ([]PublicKeyBundle, error)
	Revoke(fingerprint, reason string) error
	LookupByPublicKey(pubKeyHex string) (PublicKeyBundle, error)
	Close() error
}

type Verifier interface {
	Verify(publicKey, message, signature []byte) bool
}

type VerifierFunc func(publicKey, message, signature []byte) bool

func (fn VerifierFunc) Verify(publicKey, message, signature []byte) bool {
	return fn(publicKey, message, signature)
}

func NewBundle(label, organization string, signaturePublicKey, kemPublicKey []byte, verifierSignature []byte) PublicKeyBundle {
	now := time.Now().UTC()
	return PublicKeyBundle{
		Version:               BundleVersion,
		Fingerprint:           Fingerprint(signaturePublicKey),
		Label:                 label,
		Organization:          organization,
		SignaturePublicKey:    append([]byte(nil), signaturePublicKey...),
		KEMPublicKey:          append([]byte(nil), kemPublicKey...),
		KEMPublicKeySignature: append([]byte(nil), verifierSignature...),
		KEMAlgorithm:          "ML-KEM-768",
		SignatureAlgorithm:    "SPHINCS+",
		Status:                StatusActive,
		CreatedAt:             now,
		UpdatedAt:             now,
	}
}

func Fingerprint(publicKey []byte) string {
	sum := sha3.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

func NormalizeFingerprint(fp string) (string, error) {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fp), " ", ""))
	normalized = strings.ReplaceAll(normalized, ":", "")
	if len(normalized) != 64 {
		return "", ErrInvalidFingerprint
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", ErrInvalidFingerprint
	}
	return normalized, nil
}

func BindingMessage(fingerprint string, kemPublicKey []byte) []byte {
	msg := make([]byte, 0, len("ECP-KEM-BINDING-V1|")+len(fingerprint)+1+len(kemPublicKey))
	msg = append(msg, "ECP-KEM-BINDING-V1|"...)
	msg = append(msg, fingerprint...)
	msg = append(msg, '|')
	msg = append(msg, kemPublicKey...)
	return msg
}

func ValidateBundle(bundle PublicKeyBundle, verifier Verifier) error {
	fp, err := NormalizeFingerprint(bundle.Fingerprint)
	if err != nil {
		return err
	}
	if Fingerprint(bundle.SignaturePublicKey) != fp {
		return ErrFingerprintMismatch
	}
	if bundle.Status == StatusRevoked {
		return ErrRevoked
	}
	if verifier != nil {
		msg := BindingMessage(fp, bundle.KEMPublicKey)
		if !verifier.Verify(bundle.SignaturePublicKey, msg, bundle.KEMPublicKeySignature) {
			return ErrInvalidSignature
		}
	}
	return nil
}
