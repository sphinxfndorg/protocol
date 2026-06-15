// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/types/types.go
package types

import (
	"encoding/hex"
	"time"
)

// Meta holds all cryptographic and descriptive metadata for a signed document.
// It is serialised to the .ecpmeta sidecar and embedded into format-specific
// metadata containers (PDF properties, XMP, Office custom properties, xattrs).
type Meta struct {
	// Cryptographic fields
	Signature         string `json:"signature"`
	PublicKey         string `json:"public_key"`
	FileHash          string `json:"file_hash"`
	FinalDocumentHash string `json:"final_document_hash"`
	DocumentSignature string `json:"document_signature"`

	// Organisation — carried with the file so any device can route the lookup
	OrgCode string `json:"org_code,omitempty"` // "TNAL", "TNAD", "PLRI", etc.

	// Timestamps
	Timestamp          int64 `json:"timestamp"`
	SignatureTimestamp int64 `json:"signature_timestamp"`

	// Entropy
	Nonce string `json:"nonce"`

	// Descriptive
	Signer        string `json:"signer,omitempty"`
	DocumentTitle string `json:"document_title,omitempty"`
}

// GetPublicKeyPreview returns a shortened preview of the public key
func (m *Meta) GetPublicKeyPreview() string {
	if len(m.PublicKey) > 12 {
		return m.PublicKey[:12] + "..."
	}
	return m.PublicKey
}

// IsExpired checks if the signature is older than maxAge
func (m *Meta) IsExpired(maxAge time.Duration) bool {
	ts := m.SignatureTimestamp
	if ts == 0 {
		ts = m.Timestamp
	}
	if ts == 0 {
		return false
	}
	sigTime := time.Unix(ts, 0)
	return time.Since(sigTime) > maxAge
}

// HasSignature returns true if the meta contains a signature
func (m *Meta) HasSignature() bool {
	return m.Signature != "" && m.PublicKey != ""
}

// Clone creates a deep copy of the Meta
func (m *Meta) Clone() *Meta {
	if m == nil {
		return nil
	}
	return &Meta{
		Signature:          m.Signature,
		PublicKey:          m.PublicKey,
		FileHash:           m.FileHash,
		FinalDocumentHash:  m.FinalDocumentHash,
		DocumentSignature:  m.DocumentSignature,
		Timestamp:          m.Timestamp,
		SignatureTimestamp: m.SignatureTimestamp,
		Nonce:              m.Nonce,
		Signer:             m.Signer,
		DocumentTitle:      m.DocumentTitle,
	}
}

// ComputeFileHashFromBytes is a helper to compute hash from bytes
func ComputeFileHashFromBytes(data []byte) string {
	// This will be implemented by sign package or here with crypto
	// For now, just a placeholder - actual implementation should use SHAKE256
	return hex.EncodeToString(data[:32])
}
