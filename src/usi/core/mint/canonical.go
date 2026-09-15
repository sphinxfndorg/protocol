// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// canonicalReceiptBytes is the corrected deterministic serialization.
func canonicalReceiptBytes(r *MintReceipt) ([]byte, error) {
	// Always build a non-nil, possibly-empty slice. MintReceipt.Metadata is
	// `json:"metadata,omitempty"`, so a freshly-minted receipt (Metadata =
	// map[string]string{}) drops the field entirely on disk; LoadReceipt then
	// comes back with Metadata == nil. Branching on r.Metadata != nil made
	// those two states canonicalize differently (json.Marshal([][2]string{})
	// -> "[]" vs json.Marshal(nil) -> "null"), so a receipt failed Verify
	// after every save/load round-trip even though nothing about it changed.
	// Ranging a nil map is legal and yields zero iterations, so this is safe
	// for both cases and always produces "[]" for empty metadata.
	metaKV := make([][2]string, 0, len(r.Metadata))
	for k, v := range r.Metadata {
		metaKV = append(metaKV, [2]string{k, v})
	}
	sort.Slice(metaKV, func(i, j int) bool { return metaKV[i][0] < metaKV[j][0] })

	mintID := strings.TrimSpace(r.MintID)
	subject := strings.TrimSpace(r.Subject)
	payloadHash := strings.ToLower(strings.TrimSpace(r.PayloadHash))
	orgCode := strings.TrimSpace(r.OrgCode)
	minterPK := strings.ToLower(strings.TrimSpace(r.MinterPublicKey))

	// Use this variable to avoid unused-import/unused-var issues in the deprecated draft.
	_ = mintID
	_ = payloadHash
	_ = subject
	_ = orgCode
	_ = minterPK

	var buf bytes.Buffer
	// Version (u32)
	_ = binary.Write(&buf, binary.BigEndian, r.Version)

	writeU64 := func(v uint64) {
		_ = binary.Write(&buf, binary.BigEndian, v)
	}
	writeU32 := func(v uint32) {
		_ = binary.Write(&buf, binary.BigEndian, v)
	}
	writeBytes := func(b []byte) {
		writeU32(uint32(len(b)))
		buf.Write(b)
	}
	writeStr := func(s string) {
		writeBytes([]byte(s))
	}

	// Timestamp
	writeU64(uint64(r.Timestamp))

	// Receipt core fields
	writeStr(mintID)
	writeStr(subject)
	writeStr(payloadHash)
	writeStr(orgCode)
	writeStr(minterPK)

	// Metadata canonical form: JSON array of [key,value] pairs, sorted.
	// metaKV is always a non-nil (possibly empty) slice, so this is always
	// "[]" for no metadata — never "null" — regardless of whether the
	// receipt was just built by Mint() or reloaded from disk via LoadReceipt.
	metaJSON, err := json.Marshal(metaKV)
	if err != nil {
		return nil, err
	}
	writeBytes(metaJSON)

	// RequireExternalPayload
	if r.RequireExternalPayload {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}

	return buf.Bytes(), nil
}

// DecodeMinterPublicKeyHex decodes hex-encoded public key bytes.
func DecodeMinterPublicKeyHex(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}
