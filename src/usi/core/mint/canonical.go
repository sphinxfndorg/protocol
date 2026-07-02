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

// canonicalReceiptBytesV2 is the corrected deterministic serialization.
func canonicalReceiptBytes(r *MintReceipt) ([]byte, error) {
	var metaKV [][2]string
	if r.Metadata != nil {
		metaKV = make([][2]string, 0, len(r.Metadata))
		for k, v := range r.Metadata {
			metaKV = append(metaKV, [2]string{k, v})
		}
		sort.Slice(metaKV, func(i, j int) bool { return metaKV[i][0] < metaKV[j][0] })
	}

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

	// Metadata canonical form
	// encode as JSON of array of [key,value] sorted
	var metaArr [][2]string = metaKV
	metaJSON, _ := json.Marshal(metaArr)
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
