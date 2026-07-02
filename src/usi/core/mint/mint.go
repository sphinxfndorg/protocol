// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"

	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
	"github.com/sphinxfndorg/protocol/src/usi/core/sign"
)

// Mint creates a signed MintReceipt for arbitrary payload bytes.
//
// Subject is a user-defined token/asset identifier.
// payload can be any bytes.
// cid is the IPFS content hash (optional, can be "").
// metadataURI is an ERC-721 style metadata URI (optional, can be "").
func Mint(payload []byte, subject string, passphrase string, orgCode string, cid string, metadataURI string) (*MintResult, error) {
	if passphrase == "" {
		return nil, errors.New("passphrase required")
	}
	if subject == "" {
		return nil, errors.New("subject required")
	}

	// Load key to embed fingerprint and public key.
	kp, _, err := keys.LoadKeyFromDisk(passphrase)
	if err != nil {
		return nil, fmt.Errorf("load key: %w", err)
	}
	minterPKHex := hex.EncodeToString(kp.PublicKey)

	if orgCode == "" {
		orgCode = "SPIF"
	}
	payloadHashWithOrg := keys.SHAKE256HashWithOrg(payload, keys.OrgCode(orgCode))
	payloadHashHex := hex.EncodeToString(payloadHashWithOrg)

	// Deterministic mint id: SHA3-256(minterPKHex || subject || payloadHashHex)
	// This ensures globally unique, deterministic mint IDs.
	mintIDInput := []byte(minterPKHex + ":" + subject + ":" + payloadHashHex)
	mintIDHash := sha3.Sum256(mintIDInput)
	mintID := hex.EncodeToString(mintIDHash[:])

	rec := &MintReceipt{
		Version:                ReceiptVersion,
		MintID:                 mintID,
		Subject:                subject,
		PayloadHash:            payloadHashHex,
		CID:                    cid,
		MetadataURI:            metadataURI,
		OrgCode:                orgCode,
		Timestamp:              time.Now().Unix(),
		MinterPublicKey:        minterPKHex,
		MinterFingerprint:      "",
		SignatureHex:           "",
		Metadata:               map[string]string{},
		RequireExternalPayload: true,
	}

	// Canonical bytes to sign.
	canon, err := canonicalReceiptBytes(rec)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}

	// Sign canonical receipt bytes.
	// sign.Sign expects msg bytes (it logs message hash but uses msg directly).
	sig, err := sign.Sign(canon, passphrase)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// Verify quickly that embedded pk matches loaded kp.
	if subtle.ConstantTimeCompare(sig.PublicKey, kp.PublicKey) != 1 {
		return nil, errors.New("mint: signing public key mismatch")
	}

	rec.SignatureHex = hex.EncodeToString(sig.Signature)

	res := &MintResult{Receipt: rec}
	return res, nil
}
