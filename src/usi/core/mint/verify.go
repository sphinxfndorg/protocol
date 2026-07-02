// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
	"github.com/sphinxfndorg/protocol/src/usi/core/sign"
)

// Verify validates a MintReceipt.
// Returns (true,nil) when signature and payload hash are consistent.
//
// payload is optional: if receipt.RequireExternalPayload is true, payload MUST be provided.
func Verify(receipt *MintReceipt, payload []byte) (bool, error) {
	if receipt == nil {
		return false, errors.New("nil receipt")
	}
	if receipt.Version != ReceiptVersion {
		// still attempt verify if forward compatible, but currently require exact match.
		return false, fmt.Errorf("unsupported receipt version: %d", receipt.Version)
	}
	if receipt.MinterPublicKey == "" {
		return false, errors.New("missing minter public key")
	}
	if receipt.SignatureHex == "" {
		return false, errors.New("missing signature")
	}

	if receipt.RequireExternalPayload {
		if len(payload) == 0 {
			return false, errors.New("external payload required but missing")
		}
	}

	// If payload is provided, verify payload-hash consistency.
	if len(payload) > 0 {
		h := canonicalPayloadHashHex(payload, receipt.OrgCode)
		if h != receipt.PayloadHash {
			return false, fmt.Errorf("payload hash mismatch")
		}
	}

	// Canonical bytes must match what the minter signed.
	canon, err := canonicalReceiptBytes(receipt)
	if err != nil {
		return false, fmt.Errorf("canonicalize receipt: %w", err)
	}

	sigBytes, err := hex.DecodeString(receipt.SignatureHex)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	pkBytes, err := hex.DecodeString(receipt.MinterPublicKey)
	if err != nil {
		return false, fmt.Errorf("decode public key: %w", err)
	}

	sig := &sign.Signature{Signature: sigBytes, PublicKey: pkBytes}
	ok, err := sign.Verify(canon, sig, pkBytes)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, errors.New("invalid mint signature")
	}

	// Optional timestamp sanity check (future-only guard).
	if receipt.Timestamp > 0 {
		if time.Unix(receipt.Timestamp, 0).After(time.Now().Add(10 * time.Second)) {
			return false, errors.New("mint timestamp in the future")
		}
	}

	return true, nil
}

func canonicalPayloadHashHex(payload []byte, orgCode string) string {
	if orgCode == "" {
		orgCode = "SPIF"
	}
	// IMPORTANT: keep in sync with mint.Mint().
	// mint.Mint() currently uses keys.SHAKE256HashWithOrg which is org-prefixed+checksum.
	// To avoid importing keys here (and to keep the code building), we re-implement
	// by signing receipt bytes only; but Verify must match Mint().
	//
	// We'll do a local dependency-free fallback: if hashing changes, verification will fail.
	// Therefore, we currently call the same canonical hash as Mint(): hex of SHAKE256HashWithOrg.
	// Recompute payload hash in the same way Mint() does.
	if orgCode == "" {
		orgCode = "SPIF"
	}
	h := keys.SHAKE256HashWithOrg(payload, keys.OrgCode(orgCode))
	return hex.EncodeToString(h)
}
