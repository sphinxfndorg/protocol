// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/wallet/burn/burn.go
//
// Burn-coin address package.
//
// A burn address is only *provably* unspendable if nobody ever held a private
// key for it. The old ceremony generated a real SPHINCS+ key pair on a machine
// and then tried to wipe it: anyone who copied that process's memory (or
// simply ran modified code) kept a working key, and Go cannot reliably wipe
// the key manager's own copies. This version never creates a usable key at
// all: the "public key" is a nothing-up-my-sleeve value, SHAKE256 of a public
// label (and optional tag), so finding a signing key for it would mean
// inverting the hash.
package burn

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/sphinxfndorg/protocol/src/common"
	sphincs "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
	"golang.org/x/crypto/sha3"
)

const burnNUMSLabel = "sphinx-burn-address-nums-v1"

// BurnAddressInfo is the public, auditable result. It contains NO private
// material, because none ever exists.
type BurnAddressInfo struct {
	Address      string `json:"address"`
	PublicKeyHex string `json:"public_key_hex"`
	OrgCode      string `json:"org_code"`
}

// numsPublicKey expands label+tag into n pseudo-public-key bytes.
func numsPublicKey(tag string, n int) []byte {
	sh := sha3.NewShake256()
	sh.Write([]byte(burnNUMSLabel))
	sh.Write([]byte{0})
	sh.Write([]byte(tag))
	out := make([]byte, n)
	sh.Read(out)
	return out
}

// serializedPKLen returns the serialized public-key length of the configured
// SPHINCS+ parameter set, so the burn "key" has the same shape as a real one.
func serializedPKLen() (int, error) {
	km, err := sphincs.NewKeyManager()
	if err != nil {
		return 0, fmt.Errorf("initialize SPHINCS+ key manager: %w", err)
	}
	// The generated key pair is used only to measure the length and is dropped.
	_, pk, err := km.GenerateKey()
	if err != nil {
		return 0, fmt.Errorf("measure public key length: %w", err)
	}
	b, err := pk.SerializePK()
	if err != nil {
		return 0, fmt.Errorf("serialize public key: %w", err)
	}
	n := len(b)
	wipeBytes(b)
	return n, nil
}

// GenerateBurnAddress returns the default (empty-tag) provably unspendable
// burn address. It is deterministic: everyone derives the same address.
func GenerateBurnAddress() (*BurnAddressInfo, error) {
	return GenerateBurnAddressTagged("")
}

// GenerateBurnAddressTagged returns a burn address for a public tag
// (for example "genesis" or "fees"), so different purposes can have separate,
// independently auditable burn addresses.
func GenerateBurnAddressTagged(tag string) (*BurnAddressInfo, error) {
	n, err := serializedPKLen()
	if err != nil {
		return nil, err
	}
	pkBytes := numsPublicKey(tag, n)

	raw := keys.SHAKE256HashWithOrg(pkBytes, keys.OrgDEAD)
	address := keys.FormatOrgAddress(raw, keys.OrgDEAD)

	info := &BurnAddressInfo{
		Address:      address,
		PublicKeyHex: hex.EncodeToString(pkBytes),
		OrgCode:      string(keys.OrgDEAD),
	}
	log.Printf("[SUCCESS] GenerateBurnAddress: burn address %s (nothing-up-my-sleeve, no private key exists)", address)
	return info, nil
}

// DefaultBurnAddressInfo returns the protocol's hardcoded default burn
// address (see common.DefaultBurnAddress) as a BurnAddressInfo.
func DefaultBurnAddressInfo() *BurnAddressInfo {
	return &BurnAddressInfo{
		Address:      common.DefaultBurnAddress,
		PublicKeyHex: common.DefaultBurnPublicKeyHex,
		OrgCode:      string(keys.OrgDEAD),
	}
}

// VerifyBurnAddress recomputes the DEAD address from a public key and checks
// it matches the claimed address.
func VerifyBurnAddress(publicKeyHex, address string) error {
	pkBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return fmt.Errorf("invalid public key hex: %w", err)
	}
	raw := keys.SHAKE256HashWithOrg(pkBytes, keys.OrgDEAD)
	want := keys.FormatOrgAddress(raw, keys.OrgDEAD)
	gotNorm, err := keys.NormalizeOrgAddress(address)
	if err != nil {
		return fmt.Errorf("invalid burn address: %w", err)
	}
	wantNorm, err := keys.NormalizeOrgAddress(want)
	if err != nil {
		return fmt.Errorf("internal error re-deriving burn address: %w", err)
	}
	if gotNorm != wantNorm {
		return fmt.Errorf("burn address mismatch: public key derives %q, got %q", want, address)
	}
	return nil
}

// VerifyProvablyUnspendable checks that publicKeyHex is exactly the
// nothing-up-my-sleeve value for tag, i.e. that no private key can exist for it
// short of breaking SHAKE256. VerifyBurnAddress alone only proves the address
// matches *some* public key; this proves that key is the NUMS one.
func VerifyProvablyUnspendable(publicKeyHex, tag string) error {
	pkBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return fmt.Errorf("invalid public key hex: %w", err)
	}
	if !bytes.Equal(pkBytes, numsPublicKey(tag, len(pkBytes))) {
		return fmt.Errorf("public key is not the nothing-up-my-sleeve value for tag %q", tag)
	}
	return nil
}

// wipeBytes overwrites b with zeros.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
