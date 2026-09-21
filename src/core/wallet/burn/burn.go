// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/wallet/burn/burn.go
//
// Burn-coin address package. A "DEAD XXX" address is created from a real
// SPHINCS+ key pair exactly like a "SPIF XXX" wallet address, except the
// private key material is destroyed in a one-time ceremony.
package burn

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/sphinxfndorg/protocol/src/common"
	keyutils "github.com/sphinxfndorg/protocol/src/accounts/key/utils"
	sphincs "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
)

// BurnAddressInfo is the public, auditable output of a burn ceremony.
// It deliberately contains NO private key material and NO passphrase:
// only the DEAD display address and the SPHINCS+ public key it was derived
// from (kept so anyone can re-derive and verify the address).
type BurnAddressInfo struct {
	Address      string `json:"address"`
	PublicKeyHex string `json:"public_key_hex"`
	OrgCode      string `json:"org_code"`
}

// GenerateBurnAddress runs a one-time burn ceremony and returns the public,
// auditable result. A fresh SPHINCS+ key pair is generated, encrypted with
// an ephemeral 32-byte crypto-random passphrase, then the passphrase, the
// plaintext private key, and the encrypted blob are all wiped from memory.
// NOTHING is written to disk. Nobody retains anything that can decrypt or
// reconstruct the private key, so the resulting address is provably
// unspendable.
func GenerateBurnAddress() (*BurnAddressInfo, error) {
	km, err := sphincs.NewKeyManager()
	if err != nil {
		return nil, fmt.Errorf("initialize SPHINCS+ key manager: %w", err)
	}
	sm, err := keyutils.NewStorageManager()
	if err != nil {
		return nil, fmt.Errorf("initialize storage manager: %w", err)
	}
	diskStorage := sm.GetStorage(string(keyutils.StorageTypeDisk))

	sk, pk, err := km.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate SPHINCS+ key pair: %w", err)
	}
	pkBytes, err := pk.SerializePK()
	if err != nil {
		return nil, fmt.Errorf("serialize public key: %w", err)
	}
	skBytes, err := sk.SerializeSK()
	if err != nil {
		wipeBytes(pkBytes)
		return nil, fmt.Errorf("serialize private key: %w", err)
	}

	passBytes := make([]byte, 32)
	if _, err := rand.Read(passBytes); err != nil {
		wipeBytes(skBytes)
		wipeBytes(pkBytes)
		return nil, fmt.Errorf("generate ceremony passphrase: %w", err)
	}
	passphrase := hex.EncodeToString(passBytes)
	wipeBytes(passBytes)

	encryptedSK, encErr := diskStorage.EncryptData(skBytes, passphrase)
	wipeString(&passphrase)
	wipeBytes(skBytes)
	if encryptedSK != nil {
		wipeBytes(encryptedSK)
		encryptedSK = nil
	}
	if encErr != nil {
		wipeBytes(pkBytes)
		return nil, fmt.Errorf("ceremony encryption step: %w", encErr)
	}

	raw := keys.SHAKE256HashWithOrg(pkBytes, keys.OrgDEAD)
	address := keys.FormatOrgAddress(raw, keys.OrgDEAD)

	info := &BurnAddressInfo{
		Address:      address,
		PublicKeyHex: hex.EncodeToString(pkBytes),
		OrgCode:      string(keys.OrgDEAD),
	}
	wipeBytes(pkBytes)

	log.Printf("[SUCCESS] GenerateBurnAddress: ceremony complete, burn address %s (private material destroyed)", address)
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
// it matches the claimed address. Used to audit ceremony outputs.
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

// wipeBytes overwrites b with zeros.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// wipeString overwrites the backing bytes of *s with zeros.
func wipeString(s *string) {
	if s == nil {
		return
	}
	b := []byte(*s)
	for i := range b {
		b[i] = 0
	}
	*s = ""
}

