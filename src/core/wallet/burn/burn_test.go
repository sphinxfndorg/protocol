// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package burn

import (
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
)

func TestGenerateBurnAddressCeremony(t *testing.T) {
	info, err := GenerateBurnAddress()
	if err != nil {
		t.Fatalf("GenerateBurnAddress: %v", err)
	}
	if !common.IsBurnAddress(info.Address) {
		t.Fatalf("ceremony address %q not detected as burn", info.Address)
	}
	if err := VerifyBurnAddress(info.PublicKeyHex, info.Address); err != nil {
		t.Fatalf("VerifyBurnAddress: %v", err)
	}
	if info.Address == common.DefaultBurnAddress {
		t.Fatalf("fresh ceremony reproduced the default burn address — RNG failure?")
	}
}

func TestVerifyDefaultBurnAddress(t *testing.T) {
	if err := VerifyBurnAddress(common.DefaultBurnPublicKeyHex, common.DefaultBurnAddress); err != nil {
		t.Fatalf("default burn address does not re-derive from its public key: %v", err)
	}
}

func TestDefaultBurnAddressInfo(t *testing.T) {
	info := DefaultBurnAddressInfo()
	if info.Address != common.DefaultBurnAddress {
		t.Fatalf("DefaultBurnAddressInfo address mismatch: got %q", info.Address)
	}
	if info.PublicKeyHex != common.DefaultBurnPublicKeyHex {
		t.Fatalf("DefaultBurnAddressInfo pubkey mismatch: got %q", info.PublicKeyHex)
	}
	if info.OrgCode != common.DEADPrefix {
		t.Fatalf("DefaultBurnAddressInfo org mismatch: got %q", info.OrgCode)
	}
}
