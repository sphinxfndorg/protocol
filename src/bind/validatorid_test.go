// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package bind

import (
	"fmt"
	"strings"
	"testing"
)

// testValidatorPK returns a deterministic 32-byte stand-in for a validator
// public key. Derivation only hashes the bytes, so a fixed pattern exercises the
// same path as a real SPHINCS+ key without the keygen cost.
func testValidatorPK(seed int) []byte {
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = byte(seed*31 + i*7)
	}
	return pk
}

// TestValidatorIDFromPublicKey_Deterministic pins that the same key always yields
// the same identity across repeated derivations.
func TestValidatorIDFromPublicKey_Deterministic(t *testing.T) {
	pk := testValidatorPK(1)
	first, err := ValidatorIDFromPublicKey(pk)
	if err != nil {
		t.Fatalf("derive validator id: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := ValidatorIDFromPublicKey(pk)
		if err != nil {
			t.Fatalf("derive validator id (repeat %d): %v", i, err)
		}
		if again != first {
			t.Fatalf("derivation %d = %q, want %q", i, again, first)
		}
	}
	if !strings.HasPrefix(first, ValidatorIDPrefix) {
		t.Errorf("validator id %q must carry the %q prefix", first, ValidatorIDPrefix)
	}
	// A validator identity must never be confusable with a spendable address.
	if strings.HasPrefix(first, "SPIF") {
		t.Errorf("validator id %q must not be a bare SPIF address", first)
	}
}

// TestValidatorIDFromPublicKey_DistinctPerKey pins that two different validators
// never collide.
func TestValidatorIDFromPublicKey_DistinctPerKey(t *testing.T) {
	seen := map[string]int{}
	for i := 1; i <= 8; i++ {
		id, err := ValidatorIDFromPublicKey(testValidatorPK(i))
		if err != nil {
			t.Fatalf("derive validator id for key %d: %v", i, err)
		}
		if prev, dup := seen[id]; dup {
			t.Fatalf("key %d and key %d both derive validator id %q", prev, i, id)
		}
		seen[id] = i
	}
}

// TestValidatorIDFromPublicKey_PortIndependent is the property that motivates
// this identity form: the validator id must NOT depend on the node's listen
// address, which is exactly what the address-derived "Node-<host:port>" form
// does.
func TestValidatorIDFromPublicKey_PortIndependent(t *testing.T) {
	keyDerived, err := ValidatorIDFromPublicKey(testValidatorPK(42))
	if err != nil {
		t.Fatalf("derive validator id: %v", err)
	}

	// The same validator, presented at two different listen addresses.
	addrA := "Node-127.0.0.1:30303"
	addrB := "Node-127.0.0.1:44444"
	if addrA == addrB {
		t.Fatal("fixture addresses must differ")
	}
	if addrA == keyDerived || addrB == keyDerived {
		t.Fatal("the address-derived id must differ from the key-derived id")
	}
	// Derivation consumes only key material, so the id cannot embed an address.
	for _, addr := range []string{addrA, addrB} {
		if strings.Contains(keyDerived, addr) || strings.Contains(keyDerived, "127.0.0.1") {
			t.Errorf("validator id %q must not embed a listen address (%s)", keyDerived, addr)
		}
	}

	// Re-deriving from the same key after those addresses were in play still
	// yields the identical id — the address never enters the computation.
	again, err := ValidatorIDFromPublicKey(testValidatorPK(42))
	if err != nil {
		t.Fatalf("re-derive validator id: %v", err)
	}
	if again != keyDerived {
		t.Errorf("re-derivation = %q, want %q", again, keyDerived)
	}
}

// TestValidatorIDAliases_RoundTrip pins the bidirectional mapping between the two
// identity forms and the refusals that keep it consistent.
func TestValidatorIDAliases_RoundTrip(t *testing.T) {
	reg := NewValidatorIDAliases()
	const addrID = "Node-127.0.0.1:30303"
	keyID, err := ValidatorIDFromPublicKey(testValidatorPK(7))
	if err != nil {
		t.Fatalf("derive validator id: %v", err)
	}
	if err := reg.Register(ValidatorIDAliasEntry{
		KeyDerivedID:  keyID,
		AddressID:     addrID,
		PublicKeyHex:  "00ff",
		ListenAddress: "127.0.0.1:30303",
	}); err != nil {
		t.Fatalf("register alias: %v", err)
	}

	if got, ok := reg.AddressIDFor(keyID); !ok || got != addrID {
		t.Errorf("AddressIDFor(%q) = %q,%v; want %q,true", keyID, got, ok, addrID)
	}
	if got, ok := reg.KeyDerivedIDFor(addrID); !ok || got != keyID {
		t.Errorf("KeyDerivedIDFor(%q) = %q,%v; want %q,true", addrID, got, ok, keyID)
	}
	if reg.Len() != 1 {
		t.Errorf("Len() = %d, want 1", reg.Len())
	}

	// An idempotent re-register of the same pair must be accepted.
	if err := reg.Register(ValidatorIDAliasEntry{KeyDerivedID: keyID, AddressID: addrID}); err != nil {
		t.Errorf("re-registering the identical alias must be idempotent, got %v", err)
	}
	// Remapping one key-derived id to a different address must be refused.
	if err := reg.Register(ValidatorIDAliasEntry{KeyDerivedID: keyID, AddressID: "Node-10.0.0.9:1"}); err == nil {
		t.Error("remapping a registered validator id must be refused")
	}
	// Incomplete entries must be refused.
	if err := reg.Register(ValidatorIDAliasEntry{AddressID: "Node-x"}); err == nil {
		t.Error("an entry without a key-derived id must be refused")
	}
	if err := reg.Register(ValidatorIDAliasEntry{KeyDerivedID: keyID}); err == nil {
		t.Error("an entry without an address-derived id must be refused")
	}
	// Unknown lookups must miss, not panic.
	if _, ok := reg.AddressIDFor("VKID-nope"); ok {
		t.Error("unknown key-derived id must not resolve")
	}
	if _, ok := reg.KeyDerivedIDFor("Node-nope"); ok {
		t.Error("unknown address id must not resolve")
	}
}

// TestValidatorIDAliases_ManyValidators pins the mapping at a realistic size.
func TestValidatorIDAliases_ManyValidators(t *testing.T) {
	reg := NewValidatorIDAliases()
	const n = 12
	for i := 0; i < n; i++ {
		keyID, err := ValidatorIDFromPublicKey(testValidatorPK(100 + i))
		if err != nil {
			t.Fatalf("derive validator id %d: %v", i, err)
		}
		addrID := fmt.Sprintf("Node-127.0.0.1:%d", 30303+i)
		if err := reg.Register(ValidatorIDAliasEntry{KeyDerivedID: keyID, AddressID: addrID}); err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
	}
	if reg.Len() != n {
		t.Errorf("Len() = %d, want %d", reg.Len(), n)
	}
}

// TestValidatorIDFromPublicKey_RejectsEmpty pins the one input that cannot
// produce a meaningful identity.
func TestValidatorIDFromPublicKey_RejectsEmpty(t *testing.T) {
	if _, err := ValidatorIDFromPublicKey(nil); err == nil {
		t.Error("a nil public key must be refused")
	}
	if _, err := ValidatorIDFromPublicKey([]byte{}); err == nil {
		t.Error("an empty public key must be refused")
	}
}
