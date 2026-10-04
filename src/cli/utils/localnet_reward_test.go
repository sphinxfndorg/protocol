package utils

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
)

// TestLocalnetRewardAddressIsSPIFFormatted pins that a localnet reward address
// is a real, key-derived SPIF address.
//
// The obvious shape-only test would pass for a fabricated constant — that is the
// trap this file exists to close. common.ValidateSPIFAddress checks prefix and
// hex length and nothing else, so formatting an invented value yields a string
// that "looks valid" while corresponding to no key pair. These cases instead
// assert the property that actually matters: the address is reproducible from
// the validator's own SPHINCS+ public key.
func TestLocalnetRewardAddressIsSPIFFormatted(t *testing.T) {
	// Two distinct 32-byte keys standing in for SPHINCS+ public keys.
	keyA := bytes32(0x11)
	keyB := bytes32(0x22)

	addrA, err := localnetRewardAddress(keyA)
	if err != nil {
		t.Fatalf("localnetRewardAddress(keyA): %v", err)
	}
	addrB, err := localnetRewardAddress(keyB)
	if err != nil {
		t.Fatalf("localnetRewardAddress(keyB): %v", err)
	}

	for name, addr := range map[string]string{"keyA": addrA, "keyB": addrB} {
		if !common.ValidateSPIFAddress(addr) {
			t.Fatalf("%s: %q is not a valid SPIF address", name, addr)
		}
		// The derivation returns the CANONICAL raw-hex form (no prefix) — the
		// same spelling genesis and the state DB use.
		raw := common.CanonicalSPIFAddress(addr)
		if addr != raw {
			t.Fatalf("%s: %q is not in canonical form (want %q)", name, addr, raw)
		}
		if len(raw) != 64 {
			t.Fatalf("%s: body = %d hex chars, want 64", name, len(raw))
		}
		if _, err := hex.DecodeString(raw); err != nil {
			t.Fatalf("%s: body %q is not hex: %v", name, raw, err)
		}
		// And it renders to the SPIF display form on demand.
		display, err := common.FormatSPIFAddress(raw)
		if err != nil {
			t.Fatalf("%s: FormatSPIFAddress(%q): %v", name, raw, err)
		}
		if !strings.HasPrefix(display, common.SPIFPrefix+" ") {
			t.Fatalf("%s: display form %q lacks the %s prefix", name, display, common.SPIFPrefix)
		}
	}

	// Deterministic: the same key always yields the same address, so every
	// node reading the genesis file derives the identical value.
	again, err := localnetRewardAddress(keyA)
	if err != nil {
		t.Fatalf("localnetRewardAddress(keyA) second call: %v", err)
	}
	if again != addrA {
		t.Fatalf("derivation is not deterministic: %q vs %q", again, addrA)
	}

	// Distinct keys must not collide, or two validators would share a reward
	// address and genesis.go:1467 would reject the document.
	if addrA == addrB {
		t.Fatalf("distinct public keys produced the same reward address %q", addrA)
	}
}

// TestLocalnetRewardAddressIsNotAFabricatedConstant is the regression guard for
// the original bug: the address was a constant
// ("%064x" of 0x10c0ffee00000000+offset) merely passed through the SPIF
// formatter. Such a value satisfies every syntactic check while being derived
// from nothing, so this asserts the derivation actually consumed the key.
func TestLocalnetRewardAddressIsNotAFabricatedConstant(t *testing.T) {
	fabricated := "10c0ffee"
	for i := 0; i < 8; i++ {
		addr, err := localnetRewardAddress(bytes32(byte(i + 1)))
		if err != nil {
			t.Fatalf("localnetRewardAddress(%d): %v", i, err)
		}
		raw := strings.ToLower(common.CanonicalSPIFAddress(addr))
		if strings.HasPrefix(raw, fabricated) {
			t.Fatalf("reward address %q is derived from the fabricated 0x10c0ffee "+
				"constant, not from the validator's public key", addr)
		}
	}
}

// TestLocalnetRewardAddressesAreDistinct guards the genesis rule at
// genesis.go:1467 (a reward address may be bound to only one validator), on the
// CANONICAL form which is the key that dedup uses.
func TestLocalnetRewardAddressesAreDistinct(t *testing.T) {
	canon := make(map[string]int)
	for i := 0; i < 16; i++ {
		addr, err := localnetRewardAddress(bytes32(byte(i + 1)))
		if err != nil {
			t.Fatalf("localnetRewardAddress(%d): %v", i, err)
		}
		c := common.CanonicalSPIFAddress(addr)
		if prev, dup := canon[c]; dup {
			t.Fatalf("keys %d and %d share canonical reward address %s", prev, i, c)
		}
		canon[c] = i
	}
}

// bytes32 builds a deterministic 32-byte test key.
func bytes32(fill byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = fill
	}
	return b
}

// keep the hex import honest: genesis names the public key as hex.
var _ = hex.EncodeToString
