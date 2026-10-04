package vault

import (
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
)

// TestValidateAndNormalizeRecipientsBoundToKeysRejectsFabrication is the vault's
// rejection defense: a recipient address that is not derived from the public key
// supplied alongside it is refused, so encryption can never be pointed at a
// fabricated address.
//
// The public keys here are synthetic 32-byte values, which is sufficient — the
// check re-derives the address from the key it is given, so it proves the
// binding without needing a real key manager.
func TestValidateAndNormalizeRecipientsBoundToKeysRejectsFabrication(t *testing.T) {
	const n = 4
	pubs := make([][]byte, n)
	for i := range pubs {
		pubs[i] = []byte{byte(i + 1), 0xAA, 0xBB, 0xCC, byte(i), 0x01, 0x02, 0x03,
			0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
			0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B}
	}

	// Genuine: every address re-derives from its own public key.
	good := make([]string, n)
	for i, pk := range pubs {
		good[i] = keys.GetPublicKeyFingerprintFromBytes(pk, keys.OrgSPIF)
	}
	got, err := ValidateAndNormalizeRecipientsBoundToKeys(good, pubs, keys.OrgSPIF)
	if err != nil {
		t.Fatalf("genuine key-derived recipients were rejected: %v", err)
	}
	if len(got) != n {
		t.Fatalf("got %d normalized recipients, want %d", len(got), n)
	}
	// Normalization strips the SPIF prefix, so compare against canonical bodies.
	for i, addr := range good {
		want, err := keys.NormalizeOrgAddress(addr)
		if err != nil {
			t.Fatalf("recipient %d: NormalizeOrgAddress: %v", i, err)
		}
		if got[i] != want {
			t.Fatalf("recipient %d normalized to %q, want %q", i, got[i], want)
		}
	}

	// Fabricated: well-formed 64-hex SPIF addresses that no supplied key produces.
	forged := []string{
		strings.Repeat("11", 32),
		common.SPIFPrefix + " " + strings.Repeat("22", 32),
		strings.Repeat("AB", 32),
	}
	for _, fake := range forged {
		// Sanity: the fabricated value is well-shaped, so only the key binding can catch it.
		if _, err := keys.NormalizeOrgAddress(fake); err != nil {
			continue // rejected by shape already; nothing to prove here
		}
		fps := append(append([]string{}, good[:n-1]...), fake)
		if _, err := ValidateAndNormalizeRecipientsBoundToKeys(fps, pubs, keys.OrgSPIF); err == nil {
			t.Fatalf("fabricated recipient %q was accepted; the key binding must reject it", fake)
		}
	}

	// Swapped keys: a real address paired with the WRONG public key must be refused.
	swapped := []string{good[1], good[0], good[2], good[3]}
	if _, err := ValidateAndNormalizeRecipientsBoundToKeys(swapped, pubs, keys.OrgSPIF); err == nil {
		t.Fatal("recipient addresses paired with the wrong public keys were accepted")
	}

	// Missing key material must not silently skip verification.
	if _, err := ValidateAndNormalizeRecipientsBoundToKeys(good, nil, keys.OrgSPIF); err == nil {
		t.Fatal("recipients with no public keys were accepted; verification was skipped")
	}
	if _, err := ValidateAndNormalizeRecipientsBoundToKeys(good, make([][]byte, n), keys.OrgSPIF); err == nil {
		t.Fatal("recipients with empty public keys were accepted; verification was skipped")
	}

	// Duplicate recipients are still caught by the underlying normalizer.
	if _, err := ValidateAndNormalizeRecipientsBoundToKeys(
		[]string{good[0], good[0]}, [][]byte{pubs[0], pubs[0]}, keys.OrgSPIF); err == nil {
		t.Fatal("duplicate recipient was accepted")
	}
}
