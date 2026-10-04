package utils

import (
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
)

// TestLocalnetRewardAddressIsSPIFFormatted pins the reward-address format.
//
// localnet used to emit a bare "%064x" string. Genesis accepted it (it
// canonicalizes before validating), which is exactly why the slip went
// unnoticed — but every other address this project produces is a SPIF address,
// and a localnet genesis carrying raw-hex reward addresses is not what any
// other tooling expects to read.
func TestLocalnetRewardAddressIsSPIFFormatted(t *testing.T) {
	for _, off := range []int{0, 1, 2, 3, 7} {
		addr := localnetRewardAddress(off, off)
		t.Logf("offset %d -> %s", off, addr)

		if !common.ValidateAddress(addr) {
			t.Fatalf("offset %d: %q is not a valid protocol address", off, addr)
		}

		prefix, raw, err := common.SplitAddressPrefix(addr)
		if err != nil {
			t.Fatalf("offset %d: SplitAddressPrefix(%q): %v", off, addr, err)
		}
		if prefix != common.SPIFPrefix {
			t.Fatalf("offset %d: reward address %q has prefix %q, want %q",
				off, addr, prefix, common.SPIFPrefix)
		}
		// Round-trips through the canonicalizer without changing meaning.
		if got := common.CanonicalSPIFAddress(addr); got != raw {
			t.Fatalf("offset %d: canonical form %q != hex body %q", off, got, raw)
		}
	}
}

// TestLocalnetRewardAddressesAreDistinct guards the genesis rule at
// genesis.go:1467 (a reward address may be bound to only one validator).
// It checks the CANONICAL form, which is the key that dedup uses.
func TestLocalnetRewardAddressesAreDistinct(t *testing.T) {
	canon := make(map[string]int)
	for off := 0; off < 16; off++ {
		addr := localnetRewardAddress(off, off)
		c := common.CanonicalSPIFAddress(addr)
		if prev, dup := canon[c]; dup {
			t.Fatalf("offsets %d and %d share canonical reward address %s", prev, off, c)
		}
		canon[c] = off
	}
}
