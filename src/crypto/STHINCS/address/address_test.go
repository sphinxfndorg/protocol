// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/address/address_test.go
package address

import (
	"math/bits"
	"testing"
)

// GetTreeAddress must round-trip whatever SetTreeAddress stored. It used to
// read the wrong 8 bytes of the 12-byte field and return tree>>32.
func TestTreeAddressRoundTrip(t *testing.T) {
	values := []uint64{0, 1, 5, 1<<25 - 1, 1<<31 - 1}
	if bits.UintSize == 64 {
		values = append(values, 1<<32+5, 1<<40-1)
	}
	for _, v := range values {
		a := new(ADRS)
		a.SetTreeAddress(v)
		if got := uint64(a.GetTreeAddress()); got != v {
			t.Errorf("GetTreeAddress after SetTreeAddress(%#x) = %#x", v, got)
		}
	}
}
