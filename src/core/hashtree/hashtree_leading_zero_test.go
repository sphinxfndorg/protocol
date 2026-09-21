// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package hashtree

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/holiman/uint256"
)

// Regression test for the 31-byte merkle-root bug (JSON-RPC -32602).
//
// (*uint256.Int).Bytes() returns the minimal-length encoding, so any root
// whose big-endian form starts with 0x00 silently became 31 bytes when
// callers used .Hash.Bytes(). That value then failed the strict 32-byte
// check in VerifyTransactionAuth ("invalid merkle root hash length:
// expected 32, got 31") before broadcast. This test pins a forced
// 0x00-leading root through every fixed-width export path.
func TestLeadingZeroRootStays32Bytes(t *testing.T) {
	raw := make([]byte, 32)
	raw[0] = 0x00
	for i := 1; i < 32; i++ {
		raw[i] = byte(i)
	}
	node := &HashTreeNode{Hash: uint256.NewInt(0).SetBytes(raw)}

	// The buggy call this test guards against:
	if got := len(node.Hash.Bytes()); got != 31 {
		t.Fatalf("test premise broken: minimal .Bytes() of 0x00-leading root should be 31 bytes, got %d", got)
	}

	for name, got := range map[string][]byte{
		"HashToBytes32": HashToBytes32(node.Hash),
		"RootBytes32":   node.RootBytes32(),
	} {
		if len(got) != 32 {
			t.Fatalf("%s: expected 32 bytes, got %d (%x)", name, len(got), got)
		}
		if !bytes.Equal(got, raw) {
			t.Fatalf("%s: leading zero byte lost or value shifted: got %x want %x", name, got, raw)
		}
		if hex.EncodeToString(got)[:2] != "00" {
			t.Fatalf("%s: hex must keep leading 00 nibble, got %s", name, hex.EncodeToString(got))
		}
	}

	// Internal tree hashing is CONSENSUS-FROZEN legacy behavior: parent
	// preimages use minimal-length .Bytes() concatenation (62/63/64 bytes
	// when a child hash has a leading zero). This must stay byte-identical
	// across versions because the receipt root is re-derived during
	// stateless replay verification and compared to the stored root.
	// What this test pins instead: tree construction is deterministic —
	// two builds over the same leaves give the same root.
	leaves := [][]byte{[]byte("leaf-a"), []byte("leaf-b"), []byte("leaf-c")}
	r1 := BuildHashTree(leaves)
	r2 := BuildHashTree(leaves)
	b1 := r1.Hash.Bytes32()
	b2 := r2.Hash.Bytes32()
	if b1 != b2 {
		t.Fatalf("BuildHashTree is not deterministic: %x vs %x", b1, b2)
	}
}
