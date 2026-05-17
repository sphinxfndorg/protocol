// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/address/types.go
package xmss

// XMSSSignature represents a signature from one XMSS tree
//
// XMSS (eXtended Merkle Signature Scheme) is a stateful hash-based signature scheme.
// In STHINCS, XMSS trees form the building blocks of the hypertree structure.
// Each XMSS tree has 2^Hprime leaves, where each leaf is a WOTS+ public key.
//
// Components:
//   - WotsSignature: WOTS+ signature for the message (Len * N bytes)
//   - AUTH: Authentication path (Hprime * N bytes)
//
// Total signature size: Len*N + Hprime*N bytes
// For typical parameters: 67*32 + 4*32 = 2144 + 128 = 2272 bytes
type XMSSSignature struct {
	WotsSignature []byte // WOTS+ signature (Len * N bytes)
	AUTH          []byte // Authentication path (Hprime * N bytes)
}
