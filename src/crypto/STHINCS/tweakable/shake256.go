// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/tweakable/shake256.go
package tweakable

import (
	"crypto/subtle"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/address"
	"golang.org/x/crypto/sha3"
)

type Shake256Tweak struct {
	Variant             string
	MessageDigestLength int
	N                   int
}

// Keyed hash function Hmsg
func (h *Shake256Tweak) Hmsg(R []byte, PKseed []byte, PKroot []byte, M []byte) []byte {
	output := make([]byte, h.MessageDigestLength)
	hash := sha3.NewShake256()
	hash.Write(R)
	hash.Write(PKseed)
	hash.Write(PKroot)
	hash.Write(M)
	hash.Read(output)
	return output
}

// Pseudorandom function PRFmsg
func (h *Shake256Tweak) PRFmsg(SKprf []byte, OptRand []byte, M []byte) []byte {
	output := make([]byte, h.N)
	hash := sha3.NewShake256()
	hash.Write(SKprf)
	hash.Write(OptRand)
	hash.Write(M)
	hash.Read(output)
	return output
}

// Tweakable hash function F
//
// Robust masks tmp with a SHAKE256 bitmask before hashing. Any other Variant
// value is treated as Simple (tmp is hashed as-is) — never as "no input", so
// tmp always reaches the hash.
//
// The ADRS is encoded into a stack array rather than via GetBytes(): this is
// the hottest function in the scheme (Len x (W-1) calls per leaf, times
// 2^Hprime leaves per tree, times D trees), and GetBytes would allocate 32
// bytes on every single call. The encoding is identical.
func (h *Shake256Tweak) F(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	var adrsBuf [32]byte
	adrs.WriteTo(adrsBuf[:])

	M1 := tmp

	if h.Variant == Robust {
		// The mask is exactly len(tmp) BYTES. (This used to request
		// 8*len(tmp) bytes — a bits/bytes mix-up that squeezed 8x more SHAKE
		// output than was ever used. SHAKE is an XOF, so the first len(tmp)
		// bytes are identical either way: outputs and signatures are unchanged.)
		bitmask := h.generateBitmask(PKseed, adrsBuf[:], len(tmp))
		M1 = make([]byte, len(tmp))
		_ = subtle.XORBytes(M1, tmp, bitmask)
	}

	output := make([]byte, h.N)
	hash := sha3.NewShake256()
	hash.Write(PKseed)
	hash.Write(adrsBuf[:])
	hash.Write(M1)
	hash.Read(output)
	return output
}

// Tweakable hash function H
func (h *Shake256Tweak) H(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	return h.F(PKseed, adrs, tmp)
}

// Tweakable hash function T_l
func (h *Shake256Tweak) T_l(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	return h.F(PKseed, adrs, tmp)
}

// PRF derives a pseudorandom value; also on the hot path (once per WOTS+
// chain), so it encodes the ADRS without allocating.
func (h *Shake256Tweak) PRF(SEED []byte, adrs *address.ADRS) []byte {
	var adrsBuf [32]byte
	adrs.WriteTo(adrsBuf[:])
	output := make([]byte, h.N)
	hash := sha3.NewShake256()
	hash.Write(SEED)
	hash.Write(adrsBuf[:])
	hash.Read(output)
	return output
}

// generateBitmask squeezes exactly `length` bytes of mask from
// SHAKE256(PKseed || ADRS), with ADRS already encoded by the caller.
func (h *Shake256Tweak) generateBitmask(PKseed []byte, adrsBytes []byte, length int) []byte {
	output := make([]byte, length)
	hash := sha3.NewShake256()
	hash.Write(PKseed)
	hash.Write(adrsBytes)
	hash.Read(output)
	return output
}
