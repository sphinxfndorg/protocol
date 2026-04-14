// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/crypto/STHINCS/address/shake256.go
package tweakable

import (
	"crypto/subtle"

	"github.com/sphinxorg/protocol/src/crypto/STHINCS/address"
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

// Pseudorandom function PRF
func (h *Shake256Tweak) PRF(SEED []byte, adrs *address.ADRS) []byte {
	output := make([]byte, h.N)
	hash := sha3.NewShake256()
	hash.Write(SEED)
	hash.Write(adrs.GetBytes())
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
func (h *Shake256Tweak) F(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	var M1 []byte

	if h.Variant == Robust {
		bitmask := generateBitmask(PKseed, adrs, 8*len(tmp))
		M1 = make([]byte, len(tmp))
		_ = subtle.XORBytes(M1, tmp, bitmask)
	} else if h.Variant == Simple {
		M1 = tmp
	}

	output := make([]byte, h.N)
	hash := sha3.NewShake256()
	hash.Write(PKseed)
	hash.Write(adrs.GetBytes())
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

func generateBitmask(PKseed []byte, adrs *address.ADRS, messageLength int) []byte {
	output := make([]byte, messageLength)
	hash := sha3.NewShake256()
	hash.Write(PKseed)
	hash.Write(adrs.GetBytes())
	hash.Read(output)
	return output
}
