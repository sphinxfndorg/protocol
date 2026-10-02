// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/tweakable/sha256.go
package tweakable

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"sync"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/address"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/util"
)

type Sha256Tweak struct {
	Variant             string
	MessageDigestLength int
	N                   int
}

// Keyed hash function Hmsg
func (h *Sha256Tweak) Hmsg(R []byte, PKseed []byte, PKroot []byte, M []byte) []byte {

	hash := sha256.New()
	hash.Write(R)
	hash.Write(PKseed)
	hash.Write(PKroot)
	hash.Write(M)
	hashedConc := hash.Sum(nil)
	bitmask := mgf1sha256(hashedConc, h.MessageDigestLength)
	return bitmask
}

// Pseudorandom function PRF
func (h *Sha256Tweak) PRF(SEED []byte, adrs *address.ADRS) []byte {
	compressedADRS := compressADRS(adrs)
	hash := sha256.New()
	hash.Write(SEED)
	hash.Write(compressedADRS)
	return hash.Sum(nil)[:h.N]
}

// Pseudorandom function PRFmsg
func (h *Sha256Tweak) PRFmsg(SKprf []byte, OptRand []byte, M []byte) []byte {
	mac := hmac.New(sha256.New, SKprf)
	mac.Write(OptRand)
	mac.Write(M)
	return mac.Sum(nil)[:h.N]
}

// Tweakable hash function F
//
// Robust masks tmp with an MGF1 bitmask before hashing. Any other Variant
// value is treated as Simple (tmp is hashed as-is) — never as "no input", so
// tmp always reaches the hash.
//
// Hot path: called Len x (W-1) times per leaf, 2^Hprime leaves per tree, D
// trees per signature. compressADRS writes into a stack array and the zero
// pad is a constant-size slice, so neither allocates per call.
func (h *Sha256Tweak) F(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	var adrsBuf [22]byte
	compressADRSInto(adrs, adrsBuf[:])

	M1 := tmp
	if h.Variant == Robust {
		// Build the MGF1 seed in a fresh slice. append(PKseed, ...) would write
		// the ADRS bytes into PKseed's spare capacity whenever cap > len,
		// mutating the caller's backing array (and racing across goroutines
		// that share one PKseed).
		seed := make([]byte, 0, len(PKseed)+len(adrsBuf))
		seed = append(seed, PKseed...)
		seed = append(seed, adrsBuf[:]...)
		bitmask := mgf1sha256(seed, len(tmp))
		M1 = make([]byte, len(tmp))
		_ = subtle.XORBytes(M1, tmp, bitmask)
	}

	// pad is all zeros; it depends only on N, so it is a package-level
	// constant slice rather than a fresh allocation per call. It is never
	// written to, and F never retains it, so sharing is safe.
	pad := zeroPad(h.N)

	hash := sha256.New()
	hash.Write(PKseed)
	hash.Write(pad)
	hash.Write(adrsBuf[:])
	hash.Write(M1)
	return hash.Sum(nil)[:h.N]
}

// zeroPad returns a read-only, N-byte zero pad for the given N. Cached per N
// so the hot path does not allocate. The returned slice must never be
// modified; nothing in this package writes to it.
var zeroPadCache sync.Map // int -> []byte

func zeroPad(n int) []byte {
	if v, ok := zeroPadCache.Load(n); ok {
		return v.([]byte)
	}
	p := make([]byte, 64-n)
	zeroPadCache.Store(n, p)
	return p
}

// Tweakable hash function H
func (h *Sha256Tweak) H(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	return h.F(PKseed, adrs, tmp)
}

// Tweakable hash function T_l
func (h *Sha256Tweak) T_l(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	return h.F(PKseed, adrs, tmp)
}

// Compresses ADRS into 22 bytes
func compressADRS(adrs *address.ADRS) []byte {
	ADRSc := make([]byte, 22)
	compressADRSInto(adrs, ADRSc)
	return ADRSc
}

// compressADRSInto writes the 22-byte compressed ADRS into dst (which must be
// at least 22 bytes), using the same encoding as compressADRS.
//
// Split out so the hot path (F, called millions of times per signature) can
// encode into a stack array and avoid an allocation per call.
func compressADRSInto(adrs *address.ADRS, dst []byte) {
	if len(dst) < 22 {
		panic(fmt.Sprintf("compressADRS destination too small: have %d bytes, need 22", len(dst)))
	}
	ADRSc := dst
	// Zero first: only some of the 22 bytes are written for a given type, and
	// a reused buffer must not leak a previous address's tail into the hash.
	clear(ADRSc)

	copy(ADRSc[0:1], adrs.LayerAddress[3:4])
	copy(ADRSc[1:9], adrs.TreeAddress[4:12])
	copy(ADRSc[9:10], adrs.Type[3:4])

	switch adrs.GetType() {
	case address.WOTS_HASH:
		copy(ADRSc[10:14], adrs.KeyPairAddress[:])
		copy(ADRSc[14:18], adrs.ChainAddress[:])
		copy(ADRSc[18:22], adrs.HashAddress[:])
	case address.WOTS_PK:
		copy(ADRSc[10:14], adrs.KeyPairAddress[:])
	case address.TREE:
		copy(ADRSc[14:18], adrs.TreeHeight[:])
		copy(ADRSc[18:22], adrs.TreeIndex[:])
	case address.FORS_TREE:
		copy(ADRSc[10:14], adrs.KeyPairAddress[:])
		copy(ADRSc[14:18], adrs.TreeHeight[:])
		copy(ADRSc[18:22], adrs.TreeIndex[:])
	case address.FORS_ROOTS:
		copy(ADRSc[10:14], adrs.KeyPairAddress[:])
	}
}

// Based on RFC 2437
func mgf1sha256(seed []byte, length int) []byte {
	T := make([]byte, 0)
	counter := 0
	for len(T) < length {
		C := util.ToByte(uint64(counter), 4) //i2osp equivalent to ToByte
		hash := sha256.New()
		hash.Write(seed)
		hash.Write(C)
		hashedZC := hash.Sum(nil)
		T = append(T, hashedZC...)
		counter++
	}
	// Extract the leading l octets of T as the octet string mask.
	return T[:length]
}
