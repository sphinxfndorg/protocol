// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/tweakable/tweakable_test.go
package tweakable

import (
	"bytes"
	"testing"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/address"
)

const (
	testN         = 16
	testDigestLen = 40
)

type backend struct {
	name     string
	newTweak func(variant string) TweakableHashFunction
	// separatesFHTl: F, H and T_l carry distinct domain tags, so they must
	// differ on identical inputs. (SHA256/SHAKE256 deliberately share one
	// function for all three and rely on the ADRS type for separation.)
	separatesFHTl bool
}

func backends() []backend {
	return []backend{
		{"SHA256", func(v string) TweakableHashFunction {
			return &Sha256Tweak{Variant: v, MessageDigestLength: testDigestLen, N: testN}
		}, false},
		{"SHAKE256", func(v string) TweakableHashFunction {
			return &Shake256Tweak{Variant: v, MessageDigestLength: testDigestLen, N: testN}
		}, false},
		{"SPHINXHASH", func(v string) TweakableHashFunction {
			return &SphinxHashTweak{Variant: v, MessageDigestLength: testDigestLen, N: testN}
		}, true},
	}
}

// "unrecognized" must behave like Simple: inputs still reach the hash.
var variants = []string{Simple, Robust, "unrecognized"}

func testADRS() *address.ADRS {
	a := new(address.ADRS)
	a.SetType(address.WOTS_HASH) // SetType zeroes the other fields, so call it first
	a.SetLayerAddress(1)
	a.SetTreeAddress(2)
	a.SetKeyPairAddress(3)
	a.SetChainAddress(4)
	a.SetHashAddress(5)
	return a
}

var adrsMutations = []struct {
	name   string
	mutate func(*address.ADRS)
}{
	{"ADRS layer", func(a *address.ADRS) { a.SetLayerAddress(9) }},
	{"ADRS tree", func(a *address.ADRS) { a.SetTreeAddress(9) }},
	{"ADRS keypair", func(a *address.ADRS) { a.SetKeyPairAddress(9) }},
	{"ADRS chain", func(a *address.ADRS) { a.SetChainAddress(9) }},
	{"ADRS hash", func(a *address.ADRS) { a.SetHashAddress(9) }},
}

func fill(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

// flip returns a copy of b with one bit changed.
func flip(b []byte) []byte {
	c := append([]byte(nil), b...)
	c[0] ^= 0x01
	return c
}

func mustDiffer(t *testing.T, what string, base, other []byte) {
	t.Helper()
	if bytes.Equal(base, other) {
		t.Errorf("output does not depend on %s", what)
	}
}

// Regression for the old SphinxHashTweak stub: every argument of every
// tweakable function must change the output, for every backend and variant.
func TestTweakableOutputsDependOnEveryInput(t *testing.T) {
	for _, be := range backends() {
		for _, variant := range variants {
			be, variant := be, variant
			t.Run(be.name+"/"+variant, func(t *testing.T) {
				h := be.newTweak(variant)
				adrs := testADRS()
				pkSeed := fill(testN, 0x10)

				// F / H / T_l: PKseed, ADRS (every field), tmp.
				compress := []struct {
					name string
					call func([]byte, *address.ADRS, []byte) []byte
					tmp  []byte
				}{
					{"F", h.F, fill(testN, 0x20)},
					{"H", h.H, fill(2*testN, 0x30)},
					{"T_l", h.T_l, fill(8*testN, 0x40)},
				}
				for _, f := range compress {
					base := f.call(pkSeed, adrs, f.tmp)
					if len(base) != testN {
						t.Fatalf("%s: output length %d, want %d", f.name, len(base), testN)
					}
					if !bytes.Equal(base, f.call(pkSeed, adrs, f.tmp)) {
						t.Errorf("%s: not deterministic", f.name)
					}
					mustDiffer(t, f.name+" PKseed", base, f.call(flip(pkSeed), adrs, f.tmp))
					mustDiffer(t, f.name+" tmp", base, f.call(pkSeed, adrs, flip(f.tmp)))
					for _, m := range adrsMutations {
						a := adrs.Copy()
						m.mutate(a)
						mustDiffer(t, f.name+" "+m.name, base, f.call(pkSeed, a, f.tmp))
					}
				}

				// PRF: SEED, ADRS.
				seed := fill(testN, 0x50)
				prf := h.PRF(seed, adrs)
				if len(prf) != testN {
					t.Fatalf("PRF: output length %d, want %d", len(prf), testN)
				}
				mustDiffer(t, "PRF SEED", prf, h.PRF(flip(seed), adrs))
				for _, m := range adrsMutations {
					a := adrs.Copy()
					m.mutate(a)
					mustDiffer(t, "PRF "+m.name, prf, h.PRF(seed, a))
				}

				// PRFmsg: SKprf, OptRand, M.
				skprf, opt, msg := fill(testN, 0x60), fill(testN, 0x70), []byte("message")
				pm := h.PRFmsg(skprf, opt, msg)
				if len(pm) != testN {
					t.Fatalf("PRFmsg: output length %d, want %d", len(pm), testN)
				}
				mustDiffer(t, "PRFmsg SKprf", pm, h.PRFmsg(flip(skprf), opt, msg))
				mustDiffer(t, "PRFmsg OptRand", pm, h.PRFmsg(skprf, flip(opt), msg))
				mustDiffer(t, "PRFmsg M", pm, h.PRFmsg(skprf, opt, flip(msg)))

				// Hmsg: R, PKseed, PKroot, M.
				r, root := fill(testN, 0x80), fill(testN, 0x90)
				hm := h.Hmsg(r, pkSeed, root, msg)
				if len(hm) != testDigestLen {
					t.Fatalf("Hmsg: output length %d, want %d", len(hm), testDigestLen)
				}
				mustDiffer(t, "Hmsg R", hm, h.Hmsg(flip(r), pkSeed, root, msg))
				mustDiffer(t, "Hmsg PKseed", hm, h.Hmsg(r, flip(pkSeed), root, msg))
				mustDiffer(t, "Hmsg PKroot", hm, h.Hmsg(r, pkSeed, flip(root), msg))
				mustDiffer(t, "Hmsg M", hm, h.Hmsg(r, pkSeed, root, flip(msg)))
			})
		}
	}
}

// Robust and Simple must actually be different functions.
func TestRobustDiffersFromSimple(t *testing.T) {
	for _, be := range backends() {
		be := be
		t.Run(be.name, func(t *testing.T) {
			pk, tmp, adrs := fill(testN, 0x10), fill(2*testN, 0x30), testADRS()
			mustDiffer(t, "variant (F)", be.newTweak(Simple).F(pk, adrs, tmp), be.newTweak(Robust).F(pk, adrs, tmp))
		})
	}
}

// SphinxHashTweak tags F, H and T_l separately, so identical inputs must not
// produce identical outputs.
func TestFHTlDomainSeparation(t *testing.T) {
	for _, be := range backends() {
		if !be.separatesFHTl {
			continue
		}
		for _, variant := range []string{Simple, Robust} {
			be, variant := be, variant
			t.Run(be.name+"/"+variant, func(t *testing.T) {
				h := be.newTweak(variant)
				pk, tmp, adrs := fill(testN, 0x10), fill(2*testN, 0x30), testADRS()
				f, hh, tl := h.F(pk, adrs, tmp), h.H(pk, adrs, tmp), h.T_l(pk, adrs, tmp)
				if bytes.Equal(f, hh) || bytes.Equal(f, tl) || bytes.Equal(hh, tl) {
					t.Error("F, H and T_l collide on identical inputs: domain tags are not separating them")
				}
			})
		}
	}
}

// A tweakable function must not write into the caller's slices — including
// the spare capacity behind them. (Sha256Tweak.F used to do
// append(PKseed, compressedADRS...), which scribbles over that spare
// capacity whenever cap(PKseed) > len(PKseed).)
func TestDoesNotWriteIntoCallerSpareCapacity(t *testing.T) {
	for _, be := range backends() {
		for _, variant := range variants {
			be, variant := be, variant
			t.Run(be.name+"/"+variant, func(t *testing.T) {
				h := be.newTweak(variant)
				adrs := testADRS()
				tmp := fill(2*testN, 0x30)

				calls := map[string]func([]byte) []byte{
					"F":   func(pk []byte) []byte { return h.F(pk, adrs, tmp) },
					"H":   func(pk []byte) []byte { return h.H(pk, adrs, tmp) },
					"T_l": func(pk []byte) []byte { return h.T_l(pk, adrs, tmp) },
				}
				for name, call := range calls {
					buf := make([]byte, testN, 8*testN) // spare capacity starts zeroed
					copy(buf, fill(testN, 0x10))
					call(buf)
					for i, b := range buf[testN:cap(buf)] {
						if b != 0 {
							t.Errorf("%s wrote into caller's spare capacity (offset %d past len)", name, i)
							break
						}
					}
				}
			})
		}
	}
}
