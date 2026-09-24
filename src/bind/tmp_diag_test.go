package bind

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	config "github.com/sphinxfndorg/protocol/src/core/sthincs/config"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/address"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/tweakable"
)

// diagEnvVar enables the expensive measurement test below. It is diagnostic
// scaffolding, not a correctness check: TestTmpCountAndCost runs a full
// SPHINCS+ keygen, sign and verify, which costs minutes on a race-enabled CI
// runner and was single-handedly pushing the src/bind package past the default
// 10m go test timeout. Run it explicitly with:
//
//	SPXHASH_DIAG=1 go test ./src/bind/ -run TestTmpCountAndCost -v
const diagEnvVar = "SPXHASH_DIAG"

// requireDiag skips a measurement test unless it was explicitly requested.
func requireDiag(t *testing.T) {
	t.Helper()
	if os.Getenv(diagEnvVar) != "1" {
		t.Skipf("diagnostic measurement test: set %s=1 to run", diagEnvVar)
	}
}

// tweakCounter wraps the active tweakable hash and counts calls per function.
type tweakCounter struct {
	inner tweakable.TweakableHashFunction
	hmsg  int
	prf   int
	f     int
	h     int
	tl    int
}

func (c *tweakCounter) Hmsg(R, PKseed, PKroot, M []byte) []byte {
	c.hmsg++
	return c.inner.Hmsg(R, PKseed, PKroot, M)
}
func (c *tweakCounter) PRF(SEED []byte, adrs *address.ADRS) []byte {
	c.prf++
	return c.inner.PRF(SEED, adrs)
}
func (c *tweakCounter) PRFmsg(SKprf, OptRand, M []byte) []byte {
	return c.inner.PRFmsg(SKprf, OptRand, M)
}
func (c *tweakCounter) F(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	c.f++
	return c.inner.F(PKseed, adrs, tmp)
}
func (c *tweakCounter) H(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	c.h++
	return c.inner.H(PKseed, adrs, tmp)
}
func (c *tweakCounter) T_l(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	c.tl++
	return c.inner.T_l(PKseed, adrs, tmp)
}

func (c *tweakCounter) snapshot() (hmsg, prf, f, h, tl int) {
	return c.hmsg, c.prf, c.f, c.h, c.tl
}

func TestTmpCountAndCost(t *testing.T) {
	requireDiag(t)

	// --- 1. Real per-call cost of SpxHash on distinct (cache-missing) inputs.
	const n = 100
	start := time.Now()
	for i := 0; i < n; i++ {
		input := []byte{byte(i >> 8), byte(i), 's', 'p', 'x', 'k'}
		_ = common.SpxHash(input)
	}
	perCall := time.Since(start) / n
	t.Logf("common.SpxHash (unique inputs, cache miss): %v per call", perCall)

	// --- 2. Count tweakable-hash calls in keygen / sign / verify.
	cfg, err := config.NewSTHINCSParameters()
	if err != nil {
		t.Fatal(err)
	}
	params := cfg.Params
	ctr := &tweakCounter{inner: params.Tweak}
	params.Tweak = ctr

	h0, p0, f0, hH0, t0 := ctr.snapshot()
	start = time.Now()
	sk, pk, err := sthincs.Spx_keygen(params)
	if err != nil {
		t.Fatal(err)
	}
	keygenDur := time.Since(start)
	h1, p1, f1, hH1, t1 := ctr.snapshot()
	t.Logf("keygen: %v — Hmsg=%d PRF=%d F=%d H=%d T_l=%d",
		keygenDur, h1-h0, p1-p0, f1-f0, hH1-hH0, t1-t0)

	msg := []byte("counting measurement message")
	start = time.Now()
	sig, err := sthincs.Spx_sign(params, msg, sk)
	if err != nil {
		t.Fatal(err)
	}
	signDur := time.Since(start)
	h2, p2, f2, hH2, t2 := ctr.snapshot()
	t.Logf("sign:    %v — Hmsg=%d PRF=%d F=%d H=%d T_l=%d",
		signDur, h2-h1, p2-p1, f2-f1, hH2-hH1, t2-t1)

	start = time.Now()
	ok := sthincs.Spx_verify(params, msg, sig, pk)
	verifyDur := time.Since(start)
	h3, p3, f3, hH3, t3 := ctr.snapshot()
	t.Logf("verify:  %v (ok=%v) — Hmsg=%d PRF=%d F=%d H=%d T_l=%d",
		verifyDur, ok, h3-h2, p3-p2, f3-f2, hH3-hH2, t3-t2)

	innerPerCall := (f2 - f1) + (hH2 - hH1) + (p2 - p1)
	_ = params
	t.Logf("projection: sign needs %d inner (F/H/PRF) calls × %v ≈ %v",
		innerPerCall, perCall, time.Duration(int64(perCall)*int64(innerPerCall)))
}

// assertDifferent reports a failed dependence check as a test failure. The
// equality result is logged as well, so the diagnostic output retains the
// shape of the original temporary test.
func assertDifferent(t *testing.T, name string, baseline, changed []byte) {
	t.Helper()
	if len(baseline) == 0 {
		t.Errorf("%s: baseline output is empty", name)
	}
	if bytes.Equal(baseline, changed) {
		t.Errorf("%s input dependence: false (want true)", name)
		return
	}
	t.Logf("%s input dependence: true (want true)", name)
}

func TestTmpLayerDeps(t *testing.T) {
	cfg, err := config.NewSTHINCSParameters()
	if err != nil {
		t.Fatal(err)
	}
	params := cfg.Params
	n := params.N
	bytesN := func(value byte) []byte { return bytes.Repeat([]byte{value}, n) }

	pkSeed := bytesN(0x11)
	pkSeed2 := bytesN(0x12)
	skSeed := bytesN(0x13)
	skSeed2 := bytesN(0x14)
	root := bytesN(0x15)
	root2 := bytesN(0x16)
	message := []byte("layer-dependence message")
	message2 := []byte("layer-dependence message!")
	optRand := bytesN(0x17)
	optRand2 := bytesN(0x18)

	adrs := new(address.ADRS)
	adrs.SetType(address.WOTS_HASH)
	adrsChanged := adrs.Copy()
	adrsChanged.SetLayerAddress(1)

	input := bytesN(0x21)
	input2 := bytesN(0x22)
	hInput := append(bytesN(0x31), bytesN(0x32)...)
	hInput2 := append(bytesN(0x33), bytesN(0x34)...)
	tlInput := append(bytesN(0x35), append(bytesN(0x36), bytesN(0x37)...)...)
	tlInput2 := append(bytesN(0x38), append(bytesN(0x39), bytesN(0x3a)...)...)

	// F, H, and T_l must bind seed, address, and their complete input.
	f := params.Tweak.F(pkSeed, adrs, input)
	assertDifferent(t, "Tweak.F input", f, params.Tweak.F(pkSeed, adrs, input2))
	assertDifferent(t, "Tweak.F seed", f, params.Tweak.F(pkSeed2, adrs, input))
	assertDifferent(t, "Tweak.F adrs", f, params.Tweak.F(pkSeed, adrsChanged, input))

	h := params.Tweak.H(pkSeed, adrs, hInput)
	assertDifferent(t, "Tweak.H input", h, params.Tweak.H(pkSeed, adrs, hInput2))
	assertDifferent(t, "Tweak.H seed", h, params.Tweak.H(pkSeed2, adrs, hInput))
	assertDifferent(t, "Tweak.H adrs", h, params.Tweak.H(pkSeed, adrsChanged, hInput))

	tl := params.Tweak.T_l(pkSeed, adrs, tlInput)
	assertDifferent(t, "Tweak.T_l input", tl, params.Tweak.T_l(pkSeed, adrs, tlInput2))
	assertDifferent(t, "Tweak.T_l seed", tl, params.Tweak.T_l(pkSeed2, adrs, tlInput))
	assertDifferent(t, "Tweak.T_l adrs", tl, params.Tweak.T_l(pkSeed, adrsChanged, tlInput))

	// PRF must bind both its seed and address.
	prf := params.Tweak.PRF(skSeed, adrs)
	assertDifferent(t, "Tweak.PRF seed", prf, params.Tweak.PRF(skSeed2, adrs))
	assertDifferent(t, "Tweak.PRF adrs", prf, params.Tweak.PRF(skSeed, adrsChanged))

	// Hmsg must bind all four inputs, including the public root and randomizer.
	hmsg := params.Tweak.Hmsg(optRand, pkSeed, root, message)
	assertDifferent(t, "Tweak.Hmsg message", hmsg, params.Tweak.Hmsg(optRand, pkSeed, root, message2))
	assertDifferent(t, "Tweak.Hmsg R", hmsg, params.Tweak.Hmsg(optRand2, pkSeed, root, message))
	assertDifferent(t, "Tweak.Hmsg PKseed", hmsg, params.Tweak.Hmsg(optRand, pkSeed2, root, message))
	assertDifferent(t, "Tweak.Hmsg PKroot", hmsg, params.Tweak.Hmsg(optRand, pkSeed, root2, message))

	// PRFmsg must bind its secret, optional randomizer, and message.
	prfmsg := params.Tweak.PRFmsg(skSeed, optRand, message)
	assertDifferent(t, "Tweak.PRFmsg message", prfmsg, params.Tweak.PRFmsg(skSeed, optRand, message2))
	assertDifferent(t, "Tweak.PRFmsg OptRand", prfmsg, params.Tweak.PRFmsg(skSeed, optRand2, message))
	assertDifferent(t, "Tweak.PRFmsg SKprf", prfmsg, params.Tweak.PRFmsg(skSeed2, optRand, message))
}

func TestSpxHashRealisticMissRate(t *testing.T) {
	const n = 1000
	start := time.Now()
	for i := 0; i < n; i++ {
		// Every input is unique, matching a distinct ADRS/input pair.
		input := []byte{byte(i >> 8), byte(i), 'x'}
		if got := common.SpxHash(input); len(got) == 0 {
			t.Fatalf("common.SpxHash returned no output for unique input %d", i)
		}
	}
	total := time.Since(start)
	t.Logf("common.SpxHash, %d unique-input calls: %v total, %v/call",
		n, total, total/n)
}

func TestSpxHashRepeatedInputCacheHit(t *testing.T) {
	const n = 1000
	input := []byte("same input every time")
	if got := common.SpxHash(input); len(got) == 0 {
		t.Fatal("common.SpxHash returned no output while warming cache")
	}
	start := time.Now()
	for i := 0; i < n; i++ {
		_ = common.SpxHash(input)
	}
	total := time.Since(start)
	t.Logf("common.SpxHash, %d REPEATED-input calls: %v total, %v/call",
		n, total, total/n)
}
