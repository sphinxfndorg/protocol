// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/sthincs/zeroize_stress_test.go
package sthincs

import (
	"math/rand"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/tweakable"
)

// hookTweak wraps a real tweak and parks callers inside Hmsg.
//
// Spx_sign calls Hmsg exactly once, immediately AFTER snapshot and BEFORE
// topTreeFor. A signer blocked there has therefore provably taken its
// snapshot and provably not yet reached the cache, which is exactly the window
// TestZeroizeBetweenSnapshotAndTopTreeFor needs to hit. Using the injectable
// params.Tweak means production code needs no hook at all.
//
// All methods other than Hmsg are promoted from the embedded real tweak, so
// only Hmsg is intercepted.
type hookTweak struct {
	tweakable.TweakableHashFunction
	blockFirst int32
	calls      atomic.Int32
	arrived    chan struct{}
	release    chan struct{}
}

func (h *hookTweak) Hmsg(R, PKseed, PKroot, M []byte) []byte {
	if h.calls.Add(1) <= h.blockFirst {
		h.arrived <- struct{}{}
		<-h.release
	}
	return h.TweakableHashFunction.Hmsg(R, PKseed, PKroot, M)
}

// TestZeroizeBetweenSnapshotAndTopTreeFor is the exact, deterministic version
// of the snapshot->topTreeFor window test.
//
// Every signer is parked inside Hmsg, which Spx_sign calls after snapshot and
// before topTreeFor, so at the moment Zeroize runs each signer provably holds
// a pre-wipe snapshot and provably has not touched the cache. Zeroize then
// completes while they are still parked, and each is released into
// topTreeFor against an already-zeroized key.
//
// That is the case the zeroized flag in topTreeFor exists for: snapshot has
// long since rejected every newer caller, so the only thing preventing a spent
// key from holding a cache is that flag.
//
// Because the interleaving is forced rather than sampled, this test is
// deterministic. There is no timing window to tune and no statistic.
func TestZeroizeBetweenSnapshotAndTopTreeFor(t *testing.T) {
	p := parameters.MakeSthincsPlusSHA256128fSimple(false)
	msg := []byte("exact snapshot/topTreeFor window")

	base, pk, err := Spx_keygen(p)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// Warm the base once so a warm clone can share the cached tree.
	if _, err := Spx_sign(p, msg, base); err != nil {
		t.Fatalf("base warm-up sign: %v", err)
	}
	if base.topTree == nil {
		t.Fatal("warm-up did not populate the base top-layer cache")
	}

	for _, warm := range []bool{false, true} {
		for _, n := range []int{1, 4} {
			warm, n := warm, n
			name := "cold"
			if warm {
				name = "warm"
			}
			t.Run(name+"/signers="+strconv.Itoa(n), func(t *testing.T) {
				runInWindow(t, p, base, pk, msg, warm, n)
			})
		}
	}
}

// runInWindow parks signCount signers inside Hmsg, runs Zeroize while they are
// parked, releases them, and checks every resulting outcome.
func runInWindow(t *testing.T, p *parameters.Parameters, base *SPHINCS_SK,
	pk *SPHINCS_PK, msg []byte, warm bool, signCount int) {
	t.Helper()

	sk := cloneKey(base, warm)

	hook := &hookTweak{
		TweakableHashFunction: p.Tweak,
		blockFirst:            int32(signCount),
		arrived:               make(chan struct{}, signCount),
		release:               make(chan struct{}),
	}
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(hook.release) }) }

	// Copy the parameters and swap in the hook. The copy is local to this test
	// and never escapes, so mutating it cannot affect the shared parameter set.
	hp := *p
	hp.Tweak = hook

	type res struct {
		sig *SPHINCS_SIG
		err error
	}
	out := make([]res, signCount)

	var wg sync.WaitGroup
	start := make(chan struct{})
	var startOnce sync.Once

	for i := 0; i < signCount; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			out[i].sig, out[i].err = Spx_sign(&hp, msg, sk)
		}(i)
	}
	startOnce.Do(func() { close(start) })

	// Wait until every signer is parked inside Hmsg. Bounded so a signer that
	// never arrives fails loudly instead of hanging.
	const arriveTimeout = 60 * time.Second
	deadline := time.After(arriveTimeout)
	for i := 0; i < signCount; i++ {
		select {
		case <-hook.arrived:
		case <-deadline:
			releaseAll()
			wg.Wait()
			t.Fatalf("only %d of %d signers reached Hmsg within %s",
				i, signCount, arriveTimeout)
		}
	}

	// Every signer is now parked between its snapshot and topTreeFor.
	sk.Zeroize()
	if sk.topTree != nil {
		releaseAll()
		wg.Wait()
		t.Fatal("spent key still holds a top-layer cache immediately after Zeroize")
	}
	if !sk.zeroized {
		releaseAll()
		wg.Wait()
		t.Fatal("zeroized flag not set")
	}

	releaseAll()
	wg.Wait()

	// Every signer snapshotted before the wipe, so every one of them must have
	// completed with a valid signature built from its own snapshot.
	for i := range out {
		if out[i].err != nil {
			t.Fatalf("signer %d: pre-wipe snapshot failed to sign: %v", i, out[i].err)
		}
		if out[i].sig == nil {
			t.Fatalf("signer %d: nil signature and nil error", i)
		}
		// Verify with the ORIGINAL params: the hook must not affect the bytes.
		if !Spx_verify(p, msg, out[i].sig, pk) {
			t.Fatalf("signer %d: signature does not verify under the original params", i)
		}
	}

	// The spent key must still hold no cache after the signers ran through
	// topTreeFor.
	if sk.topTree != nil {
		t.Fatal("cache repopulated on a spent key after signers reached topTreeFor")
	}

	// And the key is permanently spent: a fresh call now fails immediately.
	sig, err := Spx_sign(p, msg, sk)
	if err == nil {
		t.Fatal("Spx_sign on a spent key returned a nil error")
	}
	if sig != nil {
		t.Fatal("Spx_sign on a spent key returned a signature")
	}
}

// cloneKey builds a fresh *SPHINCS_SK with its own copies of the four key
// components and a zero-value mutex, so each stress iteration starts from a
// live key without paying for a keygen.
//
// topTree is seeded from base when warm is true. The cached tree object is
// immutable once built (Root and AuthPathFromLeaves both hand back copies and
// never mutate the receiver), so sharing the pointer between clones is safe
// and avoids rebuilding it every iteration.
func cloneKey(base *SPHINCS_SK, warm bool) *SPHINCS_SK {
	sk := &SPHINCS_SK{
		SKseed: append([]byte(nil), base.SKseed...),
		SKprf:  append([]byte(nil), base.SKprf...),
		PKseed: append([]byte(nil), base.PKseed...),
		PKroot: append([]byte(nil), base.PKroot...),
	}
	if warm {
		sk.topTree = base.topTree
	}
	return sk
}

// signOutcome records one Spx_sign call and when it finished, relative to the
// shared t0 used by an iteration.
type signOutcome struct {
	sig   *SPHINCS_SIG
	err   error
	endNs int64
}

// iterCounters accumulates per-iteration results for one cache state.
type iterCounters struct {
	iterations int
	valid      int
	errors     int
	lateValid  int
}

// runIteration runs one race: a fresh key clone, four signers each doing a
// single Spx_sign, and a Zeroize fired after a delay drawn uniformly from
// [0, delayMax).
//
// The Zeroize goroutine is part of the WaitGroup on purpose. zeroizeEndNs is
// read by the caller after wg.Wait, and wg.Done/wg.Wait is what establishes the
// happens-before edge that makes that read race-free.
func runIteration(t *testing.T, p *parameters.Parameters, base *SPHINCS_SK,
	pk *SPHINCS_PK, msg []byte, warm bool, delayMax time.Duration,
	rng *rand.Rand, t0 time.Time) (c iterCounters) {
	t.Helper()

	sk := cloneKey(base, warm)

	const signers = 4
	out := make([]signOutcome, signers)

	var wg sync.WaitGroup
	start := make(chan struct{})
	var startOnce sync.Once

	for i := 0; i < signers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			out[i].sig, out[i].err = Spx_sign(p, msg, sk)
			out[i].endNs = time.Since(t0).Nanoseconds()
		}(i)
	}
	startOnce.Do(func() { close(start) })

	// Delay uniform in [0, delayMax). Small delays tend to land before any
	// signer has snapshotted (all errors); large delays land after they have
	// finished (valid, but not late). The interesting band is the middle,
	// which is why the whole range is swept rather than a single point.
	delay := time.Duration(rng.Int63n(int64(delayMax)))

	var zeroizeEndNs int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(delay)
		sk.Zeroize()
		zeroizeEndNs = time.Since(t0).Nanoseconds()
	}()

	wg.Wait()

	for i := range out {
		o := &out[i]
		switch {
		case o.err != nil:
			c.errors++
		case o.sig == nil:
			t.Fatalf("signer %d: nil signature and nil error", i)
		default:
			if !Spx_verify(p, msg, o.sig, pk) {
				t.Fatalf("signer %d: Spx_sign returned a signature that does "+
					"not verify, with nil error", i)
			}
			// A valid signature proves the snapshot was taken before the wipe;
			// nothing more than that is asserted here. See the LATE-VALID note
			// on the test itself.
			c.valid++
			if o.endNs > zeroizeEndNs {
				c.lateValid++
			}
		}
	}

	// After Zeroize returned and every signer finished, a spent key must not
	// be holding a cache.
	if sk.topTree != nil {
		t.Fatalf("spent key still holds a top-layer cache after Zeroize")
	}
	if !sk.zeroized {
		t.Fatal("zeroized flag not set after Zeroize returned")
	}

	c.iterations++
	return c
}

// TestZeroizeDuringSignOutcomes is the randomized, whole-signature race: it
// fires Zeroize at a uniformly random point inside a signature and checks the
// two things that must always hold, whatever the interleaving.
//
//   - No data race. util.Wipe uses an instrumented loop, so -race can see the
//     conflict if there is one.
//   - Every single Spx_sign call returns either a signature that verifies under
//     the public key, or a non-nil error. Never a nil error with an invalid or
//     nil signature.
//
// It deliberately makes no claim about WHERE inside the signature Zeroize
// landed. LATE-VALID means "Zeroize landed mid-signature": the call produced a
// valid signature, so its snapshot was pre-wipe, and it finished after Zeroize
// returned, so the key was spent by the time it was done. That is consistent
// with having passed through topTreeFor while zeroized but it does not observe
// topTreeFor, and it is not proof of any particular window.
//
// For the exact snapshot->topTreeFor window, deterministically forced rather
// than sampled, see TestZeroizeBetweenSnapshotAndTopTreeFor.
func TestZeroizeDuringSignOutcomes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping randomized Zeroize race in short mode; " +
			"TestZeroizeBetweenSnapshotAndTopTreeFor covers the window deterministically")
	}

	p := parameters.MakeSthincsPlusSHA256128fSimple(false)
	msg := []byte("snapshot/topTreeFor window")

	base, pk, err := Spx_keygen(p)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Warm the base key once so topTree is populated and a "warm" clone can
	// share that cached tree.
	if _, err := Spx_sign(p, msg, base); err != nil {
		t.Fatalf("base warm-up sign: %v", err)
	}
	if base.topTree == nil {
		t.Fatal("warm-up did not populate the base top-layer cache")
	}

	// Reference cost of one warm signature on a clone. Used both to scale the
	// Zeroize delay and to report how long iterations take.
	warmStart := time.Now()
	if _, err := Spx_sign(p, msg, cloneKey(base, true)); err != nil {
		t.Fatalf("warm timing sign: %v", err)
	}
	warmSignDur := time.Since(warmStart)
	if warmSignDur <= 0 {
		t.Fatalf("warm sign measured as %s; clock problem", warmSignDur)
	}

	const window = 5 * time.Second

	// Delay is uniform over [0, warmSignDur). Small delays tend to land before
	// any signer has snapshotted (all errors); large delays land after they
	// have finished (valid, but not late). The interesting band is the middle,
	// which is why the whole range is swept rather than a single point.
	//
	// If the window proves too short to produce any LATE-VALID on this
	// machine, concentrate the delay into [0, warmSignDur/2) so Zeroize lands
	// while signers are reliably still in FORS rather than racing them to the
	// finish line. That is a distribution choice; the loop stays bounded by
	// wall-clock and never by an iteration count.
	delayMax := warmSignDur

	rng := rand.New(rand.NewSource(0x5EED))
	t0 := time.Now()
	deadline := t0.Add(window)

	var warm, cold iterCounters
	for time.Now().Before(deadline) {
		c := runIteration(t, p, base, pk, msg, true, delayMax, rng, t0)
		warm.iterations += c.iterations
		warm.valid += c.valid
		warm.errors += c.errors
		warm.lateValid += c.lateValid

		c = runIteration(t, p, base, pk, msg, false, delayMax, rng, t0)
		cold.iterations += c.iterations
		cold.valid += c.valid
		cold.errors += c.errors
		cold.lateValid += c.lateValid
	}

	t.Logf("warmSignDur=%s window=%s delayMax=%s signers/iter=%d",
		warmSignDur, window, delayMax, 4)
	t.Logf("warm: iterations=%d valid=%d errors=%d lateValid=%d",
		warm.iterations, warm.valid, warm.errors, warm.lateValid)
	t.Logf("cold: iterations=%d valid=%d errors=%d lateValid=%d",
		cold.iterations, cold.valid, cold.errors, cold.lateValid)

	if warm.iterations == 0 || cold.iterations == 0 {
		t.Fatal("window too short to run any iterations")
	}

	// The warm case is expected to see Zeroize land mid-signature: the cached
	// tree means the signer reaches the FORS/topTreeFor boundary quickly, so a
	// Zeroize drawn from inside the signature duration usually splits it.
	//
	// This is a sanity check on the sampler, not coverage of the
	// snapshot->topTreeFor window. It only says "the delay distribution reached
	// that part of the signature". The window itself is covered
	// deterministically by TestZeroizeBetweenSnapshotAndTopTreeFor.
	if warm.lateValid == 0 {
		t.Fatalf("no LATE-VALID in the warm case across %d iterations; "+
			"Zeroize never landed mid-signature", warm.iterations)
	}

	// Cold is logged but not enforced. A cold build makes the pre-topTreeFor
	// window a smaller fraction of the signature, so the sampler can miss it
	// on a slow or heavily loaded machine without that indicating a defect.
	if cold.lateValid == 0 {
		t.Logf("note: no LATE-VALID in the cold case (%d iterations); expected "+
			"on a cold build and not treated as a failure", cold.iterations)
	}
}
