// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/sthincs/zeroize_race_test.go
package sthincs

import (
	"sync"
	"testing"
	"time"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/util"
)

// TestZeroizeConcurrentWithSign pins the synchronization between Zeroize and
// Spx_sign on a shared SPHINCS_SK.
//
// Zeroize wipes SKseed/SKPrf in place while Spx_sign reads those same backing
// arrays. Both now take sk.mu, so the reads and the wipe are ordered, and the
// race detector has nothing to report.
//
// This test is only meaningful because util.Wipe uses an explicit assignment
// loop. With clear() the detector cannot see the wipe at all, and this test
// would pass against the broken code as readily as against the fixed code —
// which is how the original defect stayed invisible.
//
// The sign outcome itself is deliberately not asserted: a Zeroize that wins
// the race hands Spx_sign a zeroed snapshot, so signing legitimately fails the
// self-check at the end of Spx_sign and returns an error. That is safe
// behavior. What must never happen is an unsynchronized read/write, which is
// what -race is here to catch.
func TestZeroizeConcurrentWithSign(t *testing.T) {
	// A fast set: the point is many overlapping attempts, not coverage of the
	// expensive parameter sets.
	p := parameters.MakeSthincsPlusSHA256128fSimple(false)
	msg := []byte("zeroize/sign race")

	// Overlap the two goroutines with a time-bounded window rather than a
	// fixed iteration count; a fixed count lets the cheap side finish long
	// before the expensive one starts, and the test would pass vacuously.
	const window = 2 * time.Second

	for trial := 0; trial < 8; trial++ {
		sk, _, err := Spx_keygen(p)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}

		var wg sync.WaitGroup
		deadline := time.Now().Add(window)

		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				// Both the signing error and a nil signature are acceptable
				// here; only the race matters.
				_, _ = Spx_sign(p, msg, sk)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				sk.Zeroize()
			}
		}()

		wg.Wait()
	}
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func utilWipeAll(bufs ...[]byte) {
	for _, b := range bufs {
		util.Wipe(b)
	}
}

// TestSnapshotLengthValidationWipesNothing confirms the documented invariant in
// snapshot: a length failure must not hand back partially built copies.
func TestSnapshotLengthValidationWipesNothing(t *testing.T) {
	p := parameters.MakeSthincsPlusSHA256128fSimple(false)

	sk, _, err := Spx_keygen(p)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Ask for a length that does not match the key's components.
	gotSeed, gotPrf, gotPKSeed, gotPKRoot, err := sk.snapshot(p.N + 1)
	if err == nil {
		t.Fatal("expected an error for a mismatched component length")
	}
	if gotSeed != nil || gotPrf != nil || gotPKSeed != nil || gotPKRoot != nil {
		t.Fatal("snapshot returned non-nil copies alongside its error; those would leak")
	}
}

// TestZeroizedKeyDoesNotRecache is the deterministic version of the cache
// invariant, with no timing dependence at all.
//
// The sequence is exactly the window a race test cannot pin down:
//
//	snapshot (valid key material)  ->  Zeroize  ->  topTreeFor(snapshot seed)
//
// The caller here holds a genuine pre-wipe snapshot, so topTreeFor builds a
// real top tree whose root does match PKroot. Under the pre-fix code the seeds
// came from sk.SKseed, which is now zeros, so the root check failed and the
// function returned nil — correct output for the wrong reason, and no positive
// evidence that the cache was protected. With the snapshot-based build a tree
// really is produced, and the zeroized flag is the only thing stopping it from
// being cached.
//
// So the assertion that matters is the cache slot, not the return value.
func TestZeroizedKeyDoesNotRecache(t *testing.T) {
	p := parameters.MakeSthincsPlusSHA256128fSimple(false)

	sk, _, err := Spx_keygen(p)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// A pre-wipe snapshot: valid key material, taken while the key is live.
	skSeed, skPrf, pkSeed, pkRoot, err := sk.snapshot(p.N)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	defer utilWipeAll(skSeed, skPrf, pkSeed, pkRoot)

	if skSeed == nil || allZero(skSeed) {
		t.Fatal("snapshot produced no usable seed")
	}

	sk.Zeroize()

	if sk.topTree != nil {
		t.Fatal("cache still populated immediately after Zeroize")
	}

	// Build with the pre-wipe snapshot. This must produce a usable tree, since
	// the snapshot is valid and its root genuinely matches PKroot.
	tree := sk.topTreeFor(p, skSeed, pkSeed, pkRoot)
	if tree == nil {
		t.Fatal("topTreeFor returned nil for a valid pre-wipe snapshot; " +
			"the tree should build fine, it just must not be cached")
	}

	// The point of the test: the tree was built, but it must not have been
	// published to the key.
	if sk.topTree != nil {
		t.Fatal("cache repopulated on a spent key: topTreeFor cached a tree " +
			"built from a pre-wipe snapshot after Zeroize ran")
	}

	// And a second call must behave identically rather than caching on the
	// second attempt.
	if again := sk.topTreeFor(p, skSeed, pkSeed, pkRoot); again == nil {
		t.Fatal("second topTreeFor returned nil")
	}
	if sk.topTree != nil {
		t.Fatal("cache repopulated on a spent key by repeated topTreeFor calls")
	}
}

// TestZeroizedKeyNeverServesFromCache checks the other half of the flag: a
// zeroized key must not hand back a previously cached tree.
func TestZeroizedKeyNeverServesFromCache(t *testing.T) {
	p := parameters.MakeSthincsPlusSHA256128fSimple(false)

	sk, _, err := Spx_keygen(p)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	skSeed, skPrf, pkSeed, pkRoot, err := sk.snapshot(p.N)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	defer utilWipeAll(skSeed, skPrf, pkSeed, pkRoot)

	// Populate the cache while the key is live.
	first := sk.topTreeFor(p, skSeed, pkSeed, pkRoot)
	if first == nil {
		t.Fatal("topTreeFor returned nil on a live key")
	}
	if sk.topTree == nil {
		t.Fatal("topTreeFor did not cache on a live key")
	}

	sk.Zeroize()
	if sk.topTree != nil {
		t.Fatal("Zeroize did not drop the cache")
	}

	// With a live-key seed the build would succeed, so a non-nil return here
	// proves the call was NOT served from a stale cache.
	second := sk.topTreeFor(p, skSeed, pkSeed, pkRoot)
	if second == nil {
		t.Fatal("topTreeFor returned nil after Zeroize with a valid pre-wipe snapshot")
	}
	if sk.topTree != nil {
		t.Fatal("cache repopulated after Zeroize")
	}
}

// TestSnapshotRejectsZeroizedKey pins the fail-fast guard at the top of
// snapshot: a spent key produces an error, not four zero-filled copies.
//
// Before the guard, a zeroized key still passed the length check (Zeroize
// wipes in place, it does not shorten anything) and handed back four buffers
// of zeros. That "worked" only because the caller then failed the self-check
// after a full signing run. Now it fails immediately.
func TestSnapshotRejectsZeroizedKey(t *testing.T) {
	p := parameters.MakeSthincsPlusSHA256128fSimple(false)

	sk, _, err := Spx_keygen(p)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// A live key snapshots fine, so the test is not passing vacuously.
	if _, _, _, _, err := sk.snapshot(p.N); err != nil {
		t.Fatalf("live key snapshot failed: %v", err)
	}

	sk.Zeroize()

	skSeed, skPrf, pkSeed, pkRoot, err := sk.snapshot(p.N)
	if err == nil {
		t.Fatal("snapshot succeeded on a zeroized key; want an error")
	}
	if skSeed != nil || skPrf != nil || pkSeed != nil || pkRoot != nil {
		t.Fatalf("snapshot returned copies alongside its error: "+
			"skSeed=%v skPrf=%v pkSeed=%v pkRoot=%v",
			skSeed != nil, skPrf != nil, pkSeed != nil, pkRoot != nil)
	}

	// The flag is permanent: a second attempt fails the same way.
	if _, _, _, _, err := sk.snapshot(p.N); err == nil {
		t.Fatal("second snapshot on a zeroized key succeeded; the flag must be permanent")
	}
}

// TestSpxSignOnZeroizedKeyFailsFast checks that signing with a spent key is a
// cheap error rather than a full signing run that fails at the self-check.
//
// The bound is relative, not absolute: one cold tree build is measured on a
// fresh key, and the zeroized call must finish in under a tenth of that. A
// cold build is the dominant cost of a signature, so anything approaching it
// would mean the guard is not actually short-circuiting.
func TestSpxSignOnZeroizedKeyFailsFast(t *testing.T) {
	p := parameters.MakeSthincsPlusSHA256128fSimple(false)
	msg := []byte("fail fast")

	// Reference cost: one signature on a fresh, cold key.
	coldSK, _, err := Spx_keygen(p)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	coldStart := time.Now()
	if _, err := Spx_sign(p, msg, coldSK); err != nil {
		t.Fatalf("cold sign: %v", err)
	}
	coldDur := time.Since(coldStart)
	if coldDur <= 0 {
		t.Fatalf("cold sign measured as %s; clock problem", coldDur)
	}

	sk, _, err := Spx_keygen(p)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sk.Zeroize()

	start := time.Now()
	sig, err := Spx_sign(p, msg, sk)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Spx_sign on a zeroized key returned a nil error")
	}
	if sig != nil {
		t.Fatal("Spx_sign on a zeroized key returned a signature")
	}
	if sk.topTree != nil {
		t.Fatal("signing on a zeroized key populated the top-layer cache")
	}

	budget := coldDur / 10
	if elapsed >= budget {
		t.Fatalf("zeroized sign took %s, budget is %s (a tenth of the %s cold build); "+
			"the snapshot guard is not short-circuiting", elapsed, budget, coldDur)
	}
	t.Logf("cold build %s; zeroized sign %s (budget %s)", coldDur, elapsed, budget)
}
