// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/sthincs/sign/backend/verify_metrics.go
package sign

import (
	"sync"
	"sync/atomic"
)

// Verification call counters.
//
// PURPOSE. These exist to answer, with evidence rather than assumption, one
// question: would memoizing Spx_verify results be worth it? A verification
// cache is only justified if the same (pk, signature) is verified more than
// once AND the key can be derived more cheaply than the verification it skips.
//
// The answer measured on this codebase was no — see the STHINCS README's
// "Memoize verification" entry — and these counters are what that conclusion
// rests on. They are kept so the question can be re-answered if the call
// pattern changes.
//
// WHAT THIS IS NOT. This is a counter, not a cache. Nothing here can change a
// verification result: there is no store of "known good" signatures, and
// verification still runs in full on every call. It cannot be reached from the
// verification path's control flow — callers only ever increment counters and
// then call Spx_verify exactly as before.
//
// COST. When disabled (the default) each call is one relaxed atomic load and,
// on the rare enabled path, one store. When enabled, repeat detection costs a
// mutex-guarded map lookup keyed by a hash the caller already computed.
var (
	// verifyMetricsEnabled gates ALL counting. Off by default so production
	// pays only a relaxed load.
	verifyMetricsEnabled atomic.Bool

	// verifyCalls counts every Spx_verify invocation, by site.
	verifyCalls atomic.Uint64

	// verifyValid counts invocations that verified successfully.
	verifyValid atomic.Uint64

	// verifyInvalid counts invocations that failed.
	verifyInvalid atomic.Uint64

	// verifyBytes counts signature bytes processed, to show the cost that a
	// cache would have to avoid re-serializing.
	verifyBytes atomic.Uint64

	// verifyRepeats counts calls whose (pk, signatureHash) pair had been seen
	// before — the exact number a positive-result cache could have served.
	verifyRepeats atomic.Uint64

	// verifySeen dedupes (pk, signatureHash) so repeats can be counted.
	verifyMu   sync.Mutex
	verifySeen map[string]struct{}
)

// EnableVerifyMetrics turns counting on. Intended for tests and local
// diagnostics; it is never enabled in consensus or serving paths.
func EnableVerifyMetrics() {
	verifyMetricsEnabled.Store(true)
}

// DisableVerifyMetrics turns counting off.
func DisableVerifyMetrics() {
	verifyMetricsEnabled.Store(false)
}

// VerifyMetricsEnabled reports whether counting is on.
func VerifyMetricsEnabled() bool {
	return verifyMetricsEnabled.Load()
}

// VerifyMetrics is a point-in-time snapshot of the counters.
type VerifyMetrics struct {
	Enabled  bool
	Calls    uint64
	Valid    uint64
	Invalid  uint64
	Bytes    uint64
	Repeats  uint64
	Distinct uint64
}

// VerifyMetricsSnapshot reads the counters. Cheap and safe to call at any time;
// it does not enable counting by itself.
func VerifyMetricsSnapshot() VerifyMetrics {
	verifyMu.Lock()
	distinct := uint64(len(verifySeen))
	verifyMu.Unlock()
	return VerifyMetrics{
		Enabled:  verifyMetricsEnabled.Load(),
		Calls:    verifyCalls.Load(),
		Valid:    verifyValid.Load(),
		Invalid:  verifyInvalid.Load(),
		Bytes:    verifyBytes.Load(),
		Repeats:  verifyRepeats.Load(),
		Distinct: distinct,
	}
}

// ResetVerifyMetrics zeroes the counters. Intended for tests, so each scenario
// starts from a known state.
func ResetVerifyMetrics() {
	verifyCalls.Store(0)
	verifyValid.Store(0)
	verifyInvalid.Store(0)
	verifyBytes.Store(0)
	verifyRepeats.Store(0)
	verifyMu.Lock()
	verifySeen = nil
	verifyMu.Unlock()
}

// recordVerifyCall counts one verification attempt.
//
// repKey identifies the exact input for repeat detection and must be a
// collision-resistant digest of (pk, signature) supplied by the caller — the
// caller already computes a signature hash at every site for the cheap
// pre-check, so this reuses it rather than re-serializing.
//
// This function returns immediately and changes nothing about the outcome: the
// caller must run the real verification regardless of what is counted.
func recordVerifyCall(sigBytes int, valid bool, repKey string) {
	if !verifyMetricsEnabled.Load() {
		return
	}
	verifyCalls.Add(1)
	verifyBytes.Add(uint64(sigBytes))
	if valid {
		verifyValid.Add(1)
	} else {
		verifyInvalid.Add(1)
	}
	if repKey == "" {
		return
	}
	verifyMu.Lock()
	if verifySeen == nil {
		verifySeen = make(map[string]struct{})
	}
	if _, dup := verifySeen[repKey]; dup {
		verifyRepeats.Add(1)
	} else {
		verifySeen[repKey] = struct{}{}
	}
	verifyMu.Unlock()
}
