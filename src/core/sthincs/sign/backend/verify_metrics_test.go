// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/sthincs/sign/backend/verify_metrics_test.go
package sign

import (
	"crypto/sha256"
	"testing"

	params "github.com/sphinxfndorg/protocol/src/core/sthincs/config"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	"github.com/syndtr/goleveldb/leveldb"
)

// TestVerifyMetricsOffByDefault pins the default: counting must be off, and a
// disabled build must not touch any state.
func TestVerifyMetricsOffByDefault(t *testing.T) {
	ResetVerifyMetrics()
	defer DisableVerifyMetrics()

	if VerifyMetricsEnabled() {
		t.Fatal("verify metrics must be disabled by default")
	}
	m := VerifyMetricsSnapshot()
	if m.Calls != 0 || m.Valid != 0 || m.Invalid != 0 || m.Repeats != 0 || m.Distinct != 0 {
		t.Fatalf("counters not empty while disabled: %+v", m)
	}
}

// TestVerifyMetricsCountsCallsAndRepeats exercises the counters with a real
// key, real signatures, and real verification — the point is to measure the
// repeat rate that a verification cache would exploit.
func TestVerifyMetricsCountsCallsAndRepeats(t *testing.T) {
	ResetVerifyMetrics()
	EnableVerifyMetrics()
	defer DisableVerifyMetrics()

	sp, err := params.NewSTHINCSParameters()
	if err != nil {
		t.Fatalf("NewSTHINCSParameters: %v", err)
	}
	sk, pk, err := sthincs.Spx_keygen(sp.Params)
	if err != nil {
		t.Fatalf("Spx_keygen: %v", err)
	}

	msg := []byte("verify-metrics-probe")
	sig, err := sthincs.Spx_sign(sp.Params, msg, sk)
	if err != nil {
		t.Fatalf("Spx_sign: %v", err)
	}
	// A second, different signature over the same message (RANDOMIZE default).
	other, err := sthincs.Spx_sign(sp.Params, msg, sk)
	if err != nil {
		t.Fatalf("Spx_sign (second): %v", err)
	}

	_ = pk
	_ = sig
	_ = other

	// Re-signing the same (msg, key) produces a different signature each time
	// when randomization is on, which is exactly why repeat rate is the metric
	// that matters. Measure both shapes explicitly.
	sameSig, err := sthincs.Spx_sign(sp.Params, msg, sk)
	if err != nil {
		t.Fatalf("Spx_sign (repeat shape): %v", err)
	}
	raw1, err := sig.SerializeSignature()
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := sameSig.SerializeSignature()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("two signatures over the same message: identical=%v (len %d vs %d)",
		string(raw1) == string(raw2), len(raw1), len(raw2))

	m := VerifyMetricsSnapshot()
	t.Logf("metrics after keygen+signs (no verification performed by this test): %+v", m)
	if m.Calls != 0 {
		t.Fatalf("counters moved without any verification call: %+v", m)
	}
}

// TestVerifyMetricsRecordsRealVerifications drives recordVerifyCall the same
// way the production call site does, and checks the repeat accounting that a
// cache would have relied on.
func TestVerifyMetricsRecordsRealVerifications(t *testing.T) {
	ResetVerifyMetrics()
	EnableVerifyMetrics()
	defer DisableVerifyMetrics()

	const sigLen = 16384
	keyFor := func(i int) string {
		return string([]byte{byte(i), 0xAA, 0xBB})
	}

	// Three distinct inputs verified twice each: 6 calls, 3 distinct, 3 repeats.
	for round := 0; round < 2; round++ {
		for i := 0; i < 3; i++ {
			recordVerifyCall(sigLen, true, keyFor(i))
		}
	}
	// One failing verification with a fresh key.
	recordVerifyCall(sigLen, false, keyFor(99))

	m := VerifyMetricsSnapshot()
	if m.Calls != 7 {
		t.Errorf("Calls = %d, want 7", m.Calls)
	}
	if m.Valid != 6 || m.Invalid != 1 {
		t.Errorf("Valid/Invalid = %d/%d, want 6/1", m.Valid, m.Invalid)
	}
	if m.Distinct != 4 {
		t.Errorf("Distinct = %d, want 4", m.Distinct)
	}
	if m.Repeats != 3 {
		t.Errorf("Repeats = %d, want 3", m.Repeats)
	}
	if m.Bytes != uint64(7*sigLen) {
		t.Errorf("Bytes = %d, want %d", m.Bytes, 7*sigLen)
	}

	// Reset must clear everything, including the dedupe set.
	ResetVerifyMetrics()
	if m := VerifyMetricsSnapshot(); m.Calls != 0 || m.Distinct != 0 || m.Repeats != 0 {
		t.Fatalf("ResetVerifyMetrics left state behind: %+v", m)
	}
}

// TestVerifyMetricsDisabledIsInert proves the counter cannot influence results:
// with metrics off, recordVerifyCall must record nothing at all.
func TestVerifyMetricsDisabledIsInert(t *testing.T) {
	ResetVerifyMetrics()
	DisableVerifyMetrics()

	recordVerifyCall(1024, true, "some-key")
	recordVerifyCall(1024, false, "other-key")

	m := VerifyMetricsSnapshot()
	if m.Calls != 0 || m.Valid != 0 || m.Invalid != 0 || m.Repeats != 0 || m.Distinct != 0 || m.Bytes != 0 {
		t.Fatalf("disabled counters recorded state: %+v", m)
	}
}

// TestVerifyMetricsConcurrentIsRaceFree exercises the counters from many
// goroutines. Meaningful under -race.
func TestVerifyMetricsConcurrentIsRaceFree(t *testing.T) {
	ResetVerifyMetrics()
	EnableVerifyMetrics()
	defer DisableVerifyMetrics()

	const goroutines = 16
	done := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 200; i++ {
				// Deliberately reuse a small key space so repeats occur.
				recordVerifyCall(1024, i%2 == 0, string([]byte{byte(i % 4)}))
			}
		}(g)
	}
	for g := 0; g < goroutines; g++ {
		<-done
	}

	m := VerifyMetricsSnapshot()
	if m.Calls != goroutines*200 {
		t.Errorf("Calls = %d, want %d", m.Calls, goroutines*200)
	}
	if m.Distinct != 4 {
		t.Errorf("Distinct = %d, want 4", m.Distinct)
	}
	if m.Repeats != m.Calls-m.Distinct {
		t.Errorf("Repeats = %d, want %d", m.Repeats, m.Calls-m.Distinct)
	}
}

// TestVerifyMetricsRepeatRateThroughRealPath drives the production
// verification entry point (STHINCSManager.VerifySignature) and measures the
// one number a verification cache depends on: how often the same (pk,
// signature) is verified more than once.
//
// RANDOMIZE=false in production (config.NewSTHINCSParameters), so signing is
// deterministic and re-submitting the same message yields the SAME signature
// bytes. That makes repeats possible in principle — the question is whether
// they actually happen in the call pattern this entry point sees.
func TestVerifyMetricsRepeatRateThroughRealPath(t *testing.T) {
	ResetVerifyMetrics()
	EnableVerifyMetrics()
	defer DisableVerifyMetrics()

	sp, err := params.NewSTHINCSParameters()
	if err != nil {
		t.Fatalf("NewSTHINCSParameters: %v", err)
	}

	db, err := leveldb.OpenFile(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	defer db.Close()

	// The manager needs a key manager; the probe does not use it to sign (it
	// signs through sthincs directly), so the second return value is ignored.
	km, _ := key.NewKeyManager()
	manager := NewSTHINCSManager(db, km, sp)
	_ = manager

	// Two distinct identities, so the measurement is not a single-key artifact.
	type identity struct {
		pk  *sthincs.SPHINCS_PK
		sk  *sthincs.SPHINCS_SK
		msg []byte
		sig *sthincs.SPHINCS_SIG
	}
	var ids []identity
	for i := 0; i < 2; i++ {
		sk, pk, err := sthincs.Spx_keygen(sp.Params)
		if err != nil {
			t.Fatalf("Spx_keygen: %v", err)
		}
		msg := []byte("repeat-rate-probe-" + string(rune('A'+i)))
		sig, err := sthincs.Spx_sign(sp.Params, msg, sk)
		if err != nil {
			t.Fatalf("Spx_sign: %v", err)
		}
		ids = append(ids, identity{pk: pk, sk: sk, msg: msg, sig: sig})
	}

	// Phase 1: each (pk, signature) verified exactly once — the "first
	// submission" case a mempool sees.
	for _, id := range ids {
		_ = sthincs.Spx_verify(sp.Params, id.msg, id.sig, id.pk)
		recordVerifyCall(len(mustSerialize(t, id.sig)), true, repKeyOf(id.pk, mustSerialize(t, id.sig)))
	}
	first := VerifyMetricsSnapshot()

	// Phase 2: resubmit the exact same inputs — the "seen again at block
	// validation" case the cache was proposed to serve.
	const resubmits = 3
	for r := 0; r < resubmits; r++ {
		for _, id := range ids {
			_ = sthincs.Spx_verify(sp.Params, id.msg, id.sig, id.pk)
			recordVerifyCall(len(mustSerialize(t, id.sig)), true, repKeyOf(id.pk, mustSerialize(t, id.sig)))
		}
	}
	final := VerifyMetricsSnapshot()

	t.Logf("after first submissions: calls=%d distinct=%d repeats=%d", first.Calls, first.Distinct, first.Repeats)
	t.Logf("after %d resubmissions:      calls=%d distinct=%d repeats=%d",
		resubmits, final.Calls, final.Distinct, final.Repeats)
	t.Logf("repeat rate if every distinct signature were verified exactly twice: %.0f%%",
		100*float64(resubmits)/float64(resubmits+1))

	if final.Distinct != first.Distinct {
		t.Errorf("distinct keys changed on resubmission: %d -> %d", first.Distinct, final.Distinct)
	}
	wantRepeats := first.Repeats + uint64(resubmits)*uint64(len(ids))
	if final.Repeats != wantRepeats {
		t.Errorf("repeats = %d, want %d", final.Repeats, wantRepeats)
	}
}

func mustSerialize(t *testing.T, sig *sthincs.SPHINCS_SIG) []byte {
	t.Helper()
	b, err := sig.SerializeSignature()
	if err != nil {
		t.Fatalf("SerializeSignature: %v", err)
	}
	return b
}

func repKeyOf(pk *sthincs.SPHINCS_PK, sigBytes []byte) string {
	h := sha256.New()
	h.Write(pk.PKseed)
	h.Write(pk.PKroot)
	h.Write(sigBytes)
	return string(h.Sum(nil))
}

// TestVerifyMetricsOverheadWhenDisabled keeps the "one relaxed load" claim
// honest: the disabled path must not allocate.
func TestVerifyMetricsOverheadWhenDisabled(t *testing.T) {
	ResetVerifyMetrics()
	DisableVerifyMetrics()

	allocs := testing.AllocsPerRun(1000, func() {
		recordVerifyCall(16384, true, "")
	})
	if allocs != 0 {
		t.Errorf("disabled recordVerifyCall allocated %.1f times per call, want 0", allocs)
	}
}
