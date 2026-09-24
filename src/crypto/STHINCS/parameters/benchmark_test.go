package parameters_test

import (
	"testing"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
)

type sphinxHashParameterCase struct {
	name string
	make func(bool) *parameters.Parameters
}

func sphinxHashParameterCases() []sphinxHashParameterCase {
	return []sphinxHashParameterCase{
		{"SHA256-256f-robust", parameters.MakeSthincsPlusSHA256256fRobust},
		{"SHA256-256s-robust", parameters.MakeSthincsPlusSHA256256sRobust},
		{"SHA256-256f-simple", parameters.MakeSthincsPlusSHA256256fSimple},
		{"SHA256-256s-simple", parameters.MakeSthincsPlusSHA256256sSimple},
		{"SHA256-192f-robust", parameters.MakeSthincsPlusSHA256192fRobust},
		{"SHA256-192s-robust", parameters.MakeSthincsPlusSHA256192sRobust},
		{"SHA256-192f-simple", parameters.MakeSthincsPlusSHA256192fSimple},
		{"SHA256-192s-simple", parameters.MakeSthincsPlusSHA256192sSimple},
		{"SHA256-128f-robust", parameters.MakeSthincsPlusSHA256128fRobust},
		{"SHA256-128s-robust", parameters.MakeSthincsPlusSHA256128sRobust},
		{"SHA256-128f-simple", parameters.MakeSthincsPlusSHA256128fSimple},
		{"SHA256-128s-simple", parameters.MakeSthincsPlusSHA256128sSimple},
		{"SHAKE256-256f-robust", parameters.MakeSthincsPlusSHAKE256256fRobust},
		{"SHAKE256-256s-robust", parameters.MakeSthincsPlusSHAKE256256sRobust},
		{"SHAKE256-256f-simple", parameters.MakeSthincsPlusSHAKE256256fSimple},
		{"SHAKE256-256s-simple", parameters.MakeSthincsPlusSHAKE256256sSimple},
		{"SHAKE256-192f-robust", parameters.MakeSthincsPlusSHAKE256192fRobust},
		{"SHAKE256-192s-robust", parameters.MakeSthincsPlusSHAKE256192sRobust},
		{"SHAKE256-192f-simple", parameters.MakeSthincsPlusSHAKE256192fSimple},
		{"SHAKE256-192s-simple", parameters.MakeSthincsPlusSHAKE256192sSimple},
		{"SHAKE256-128f-robust", parameters.MakeSthincsPlusSHAKE256128fRobust},
		{"SHAKE256-128s-robust", parameters.MakeSthincsPlusSHAKE256128sRobust},
		{"SHAKE256-128f-simple", parameters.MakeSthincsPlusSHAKE256128fSimple},
		{"SHAKE256-128s-simple", parameters.MakeSthincsPlusSHAKE256128sSimple},
		{"SPHINXHASH-256f-robust", parameters.MakeSthincsPlusSPHINXHASH256fRobust},
		{"SPHINXHASH-256s-robust", parameters.MakeSthincsPlusSPHINXHASH256sRobust},
		{"SPHINXHASH-256f-simple", parameters.MakeSthincsPlusSPHINXHASH256fSimple},
		{"SPHINXHASH-256s-simple", parameters.MakeSthincsPlusSPHINXHASH256sSimple},
		{"SPHINXHASH-192f-robust", parameters.MakeSthincsPlusSPHINXHASH192fRobust},
		{"SPHINXHASH-192s-robust", parameters.MakeSthincsPlusSPHINXHASH192sRobust},
		{"SPHINXHASH-192f-simple", parameters.MakeSthincsPlusSPHINXHASH192fSimple},
		{"SPHINXHASH-192s-simple", parameters.MakeSthincsPlusSPHINXHASH192sSimple},
		{"SPHINXHASH-128f-robust", parameters.MakeSthincsPlusSPHINXHASH128fRobust},
		{"SPHINXHASH-128s-robust", parameters.MakeSthincsPlusSPHINXHASH128sRobust},
		{"SPHINXHASH-128f-simple", parameters.MakeSthincsPlusSPHINXHASH128fSimple},
		{"SPHINXHASH-128s-simple", parameters.MakeSthincsPlusSPHINXHASH128sSimple},
	}
}

// BenchmarkSpxSignConstructors measures Spx_sign for every parameter
// constructor. The active production set is not changed by this benchmark.
// Run with -benchtime=1x when collecting comparable one-signature timings on
// a machine where the full signing cost is intentionally high.
func BenchmarkSpxSignConstructors(b *testing.B) {
	message := []byte("sphinx-sthincs-sign-benchmark")
	for _, tc := range sphinxHashParameterCases() {
		tc := tc
		b.Run(tc.name, func(b *testing.B) {
			params := tc.make(false)
			sk, _, err := sthincs.Spx_keygen(params)
			if err != nil {
				b.Fatalf("Spx_keygen: %v", err)
			}

			// Measure Spx_sign only. Capture the serialized size outside the
			// timed loop so the reported ns/op is signing cost, not codec cost.
			probeSignature, err := sthincs.Spx_sign(params, message, sk)
			if err != nil {
				b.Fatalf("Spx_sign probe: %v", err)
			}
			serialized, err := probeSignature.SerializeSignature()
			if err != nil {
				b.Fatalf("SerializeSignature: %v", err)
			}
			signatureSize := len(serialized)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := sthincs.Spx_sign(params, message, sk); err != nil {
					b.Fatalf("Spx_sign: %v", err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(signatureSize), "signature-bytes")
		})
	}
}
