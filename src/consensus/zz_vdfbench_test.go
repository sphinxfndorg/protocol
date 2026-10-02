package consensus

import (
	"math/big"
	"testing"
	"time"
)

func TestVDFFromGenesisParamsIsSlow(t *testing.T) {
	InitVDFFromGenesis(func() (string, error) {
		return "GENESIS_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", nil
	})
	p, err := LoadCanonicalVDFParams()
	if err != nil {
		t.Fatalf("LoadCanonicalVDFParams: %v", err)
	}
	t.Logf("params: D bits=%d T=%d", p.Discriminant.BitLen(), p.T)
	start := time.Now()
	v := NewProductionVDF(p.Discriminant, p.T)
	elapsed := time.Since(start)
	t.Logf("NewProductionVDF took %v (impl=%v)", elapsed, v != nil)
	if elapsed > 5*time.Second {
		t.Errorf("NewProductionVDF is %v — far too slow to hold a consensus lock for", elapsed)
	}
	_ = big.NewInt(0)
}
