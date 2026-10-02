// hmsglen_test.go reports Hmsg outLen vs hasher digest size per parameter set,
// settling from data whether spxHashExpand ever takes its XOF expansion branch
// (outLen > digest size).
//
// Diagnostic only: writes no files, asserts nothing about digests.
package tweakable_test

import (
	"fmt"
	"testing"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	spx "github.com/sphinxfndorg/protocol/src/spxhash/v2"
)

// digestLenFor recomputes parameters.MakeSthincsPlus's MessageDigestLength
// formula (md_len + idx_tree_len + idx_leaf_len). The value is consumed by the
// tweakable instance rather than stored on Parameters, so it is derived here
// from the same inputs MakeSthincsPlus uses.
func digestLenFor(p *parameters.Parameters) int {
	hPrime := p.H / p.D
	mdLen := int((p.K*p.LogT + 7) / 8)
	idxTreeLen := int((p.H - hPrime + 7) / 8)
	idxLeafLen := int((hPrime + 7) / 8)
	return mdLen + idxTreeLen + idxLeafLen
}

func TestReportHmsgDigestLengths(t *testing.T) {
	fmt.Printf("\n%-24s %8s %8s %10s\n", "set", "HmsgLen", "digestSz", "expands?")
	anyExpand := false
	for _, pc := range allParamCases() {
		p := pc.make(false)
		h, err := spx.NewSphinxHash(256, spx.ProtocolSalt)
		if err != nil {
			t.Fatalf("NewSphinxHash: %v", err)
		}
		msgLen := digestLenFor(p)
		digestSz := h.Size()
		expands := msgLen > digestSz
		if expands {
			anyExpand = true
		}
		fmt.Printf("%-24s %8d %8d %10v\n", pc.name, msgLen, digestSz, expands)
	}
	fmt.Printf("\nany set needing XOF expansion in Hmsg: %v\n", anyExpand)
	if anyExpand {
		t.Log("Hmsg expands past the digest on at least one set")
	} else {
		t.Log("Hmsg NEVER expands past the digest: the digest-size path is the only one taken")
	}
	fmt.Println()
}
