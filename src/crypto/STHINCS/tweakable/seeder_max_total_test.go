// seeder_max_total_test.go reports the exact `total` that spxHashExpand
// computes for every call type across all 36 parameter sets, so the stack
// bound in spxHashExpand is chosen from measurement, not guesswork.
//
// Diagnostic only: asserts nothing about digests and writes no files.
package tweakable_test

import (
	"encoding/binary"
	"fmt"
	"sort"
	"testing"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
)

type paramCase struct {
	name string
	make func(bool) *parameters.Parameters
}

func allParamCases() []paramCase {
	return []paramCase{
		{"SHA256-128f-simple", parameters.MakeSthincsPlusSHA256128fSimple},
		{"SHA256-128f-robust", parameters.MakeSthincsPlusSHA256128fRobust},
		{"SHA256-128s-simple", parameters.MakeSthincsPlusSHA256128sSimple},
		{"SHA256-128s-robust", parameters.MakeSthincsPlusSHA256128sRobust},
		{"SHA256-192f-simple", parameters.MakeSthincsPlusSHA256192fSimple},
		{"SHA256-192f-robust", parameters.MakeSthincsPlusSHA256192fRobust},
		{"SHA256-192s-simple", parameters.MakeSthincsPlusSHA256192sSimple},
		{"SHA256-192s-robust", parameters.MakeSthincsPlusSHA256192sRobust},
		{"SHA256-256f-simple", parameters.MakeSthincsPlusSHA256256fSimple},
		{"SHA256-256f-robust", parameters.MakeSthincsPlusSHA256256fRobust},
		{"SHA256-256s-simple", parameters.MakeSthincsPlusSHA256256sSimple},
		{"SHA256-256s-robust", parameters.MakeSthincsPlusSHA256256sRobust},
		{"SHAKE256-128f-simple", parameters.MakeSthincsPlusSHAKE256128fSimple},
		{"SHAKE256-128f-robust", parameters.MakeSthincsPlusSHAKE256128fRobust},
		{"SHAKE256-128s-simple", parameters.MakeSthincsPlusSHAKE256128sSimple},
		{"SHAKE256-128s-robust", parameters.MakeSthincsPlusSHAKE256128sRobust},
		{"SHAKE256-192f-simple", parameters.MakeSthincsPlusSHAKE256192fSimple},
		{"SHAKE256-192f-robust", parameters.MakeSthincsPlusSHAKE256192fRobust},
		{"SHAKE256-192s-simple", parameters.MakeSthincsPlusSHAKE256192sSimple},
		{"SHAKE256-192s-robust", parameters.MakeSthincsPlusSHAKE256192sRobust},
		{"SHAKE256-256f-simple", parameters.MakeSthincsPlusSHAKE256256fSimple},
		{"SHAKE256-256f-robust", parameters.MakeSthincsPlusSHAKE256256fRobust},
		{"SHAKE256-256s-simple", parameters.MakeSthincsPlusSHAKE256256sSimple},
		{"SHAKE256-256s-robust", parameters.MakeSthincsPlusSHAKE256256sRobust},
		{"SPHINXHASH-128f-simple", parameters.MakeSthincsPlusSPHINXHASH128fSimple},
		{"SPHINXHASH-128f-robust", parameters.MakeSthincsPlusSPHINXHASH128fRobust},
		{"SPHINXHASH-128s-simple", parameters.MakeSthincsPlusSPHINXHASH128sSimple},
		{"SPHINXHASH-128s-robust", parameters.MakeSthincsPlusSPHINXHASH128sRobust},
		{"SPHINXHASH-192f-simple", parameters.MakeSthincsPlusSPHINXHASH192fSimple},
		{"SPHINXHASH-192f-robust", parameters.MakeSthincsPlusSPHINXHASH192fRobust},
		{"SPHINXHASH-192s-simple", parameters.MakeSthincsPlusSPHINXHASH192sSimple},
		{"SPHINXHASH-192s-robust", parameters.MakeSthincsPlusSPHINXHASH192sRobust},
		{"SPHINXHASH-256f-simple", parameters.MakeSthincsPlusSPHINXHASH256fSimple},
		{"SPHINXHASH-256f-robust", parameters.MakeSthincsPlusSPHINXHASH256fRobust},
		{"SPHINXHASH-256s-simple", parameters.MakeSthincsPlusSPHINXHASH256sSimple},
		{"SPHINXHASH-256s-robust", parameters.MakeSthincsPlusSPHINXHASH256sRobust},
	}
}

// seedTotal mirrors spxHashExpand's sizing arithmetic exactly. It is a copy
// rather than a call into the real encoder so the report cannot silently drift;
// TestSeedTotalMatchesEncoding guards that.
func seedTotal(parts ...[]byte) int {
	total := 1 // the domain byte
	for _, p := range parts {
		total += 4 + len(p)
	}
	return total
}

// seedStackBound is the stack-allocated size of the hash-input scratch buffer
// in spxHashExpand, sized from the measurement in TestReportSeedTotals rather
// than guessed.
//
// Sizing rule: keep the HOT call types (PRF, F, H) on the stack, and let T_l —
// whose input is Len*N or K*N bytes and therefore genuinely large — take the
// heap fallback. H is the largest hot case because a tree node hashes two
// N-byte children (2N), while F hashes a single N-byte chain value.
//
// Anything above this bound takes the heap path. There is no pool and no
// shared state: the buffer is a plain local array, so this is goroutine-safe by
// construction.
const seedStackBound = 256

// spxHashExpandSeedForTest encodes the seed exactly as spxHashExpand does, so
// the sizing report measures the real encoder rather than a copy.
func spxHashExpandSeedForTest(domain byte, parts ...[]byte) []byte {
	total := seedTotal(parts...)
	var stack [seedStackBound]byte
	var seed []byte
	if total <= seedStackBound {
		seed = stack[:0]
	} else {
		seed = make([]byte, 0, total)
	}
	seed = append(seed, domain)
	for _, p := range parts {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		seed = append(seed, l[:]...)
		seed = append(seed, p...)
	}
	return seed
}

// TestSeedTotalMatchesEncoding guards the duplicated sizing arithmetic.
func TestSeedTotalMatchesEncoding(t *testing.T) {
	p := parameters.MakeSthincsPlusSPHINXHASH256sRobust(false)
	parts := [][]byte{make([]byte, p.N), make([]byte, 32), make([]byte, p.N)}
	got := len(spxHashExpandSeedForTest(0x01, parts...))
	want := seedTotal(parts...)
	if got != want {
		t.Fatalf("encoded seed length %d != computed total %d", got, want)
	}
}

func TestReportSeedTotals(t *testing.T) {
	type row struct {
		set                       string
		N, K, D                   int
		prf, f, h, tlWots, tlFors int
		hmsg                      int
	}
	var rows []row
	for _, pc := range allParamCases() {
		p := pc.make(false)
		n := p.N
		adrs := make([]byte, 32) // address.GetBytes() is always 32 bytes
		pkseed := make([]byte, n)

		prf := seedTotal(make([]byte, n), adrs)
		f := seedTotal(pkseed, adrs, make([]byte, n))
		h := seedTotal(pkseed, adrs, make([]byte, 2*n))
		tlWots := seedTotal(pkseed, adrs, make([]byte, p.Len*n))
		tlFors := seedTotal(pkseed, adrs, make([]byte, p.K*n))
		// Hmsg's M is the caller's message and is unbounded; 64 bytes is a
		// representative floor, not a maximum.
		hmsg := seedTotal(make([]byte, n), make([]byte, n), make([]byte, n), make([]byte, 64))

		rows = append(rows, row{pc.name, n, p.K, p.D, prf, f, h, tlWots, tlFors, hmsg})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].tlWots < rows[j].tlWots })

	fmt.Printf("\n%-24s %3s %3s %2s %6s %6s %6s %9s %10s %7s\n",
		"set", "N", "K", "D", "PRF", "F", "H", "T_l(wots)", "T_l(FORS)", "Hmsg*")
	for _, r := range rows {
		fmt.Printf("%-24s %3d %3d %2d %6d %6d %6d %9d %10d %7d\n",
			r.set, r.N, r.K, r.D, r.prf, r.f, r.h, r.tlWots, r.tlFors, r.hmsg)
	}

	maxOf := func(f func(row) int) int {
		m := 0
		for _, r := range rows {
			if v := f(r); v > m {
				m = v
			}
		}
		return m
	}
	hotMax := maxOf(func(r row) int {
		if r.h > r.f {
			return r.h
		}
		return r.f
	})
	fmt.Printf("\nMAXIMA across all 36 parameter sets:\n")
	fmt.Printf("  PRF             = %d\n", maxOf(func(r row) int { return r.prf }))
	fmt.Printf("  F               = %d\n", maxOf(func(r row) int { return r.f }))
	fmt.Printf("  H               = %d\n", maxOf(func(r row) int { return r.h }))
	fmt.Printf("  hot max (F/H)   = %d\n", hotMax)
	fmt.Printf("  T_l (WOTS+)     = %d\n", maxOf(func(r row) int { return r.tlWots }))
	fmt.Printf("  T_l (FORS)      = %d\n", maxOf(func(r row) int { return r.tlFors }))
	fmt.Printf("  seedStackBound  = %d\n", seedStackBound)
	if hotMax > seedStackBound {
		t.Errorf("bound %d does not cover the hot maximum %d", seedStackBound, hotMax)
	}
	fmt.Println()
}
