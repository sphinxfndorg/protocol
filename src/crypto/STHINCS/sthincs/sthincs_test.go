// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/sthincs/sthincs_test.go
package sthincs

import (
	"bytes"
	"testing"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/fors"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/hypertree"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/xmss"
)

// TestSplitDigestRightAlignsIndices checks the exact bug that used to make
// idx_tree and idx_leaf always 0: index bytes must be read big-endian from the
// real slice and masked to the low bits. It needs no signing, so it is fast.
func TestSplitDigestRightAlignsIndices(t *testing.T) {
	// K*A = 32 bits -> 4 md bytes in every case below.
	d6 := &parameters.Parameters{H: 30, D: 6, K: 4, A: 8} // H'=5:  tree 25 bits (4 B), leaf 5 bits (1 B)
	d3 := &parameters.Parameters{H: 30, D: 3, K: 4, A: 8} // H'=10: tree 20 bits (3 B), leaf 10 bits (2 B)
	md := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	cases := []struct {
		name     string
		params   *parameters.Parameters
		tree     []byte
		leaf     []byte
		wantTree uint64
		wantLeaf int
	}{
		{"D6 all ones", d6, []byte{0xFF, 0xFF, 0xFF, 0xFF}, []byte{0xFF}, 1<<25 - 1, 1<<5 - 1},
		{"D6 high bits masked off", d6, []byte{0xFE, 0x00, 0x00, 0x05}, []byte{0xE3}, 5, 3},
		{"D3 all ones", d3, []byte{0xFF, 0xFF, 0xFF}, []byte{0xFF, 0xFF}, 1<<20 - 1, 1<<10 - 1},
		{"D3 small values", d3, []byte{0x00, 0x01, 0x02}, []byte{0x00, 0x07}, 0x102, 7},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			digest := bytes.Join([][]byte{md, tc.tree, tc.leaf}, nil)

			gotMD, gotTree, gotLeaf, err := splitDigest(tc.params, digest)
			if err != nil {
				t.Fatalf("splitDigest: %v", err)
			}
			if !bytes.Equal(gotMD, md) {
				t.Errorf("md = %x, want %x", gotMD, md)
			}
			if gotTree != tc.wantTree {
				t.Errorf("idx_tree = %#x, want %#x", gotTree, tc.wantTree)
			}
			if gotLeaf != tc.wantLeaf {
				t.Errorf("idx_leaf = %#x, want %#x", gotLeaf, tc.wantLeaf)
			}
		})
	}
}

// A digest that is one byte too short must be rejected, not silently padded.
func TestSplitDigestRejectsShortDigest(t *testing.T) {
	params := &parameters.Parameters{H: 30, D: 6, K: 4, A: 8}
	need := 4 + 4 + 1
	if _, _, _, err := splitDigest(params, make([]byte, need-1)); err == nil {
		t.Fatal("expected error for short digest, got nil")
	}
	if _, _, _, err := splitDigest(params, make([]byte, need)); err != nil {
		t.Fatalf("exact-length digest rejected: %v", err)
	}
}

// indicesOf recomputes the (idx_tree, idx_leaf) a signature was made under,
// from the signature's own randomizer R.
func indicesOf(t *testing.T, params *parameters.Parameters, pk *SPHINCS_PK, msg []byte, sig *SPHINCS_SIG) (uint64, int) {
	t.Helper()
	digest := params.Tweak.Hmsg(sig.GetR(), pk.PKseed, pk.PKroot, msg)
	_, tree, leaf, err := splitDigest(params, digest)
	if err != nil {
		t.Fatalf("splitDigest: %v", err)
	}
	return tree, leaf
}

type hashSetCase struct {
	name string
	make func(bool) *parameters.Parameters
}

// One fast (128f) parameter set per hash backend and variant.
func hashSetCases() []hashSetCase {
	return []hashSetCase{
		{"SHA256-128f-simple", parameters.MakeSthincsPlusSHA256128fSimple},
		{"SHA256-128f-robust", parameters.MakeSthincsPlusSHA256128fRobust},
		{"SHAKE256-128f-simple", parameters.MakeSthincsPlusSHAKE256128fSimple},
		{"SHAKE256-128f-robust", parameters.MakeSthincsPlusSHAKE256128fRobust},
		{"SPHINXHASH-128f-simple", parameters.MakeSthincsPlusSPHINXHASH128fSimple},
		{"SPHINXHASH-128f-robust", parameters.MakeSthincsPlusSPHINXHASH128fRobust},
	}
}

// TestSignVerifyAcrossHashBackends runs, for SHA256, SHAKE256 and SPHINXHASH
// (simple and robust), the following end-to-end checks under one key:
//  1. each signature verifies against its own message,
//  2. two messages are signed at different (idx_tree, idx_leaf), in range,
//  3. each signature FAILS against the other message,
//  4. a signature FAILS under a completely different key pair.
//
// (2) fails on the old always-0 index bug; (3) and (4) fail on the old
// input-ignoring SphinxHashTweak stub.
func TestSignVerifyAcrossHashBackends(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping signing tests in -short mode")
	}

	for _, tc := range hashSetCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			params := tc.make(true)

			sk, pk, err := Spx_keygen(params)
			if err != nil {
				t.Fatalf("Spx_keygen: %v", err)
			}
			_, pk2, err := Spx_keygen(params) // an unrelated key pair
			if err != nil {
				t.Fatalf("Spx_keygen (second key): %v", err)
			}

			msgA := []byte("STHINCS test message A")
			msgB := []byte("STHINCS test message B")

			sigA, err := Spx_sign(params, msgA, sk)
			if err != nil {
				t.Fatalf("Spx_sign(A): %v", err)
			}
			sigB, err := Spx_sign(params, msgB, sk)
			if err != nil {
				t.Fatalf("Spx_sign(B): %v", err)
			}

			// 1. Each signature verifies against its own message.
			if !Spx_verify(params, msgA, sigA, pk) {
				t.Fatal("sigA does not verify against msgA")
			}
			if !Spx_verify(params, msgB, sigB, pk) {
				t.Fatal("sigB does not verify against msgB")
			}

			// 2. Indices differ and are in range.
			treeA, leafA := indicesOf(t, params, pk, msgA, sigA)
			treeB, leafB := indicesOf(t, params, pk, msgB, sigB)
			t.Logf("msgA: idx_tree=%d idx_leaf=%d | msgB: idx_tree=%d idx_leaf=%d", treeA, leafA, treeB, leafB)

			hPrime := params.H / params.D
			maxTree := uint64(1) << uint(params.H-hPrime)
			maxLeaf := 1 << uint(hPrime)
			for name, ix := range map[string]struct {
				tree uint64
				leaf int
			}{"A": {treeA, leafA}, "B": {treeB, leafB}} {
				if ix.tree >= maxTree {
					t.Errorf("msg%s idx_tree %d out of range [0, %d)", name, ix.tree, maxTree)
				}
				if ix.leaf < 0 || ix.leaf >= maxLeaf {
					t.Errorf("msg%s idx_leaf %d out of range [0, %d)", name, ix.leaf, maxLeaf)
				}
			}
			if treeA == treeB && leafA == leafB {
				t.Fatalf("both messages signed at the same (idx_tree=%d, idx_leaf=%d): indices are not message-dependent", treeA, leafA)
			}

			// 3. Neither signature verifies against the other message.
			if Spx_verify(params, msgB, sigA, pk) {
				t.Error("sigA wrongly verifies against msgB")
			}
			if Spx_verify(params, msgA, sigB, pk) {
				t.Error("sigB wrongly verifies against msgA")
			}

			// 4. A signature does not verify under a different key pair.
			if Spx_verify(params, msgA, sigA, pk2) {
				t.Error("sigA wrongly verifies under an unrelated public key")
			}
		})
	}
}

// cloneSig deep-copies a signature so each malformed variant starts clean.
func cloneSig(s *SPHINCS_SIG) *SPHINCS_SIG {
	c := &SPHINCS_SIG{R: append([]byte(nil), s.R...)}

	f := &fors.FORSSignature{}
	for _, e := range s.SIG_FORS.Forspkauth {
		if e == nil {
			f.Forspkauth = append(f.Forspkauth, nil)
			continue
		}
		f.Forspkauth = append(f.Forspkauth, &fors.TreePKAUTH{
			PrivateKeyValue: append([]byte(nil), e.PrivateKeyValue...),
			AUTH:            append([]byte(nil), e.AUTH...),
		})
	}
	c.SIG_FORS = f

	h := &hypertree.HTSignature{}
	for _, x := range s.SIG_HT.XMSSSignatures {
		if x == nil {
			h.XMSSSignatures = append(h.XMSSSignatures, nil)
			continue
		}
		h.XMSSSignatures = append(h.XMSSSignatures, &xmss.XMSSSignature{
			WotsSignature: append([]byte(nil), x.WotsSignature...),
			AUTH:          append([]byte(nil), x.AUTH...),
		})
	}
	c.SIG_HT = h
	return c
}

// Signatures and public keys are attacker-controlled: any malformed one must
// come back as "invalid", never as a crash. Spx_sign must also refuse a
// malformed secret key, and Zeroize must wipe the secret parts.
func TestVerifyRejectsMalformedInputsAndSignRejectsBadKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping signing tests in -short mode")
	}

	params := parameters.MakeSthincsPlusSHAKE256128fSimple(true)
	sk, pk, err := Spx_keygen(params)
	if err != nil {
		t.Fatalf("Spx_keygen: %v", err)
	}
	msg := []byte("malformed input test")
	good, err := Spx_sign(params, msg, sk)
	if err != nil {
		t.Fatalf("Spx_sign: %v", err)
	}
	if !Spx_verify(params, msg, good, pk) {
		t.Fatal("baseline signature does not verify")
	}

	// --- malformed / corrupted signatures ---
	sigMutations := []struct {
		name   string
		mutate func(s *SPHINCS_SIG)
	}{
		{"nil R", func(s *SPHINCS_SIG) { s.R = nil }},
		{"short R", func(s *SPHINCS_SIG) { s.R = s.R[:len(s.R)-1] }},
		{"long R", func(s *SPHINCS_SIG) { s.R = append(s.R, 0) }},
		{"flipped R byte", func(s *SPHINCS_SIG) { s.R[0] ^= 1 }},

		{"nil FORS sig", func(s *SPHINCS_SIG) { s.SIG_FORS = nil }},
		{"empty FORS list", func(s *SPHINCS_SIG) { s.SIG_FORS.Forspkauth = nil }},
		{"nil FORS entry", func(s *SPHINCS_SIG) { s.SIG_FORS.Forspkauth[0] = nil }},
		{"drop last FORS entry", func(s *SPHINCS_SIG) {
			s.SIG_FORS.Forspkauth = s.SIG_FORS.Forspkauth[:len(s.SIG_FORS.Forspkauth)-1]
		}},
		{"truncated FORS AUTH", func(s *SPHINCS_SIG) { s.SIG_FORS.Forspkauth[0].AUTH = s.SIG_FORS.Forspkauth[0].AUTH[:1] }},
		{"nil FORS leaf value", func(s *SPHINCS_SIG) { s.SIG_FORS.Forspkauth[0].PrivateKeyValue = nil }},
		{"flipped FORS leaf byte", func(s *SPHINCS_SIG) { s.SIG_FORS.Forspkauth[0].PrivateKeyValue[0] ^= 1 }},
		{"flipped FORS AUTH byte", func(s *SPHINCS_SIG) { s.SIG_FORS.Forspkauth[0].AUTH[0] ^= 1 }},

		{"nil HT sig", func(s *SPHINCS_SIG) { s.SIG_HT = nil }},
		{"empty HT list", func(s *SPHINCS_SIG) { s.SIG_HT.XMSSSignatures = nil }},
		{"nil XMSS entry", func(s *SPHINCS_SIG) { s.SIG_HT.XMSSSignatures[0] = nil }},
		{"drop last XMSS entry", func(s *SPHINCS_SIG) {
			s.SIG_HT.XMSSSignatures = s.SIG_HT.XMSSSignatures[:len(s.SIG_HT.XMSSSignatures)-1]
		}},
		{"extra XMSS entry", func(s *SPHINCS_SIG) {
			s.SIG_HT.XMSSSignatures = append(s.SIG_HT.XMSSSignatures, s.SIG_HT.XMSSSignatures[0])
		}},
		{"truncated WOTS sig", func(s *SPHINCS_SIG) {
			x := s.SIG_HT.XMSSSignatures[0]
			x.WotsSignature = x.WotsSignature[:len(x.WotsSignature)/2]
		}},
		{"nil XMSS AUTH", func(s *SPHINCS_SIG) { s.SIG_HT.XMSSSignatures[0].AUTH = nil }},
		{"flipped WOTS byte", func(s *SPHINCS_SIG) { s.SIG_HT.XMSSSignatures[0].WotsSignature[0] ^= 1 }},
		{"flipped XMSS AUTH byte", func(s *SPHINCS_SIG) { s.SIG_HT.XMSSSignatures[0].AUTH[0] ^= 1 }},
	}
	for _, m := range sigMutations {
		m := m
		t.Run("sig/"+m.name, func(t *testing.T) {
			bad := cloneSig(good)
			m.mutate(bad)
			if Spx_verify(params, msg, bad, pk) {
				t.Fatal("malformed/corrupted signature was accepted")
			}
		})
	}

	// --- malformed public keys / arguments ---
	t.Run("pk/nil", func(t *testing.T) {
		if Spx_verify(params, msg, good, nil) {
			t.Fatal("accepted nil public key")
		}
	})
	t.Run("pk/short PKroot", func(t *testing.T) {
		bad := &SPHINCS_PK{PKseed: pk.PKseed, PKroot: pk.PKroot[:len(pk.PKroot)-1]}
		if Spx_verify(params, msg, good, bad) {
			t.Fatal("accepted short PKroot")
		}
	})
	t.Run("pk/nil PKseed", func(t *testing.T) {
		bad := &SPHINCS_PK{PKseed: nil, PKroot: pk.PKroot}
		if Spx_verify(params, msg, good, bad) {
			t.Fatal("accepted nil PKseed")
		}
	})
	t.Run("args/nil params, sig and message", func(t *testing.T) {
		if Spx_verify(nil, msg, good, pk) || Spx_verify(params, nil, good, pk) || Spx_verify(params, msg, nil, pk) {
			t.Fatal("accepted nil argument")
		}
	})

	// --- Spx_sign must reject malformed secret keys ---
	t.Run("sign/short SKseed", func(t *testing.T) {
		bad := &SPHINCS_SK{SKseed: sk.SKseed[:len(sk.SKseed)-1], SKprf: sk.SKprf, PKseed: sk.PKseed, PKroot: sk.PKroot}
		if _, err := Spx_sign(params, msg, bad); err == nil {
			t.Fatal("Spx_sign accepted a short SKseed")
		}
	})
	t.Run("sign/nil PKroot", func(t *testing.T) {
		bad := &SPHINCS_SK{SKseed: sk.SKseed, SKprf: sk.SKprf, PKseed: sk.PKseed, PKroot: nil}
		if _, err := Spx_sign(params, msg, bad); err == nil {
			t.Fatal("Spx_sign accepted a nil PKroot")
		}
	})

	// --- Zeroize wipes the secret parts only ---
	t.Run("Zeroize", func(t *testing.T) {
		pkseedBefore := append([]byte(nil), sk.PKseed...)
		sk.Zeroize()
		for _, part := range []struct {
			name string
			b    []byte
		}{{"SKseed", sk.SKseed}, {"SKprf", sk.SKprf}} {
			for _, b := range part.b {
				if b != 0 {
					t.Fatalf("%s not zeroed", part.name)
				}
			}
		}
		if !bytes.Equal(sk.PKseed, pkseedBefore) {
			t.Fatal("Zeroize modified the public seed")
		}
		var nilKey *SPHINCS_SK
		nilKey.Zeroize() // must not panic
	})
}
