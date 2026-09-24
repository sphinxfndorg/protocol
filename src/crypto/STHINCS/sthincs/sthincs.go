// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/sthincs/sthincs.go
package sthincs

import (
	"crypto/rand"
	"fmt"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/address"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/fors"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/hypertree"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/util"
)

type SPHINCS_PK struct {
	PKseed []byte
	PKroot []byte
}

type SPHINCS_SK struct {
	SKseed []byte
	SKprf  []byte
	PKseed []byte
	PKroot []byte
}

type SPHINCS_SIG struct {
	R        []byte
	SIG_FORS *fors.FORSSignature
	SIG_HT   *hypertree.HTSignature
}

func (s *SPHINCS_SIG) GetR() []byte {
	return s.R
}

func (s *SPHINCS_SIG) GetSIG_FORS() *fors.FORSSignature {
	return s.SIG_FORS
}

func (s *SPHINCS_SIG) GetSIG_HT() *hypertree.HTSignature {
	return s.SIG_HT
}

// Zeroize overwrites the secret parts of the key (SKseed, SKprf) in place.
// Call it when you are done with a secret key. The public halves (PKseed,
// PKroot) are left intact. Note that any serialized copy of the key (see
// SerializeSK) is a separate buffer that the caller must wipe itself, and
// that Go cannot guarantee no other copy exists (swap, core dumps, etc.).
func (sk *SPHINCS_SK) Zeroize() {
	if sk == nil {
		return
	}
	clear(sk.SKseed)
	clear(sk.SKprf)
}

// bitMask returns a mask with the low `bits` bits set (bits in 0..64).
func bitMask(bits int) uint64 {
	if bits <= 0 {
		return 0
	}
	if bits >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << uint(bits)) - 1
}

// splitDigest splits the Hmsg output into (FORS message digest, tree index,
// leaf index), exactly as in the SPHINCS+ specification:
//
//	md       = digest[0 : ceil(K*A / 8)]
//	idx_tree = toInt(next ceil((H - H/D) / 8) bytes) mod 2^(H - H/D)
//	idx_leaf = toInt(next ceil((H/D) / 8) bytes)     mod 2^(H/D)
//
// toInt is big-endian over the actual byte slice. The slice must NOT be
// copied left-aligned into a fixed-size buffer before masking: doing that
// shifts the value into the high bits, and the low-bit mask then zeroes
// it, which makes every index 0 (a previous version of this file had that
// bug in both sign and verify, so every signature reused tree 0 / leaf 0).
func splitDigest(params *parameters.Parameters, digest []byte) (md []byte, idxTree uint64, idxLeaf int, err error) {
	hPrime := params.H / params.D
	treeBits := params.H - hPrime
	leafBits := hPrime

	mdBytes := (params.K*params.A + 7) / 8
	treeBytes := (treeBits + 7) / 8
	leafBytes := (leafBits + 7) / 8

	if treeBytes > 8 {
		return nil, 0, 0, fmt.Errorf("tree index needs %d bytes, max supported is 8", treeBytes)
	}
	if leafBytes > 4 {
		return nil, 0, 0, fmt.Errorf("leaf index needs %d bytes, max supported is 4", leafBytes)
	}

	total := mdBytes + treeBytes + leafBytes
	if len(digest) < total {
		return nil, 0, 0, fmt.Errorf("message digest too short: need %d bytes, have %d (increase MessageDigestLength)", total, len(digest))
	}

	md = digest[:mdBytes]
	treeSlice := digest[mdBytes : mdBytes+treeBytes]
	leafSlice := digest[mdBytes+treeBytes : total]

	idxTree = util.BytesToUint64(treeSlice) & bitMask(treeBits)
	idxLeaf = int(util.BytesToUint64(leafSlice) & bitMask(leafBits))

	return md, idxTree, idxLeaf, nil
}

// Spx_keygen generates a SPHINCS+ key pair
func Spx_keygen(params *parameters.Parameters) (*SPHINCS_SK, *SPHINCS_PK, error) {
	if params == nil {
		return nil, nil, fmt.Errorf("nil parameters provided")
	}

	SKseed := make([]byte, params.N)
	if _, err := rand.Read(SKseed); err != nil {
		return nil, nil, fmt.Errorf("failed to generate SKseed: %w", err)
	}

	SKprf := make([]byte, params.N)
	if _, err := rand.Read(SKprf); err != nil {
		return nil, nil, fmt.Errorf("failed to generate SKprf: %w", err)
	}

	PKseed := make([]byte, params.N)
	if _, err := rand.Read(PKseed); err != nil {
		return nil, nil, fmt.Errorf("failed to generate PKseed: %w", err)
	}

	PKroot, err := hypertree.Ht_PKgen(params, SKseed, PKseed)
	if err != nil {
		return nil, nil, fmt.Errorf("hypertree PKgen failed: %w", err)
	}

	sk := &SPHINCS_SK{
		SKseed: SKseed,
		SKprf:  SKprf,
		PKseed: PKseed,
		PKroot: PKroot,
	}

	pk := &SPHINCS_PK{
		PKseed: PKseed,
		PKroot: PKroot,
	}

	return sk, pk, nil
}

// Spx_sign generates a SPHINCS+ signature.
//
// Before returning, the signature is verified against the key's own public
// half (a "sign-then-verify" self-check). A transient fault (bit flip,
// glitched hash) during signing otherwise yields an invalid signature that
// can leak information about the secret key; with the self-check such a
// signature is discarded and an error is returned instead. Cost: one
// verification, which is small next to signing.
func Spx_sign(params *parameters.Parameters, M []byte, SK *SPHINCS_SK) (*SPHINCS_SIG, error) {
	if params == nil || params.Tweak == nil || M == nil || SK == nil {
		return nil, fmt.Errorf("nil parameters provided")
	}
	if len(SK.SKseed) != params.N || len(SK.SKprf) != params.N ||
		len(SK.PKseed) != params.N || len(SK.PKroot) != params.N {
		return nil, fmt.Errorf("invalid secret key: every component must be exactly %d bytes", params.N)
	}

	// init
	adrs := new(address.ADRS)

	// generate randomizer
	opt := make([]byte, params.N)
	if params.RANDOMIZE {
		if _, err := rand.Read(opt); err != nil {
			return nil, fmt.Errorf("failed to generate randomizer: %w", err)
		}
	}

	R := params.Tweak.PRFmsg(SK.SKprf, opt, M)

	SIG := &SPHINCS_SIG{
		R: R,
	}

	// compute message digest and derive FORS digest + tree/leaf indices
	digest := params.Tweak.Hmsg(R, SK.PKseed, SK.PKroot, M)

	tmp_md, idx_tree, idx_leaf, err := splitDigest(params, digest)
	if err != nil {
		return nil, fmt.Errorf("digest split failed: %w", err)
	}

	// FORS sign
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idx_tree)
	adrs.SetType(address.FORS_TREE)
	adrs.SetKeyPairAddress(idx_leaf)

	// Work on private copies so nothing below can modify the caller's key,
	// and wipe the secret copy as soon as we are done with it.
	SKseed := make([]byte, params.N)
	copy(SKseed, SK.SKseed)
	defer clear(SKseed)
	PKseed := make([]byte, params.N)
	copy(PKseed, SK.PKseed)

	forsSig, err := fors.Fors_sign(params, tmp_md, SKseed, PKseed, adrs)
	if err != nil {
		return nil, fmt.Errorf("FORS sign failed: %w", err)
	}
	SIG.SIG_FORS = forsSig

	PK_FORS, err := fors.Fors_pkFromSig(params, SIG.SIG_FORS, tmp_md, PKseed, adrs)
	if err != nil {
		return nil, fmt.Errorf("FORS pkFromSig failed: %w", err)
	}

	// sign FORS public key with HT
	adrs.SetType(address.TREE)
	htSig, err := hypertree.Ht_sign(params, PK_FORS, SKseed, PKseed, idx_tree, idx_leaf)
	if err != nil {
		return nil, fmt.Errorf("hypertree sign failed: %w", err)
	}
	SIG.SIG_HT = htSig

	// Fault-attack countermeasure: never release a signature that does not
	// verify under our own public key.
	selfPK := &SPHINCS_PK{PKseed: SK.PKseed, PKroot: SK.PKroot}
	if !Spx_verify(params, M, SIG, selfPK) {
		return nil, fmt.Errorf("signature self-check failed (possible fault during signing); signature discarded")
	}

	return SIG, nil
}

// Spx_verify verifies a SPHINCS+ signature.
// Returns bool (no error) for compatibility; any internal error is treated
// as a failed verification. For production, consider changing to (bool, error).
//
// Signatures are attacker-controlled input, so verification is hardened:
// every length that the caller supplies is checked up front, and a recover()
// converts any panic caused by a malformed signature into a plain "invalid"
// result instead of crashing the process (remote DoS on a node).
func Spx_verify(params *parameters.Parameters, M []byte, SIG *SPHINCS_SIG, PK *SPHINCS_PK) (valid bool) {
	defer func() {
		if r := recover(); r != nil {
			valid = false
		}
	}()

	if params == nil || params.Tweak == nil || M == nil || SIG == nil || PK == nil {
		return false
	}
	if len(PK.PKseed) != params.N || len(PK.PKroot) != params.N {
		return false
	}

	// init
	adrs := new(address.ADRS)
	R := SIG.GetR()
	SIG_FORS := SIG.GetSIG_FORS()
	SIG_HT := SIG.GetSIG_HT()
	if len(R) != params.N || SIG_FORS == nil || SIG_HT == nil {
		return false
	}

	// compute message digest and derive FORS digest + tree/leaf indices
	digest := params.Tweak.Hmsg(R, PK.PKseed, PK.PKroot, M)

	tmp_md, idx_tree, idx_leaf, err := splitDigest(params, digest)
	if err != nil {
		return false
	}

	// compute FORS public key
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idx_tree)
	adrs.SetType(address.FORS_TREE)
	adrs.SetKeyPairAddress(idx_leaf)

	// Private copies (lengths are exactly N, checked above) so nothing below
	// can modify the caller's public key.
	PKseed := make([]byte, params.N)
	copy(PKseed, PK.PKseed)
	PKroot := make([]byte, params.N)
	copy(PKroot, PK.PKroot)

	PK_FORS, err := fors.Fors_pkFromSig(params, SIG_FORS, tmp_md, PKseed, adrs)
	if err != nil {
		return false
	}

	// verify HT signature
	adrs.SetType(address.TREE)

	ok, err := hypertree.Ht_verify(params, PK_FORS, SIG_HT, PKseed, idx_tree, idx_leaf, PKroot)
	if err != nil {
		return false
	}

	return ok
}
