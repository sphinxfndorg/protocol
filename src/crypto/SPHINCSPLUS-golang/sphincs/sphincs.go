package sphincs

import (
	"crypto/rand"
	"math"

	"github.com/sphinxorg/protocol/src/crypto/SPHINCSPLUS-golang/address"
	"github.com/sphinxorg/protocol/src/crypto/SPHINCSPLUS-golang/fors"
	"github.com/sphinxorg/protocol/src/crypto/SPHINCSPLUS-golang/hypertree"
	"github.com/sphinxorg/protocol/src/crypto/SPHINCSPLUS-golang/parameters"
	"github.com/sphinxorg/protocol/src/crypto/SPHINCSPLUS-golang/util"
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

func Spx_keygen(params *parameters.Parameters) (*SPHINCS_SK, *SPHINCS_PK) {
	SKseed := make([]byte, params.N)
	rand.Read(SKseed)

	SKprf := make([]byte, params.N)
	rand.Read(SKprf)

	PKseed := make([]byte, params.N)
	rand.Read(PKseed)

	PKroot := hypertree.Ht_PKgen(params, SKseed, PKseed)

	sk := new(SPHINCS_SK)
	sk.SKseed = SKseed
	sk.SKprf = SKprf
	sk.PKseed = PKseed
	sk.PKroot = PKroot

	pk := new(SPHINCS_PK)
	pk.PKseed = PKseed
	pk.PKroot = PKroot

	return sk, pk
}

func Spx_sign(params *parameters.Parameters, M []byte, SK *SPHINCS_SK) *SPHINCS_SIG {
	// init
	adrs := new(address.ADRS)

	// generate randomizer
	opt := make([]byte, params.N)
	if params.RANDOMIZE {
		rand.Read(opt)
	}

	R := params.Tweak.PRFmsg(SK.SKprf, opt, M)

	SIG := new(SPHINCS_SIG)
	SIG.R = R

	// compute message digest and index
	digest := params.Tweak.Hmsg(R, SK.PKseed, SK.PKroot, M)

	// Calculate sizes for each part
	tmp_md_bytes := int(math.Floor(float64(params.K*params.A+7) / 8))
	tmp_idx_tree_bytes := int(math.Floor(float64(params.H-params.H/params.D+7) / 8))
	tmp_idx_leaf_bytes := int(math.Floor(float64(params.H/params.D+7)) / 8)

	// Check if digest is large enough
	total_needed := tmp_md_bytes + tmp_idx_tree_bytes + tmp_idx_leaf_bytes
	if len(digest) < total_needed {
		// Pad the digest if it's too small
		padded := make([]byte, total_needed)
		copy(padded, digest)
		// Fill the rest with a deterministic pattern
		for i := len(digest); i < total_needed; i++ {
			padded[i] = byte(i % 256)
		}
		digest = padded
	}

	// Now safely extract the parts
	var tmp_md, tmp_idx_tree, tmp_idx_leaf []byte

	if tmp_md_bytes > 0 {
		end := min(tmp_md_bytes, len(digest))
		tmp_md = digest[:end]
	}

	if tmp_idx_tree_bytes > 0 {
		start := min(tmp_md_bytes, len(digest))
		end := min(tmp_md_bytes+tmp_idx_tree_bytes, len(digest))
		if start < end {
			tmp_idx_tree = digest[start:end]
		}
	}

	if tmp_idx_leaf_bytes > 0 {
		start := min(tmp_md_bytes+tmp_idx_tree_bytes, len(digest))
		end := min(tmp_md_bytes+tmp_idx_tree_bytes+tmp_idx_leaf_bytes, len(digest))
		if start < end {
			tmp_idx_leaf = digest[start:end]
		}
	}

	// Convert to integers with proper bounds checking
	var idx_tree uint64
	var idx_leaf int

	if len(tmp_idx_tree) > 0 {
		// Ensure we don't read past the buffer
		var tmp [8]byte
		copy(tmp[:], tmp_idx_tree)
		idx_tree = util.BytesToUint64(tmp[:]) & (math.MaxUint64 >> (64 - (params.H - params.H/params.D)))
	}

	if len(tmp_idx_leaf) > 0 {
		// Ensure we don't read past the buffer
		var tmp [4]byte
		copy(tmp[:], tmp_idx_leaf)
		idx_leaf = int(util.BytesToUint32(tmp[:]) & (math.MaxUint32 >> (32 - params.H/params.D)))
	}

	// FORS sign
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idx_tree)
	adrs.SetType(address.FORS_TREE)
	adrs.SetKeyPairAddress(idx_leaf)

	// This ensures that we avoid side effects modifying PK
	SKseed := make([]byte, params.N)
	copy(SKseed, SK.SKseed)
	PKseed := make([]byte, params.N)
	copy(PKseed, SK.PKseed)

	SIG.SIG_FORS = fors.Fors_sign(params, tmp_md, SKseed, PKseed, adrs)

	PK_FORS := fors.Fors_pkFromSig(params, SIG.SIG_FORS, tmp_md, PKseed, adrs)

	// sign FORS public key with HT
	adrs.SetType(address.TREE)
	SIG.SIG_HT = hypertree.Ht_sign(params, PK_FORS, SKseed, PKseed, idx_tree, idx_leaf)

	return SIG
}

func Spx_verify(params *parameters.Parameters, M []byte, SIG *SPHINCS_SIG, PK *SPHINCS_PK) bool {
	// init
	adrs := new(address.ADRS)
	R := SIG.GetR()
	SIG_FORS := SIG.GetSIG_FORS()
	SIG_HT := SIG.GetSIG_HT()

	// compute message digest and index
	digest := params.Tweak.Hmsg(R, PK.PKseed, PK.PKroot, M)

	tmp_md_bytes := int(math.Floor(float64(params.K*params.A+7) / 8))
	tmp_idx_tree_bytes := int(math.Floor(float64(params.H-params.H/params.D+7) / 8))
	tmp_idx_leaf_bytes := int(math.Floor(float64(params.H/params.D+7)) / 8)

	// Check if digest is large enough
	total_needed := tmp_md_bytes + tmp_idx_tree_bytes + tmp_idx_leaf_bytes
	if len(digest) < total_needed {
		// Pad the digest if it's too small
		padded := make([]byte, total_needed)
		copy(padded, digest)
		// Fill the rest with a deterministic pattern
		for i := len(digest); i < total_needed; i++ {
			padded[i] = byte(i % 256)
		}
		digest = padded
	}

	// Now safely extract the parts
	var tmp_md, tmp_idx_tree, tmp_idx_leaf []byte

	if tmp_md_bytes > 0 {
		end := min(tmp_md_bytes, len(digest))
		tmp_md = digest[:end]
	}

	if tmp_idx_tree_bytes > 0 {
		start := min(tmp_md_bytes, len(digest))
		end := min(tmp_md_bytes+tmp_idx_tree_bytes, len(digest))
		if start < end {
			tmp_idx_tree = digest[start:end]
		}
	}

	if tmp_idx_leaf_bytes > 0 {
		start := min(tmp_md_bytes+tmp_idx_tree_bytes, len(digest))
		end := min(tmp_md_bytes+tmp_idx_tree_bytes+tmp_idx_leaf_bytes, len(digest))
		if start < end {
			tmp_idx_leaf = digest[start:end]
		}
	}

	var idx_tree uint64
	var idx_leaf int

	if len(tmp_idx_tree) > 0 {
		var tmp [8]byte
		copy(tmp[:], tmp_idx_tree)
		idx_tree = uint64(util.BytesToUint64(tmp[:]) & (math.MaxUint64 >> (64 - (params.H - params.H/params.D))))
	}

	if len(tmp_idx_leaf) > 0 {
		var tmp [4]byte
		copy(tmp[:], tmp_idx_leaf)
		idx_leaf = int(util.BytesToUint32(tmp[:]) & (math.MaxUint32 >> (32 - params.H/params.D)))
	}

	// compute FORS public key
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idx_tree)
	adrs.SetType(address.FORS_TREE)
	adrs.SetKeyPairAddress(idx_leaf)

	// This ensures that we avoid side effects modifying PK
	PKseed := make([]byte, params.N)
	copy(PKseed, PK.PKseed)
	PKroot := make([]byte, params.N)
	copy(PKroot, PK.PKroot)

	PK_FORS := fors.Fors_pkFromSig(params, SIG_FORS, tmp_md, PKseed, adrs)

	// verify HT signature
	adrs.SetType(address.TREE)

	return hypertree.Ht_verify(params, PK_FORS, SIG_HT, PKseed, idx_tree, idx_leaf, PKroot)
}
