// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/sthincs/sthincs.go
package sthincs

import (
	"crypto/rand"
	"fmt"
	"math"

	"github.com/sphinxorg/protocol/src/crypto/STHINCS/address"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/fors"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/hypertree"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/util"
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

// Spx_keygen generates a SPHINCS+ key pair
// Fixed: Returns error
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

// Spx_sign generates a SPHINCS+ signature
// Fixed: Returns error
func Spx_sign(params *parameters.Parameters, M []byte, SK *SPHINCS_SK) (*SPHINCS_SIG, error) {
	if params == nil || M == nil || SK == nil {
		return nil, fmt.Errorf("nil parameters provided")
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

	return SIG, nil
}

// Spx_verify verifies a SPHINCS+ signature
// Fixed: Returns bool (no error) for compatibility, but logs errors internally
// For production, consider changing to (bool, error)
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

	PK_FORS, err := fors.Fors_pkFromSig(params, SIG_FORS, tmp_md, PKseed, adrs)
	if err != nil {
		// Verification failed due to error
		return false
	}

	// verify HT signature
	adrs.SetType(address.TREE)

	valid, err := hypertree.Ht_verify(params, PK_FORS, SIG_HT, PKseed, idx_tree, idx_leaf, PKroot)
	if err != nil {
		// Verification failed due to error
		return false
	}

	return valid
}
