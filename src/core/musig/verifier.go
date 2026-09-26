// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package multisig

import (
	"fmt"
	"sync"

	params "github.com/sphinxfndorg/protocol/src/core/sthincs/config"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
)

type MultiSigWitness struct {
	Policy MultiPartyPolicy `json:"policy"`
	Sigs   map[int][]byte   `json:"sigs"`
	Expiry uint64           `json:"expiry"`
}

var (
	cachedParams    *params.STHINCSParameters
	cachedParamsErr error
	cachedOnce      sync.Once
)

func sthincsParams() (*params.STHINCSParameters, error) {
	cachedOnce.Do(func() {
		cachedParams, cachedParamsErr = params.NewSTHINCSParameters()
	})
	if cachedParamsErr != nil {
		return nil, cachedParamsErr
	}
	if cachedParams == nil || cachedParams.Params == nil {
		return nil, fmt.Errorf("sthincs parameters unavailable")
	}
	return cachedParams, nil
}

func VerifyThreshold(msg []byte, w MultiSigWitness, currentHeight uint64) bool {
	if len(msg) == 0 {
		return false
	}
	if currentHeight > w.Expiry {
		return false
	}
	if err := w.Policy.Validate(); err != nil {
		return false
	}
	if len(w.Sigs) == 0 {
		return false
	}
	sp, err := sthincsParams()
	if err != nil {
		return false
	}
	seen := make(map[int]bool)
	valid := 0
	for idx, sigBytes := range w.Sigs {
		if seen[idx] {
			continue
		}
		if idx < 0 || idx >= len(w.Policy.PubKeys) {
			continue
		}
		pk, err := sthincs.DeserializePK(sp.Params, w.Policy.PubKeys[idx])
		if err != nil {
			continue
		}
		sig, err := sthincs.DeserializeSignature(sp.Params, sigBytes)
		if err != nil {
			continue
		}
		if !sthincs.Spx_verify(sp.Params, msg, sig, pk) {
			continue
		}
		seen[idx] = true
		valid++
	}
	return valid >= int(w.Policy.Threshold)
}
