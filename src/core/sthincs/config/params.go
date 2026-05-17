// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/sphincs/config/params.go
package params

import (
	"errors"
	"fmt"

	"github.com/sphinxorg/protocol/src/crypto/STHINCS/parameters"
)

// SIPS0015 https://github.com/sphinxorg/SIPS/blob/main/.github/workflows/sips0015/sips0015.md

// STHINCSParameters wraps the Parameters struct for additional configuration.
type STHINCSParameters struct {
	Params *parameters.Parameters // Now refers to sphinx-core parameters
}

// NewSTHINCSParameters initializes SPHINCS+ parameters for SHAKE256-128f-robust (LV-3 of NIST claimed).
func NewSTHINCSParameters() (*STHINCSParameters, error) {
	params := parameters.MakeSthincsPlusSPHINXHASH128sRobust(false)
	if params == nil {
		fmt.Println("Parameters initialization failed")
		return nil, errors.New("failed to initialize SPHINCS+ parameters")
	}
	return &STHINCSParameters{Params: params}, nil
}
