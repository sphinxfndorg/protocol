// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/common/types.go
package common

import spxhash "github.com/sphinxorg/protocol/src/spxhash/hash"

// Params represents the configuration for SphinxHash.
type Params struct {
	BitSize int
}

// Predefined Params for 256-bit hashing
var spxParams = Params{
	BitSize: 256,
}

// SpxHash hashes the given data using the SphinxHash algorithm with the predefined parameters.
func SpxHash(data []byte) []byte {
	// Use the default params (256-bit configuration)
	params := spxParams

	// Create a new SphinxHash instance with the configured bit size
	sphinxHash := spxhash.NewSphinxHash(params.BitSize, data)

	// Return the final hash for the data
	return sphinxHash.GetHash(data)
}
