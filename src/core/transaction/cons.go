// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/transaction/cons.go
package types

const (
	// MaxReturnDataSize bounds OP_RETURN-style payloads. NFT anchors need room
	// for mint id, CID, CID hash, and subject, while still keeping block data
	// small and fee-accounted.
	MaxReturnDataSize = 4096

	NFTAnchorType    = "sphinx_nft_anchor"
	NFTAnchorVersion = 1
)

// SPX is defined in accounts.go — do not redeclare here.
