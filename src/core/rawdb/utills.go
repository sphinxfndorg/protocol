// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/util.go
package rawdb

import (
	"encoding/hex"
	"errors"
)

// ErrNotFound is returned (wrapped) by every Read* function when the
// requested key does not exist, so callers can distinguish "not found" from
// "corrupt data" with errors.Is(err, rawdb.ErrNotFound) instead of the bare
// nil that callers like GetBlockByNumber return today on any failure.
var ErrNotFound = errors.New("rawdb: not found")

// hashString converts a header/block hash byte slice into the printable
// string form used as a DB key. This mirrors types.Block.GetParentHash's
// existing convention exactly: bytes that are already printable ASCII
// (which covers the "GENESIS_..." text-hash case, and any hash already
// stored as a printable string) are used as-is; anything else is
// hex-encoded. Keeping this identical to the existing convention means
// rawdb keys line up with whatever Block.GetHash() already returns
// elsewhere in the codebase.
func hashString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	for _, r := range b {
		if r < 32 || r > 126 {
			return hex.EncodeToString(b)
		}
	}
	return string(b)
}
