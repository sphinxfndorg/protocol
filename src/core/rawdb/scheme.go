// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/schema.go
package rawdb

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Key prefixes. Every block-data key in the system is built exclusively
// through the functions below — no other package should construct these
// strings by hand. None of these collide with the existing `acct:`,
// `supply:total`, `supply:genesis`, `supply:rewards` keys used by StateDB;
// same LevelDB instance, disjoint namespaces.
const (
	headerPrefix       = "hdr:"
	bodyPrefix         = "bdy:"
	canonicalPrefix    = "H:"
	heightLookupPrefix = "h:"
	txLookupPrefix     = "tx:"
	addressTxPrefix    = "addrtx:"
	receiptPrefix      = "rcpt:"
	headBlockKey       = "head:block"
	headHeaderKey      = "head:header"
	genesisHashKey     = "genesis:hash"
)

// encodeHeight returns the fixed-width, hex-encoded big-endian
// representation of height used in canonical and height-lookup keys, so
// that ListKeysWithPrefix on canonicalPrefix returns results in ascending
// height order for free — no separate sort step for range scans.
func encodeHeight(height uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, height)
	return hex.EncodeToString(buf)
}

// decodeHeight parses a fixed-width hex height string back into a uint64.
func decodeHeight(s string) (uint64, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return 0, fmt.Errorf("rawdb: invalid height encoding %q: %w", s, err)
	}
	if len(buf) != 8 {
		return 0, fmt.Errorf("rawdb: invalid height encoding length %d (want 8)", len(buf))
	}
	return binary.BigEndian.Uint64(buf), nil
}

func headerKey(hash string) string       { return headerPrefix + hash }
func bodyKey(hash string) string         { return bodyPrefix + hash }
func canonicalKey(height uint64) string  { return canonicalPrefix + encodeHeight(height) }
func heightLookupKey(hash string) string { return heightLookupPrefix + hash }
func txLookupKey(txID string) string     { return txLookupPrefix + txID }
func addressTxKey(addr string) string    { return addressTxPrefix + addr }
func receiptKey(hash string) string      { return receiptPrefix + hash }
