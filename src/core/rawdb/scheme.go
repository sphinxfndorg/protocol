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

// encodeIndex returns the fixed-width, hex-encoded big-endian
// representation of a transaction's position within its block, used as the
// final component of an address→tx key so that keys for one address sort by
// height and then by position within the block.
func encodeIndex(index int) string {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(index))
	return hex.EncodeToString(buf)
}

func headerKey(hash string) string       { return headerPrefix + hash }
func bodyKey(hash string) string         { return bodyPrefix + hash }
func canonicalKey(height uint64) string  { return canonicalPrefix + encodeHeight(height) }
func heightLookupKey(hash string) string { return heightLookupPrefix + hash }
func txLookupKey(txID string) string     { return txLookupPrefix + txID }
func receiptKey(hash string) string      { return receiptPrefix + hash }

// addressTxKey is the exact key for one (address, blockHeight, txIndex)
// tuple. The trailing ':' after the address terminates it, so a prefix scan
// for "xAlice" cannot also match "xAlice2", and the fixed-width components
// make lexicographic order match height/index order.
func addressTxKey(addr string, height uint64, index int) string {
	return addressTxScanPrefix(addr) + encodeHeight(height) + ":" + encodeIndex(index)
}

// addressTxKeySuffixLen is the fixed length of the height:index portion of
// an address→tx key: 16 hex chars of height, the ':' separator, and 8 hex
// chars of index.
const addressTxKeySuffixLen = 16 + 1 + 8

// addressTxScanPrefix is the exact scan prefix for one address's history.
// Iterating it in reverse yields that address's most recent activity first.
func addressTxScanPrefix(addr string) string {
	return addressTxPrefix + addr + ":"
}
