// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/transaction/bloomindex.go
package types

import (
	"github.com/sphinxfndorg/protocol/src/core/bloom"
)

// BuildBlockBloomFilter scans body and returns a populated Bloom filter
// keyed on the addresses and transaction IDs a caller would search for:
// Sender, Receiver, ToContract (when set), and the transaction ID
// itself. Uses bloom.DefaultConfig() so every node builds and hashes
// bit-for-bit identical filters.
//
// Keys are deduped before hashing: a block repeats the same addresses
// heavily (miner, fee recipient, hot contracts) and the filter does not
// record how many times a key was added, so hashing a duplicate is pure
// waste. Duplicates set the same bits, so the output is identical to
// adding every field of every transaction individually.
func BuildBlockBloomFilter(body *BlockBody) *bloom.BloomFilter {
	bf := bloom.NewDefault()
	if body == nil {
		return bf
	}

	seen := make(map[string]struct{}, len(body.TxsList)*2)
	keys := make([]string, 0, len(body.TxsList)*4)
	add := func(key string) {
		if key == "" {
			return
		}
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}

	for _, tx := range body.TxsList {
		if tx == nil {
			continue
		}
		add(tx.ID)
		add(tx.Sender)
		add(tx.Receiver)
		add(tx.ToContract)
	}

	bf.AddStrings(keys)
	return bf
}

// SetBloomFilter stores bf's raw bytes onto the header's LogsBloom field.
func (h *BlockHeader) SetBloomFilter(bf *bloom.BloomFilter) {
	if h == nil || bf == nil {
		return
	}
	h.LogsBloom = bf.Bytes()
}

// DecodeBloomFilter reconstructs a *bloom.BloomFilter from the header's
// stored LogsBloom bytes. Returns an error if LogsBloom is not exactly
// bloom.BloomBytes long (e.g. an old header from before this field
// existed, or a corrupted header).
func (h *BlockHeader) DecodeBloomFilter() (*bloom.BloomFilter, error) {
	if h == nil {
		return nil, bloom.ErrSizeMismatch
	}
	return bloom.LoadFilter(bloom.DefaultConfig(), h.LogsBloom)
}

// PopulateLogsBloom builds the Bloom filter for b's current body and
// stores it on b.Header.LogsBloom. Callers must invoke this once, after
// the transaction list is finalized and before FinalizeHash/nonce
// mining begins — filter construction scans every transaction and must
// not be repeated per nonce attempt.
func (b *Block) PopulateLogsBloom() {
	if b == nil || b.Header == nil {
		return
	}
	bf := BuildBlockBloomFilter(&b.Body)
	b.Header.SetBloomFilter(bf)
}
