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
func BuildBlockBloomFilter(body *BlockBody) *bloom.BloomFilter {
	bf := bloom.NewDefault()
	if body == nil {
		return bf
	}
	for _, tx := range body.TxsList {
		if tx == nil {
			continue
		}
		if tx.ID != "" {
			bf.Add([]byte(tx.ID))
		}
		if tx.Sender != "" {
			bf.Add([]byte(tx.Sender))
		}
		if tx.Receiver != "" {
			bf.Add([]byte(tx.Receiver))
		}
		if tx.ToContract != "" {
			bf.Add([]byte(tx.ToContract))
		}
	}
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
