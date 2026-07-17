// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/transaction/bloomquery.go
package types

// MayContainAddress reports whether this header's Bloom filter might
// include addr. A false result is certain; a true result must still be
// verified against the actual block body (BlockContainsAddress) before
// being trusted, since Bloom filters can false-positive.
func (h *BlockHeader) MayContainAddress(addr string) bool {
	if h == nil || len(h.LogsBloom) == 0 {
		return false
	}
	bf, err := h.DecodeBloomFilter()
	if err != nil {
		return false
	}
	return bf.Contains([]byte(addr))
}

// MayContainTxID reports whether this header's Bloom filter might
// include txID. Same false-positive caveat as MayContainAddress.
func (h *BlockHeader) MayContainTxID(txID string) bool {
	if h == nil || len(h.LogsBloom) == 0 {
		return false
	}
	bf, err := h.DecodeBloomFilter()
	if err != nil {
		return false
	}
	return bf.Contains([]byte(txID))
}

// BlockContainsAddress does the definitive, non-probabilistic check:
// does any transaction in b actually reference addr as Sender,
// Receiver, or ToContract. Callers doing a bulk chain scan should first
// filter candidate blocks with MayContainAddress (cheap) and only call
// this (a full body scan) on blocks that pass.
func (b *Block) BlockContainsAddress(addr string) bool {
	if b == nil {
		return false
	}
	for _, tx := range b.Body.TxsList {
		if tx == nil {
			continue
		}
		if tx.Sender == addr || tx.Receiver == addr || tx.ToContract == addr {
			return true
		}
	}
	return false
}

// MayContainAddress is a convenience forwarding to b.Header.MayContainAddress.
func (b *Block) MayContainAddress(addr string) bool {
	if b == nil || b.Header == nil {
		return false
	}
	return b.Header.MayContainAddress(addr)
}
