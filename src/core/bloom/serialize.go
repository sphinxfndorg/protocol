// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/bloom/serialize.go
package bloom

import (
	"encoding/hex"
	"encoding/json"
	"errors"
)

// ErrSizeMismatch is returned when loading raw bytes into a filter whose
// Config expects a different byte length.
var ErrSizeMismatch = errors.New("bloom: byte length does not match config bits")

// Bytes returns a copy of the filter's raw bitset bytes (MSB-first per
// byte, per the bitset package convention). This is the wire format
// stored directly in BlockHeader.LogsBloom.
func (bf *BloomFilter) Bytes() []byte {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	src := bf.bits.Bytes()
	out := make([]byte, len(src))
	copy(out, src)
	return out
}

// Load replaces bf's bits with buf, which must be exactly cfg.Bytes()
// long. Used when deserializing a filter received from a peer.
func (bf *BloomFilter) Load(buf []byte) error {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	if len(buf) != bf.cfg.Bytes() {
		return ErrSizeMismatch
	}
	cp := make([]byte, len(buf))
	copy(cp, buf)
	bf.bits = newBitsetFromBytes(cp)
	return nil
}

// LoadFilter builds a new BloomFilter from raw bytes under cfg. buf must
// be exactly cfg.Bytes() long.
func LoadFilter(cfg Config, buf []byte) (*BloomFilter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if len(buf) != cfg.Bytes() {
		return nil, ErrSizeMismatch
	}
	cp := make([]byte, len(buf))
	copy(cp, buf)
	return &BloomFilter{bits: newBitsetFromBytes(cp), cfg: cfg}, nil
}

// MarshalBinary implements encoding.BinaryMarshaler, returning the raw
// bitset bytes.
func (bf *BloomFilter) MarshalBinary() ([]byte, error) {
	return bf.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler. bf must already
// have a valid Config (e.g. from New/NewDefault) before calling this.
func (bf *BloomFilter) UnmarshalBinary(data []byte) error {
	return bf.Load(data)
}

// bloomJSON is the wire shape used by MarshalJSON/UnmarshalJSON: the raw
// bitset hex-encoded, alongside the Config it was built with, so a
// filter can be losslessly reconstructed regardless of default changes.
type bloomJSON struct {
	Bits int    `json:"bits"`
	K    int    `json:"k"`
	Data string `json:"data"`
}

// MarshalJSON encodes the filter as hex-encoded bytes plus its Config.
func (bf *BloomFilter) MarshalJSON() ([]byte, error) {
	bf.mu.RLock()
	cfg := bf.cfg
	raw := bf.bits.Bytes()
	bf.mu.RUnlock()

	return json.Marshal(bloomJSON{
		Bits: cfg.Bits,
		K:    cfg.K,
		Data: hex.EncodeToString(raw),
	})
}

// UnmarshalJSON decodes a filter previously produced by MarshalJSON,
// reconstructing both its Config and its bits.
func (bf *BloomFilter) UnmarshalJSON(data []byte) error {
	var aux bloomJSON
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	cfg := Config{Bits: aux.Bits, K: aux.K}
	if err := cfg.Validate(); err != nil {
		return err
	}
	raw, err := hex.DecodeString(aux.Data)
	if err != nil {
		return err
	}
	if len(raw) != cfg.Bytes() {
		return ErrSizeMismatch
	}

	bf.mu.Lock()
	defer bf.mu.Unlock()
	bf.cfg = cfg
	bf.bits = newBitsetFromBytes(raw)
	return nil
}
