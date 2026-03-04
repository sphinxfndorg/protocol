// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// consensus/randao.go
package consensus

import (
	"encoding/binary"

	"github.com/sphinxorg/protocol/src/common"
)

func NewRANDAO(genesisSeed [32]byte) *RANDAO {
	return &RANDAO{
		mix:     genesisSeed,
		reveals: make(map[uint64][][32]byte),
	}
}

// AddReveal adds a validator's random reveal
func (r *RANDAO) AddReveal(epoch uint64, reveal [32]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.reveals[epoch] = append(r.reveals[epoch], reveal)

	// Update mix with XOR
	for i := 0; i < 32; i++ {
		r.mix[i] ^= reveal[i]
	}
}

// GetSeed returns randomness seed for a given slot
func (r *RANDAO) GetSeed(slot uint64) [32]byte {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Mix current RANDAO with slot number
	data := make([]byte, 40)
	copy(data[:32], r.mix[:])
	binary.LittleEndian.PutUint64(data[32:], slot)

	// Use SpxHash instead of sha256
	hashResult := common.SpxHash(data)

	// Convert []byte to [32]byte
	var result [32]byte
	copy(result[:], hashResult)
	return result
}

// GenerateVRF generates a VRF proof (simplified)
func (r *RANDAO) GenerateVRF(secretKey []byte, seed [32]byte) [32]byte {
	data := append(secretKey, seed[:]...)

	// Use SpxHash instead of sha256
	hashResult := common.SpxHash(data)

	// Convert []byte to [32]byte
	var result [32]byte
	copy(result[:], hashResult)
	return result
}
