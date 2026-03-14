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

// go/src/consensus/randao.go
package consensus

import (
	"encoding/binary"

	"github.com/sphinxorg/protocol/src/common"
)

// NewRANDAO initialises a RANDAO beacon with the given genesis seed.
// genesisSeed is typically [32]byte{0x53,0x50,0x48,0x58} ("SPHX\0…").
func NewRANDAO(genesisSeed [32]byte) *RANDAO {
	return &RANDAO{
		mix:     genesisSeed,                 // starting mix — same on every node
		reveals: make(map[uint64][][32]byte), // epoch → list of reveals
	}
}

// AddReveal incorporates a validator's random reveal into the running RANDAO mix.
// Called once per validator per epoch when the validator publishes their secret.
// The reveal is XOR'd into the mix byte-by-byte, making the mix a cumulative
// commitment to all revealed values for the epoch.
func (r *RANDAO) AddReveal(epoch uint64, reveal [32]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Append the raw reveal to the per-epoch log for audit purposes.
	r.reveals[epoch] = append(r.reveals[epoch], reveal)

	// XOR every byte of the reveal into the running mix.
	// XOR is commutative and associative, so the final mix does not depend on
	// the order in which reveals arrive.
	for i := 0; i < 32; i++ {
		r.mix[i] ^= reveal[i]
	}
}

// GetSeed derives a deterministic 32-byte seed for the given slot number.
// The seed is computed as SpxHash(mix || slot), where:
//   - mix    is the 32-byte RANDAO accumulator (same on all nodes)
//   - slot   is encoded as a little-endian uint64 (8 bytes)
//
// Because the mix and slot number are identical on every node, GetSeed returns
// the same value everywhere — which is the key property required for consistent
// leader election across the network.
func (r *RANDAO) GetSeed(slot uint64) [32]byte {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Build the 40-byte pre-image: first 32 bytes = mix, last 8 bytes = slot.
	data := make([]byte, 40)
	copy(data[:32], r.mix[:])                      // copy current RANDAO mix
	binary.LittleEndian.PutUint64(data[32:], slot) // append slot number LE

	// Hash the pre-image using the Sphinx-native hash function.
	hashResult := common.SpxHash(data)

	// Copy the hash output into a fixed-size [32]byte result.
	var result [32]byte
	copy(result[:], hashResult)
	return result
}

// GenerateVRF produces a Verifiable Random Function (VRF) output by hashing
// a validator's secret key together with the current RANDAO seed.
// Used by validators to prove that their reveal was derived from their key
// without revealing the key itself.
func (r *RANDAO) GenerateVRF(secretKey []byte, seed [32]byte) [32]byte {
	// Concatenate secretKey and seed as the VRF input.
	data := append(secretKey, seed[:]...)

	// Hash using SpxHash.  In production this would be replaced with a proper
	// VRF construction (e.g. ECVRF) that provides a zero-knowledge proof.
	hashResult := common.SpxHash(data)

	var result [32]byte
	copy(result[:], hashResult)
	return result
}
