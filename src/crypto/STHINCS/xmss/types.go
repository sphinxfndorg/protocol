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

// go/src/crypto/STHINCS/address/types.go
package xmss

// XMSSSignature represents a signature from one XMSS tree
//
// XMSS (eXtended Merkle Signature Scheme) is a stateful hash-based signature scheme.
// In STHINCS, XMSS trees form the building blocks of the hypertree structure.
// Each XMSS tree has 2^Hprime leaves, where each leaf is a WOTS+ public key.
//
// Components:
//   - WotsSignature: WOTS+ signature for the message (Len * N bytes)
//   - AUTH: Authentication path (Hprime * N bytes)
//
// Total signature size: Len*N + Hprime*N bytes
// For typical parameters: 67*32 + 4*32 = 2144 + 128 = 2272 bytes
type XMSSSignature struct {
	WotsSignature []byte // WOTS+ signature (Len * N bytes)
	AUTH          []byte // Authentication path (Hprime * N bytes)
}
