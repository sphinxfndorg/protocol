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

// go/src/crypto/STHINCS/spxhash.go
package tweakable

import (
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/address"
)

// SphinxHashTweak must match the same field structure as Sha256Tweak
type SphinxHashTweak struct {
	Variant             string
	MessageDigestLength int
	N                   int
}

func (s *SphinxHashTweak) Hmsg(R []byte, PKseed []byte, PKroot, M []byte) []byte {
	var buffer []byte
	buffer = append(buffer, R...)
	buffer = append(buffer, PKseed...)
	buffer = append(buffer, PKroot...)
	buffer = append(buffer, M...)

	// Simple stub hash - replace with actual SphinxHash
	hash := make([]byte, s.N)
	for i := 0; i < s.N; i++ {
		if i < len(buffer) {
			hash[i] = buffer[i] ^ byte(i)
		} else {
			hash[i] = byte((i * 31) % 256)
		}
	}
	return hash[:s.N]
}

func (s *SphinxHashTweak) PRF(SEED []byte, adrs *address.ADRS) []byte {
	var buffer []byte
	buffer = append(buffer, SEED...)
	buffer = append(buffer, adrs.GetBytes()...)

	hash := make([]byte, s.N)
	for i := 0; i < s.N; i++ {
		if i < len(buffer) {
			hash[i] = buffer[i] ^ byte(i+1)
		} else {
			hash[i] = byte((i * 47) % 256)
		}
	}
	return hash[:s.N]
}

func (s *SphinxHashTweak) PRFmsg(SKprf []byte, OptRand []byte, M []byte) []byte {
	var buffer []byte
	buffer = append(buffer, SKprf...)
	buffer = append(buffer, OptRand...)
	buffer = append(buffer, M...)

	hash := make([]byte, s.N)
	for i := 0; i < s.N; i++ {
		if i < len(buffer) {
			hash[i] = buffer[i] ^ byte(i+2)
		} else {
			hash[i] = byte((i * 53) % 256)
		}
	}
	return hash[:s.N]
}

func (s *SphinxHashTweak) F(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	var buffer []byte
	buffer = append(buffer, PKseed...)
	buffer = append(buffer, adrs.GetBytes()...)
	buffer = append(buffer, tmp...)

	hash := make([]byte, s.N)
	for i := 0; i < s.N; i++ {
		if i < len(buffer) {
			hash[i] = buffer[i] ^ byte(i+3)
		} else {
			hash[i] = byte((i * 59) % 256)
		}
	}
	return hash[:s.N]
}

func (s *SphinxHashTweak) H(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	var buffer []byte
	buffer = append(buffer, PKseed...)
	buffer = append(buffer, adrs.GetBytes()...)
	buffer = append(buffer, tmp...)

	hash := make([]byte, s.N)
	for i := 0; i < s.N; i++ {
		if i < len(buffer) {
			hash[i] = buffer[i] ^ byte(i+4)
		} else {
			hash[i] = byte((i * 61) % 256)
		}
	}
	return hash[:s.N]
}

func (s *SphinxHashTweak) T_l(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
	var buffer []byte
	buffer = append(buffer, PKseed...)
	buffer = append(buffer, adrs.GetBytes()...)
	buffer = append(buffer, tmp...)

	hash := make([]byte, s.N)
	for i := 0; i < s.N; i++ {
		if i < len(buffer) {
			hash[i] = buffer[i] ^ byte(i+5)
		} else {
			hash[i] = byte((i * 67) % 256)
		}
	}
	return hash[:s.N]
}
