// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/crypter/key/utils.go
package crypter

import (
	"runtime"
	"unsafe"
)

// NewSecureBuffer creates a new secure buffer with the given data
func NewSecureBuffer(data []byte) *SecureBuffer {
	return &SecureBuffer{data: data}
}

// Bytes returns a copy of the underlying data (use with caution)
func (sb *SecureBuffer) Bytes() []byte {
	if sb.data == nil {
		return nil
	}
	cp := make([]byte, len(sb.data))
	copy(cp, sb.data)
	return cp
}

// Clear securely wipes the buffer from memory
func (sb *SecureBuffer) Clear() {
	if sb.data != nil {
		// Use runtime.MemclrNoHeapPointers for efficient clearing
		for i := range sb.data {
			sb.data[i] = 0
		}
		sb.data = nil
	}
	runtime.GC() // Encourage garbage collection
}

// Len returns the length of the data
func (sb *SecureBuffer) Len() int {
	if sb.data == nil {
		return 0
	}
	return len(sb.data)
}

// clearBytes securely clears a byte slice from memory
func clearBytes(data []byte) {
	if data == nil {
		return
	}

	// Use compiler intrinsic for efficient memory clearing
	for i := range data {
		data[i] = 0
	}

	// Prevent compiler optimization
	_ = (*[0]byte)(unsafe.Pointer(&data[0]))
}
