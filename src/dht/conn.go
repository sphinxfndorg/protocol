// Copyright 2024 Lei Ni (nilei81@gmail.com)
//
// This library follows a dual licensing model -
//
// - it is licensed under the 2-clause BSD license if you have written evidence showing that you are a licensee of github.com/lni/pothos
// - otherwise, it is licensed under the GPL-2 license
//
// See the LICENSE file for details
// https://github.com/lni/dht/tree/main
//
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

// go/src/dht/conn.go
package dht

import (
	"errors"
	"net"
	"os"
	"time"

	security "github.com/sphinxorg/protocol/src/handshake"
	"github.com/sphinxorg/protocol/src/rpc"
	"go.uber.org/zap"
	"lukechampine.com/blake3"
)

// Constants for UDP packet handling and security
const (
	// maxPacketSize is the maximum size of a UDP packet (4KB)
	// UDP has a theoretical limit of 64KB but 4KB is safer for network transmission
	maxPacketSize int = 4096

	// readTimeout is the maximum time to wait for reading a packet
	// Prevents blocking indefinitely on read operations
	readTimeout = 250 * time.Millisecond

	// hashSize is the output size of BLAKE3 hash function (256 bits/32 bytes)
	// Used for message integrity verification
	hashSize = 32 // BLAKE3 output size (256 bits/32 bytes)
)

// Add this method to the conn struct to use getMessageBuf
// EncodeMessage prepares a message for transmission by adding magic number and hash
func (c *conn) EncodeMessage(msg rpc.Message) ([]byte, error) {
	// Use getMessageBuf to add magic header and BLAKE3 hash to the message
	return getMessageBuf(c.sendBuf, msg)
}

// newConn creates a new UDP connection for DHT communication
// It sets up a listening socket on the configured address
func newConn(cfg Config, logger *zap.Logger) (*conn, error) {
	// Create a UDP listener on the specified address and protocol
	// ListenPacket creates a connection that can read and write packets
	listener, err := net.ListenPacket(cfg.Proto, cfg.Address.String())
	if err != nil {
		return nil, err // Return error if binding fails (port already in use, etc.)
	}

	// Initialize and return the connection struct
	return &conn{
		ReceivedCh: make(chan rpc.Message, 256), // Channel for incoming messages with buffer
		sendBuf:    make([]byte, maxPacketSize), // Buffer for sending messages
		recvBuf:    make([]byte, maxPacketSize), // Buffer for receiving messages
		c:          listener.(*net.UDPConn),     // Type assert to UDP connection
		log:        logger,                      // Logger for debugging
	}, nil
}

// Close gracefully shuts down the UDP connection
func (c *conn) Close() error {
	return c.c.Close() // Close the underlying UDP socket
}

// SendMessage transmits a byte buffer to a specific UDP address
func (c *conn) SendMessage(buf []byte, addr net.UDPAddr) error {
	// WriteTo sends the buffer to the specified address
	// Returns number of bytes sent and error if any
	if _, err := c.c.WriteTo(buf, &addr); err != nil {
		return err
	}
	return nil
}

// ReceiveMessageLoop is the main receiving loop that processes incoming UDP packets
// It runs continuously until stopc is signaled
func (c *conn) ReceiveMessageLoop(stopc chan struct{}) error {
	for {
		// Check if we should stop before each iteration
		select {
		case <-stopc:
			return nil // Stop signal received, exit gracefully
		default:
			// Continue processing
		}

		// Set a read deadline to prevent blocking forever
		// This allows the loop to check the stop channel periodically
		timeout := time.Now().Add(readTimeout)
		if err := c.c.SetReadDeadline(timeout); err != nil {
			return err
		}

		// Read a packet from the UDP socket
		// ReadFromUDP returns number of bytes read, address of sender, and error
		n, _, err := c.c.ReadFromUDP(c.recvBuf)

		// Handle deadline exceeded errors (normal timeout)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue // Timeout occurred, loop again to check stop channel
		}
		// Handle other errors by continuing (non-fatal)
		if err != nil {
			continue
		}

		// Verify the received message integrity using magic number and BLAKE3 hash
		buf, ok := verifyReceivedMessage(c.recvBuf[:n])
		if !ok {
			continue // Message failed verification, skip it
		}

		// Decode the security layer message
		secMsg, err := security.DecodeMessage(buf)
		if err != nil || secMsg.Type != "rpc" {
			continue // Not a valid RPC message, skip
		}

		// Extract the data bytes from the security message
		dataBytes, ok := secMsg.Data.([]byte)
		if !ok {
			continue // Data is not in expected format, skip
		}

		// Unmarshal the RPC message from the data bytes
		var msg rpc.Message
		if err := msg.Unmarshal(dataBytes); err != nil {
			continue // Failed to unmarshal RPC message, skip
		}

		// Send the valid message to the received channel
		// Check stop channel again before sending
		select {
		case <-stopc:
			return nil // Stop signal received, exit
		case c.ReceivedCh <- msg:
			// Message successfully queued for processing
		}
	}
}

// getMessageBuf prepares a message buffer for sending by adding:
// - Magic number (2 bytes) for protocol identification
// - Message size (2 bytes) for framing
// - Message payload (variable)
// - BLAKE3 hash (32 bytes) for integrity verification
func getMessageBuf(buf []byte, msg rpc.Message) ([]byte, error) {
	// Calculate the size of the marshaled message
	msgSize := msg.MarshalSize()

	// Calculate total buffer size: magic(2) + size(2) + payload(msgSize) + hash(32)
	bufSize := 2 + 2 + msgSize + hashSize

	// If the provided buffer is too small, allocate a new one
	if bufSize > len(buf) {
		buf = make([]byte, bufSize)
	}

	// Create codec for binary encoding/decoding
	codec := &rpc.Codec{}

	// Write magic number (protocol identifier) at the beginning
	// This helps identify Sphinx protocol packets vs random UDP traffic
	buf[0] = magicNumber[0]
	buf[1] = magicNumber[1]

	// Write message payload size as uint16 (2 bytes)
	// This allows the receiver to know how many bytes to read for the payload
	codec.PutUint16(buf[2:], uint16(msgSize))

	// Marshal the message payload into the buffer starting at offset 4
	// Marshal writes the message to the provided byte slice
	if _, err := msg.Marshal(buf[4:]); err != nil {
		return nil, err
	}

	// Calculate BLAKE3 hash of header + payload (bytes 2 through 4+msgSize-1)
	// This ensures integrity of both the size field and the payload
	hash := blake3.Sum256(buf[2 : 4+msgSize])

	// Copy the hash to the end of the buffer
	// The receiver will verify this hash matches the calculated one
	copy(buf[4+msgSize:], hash[:])

	// Return the complete buffer (only the used portion)
	return buf[:bufSize], nil
}

// verifyReceivedMessage validates an incoming message by checking:
// - Magic number matches expected value
// - Message length is sufficient
// - BLAKE3 hash matches the content
// Returns the payload and success flag
func verifyReceivedMessage(msg []byte) ([]byte, bool) {
	// Minimum message size: magic(2) + size(2) + hash(32) = 36 bytes
	// If smaller, it cannot be valid
	if len(msg) < 4+hashSize {
		return nil, false
	}

	// Verify magic number matches expected protocol identifier
	// This ensures we're receiving Sphinx protocol messages
	if msg[0] != magicNumber[0] || msg[1] != magicNumber[1] {
		return nil, false
	}

	// Create codec for reading uint16 from bytes
	codec := &rpc.Codec{}

	// Extract the payload size from bytes 2-3
	sz := int(codec.Uint16(msg[2:]))

	// Verify total message length matches expected format
	// Expected: magic(2) + size(2) + payload(sz) + hash(32)
	if len(msg) != 4+sz+hashSize {
		return nil, false
	}

	// Calculate and verify BLAKE3 hash
	// Compute hash of header + payload (bytes 2 through 4+sz-1)
	expectedHash := blake3.Sum256(msg[2 : 4+sz])

	// Extract received hash from the end of the message
	receivedHash := msg[4+sz : 4+sz+hashSize]

	// Compare hashes using constant-time comparison
	// This prevents timing attacks that could exploit early returns
	if !equalHashes(expectedHash[:], receivedHash) {
		return nil, false // Hash mismatch - message tampered or corrupted
	}

	// Message is valid - return the payload (bytes 4 through 4+sz-1)
	return msg[4 : 4+sz], true
}

// Constant-time hash comparison to prevent timing attacks
// This function compares two byte slices in a way that doesn't leak
// information about where the difference occurs through timing
func equalHashes(a, b []byte) bool {
	// If lengths differ, hashes cannot be equal
	if len(a) != len(b) {
		return false
	}

	// XOR each byte pair and OR the results together
	// This operation takes the same amount of time regardless of where
	// the first difference occurs, preventing timing attacks
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i] // XOR: 0 if equal, non-zero if different
	}

	// result will be 0 only if all bytes were equal
	return result == 0
}
