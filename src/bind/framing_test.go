// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/framing_test.go
//
// Regression tests for framed P2P writes. A framed message larger than the
// socket's per-send capacity used to be silently truncated, which broke the
// get_blocks reply and with it the whole catch-up path.
package bind

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// shortWriteConn is a net.Conn stand-in whose Write accepts at most chunk
// bytes per call, emulating a TCP socket whose send buffer is smaller than the
// frame. Writes land in an in-memory buffer so the test can assert on exactly
// what the writer handed to the transport.
type shortWriteConn struct {
	net.Conn
	chunk int
	buf   bytes.Buffer
}

func (c *shortWriteConn) Write(p []byte) (int, error) {
	if len(p) > c.chunk {
		p = p[:c.chunk]
	}
	return c.buf.Write(p)
}

// frame returns the payload recovered from the framed bytes, or nil when the
// frame is incomplete.
func (c *shortWriteConn) frame() []byte {
	raw := c.buf.Bytes()
	if len(raw) < 4 {
		return nil
	}
	size := int(binary.BigEndian.Uint32(raw[:4]))
	if len(raw) < 4+size {
		return nil
	}
	return raw[4 : 4+size]
}

// TestWriteFramedMessage_FullFrameDespiteShortWrites is the regression test for
// the truncated get_blocks reply. Three committed blocks carry three SPHINCS+
// attestations each at ~4864 bytes per signature, so the reply is tens of KB
// and routinely exceeds one send. Before the fix only the first chunk reached
// the socket, the attestation signatures at the tail were lost, and every
// peer-served block failed verification with "decode signed proof: EOF".
func TestWriteFramedMessage_FullFrameDespiteShortWrites(t *testing.T) {
	payload := make([]byte, 44*1024)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	for _, chunk := range []int{1, 7, 1024, 8192} {
		conn := &shortWriteConn{chunk: chunk}
		if err := writeFramedMessage(conn, payload); err != nil {
			t.Fatalf("chunk=%d: write failed: %v", chunk, err)
		}
		got := conn.frame()
		if len(got) != len(payload) {
			t.Fatalf("chunk=%d: framed %d bytes, want %d (frame truncated)", chunk, len(got), len(payload))
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("chunk=%d: payload corrupted in transit", chunk)
		}
	}
}

// TestWriteAll_PropagatesWriteError asserts writeAll does not report success
// when the connection is gone, and does not spin on a zero-byte write.
func TestWriteAll_PropagatesWriteError(t *testing.T) {
	srv, cli := net.Pipe()
	_ = cli.Close()
	if err := writeAll(srv, make([]byte, 1024)); err == nil {
		t.Fatal("writeAll on a closed connection returned nil error")
	}
}

// zeroWriteConn returns (0, nil) forever, which a naive loop would treat as
// progress and spin on.
type zeroWriteConn struct {
	net.Conn
}

func (zeroWriteConn) Write(p []byte) (int, error) { return 0, nil }

func TestWriteAll_RejectsZeroLengthWrite(t *testing.T) {
	done := make(chan error, 1)
	go func() { done <- writeAll(zeroWriteConn{}, make([]byte, 16)) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("writeAll reported success on a connection that never accepts bytes")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writeAll spun on a zero-length write instead of returning")
	}
}
