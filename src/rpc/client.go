// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/rpc/client.go
package rpc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	security "github.com/sphinxfndorg/protocol/src/handshake"
)

// CallRPC sends a JSON-RPC 2.0 request to a node and returns the raw
// `result` field of the response as json.RawMessage.
//
// address MUST be the node's P2P TCP address — the tcpAddr passed to
// server.NewServer / transport.NewTCPServer (see port.go's baseTCPPort,
// default 32307) — NOT the HTTP/Gin address (go/src/http). The HTTP server
// is a plain REST API (/transaction, /blockcount, ...) with no JSON-RPC
// bridge at all; posting this protocol's bytes to it just confuses the
// net/http parser.
//
// The P2P TCP listener (transport.TCPServer.handleConnection, tcp.go) is
// the only listener in this codebase that forwards requests into
// rpc.Server.HandleRequest, and it requires, in this exact order:
//  1. A completed Kyber768/SPHINCS+ handshake (security.PerformHandshake,
//     protocol label "p2p" — the same label transport/tcp.go's own Connect
//     method uses to talk to this same listener).
//  2. The request wrapped as security.Message{Type: "jsonrpc", Data: ...}
//     — NOT "rpc". The listener only forwards "jsonrpc"-typed messages into
//     HandleRequest; any other Type is just dropped into messageCh and
//     never answered.
//  3. Encrypted via security.SecureMessage, decrypted on the way back via
//     security.DecodeSecureMessage, both keyed by the handshake result.
//
// An earlier version of this function built a "rpc"-typed, unencrypted,
// handshake-less message and dialed the HTTP port by default. That protocol
// has no listener anywhere in the codebase, so every call either blocked on
// a handshake the server was waiting for and never received, or (against
// the HTTP server) was parsed as garbage — which is why wallet RPC calls
// (balance, nonce, send, history) always failed with "Error".
func CallRPC(address, method string, params interface{}, ttlSeconds uint16) (json.RawMessage, error) {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", address, err)
	}
	defer conn.Close()

	if ttlSeconds == 0 {
		ttlSeconds = 30
	}
	deadline := time.Now().Add(time.Duration(ttlSeconds) * time.Second)
	_ = conn.SetDeadline(deadline)

	// Step 1: handshake. Must match the "p2p" label used by the server's
	// own listener and by transport/tcp.go's Connect (client-role P2P
	// dialer) — using a different label here is what would silently break
	// this again if changed without checking tcp.go.
	handshake := security.NewHandshake()
	enc, err := handshake.PerformHandshake(conn, "p2p", true)
	if err != nil {
		return nil, fmt.Errorf("handshake with %s: %w", address, err)
	}
	if enc == nil {
		return nil, fmt.Errorf("handshake with %s returned nil encryption key", address)
	}

	// Step 2 & 3: build + encrypt the JSON-RPC request.
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      time.Now().UnixNano(),
	}
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	secMsg := &security.Message{Type: "jsonrpc", Data: reqData}
	encryptedReq, err := security.SecureMessage(secMsg, enc)
	if err != nil {
		return nil, fmt.Errorf("encrypt request: %w", err)
	}

	if err := writeFramedMessage(conn, encryptedReq); err != nil {
		return nil, err
	}

	respData, err := readFramedMessage(conn, deadline)
	if err != nil {
		return nil, err
	}

	respMsg, err := security.DecodeSecureMessage(respData, enc)
	if err != nil {
		return nil, fmt.Errorf("decrypt response: %w", err)
	}
	if respMsg.Type != "jsonrpc" {
		return nil, fmt.Errorf("unexpected response type %q (expected \"jsonrpc\")", respMsg.Type)
	}

	var jsonResp JSONRPCResponse
	if err := json.Unmarshal(respMsg.Data, &jsonResp); err != nil {
		return nil, fmt.Errorf("parse JSON-RPC response: %w", err)
	}
	if jsonResp.Error != nil {
		return nil, fmt.Errorf("RPC error (%d): %s", jsonResp.Error.Code, jsonResp.Error.Message)
	}

	resultBytes, err := json.Marshal(jsonResp.Result)
	if err != nil {
		return nil, fmt.Errorf("re-marshal result: %w", err)
	}
	return resultBytes, nil
}

// writeFramedMessage writes a 4-byte big-endian length prefix followed by
// the payload — the exact framing transport/tcp.go's handleConnection reads.
func writeFramedMessage(conn net.Conn, data []byte) error {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := conn.Write(lenBuf); err != nil {
		return fmt.Errorf("writing length prefix: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("writing payload: %w", err)
	}
	return nil
}

// readFramedMessage reads a 4-byte big-endian length prefix followed by the
// payload, matching the framing transport/tcp.go's handleConnection writes.
func readFramedMessage(conn net.Conn, deadline time.Time) ([]byte, error) {
	_ = conn.SetReadDeadline(deadline)
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("reading length prefix: %w", err)
	}
	size := binary.BigEndian.Uint32(lenBuf[:])
	if size == 0 || size > 16*1024*1024 { // Sanity cap: 16MB
		return nil, fmt.Errorf("implausible message size: %d", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, fmt.Errorf("reading %d-byte payload: %w", size, err)
	}
	return data, nil
}
