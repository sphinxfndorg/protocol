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

	return decodeRPCResult(respMsg.Data)
}

// rpcResponseEnvelope is the LOSSLESS shape of a JSON-RPC 2.0 response: the
// `result` member is kept as the exact bytes the server sent rather than
// being decoded into an interface{}.
//
// ★ FIX: decoding into rpc.JSONRPCResponse previously turned every JSON number
// in `result` into a float64 and then re-marshalled it, because Result is
// typed interface{}. That silently corrupted large integers: the node emits
// nSPX amounts (and block-header Difficulty/GasLimit/ChainWeight) as exact
// plain-digit big.Int values, but a float64 cannot hold ~10^25 exactly, and
// encoding/json renders such floats in exponent notation. A transaction
// history response therefore arrived at the wallet as
//
//	"amount": 1e+25
//
// instead of
//
//	"amount": 19999999999705000000000000
//
// which the wallet's types.Transaction (Amount *big.Int) rejected outright with
// `math/big: cannot unmarshal "1e+25" into a *big.Int` — the reported
// "[Wallet] Failed to fetch transaction history" error — and which also lost
// the low-order digits of every amount it did parse.
type rpcResponseEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *RPCError       `json:"error"`
	ID      json.RawMessage `json:"id"`
}

// decodeRPCResult parses a JSON-RPC 2.0 response body and returns the raw
// `result` value verbatim, so callers unmarshal it themselves with whatever
// numeric fidelity they need. A missing or null result is reported as "null"
// (exactly what the previous interface{} + re-marshal path produced), and an
// error member is surfaced with the same message as before.
func decodeRPCResult(data []byte) (json.RawMessage, error) {
	var env rpcResponseEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse JSON-RPC response: %w", err)
	}
	if env.Error != nil {
		return nil, fmt.Errorf("RPC error (%d): %s", env.Error.Code, env.Error.Message)
	}
	if env.Result == nil {
		return json.RawMessage("null"), nil
	}
	return env.Result, nil
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
