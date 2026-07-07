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

// CallRPC sends an RPC request to a peer, supporting both JSON and binary formats.
func CallRPC(address, method string, params interface{}, nodeID NodeID, ttl uint16) (*Message, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Convert method to RPCType.
	// NOTE: this must stay in sync with JSONRPCHandler.registerMethods /
	// mapRPCTypeToMethod in json.go — previously only 6 of the ~20 server
	// methods were mapped here, so calls like "getbalance", "getnetworkinfo",
	// "ping", or "gettransactionhistory" failed locally with
	// ErrUnsupportedRPCType before ever reaching the network, silently
	// forcing callers (e.g. WalletClient) onto their mock-data fallback.
	var rpcType RPCType
	switch method {
	case "getblockcount":
		rpcType = RPCGetBlockCount
	case "getbestblockhash":
		rpcType = RPCGetBestBlockHash
	case "getblock":
		rpcType = RPCGetBlock
	case "getblocks":
		rpcType = RPCGetBlocks
	case "sendrawtransaction":
		rpcType = RPCSendRawTransaction
	case "gettransaction":
		rpcType = RPCGetTransaction
	case "ping":
		rpcType = RPCPing
	case "join":
		rpcType = RPCJoin
	case "findnode":
		rpcType = RPCFindNode
	case "get":
		rpcType = RPCGet
	case "store":
		rpcType = RPCStore
	case "getblockbynumber":
		rpcType = RPCGetBlockByNumber
	case "getblockhash":
		rpcType = RPCGetBlockHash
	case "getdifficulty":
		rpcType = RPCGetDifficulty
	case "getchaintip":
		rpcType = RPCGetChainTip
	case "getnetworkinfo":
		rpcType = RPCGetNetworkInfo
	case "getmininginfo":
		rpcType = RPCGetMiningInfo
	case "estimatefee":
		rpcType = RPCEstimateFee
	case "getmempoolinfo":
		rpcType = RPCGetMemPoolInfo
	case "validateaddress":
		rpcType = RPCValidateAddress
	case "verifymessage":
		rpcType = RPCVerifyMessage
	case "getrawtransaction":
		rpcType = RPCGetRawTransaction
	case "getbalance":
		rpcType = RPCGetBalance
	case "gettransactionhistory":
		rpcType = RPCGetTransactionHistory
	case "getsupplystatus":
		rpcType = RPCGetSupplyStatus
	case "getcheckpoint":
		rpcType = RPCGetCheckpoint
	case "storeartifact":
		rpcType = RPCStoreArtifact
	case "getartifact":
		rpcType = RPCGetArtifact
	case "getnonce":
		rpcType = RPCGetNonce
	default:
		return nil, ErrUnsupportedRPCType
	}

	// Serialize params
	paramsData, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	// Create Message
	msg := &Message{
		RPCType: rpcType,
		Query:   true,
		TTL:     ttl,
		Target:  NodeID{}, // Set to target node ID in production
		RPCID:   GetRPCID(),
		From: Remote{
			NodeID:  nodeID,
			Address: net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}, // Set actual address in production
		},
		Values:    [][]byte{paramsData},
		Iteration: 0,
		Secret:    uint16(time.Now().UnixNano() % 65536),
	}

	// Serialize Message
	data, err := msg.Marshal(make([]byte, msg.MarshalSize()))
	if err != nil {
		return nil, err
	}

	// Wrap binary RPC data as a JSON byte string. json.RawMessage must contain
	// valid JSON, not arbitrary binary bytes.
	rpcPayload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	secMsg := &security.Message{Type: "rpc", Data: rpcPayload}
	encodedData, err := secMsg.Encode()
	if err != nil {
		return nil, err
	}

	// Write length-prefixed message
	if err := writeFramedMessage(conn, encodedData); err != nil {
		return nil, err
	}

	// Read length-prefixed response
	respData, err := readFramedMessage(conn)
	if err != nil {
		return nil, err
	}
	respMsg, err := security.DecodeMessage(respData)
	if err != nil {
		return nil, err
	}

	// Ensure the response is of type "rpc"
	if respMsg.Type != "rpc" {
		return nil, ErrInvalidMessageFormat
	}

	// Extract and deserialize the RPC Message. Binary RPC payloads are carried
	// as JSON byte strings inside security.Message.Data.
	var dataBytes []byte
	if err := json.Unmarshal(respMsg.Data, &dataBytes); err != nil {
		dataBytes = respMsg.Data
	}
	if len(dataBytes) == 0 {
		return nil, ErrInvalidMessageFormat
	}

	// Check if the response is a JSON-RPC error response before trying to unmarshal as binary Message.
	// The server may return JSON-RPC errors (e.g. method not found). Those payloads are valid
	// JSON, not binary RPC Message bytes, so attempting resp.Unmarshal() would fail with
	// buffer-size / format errors.
	var rpcErrResp struct {
		JSONRPC string    `json:"jsonrpc"`
		Error   *RPCError `json:"error"`
		Result  any       `json:"result"`
	}
	if err := json.Unmarshal(dataBytes, &rpcErrResp); err == nil && rpcErrResp.JSONRPC == "2.0" {
		if rpcErrResp.Error != nil {
			return nil, fmt.Errorf("RPC error (%d): %s", rpcErrResp.Error.Code, rpcErrResp.Error.Message)
		}
		// If it's a JSON-RPC response without an error, we still can't treat it as a binary Message.
		return nil, fmt.Errorf("unexpected JSON-RPC response (expected binary Message): %s", string(dataBytes))
	}

	var resp Message
	if err := resp.Unmarshal(dataBytes); err != nil {
		return nil, err
	}

	return &resp, nil
}

// writeFramedMessage writes a length-prefixed message to the connection.
func writeFramedMessage(conn net.Conn, data []byte) error {
	// Write 4-byte big-endian length prefix
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := conn.Write(lenBuf); err != nil {
		return fmt.Errorf("writing length prefix: %w", err)
	}
	// Write payload
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("writing payload: %w", err)
	}
	return nil
}

// readFramedMessage reads a length-prefixed message from the connection.
func readFramedMessage(conn net.Conn) ([]byte, error) {
	// Read 4-byte big-endian length prefix
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
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
