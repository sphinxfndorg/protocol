// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/rpc/client.go
package rpc

import (
	"encoding/json"
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
	case "getsupplystatus": // ADD THIS
		rpcType = RPCGetSupplyStatus
	case "getcheckpoint":
		rpcType = RPCGetCheckpoint
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

	if _, err := conn.Write(encodedData); err != nil {
		return nil, err
	}

	// Read response
	respData := readConn(conn)
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

	var resp Message
	if err := resp.Unmarshal(dataBytes); err != nil {
		return nil, err
	}

	return &resp, nil
}

// readConn reads data from a connection.
func readConn(conn net.Conn) []byte {
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	return buf[:n]
}
