// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/rpc/server.go

package rpc

import (
	"encoding/json"
	"log"
	"net"
	"time"

	"github.com/sphinxorg/protocol/src/core"
	sign "github.com/sphinxorg/protocol/src/core/sthincs/sign/backend"
	security "github.com/sphinxorg/protocol/src/handshake"
)

// NewServer creates a new RPC server instance.
// NewServer creates a new RPC server instance with SPHINCS manager
func NewServer(messageCh chan *security.Message, blockchain *core.Blockchain, sphincsManager *sign.STHINCSManager) *Server {
	metrics := NewMetrics()
	server := &Server{
		messageCh:      messageCh,
		metrics:        metrics,
		blockchain:     blockchain,
		queryManager:   NewQueryManager(),
		store:          NewKVStore(),
		sphincsManager: sphincsManager,
	}
	server.handler = NewJSONRPCHandler(server)
	// Start garbage collection always (it runs in a separate goroutine)
	server.StartGarbageCollection()
	if messageCh != nil {
		go server.handleMessages()
	}
	return server
}

// handleMessages processes incoming messages from the message channel.
func (s *Server) handleMessages() {
	for msg := range s.messageCh {
		log.Printf("rpc.Server: Received message on messageCh: Type=%s, Data=%v, ChannelLen=%d", msg.Type, msg.Data, len(s.messageCh))
		if msg.Type == "rpc" {
			// Binary RPC payloads are carried as JSON byte strings inside
			// security.Message.Data.
			dataBytes := unwrapRPCPayload(msg.Data)
			if len(dataBytes) == 0 {
				log.Printf("rpc.Server: Empty RPC data")
				continue
			}
			// Decode the RPC message to get the From field
			var rpcMsg Message
			if err := rpcMsg.Unmarshal(dataBytes); err != nil {
				log.Printf("rpc.Server: Failed to unmarshal RPC message: %v", err)
				continue
			}
			log.Printf("rpc.Server: Decoded RPC message: RPCType=%s, RPCID=%v, From=%s, Query=%v", rpcMsg.RPCType, rpcMsg.RPCID, rpcMsg.From.Address.String(), rpcMsg.Query)
			// Process the RPC request
			respData, err := s.HandleRequest(dataBytes)
			if err != nil {
				log.Printf("rpc.Server: Error handling RPC request: %v", err)
				continue
			}
			log.Printf("rpc.Server: Processed RPC request, response: %s", string(respData))
			// Send response back to the client
			if err := s.sendResponse(rpcMsg.From.Address.String(), respData); err != nil {
				log.Printf("rpc.Server: Failed to send response to %s: %v", rpcMsg.From.Address.String(), err)
				continue
			}
			log.Printf("rpc.Server: Sent response to %s: %s", rpcMsg.From.Address.String(), string(respData))
		} else {
			log.Printf("rpc.Server: Ignoring non-RPC message type: %s", msg.Type)
		}
	}
}

// sendResponse sends an RPC response to the specified address.
func (s *Server) sendResponse(address string, respData []byte) error {
	conn, err := net.Dial("udp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	payload, err := json.Marshal(respData)
	if err != nil {
		return err
	}
	secMsg := &security.Message{Type: "rpc", Data: payload}
	encodedData, err := secMsg.Encode()
	if err != nil {
		return err
	}
	if _, err := conn.Write(encodedData); err != nil {
		return err
	}
	return nil
}

// HandleRequest processes an incoming RPC request (JSON or binary).
func (s *Server) HandleRequest(data []byte) ([]byte, error) {
	log.Printf("rpc.Server: Handling request: %s", string(data))
	// Try decoding as security.Message
	secMsg, err := security.DecodeMessage(data)
	if err == nil && secMsg.Type == "rpc" {
		// Binary RPC payloads are carried as JSON byte strings inside
		// security.Message.Data.
		dataBytes := unwrapRPCPayload(secMsg.Data)
		if len(dataBytes) == 0 {
			log.Printf("rpc.Server: Empty RPC data in security.Message")
			return s.handler.errorResponse(nil, ErrCodeInvalidRequest, "Invalid RPC data format")
		}
		var msg Message
		if err := msg.Unmarshal(dataBytes); err != nil {
			log.Printf("rpc.Server: Invalid RPC message format: %v", err)
			return s.handler.errorResponse(nil, ErrCodeInvalidRequest, "Invalid RPC message format")
		}
		log.Printf("rpc.Server: Decoded RPC message: RPCType=%s, RPCID=%v, Query=%v", msg.RPCType, msg.RPCID, msg.Query)
		// Check if the response is expected
		if !msg.Query && !s.queryManager.IsExpectedResponse(msg) {
			log.Printf("rpc.Server: Unexpected response: RPCID=%v", msg.RPCID)
			return s.handler.errorResponse(msg.RPCID, ErrCodeInvalidRequest, "Unexpected response")
		}
		respData, err := s.handler.ProcessRequest(dataBytes)
		if err != nil {
			log.Printf("rpc.Server: Error processing RPC request: %v", err)
			return respData, err
		}
		log.Printf("rpc.Server: Successfully processed RPC request, response: %s", string(respData))
		return respData, nil
	}

	// Fallback to direct JSON/binary processing
	log.Printf("rpc.Server: Attempting direct JSON/binary processing: %s", string(data))
	return s.handler.ProcessRequest(data)
}

func unwrapRPCPayload(data []byte) []byte {
	var payload []byte
	if err := json.Unmarshal(data, &payload); err == nil {
		return payload
	}
	return data
}

// StartGarbageCollection starts a goroutine to periodically clean up expired queries and key-value entries.
func (s *Server) StartGarbageCollection() {
	go func() {
		ticker := time.NewTicker(time.Second * 5)
		defer ticker.Stop()
		for range ticker.C {
			s.queryManager.GC()
			s.store.GC()
		}
	}()
}
