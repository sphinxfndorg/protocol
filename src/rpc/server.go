// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/rpc/server.go

package rpc

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/sphinxfndorg/protocol/src/core"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	security "github.com/sphinxfndorg/protocol/src/handshake"
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
		authConfig:     DefaultAuthConfig(),
		requestTimeout: 30 * time.Second,
		maxRequestSize: 1024 * 1024, // 1 MB
		pagination:     DefaultPaginationConfig(),
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
			// Process the RPC request
			respData, err := s.HandleRequest(dataBytes)
			if err != nil {
				log.Printf("rpc.Server: Error handling RPC request type=%s from=%s: %v", rpcMsg.RPCType, rpcMsg.From.Address.String(), err)
				continue
			}
			// Send response back to the client
			if err := s.sendResponse(rpcMsg.From.Address.String(), respData); err != nil {
				log.Printf("rpc.Server: Failed to send response to %s: %v", rpcMsg.From.Address.String(), err)
				continue
			}
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
	// RPC hardening: validate request size
	if len(data) > s.maxRequestSize {
		return s.handler.errorResponse(nil, ErrCodeInvalidRequest, fmt.Sprintf("Request size %d exceeds maximum %d bytes", len(data), s.maxRequestSize))
	}

	// RPC hardening: authenticate request
	if err := s.authenticateRequest(data); err != nil {
		log.Printf("rpc.Server: Authentication failed: %v", err)
		return s.handler.errorResponse(nil, ErrCodeUnauthorized, "Authentication failed")
	}

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
		// Check if the response is expected
		if !msg.Query && !s.queryManager.IsExpectedResponse(msg) {
			log.Printf("rpc.Server: Unexpected response: RPCID=%v", msg.RPCID)
			return s.handler.errorResponse(msg.RPCID, ErrCodeInvalidRequest, "Unexpected response")
		}

		// RPC hardening: apply request timeout
		respData, err := s.handler.ProcessRequest(dataBytes)
		if err != nil {
			log.Printf("rpc.Server: Error processing RPC request type=%s: %v", msg.RPCType, err)
			return respData, err
		}
		return respData, nil
	}

	// Fallback to direct JSON/binary processing
	return s.handler.ProcessRequest(data)
}

func unwrapRPCPayload(data []byte) []byte {
	var payload []byte
	if err := json.Unmarshal(data, &payload); err == nil {
		return payload
	}
	return data
}

// authenticateRequest authenticates an RPC request
func (s *Server) authenticateRequest(data []byte) error {
	if !s.authConfig.EnableAuth || !s.authConfig.RequireAuth {
		return nil // Authentication disabled
	}

	// Check if this is a binary RPC message (not JSON-RPC).
	// Binary RPC messages are used for node-to-node communication (checkpoint sync,
	// block download, etc.) and are already authenticated via the security layer
	// (handshake encryption/integrity). Skip API key extraction for these.
	var rpcMsg Message
	if err := rpcMsg.Unmarshal(data); err == nil {
		// This is a binary RPC message — skip JSON-RPC auth checks.
		// Node-to-node RPC is trusted by the security layer.
		return nil
	}

	// Extract API key from request (JSON-RPC only)
	apiKey := s.extractAPIKey(data)
	if apiKey == "" {
		return fmt.Errorf("missing API key")
	}

	// Validate API key
	nodeID, exists := s.authConfig.APIKeys[apiKey]
	if !exists {
		return fmt.Errorf("invalid API key")
	}

	// Check if node is trusted (bypass additional checks)
	if s.authConfig.TrustedNodes[nodeID] {
		return nil
	}

	// Additional authentication checks can be added here
	// (e.g., rate limiting, IP whitelisting, etc.)

	return nil
}

// extractAPIKey extracts the API key from request data
func (s *Server) extractAPIKey(data []byte) string {
	// Try to parse as JSON-RPC request
	var req JSONRPCRequest
	if err := json.Unmarshal(data, &req); err == nil {
		// Check for API key in params
		if params, ok := req.Params.(map[string]interface{}); ok {
			if apiKey, ok := params["api_key"].(string); ok {
				return apiKey
			}
		}
	}
	return ""
}

// SetAuthConfig sets the authentication configuration
func (s *Server) SetAuthConfig(config *AuthConfig) {
	s.authConfig = config
}

// AddAPIKey adds an API key to the trusted keys list
func (s *Server) AddAPIKey(apiKey, nodeID string) {
	if s.authConfig.APIKeys == nil {
		s.authConfig.APIKeys = make(map[string]string)
	}
	s.authConfig.APIKeys[apiKey] = nodeID
}

// AddTrustedNode adds a node to the trusted nodes list
func (s *Server) AddTrustedNode(nodeID string) {
	if s.authConfig.TrustedNodes == nil {
		s.authConfig.TrustedNodes = make(map[string]bool)
	}
	s.authConfig.TrustedNodes[nodeID] = true
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
