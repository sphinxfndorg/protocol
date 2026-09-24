// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/rpc/server.go

package rpc

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/core"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	"github.com/syndtr/goleveldb/leveldb"
)

// NewServer creates a new RPC server instance using the legacy process-relative
// artifact database path. Callers that have a node data directory should use
// NewServerWithArtifactPath so independent nodes do not contend for one
// process-relative LevelDB lock.
func NewServer(messageCh chan *security.Message, blockchain *core.Blockchain, sphincsManager *sign.STHINCSManager) *Server {
	return NewServerWithArtifactPath(messageCh, blockchain, sphincsManager, "")
}

// NewServerWithArtifactPath creates an RPC server whose persistent NFT artifact
// store is rooted at artifactPath. An empty path preserves the historical
// ./artifact-db behavior for callers that do not provide node storage.
func NewServerWithArtifactPath(messageCh chan *security.Message, blockchain *core.Blockchain, sphincsManager *sign.STHINCSManager, artifactPath string) *Server {
	metrics := NewMetrics()

	// Initialize persistent artifact storage (no TTL — artifacts are durable).
	artifactDB, err := initArtifactDB(artifactPath)
	if err != nil {
		log.Printf("rpc.Server: Failed to open artifact DB: %v — artifacts will use ephemeral store", err)
		artifactDB = nil
	}

	server := &Server{
		messageCh:      messageCh,
		metrics:        metrics,
		blockchain:     blockchain,
		queryManager:   NewQueryManager(),
		store:          NewKVStore(),
		sphincsManager: sphincsManager,
		artifactDB:     artifactDB,
		authConfig:     DefaultAuthConfig(),
		requestTimeout: 30 * time.Second,
		maxRequestSize: 1024 * 1024, // 1 MB
		pagination:     DefaultPaginationConfig(),
		gcStopCh:       make(chan struct{}),
	}
	server.handler = NewJSONRPCHandler(server)
	// Start garbage collection always (it runs in a separate goroutine)
	server.StartGarbageCollection()
	if messageCh != nil {
		go server.handleMessages()
	}
	return server
}

// Artifact databases are shared per path within a process. A single global
// handle is incorrect for multiple node servers in one process, while opening
// the same path repeatedly would hit LevelDB's exclusive lock. The map keeps
// both properties: independent node paths are independent databases, and a
// repeated server for one path reuses its existing handle.
var (
	artifactDBMu     sync.Mutex
	artifactDBByPath = make(map[string]*leveldb.DB)
	artifactDBErr    = make(map[string]error)
)

// initArtifactDB opens (creating if needed) the LevelDB backing store for NFT
// artifacts. An empty path retains the historical ./artifact-db location.
func initArtifactDB(artifactPath string) (*leveldb.DB, error) {
	if artifactPath == "" {
		artifactPath = filepath.Join(".", "artifact-db")
	}
	artifactPath = filepath.Clean(artifactPath)

	artifactDBMu.Lock()
	defer artifactDBMu.Unlock()
	if db, ok := artifactDBByPath[artifactPath]; ok {
		return db, artifactDBErr[artifactPath]
	}
	if err, ok := artifactDBErr[artifactPath]; ok {
		return nil, err
	}

	if err := os.MkdirAll(artifactPath, 0755); err != nil {
		err = fmt.Errorf("create artifact db directory %s: %w", artifactPath, err)
		artifactDBErr[artifactPath] = err
		return nil, err
	}
	db, err := leveldb.OpenFile(artifactPath, nil)
	if err != nil {
		err = fmt.Errorf("open artifact db at %s: %w", artifactPath, err)
		artifactDBErr[artifactPath] = err
		return nil, err
	}
	artifactDBByPath[artifactPath] = db
	return db, nil
}

// Close releases resources held by the server.
//
// Artifact database handles are shared per resolved path for the lifetime of
// the process. This keeps independent node paths independent while allowing an
// in-process restart to reuse its existing handle. The OS releases the handle
// and lock when the process exits; it is safe to call Close multiple times.
func (s *Server) Close() {
	s.artifactDB = nil
}

// SetTxRelay wires the outbound transaction gossip relay used by
// sendrawtransaction. StartNode calls it with the P2P consensus manager's
// BroadcastMessage so wallet-submitted transactions reach every validator's
// mempool. Must be called during node startup, before the transport listener
// begins serving RPC traffic.
func (s *Server) SetTxRelay(relay func(tx *types.Transaction)) {
	s.txRelay = relay
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
		for {
			select {
			case <-ticker.C:
				s.queryManager.GC()
				s.store.GC()
			case <-s.gcStopCh:
				return
			}
		}
	}()
}

// StopGarbageCollection releases the server's background cleanup worker.
func (s *Server) StopGarbageCollection() {
	s.gcStopOnce.Do(func() { close(s.gcStopCh) })
}
