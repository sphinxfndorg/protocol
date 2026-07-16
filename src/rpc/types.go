// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/rpc/types.go
package rpc

import (
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sphinxfndorg/protocol/src/core"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	security "github.com/sphinxfndorg/protocol/src/handshake"
)

// NodeID represents a unique 256-bit node identifier.
type NodeID [32]byte

// Codec provides binary encoding/decoding utilities.
type Codec struct{}

// RPCID represents a unique RPC request identifier.
type RPCID uint64

// GetRPCID generates a random non-zero RPCID.
func GetRPCID() RPCID {
	for {
		if v := rand.Uint64(); v != 0 {
			return RPCID(v)
		}
	}
}

// RPCType defines the type of RPC message.
type RPCType int8

// Remote represents a remote node's address and ID.
type Remote struct {
	NodeID  NodeID
	Address net.UDPAddr
}

// Message represents an RPC message for P2P communication.
type Message struct {
	RPCType   RPCType
	Query     bool
	TTL       uint16 // TTL in seconds
	Target    NodeID
	RPCID     RPCID
	From      Remote
	Nodes     []Remote
	Values    [][]byte
	Iteration uint8
	Secret    uint16
}

// Metrics holds RPC-related Prometheus metrics.
type Metrics struct {
	RequestCount     *prometheus.CounterVec
	RequestLatency   *prometheus.HistogramVec
	ErrorCount       *prometheus.CounterVec
	SyncProgress     *prometheus.GaugeVec
	ConsensusLatency *prometheus.HistogramVec
	MempoolEvictions *prometheus.CounterVec
}

// Server processes RPC requests.
type Server struct {
	messageCh      chan *security.Message
	metrics        *Metrics
	blockchain     *core.Blockchain
	handler        *JSONRPCHandler
	queryManager   *QueryManager
	store          *KVStore
	sphincsManager *sign.STHINCSManager // Added

	// RPC hardening: authentication and timeouts
	authConfig     *AuthConfig
	requestTimeout time.Duration
	maxRequestSize int
	pagination     *PaginationConfig
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	EnableAuth   bool
	APIKeys      map[string]string // API key -> node ID mapping
	RequireAuth  bool
	TrustedNodes map[string]bool // Trusted node IDs that bypass auth
}

// DefaultAuthConfig returns secure defaults for RPC authentication
// NOTE: RequireAuth is false by default so that node-to-node RPC (checkpoint sync,
// block download, etc.) works out of the box. For external API security, set
// RequireAuth=true and configure APIKeys.
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		EnableAuth:   true,
		APIKeys:      make(map[string]string),
		RequireAuth:  false, // Allow peer-to-peer RPC without API keys by default
		TrustedNodes: make(map[string]bool),
	}
}

// PaginationConfig holds pagination configuration
type PaginationConfig struct {
	DefaultPageSize int
	MaxPageSize     int
}

// DefaultPaginationConfig returns sensible defaults for pagination
func DefaultPaginationConfig() *PaginationConfig {
	return &PaginationConfig{
		DefaultPageSize: 100,
		MaxPageSize:     1000,
	}
}

// JSONRPCRequest represents a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	ID      interface{} `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

// RPCError represents a JSON-RPC error object.
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// RPCHandler defines a function type for handling RPC methods.
type RPCHandler func(params interface{}) (interface{}, error)

// JSONRPCHandler manages JSON-RPC request processing.
type JSONRPCHandler struct {
	server  *Server
	methods map[string]RPCHandler
}

// requestStatus tracks the status of a request to a node.
type requestStatus struct {
	Timeout   bool
	Responded bool
}

// Query represents an ongoing query session.
type Query struct {
	onCompletion func()
	pending      int
	start        time.Time
	RPCID        RPCID
	Target       NodeID
	Requested    map[NodeID]*requestStatus
}

// join tracks join requests.
type join struct {
	start time.Time
}

// ping tracks ping requests.
type ping struct {
	start     time.Time
	requested map[NodeID]struct{}
}

// get tracks get requests.
type get struct {
	start time.Time
}

// QueryManager manages ongoing queries.
type QueryManager struct {
	findNode map[RPCID]*Query
	join     map[RPCID]*join
	ping     map[RPCID]*ping
	get      map[RPCID]*get
}

const (
	// expiredInterval defines the expiration time for queries.
	expiredInterval = 10 * time.Second
)

// checksum holds a 256-bit BLAKE3 digest packed as four uint64 values.
// Using a struct (instead of [32]byte) makes it directly usable as a map key
// and avoids repeated array copies on comparison.
type checksum struct {
	v1, v2, v3, v4 uint64
}

// Key is the DHT key type used to index stored records.
type Key [32]byte

// stored holds the values and metadata associated with a single DHT key.
type stored struct {
	values   [][]byte              // Deduplicated list of values
	included map[checksum]struct{} // Set of checksums already stored (for O(1) dedup)
	ttl      time.Time             // Expiry time for this record
}

// KVStore is a thread-safe, in-memory key-value store with TTL-based expiry
// and content-addressed deduplication backed by BLAKE3.
type KVStore struct {
	mu   sync.Mutex
	data map[Key]*stored
}
