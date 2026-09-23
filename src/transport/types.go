// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/transport/types.go
package transport

import (
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	"github.com/sphinxfndorg/protocol/src/rpc"
)

type IPConfig struct {
	IP   string
	Port string
}

// TCPServer represents a TCP server for handling P2P connections
type TCPServer struct {
	listener    net.Listener
	address     string
	messageCh   chan *security.Message
	rpcServer   *rpc.Server
	handshake   *security.Handshake
	tcpReadyCh  chan struct{}
	connections map[string]net.Conn                // Map of node address (e.g., 127.0.0.1:30307) to connection
	encKeys     map[string]*security.EncryptionKey // Map of node address to encryption key
	mu          sync.Mutex

	// stopped is set by Stop before the listener is closed, and consulted by
	// the accept loop. Without it, closing the listener makes Accept return
	// "use of closed network connection" immediately and forever, so the loop
	// spun at 100% CPU logging the same error — a hot loop that was latent only
	// because nothing used to call Stop on this server.
	stopped atomic.Bool
}

// WebSocketServer manages WebSocket connections.
type WebSocketServer struct {
	address   string
	mux       *http.ServeMux
	server    *http.Server // Add server field to store http.Server
	upgrader  websocket.Upgrader
	messageCh chan *security.Message
	rpcServer *rpc.Server
	handshake *security.Handshake
}
