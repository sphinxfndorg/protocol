// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/server/types.go
package server

import (
	"github.com/sphinxorg/protocol/src/http"
	"github.com/sphinxorg/protocol/src/network"
	"github.com/sphinxorg/protocol/src/p2p"
	"github.com/sphinxorg/protocol/src/transport"
)

// Server encapsulates TCP, WebSocket, HTTP, and P2P servers.
type Server struct {
	tcpServer  *transport.TCPServer
	wsServer   *transport.WebSocketServer
	httpServer *http.Server
	p2pServer  *p2p.Server
	readyCh    chan struct{}
	nodeConfig network.NodePortConfig
}
