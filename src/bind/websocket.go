// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/websocket.go
package bind

import (
	"sync"

	logger "github.com/sphinxfndorg/protocol/src/console"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	"github.com/sphinxfndorg/protocol/src/rpc"
	"github.com/sphinxfndorg/protocol/src/transport"
)

// startWebSocketServer starts a WebSocket server for the given node.
func startWebSocketServer(name, port string, messageCh chan *security.Message, rpcServer *rpc.Server, readyCh chan struct{}, wg *sync.WaitGroup) {
	wsServer := transport.NewWebSocketServer(port, messageCh, rpcServer)
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("Starting WebSocket server for %s on %s", name, port)
		if err := wsServer.Start(readyCh); err != nil {
			logger.Error("WebSocket server failed for %s: %v", name, err)
			return
		}
		logger.Info("WebSocket server for %s successfully started", name)
	}()
}
