// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/websocket.go
package bind

import (
	"sync"

	security "github.com/sphinxfndorg/protocol/src/handshake"
	logger "github.com/sphinxfndorg/protocol/src/log"
	"github.com/sphinxfndorg/protocol/src/rpc"
	"github.com/sphinxfndorg/protocol/src/transport"
)

// startWebSocketServer starts a WebSocket server for the given node.
func startWebSocketServer(name, port string, messageCh chan *security.Message, rpcServer *rpc.Server, readyCh chan struct{}, wg *sync.WaitGroup) {
	wsServer := transport.NewWebSocketServer(port, messageCh, rpcServer)
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("Starting WebSocket server for %s on %s", name, port)
		if err := wsServer.Start(readyCh); err != nil {
			logger.Errorf("WebSocket server failed for %s: %v", name, err)
			return
		}
		logger.Infof("WebSocket server for %s successfully started", name)
	}()
}
