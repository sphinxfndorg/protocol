// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/http.go
package bind

import (
	"sync"
	"time"

	logger "github.com/sphinxfndorg/protocol/src/console"
	"github.com/sphinxfndorg/protocol/src/core"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	"github.com/sphinxfndorg/protocol/src/http"
)

// startHTTPServer starts an HTTP server for the given node.
func startHTTPServer(name, port string, messageCh chan *security.Message, blockchain *core.Blockchain, readyCh chan struct{}, wg *sync.WaitGroup) {
	httpServer := http.NewServer(port, messageCh, blockchain, readyCh)
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("Starting HTTP server for %s on %s", name, port)
		startCh := make(chan error, 1)
		go func() {
			if err := httpServer.Start(); err != nil {
				startCh <- err
			} else {
				startCh <- nil
			}
		}()
		select {
		case err := <-startCh:
			if err != nil {
				logger.Error("HTTP server failed for %s: %v", name, err)
				return
			}
		case <-time.After(2 * time.Second):
			logger.Info("HTTP server for %s successfully started", name)
			logger.Info("Sending ready signal for HTTP server %s", name)
			readyCh <- struct{}{}
		}
	}()
}
