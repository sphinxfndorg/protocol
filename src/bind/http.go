// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/http.go
package bind

import (
	"sync"
	"time"

	"github.com/sphinxorg/protocol/src/core"
	security "github.com/sphinxorg/protocol/src/handshake"
	"github.com/sphinxorg/protocol/src/http"
	logger "github.com/sphinxorg/protocol/src/log"
)

// startHTTPServer starts an HTTP server for the given node.
func startHTTPServer(name, port string, messageCh chan *security.Message, blockchain *core.Blockchain, readyCh chan struct{}, wg *sync.WaitGroup) {
	httpServer := http.NewServer(port, messageCh, blockchain, readyCh)
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("Starting HTTP server for %s on %s", name, port)
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
				logger.Errorf("HTTP server failed for %s: %v", name, err)
				return
			}
		case <-time.After(2 * time.Second):
			logger.Infof("HTTP server for %s successfully started", name)
			logger.Infof("Sending ready signal for HTTP server %s", name)
			readyCh <- struct{}{}
		}
	}()
}
