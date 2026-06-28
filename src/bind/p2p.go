// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/p2p.go
package bind

import (
	"fmt"
	"sync"
	"time"

	logger "github.com/sphinxfndorg/protocol/src/log"
	"github.com/sphinxfndorg/protocol/src/p2p"
)

// startP2PServer starts a P2P server for the given node.
func startP2PServer(name string, server *p2p.Server, readyCh chan<- struct{}, errorCh chan<- error, udpReadyCh chan<- struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("Starting P2P server for %s on %s", name, server.LocalNode().Address)
		startCh := make(chan error, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("Panic in P2P server startup for %s: %v", name, r)
					startCh <- fmt.Errorf("panic: %v", r)
				}
			}()
			logger.Infof("Calling server.Start() for %s", name)
			err := server.Start()
			logger.Infof("server.Start() for %s returned with error: %v", name, err)
			startCh <- err
		}()
		select {
		case err := <-startCh:
			if err != nil {
				logger.Errorf("P2P server failed for %s: %v", name, err)
				// Attempt to close the server on failure
				if closeErr := server.Close(); closeErr != nil {
					logger.Errorf("Failed to close P2P server for %s: %v", name, closeErr)
				}
				if closeErr := server.CloseDB(); closeErr != nil {
					logger.Errorf("Failed to close DB for %s: %v", name, closeErr)
				}
				errorCh <- err
				return
			}
			logger.Infof("P2P server for %s started successfully", name)
			logger.Infof("Sending UDP ready signal for %s", name)
			udpReadyCh <- struct{}{} // Signal UDP listener is ready
			logger.Infof("Sending ready signal for P2P server %s", name)
			readyCh <- struct{}{}
		case <-time.After(10 * time.Second):
			logger.Warnf("P2P server for %s took too long to start, assuming ready", name)
			logger.Infof("Sending UDP ready signal for %s", name)
			udpReadyCh <- struct{}{}
			logger.Infof("Sending ready signal for P2P server %s", name)
			readyCh <- struct{}{}
		}
	}()
}
