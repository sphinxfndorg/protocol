// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/shutdown.go
package bind

import (
	"fmt"

	logger "github.com/sphinxfndorg/protocol/src/console"
)

// Shutdown gracefully shuts down all server components in the given NodeResources.
// Shutdown stops all servers and closes resources.
func Shutdown(resources []NodeResources) error {
	var errs []error
	for _, res := range resources {
		if res.P2PServer != nil {
			if err := res.P2PServer.Close(); err != nil {
				logger.Error("Failed to close P2P server: %v", err)
				errs = append(errs, err)
			}
			if err := res.P2PServer.CloseDB(); err != nil {
				logger.Error("Failed to close P2P server DB: %v", err)
				errs = append(errs, err)
			}
		}
		if res.TCPServer != nil {
			if err := res.TCPServer.Stop(); err != nil {
				logger.Error("Failed to stop TCP server: %v", err)
				errs = append(errs, err)
			}
		}
		if res.HTTPServer != nil {
			if err := res.HTTPServer.Stop(); err != nil {
				logger.Error("Failed to stop HTTP server: %v", err)
				errs = append(errs, err)
			}
		}
		if res.WebSocketServer != nil {
			if err := res.WebSocketServer.Stop(); err != nil {
				logger.Error("Failed to stop WebSocket server: %v", err)
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errs)
	}
	return nil
}
