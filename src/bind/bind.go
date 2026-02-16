// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/bind/bind.go
package bind

import (
	"fmt"
	"sync"

	logger "github.com/sphinxorg/protocol/src/log"
	"github.com/sphinxorg/protocol/src/transport"
)

// BindTCPServers binds TCP servers for the given node configurations.
func BindTCPServers(configs []NodeConfig, wg *sync.WaitGroup) error {
	for _, config := range configs {
		if config.Address == "" || config.Name == "" || config.MessageCh == nil || config.RPCServer == nil || config.ReadyCh == nil {
			logger.Errorf("Invalid configuration for %s: missing required fields", config.Name)
			return fmt.Errorf("invalid configuration for %s: missing required fields", config.Name)
		}

		// Create and start TCP server
		tcpServer := transport.NewTCPServer(config.Address, config.MessageCh, config.RPCServer, config.ReadyCh)
		wg.Add(1)
		go func(name, addr string, server *transport.TCPServer) {
			defer wg.Done()
			logger.Infof("Starting TCP server for %s on %s", name, addr)
			if err := server.Start(); err != nil {
				logger.Errorf("TCP server failed for %s: %v", name, err)
			} else {
				logger.Infof("TCP server for %s successfully started", name)
			}
		}(config.Name, config.Address, tcpServer)
	}
	return nil
}
