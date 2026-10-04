// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/listen_addr.go
package core

import (
	"net"
	"strconv"
)

// SetListenAddr records the P2P address this process bound (bind.StartNode).
// It adds the runtime fact that params/commit DefaultPort cannot express.
func (bc *Blockchain) SetListenAddr(addr string) {
	if bc == nil {
		return
	}
	bc.listenAddrMu.Lock()
	bc.listenAddr = addr
	bc.listenAddrMu.Unlock()
}

// GetListenAddr returns the bound P2P address, or "" if none was registered.
func (bc *Blockchain) GetListenAddr() string {
	if bc == nil {
		return ""
	}
	bc.listenAddrMu.RLock()
	defer bc.listenAddrMu.RUnlock()
	return bc.listenAddr
}

// GetListenPort returns the port of the bound address, or 0 so callers omit the field.
func (bc *Blockchain) GetListenPort() int {
	_, portStr, err := net.SplitHostPort(bc.GetListenAddr())
	if err != nil || portStr == "" {
		return 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}
