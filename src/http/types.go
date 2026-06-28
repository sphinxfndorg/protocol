// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/http/types.go
package http

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/sphinxfndorg/protocol/src/core"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	security "github.com/sphinxfndorg/protocol/src/handshake"
)

// Server represents an HTTP server.
type Server struct {
	address         string
	router          *gin.Engine
	messageCh       chan *security.Message
	blockchain      *core.Blockchain
	httpServer      *http.Server
	lastTxMutex     sync.RWMutex
	lastTransaction *types.Transaction
	readyCh         chan struct{}
}
