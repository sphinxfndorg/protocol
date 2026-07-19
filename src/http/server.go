// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/http/server.go

package http

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sphinxfndorg/protocol/src/core"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	security "github.com/sphinxfndorg/protocol/src/handshake"
)

func NewServer(address string, messageCh chan *security.Message, blockchain *core.Blockchain, readyCh chan struct{}) *Server {
	r := gin.Default()
	s := &Server{
		address:    address,
		router:     r,
		messageCh:  messageCh,
		blockchain: blockchain,
		httpServer: &http.Server{
			Addr:    address,
			Handler: r,
		},
		readyCh: readyCh,
	}
	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	// Register explorer API routes
	apiGroup := s.router.Group("/api/v1")
	s.registerExplorerRoutes(apiGroup)

	// Serve explorer static files from the built dist directory
	s.router.Static("/explorer", "./src/explorer/dist")

	// For the root path, redirect to /explorer/
	s.router.GET("/explorer", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/explorer/")
	})

	// Client-side routing catch-all: for any non-API, non-static request
	// under /explorer/, serve the SPA's index.html so that client-side
	// routes like /explorer/block/123 work on page refresh.
	s.router.NoRoute(func(c *gin.Context) {
		// Only intercept /explorer/* paths for SPA routing
		if len(c.Request.URL.Path) >= 9 && c.Request.URL.Path[:9] == "/explorer" {
			c.File("./src/explorer/dist/index.html")
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
	})

	s.router.GET("/", func(c *gin.Context) {
		s.lastTxMutex.RLock()
		lastTx := s.lastTransaction
		s.lastTxMutex.RUnlock()

		var lastTxResp interface{}
		if lastTx != nil {
			lastTxResp = gin.H{
				"sender":    lastTx.Sender,
				"receiver":  lastTx.Receiver,
				"amount":    lastTx.Amount.String(),
				"nonce":     lastTx.Nonce,
				"timestamp": lastTx.Timestamp,
			}
		} else {
			lastTxResp = "No transactions yet"
		}

		blocks := s.blockchain.GetBlocks()
		if len(blocks) == 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "no blocks in blockchain"})
			return
		}
		genesisBlock := blocks[0]
		bestBlockHash := s.blockchain.GetBestBlockHash()
		blockCount := s.blockchain.GetBlockCount()

		c.JSON(http.StatusOK, gin.H{
			"message": "Welcome to the blockchain API",
			"blockchain_info": gin.H{
				"genesis_block_hash":   fmt.Sprintf("%x", genesisBlock.GenerateBlockHash()),
				"genesis_block_height": genesisBlock.Header.Block,
				"best_block_hash":      fmt.Sprintf("%x", bestBlockHash),
				"block_count":          blockCount,
			},
			"last_transaction": lastTxResp,
			"available_endpoints": []string{
				"/transaction (POST)",
				"/block/:id (GET)",
				"/bestblockhash (GET)",
				"/blockcount (GET)",
				"/metrics (GET)",
				"/latest-transaction (GET)",
			},
		})
	})

	s.router.POST("/transaction", s.handleTransaction)
	s.router.GET("/block/:id", s.handleGetBlock)
	s.router.GET("/bestblockhash", s.handleGetBestBlockHash)
	s.router.GET("/blockcount", s.handleGetBlockCount)
	s.router.GET("/metrics", gin.WrapH(promhttp.Handler()))
	s.router.GET("/latest-transaction", func(c *gin.Context) {
		s.lastTxMutex.RLock()
		defer s.lastTxMutex.RUnlock()
		if s.lastTransaction == nil {
			c.JSON(http.StatusOK, gin.H{"message": "No transactions yet"})
			return
		}
		c.JSON(http.StatusOK, s.lastTransaction)
	})
}

func (s *Server) handleTransaction(c *gin.Context) {
	var tx types.Transaction
	if err := c.ShouldBindJSON(&tx); err != nil {
		log.Printf("Transaction binding error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid transaction format: %v", err)})
		return
	}
	if err := s.blockchain.AddTransaction(&tx); err != nil {
		log.Printf("Transaction add error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("failed to add transaction: %v", err)})
		return
	}

	log.Printf("Received transaction: Sender=%s, Receiver=%s, Amount=%s, Nonce=%d",
		tx.Sender, tx.Receiver, tx.Amount.String(), tx.Nonce)

	// Marshal transaction to JSON before sending
	txData, err := json.Marshal(&tx)
	if err != nil {
		log.Printf("Failed to marshal transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process transaction"})
		return
	}

	s.messageCh <- &security.Message{
		Type: "transaction",
		Data: txData, // Use marshaled bytes
	}

	s.lastTxMutex.Lock()
	s.lastTransaction = &tx
	s.lastTxMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{"status": "Transaction submitted"})
}

func (s *Server) handleGetBlock(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid block ID"})
		return
	}
	blocks := s.blockchain.GetBlocks()
	for _, block := range blocks {
		if block.Header.Block == id {
			c.JSON(http.StatusOK, block)
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "block not found"})
}

func (s *Server) handleGetBestBlockHash(c *gin.Context) {
	hash := s.blockchain.GetBestBlockHash()
	c.JSON(http.StatusOK, gin.H{"hash": fmt.Sprintf("%x", hash)})
}

func (s *Server) handleGetBlockCount(c *gin.Context) {
	count := s.blockchain.GetBlockCount()
	c.JSON(http.StatusOK, gin.H{"count": count})
}

func (s *Server) Start() error {
	log.Printf("Starting HTTP server on %s", s.address)
	go func() {
		if s.readyCh != nil {
			s.readyCh <- struct{}{}
			log.Printf("Sent HTTP ready signal for %s", s.address)
		}
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error on %s: %v", s.address, err)
		}
	}()
	return nil
}

func (s *Server) Stop() error {
	if s.httpServer == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown HTTP server on %s: %v", s.address, err)
	}
	log.Printf("HTTP server on %s stopped", s.address)
	return nil
}
