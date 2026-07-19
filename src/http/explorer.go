// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/http/explorer.go — Block Explorer API

package http

import (
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sphinxfndorg/protocol/src/core"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// registerExplorerRoutes adds all block explorer API endpoints to the Gin router.
func (s *Server) registerExplorerRoutes(r *gin.RouterGroup) {
	explorer := r.Group("/explorer")
	{
		explorer.GET("/stats", s.handleExplorerStats)
		explorer.GET("/blocks", s.handleExplorerBlocks)
		explorer.GET("/block/:height", s.handleExplorerBlockByHeight)
		explorer.GET("/block/hash/:hash", s.handleExplorerBlockByHash)
		explorer.GET("/tx/:txid", s.handleExplorerTransaction)
		explorer.GET("/address/:address", s.handleExplorerAddress)
		explorer.GET("/search", s.handleExplorerSearch)
		explorer.GET("/mempool", s.handleExplorerMempool)
		explorer.GET("/wallets", s.handleExplorerWallets)
		explorer.GET("/validators", s.handleExplorerValidators)
		explorer.GET("/validators/map", s.handleExplorerValidatorMap)
		explorer.GET("/validators/:id", s.handleExplorerValidatorDetail)
	}
}

// ============================================================================
// Handler: Dashboard Stats
// ============================================================================

func (s *Server) handleExplorerStats(c *gin.Context) {
	bc := s.blockchain
	if bc == nil {
		c.JSON(http.StatusOK, gin.H{"error": "blockchain not initialized"})
		return
	}

	chainTip := bc.GetChainTip()
	blockCount := bc.GetBlockCount()
	stats := bc.GetStats()
	tpsStats := bc.GetTPSStats()
	mempoolInfo := bc.GetMemPoolInfo()
	chainInfo := bc.GetChainInfo()

	// Get wallet stats
	walletStats := gin.H{
		"total_accounts":       0,
		"spif_addresses":       0,
		"legacy_addresses":     0,
		"active_wallets":       0,
		"wallets_with_balance": 0,
	}
	stateDB, err := bc.NewStateDB()
	if err == nil {
		if sdb, ok := stateDB.(*core.StateDB); ok {
			if ws, err := sdb.GetWalletStats(10); err == nil {
				walletStats = gin.H{
					"total_accounts":       ws.TotalAccounts,
					"spif_addresses":       ws.SPIFAddresses,
					"legacy_addresses":     ws.LegacyAddresses,
					"active_wallets":       ws.ActiveWallets,
					"wallets_with_balance": ws.WalletsWithBalance,
					"total_supply_nspx":    ws.TotalSupplyNSPX,
					"total_supply_spx":     ws.TotalSupplySPX,
				}
			}
		}
		stateDB.Close()
	}

	// Get validator count
	validators := bc.GetExplorerValidators()
	validatorStats := gin.H{
		"total_validators":  0,
		"active_validators": 0,
	}
	if validators != nil {
		validatorStats = gin.H{
			"total_validators":  validators.TotalValidators,
			"active_validators": validators.ActiveValidators,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"chain":            chainInfo,
		"tip":              chainTip,
		"block_count":      blockCount,
		"stats":            stats,
		"tps":              tpsStats,
		"mempool":          mempoolInfo,
		"wallets":          walletStats,
		"validators":       validatorStats,
		"current_time":     time.Now().Unix(),
		"current_time_iso": time.Now().UTC().Format(time.RFC3339),
	})
}

// ============================================================================
// Handler: Blocks List (paginated)
// ============================================================================

func (s *Server) handleExplorerBlocks(c *gin.Context) {
	bc := s.blockchain
	if bc == nil {
		c.JSON(http.StatusOK, gin.H{"error": "blockchain not initialized", "blocks": []interface{}{}})
		return
	}

	pageStr := c.DefaultQuery("page", "1")
	limitStr := c.DefaultQuery("limit", "25")

	page, err := strconv.ParseUint(pageStr, 10, 64)
	if err != nil || page < 1 {
		page = 1
	}
	limit, err := strconv.ParseUint(limitStr, 10, 64)
	if err != nil || limit < 1 || limit > 100 {
		limit = 25
	}

	blockCount := bc.GetBlockCount()
	if blockCount == 0 {
		c.JSON(http.StatusOK, gin.H{"blocks": []interface{}{}, "total": 0, "page": page, "limit": limit})
		return
	}

	totalPages := (blockCount + limit - 1) / limit
	if page > totalPages {
		page = totalPages
	}

	startHeight := blockCount - (page-1)*limit
	endHeight := uint64(0)
	if startHeight > limit {
		endHeight = startHeight - limit
	} else {
		endHeight = 0
	}

	blocks := make([]gin.H, 0)
	for h := startHeight; h > endHeight; h-- {
		block := bc.GetBlockByNumber(h - 1) // h-1 because height is 0-indexed
		if block == nil {
			continue
		}
		blocks = append(blocks, formatBlockSummary(block))
	}

	c.JSON(http.StatusOK, gin.H{
		"blocks":      blocks,
		"total":       blockCount,
		"page":        page,
		"limit":       limit,
		"total_pages": totalPages,
	})
}

// ============================================================================
// Handler: Block by Height
// ============================================================================

func (s *Server) handleExplorerBlockByHeight(c *gin.Context) {
	bc := s.blockchain
	if bc == nil {
		c.JSON(http.StatusOK, gin.H{"error": "blockchain not initialized"})
		return
	}

	heightStr := c.Param("height")
	height, err := strconv.ParseUint(heightStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid block height"})
		return
	}

	block := bc.GetBlockByNumber(height)
	if block == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "block not found", "height": height})
		return
	}

	c.JSON(http.StatusOK, formatBlockDetail(block))
}

// ============================================================================
// Handler: Block by Hash
// ============================================================================

func (s *Server) handleExplorerBlockByHash(c *gin.Context) {
	bc := s.blockchain
	if bc == nil {
		c.JSON(http.StatusOK, gin.H{"error": "blockchain not initialized"})
		return
	}

	hash := c.Param("hash")
	if hash == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing block hash"})
		return
	}

	// Try to get block by hash through the blockchain
	block := bc.GetBlockByHash(hash)
	if block == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "block not found", "hash": hash})
		return
	}

	// Convert to types.Block via helper
	if helper, ok := block.(*core.BlockHelper); ok {
		if underlying, ok := helper.GetUnderlyingBlock().(*types.Block); ok {
			c.JSON(http.StatusOK, formatBlockDetail(underlying))
			return
		}
	}

	c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse block"})
}

// ============================================================================
// Handler: Transaction Detail
// ============================================================================

func (s *Server) handleExplorerTransaction(c *gin.Context) {
	bc := s.blockchain
	if bc == nil {
		c.JSON(http.StatusOK, gin.H{"error": "blockchain not initialized"})
		return
	}

	txid := c.Param("txid")
	if txid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing transaction ID"})
		return
	}

	// Try to get from blockchain (confirmed)
	tx, err := bc.GetTransactionByIDString(txid)
	status := "success"
	blockHeight := uint64(0)

	if err != nil || tx == nil {
		// Check mempool (pending)
		mempool := bc.GetMempool()
		if mempool != nil {
			pendingTx, _ := mempool.GetTransaction(txid)
			if pendingTx != nil {
				status = "pending"
				tx = pendingTx
			} else {
				status = "failed"
				c.JSON(http.StatusOK, gin.H{
					"txid":   txid,
					"status": "failed",
					"error":  "transaction not found in blockchain or mempool",
				})
				return
			}
		} else {
			status = "failed"
			c.JSON(http.StatusOK, gin.H{
				"txid":   txid,
				"status": "failed",
				"error":  "transaction not found",
			})
			return
		}
	} else {
		// Find which block contains this transaction
		blockCount := bc.GetBlockCount()
		for h := blockCount; h > 0; h-- {
			block := bc.GetBlockByNumber(h - 1)
			if block == nil {
				continue
			}
			for _, btx := range block.Body.TxsList {
				if btx != nil && btx.ID == txid {
					blockHeight = block.GetHeight()
					break
				}
			}
			if blockHeight > 0 {
				break
			}
		}
	}

	// Build response
	amountSPX := "0"
	if tx.Amount != nil {
		amountSPX = new(big.Float).Quo(
			new(big.Float).SetInt(tx.Amount),
			new(big.Float).SetFloat64(1e18),
		).Text('f', 18)
	}

	gasFee := "0"
	if tx.GasPrice != nil && tx.GasLimit != nil {
		fee := new(big.Int).Mul(tx.GasPrice, tx.GasLimit)
		gasFee = new(big.Float).Quo(
			new(big.Float).SetInt(fee),
			new(big.Float).SetFloat64(1e18),
		).Text('f', 18)
	}

	response := gin.H{
		"txid":            tx.ID,
		"hash":            tx.Hash(),
		"status":          status,
		"sender":          tx.Sender,
		"receiver":        tx.Receiver,
		"amount_nspx":     tx.Amount.String(),
		"amount_spx":      amountSPX,
		"gas_limit":       tx.GasLimit.String(),
		"gas_price":       tx.GasPrice.String(),
		"gas_fee_spx":     gasFee,
		"nonce":           tx.Nonce,
		"timestamp":       tx.Timestamp,
		"timestamp_iso":   time.Unix(tx.Timestamp, 0).UTC().Format(time.RFC3339),
		"block_height":    blockHeight,
		"chain_id":        tx.ChainID,
		"is_system_tx":    tx.IsSystemTransaction(),
		"has_full_auth":   tx.HasFullAuthBundle(),
		"signature":       fmt.Sprintf("%x", tx.Signature),
		"public_key":      fmt.Sprintf("%x", tx.PublicKey),
		"signature_hash":  fmt.Sprintf("%x", tx.SignatureHash),
		"merkle_root":     fmt.Sprintf("%x", tx.MerkleRootHash),
		"commitment":      fmt.Sprintf("%x", tx.Commitment),
		"proof":           fmt.Sprintf("%x", tx.Proof),
		"has_return_data": len(tx.ReturnData) > 0,
		"return_data":     fmt.Sprintf("%x", tx.ReturnData),
	}

	if len(tx.Data) > 0 {
		response["data"] = fmt.Sprintf("%x", tx.Data)
	}

	c.JSON(http.StatusOK, response)
}

// ============================================================================
// Handler: Address Overview
// ============================================================================

func (s *Server) handleExplorerAddress(c *gin.Context) {
	bc := s.blockchain
	if bc == nil {
		c.JSON(http.StatusOK, gin.H{"error": "blockchain not initialized"})
		return
	}

	address := c.Param("address")
	if address == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing address"})
		return
	}

	// Normalize address
	normalized := normalizeAddress(address)

	stateDB, err := bc.NewStateDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to access state"})
		return
	}
	defer stateDB.Close()

	balance, err := stateDB.GetBalance(normalized)
	if err != nil {
		balance = big.NewInt(0)
	}

	nonce, err := stateDB.GetNonce(normalized)
	if err != nil {
		nonce = 0
	}

	balanceResult, err := stateDB.GetBalanceResult(normalized)
	if err != nil {
		balanceResult = nil
	}

	// Transaction history
	limitStr := c.DefaultQuery("limit", "25")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 100 {
		limit = 25
	}
	txs, err := stateDB.GetTransactionHistory(normalized, limit)
	if err != nil {
		txs = []*types.Transaction{}
	}

	// Format balance
	balanceSPX := "0"
	if balance != nil {
		balanceSPX = new(big.Float).Quo(
			new(big.Float).SetInt(balance),
			new(big.Float).SetFloat64(1e18),
		).Text('f', 18)
	}

	// Address type
	addrType := "Legacy"
	if len(normalized) == 64 {
		addrType = "SPIF"
	}

	// Format transactions
	txList := make([]gin.H, 0)
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		dir := "out"
		amount := "0"
		if tx.Amount != nil {
			amount = new(big.Float).Quo(
				new(big.Float).SetInt(tx.Amount),
				new(big.Float).SetFloat64(1e18),
			).Text('f', 18)
		}
		if tx.Receiver == normalized {
			dir = "in"
		}

		txStatus := "success"
		// Check if pending (from mempool)
		if bc.GetMempool() != nil && bc.GetMempool().HasTransaction(tx.ID) {
			_, err := bc.GetTransactionByIDString(tx.ID)
			if err != nil {
				txStatus = "pending"
			}
		}

		txList = append(txList, gin.H{
			"txid":       tx.ID,
			"direction":  dir,
			"amount_spx": amount,
			"timestamp":  tx.Timestamp,
			"age":        time.Since(time.Unix(tx.Timestamp, 0)).String(),
			"status":     txStatus,
			"sender":     tx.Sender,
			"receiver":   tx.Receiver,
		})
	}

	balances := gin.H{
		"confirmed": balanceSPX,
	}
	if balanceResult != nil {
		balances = gin.H{
			"confirmed": new(big.Float).Quo(
				new(big.Float).SetInt(balanceResult.Confirmed),
				new(big.Float).SetFloat64(1e18),
			).Text('f', 18),
			"pending": new(big.Float).Quo(
				new(big.Float).SetInt(balanceResult.Pending),
				new(big.Float).SetFloat64(1e18),
			).Text('f', 18),
			"unlocked": new(big.Float).Quo(
				new(big.Float).SetInt(balanceResult.Unlocked),
				new(big.Float).SetFloat64(1e18),
			).Text('f', 18),
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"address":           normalized,
		"address_type":      addrType,
		"balance_nspx":      balance.String(),
		"balance_spx":       balanceSPX,
		"nonce":             nonce,
		"is_valid":          bc.ValidateAddress(normalized),
		"transaction_count": len(txList),
		"transactions":      txList,
		"balances":          balances,
	})
}

// ============================================================================
// Handler: Search
// ============================================================================

func (s *Server) handleExplorerSearch(c *gin.Context) {
	bc := s.blockchain
	if bc == nil {
		c.JSON(http.StatusOK, gin.H{"error": "blockchain not initialized"})
		return
	}

	query := c.DefaultQuery("q", "")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing search query"})
		return
	}

	results := gin.H{
		"query":    query,
		"type":     "unknown",
		"matches":  []interface{}{},
		"redirect": "",
	}

	// Try block height (numeric)
	if height, err := strconv.ParseUint(query, 10, 64); err == nil {
		block := bc.GetBlockByNumber(height)
		if block != nil {
			results["type"] = "block_height"
			results["redirect"] = fmt.Sprintf("/block/%d", height)
			results["matches"] = append(results["matches"].([]interface{}), gin.H{
				"type":   "block",
				"height": height,
				"hash":   block.GetHash(),
			})
			c.JSON(http.StatusOK, results)
			return
		}
	}

	// Try block hash (64 hex chars)
	if len(query) == 64 {
		isHex := true
		for _, c := range query {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				isHex = false
				break
			}
		}
		if isHex {
			// Try as block hash
			block := bc.GetBlockByHash(query)
			if block != nil {
				if helper, ok := block.(*core.BlockHelper); ok {
					if underlying, ok := helper.GetUnderlyingBlock().(*types.Block); ok {
						results["type"] = "block_hash"
						results["redirect"] = fmt.Sprintf("/block/%d", underlying.GetHeight())
						results["matches"] = append(results["matches"].([]interface{}), gin.H{
							"type":   "block",
							"hash":   query,
							"height": underlying.GetHeight(),
						})
						c.JSON(http.StatusOK, results)
						return
					}
				}
			}

			// Try as transaction ID
			tx, err := bc.GetTransactionByIDString(query)
			if err == nil && tx != nil {
				results["type"] = "transaction"
				results["redirect"] = fmt.Sprintf("/tx/%s", query)
				results["matches"] = append(results["matches"].([]interface{}), gin.H{
					"type": "transaction",
					"txid": query,
				})
				c.JSON(http.StatusOK, results)
				return
			}
		}
	}

	// Try as address (40 or 64 hex chars)
	if len(query) == 40 || len(query) == 64 {
		isHex := true
		for _, c := range query {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				isHex = false
				break
			}
		}
		if isHex && bc.ValidateAddress(query) {
			results["type"] = "address"
			results["redirect"] = fmt.Sprintf("/address/%s", query)
			results["matches"] = append(results["matches"].([]interface{}), gin.H{
				"type":    "address",
				"address": query,
			})
			c.JSON(http.StatusOK, results)
			return
		}
	}

	// No matches found
	c.JSON(http.StatusOK, results)
}

// ============================================================================
// Handler: Mempool
// ============================================================================

func (s *Server) handleExplorerMempool(c *gin.Context) {
	bc := s.blockchain
	if bc == nil {
		c.JSON(http.StatusOK, gin.H{"error": "blockchain not initialized"})
		return
	}

	mempoolInfo := bc.GetMemPoolInfo()
	mempool := bc.GetMempool()

	pendingTxs := make([]gin.H, 0)
	if mempool != nil {
		for _, tx := range mempool.GetPendingTransactions() {
			if tx == nil {
				continue
			}
			amountSPX := "0"
			if tx.Amount != nil {
				amountSPX = new(big.Float).Quo(
					new(big.Float).SetInt(tx.Amount),
					new(big.Float).SetFloat64(1e18),
				).Text('f', 6)
			}
			pendingTxs = append(pendingTxs, gin.H{
				"txid":       tx.ID,
				"sender":     tx.Sender,
				"receiver":   tx.Receiver,
				"amount_spx": amountSPX,
				"nonce":      tx.Nonce,
				"timestamp":  tx.Timestamp,
				"age_sec":    time.Since(time.Unix(tx.Timestamp, 0)).Seconds(),
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"mempool":     mempoolInfo,
		"pending_txs": pendingTxs,
		"tx_count":    len(pendingTxs),
	})
}

// ============================================================================
// Handler: Wallets
// ============================================================================

func (s *Server) handleExplorerWallets(c *gin.Context) {
	bc := s.blockchain
	if bc == nil {
		c.JSON(http.StatusOK, gin.H{"error": "blockchain not initialized"})
		return
	}

	limitStr := c.DefaultQuery("limit", "50")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 100 {
		limit = 50
	}

	rawDB, err := bc.NewStateDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to access state"})
		return
	}
	defer rawDB.Close()

	sdb, ok := rawDB.(*core.StateDB)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid state DB type"})
		return
	}

	walletStats, err := sdb.GetWalletStats(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get wallet stats"})
		return
	}

	c.JSON(http.StatusOK, walletStats)
}

// ============================================================================
// Handler: Validators
// ============================================================================

func (s *Server) handleExplorerValidators(c *gin.Context) {
	bc := s.blockchain
	if bc == nil {
		c.JSON(http.StatusOK, gin.H{"error": "blockchain not initialized"})
		return
	}

	validators := bc.GetExplorerValidators()
	if validators == nil {
		c.JSON(http.StatusOK, gin.H{
			"total_validators":   0,
			"active_validators":  0,
			"slashed_validators": 0,
			"total_stake_spx":    "0",
			"min_stake_spx":      0,
			"validators":         []interface{}{},
		})
		return
	}

	c.JSON(http.StatusOK, validators)
}

// ============================================================================
// Handler: Validator Map (GeoIP)
// ============================================================================

func (s *Server) handleExplorerValidatorMap(c *gin.Context) {
	bc := s.blockchain
	if bc == nil {
		c.JSON(http.StatusOK, gin.H{"error": "blockchain not initialized"})
		return
	}

	validators := bc.GetExplorerValidators()
	if validators == nil {
		c.JSON(http.StatusOK, gin.H{
			"validators":        []interface{}{},
			"total_validators":  0,
			"active_validators": 0,
			"countries":         []string{},
		})
		return
	}

	// Build validator locations from their node IDs (IP-based)
	type validatorLocation struct {
		ID        string  `json:"id"`
		IP        string  `json:"ip"`
		Country   string  `json:"country"`
		City      string  `json:"city"`
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
		StakeSPX  string  `json:"stake_spx"`
		Status    string  `json:"status"`
	}

	locations := make([]validatorLocation, 0)
	countries := make(map[string]bool)
	countryOrder := make([]string, 0)

	for _, v := range validators.Validators {
		if v == nil {
			continue
		}

		// Extract IP from validator ID (format: "Node-IP:port")
		ip := extractIPFromNodeID(v.ID)
		country, city, lat, lng := resolveGeoLocation(ip)

		if !countries[country] {
			countries[country] = true
			countryOrder = append(countryOrder, country)
		}

		locations = append(locations, validatorLocation{
			ID:        v.ID,
			IP:        ip,
			Country:   country,
			City:      city,
			Latitude:  lat,
			Longitude: lng,
			StakeSPX:  v.StakeSPX,
			Status:    v.Status,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"validators":        locations,
		"total_validators":  validators.TotalValidators,
		"active_validators": validators.ActiveValidators,
		"countries":         countryOrder,
		"country_count":     len(countries),
	})
}

// ============================================================================
// Handler: Validator Detail
// ============================================================================

func (s *Server) handleExplorerValidatorDetail(c *gin.Context) {
	bc := s.blockchain
	if bc == nil {
		c.JSON(http.StatusOK, gin.H{"error": "blockchain not initialized"})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing validator ID"})
		return
	}

	validators := bc.GetExplorerValidators()
	if validators == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "validator not found"})
		return
	}

	for _, v := range validators.Validators {
		if v != nil && v.ID == id {
			// Get location info
			ip := extractIPFromNodeID(v.ID)
			country, city, lat, lng := resolveGeoLocation(ip)

			c.JSON(http.StatusOK, gin.H{
				"validator": v,
				"location": gin.H{
					"ip":        ip,
					"country":   country,
					"city":      city,
					"latitude":  lat,
					"longitude": lng,
				},
			})
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "validator not found", "id": id})
}

// ============================================================================
// Helper Functions
// ============================================================================

// formatBlockSummary returns a summary of a block for list views.
func formatBlockSummary(block *types.Block) gin.H {
	if block == nil {
		return gin.H{}
	}

	txCount := len(block.Body.TxsList)
	age := time.Since(time.Unix(block.Header.Timestamp, 0))

	return gin.H{
		"height":     block.GetHeight(),
		"hash":       block.GetHash(),
		"prev_hash":  block.GetPrevHash(),
		"timestamp":  block.Header.Timestamp,
		"age":        fmtDuration(age),
		"age_sec":    age.Seconds(),
		"tx_count":   txCount,
		"difficulty": block.Header.Difficulty.String(),
		"nonce":      block.Header.Nonce,
		"gas_used":   block.Header.GasUsed.String(),
		"gas_limit":  block.Header.GasLimit.String(),
		"proposer":   block.Header.ProposerID,
	}
}

// formatBlockDetail returns full block details for the detail view.
func formatBlockDetail(block *types.Block) gin.H {
	if block == nil {
		return gin.H{}
	}

	summary := formatBlockSummary(block)
	txList := make([]gin.H, 0)

	for _, tx := range block.Body.TxsList {
		if tx == nil {
			continue
		}
		amountSPX := "0"
		if tx.Amount != nil {
			amountSPX = new(big.Float).Quo(
				new(big.Float).SetInt(tx.Amount),
				new(big.Float).SetFloat64(1e18),
			).Text('f', 6)
		}
		txList = append(txList, gin.H{
			"txid":       tx.ID,
			"sender":     tx.Sender,
			"receiver":   tx.Receiver,
			"amount_spx": amountSPX,
			"nonce":      tx.Nonce,
			"timestamp":  tx.Timestamp,
		})
	}

	// Attestations
	attList := make([]gin.H, 0)
	for _, att := range block.Body.Attestations {
		if att == nil {
			continue
		}
		stakeSPX := "0"
		if att.Stake != nil {
			stakeSPX = new(big.Float).Quo(
				new(big.Float).SetInt(att.Stake),
				new(big.Float).SetFloat64(1e18),
			).Text('f', 2)
		}
		attList = append(attList, gin.H{
			"validator_id": att.ValidatorID,
			"block_hash":   att.BlockHash,
			"view":         att.View,
			"stake_spx":    stakeSPX,
		})
	}

	detail := gin.H{
		"header": gin.H{
			"version":       block.Header.Version,
			"height":        block.Header.Height,
			"timestamp":     block.Header.Timestamp,
			"timestamp_iso": time.Unix(block.Header.Timestamp, 0).UTC().Format(time.RFC3339),
			"parent_hash":   fmt.Sprintf("%x", block.Header.ParentHash),
			"hash":          block.GetHash(),
			"difficulty":    block.Header.Difficulty.String(),
			"nonce":         block.Header.Nonce,
			"txs_root":      fmt.Sprintf("%x", block.Header.TxsRoot),
			"state_root":    fmt.Sprintf("%x", block.Header.StateRoot),
			"gas_limit":     block.Header.GasLimit.String(),
			"gas_used":      block.Header.GasUsed.String(),
			"extra_data":    fmt.Sprintf("%x", block.Header.ExtraData),
			"miner":         fmt.Sprintf("%x", block.Header.Miner),
			"logs_bloom":    fmt.Sprintf("%x", block.Header.LogsBloom),
			"proposer":      block.Header.ProposerID,
			"commit_status": block.Header.CommitStatus,
			"sig_valid":     block.Header.SigValid,
			"chain_weight":  block.Header.ChainWeight.String(),
		},
		"tx_count":     len(txList),
		"transactions": txList,
		"attestations": attList,
		"att_count":    len(attList),
		"block_hash":   block.GetHash(),
		"block_height": block.GetHeight(),
	}

	// Merge summary fields
	for k, v := range summary {
		detail[k] = v
	}

	return detail
}

// normalizeAddress normalizes an SPIF or hex address.
func normalizeAddress(address string) string {
	// Remove SPIF prefix and spaces
	addr := strings.TrimPrefix(address, "SPIF ")
	addr = strings.TrimPrefix(addr, "spif ")
	addr = strings.ReplaceAll(addr, " ", "")
	addr = strings.ReplaceAll(addr, "-", "")
	addr = strings.ToLower(addr)
	return addr
}

// extractIPFromNodeID extracts IP from a node ID like "Node-127.0.0.1:30303"
func extractIPFromNodeID(nodeID string) string {
	// Format: Node-IP:port
	if strings.HasPrefix(nodeID, "Node-") {
		rest := strings.TrimPrefix(nodeID, "Node-")
		if idx := strings.LastIndex(rest, ":"); idx > 0 {
			return rest[:idx]
		}
		return rest
	}
	return nodeID
}

// resolveGeoLocation returns mock geographic data for a validator IP.
// In production, this would use a GeoIP database like MaxMind GeoLite2.
func resolveGeoLocation(ip string) (country string, city string, latitude float64, longitude float64) {
	// This is a static mock based on common IP patterns.
	// For production, integrate with a GeoIP service or database.
	if strings.HasPrefix(ip, "127.") || ip == "localhost" || ip == "" {
		return "Unknown", "Unknown", 0, 0
	}

	// Simple heuristic mapping for demo purposes
	// In production, use ip-api.com, ipinfo.io, or MaxMind GeoLite2
	parts := strings.Split(ip, ".")
	if len(parts) >= 2 {
		firstOctet, _ := strconv.Atoi(parts[0])
		switch {
		case firstOctet >= 1 && firstOctet <= 9:
			return "United States", "New York", 40.7128, -74.0060
		case firstOctet >= 10 && firstOctet <= 49:
			return "United States", "San Francisco", 37.7749, -122.4194
		case firstOctet >= 50 && firstOctet <= 79:
			return "United Kingdom", "London", 51.5074, -0.1278
		case firstOctet >= 80 && firstOctet <= 89:
			return "Germany", "Frankfurt", 50.1109, 8.6821
		case firstOctet >= 90 && firstOctet <= 99:
			return "India", "Mumbai", 19.0760, 72.8777
		case firstOctet >= 100 && firstOctet <= 109:
			return "Japan", "Tokyo", 35.6762, 139.6503
		case firstOctet >= 110 && firstOctet <= 119:
			return "Indonesia", "Jakarta", -6.2088, 106.8456
		case firstOctet >= 120 && firstOctet <= 129:
			return "Australia", "Sydney", -33.8688, 151.2093
		case firstOctet >= 130 && firstOctet <= 149:
			return "Singapore", "Singapore", 1.3521, 103.8198
		case firstOctet >= 150 && firstOctet <= 179:
			return "Brazil", "São Paulo", -23.5505, -46.6333
		case firstOctet >= 180 && firstOctet <= 189:
			return "South Korea", "Seoul", 37.5665, 126.9780
		case firstOctet >= 190 && firstOctet <= 199:
			return "Canada", "Toronto", 43.6532, -79.3832
		case firstOctet >= 200 && firstOctet <= 209:
			return "South Africa", "Cape Town", -33.9249, 18.4241
		case firstOctet >= 210 && firstOctet <= 219:
			return "China", "Shanghai", 31.2304, 121.4737
		case firstOctet >= 220 && firstOctet <= 229:
			return "Taiwan", "Taipei", 25.0330, 121.5654
		case firstOctet >= 230 && firstOctet <= 239:
			return "United Arab Emirates", "Dubai", 25.2048, 55.2708
		default:
			return "Unknown", "Unknown", 0, 0
		}
	}

	return "Unknown", "Unknown", 0, 0
}

// fmtDuration formats a duration to a human-readable string.
func fmtDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd %dh", int(d.Hours()/24), int(d.Hours())%24)
}
