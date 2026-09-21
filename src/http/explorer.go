// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/http/explorer.go — Block Explorer API

package http

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/core"
	"github.com/sphinxfndorg/protocol/src/core/rawdb"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
	"github.com/sphinxfndorg/protocol/src/policy"
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
		explorer.GET("/holders/growth", s.handleExplorerHolderGrowth)
		explorer.GET("/wallets", s.handleExplorerWallets)
		explorer.GET("/validators", s.handleExplorerValidators)
		explorer.GET("/validators/map", s.handleExplorerValidatorMap)
		explorer.GET("/validators/:id", s.handleExplorerValidatorDetail)
	}
}

// handleExplorerHolderGrowth returns the growth of addresses first observed in
// canonical blocks. It intentionally does not accept client-side "registration"
// events: a wallet created offline is private and must not affect public metrics
// until it appears in a finalized block.
func (s *Server) handleExplorerHolderGrowth(c *gin.Context) {
	bc := s.blockchain
	if bc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "blockchain not initialized"})
		return
	}

	days, err := strconv.Atoi(c.DefaultQuery("days", "30"))
	if err != nil || days < 1 || days > 365 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "days must be between 1 and 365"})
		return
	}

	// Blocks are the durable event log. Rebuilding this small aggregate keeps it
	// correct after restart and avoids maintaining mutable explorer-only state.
	cutoff := time.Now().UTC().AddDate(0, 0, -(days - 1)).Truncate(24 * time.Hour)
	seen := make(map[string]struct{})
	var holdersBeforeCutoff uint64
	type dayStat struct{ holders, newHolders uint64 }
	byDay := make(map[string]*dayStat)

	for height := uint64(0); height < bc.GetBlockCount(); height++ {
		block := bc.GetBlockByNumber(height)
		if block == nil || block.Header == nil {
			continue
		}
		day := time.Unix(block.Header.Timestamp, 0).UTC().Truncate(24 * time.Hour)
		key := day.Format("2006-01-02")
		for _, tx := range block.Body.TxsList {
			if tx == nil {
				continue
			}
			for _, candidate := range []string{tx.Sender, tx.Receiver} {
				address, normalizeErr := common.NormalizeSPIFAddress(candidate)
				// The explorer's PQ holder metric excludes legacy 20-byte accounts.
				if normalizeErr != nil || len(address) != 64 {
					continue
				}
				if _, exists := seen[address]; exists {
					continue
				}
				seen[address] = struct{}{}
				if !day.Before(cutoff) {
					if byDay[key] == nil {
						byDay[key] = &dayStat{}
					}
					byDay[key].newHolders++
				}
			}
		}
		if !day.Before(cutoff) {
			if byDay[key] == nil {
				byDay[key] = &dayStat{}
			}
			byDay[key].holders = uint64(len(seen))
		} else {
			holdersBeforeCutoff = uint64(len(seen))
		}
	}

	points := make([]gin.H, 0, days)
	lastHolders := holdersBeforeCutoff
	for offset := days - 1; offset >= 0; offset-- {
		day := cutoff.AddDate(0, 0, days-1-offset)
		stat := byDay[day.Format("2006-01-02")]
		newHolders := uint64(0)
		if stat != nil {
			newHolders = stat.newHolders
			if stat.holders > 0 {
				lastHolders = stat.holders
			}
		}
		points = append(points, gin.H{
			"date":        day.Format("2006-01-02"),
			"holders":     lastHolders,
			"new_holders": newHolders,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"metric": "on_chain_spif_addresses_first_observed",
		"note":   "Offline address generation is not observable. An address is counted when it first appears in a canonical block.",
		"days":   days,
		"points": points,
	})
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

	// burnStats is the supply/burn panel the dashboard reads. It is populated
	// only when state is readable; the shape is defined up front so clients can
	// bind to the keys unconditionally instead of guarding every access.
	burnStats := gin.H{
		"address":           common.DefaultBurnAddress,
		"burned_nspx":       "0",
		"burned_spx":        "0",
		"circulating_nspx":  "0",
		"circulating_spx":   "0",
		"total_supply_nspx": "0",
		"total_supply_spx":  "0",
		"max_supply_spx":    core.GetMaxSupplySPX().String(),
		"max_supply_nspx":   core.GetMaxSupplyNSPX().String(),
		"burn_percent":      0.0,
	}

	stateDB, err := bc.NewStateDB()
	if err == nil {
		if sdb, ok := stateDB.(*core.StateDB); ok {
			var ws *core.WalletStats
			if w, err := sdb.GetWalletStats(10); err == nil {
				ws = w
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

			// Burn accounting: read the canonical DEAD address balance, which
			// is the single auditable source of burned supply (fee burns +
			// block-reward burns + manual user burns). Circulating = total - burned.
			burnedNSPX, err := sdb.GetBalance(common.CanonicalAddress(common.DefaultBurnAddress))
			if err != nil || burnedNSPX == nil {
				burnedNSPX = big.NewInt(0)
			}
			totalSupplyNSPX := sdb.GetTotalSupply()
			if totalSupplyNSPX == nil {
				totalSupplyNSPX = big.NewInt(0)
			}
			circulatingNSPX := new(big.Int).Sub(totalSupplyNSPX, burnedNSPX)
			if circulatingNSPX.Sign() < 0 {
				circulatingNSPX = big.NewInt(0)
			}

			burnPercent := 0.0
			if totalSupplyNSPX.Sign() > 0 {
				ratio, _ := new(big.Float).Quo(
					new(big.Float).SetInt(burnedNSPX),
					new(big.Float).SetInt(totalSupplyNSPX),
				).Float64()
				burnPercent = ratio * 100
			}

			walletStats["burned_nspx"] = burnedNSPX.String()
			walletStats["burned_spx"] = nspxToSPXString(burnedNSPX)
			walletStats["circulating_nspx"] = circulatingNSPX.String()
			walletStats["circulating_spx"] = nspxToSPXString(circulatingNSPX)

			burnStats["burned_nspx"] = burnedNSPX.String()
			burnStats["burned_spx"] = nspxToSPXString(burnedNSPX)
			burnStats["circulating_nspx"] = circulatingNSPX.String()
			burnStats["circulating_spx"] = nspxToSPXString(circulatingNSPX)
			burnStats["total_supply_nspx"] = totalSupplyNSPX.String()
			burnStats["total_supply_spx"] = nspxToSPXString(totalSupplyNSPX)
			burnStats["burn_percent"] = burnPercent
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
		// Burn accounting — DEAD address balance is the single auditable burn
		// total across fee burns, block-reward burns, and manual user burns.
		// The full panel (burned / circulating / supply cap) is emitted so the
		// explorer never has to derive supply figures client-side.
		"burn": burnStats,
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
		summary := formatBlockSummary(bc, block)
		// Confirmation depth is chain-relative: the formatter only sees one
		// block, so the list handler stamps it from the chain tip.
		summary["confirmations"] = confirmationsForHeight(blockCount, block.GetHeight())
		blocks = append(blocks, summary)
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

	detail := formatBlockDetail(bc, block)
	stampBlockConfirmations(detail, bc.GetBlockCount())
	c.JSON(http.StatusOK, detail)
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
			detail := formatBlockDetail(bc, underlying)
			stampBlockConfirmations(detail, bc.GetBlockCount())
			c.JSON(http.StatusOK, detail)
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
	blockHash := ""
	haveBlockRef := false

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
		// Resolve the committing block through the tx-lookup index (O(1) when
		// present) rather than walking every block on the chain. GetTxBlockInfo
		// falls back to a full scan for chains that predate the index, so
		// un-migrated nodes keep working. When neither path resolves the block,
		// the response reports no block reference — and therefore no
		// confirmations — instead of inventing genesis as the container.
		if hash, height, cerr := bc.GetTxConfirmation(txid); cerr == nil {
			blockHash = hash
			blockHeight = height
			haveBlockRef = true
		}
	}

	// Confirmations are counted from the chain tip down to the committing block;
	// pending (mempool) transactions have none yet.
	confirmations := uint64(0)
	if status == "success" && haveBlockRef {
		confirmations = confirmationsForHeight(bc.GetBlockCount(), blockHeight)
	}

	// Build response
	amountSPX := nspxToSPXString(tx.Amount)
	fee := txFeeNSPX(tx)
	gasFee := nspxToSPXString(fee)
	burned := txBurnNSPX(bc, tx)

	response := gin.H{
		"txid":          tx.ID,
		"hash":          tx.Hash(),
		"status":        status,
		"sender":        tx.Sender,
		"receiver":      tx.Receiver,
		"amount_nspx":   bigIntString(tx.Amount),
		"amount_spx":    amountSPX,
		"gas_limit":     bigIntString(tx.GasLimit),
		"gas_price":     bigIntString(tx.GasPrice),
		"gas_used":      txReceiptGasUsed(bc, tx.ID, tx),
		"gas_fee_spx":   gasFee,
		"fee_nspx":      bigIntString(fee),
		"burned_this_tx_nspx": burned.String(),
		"burned_this_tx_spx":  nspxToSPXString(burned),
		"nonce":         tx.Nonce,
		"timestamp":     tx.Timestamp,
		"timestamp_iso": time.Unix(tx.Timestamp, 0).UTC().Format(time.RFC3339),
		"age":           fmtDuration(time.Since(time.Unix(tx.Timestamp, 0))),
		"age_sec":       time.Since(time.Unix(tx.Timestamp, 0)).Seconds(),
		// Confirmation provenance: which block committed this transaction and
		// how deep it now is. Clients render "included in block N" and the
		// confirmation count straight from these fields.
		"block_height":    blockHeight,
		"block_hash":      blockHash,
		"confirmations":   confirmations,
		"chain_id":        tx.ChainID,
		"is_system_tx":    tx.IsSystemTransaction(),
		"has_full_auth":   tx.HasFullAuthBundle(),
		"to_contract":     tx.ToContract,
		"is_contract_tx":  tx.HasContractPayload(),
		"signature":       fmt.Sprintf("%x", tx.Signature),
		"public_key":      fmt.Sprintf("%x", tx.PublicKey),
		"signature_hash":  fmt.Sprintf("%x", tx.SignatureHash),
		"merkle_root":     fmt.Sprintf("%x", tx.MerkleRootHash),
		"commitment":      fmt.Sprintf("%x", tx.Commitment),
		"proof":           fmt.Sprintf("%x", tx.Proof),
		"has_return_data": len(tx.ReturnData) > 0,
		"return_data":     fmt.Sprintf("%x", tx.ReturnData),
	}
	if len(tx.ReturnData) > 0 {
		response["return_data_text"] = decodeReturnData(tx.ReturnData)
		response["return_data_kind"] = returnDataKind(tx.ReturnData)
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

	// Reject malformed addresses before they reach state lookups. This avoids
	// ambiguous explorer results and keeps the address representation canonical.
	normalized, err := common.NormalizeSPIFAddress(address)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid " + common.SPIFPrefix + " address"})
		return
	}

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
	balanceSPX := nspxToSPXString(balance)

	// Address type
	addrType := "Legacy"
	if len(normalized) == 64 {
		addrType = common.SPIFPrefix
	}

	// Format transactions
	blockCount := bc.GetBlockCount()
	txList := make([]gin.H, 0)
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		dir := "out"
		amount := nspxToSPXString(tx.Amount)
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

		// Per-row block provenance. An address history that lists amounts but
		// not the committing block (or its depth) cannot answer the first
		// question anyone asks of it: "is this confirmed?".
		txBlockHash := ""
		txBlockHeight := uint64(0)
		txConfirmations := uint64(0)
		if txStatus == "success" {
			if hash, height, cerr := bc.GetTxConfirmation(tx.ID); cerr == nil {
				txBlockHash, txBlockHeight = hash, height
				txConfirmations = confirmationsForHeight(blockCount, height)
			}
		}

		txList = append(txList, gin.H{
			"txid":          tx.ID,
			"direction":     dir,
			"amount_spx":    amount,
			"amount_nspx":   bigIntString(tx.Amount),
			"fee_spx":       nspxToSPXString(txFeeNSPX(tx)),
			"fee_nspx":      bigIntString(txFeeNSPX(tx)),
			"nonce":         tx.Nonce,
			"timestamp":     tx.Timestamp,
			"age":           fmtDuration(time.Since(time.Unix(tx.Timestamp, 0))),
			"status":        txStatus,
			"sender":        tx.Sender,
			"receiver":      tx.Receiver,
			"block_height":  txBlockHeight,
			"block_hash":    txBlockHash,
			"confirmations": txConfirmations,
		})
	}

	balances := gin.H{
		"confirmed": balanceSPX,
	}
	if balanceResult != nil {
		balances = gin.H{
			"confirmed": nspxToSPXString(balanceResult.Confirmed),
			"pending":   nspxToSPXString(balanceResult.Pending),
			"unlocked":  nspxToSPXString(balanceResult.Unlocked),
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

// nSPXPerSPX is the canonical denomination multiplier (denom.SPX = 1e18), i.e.
// the number of nSPX in one whole SPX. Sourced from the protocol constants so a
// future denomination change cannot silently desync the explorer's figures from
// consensus accounting.
var nSPXPerSPX = big.NewInt(int64(denom.SPX))

// nspxToSPXString renders an nSPX amount as a fixed-precision SPX string.
// Returns "0" for nil/zero so callers can emit the field unconditionally.
func nspxToSPXString(amount *big.Int) string {
	if amount == nil || amount.Sign() == 0 {
		return "0"
	}
	return new(big.Float).Quo(
		new(big.Float).SetInt(amount),
		new(big.Float).SetInt(nSPXPerSPX),
	).Text('f', 18)
}

func txFeeNSPX(tx *types.Transaction) *big.Int {
	if tx == nil {
		return nil
	}
	return tx.GetGasFee()
}

// txBurnNSPX returns the deterministic protocol-burn slice of a transaction's
// gas fee in nSPX: floor(gasFee * BurnFeeBPS / 10000) per the fee-allocation
// schedule the executor applies (see executor.applyTransactions). A manual
// transfer whose receiver is the DEAD burn address burns the full amount on
// top of any fee burn. Returns zero (never nil) so API payloads can emit the
// burn fields unconditionally.
func txBurnNSPX(bc *core.Blockchain, tx *types.Transaction) *big.Int {
	burned := big.NewInt(0)
	if tx == nil {
		return burned
	}
	if bc != nil {
		fee := txFeeNSPX(tx)
		if fee != nil && fee.Sign() > 0 {
			if dist := bc.ActivePolicy().DistributeFees(fee); dist != nil && dist.Burned != nil {
				burned.Add(burned, dist.Burned)
			}
		}
	}
	if tx.Amount != nil && tx.Amount.Sign() > 0 && common.IsBurnAddress(tx.Receiver) {
		burned.Add(burned, tx.Amount)
	}
	return burned
}

// txGasUsed quotes the deterministic gas units charged for a transaction from
// the policy schedule (base + per-ReturnData-byte). Receipts store the same
// number at write time (rawdb.WriteReceipts), but the explorer serves this
// computed fallback as well so blocks whose receipts predate receipt writes —
// or whose receipt is simply missing — still show gas instead of zero.
func txGasUsed(bc *core.Blockchain, tx *types.Transaction) uint64 {
	if tx == nil {
		return 0
	}
	pol := policy.GetDefaultPolicyParams()
	if bc != nil {
		pol = bc.ActivePolicy()
	}
	if pol == nil {
		return 0
	}
	return pol.QuoteTransactionGas(uint64(len(tx.ReturnData))).GasLimit.Uint64()
}

// txReceiptGasUsed returns the stored per-transaction gas from the receipt
// index when present (the write-time figure rawdb.WriteReceipts computed),
// falling back to the deterministic policy quote otherwise.
func txReceiptGasUsed(bc *core.Blockchain, txID string, tx *types.Transaction) uint64 {
	if bc != nil {
		if st := bc.GetStorage(); st != nil {
			if db, err := st.GetDB(); err == nil && db != nil {
				if rcpt, err := rawdb.ReadReceipt(db, txID); err == nil && rcpt != nil {
					return rcpt.GasUsed
				}
			}
		}
	}
	return txGasUsed(bc, tx)
}

// decodeReturnData renders OP_RETURN bytes for the explorer: printable ASCII
// (memos, anchor JSON, vault seeds) as text, anything else as hex. Mirrors the
// canonical Transaction.GetReturnDataAsString so the API and storage agree.
func decodeReturnData(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	for _, b := range data {
		if b < 32 || b > 126 {
			return hex.EncodeToString(data)
		}
	}
	return string(data)
}

// returnDataKind classifies OP_RETURN content so the UI can label it: a mint
// anchor tag, some other JSON payload, or a plain-text memo.
func returnDataKind(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if core.IsMintAnchor(data) {
		return "mint_anchor"
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}' {
		var js map[string]any
		if json.Unmarshal(trimmed, &js) == nil {
			return "json"
		}
	}
	return "memo"
}

// blockBurnTotals reads this block's burn accounting from its atomic-commit
// journal (tx_<hashprefix>.json): how much nSPX the block burned, and what the
// DEAD-address total was before the block ran. Journals are written for every
// committed block and kept for diagnostics, so historical blocks keep their
// totals. Returns empty strings when no journal exists for the block.
func blockBurnTotals(blockHash string) (burnedThis, burnedBefore string) {
	jm := core.GetJournalManager()
	if jm == nil {
		return "", ""
	}
	dir := jm.JournalDir()
	if dir == "" || len(blockHash) < 16 {
		return "", ""
	}
	raw, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("tx_%s.json", blockHash[:16])))
	if err != nil {
		return "", ""
	}
	var journal struct {
		BurnedThisBlockNSPX string `json:"burned_this_block_nspx"`
		BurnedBeforeNSPX    string `json:"burned_before_nspx"`
	}
	if err := json.Unmarshal(raw, &journal); err != nil {
		return "", ""
	}
	return journal.BurnedThisBlockNSPX, journal.BurnedBeforeNSPX
}

// blockRewardSplit returns this block's policy block-reward total and its
// deterministic miner/burned split. Genesis (height 0) funds the vault rather
// than minting a proposer reward, so it reports zeros.
func blockRewardSplit(bc *core.Blockchain, height uint64) (total, miner, burned *big.Int) {
	zero := big.NewInt(0)
	if bc == nil || height == 0 {
		return zero, big.NewInt(0), big.NewInt(0)
	}
	total = bc.PolicyBlockReward()
	if total == nil {
		total = big.NewInt(0)
	}
	split := bc.ActivePolicy().SplitBlockReward(total)
	if split == nil {
		return total, big.NewInt(0), big.NewInt(0)
	}
	return split.Total, split.Miner, split.Burned
}

// confirmationsForHeight returns how many blocks confirm the block at the given
// zero-indexed height: the block itself plus every descendant, i.e.
// blockCount - height. blockCount is the total number of blocks on the chain
// (heights 0..blockCount-1), so genesis on a 5-block chain reports 5.
func confirmationsForHeight(blockCount, height uint64) uint64 {
	if blockCount == 0 || height >= blockCount {
		return 0
	}
	return blockCount - height
}

// stampBlockConfirmations writes the confirmation count into a block payload
// and, when present, into each transaction row it contains. Block payloads have
// no access to chain height (the formatters only see one block), so the count
// is applied by the handlers that already know the chain tip.
func stampBlockConfirmations(detail gin.H, blockCount uint64) {
	if detail == nil {
		return
	}
	height, ok := detail["height"].(uint64)
	if !ok {
		if h, ok := detail["block_height"].(uint64); ok {
			height = h
		} else {
			return
		}
	}
	confirmations := confirmationsForHeight(blockCount, height)
	detail["confirmations"] = confirmations

	txs, ok := detail["transactions"].([]gin.H)
	if !ok {
		return
	}
	for _, row := range txs {
		row["block_height"] = height
		row["confirmations"] = confirmations
	}
}

// formatBlockSummary returns a summary of a block for list views.
func formatBlockSummary(bc *core.Blockchain, block *types.Block) gin.H {
	if block == nil {
		return gin.H{}
	}

	txCount := len(block.Body.TxsList)
	age := time.Since(time.Unix(block.Header.Timestamp, 0))

	// Every hash is emitted as hex and every optional *big.Int is nil-checked:
	// a block loaded from disk may carry a zero-value header, and the explorer
	// must render a partial block rather than panic on it.
	hash := block.GetHash()
	burnedThis, burnedBefore := blockBurnTotals(hash)
	rewardTotal, rewardMiner, rewardBurned := blockRewardSplit(bc, block.GetHeight())
	summary := gin.H{
		"height":     block.GetHeight(),
		"hash":       hash,
		"prev_hash":  block.GetPrevHash(),
		"timestamp":  block.Header.Timestamp,
		"age":        fmtDuration(age),
		"age_sec":    age.Seconds(),
		"tx_count":   txCount,
		"difficulty": bigIntString(block.Header.Difficulty),
		"nonce":      block.Header.Nonce,
		"gas_used":   bigIntString(block.Header.GasUsed),
		"gas_limit":  bigIntString(block.Header.GasLimit),
		"proposer":   block.Header.ProposerID,
		"version":    block.Header.Version,
		// Merkle commitments and the previous-block link are what make a block
		// independently auditable, so they are in the list payload too — not
		// only in the detail payload.
		"txs_root":          fmt.Sprintf("%x", block.Header.TxsRoot),
		"state_root":        fmt.Sprintf("%x", block.Header.StateRoot),
		"uncles_hash":       fmt.Sprintf("%x", block.Header.UnclesHash),
		"commit_status":     block.Header.CommitStatus,
		"sig_valid":         block.Header.SigValid,
		"chain_weight":      bigIntString(block.Header.ChainWeight),
		"attestation_count": len(block.Body.Attestations),
		// Burned coins live at the provably-unspendable DEAD address; the
		// journal totals below are the per-block auditable source for "how
		// many coins were burned in this block". Empty when no journal exists
		// for the block (e.g. genesis imports or pruned journal dirs).
		"burned_this_block_nspx": burnedThis,
		"burned_this_block_spx":  nspxToSPXString(parseNSPX(burnedThis)),
		"burned_before_nspx":     burnedBefore,
		// The coinbase reward is deterministic policy issuance (total split
		// into miner + burned slices), so a block card can show it without a
		// separate reward lookup.
		"block_reward_nspx":        bigIntString(rewardTotal),
		"block_reward_spx":         nspxToSPXString(rewardTotal),
		"block_reward_miner_nspx":  bigIntString(rewardMiner),
		"block_reward_burned_nspx": bigIntString(rewardBurned),
	}
	return summary
}

// formatBlockDetail returns full block details for the detail view.
func formatBlockDetail(bc *core.Blockchain, block *types.Block) gin.H {
	if block == nil {
		return gin.H{}
	}

	summary := formatBlockSummary(bc, block)
	txList := make([]gin.H, 0)

	for _, tx := range block.Body.TxsList {
		if tx == nil {
			continue
		}
		amountSPX := nspxToSPXString(tx.Amount)
		fee := txFeeNSPX(tx)
		burned := txBurnNSPX(bc, tx)
		txSummary := gin.H{
			"txid":           tx.ID,
			"sender":         tx.Sender,
			"receiver":       tx.Receiver,
			"amount_spx":     amountSPX,
			"amount_nspx":    bigIntString(tx.Amount),
			"nonce":          tx.Nonce,
			"timestamp":      tx.Timestamp,
			"timestamp_iso":  time.Unix(tx.Timestamp, 0).UTC().Format(time.RFC3339),
			"is_system_tx":   tx.IsSystemTransaction(),
			"has_full_auth":  tx.HasFullAuthBundle(),
			"gas_limit":      bigIntString(tx.GasLimit),
			"gas_price":      bigIntString(tx.GasPrice),
			"gas_used":       txReceiptGasUsed(bc, tx.ID, tx),
			"fee_spx":        nspxToSPXString(fee),
			"fee_nspx":       bigIntString(fee),
			"burned_this_tx_nspx": burned.String(),
			"burned_this_tx_spx":  nspxToSPXString(burned),
			"to_contract":    tx.ToContract,
			"is_contract_tx": tx.HasContractPayload(),
		}
		// ReturnData is where mint anchors live: core.ValidateAnchorData
		// parses the AnchorTag out of it, and its CID field is the only
		// on-chain record of what a mint pinned. The per-transaction endpoint
		// (handleExplorerTransaction) already exposes it as hex with a
		// has_return_data flag; this mirrors that convention so a caller can
		// inspect a whole block without an extra request per transaction.
		//
		// Without this, answering a question like "how many anchors recorded a
		// local-only (spxhash-) CID?" required an O(blocks + txs) walk, because
		// block detail listed txids but not the payload that classifies them.
		//
		// Empty payloads are omitted rather than emitted as "": most
		// transactions carry no ReturnData, and a per-block list would
		// otherwise fill with empty keys. has_return_data is always present so
		// an absent return_data is unambiguous.
		txSummary["has_return_data"] = len(tx.ReturnData) > 0
		if len(tx.ReturnData) > 0 {
			txSummary["return_data"] = fmt.Sprintf("%x", tx.ReturnData)
			txSummary["return_data_text"] = decodeReturnData(tx.ReturnData)
			txSummary["return_data_kind"] = returnDataKind(tx.ReturnData)
		}
		txList = append(txList, txSummary)
	}

	// Attestations
	attList := make([]gin.H, 0)
	for _, att := range block.Body.Attestations {
		if att == nil {
			continue
		}
		stakeSPX := nspxToSPXString(att.Stake)
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
			"difficulty":    bigIntString(block.Header.Difficulty),
			"nonce":         block.Header.Nonce,
			"txs_root":      fmt.Sprintf("%x", block.Header.TxsRoot),
			"state_root":    fmt.Sprintf("%x", block.Header.StateRoot),
			"uncles_hash":   fmt.Sprintf("%x", block.Header.UnclesHash),
			"gas_limit":     bigIntString(block.Header.GasLimit),
			"gas_used":      bigIntString(block.Header.GasUsed),
			"extra_data":    fmt.Sprintf("%x", block.Header.ExtraData),
			"miner":         fmt.Sprintf("%x", block.Header.Miner),
			"logs_bloom":    fmt.Sprintf("%x", block.Header.LogsBloom),
			"proposer":      block.Header.ProposerID,
			"sig_valid":     block.Header.SigValid,
			"commit_status": block.Header.CommitStatus,
			"chain_weight":  bigIntString(block.Header.ChainWeight),
			"age":           summary["age"],
			"age_sec":       summary["age_sec"],
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

// parseNSPX parses a decimal nSPX string, returning zero on empty/garbage so
// display conversions never fail on a missing journal total.
func parseNSPX(s string) *big.Int {
	if s == "" {
		return big.NewInt(0)
	}
	if v, ok := new(big.Int).SetString(s, 10); ok {
		return v
	}
	return big.NewInt(0)
}

func bigIntString(value *big.Int) string {
	if value == nil {
		return "0"
	}
	return value.String()
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
