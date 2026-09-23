// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/rpc/json.go
package rpc

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/contracts"
	"github.com/sphinxfndorg/protocol/src/core"
	state "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	security "github.com/sphinxfndorg/protocol/src/handshake"
)

// NewJSONRPCHandler creates a new JSON-RPC handler with registered methods.
func NewJSONRPCHandler(server *Server) *JSONRPCHandler {
	handler := &JSONRPCHandler{
		server:  server,
		methods: make(map[string]RPCHandler),
	}
	handler.registerMethods() // Register all supported RPC methods
	return handler
}

// getBlockByNumber retrieves a block by its height (number)
func (h *JSONRPCHandler) getBlockByNumber(params interface{}) (interface{}, error) {
	var paramsArray []interface{}
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing block number parameter")
	}

	height, ok := paramsArray[0].(float64)
	if !ok {
		return nil, errors.New("invalid block number parameter")
	}

	block := h.server.blockchain.GetBlockByNumber(uint64(height))
	if block == nil {
		return nil, errors.New("block not found")
	}
	return block, nil
}

// getBlockHeader returns ONLY the header of a single block — never the body.
func (h *JSONRPCHandler) getBlockHeader(params interface{}) (interface{}, error) {
	if h.server.blockchain == nil {
		return nil, errors.New("blockchain not initialized")
	}

	getConcrete := func(b consensus.Block) (*types.Block, error) {
		if b == nil {
			return nil, errors.New("block not found")
		}
		underlying, ok := b.GetUnderlyingBlock().(*types.Block)
		if !ok {
			return nil, errors.New("block not found")
		}
		return underlying, nil
	}
	getTip := func() (*types.Block, error) {
		return getConcrete(h.server.blockchain.GetLatestBlock())
	}

	var raw *types.Block
	var blkError error

	switch {
	case params == nil:
		raw, blkError = getTip()
	default:
		var paramsArray []interface{}
		if err := h.parseParams(params, &paramsArray); err != nil {
			return nil, err
		}
		switch {
		case len(paramsArray) == 0:
			raw, blkError = getTip()
		default:
			switch v := paramsArray[0].(type) {
			case float64:
				if v < 0 {
					raw, blkError = getTip()
				} else {
					raw = h.server.blockchain.GetBlockByNumber(uint64(v))
					blkError = nil
				}
			case string:
				if v == "" || v == "latest" {
					raw, blkError = getTip()
				} else {
					raw, blkError = getConcrete(h.server.blockchain.GetBlockByHash(v))
				}
			default:
				return nil, errors.New("invalid block header parameter")
			}
		}
	}

	if blkError != nil {
		return nil, blkError
	}
	if raw == nil || raw.Header == nil {
		return nil, errors.New("block header unavailable")
	}

	return raw.Header, nil
}

// getHeaders returns up to `count` block headers starting at `start_height`.
func (h *JSONRPCHandler) getHeaders(params interface{}) (interface{}, error) {
	if h.server.blockchain == nil {
		return nil, errors.New("blockchain not initialized")
	}

	start := uint64(0)
	count := 100
	if params != nil {
		var paramsArray []interface{}
		if err := h.parseParams(params, &paramsArray); err != nil {
			return nil, err
		}
		if len(paramsArray) > 0 {
			if v, ok := paramsArray[0].(float64); ok && v >= 0 {
				start = uint64(v)
			}
		}
		if len(paramsArray) > 1 {
			if v, ok := paramsArray[1].(float64); ok && v > 0 {
				count = int(v)
			}
		}
	}

	tipBlock := h.server.blockchain.GetLatestBlock()
	if tipBlock == nil {
		return []*types.BlockHeader{}, nil
	}

	headers := make([]*types.BlockHeader, 0, count)
	for height := start; height <= tipBlock.GetHeight() && len(headers) < count; height++ {
		blk := h.server.blockchain.GetBlockByNumber(height)
		if blk == nil || blk.Header == nil {
			continue
		}
		headers = append(headers, blk.Header)
	}
	return headers, nil
}

// getBlockHash returns the hash of a block at a given height
func (h *JSONRPCHandler) getBlockHash(params interface{}) (interface{}, error) {
	var paramsArray []interface{}
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing block height parameter")
	}

	height, ok := paramsArray[0].(float64)
	if !ok {
		return nil, errors.New("invalid block height parameter")
	}

	hash := h.server.blockchain.GetBlockHash(uint64(height))
	if hash == "" {
		return nil, errors.New("block not found")
	}
	return hash, nil
}

// getSupplyStatus returns detailed supply information.
func (h *JSONRPCHandler) getSupplyStatus(params interface{}) (interface{}, error) {
	if h.server.blockchain == nil {
		return nil, errors.New("blockchain not initialized")
	}
	return h.server.blockchain.GetSupplyStatus()
}

// getDifficulty returns the current network difficulty as a string
func (h *JSONRPCHandler) getDifficulty(_ interface{}) (interface{}, error) {
	return h.server.blockchain.GetDifficulty().String(), nil
}

// getChainTip returns information about the current chain tip (latest block)
func (h *JSONRPCHandler) getChainTip(_ interface{}) (interface{}, error) {
	return h.server.blockchain.GetChainTip(), nil
}

// getNetworkInfo returns network-related statistics and configuration
func (h *JSONRPCHandler) getNetworkInfo(_ interface{}) (interface{}, error) {
	return h.server.blockchain.GetNetworkInfo(), nil
}

// getMiningInfo returns mining-related statistics
func (h *JSONRPCHandler) getMiningInfo(_ interface{}) (interface{}, error) {
	return h.server.blockchain.GetMiningInfo(), nil
}

// estimateFee estimates the transaction fee per byte.
func (h *JSONRPCHandler) estimateFee(params interface{}) (interface{}, error) {
	var paramsArray []interface{}
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}

	blocks := 6
	if len(paramsArray) > 0 {
		if blocksParam, ok := paramsArray[0].(float64); ok {
			blocks = int(blocksParam)
		}
	}

	return h.server.blockchain.EstimateFee(blocks), nil
}

// getMemPoolInfo returns statistics about the memory pool
func (h *JSONRPCHandler) getMemPoolInfo(_ interface{}) (interface{}, error) {
	return h.server.blockchain.GetMemPoolInfo(), nil
}

// validateAddress checks if a given address is valid.
func (h *JSONRPCHandler) validateAddress(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing address parameter")
	}

	isValid := h.server.blockchain.ValidateAddress(paramsArray[0])
	return map[string]interface{}{
		"isvalid": isValid,
		"address": paramsArray[0],
	}, nil
}

// verifyMessage verifies a cryptographic signature for a message and address
func (h *JSONRPCHandler) verifyMessage(params interface{}) (interface{}, error) {
	var paramsStruct struct {
		Address   string `json:"address"`
		Signature string `json:"signature"`
		Message   string `json:"message"`
	}
	if err := h.parseParams(params, &paramsStruct); err != nil {
		return nil, err
	}

	isValid := h.server.blockchain.VerifyMessage(
		paramsStruct.Address,
		paramsStruct.Signature,
		paramsStruct.Message,
	)

	return map[string]interface{}{
		"verified": isValid,
	}, nil
}

// getBalance returns the confirmed, pending, and unlocked balance for an address.
func (h *JSONRPCHandler) getBalance(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 || paramsArray[0] == "" {
		return nil, errors.New("missing address parameter")
	}
	address := paramsArray[0]

	stateDB, err := h.server.blockchain.NewStateDB()
	if err != nil {
		return nil, err
	}
	defer stateDB.Close()

	result, err := stateDB.GetBalanceResult(address)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"address":  address,
		"balance":  result.Confirmed.String(),
		"pending":  result.Pending.String(),
		"unlocked": result.Unlocked.String(),
	}, nil
}

// getTransactionHistory returns recent transactions involving the given address.
func (h *JSONRPCHandler) getTransactionHistory(params interface{}) (interface{}, error) {
	var paramsArray []interface{}
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing address parameter")
	}
	address, ok := paramsArray[0].(string)
	if !ok || address == "" {
		return nil, errors.New("invalid address parameter")
	}

	limit := 20
	if len(paramsArray) > 1 {
		if limitParam, ok := paramsArray[1].(float64); ok && limitParam > 0 {
			limit = int(limitParam)
		}
	}

	stateDB, err := h.server.blockchain.NewStateDB()
	if err != nil {
		return nil, err
	}

	return stateDB.GetTransactionHistory(address, limit)
}

// getRawTransaction returns raw transaction data.
func (h *JSONRPCHandler) getRawTransaction(params interface{}) (interface{}, error) {
	var paramsArray []interface{}
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing transaction ID parameter")
	}

	txID, ok := paramsArray[0].(string)
	if !ok {
		return nil, errors.New("invalid transaction ID parameter")
	}

	verbose := false
	if len(paramsArray) > 1 {
		if verboseParam, ok := paramsArray[1].(bool); ok {
			verbose = verboseParam
		}
	}

	result := h.server.blockchain.GetRawTransaction(txID, verbose)
	if result == nil {
		return nil, errors.New("transaction not found")
	}
	return result, nil
}

// getCheckpoint returns the current checkpoint information.
func (h *JSONRPCHandler) getCheckpoint(params interface{}) (interface{}, error) {
	if h.server.blockchain == nil {
		return nil, errors.New("blockchain not initialized")
	}

	cp, err := h.server.blockchain.GetCheckpointMessage()
	if err != nil {
		return nil, err
	}

	return cp, nil
}

// registerMethods registers all supported RPC methods with their handler functions
func (h *JSONRPCHandler) registerMethods() {
	h.methods["getblockcount"] = h.getBlockCount
	h.methods["getbestblockhash"] = h.getBestBlockHash
	h.methods["getblock"] = h.getBlock
	h.methods["getblocks"] = h.getBlocks
	h.methods["sendrawtransaction"] = h.sendRawTransaction
	h.methods["gettransaction"] = h.getTransaction
	h.methods["gettransactionreceipt"] = h.getTransactionReceipt
	h.methods["spx_getTransactionReceipt"] = h.getTransactionReceipt
	h.methods["sphinx_getTransactionReceipt"] = h.getTransactionReceipt
	h.methods["ping"] = h.ping
	h.methods["join"] = h.join
	h.methods["findnode"] = h.findNode
	h.methods["get"] = h.get
	h.methods["store"] = h.store

	h.methods["getblockbynumber"] = h.getBlockByNumber
	h.methods["getblockhash"] = h.getBlockHash
	h.methods["getdifficulty"] = h.getDifficulty
	h.methods["getchaintip"] = h.getChainTip
	h.methods["getnetworkinfo"] = h.getNetworkInfo
	h.methods["getmininginfo"] = h.getMiningInfo
	h.methods["estimatefee"] = h.estimateFee
	h.methods["getmempoolinfo"] = h.getMemPoolInfo
	h.methods["validateaddress"] = h.validateAddress
	h.methods["verifymessage"] = h.verifyMessage
	h.methods["getrawtransaction"] = h.getRawTransaction
	h.methods["getbalance"] = h.getBalance
	h.methods["gettransactionhistory"] = h.getTransactionHistory
	h.methods["getsupplystatus"] = h.getSupplyStatus
	h.methods["getcheckpoint"] = h.getCheckpoint

	h.methods["getblockheader"] = h.getBlockHeader
	h.methods["getheaders"] = h.getHeaders

	h.methods["storeartifact"] = h.storeArtifact
	h.methods["getartifact"] = h.getArtifact
	h.methods["getnonce"] = h.getNonce
	h.methods["getcontract"] = h.getContract
	h.methods["getcontractstorage"] = h.getContractStorage
	h.methods["callcontractreadonly"] = h.callContractReadOnly

	h.methods["deploycontract"] = h.deployContract
	h.methods["callcontract"] = h.callContract

	h.methods["gettransactionevents"] = h.getTransactionEvents

	// Read-only sync status for wallet/GUI clients (nil-provider-safe; see
	// syncstatus.go for the honesty rules and the provider wiring).
	h.methods["getsyncstatus"] = h.getSyncStatus
}

func (h *JSONRPCHandler) getContract(params interface{}) (interface{}, error) {
	var values []interface{}
	if err := h.parseParams(params, &values); err != nil {
		return nil, err
	}
	if len(values) != 1 {
		return nil, errors.New("getcontract requires one contract address")
	}
	address, ok := values[0].(string)
	if !ok {
		return nil, errors.New("invalid contract address")
	}
	meta, code, err := h.server.blockchain.GetContract(address)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"meta": meta, "code": hex.EncodeToString(code)}, nil
}

func (h *JSONRPCHandler) getContractStorage(params interface{}) (interface{}, error) {
	var values []interface{}
	if err := h.parseParams(params, &values); err != nil {
		return nil, err
	}
	if len(values) != 2 {
		return nil, errors.New("getcontractstorage requires contract address and key")
	}
	address, addressOK := values[0].(string)
	key, keyOK := values[1].(string)
	if !addressOK || !keyOK {
		return nil, errors.New("invalid contract storage parameters")
	}
	value, err := h.server.blockchain.GetContractStorage(address, key)
	if err != nil {
		// A key that simply has not been written yet — e.g. a token whose
		// mint transaction has not committed, which is the normal state while
		// a wallet polls for confirmation — is a MISS, not a malformed
		// request. Every handler error is mapped to -32602 Invalid params
		// above, so answering null here instead keeps clients from reporting
		// a plain "not found" as "RPC error (-32602): key contract:…".
		// All existing consumers (wallet decodeStorageHex, the mint storage
		// poller, abi's remoteStore) already render a null body as a clean
		// miss.
		if errors.Is(err, state.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return hex.EncodeToString(value), nil
}

func (h *JSONRPCHandler) callContractReadOnly(params interface{}) (interface{}, error) {
	var values []interface{}
	if err := h.parseParams(params, &values); err != nil {
		return nil, err
	}
	if len(values) != 1 {
		return nil, errors.New("callcontractreadonly requires one object")
	}
	raw, ok := values[0].(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid read-only call parameters")
	}
	address, _ := raw["to"].(string)
	caller, _ := raw["from"].(string)
	callDataHex, _ := raw["callData"].(string)
	if address == "" || callDataHex == "" {
		return nil, errors.New("to and callData are required")
	}
	callData, err := hex.DecodeString(strings.TrimPrefix(callDataHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid callData hex: %w", err)
	}
	value := new(big.Int)
	if rawValue, ok := raw["value"].(string); ok && rawValue != "" {
		if _, ok := value.SetString(rawValue, 10); !ok {
			return nil, errors.New("invalid value")
		}
	}
	result, err := h.server.blockchain.CallContractReadOnly(address, caller, callData, value, 0)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// deployContract builds an unsigned contract deployment transaction and returns
// it as hex-encoded JSON for the client to sign and submit via sendrawtransaction.
//
// ★ FIX: Nonce is now *uint64 so the handler distinguishes "not provided" from
// a client that deliberately passes 0. A client that has already claimed a
// pending-aware nonce via getnonce (or its own wallet reservation) can now
// inject that exact value and have it honored verbatim — including 0 for a
// first-ever tx on a fresh account — instead of being silently overwritten by
// a raw state-DB read.
//
// Params (single object):
//   - from:        sender SPIF address (required)
//   - code:        hex-encoded deploy code JSON (required)
//   - gasLimit:    optional gas limit
//   - gasPrice:    optional gas price in nSPX
//   - nonce:       optional nonce (absent = query state; present = use verbatim,
//     including 0)
//
// Returns: { "tx": "<hex>", "contractAddress": "<predicted>" }
func (h *JSONRPCHandler) deployContract(params interface{}) (interface{}, error) {
	if h.server.blockchain == nil {
		return nil, errors.New("blockchain not initialized")
	}

	var paramsStruct struct {
		From     string  `json:"from"`
		Code     string  `json:"code"`
		GasLimit uint64  `json:"gasLimit"`
		GasPrice string  `json:"gasPrice"`
		Nonce    *uint64 `json:"nonce"` // ★ FIX: pointer distinguishes absent from 0
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}
	if err := json.Unmarshal(paramsJSON, &paramsStruct); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}
	if paramsStruct.From == "" {
		return nil, errors.New("missing 'from' parameter")
	}
	if paramsStruct.Code == "" {
		return nil, errors.New("missing 'code' parameter")
	}

	codeHex := strings.TrimPrefix(paramsStruct.Code, "0x")
	codeBytes, err := hex.DecodeString(codeHex)
	if err != nil {
		return nil, fmt.Errorf("invalid code hex: %w", err)
	}

	rawFrom, err := common.NormalizeSPIFAddress(paramsStruct.From)
	if err != nil {
		return nil, fmt.Errorf("invalid sender address: %w", err)
	}

	// ★ FIX: honor a client-provided nonce verbatim (including 0). Only fall
	// back to a state-DB read when the field was genuinely absent. The old
	// `if nonce == 0 { re-query }` form made a client-passed 0 indistinguishable
	// from "not provided", so the state read always won — which is how a
	// wallet that had reserved nonce 0 ended up broadcasting a tx the
	// pending-aware mempool validator rejected as "invalid nonce: 0 must equal 1".
	nonce := uint64(0)
	if paramsStruct.Nonce != nil {
		nonce = *paramsStruct.Nonce
	} else {
		stateDB, dbErr := h.server.blockchain.NewStateDB()
		if dbErr != nil {
			return nil, fmt.Errorf("failed to query nonce: %w", dbErr)
		}
		defer stateDB.Close()
		nonce, err = stateDB.GetNonce(rawFrom)
		if err != nil {
			return nil, fmt.Errorf("failed to get nonce: %w", err)
		}
	}

	gasLimit := paramsStruct.GasLimit
	gasPrice := new(big.Int)
	if paramsStruct.GasPrice != "" {
		if _, ok := gasPrice.SetString(paramsStruct.GasPrice, 10); !ok {
			return nil, errors.New("invalid gasPrice")
		}
	}

	chainID := uint64(7331)
	if chainHdr := core.GetSphinxChainHeader(); chainHdr != nil && chainHdr.ChainID != 0 {
		chainID = chainHdr.ChainID
	}

	tx := &types.Transaction{
		ChainID:   chainID,
		Sender:    rawFrom,
		Receiver:  "",
		Amount:    big.NewInt(0),
		GasLimit:  new(big.Int).SetUint64(gasLimit),
		GasPrice:  gasPrice,
		Nonce:     nonce,
		Timestamp: 0,
		Signature: []byte{},
		Code:      codeBytes,
	}

	predictedAddress := contracts.ContractAddress(rawFrom, nonce, codeBytes)

	txJSON, err := json.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction: %w", err)
	}
	txHex := hex.EncodeToString(txJSON)

	return map[string]interface{}{
		"tx":              txHex,
		"contractAddress": predictedAddress,
	}, nil
}

// callContract builds an unsigned contract call transaction and returns it as
// hex-encoded JSON for the client to sign and submit via sendrawtransaction.
//
// ★ FIX: Nonce is now *uint64 for the same reason as deployContract — a
// client that already claimed nonce 0 for its very first contract call must
// be able to say "use 0" and have that survive the handler.
//
// Params (single object):
//   - from:        sender SPIF address (required)
//   - to:          target contract address (required)
//   - callData:    hex-encoded call data (required)
//   - value:       optional nSPX to send (default: 0)
//   - gasLimit:    optional gas limit
//   - gasPrice:    optional gas price in nSPX
//   - nonce:       optional nonce (absent = query state; present = use verbatim)
//
// Returns: { "tx": "<hex>" }
func (h *JSONRPCHandler) callContract(params interface{}) (interface{}, error) {
	if h.server.blockchain == nil {
		return nil, errors.New("blockchain not initialized")
	}

	var paramsStruct struct {
		From     string  `json:"from"`
		To       string  `json:"to"`
		CallData string  `json:"callData"`
		Value    string  `json:"value"`
		GasLimit uint64  `json:"gasLimit"`
		GasPrice string  `json:"gasPrice"`
		Nonce    *uint64 `json:"nonce"` // ★ FIX: pointer distinguishes absent from 0
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}
	if err := json.Unmarshal(paramsJSON, &paramsStruct); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}
	if paramsStruct.From == "" {
		return nil, errors.New("missing 'from' parameter")
	}
	if paramsStruct.To == "" {
		return nil, errors.New("missing 'to' (contract address) parameter")
	}
	if paramsStruct.CallData == "" {
		return nil, errors.New("missing 'callData' parameter")
	}

	callDataHex := strings.TrimPrefix(paramsStruct.CallData, "0x")
	callDataBytes, err := hex.DecodeString(callDataHex)
	if err != nil {
		return nil, fmt.Errorf("invalid callData hex: %w", err)
	}

	rawFrom, err := common.NormalizeSPIFAddress(paramsStruct.From)
	if err != nil {
		return nil, fmt.Errorf("invalid sender address: %w", err)
	}

	// ★ FIX: same pointer-honoring logic as deployContract.
	nonce := uint64(0)
	if paramsStruct.Nonce != nil {
		nonce = *paramsStruct.Nonce
	} else {
		stateDB, dbErr := h.server.blockchain.NewStateDB()
		if dbErr != nil {
			return nil, fmt.Errorf("failed to query nonce: %w", dbErr)
		}
		defer stateDB.Close()
		nonce, err = stateDB.GetNonce(rawFrom)
		if err != nil {
			return nil, fmt.Errorf("failed to get nonce: %w", err)
		}
	}
	amount := big.NewInt(0)
	if paramsStruct.Value != "" {
		if _, ok := amount.SetString(paramsStruct.Value, 10); !ok {
			return nil, errors.New("invalid value")
		}
	}

	gasLimit := paramsStruct.GasLimit
	gasPrice := new(big.Int)
	if paramsStruct.GasPrice != "" {
		if _, ok := gasPrice.SetString(paramsStruct.GasPrice, 10); !ok {
			return nil, errors.New("invalid gasPrice")
		}
	}

	chainID := uint64(7331)
	if chainHdr := core.GetSphinxChainHeader(); chainHdr != nil && chainHdr.ChainID != 0 {
		chainID = chainHdr.ChainID
	}

	tx := &types.Transaction{
		ChainID:    chainID,
		Sender:     rawFrom,
		Receiver:   paramsStruct.To,
		Amount:     amount,
		GasLimit:   new(big.Int).SetUint64(gasLimit),
		GasPrice:   gasPrice,
		Nonce:      nonce,
		Timestamp:  0,
		Signature:  []byte{},
		ToContract: paramsStruct.To,
		CallData:   callDataBytes,
	}

	txJSON, err := json.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction: %w", err)
	}
	txHex := hex.EncodeToString(txJSON)

	return map[string]interface{}{
		"tx": txHex,
	}, nil
}

// ProcessRequest processes a JSON-RPC request or batch of requests.
func (h *JSONRPCHandler) ProcessRequest(data []byte) ([]byte, error) {
	var msg Message
	if err := msg.Unmarshal(data); err == nil {
		return h.processBinaryMessage(msg)
	}

	var singleReq JSONRPCRequest
	if err := json.Unmarshal(data, &singleReq); err == nil && singleReq.JSONRPC == "2.0" {
		return h.processSingleRequest(singleReq)
	}

	var batchReq []JSONRPCRequest
	if err := json.Unmarshal(data, &batchReq); err == nil && len(batchReq) > 0 {
		return h.processBatchRequest(batchReq)
	}

	return h.errorResponse(nil, ErrCodeParseError, "Parse error: invalid JSON or binary format")
}

// processBinaryMessage handles a binary Message.
func (h *JSONRPCHandler) processBinaryMessage(msg Message) ([]byte, error) {
	start := time.Now()
	method := msg.RPCType.String()
	h.server.metrics.RequestCount.WithLabelValues(method).Inc()
	defer func() {
		h.server.metrics.RequestLatency.WithLabelValues(method).Observe(time.Since(start).Seconds())
	}()

	if msg.TTL == 0 {
		return h.errorResponse(msg.RPCID, ErrCodeInvalidRequest, "Invalid TTL")
	}

	methodName, err := h.mapRPCTypeToMethod(msg.RPCType)
	if err != nil {
		h.server.metrics.ErrorCount.WithLabelValues(method).Inc()
		return h.errorResponse(msg.RPCID, ErrCodeMethodNotFound, err.Error())
	}

	var params interface{}
	if len(msg.Values) > 0 {
		if err := json.Unmarshal(msg.Values[0], &params); err != nil {
			h.server.metrics.ErrorCount.WithLabelValues(method).Inc()
			return h.errorResponse(msg.RPCID, ErrCodeInvalidParams, "Invalid parameters format")
		}
	}

	handler, exists := h.methods[methodName]
	if !exists {
		h.server.metrics.ErrorCount.WithLabelValues(method).Inc()
		return h.errorResponse(msg.RPCID, ErrCodeMethodNotFound, fmt.Sprintf("Method %s not found", methodName))
	}

	if msg.Query {
		switch msg.RPCType {
		case RPCPing:
			h.server.queryManager.AddPing(msg.RPCID, msg.Target)
		case RPCJoin:
			h.server.queryManager.AddJoin(msg.RPCID)
		case RPCFindNode:
			h.server.queryManager.AddFindNode(msg.RPCID, msg.Target, nil)
		case RPCGet, RPCStore:
			h.server.queryManager.AddGet(msg.RPCID)
		}
	}

	result, err := handler(params)
	if err != nil {
		h.server.metrics.ErrorCount.WithLabelValues(method).Inc()
		return h.errorResponse(msg.RPCID, ErrCodeInvalidParams, err.Error())
	}

	respMsg := Message{
		RPCType:   msg.RPCType,
		Query:     false,
		TTL:       msg.TTL,
		Target:    msg.From.NodeID,
		RPCID:     msg.RPCID,
		From:      msg.From,
		Values:    [][]byte{},
		Iteration: msg.Iteration,
		Secret:    msg.Secret,
	}
	if result != nil {
		resultData, err := json.Marshal(result)
		if err != nil {
			return nil, err
		}
		respMsg.Values = append(respMsg.Values, resultData)
	}

	return respMsg.Marshal(make([]byte, respMsg.MarshalSize()))
}

// processSingleRequest handles a single JSON-RPC request.
func (h *JSONRPCHandler) processSingleRequest(req JSONRPCRequest) ([]byte, error) {
	start := time.Now()
	h.server.metrics.RequestCount.WithLabelValues(req.Method).Inc()
	defer func() {
		h.server.metrics.RequestLatency.WithLabelValues(req.Method).Observe(time.Since(start).Seconds())
	}()

	if req.JSONRPC != "2.0" {
		return h.errorResponse(req.ID, ErrCodeInvalidRequest, "Invalid JSON-RPC version")
	}
	if req.Method == "" {
		return h.errorResponse(req.ID, ErrCodeInvalidRequest, "Method is required")
	}

	handler, exists := h.methods[req.Method]
	if !exists {
		h.server.metrics.ErrorCount.WithLabelValues(req.Method).Inc()
		return h.errorResponse(req.ID, ErrCodeMethodNotFound, fmt.Sprintf("Method %s not found", req.Method))
	}

	result, err := handler(req.Params)
	if err != nil {
		h.server.metrics.ErrorCount.WithLabelValues(req.Method).Inc()
		return h.errorResponse(req.ID, ErrCodeInvalidParams, err.Error())
	}

	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		Result:  result,
		ID:      req.ID,
	}
	return json.Marshal(resp)
}

// processBatchRequest handles a batch of JSON-RPC requests.
func (h *JSONRPCHandler) processBatchRequest(reqs []JSONRPCRequest) ([]byte, error) {
	responses := make([]JSONRPCResponse, 0, len(reqs))
	for _, req := range reqs {
		respData, err := h.processSingleRequest(req)
		if err != nil {
			continue
		}
		var resp JSONRPCResponse
		if err := json.Unmarshal(respData, &resp); err != nil {
			continue
		}
		responses = append(responses, resp)
	}
	if len(responses) == 0 {
		return h.errorResponse(nil, ErrCodeInvalidRequest, "Empty batch request")
	}
	return json.Marshal(responses)
}

// errorResponse creates a JSON-RPC error response.
func (h *JSONRPCHandler) errorResponse(id interface{}, code int, message string) ([]byte, error) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		Error: &RPCError{
			Code:    code,
			Message: message,
		},
		ID: id,
	}
	return json.Marshal(resp)
}

// mapRPCTypeToMethod maps an RPCType to a method name.
func (h *JSONRPCHandler) mapRPCTypeToMethod(rpcType RPCType) (string, error) {
	switch rpcType {
	case RPCGetBlockCount:
		return "getblockcount", nil
	case RPCGetBestBlockHash:
		return "getbestblockhash", nil
	case RPCGetBlock:
		return "getblock", nil
	case RPCGetBlocks:
		return "getblocks", nil
	case RPCSendRawTransaction:
		return "sendrawtransaction", nil
	case RPCGetTransaction:
		return "gettransaction", nil
	case RPCPing:
		return "ping", nil
	case RPCJoin:
		return "join", nil
	case RPCFindNode:
		return "findnode", nil
	case RPCGet:
		return "get", nil
	case RPCStore:
		return "store", nil
	case RPCGetBlockByNumber:
		return "getblockbynumber", nil
	case RPCGetBlockHeader:
		return "getblockheader", nil
	case RPCGetHeaders:
		return "getheaders", nil
	case RPCGetBlockHash:
		return "getblockhash", nil
	case RPCGetDifficulty:
		return "getdifficulty", nil
	case RPCGetChainTip:
		return "getchaintip", nil
	case RPCGetNetworkInfo:
		return "getnetworkinfo", nil
	case RPCGetMiningInfo:
		return "getmininginfo", nil
	case RPCEstimateFee:
		return "estimatefee", nil
	case RPCGetMemPoolInfo:
		return "getmempoolinfo", nil
	case RPCValidateAddress:
		return "validateaddress", nil
	case RPCVerifyMessage:
		return "verifymessage", nil
	case RPCGetRawTransaction:
		return "getrawtransaction", nil
	case RPCGetBalance:
		return "getbalance", nil
	case RPCGetTransactionHistory:
		return "gettransactionhistory", nil
	case RPCGetSupplyStatus:
		return "getsupplystatus", nil
	case RPCGetCheckpoint:
		return "getcheckpoint", nil
	case RPCStoreArtifact:
		return "storeartifact", nil
	case RPCGetArtifact:
		return "getartifact", nil
	case RPCGetNonce:
		return "getnonce", nil
	default:
		return "", ErrUnsupportedRPCType
	}
}

// String converts an RPCType to its string representation.
func (t RPCType) String() string {
	switch t {
	case RPCGetBlockCount:
		return "getblockcount"
	case RPCGetBestBlockHash:
		return "getbestblockhash"
	case RPCGetBlock:
		return "getblock"
	case RPCGetBlocks:
		return "getblocks"
	case RPCSendRawTransaction:
		return "sendrawtransaction"
	case RPCGetTransaction:
		return "gettransaction"
	case RPCPing:
		return "ping"
	case RPCJoin:
		return "join"
	case RPCFindNode:
		return "findnode"
	case RPCGet:
		return "get"
	case RPCStore:
		return "store"
	case RPCGetBlockByNumber:
		return "getblockbynumber"
	case RPCGetBlockHeader:
		return "getblockheader"
	case RPCGetHeaders:
		return "getheaders"
	case RPCGetBlockHash:
		return "getblockhash"
	case RPCGetDifficulty:
		return "getdifficulty"
	case RPCGetChainTip:
		return "getchaintip"
	case RPCGetNetworkInfo:
		return "getnetworkinfo"
	case RPCGetMiningInfo:
		return "getmininginfo"
	case RPCEstimateFee:
		return "estimatefee"
	case RPCGetMemPoolInfo:
		return "getmempoolinfo"
	case RPCValidateAddress:
		return "validateaddress"
	case RPCVerifyMessage:
		return "verifymessage"
	case RPCGetRawTransaction:
		return "getrawtransaction"
	case RPCGetBalance:
		return "getbalance"
	case RPCGetTransactionHistory:
		return "gettransactionhistory"
	case RPCGetSupplyStatus:
		return "getsupplystatus"
	case RPCGetCheckpoint:
		return "getcheckpoint"
	case RPCStoreArtifact:
		return "storeartifact"
	case RPCGetArtifact:
		return "getartifact"
	case RPCGetNonce:
		return "getnonce"
	default:
		return "unknown"
	}
}

// RPC Method Handlers

// getBlockCount returns the current block height
func (h *JSONRPCHandler) getBlockCount(_ interface{}) (interface{}, error) {
	latest := h.server.blockchain.GetLatestBlock()
	if latest == nil {
		return uint64(0), nil
	}
	return latest.GetHeight(), nil
}

// getBestBlockHash returns the hash of the best (tip) block
func (h *JSONRPCHandler) getBestBlockHash(_ interface{}) (interface{}, error) {
	hash := h.server.blockchain.GetBestBlockHash()
	return string(hash), nil
}

// getBlock retrieves a block by its hash
func (h *JSONRPCHandler) getBlock(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing block hash parameter")
	}
	hashStr := paramsArray[0]

	block := h.server.blockchain.GetBlockByHash(hashStr)
	if block == nil {
		return nil, errors.New("block not found")
	}

	if adapter, ok := block.(*core.BlockHelper); ok {
		return adapter.GetUnderlyingBlock(), nil
	}

	return block, nil
}

// getBlocks returns a list of recent blocks
func (h *JSONRPCHandler) getBlocks(_ interface{}) (interface{}, error) {
	return h.server.blockchain.GetBlocks(), nil
}

// sendRawTransaction broadcasts a signed transaction to the network
func (h *JSONRPCHandler) sendRawTransaction(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing transaction hex parameter")
	}
	rawTx := paramsArray[0]
	txBytes, err := hex.DecodeString(rawTx)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction hex: %v", err)
	}

	var tx types.Transaction
	if err := json.Unmarshal(txBytes, &tx); err != nil {
		return nil, fmt.Errorf("invalid transaction format: %v", err)
	}
	if tx.ID == "" {
		tx.ID = tx.Hash()
	}

	if !tx.IsSystemTransaction() {
		if h.server.sphincsManager == nil {
			return nil, errors.New("SPHINCS manager not available - cannot verify transaction")
		}
		if err := h.verifyTransactionLocally(&tx); err != nil {
			return nil, fmt.Errorf("signature verification failed: %w", err)
		}
	} else if !tx.IsSystemTransaction() && !tx.HasFullAuthBundle() {
		return nil, errors.New("transaction missing full SPHINCS auth bundle")
	}

	if err := h.server.blockchain.AddTransaction(&tx); err != nil {
		return nil, err
	}

	txData, err := json.Marshal(&tx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction: %v", err)
	}
	if relay := h.server.txRelay; relay != nil {
		relay(&tx)
	}
	if ch := h.server.messageCh; ch != nil {
		select {
		case ch <- &security.Message{
			Type: "transaction",
			Data: txData,
		}:
		default:
		}
	}

	return map[string]string{"txid": tx.ID}, nil
}

// verifyTransactionLocally verifies a transaction's SPHINCS+ auth bundle.
func (h *JSONRPCHandler) verifyTransactionLocally(tx *types.Transaction) error {
	if h.server.sphincsManager == nil {
		return errors.New("SPHINCS manager not available")
	}

	tsBytes := tx.AuthTimestamp
	if len(tsBytes) == 0 {
		tsBytes = make([]byte, 8)
		binary.BigEndian.PutUint64(tsBytes, uint64(tx.Timestamp))
	}

	nonceBytes := tx.AuthNonce
	if len(nonceBytes) == 0 {
		nonceBytes = make([]byte, 16)
		binary.BigEndian.PutUint64(nonceBytes[0:8], tx.Nonce)
	}

	return h.server.sphincsManager.VerifyTransactionAuth(
		[]byte(tx.ID),
		tsBytes,
		nonceBytes,
		tx.Signature,
		tx.PublicKey,
		tx.SignatureHash,
		tx.MerkleRootHash,
		tx.Commitment,
		tx.Proof,
		false,
	)
}

// getTransaction retrieves a transaction by its ID
func (h *JSONRPCHandler) getTransaction(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing transaction ID parameter")
	}
	txID := paramsArray[0]

	tx, err := h.server.blockchain.GetTransactionByIDString(txID)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

// getTransactionReceipt returns the confirmation provenance of a transaction.
func (h *JSONRPCHandler) getTransactionReceipt(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing transaction ID parameter")
	}
	txID := paramsArray[0]

	if h.server.blockchain == nil {
		return nil, errors.New("blockchain not initialized")
	}

	response := map[string]interface{}{
		"txid":      txID,
		"confirmed": false,
		"height":    0,
		"blockhash": "",
	}
	if blockHash, height, err := h.server.blockchain.GetTxConfirmation(txID); err == nil {
		response["confirmed"] = true
		response["height"] = height
		response["blockhash"] = blockHash
	}

	broadcast, validating, pending, invalid, all := h.server.blockchain.MempoolSnapshot()
	response["pool"] = map[string]interface{}{
		"broadcast":  broadcast,
		"validating": validating,
		"pending":    pending,
		"invalid":    invalid,
		"total":      all,
	}
	if reason, exists := h.server.blockchain.GetTransactionError(txID); exists {
		response["invalid_reason"] = reason
	}

	// Enrich with events: Blockchain.GetTransactionEvents owns contract
	// resolution and storage reads; the receipt only renders the result.
	// Native/empty txs and unresolvable txids all produce an empty array
	// (never null).
	events, err := h.server.blockchain.GetTransactionEvents(txID)
	if err != nil {
		events = []contracts.ContractEvent{}
	}
	response["events"] = events
	return response, nil
}

// getTransactionEvents returns the events emitted by a confirmed transaction.
// For a nonexistent txid the error matches GetTransactionByIDString's
// not-found behavior; an existing tx that emitted no events returns an empty
// array with no error.
func (h *JSONRPCHandler) getTransactionEvents(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing transaction ID parameter")
	}
	txID := paramsArray[0]

	if h.server.blockchain == nil {
		return nil, errors.New("blockchain not initialized")
	}

	// Fail for nonexistent txid (GetTransactionByIDString returns error, via
	// Blockchain.GetTransactionEvents).
	events, err := h.server.blockchain.GetTransactionEvents(txID)
	if err != nil {
		return nil, err
	}
	if events == nil {
		events = []contracts.ContractEvent{}
	}
	return events, nil
}

// ping responds to health checks
func (h *JSONRPCHandler) ping(params interface{}) (interface{}, error) {
	return map[string]string{"status": "pong"}, nil
}

// join acknowledges node joining the network
func (h *JSONRPCHandler) join(params interface{}) (interface{}, error) {
	return map[string]string{"status": "joined"}, nil
}

// findNode locates a node by its ID
func (h *JSONRPCHandler) findNode(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing node ID parameter")
	}
	nodeIDStr := paramsArray[0]
	nodeIDBytes, err := hex.DecodeString(nodeIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid node ID: %v", err)
	}
	var nodeID NodeID
	copy(nodeID[:], nodeIDBytes)
	return map[string]string{"nodeID": nodeIDStr}, nil
}

// get retrieves stored values by key from the DHT
func (h *JSONRPCHandler) get(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 {
		return nil, errors.New("missing key parameter")
	}
	keyStr := paramsArray[0]
	keyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid key: %v", err)
	}
	var key Key
	copy(key[:], keyBytes)
	values, ok := h.server.store.Get(key)
	if !ok {
		return nil, errors.New("key not found")
	}
	hexValues := make([]string, len(values))
	for i, v := range values {
		hexValues[i] = hex.EncodeToString(v)
	}
	return map[string]interface{}{"values": hexValues}, nil
}

// store saves a value under a key with optional TTL
func (h *JSONRPCHandler) store(params interface{}) (interface{}, error) {
	var paramsStruct struct {
		Key   string `json:"key"`
		Value string `json:"value"`
		TTL   uint16 `json:"ttl"`
	}
	if err := h.parseParams(params, &paramsStruct); err != nil {
		return nil, err
	}
	if paramsStruct.Key == "" || paramsStruct.Value == "" {
		return nil, errors.New("missing key or value parameter")
	}
	keyBytes, err := hex.DecodeString(paramsStruct.Key)
	if err != nil {
		return nil, fmt.Errorf("invalid key: %v", err)
	}
	valueBytes, err := hex.DecodeString(paramsStruct.Value)
	if err != nil {
		return nil, fmt.Errorf("invalid value: %v", err)
	}
	var key Key
	copy(key[:], keyBytes)
	h.server.store.Put(key, valueBytes, paramsStruct.TTL)
	return map[string]string{"status": "stored"}, nil
}

// parseParams safely converts interface{} params into a target struct or slice
func (h *JSONRPCHandler) parseParams(params interface{}, target interface{}) error {
	if params == nil {
		return errors.New("missing parameters")
	}
	data, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("invalid parameters: %v", err)
	}
	return json.Unmarshal(data, target)
}

// storeArtifact persists a StorageArtifact keyed by MintID.
func (h *JSONRPCHandler) storeArtifact(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 || paramsArray[0] == "" {
		return nil, errors.New("missing artifact JSON parameter")
	}

	var artifact struct {
		MintID        string `json:"mint_id"`
		Subject       string `json:"subject"`
		CID           string `json:"cid"`
		CIDHashHex    string `json:"cid_hash_hex"`
		PayloadHash   string `json:"payload_hash"`
		ReceiptHash   string `json:"receipt_hash"`
		AnchorTagType string `json:"anchor_tag_type"`
	}
	if err := json.Unmarshal([]byte(paramsArray[0]), &artifact); err != nil {
		return nil, fmt.Errorf("invalid artifact JSON: %w", err)
	}
	if artifact.MintID == "" {
		return nil, errors.New("artifact must have a mint_id")
	}

	artifactData, _ := json.Marshal(artifact)

	if h.server.artifactDB != nil {
		mintIDKey := []byte("artifact:" + artifact.MintID)
		if err := h.server.artifactDB.Put(mintIDKey, artifactData, nil); err != nil {
			return nil, fmt.Errorf("failed to store artifact: %w", err)
		}
		if artifact.CIDHashHex != "" {
			cidHashKey := []byte("cidhash:" + artifact.CIDHashHex)
			if err := h.server.artifactDB.Put(cidHashKey, []byte(artifact.MintID), nil); err != nil {
				return nil, fmt.Errorf("failed to store CID hash index: %w", err)
			}
		}
	} else {
		mintIDKey := sha3Key("artifact:" + artifact.MintID)
		h.server.store.Put(mintIDKey, artifactData, 43200)

		if artifact.CIDHashHex != "" {
			cidHashKey := sha3Key("cidhash:" + artifact.CIDHashHex)
			h.server.store.Put(cidHashKey, []byte(artifact.MintID), 43200)
		}
	}

	return map[string]string{
		"status":  "stored",
		"mint_id": artifact.MintID,
	}, nil
}

// getArtifact retrieves a stored StorageArtifact by MintID.
func (h *JSONRPCHandler) getArtifact(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 || paramsArray[0] == "" {
		return nil, errors.New("missing mint_id parameter")
	}
	mintID := paramsArray[0]

	if h.server.artifactDB != nil {
		mintIDKey := []byte("artifact:" + mintID)
		data, err := h.server.artifactDB.Get(mintIDKey, nil)
		if err == nil {
			var artifact interface{}
			if err := json.Unmarshal(data, &artifact); err != nil {
				return nil, fmt.Errorf("parse stored artifact: %w", err)
			}
			return artifact, nil
		}
	}

	mintIDKey := sha3Key("artifact:" + mintID)
	values, ok := h.server.store.Get(mintIDKey)
	if !ok || len(values) == 0 {
		return map[string]interface{}{
			"found":   false,
			"mint_id": mintID,
		}, nil
	}

	var artifact interface{}
	if err := json.Unmarshal(values[0], &artifact); err != nil {
		return nil, fmt.Errorf("parse stored artifact: %w", err)
	}
	return artifact, nil
}

// getNonce returns the next nonce for an address.
//
// The return value is the MEMPOOL's pending-aware nonce (see
// Mempool.GetSenderNonce), which accounts for both committed state AND any
// transactions already parked in the mempool for this sender. This is what a
// wallet must use to build a new tx, because the mempool's validator accepts
// a tx only when its nonce exactly equals this pending-aware value — a raw
// state-DB read would return the committed nonce and produce a tx the
// validator rejects with "invalid nonce: N must equal N+1" while a prior tx
// from the same sender is still in flight.
func (h *JSONRPCHandler) getNonce(params interface{}) (interface{}, error) {
	var paramsArray []string
	if err := h.parseParams(params, &paramsArray); err != nil {
		return nil, err
	}
	if len(paramsArray) < 1 || paramsArray[0] == "" {
		return nil, errors.New("missing address parameter")
	}
	address := paramsArray[0]

	if h.server.blockchain != nil && h.server.blockchain.GetMempool() != nil {
		return h.server.blockchain.GetMempool().GetSenderNonce(address), nil
	}

	stateDB, err := h.server.blockchain.NewStateDB()
	if err != nil {
		return uint64(0), nil
	}
	defer stateDB.Close()

	nonce, err := stateDB.GetNonce(address)
	if err != nil {
		return uint64(0), nil
	}
	return nonce, nil
}

// sha3Key creates a deterministic 32-byte KV key from a string using the
// protocol's Sphinx hash.
func sha3Key(input string) Key {
	h := common.SpxHash([]byte(input))
	var k Key
	copy(k[:], h[:])
	return k
}

// RPCCallerImpl implements core.RPCCaller
type RPCCallerImpl struct {
	nodeID NodeID
}

// NewRPCCaller creates a new RPC caller with the given node ID
func NewRPCCaller(nodeID NodeID) *RPCCallerImpl {
	return &RPCCallerImpl{nodeID: nodeID}
}

// GetCheckpoint retrieves a checkpoint from a peer.
func (c *RPCCallerImpl) GetCheckpoint(peerAddress string) (*consensus.CheckpointMessage, error) {
	resp, err := CallRPC(peerAddress, "getcheckpoint", nil, 60)
	if err != nil {
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}

	if len(resp) == 0 {
		return nil, fmt.Errorf("empty response from peer")
	}

	var cp consensus.CheckpointMessage
	if err := json.Unmarshal(resp, &cp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal checkpoint: %w", err)
	}

	return &cp, nil
}

// GetSupplyStatus retrieves supply status from a peer.
func (c *RPCCallerImpl) GetSupplyStatus(peerAddress string) (map[string]interface{}, error) {
	resp, err := CallRPC(peerAddress, "getsupplystatus", nil, 60)
	if err != nil {
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}

	if len(resp) == 0 {
		return nil, fmt.Errorf("empty response from peer")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal supply status: %w", err)
	}

	return result, nil
}

// Ensure RPCCallerImpl implements core.RPCCaller
var _ core.RPCCaller = (*RPCCallerImpl)(nil)
