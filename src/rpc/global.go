// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/rpc/global.go
package rpc

// Standard JSON-RPC error codes.
const (
	ErrCodeParseError     = -32700 // Invalid JSON
	ErrCodeInvalidRequest = -32600 // Not a valid JSON-RPC request
	ErrCodeMethodNotFound = -32601 // Method does not exist
	ErrCodeInvalidParams  = -32602 // Invalid parameters
	ErrCodeInternalError  = -32603 // Internal server error
)

// RPC message types.
const (
	RPCGetBlockCount RPCType = iota
	RPCGetBestBlockHash
	RPCGetBlock
	RPCGetBlocks
	RPCSendRawTransaction
	RPCGetTransaction
	RPCPing
	RPCJoin
	RPCFindNode
	RPCGet
	RPCStore
	RPCGetBlockByNumber
	RPCGetBlockHash
	RPCGetDifficulty
	RPCGetChainTip
	RPCGetNetworkInfo
	RPCGetMiningInfo
	RPCEstimateFee
	RPCGetMemPoolInfo
	RPCValidateAddress
	RPCVerifyMessage
	RPCGetRawTransaction
	RPCGetBalance
	RPCGetTransactionHistory
	RPCGetSupplyStatus
	RPCGetCheckpoint
	RPCStoreArtifact
	RPCGetArtifact
	RPCGetNonce

	// Lightweight (header-only) sync endpoints. Wallets such as src/usi are
	// lightweight clients — NOT vault full nodes — so they download block
	// headers only and never block bodies. These RPC types back the
	// "getblockheader" / "getheaders" methods (see json.go).
	RPCGetBlockHeader
	RPCGetHeaders
)
