// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// assembleUnsignedTx is the single canonical constructor for every unsigned
// contract transaction the ABI emits. Before this helper, all seven builders
// (SIP-20 deploy/call, WASM deploy/call/function-call, SVM deploy, the
// deploy-from-hex path) repeated the same types.Transaction literal — seven
// copies that could drift apart, with one consensus-relevant omission: none
// of them could ever set Receiver, Amount, or ReturnData, which is correct —
// contract operations carry value in Code/CallData, never in a native
// transfer, and ReturnData is owned by the mint-anchor flow (src/core/mint_anchor.go,
// node-verified via src/core.ValidateTransactionPolicy). All builders now
// delegate here so a consensus-relevant field can only ever be added in
// exactly one place.
func assembleUnsignedTx(options TxOptions, code, callData []byte, contractAddress string, gasLimit, gasPrice *big.Int) *types.Transaction {
	return &types.Transaction{
		ChainID:    options.ChainID,
		Sender:     options.Sender,
		Amount:     big.NewInt(0),
		Nonce:      options.Nonce,
		Timestamp:  timestamp(options),
		Code:       append([]byte(nil), code...),
		ToContract: contractAddress,
		CallData:   append([]byte(nil), callData...),
		GasLimit:   gasLimit,
		GasPrice:   gasPrice,
	}
}

// EncodeRawTransaction produces the canonical hex(JSON(transaction)) wire
// payload accepted by the node's sendrawtransaction RPC method.
//
// It lives in the ABI package rather than src/bind because it completes the
// client story — build (the ABI builders above) → encode (here) → broadcast —
// while keeping the dependency footprint leaf-sized: src/bind pulls the full
// node runtime (43+ packages: consensus, network, p2p, dht, transport, zap),
// the ABI pulls 11. SDKs, wallets, and the CLI encode contract payloads
// through this function so they emit byte-identical payloads. Code and call
// data remain binary fields and use Go JSON's byte-slice encoding internally.
func EncodeRawTransaction(tx *types.Transaction) (string, error) {
	if tx == nil {
		return "", fmt.Errorf("nil transaction")
	}
	data, err := json.Marshal(tx)
	if err != nil {
		return "", fmt.Errorf("marshal raw transaction: %w", err)
	}
	return hex.EncodeToString(data), nil
}
