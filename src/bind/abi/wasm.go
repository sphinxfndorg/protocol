// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"errors"
	"math/big"

	"github.com/sphinxfndorg/protocol/src/contracts"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
)

// NewWASMDeployTx constructs an unsigned transaction carrying a standard
// WebAssembly binary. Compile source code with Rust, C/C++, TinyGo or another
// compiler that targets the documented Sphinx WASM host ABI.
func NewWASMDeployTx(options TxOptions, wasm []byte) (*types.Transaction, error) {
	if options.Sender == "" {
		return nil, errors.New("sender is required")
	}
	if len(wasm) == 0 {
		return nil, errors.New("WASM bytecode is required")
	}
	if !contracts.IsWASM(wasm) {
		return nil, errors.New("invalid WASM bytecode")
	}
	p := policy.GetDefaultPolicyParams()
	base := p.QuoteTransactionGas(0)
	contract := p.QuoteContractGas(true, uint64(len(wasm)), 0, 0)
	return assembleUnsignedTx(options, wasm, nil, "", new(big.Int).Add(base.GasLimit, contract.GasLimit), new(big.Int).Set(base.GasPrice)), nil
}

// NewWASMCallTx constructs an unsigned call to a deployed WASM contract.
// callData is interpreted by the contract through sphinx.calldata_word.
func NewWASMCallTx(options TxOptions, contractAddress string, callData []byte) (*types.Transaction, error) {
	if options.Sender == "" || contractAddress == "" {
		return nil, errors.New("sender and contract address are required")
	}
	p := policy.GetDefaultPolicyParams()
	base := p.QuoteTransactionGas(0)
	contract := p.QuoteContractGas(false, 0, uint64(len(callData)), 0)
	return assembleUnsignedTx(options, nil, callData, contractAddress, new(big.Int).Add(base.GasLimit, contract.GasLimit), new(big.Int).Set(base.GasPrice)), nil
}

// NewWASMFunctionCallTx encodes a canonical function selector and u64
// arguments for a call. Use NewWASMCallTx when a contract deliberately uses a
// custom raw payload instead.
func NewWASMFunctionCallTx(options TxOptions, contractAddress, function string, args ...uint64) (*types.Transaction, error) {
	callData, err := EncodeWASMFunctionCall(function, args...)
	if err != nil {
		return nil, err
	}
	return NewWASMCallTx(options, contractAddress, callData)
}
