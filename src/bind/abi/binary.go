// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/sphinxfndorg/protocol/src/contracts"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
)

// BinaryArtifact is the portable representation of deployable bytecode.
// Code is raw bytes in memory; HexCode is the canonical transport form.
type BinaryArtifact struct {
	Runtime  string `json:"runtime"`
	HexCode  string `json:"code"`
	CodeHash string `json:"code_hash"`
}

// EncodeBinary returns canonical lower-case 0x-prefixed hexadecimal code.
func EncodeBinary(code []byte) string { return "0x" + hex.EncodeToString(code) }

// DecodeBinary decodes the canonical 0x-prefixed (or plain) hex artifact.
func DecodeBinary(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(strings.TrimPrefix(encoded, "0x"))
	if encoded == "" {
		return nil, errors.New("empty binary artifact")
	}
	if len(encoded)%2 != 0 {
		return nil, errors.New("binary artifact has odd-length hex")
	}
	code, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode binary artifact: %w", err)
	}
	return code, nil
}

// NewBinaryArtifact validates code for its declared runtime and produces a
// content-addressed artifact that can be emitted by any language toolchain.
func NewBinaryArtifact(runtime string, code []byte) (*BinaryArtifact, error) {
	if len(code) == 0 {
		return nil, errors.New("empty binary code")
	}
	switch runtime {
	case contracts.RuntimeWASM:
		if !contracts.IsWASM(code) {
			return nil, errors.New("artifact is not WASM bytecode")
		}
	case "svm1":
		if _, err := contracts.AnalyzeSVM(code); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported binary runtime %q", runtime)
	}
	sum := sha256.Sum256(code)
	return &BinaryArtifact{Runtime: runtime, HexCode: EncodeBinary(code), CodeHash: hex.EncodeToString(sum[:])}, nil
}

// DecodeArtifactCode checks the declared runtime before returning raw bytes.
func DecodeArtifactCode(artifact *BinaryArtifact) ([]byte, error) {
	if artifact == nil {
		return nil, errors.New("nil binary artifact")
	}
	code, err := DecodeBinary(artifact.HexCode)
	if err != nil {
		return nil, err
	}
	decoded, err := NewBinaryArtifact(artifact.Runtime, code)
	if err != nil {
		return nil, err
	}
	if artifact.CodeHash != "" && !strings.EqualFold(artifact.CodeHash, decoded.CodeHash) {
		return nil, errors.New("binary artifact hash mismatch")
	}
	return code, nil
}

// NewWASMDeployTxFromHex decodes a portable artifact before quoting a deploy.
func NewWASMDeployTxFromHex(options TxOptions, encoded string) (*types.Transaction, error) {
	code, err := DecodeBinary(encoded)
	if err != nil {
		return nil, err
	}
	return NewWASMDeployTx(options, code)
}

// NewSVMDeployTx constructs an unsigned deployment from validated SVM1 binary
// and includes its statically analyzable operation gas in the quote.
func NewSVMDeployTx(options TxOptions, code []byte) (*types.Transaction, error) {
	if options.Sender == "" {
		return nil, errors.New("sender is required")
	}
	operations, err := contracts.AnalyzeSVM(code)
	if err != nil {
		return nil, err
	}
	p := policy.GetDefaultPolicyParams()
	base := p.QuoteTransactionGas(0)
	contract := p.QuoteContractGas(true, uint64(len(code)), 0, operations)
	return assembleUnsignedTx(options, code, nil, "", new(big.Int).Add(base.GasLimit, contract.GasLimit), new(big.Int).Set(base.GasPrice)), nil
}
