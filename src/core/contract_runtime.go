// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/sphinxfndorg/protocol/src/contracts"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// contractStore buffers a transaction's writes until execution succeeds. This
// prevents a failed contract call from leaving partial storage changes.
type contractStore struct {
	state   *StateDB
	overlay map[string][]byte
}

func newContractStore(state *StateDB) *contractStore {
	return &contractStore{state: state, overlay: make(map[string][]byte)}
}

func contractKey(address, kind, key string) string {
	return address + ":" + kind + ":" + key
}

func (s *contractStore) get(key string) ([]byte, error) {
	if value, ok := s.overlay[key]; ok {
		return append([]byte(nil), value...), nil
	}
	return s.state.GetContractValue(key)
}

func (s *contractStore) put(key string, value []byte) { s.overlay[key] = append([]byte(nil), value...) }

func (s *contractStore) ContractExists(address string) bool {
	_, err := s.get(contractKey(address, "meta", ""))
	return err == nil
}
func (s *contractStore) SetContractCode(address string, code []byte) {
	s.put(contractKey(address, "code", ""), code)
}
func (s *contractStore) GetContractCode(address string) ([]byte, error) {
	return s.get(contractKey(address, "code", ""))
}
func (s *contractStore) SetContractMeta(address string, meta []byte) {
	s.put(contractKey(address, "meta", ""), meta)
}
func (s *contractStore) GetContractMeta(address string) ([]byte, error) {
	return s.get(contractKey(address, "meta", ""))
}
func (s *contractStore) SetContractStorage(address, key string, value []byte) {
	s.put(contractKey(address, "storage", key), value)
}
func (s *contractStore) GetContractStorage(address, key string) ([]byte, error) {
	return s.get(contractKey(address, "storage", key))
}
func (s *contractStore) commit() {
	for key, value := range s.overlay {
		s.state.SetContractValue(key, value)
	}
}

func (s *contractStore) recordEvents(tx *types.Transaction, result *contracts.ExecutionResult) error {
	if result == nil {
		return nil
	}
	for i, event := range result.Events {
		encoded, err := json.Marshal(event)
		if err != nil {
			return err
		}
		s.SetContractStorage(result.ContractAddress, fmt.Sprintf("event:%s:%020d:%04d", tx.Sender, tx.Nonce, i), encoded)
	}
	return nil
}

func isSVMCode(code []byte) bool { return bytes.HasPrefix(code, contracts.SVM1Magic) }

// GetContract returns immutable deployed metadata and code for RPC, indexers,
// and developer tools. It never executes contract code.
func (bc *Blockchain) GetContract(address string) (*contracts.ContractMeta, []byte, error) {
	if address == "" {
		return nil, nil, errors.New("missing contract address")
	}
	state, err := bc.newStateDB()
	if err != nil {
		return nil, nil, err
	}
	store := newContractStore(state)
	metaJSON, err := store.GetContractMeta(address)
	if err != nil {
		return nil, nil, fmt.Errorf("load contract: %w", err)
	}
	var meta contracts.ContractMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, nil, fmt.Errorf("decode contract metadata: %w", err)
	}
	code, err := store.GetContractCode(address)
	if err != nil {
		return nil, nil, fmt.Errorf("load contract code: %w", err)
	}
	return &meta, code, nil
}

// GetContractStorage returns a raw consensus storage value. Standard-specific
// decoding belongs in SDKs and indexers, keeping core state generic.
func (bc *Blockchain) GetContractStorage(address, key string) ([]byte, error) {
	if address == "" || key == "" {
		return nil, errors.New("contract address and storage key are required")
	}
	state, err := bc.newStateDB()
	if err != nil {
		return nil, err
	}
	return newContractStore(state).GetContractStorage(address, key)
}

// executeContractTransaction runs deploy/call transactions as part of block
// execution. It must only be called after normal sender/nonce validation.
func (bc *Blockchain) executeContractTransaction(tx *types.Transaction, state *StateDB, heights ...uint64) error {
	var blockHeight uint64
	if len(heights) > 0 {
		blockHeight = heights[0]
	}
	if len(tx.Code) == 0 && tx.ToContract == "" {
		return nil
	}
	store := newContractStore(state)
	policy := bc.ActivePolicy()
	var operations, reads, writes, eventBytes, transfers uint64
	wasmExecution := false

	if len(tx.Code) > 0 {
		if isSVMCode(tx.Code) {
			analyzed, err := contracts.AnalyzeSVM(tx.Code)
			if err != nil {
				return fmt.Errorf("invalid SVM contract: %w", err)
			}
			operations = analyzed
			address := contracts.ContractAddress(tx.Sender, tx.Nonce, tx.Code)
			if store.ContractExists(address) {
				return fmt.Errorf("contract already exists: %s", address)
			}
			meta, err := json.Marshal(&contracts.ContractMeta{Address: address, Creator: tx.Sender, Runtime: "svm1", Standard: "svm1", CreatedAt: tx.Timestamp})
			if err != nil {
				return err
			}
			store.SetContractCode(address, tx.Code)
			store.SetContractMeta(address, meta)
			_, executed, err := contracts.ExecuteSVMWithCallData(store, address, tx.Code, tx.CallData, operations)
			if err != nil {
				return fmt.Errorf("svm deployment: %w", err)
			}
			if executed != operations {
				return errors.New("SVM operation count mismatch")
			}
		} else if contracts.IsWASM(tx.Code) {
			wasmExecution = true
			if !tx.Amount.IsUint64() {
				return errors.New("WASM transferred value exceeds u64 ABI range")
			}
			if err := contracts.ValidateWASM(tx.Code, policy.WASMMaxCodeBytes, policy.WASMMemoryPages); err != nil {
				return fmt.Errorf("invalid WASM contract: %w", err)
			}
			address := contracts.ContractAddress(tx.Sender, tx.Nonce, tx.Code)
			if store.ContractExists(address) {
				return fmt.Errorf("contract already exists: %s", address)
			}
			meta, err := json.Marshal(&contracts.ContractMeta{Address: address, Creator: tx.Sender, Runtime: contracts.RuntimeWASM, Standard: contracts.RuntimeWASM, CreatedAt: tx.Timestamp})
			if err != nil {
				return err
			}
			store.SetContractCode(address, tx.Code)
			store.SetContractMeta(address, meta)
			analysis, err := contracts.AnalyzeWASM(tx.Code)
			if err != nil {
				return fmt.Errorf("analyze WASM: %w", err)
			}
			operations, reads, writes, eventBytes, transfers = analysis.Operations, analysis.StorageReads, analysis.StorageWrites, analysis.EventBytes, analysis.Transfers
			result, err := contracts.ExecuteWASMWithContext(store, address, tx.Code, tx.CallData, policy.WASMMaxCodeBytes, policy.WASMMemoryPages, contracts.WASMContext{Caller: tx.Sender, Value: tx.Amount.Uint64(), BlockHeight: blockHeight, MaxEvents: policy.WASMMaxEvents, Transfer: bc.contractTransfer(state, address)})
			if err != nil {
				return fmt.Errorf("WASM deployment: %w", err)
			}
			if err := store.recordEvents(tx, result); err != nil {
				return err
			}
		} else if _, err := contracts.Deploy(store, tx); err != nil {
			return fmt.Errorf("native contract deploy: %w", err)
		}
	} else {
		metaJSON, err := store.GetContractMeta(tx.ToContract)
		if err != nil {
			return fmt.Errorf("load contract: %w", err)
		}
		var meta contracts.ContractMeta
		if err := json.Unmarshal(metaJSON, &meta); err != nil {
			return fmt.Errorf("decode contract meta: %w", err)
		}
		if meta.Runtime == "svm1" {
			code, err := store.GetContractCode(tx.ToContract)
			if err != nil {
				return err
			}
			operations, err = contracts.AnalyzeSVM(code)
			if err != nil {
				return fmt.Errorf("invalid stored SVM contract: %w", err)
			}
			_, executed, err := contracts.ExecuteSVMWithCallData(store, tx.ToContract, code, tx.CallData, operations)
			if err != nil {
				return fmt.Errorf("svm execution: %w", err)
			}
			if executed != operations {
				return errors.New("SVM operation count mismatch")
			}
		} else if meta.Runtime == contracts.RuntimeWASM {
			wasmExecution = true
			if !tx.Amount.IsUint64() {
				return errors.New("WASM transferred value exceeds u64 ABI range")
			}
			code, err := store.GetContractCode(tx.ToContract)
			if err != nil {
				return err
			}
			analysis, err := contracts.AnalyzeWASM(code)
			if err != nil {
				return fmt.Errorf("analyze stored WASM: %w", err)
			}
			operations, reads, writes, eventBytes, transfers = analysis.Operations, analysis.StorageReads, analysis.StorageWrites, analysis.EventBytes, analysis.Transfers
			result, err := contracts.ExecuteWASMWithContext(store, tx.ToContract, code, tx.CallData, policy.WASMMaxCodeBytes, policy.WASMMemoryPages, contracts.WASMContext{Caller: tx.Sender, Value: tx.Amount.Uint64(), BlockHeight: blockHeight, MaxEvents: policy.WASMMaxEvents, Transfer: bc.contractTransfer(state, tx.ToContract)})
			if err != nil {
				return fmt.Errorf("WASM execution: %w", err)
			}
			if err := store.recordEvents(tx, result); err != nil {
				return err
			}
		} else if _, err := contracts.Call(store, tx); err != nil {
			return fmt.Errorf("native contract call: %w", err)
		}
	}

	quote := policy.QuoteTransactionGas(uint64(len(tx.ReturnData)))
	contractQuote := policy.QuoteContractGas(len(tx.Code) > 0, uint64(len(tx.Code)), uint64(len(tx.CallData)), operations)
	if wasmExecution {
		contractQuote = policy.QuoteWASMContractGas(len(tx.Code) > 0, uint64(len(tx.Code)), uint64(len(tx.CallData)), operations, reads, writes, eventBytes, transfers)
	}
	quote.GasLimit.Add(quote.GasLimit, contractQuote.GasLimit)
	if tx.GasLimit == nil || tx.GasLimit.Cmp(quote.GasLimit) < 0 {
		return errors.New("contract gas limit below policy requirement")
	}
	store.commit()
	return nil
}

func (bc *Blockchain) contractTransfer(state *StateDB, from string) func(string, uint64) error {
	return func(to string, amount uint64) error {
		if to == "" {
			return errors.New("empty transfer recipient")
		}
		value := new(big.Int).SetUint64(amount)
		return state.Transfer(from, to, value)
	}
}
