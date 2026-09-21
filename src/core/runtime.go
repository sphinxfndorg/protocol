// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/contracts"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// contractStore buffers a transaction's writes until execution succeeds. This
// prevents a failed contract call from leaving partial storage changes.
//
// resolved maps a contract's canonical address to the on-disk address rendering
// the contract was actually found under (see keyFor). Address renderings vary
// across node versions — current nodes use the grouped uppercase form
// ("SPIF E1FE 1F5D …"), older ones used "SPIF"+40-lowercase-hex — so a read
// records whichever rendering hit and every later write for that contract
// reuses it. That keeps a call's writes on the same key its state lives at,
// which preserves legacy keys and keeps block replay deterministic.
type contractStore struct {
	state    *StateDB
	overlay  map[string][]byte
	resolved map[string]string
}

func newContractStore(state *StateDB) *contractStore {
	return &contractStore{
		state:    state,
		overlay:  make(map[string][]byte),
		resolved: make(map[string]string),
	}
}

// canonicalContractAddress collapses every accepted SPIF address rendering
// (the grouped display form "SPIF XXXX XXXX …", bare raw hex, mixed case, or
// the legacy "SPIF"+40-lowercase-hex form) into the single canonical form that
// contracts.ContractAddress returns and that is used as the contract storage
// key. Values that are not parseable SPIF addresses (empty strings, system ids
// such as "genesis") are returned unchanged so callers keep their behaviour.
//
// Without this, a contract deployed as "SPIF E1FE 1F5D …" was only reachable by
// callers echoing back that exact spaced/uppercase string; a lookup phrased as
// raw hex, differently grouped, or in the legacy 20-byte form silently missed,
// which surfaced as spurious "contract does not exist" rejections and empty
// getcontractstorage reads.
func canonicalContractAddress(address string) string {
	if address == "" {
		return address
	}
	raw, err := common.NormalizeSPIFAddress(address)
	if err != nil {
		return address
	}
	formatted, err := common.FormatSPIFAddress(raw)
	if err != nil {
		return address
	}
	return formatted
}

// contractKey builds the canonical composite state key for a contract. Writes
// stage through contractStore.put, which reuses a resolved legacy rendering when
// one exists (see keyFor); this helper is the canonical form used for fresh
// contracts and by tests.
func contractKey(address, kind, key string) string {
	return canonicalContractAddress(address) + ":" + kind + ":" + key
}

// contractAddressRenderings returns the candidate on-disk address renderings a
// contract may have been stored under, most canonical first:
//
//  1. the canonical grouped form ("SPIF E1FE 1F5D …") used by current nodes;
//  2. the raw address exactly as the caller supplied it;
//  3. for 20-byte addresses, the historical "SPIF"+lowercase form that older
//     nodes emitted for the legacy 20-byte contract addresses.
//
// Reads consult each rendering in turn so a contract stays reachable no matter
// which accepted rendering the caller used.
func contractAddressRenderings(address string) []string {
	seen := make(map[string]bool, 3)
	renderings := make([]string, 0, 3)
	add := func(candidate string) {
		if candidate == "" || seen[candidate] {
			return
		}
		seen[candidate] = true
		renderings = append(renderings, candidate)
	}
	add(canonicalContractAddress(address))
	add(address)
	if raw, err := common.NormalizeSPIFAddress(address); err == nil && len(raw) == 40 {
		add(common.SPIFPrefix + strings.ToLower(raw))
	}
	return renderings
}

// keyFor returns the address rendering to use as the key prefix for this
// contract. A read that located the contract records the rendering it was
// stored under, and that rendering is reused so writes land on the same key the
// contract's existing state lives at. Fresh deployments (no prior read hit) key
// on the canonical rendering produced by contracts.ContractAddress.
func (s *contractStore) keyFor(address string) string {
	canonical := canonicalContractAddress(address)
	if resolved, ok := s.resolved[canonical]; ok {
		return resolved
	}
	return canonical
}

// renderingsFor returns the address renderings to consult for a read, with the
// write rendering (see keyFor) first so the common case is a single lookup.
func (s *contractStore) renderingsFor(address string) []string {
	preferred := s.keyFor(address)
	ordered := make([]string, 0, 3)
	ordered = append(ordered, preferred)
	for _, rendering := range contractAddressRenderings(address) {
		if rendering != preferred {
			ordered = append(ordered, rendering)
		}
	}
	return ordered
}

// get reads a single composite key, preferring this transaction's buffered
// writes over committed state.
func (s *contractStore) get(key string) ([]byte, error) {
	if value, ok := s.overlay[key]; ok {
		return append([]byte(nil), value...), nil
	}
	return s.state.GetContractValue(key)
}

// getFor reads address:kind:key, trying each candidate rendering of the address
// in turn. The rendering that produced the hit is remembered so every later
// write for the same contract lands on the same key — this is what keeps a
// legacy-keyed contract's writes on its legacy key instead of silently moving
// them to the canonical key mid-transaction.
func (s *contractStore) getFor(address, kind, key string) ([]byte, error) {
	var err error
	for _, rendering := range s.renderingsFor(address) {
		var value []byte
		value, err = s.get(rendering + ":" + kind + ":" + key)
		if err == nil {
			s.resolved[canonicalContractAddress(address)] = rendering
			return value, nil
		}
	}
	return nil, err
}

// put stages a write for address:kind:key under the contract's resolved
// rendering (see keyFor).
func (s *contractStore) put(address, kind, key string, value []byte) {
	s.overlay[s.keyFor(address)+":"+kind+":"+key] = append([]byte(nil), value...)
}

func (s *contractStore) ContractExists(address string) bool {
	_, err := s.getFor(address, "meta", "")
	return err == nil
}
func (s *contractStore) SetContractCode(address string, code []byte) {
	s.put(address, "code", "", code)
}
func (s *contractStore) GetContractCode(address string) ([]byte, error) {
	return s.getFor(address, "code", "")
}
func (s *contractStore) SetContractMeta(address string, meta []byte) {
	s.put(address, "meta", "", meta)
}
func (s *contractStore) GetContractMeta(address string) ([]byte, error) {
	return s.getFor(address, "meta", "")
}
func (s *contractStore) SetContractStorage(address, key string, value []byte) {
	s.put(address, "storage", key, value)
}
func (s *contractStore) GetContractStorage(address, key string) ([]byte, error) {
	return s.getFor(address, "storage", key)
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
		} else if _, err := contracts.CallWithContext(store, tx, &contracts.NativeCallContext{
			// The executor escrowed tx.Amount at the contract address before
			// this function ran, so the runtime's payouts (SIP-721 resale
			// royalty → creator, proceeds → seller, license fee → creator)
			// always sum exactly to the carried value and the contract nets
			// zero. Payouts are buffered in StateDB like every other write, so
			// a later failure rolls them back atomically.
			Value:      tx.Amount,
			PriceFloor: policy.MinTokenSaleValue,
			Transfer:   bc.contractTransferNSPX(state, tx.ToContract),
		}); err != nil {
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

// contractTransferNSPX is the *big.Int counterpart of contractTransfer: native
// standards that settle value (SIP-721 resale royalties and license fees) use
// this surface to move the escrowed tx.Amount out of the contract address.
// It is deliberately the only balance-movement hook handed to native runtimes,
// keeping every payout traced, buffered, and aborted-with-the-block exactly
// like the executor's own transfers.
func (bc *Blockchain) contractTransferNSPX(state *StateDB, from string) func(string, *big.Int) error {
	return func(to string, amount *big.Int) error {
		if to == "" {
			return errors.New("empty transfer recipient")
		}
		if amount == nil || amount.Sign() <= 0 {
			return errors.New("invalid transfer amount")
		}
		return state.Transfer(from, to, amount)
	}
}
