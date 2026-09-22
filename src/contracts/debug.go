// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// ExecutionTrace contains detailed execution trace information for debugging
type ExecutionTrace struct {
	ContractAddress string               `json:"contract_address"`
	Method          string               `json:"method,omitempty"`
	Runtime         string               `json:"runtime"`
	Timestamp       int64                `json:"timestamp"`
	Duration        int64                `json:"duration_ms"`
	GasUsed         uint64               `json:"gas_used"`
	Success         bool                 `json:"success"`
	Error           string               `json:"error,omitempty"`
	StorageReads    []StorageAccessTrace `json:"storage_reads,omitempty"`
	StorageWrites   []StorageAccessTrace `json:"storage_writes,omitempty"`
	NestedCalls     []ExecutionTrace     `json:"nested_calls,omitempty"`
	Events          []ContractEvent      `json:"events,omitempty"`
	ReturnValue     interface{}          `json:"return_value,omitempty"`
	CallData        string               `json:"call_data,omitempty"`
	StackTrace      []StackFrame         `json:"stack_trace,omitempty"`
}

// SimulationResult captures a local dry-run of a contract call with storage and
// trace data for developer tooling and SDK regression tests.
type SimulationResult struct {
	ContractAddress string            `json:"contract_address"`
	Method          string            `json:"method"`
	Runtime         string            `json:"runtime"`
	Status          string            `json:"status"`
	Success         bool              `json:"success"`
	Error           string            `json:"error,omitempty"`
	Trace           *ExecutionTrace   `json:"trace,omitempty"`
	StorageBefore   map[string]string `json:"storage_before,omitempty"`
	StorageAfter    map[string]string `json:"storage_after,omitempty"`
	Events          []ContractEvent   `json:"events,omitempty"`
	CallTree        *CallFrame        `json:"call_tree,omitempty"`
}

// StorageAccessTrace logs a storage read or write during execution
type StorageAccessTrace struct {
	Address   string `json:"address"`
	Key       string `json:"key"`
	Value     string `json:"value"`
	ValueLen  uint32 `json:"value_len"`
	Timestamp int64  `json:"timestamp"`
	IsWrite   bool   `json:"is_write"`
}

// StackFrame represents a level in the call stack during execution
type StackFrame struct {
	ContractAddress string            `json:"contract_address"`
	Method          string            `json:"method"`
	Line            uint32            `json:"line,omitempty"`
	Instruction     string            `json:"instruction,omitempty"`
	LocalVars       map[string]string `json:"local_vars,omitempty"`
}

// CallFrame represents a single frame in the contract call stack, capturing
// per-frame execution details including gas, storage deltas, events, and
// nested calls. This is the structured trace format for regression testing
// and debugging multi-hop contract interactions.
type CallFrame struct {
	Depth        int               `json:"depth"`
	Kind         string            `json:"kind"` // "native" | "svm1" | "wasm"
	Contract     string            `json:"contract"`
	Caller       string            `json:"caller"`
	Method       string            `json:"method"`
	Args         map[string]string `json:"args,omitempty"`
	GasUsed      uint64            `json:"gas_used"`
	StorageDelta []StorageWrite    `json:"storage_delta,omitempty"`
	Events       []EmittedEvent    `json:"events,omitempty"`
	Reverted     bool              `json:"reverted"`
	RevertReason string            `json:"revert_reason,omitempty"`
	Children     []*CallFrame      `json:"children,omitempty"`
	Parent       *CallFrame        `json:"-"` // internal use, not serialized
}

// StorageWrite captures a single storage key change within a call frame,
// including the old and new values for delta analysis.
type StorageWrite struct {
	Key      string `json:"key"`       // full contract:-namespaced key
	OldValue string `json:"old_value"` // empty if key didn't previously exist
	NewValue string `json:"new_value"`
}

// EmittedEvent captures an event emitted during contract execution, tagged
// with the originating contract address for multi-hop trace attribution.
type EmittedEvent struct {
	Contract string            `json:"contract"` // origin contract address
	Name     string            `json:"name"`
	Data     map[string]string `json:"data"`
}

// CallFrameBuilder helps construct CallFrame trees during execution
type CallFrameBuilder struct {
	frames  []*CallFrame
	current *CallFrame
}

// DebugAdapter provides hooks for tracing contract execution
type DebugAdapter interface {
	// TraceStorageRead logs a storage read
	TraceStorageRead(address, key string, value []byte, timestamp int64)

	// TraceStorageWrite logs a storage write
	TraceStorageWrite(address, key string, value []byte, timestamp int64)

	// TraceCall logs the start of a contract call
	TraceCallStart(contract, method string)

	// TraceCallEnd logs the end of a contract call
	TraceCallEnd(contract, method string, success bool, gasUsed uint64, err error)

	// TraceNestedCall logs a nested contract call
	TraceNestedCall(target, method string, args []ABIValue)

	// GetTrace returns the complete execution trace
	GetTrace() *ExecutionTrace
}

// SimpleDebugAdapter is a basic implementation of DebugAdapter
type SimpleDebugAdapter struct {
	trace     *ExecutionTrace
	stack     []*ExecutionTrace
	startTime time.Time
}

// NewSimpleDebugAdapter creates a new debug adapter
func NewSimpleDebugAdapter(contract, runtime string) *SimpleDebugAdapter {
	trace := &ExecutionTrace{
		ContractAddress: contract,
		Runtime:         runtime,
		Timestamp:       time.Now().UnixMilli(),
		StorageReads:    []StorageAccessTrace{},
		StorageWrites:   []StorageAccessTrace{},
		NestedCalls:     []ExecutionTrace{},
		Events:          []ContractEvent{},
	}
	return &SimpleDebugAdapter{
		trace:     trace,
		stack:     []*ExecutionTrace{trace},
		startTime: time.Now(),
	}
}

// TraceStorageRead logs a storage read
func (sa *SimpleDebugAdapter) TraceStorageRead(address, key string, value []byte, timestamp int64) {
	if len(sa.stack) == 0 {
		return
	}
	current := sa.stack[len(sa.stack)-1]
	current.StorageReads = append(current.StorageReads, StorageAccessTrace{
		Address:   address,
		Key:       key,
		Value:     fmt.Sprintf("0x%x", value),
		ValueLen:  uint32(len(value)),
		Timestamp: timestamp,
		IsWrite:   false,
	})
}

// TraceStorageWrite logs a storage write
func (sa *SimpleDebugAdapter) TraceStorageWrite(address, key string, value []byte, timestamp int64) {
	if len(sa.stack) == 0 {
		return
	}
	current := sa.stack[len(sa.stack)-1]
	current.StorageWrites = append(current.StorageWrites, StorageAccessTrace{
		Address:   address,
		Key:       key,
		Value:     fmt.Sprintf("0x%x", value),
		ValueLen:  uint32(len(value)),
		Timestamp: timestamp,
		IsWrite:   true,
	})
}

// TraceCallStart logs the start of a contract call
func (sa *SimpleDebugAdapter) TraceCallStart(contract, method string) {
	if len(sa.stack) == 0 {
		return
	}
	current := sa.stack[len(sa.stack)-1]
	current.Method = method
}

// TraceCallEnd logs the end of a contract call
func (sa *SimpleDebugAdapter) TraceCallEnd(contract, method string, success bool, gasUsed uint64, err error) {
	if len(sa.stack) == 0 {
		return
	}
	current := sa.stack[len(sa.stack)-1]
	current.Success = success
	current.GasUsed = gasUsed
	current.Duration = time.Since(sa.startTime).Milliseconds()
	if err != nil {
		current.Error = err.Error()
	}
}

// TraceNestedCall logs a nested contract call
func (sa *SimpleDebugAdapter) TraceNestedCall(target, method string, args []ABIValue) {
	if len(sa.stack) == 0 {
		return
	}
	current := sa.stack[len(sa.stack)-1]

	nested := &ExecutionTrace{
		ContractAddress: target,
		Method:          method,
		Timestamp:       time.Now().UnixMilli(),
		StorageReads:    []StorageAccessTrace{},
		StorageWrites:   []StorageAccessTrace{},
		NestedCalls:     []ExecutionTrace{},
		Events:          []ContractEvent{},
	}

	// Store args as call data
	if len(args) > 0 {
		argsJSON, _ := json.Marshal(args)
		nested.CallData = string(argsJSON)
	}

	current.NestedCalls = append(current.NestedCalls, *nested)
	sa.stack = append(sa.stack, nested)
}

// GetTrace returns the complete execution trace
func (sa *SimpleDebugAdapter) GetTrace() *ExecutionTrace {
	return sa.trace
}

// ContractSimulator provides a local simulation environment for testing contracts
type ContractSimulator struct {
	store       Store
	debug       DebugAdapter
	blockHeight uint64
	timestamp   int64
}

// NewContractSimulator creates a simulator with an in-memory store
func NewContractSimulator() *ContractSimulator {
	return &ContractSimulator{
		store:       NewMemoryStore(),
		blockHeight: 0,
		timestamp:   time.Now().Unix(),
	}
}

// Deploy simulates contract deployment. It mirrors the consensus deploy path
// in runtime.go: the spec is normalized and validated, the built code and meta
// are stored, and then the standard's initialization runs (initSIP20 /
// initSIP721). Skipping that init left simulated contracts with an empty
// store — no info record, no initial-supply balances — so Simulate snapshots
// could never show keys like "sip20:balance:<owner>" that a real mined deploy
// writes before any call is even made.
func (cs *ContractSimulator) Deploy(spec *DeploySpec) (string, error) {
	if spec == nil {
		return "", errors.New("nil deploy spec")
	}
	// Normalize a local copy so the caller's struct is not mutated, exactly
	// as the consensus path works on a decoded copy of tx.Code.
	normalized := *spec
	normalizeDeploySpec(&normalized)
	if err := ValidateDeploySpec(&normalized); err != nil {
		return "", err
	}
	spec = &normalized

	code, err := BuildDeployCode(spec)
	if err != nil {
		return "", err
	}

	address := ContractAddress("test", 0, code)
	meta := &ContractMeta{
		Address:        address,
		Creator:        "test",
		Runtime:        spec.Runtime,
		RuntimeVersion: 1,
		Standard:       spec.Standard,
		CreatedAt:      cs.timestamp,
	}

	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return "", err
	}

	cs.store.SetContractCode(address, code)
	cs.store.SetContractMeta(address, metaBytes)

	// Initialize the standard's storage exactly as the consensus deploy path
	// does (see Deploy in runtime.go). Sender "test" matches the creator used
	// to derive the address above, so spec.Owner == "" resolves to it.
	switch spec.Standard {
	case StandardSIP20:
		err = initSIP20(cs.store, address, "test", spec)
	case StandardSIP721:
		err = initSIP721(cs.store, address, "test", spec)
	default:
		return "", fmt.Errorf("unsupported contract standard: %s", spec.Standard)
	}
	if err != nil {
		return "", err
	}

	return address, nil
}

// Call simulates a contract call with tracing. Native runtime calls are routed
// through the same consensus execution path as production, while WASM runs in a
// read-only overlay to preserve determinism.
func (cs *ContractSimulator) Call(address string, spec *RichCallSpec) (*ExecutionTrace, error) {
	debug := NewSimpleDebugAdapter(address, "wasm1")

	if !cs.store.ContractExists(address) {
		return nil, fmt.Errorf("contract not found: %s", address)
	}
	if spec == nil {
		return nil, fmt.Errorf("nil rich call spec")
	}

	code, err := cs.store.GetContractCode(address)
	if err != nil {
		return nil, err
	}

	callData, err := BuildRichCallData(spec)
	if err != nil {
		return nil, err
	}
	debug.TraceCallStart(address, spec.Method)

	var result *ExecutionResult
	if IsWASM(code) {
		result, err = ExecuteWASMReadOnly(cs.store, address, code, callData, 1_000_000, 512)
	} else {
		metaJSON, metaErr := cs.store.GetContractMeta(address)
		if metaErr != nil {
			debug.TraceCallEnd(address, spec.Method, false, 0, metaErr)
			return debug.GetTrace(), metaErr
		}
		var meta ContractMeta
		if err := json.Unmarshal(metaJSON, &meta); err != nil {
			debug.TraceCallEnd(address, spec.Method, false, 0, err)
			return debug.GetTrace(), err
		}
		callSpec, convErr := spec.ToCallSpec(&ContractABI{Version: 1, Methods: []ABIMethod{{Name: spec.Method, Parameters: nil}}})
		if convErr != nil {
			debug.TraceCallEnd(address, spec.Method, false, 0, convErr)
			return debug.GetTrace(), convErr
		}
		if meta.Standard == StandardSIP20 {
			callSpec, convErr = spec.ToCallSpec(&StablecoinABI)
			if convErr != nil {
				debug.TraceCallEnd(address, spec.Method, false, 0, convErr)
				return debug.GetTrace(), convErr
			}
		}
		payload, marshalErr := BuildCallData(callSpec)
		if marshalErr != nil {
			debug.TraceCallEnd(address, spec.Method, false, 0, marshalErr)
			return debug.GetTrace(), marshalErr
		}
		tx := &types.Transaction{
			Sender:     "simulator",
			ToContract: address,
			CallData:   payload,
			Timestamp:  cs.timestamp,
			Amount:     big.NewInt(0),
		}
		result, err = Call(cs.store, tx)
	}

	if err != nil {
		debug.TraceCallEnd(address, spec.Method, false, 0, err)
		return debug.GetTrace(), err
	}

	debug.trace.Events = append(debug.trace.Events, result.Events...)
	if result != nil && len(result.Events) > 0 {
		debug.trace.Events = append(debug.trace.Events, result.Events...)
	}
	debug.TraceCallEnd(address, spec.Method, result.Status == "success" || result.Status == "ok" || result.Status == "deployed", 0, nil)

	return debug.GetTrace(), nil
}

// Simulate executes a contract call in the local simulator and returns a
// structured dry-run result with trace and storage deltas for regression tests.
func (cs *ContractSimulator) Simulate(address string, spec *RichCallSpec) (*SimulationResult, error) {
	if !cs.store.ContractExists(address) {
		return nil, fmt.Errorf("contract not found: %s", address)
	}
	mem, ok := cs.store.(*MemoryStore)
	if !ok {
		return nil, fmt.Errorf("simulator requires a MemoryStore")
	}
	before := mem.Snapshot(address)

	// Convert ABIValues to map[string]string for the call tree
	argsMap := abivarsToMap(spec.Args)

	// Build call tree for structured tracing
	callTree := NewCallFrameBuilder(0, "native", address, "simulator", spec.Method, argsMap)

	trace, err := cs.Call(address, spec)
	after := mem.Snapshot(address)

	// Populate storage delta for the root frame
	callTree.AddStorageWrite("storage:before", "", beforeToString(before))
	callTree.AddStorageWrite("storage:after", beforeToString(before), afterToString(after))

	res := &SimulationResult{
		ContractAddress: address,
		Method:          spec.Method,
		Runtime:         "simulator",
		Status:          "ok",
		Success:         err == nil,
		StorageBefore:   before,
		StorageAfter:    after,
		Trace:           trace,
		CallTree:        callTree.Root(),
	}
	if trace != nil {
		res.Events = trace.Events
	}
	if err != nil {
		res.Status = "error"
		res.Error = err.Error()
		res.Success = false
		callTree.MarkReverted(err.Error())
		return res, err
	}
	if trace != nil && trace.Error != "" {
		res.Status = "error"
		res.Error = trace.Error
		res.Success = false
		callTree.MarkReverted(trace.Error)
	}
	return res, nil
}

// abivarsToMap converts []ABIValue to map[string]string for tracing
func abivarsToMap(vars []ABIValue) map[string]string {
	result := make(map[string]string)
	for i, v := range vars {
		result[fmt.Sprintf("arg[%d]", i)] = fmt.Sprintf("%v", v)
	}
	return result
}

func beforeToString(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	data, _ := json.Marshal(m)
	return string(data)
}

func afterToString(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	data, _ := json.Marshal(m)
	return string(data)
}

// SetBlockHeight sets the simulated block height
func (cs *ContractSimulator) SetBlockHeight(height uint64) {
	cs.blockHeight = height
}

// SetTimestamp sets the simulated timestamp
func (cs *ContractSimulator) SetTimestamp(ts int64) {
	cs.timestamp = ts
}

// MemoryStore is an in-memory implementation of Store for testing
type MemoryStore struct {
	contracts map[string][]byte            // address -> code
	metadata  map[string][]byte            // address -> metadata
	storage   map[string]map[string][]byte // address -> key -> value
}

// NewMemoryStore creates a new in-memory store
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		contracts: make(map[string][]byte),
		metadata:  make(map[string][]byte),
		storage:   make(map[string]map[string][]byte),
	}
}

// ContractExists checks if a contract exists
func (ms *MemoryStore) ContractExists(address string) bool {
	_, ok := ms.contracts[address]
	return ok
}

// SetContractCode stores contract code
func (ms *MemoryStore) SetContractCode(address string, code []byte) {
	ms.contracts[address] = append([]byte{}, code...)
	if _, ok := ms.storage[address]; !ok {
		ms.storage[address] = make(map[string][]byte)
	}
}

// GetContractCode retrieves contract code
func (ms *MemoryStore) GetContractCode(address string) ([]byte, error) {
	code, ok := ms.contracts[address]
	if !ok {
		return nil, fmt.Errorf("contract not found: %s", address)
	}
	return append([]byte{}, code...), nil
}

// SetContractMeta stores contract metadata
func (ms *MemoryStore) SetContractMeta(address string, meta []byte) {
	ms.metadata[address] = append([]byte{}, meta...)
}

// GetContractMeta retrieves contract metadata
func (ms *MemoryStore) GetContractMeta(address string) ([]byte, error) {
	meta, ok := ms.metadata[address]
	if !ok {
		return nil, fmt.Errorf("contract metadata not found: %s", address)
	}
	return append([]byte{}, meta...), nil
}

// SetContractStorage sets a storage key-value pair
func (ms *MemoryStore) SetContractStorage(address, key string, value []byte) {
	if _, ok := ms.storage[address]; !ok {
		ms.storage[address] = make(map[string][]byte)
	}
	ms.storage[address][key] = append([]byte{}, value...)
}

// GetContractStorage retrieves a storage value
func (ms *MemoryStore) GetContractStorage(address, key string) ([]byte, error) {
	if store, ok := ms.storage[address]; ok {
		if value, ok := store[key]; ok {
			return append([]byte{}, value...), nil
		}
	}
	return []byte{}, nil
}

// Snapshot returns a string-keyed view of all storage entries for a contract.
func (ms *MemoryStore) Snapshot(address string) map[string]string {
	out := make(map[string]string)
	if store, ok := ms.storage[address]; ok {
		for k, v := range store {
			out[k] = string(v)
		}
	}
	return out
}

// SnapshotToFrame captures storage state for a contract and returns it as
// a StorageDelta suitable for a CallFrame. This is the bridge between the
// existing Snapshot method and the new CallFrame-based tracing.
func (ms *MemoryStore) SnapshotToFrame(address string) []StorageWrite {
	out := make([]StorageWrite, 0)
	if store, ok := ms.storage[address]; ok {
		for k, v := range store {
			fullKey := fmt.Sprintf("contract:%s:%s", address, k)
			out = append(out, StorageWrite{
				Key:      fullKey,
				OldValue: "",
				NewValue: string(v),
			})
		}
	}
	return out
}

// NewCallFrameBuilder creates a new CallFrameBuilder for root frame
func NewCallFrameBuilder(depth int, kind, contract, caller, method string, args map[string]string) *CallFrameBuilder {
	root := &CallFrame{
		Depth:    depth,
		Kind:     kind,
		Contract: contract,
		Caller:   caller,
		Method:   method,
		Args:     args,
		Children: []*CallFrame{},
		Events:   []EmittedEvent{},
	}
	return &CallFrameBuilder{
		frames:  []*CallFrame{root},
		current: root,
	}
}

// PushFrame creates a new child frame and makes it current
func (b *CallFrameBuilder) PushFrame(kind, contract, caller, method string, args map[string]string) *CallFrame {
	child := &CallFrame{
		Depth:    b.current.Depth + 1,
		Kind:     kind,
		Contract: contract,
		Caller:   caller,
		Method:   method,
		Args:     args,
		Children: []*CallFrame{},
		Events:   []EmittedEvent{},
		Parent:   b.current,
	}
	b.current.Children = append(b.current.Children, child)
	b.current = child
	b.frames = append(b.frames, child)
	return child
}

// PopFrame returns to the parent frame
func (b *CallFrameBuilder) PopFrame() {
	if b.current.Parent != nil {
		b.current = b.current.Parent
	}
}

// AddStorageWrite adds a storage delta to the current frame
func (b *CallFrameBuilder) AddStorageWrite(key, oldValue, newValue string) {
	b.current.StorageDelta = append(b.current.StorageDelta, StorageWrite{
		Key:      key,
		OldValue: oldValue,
		NewValue: newValue,
	})
}

// AddEvent adds an emitted event to the current frame
func (b *CallFrameBuilder) AddEvent(contract, name string, data map[string]string) {
	b.current.Events = append(b.current.Events, EmittedEvent{
		Contract: contract,
		Name:     name,
		Data:     data,
	})
}

// SetGasUsed sets the gas used for the current frame
func (b *CallFrameBuilder) SetGasUsed(gas uint64) {
	b.current.GasUsed = gas
}

// MarkReverted marks the current frame as reverted with a reason
func (b *CallFrameBuilder) MarkReverted(reason string) {
	b.current.Reverted = true
	b.current.RevertReason = reason
}

// Root returns the root CallFrame
func (b *CallFrameBuilder) Root() *CallFrame {
	return b.frames[0]
}
